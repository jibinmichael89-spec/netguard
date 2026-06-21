#!/usr/bin/env python3
"""
NetGuard NVD Reference Cache
Periodically fetches general historical CVE examples from the NVD API to enrich
risk explanations with real-world context. These are category-level reference
examples — not device-specific vulnerability findings.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_DELAY_SECONDS = 2
RESULTS_PER_PAGE = 3
DESCRIPTION_MAX_LENGTH = 200
REFRESH_INTERVAL_SECONDS = 7 * 24 * 3600
REQUEST_TIMEOUT_SECONDS = 30

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

if getattr(sys, "frozen", False):
    _bundle_root = sys._MEIPASS
else:
    _bundle_root = PROJECT_ROOT

RISK_RULES_PATH = os.path.join(_bundle_root, "daemon", "data", "risk_rules.json")
NVD_CACHE_PATH = os.path.join(_bundle_root, "daemon", "data", "nvd_reference_cache.json")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_risk_rules(path: str = RISK_RULES_PATH) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def save_cache(cache: dict, path: str = NVD_CACHE_PATH) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(cache, handle, indent=2)
        handle.write("\n")


def truncate_description(text: str, max_length: int = DESCRIPTION_MAX_LENGTH) -> str:
    normalized = " ".join(text.split())
    if len(normalized) <= max_length:
        return normalized
    return normalized[: max_length - 3].rstrip() + "..."


def extract_published_date(published: str | None) -> str | None:
    if not published:
        return None
    return published[:10]


def extract_severity(cve: dict) -> str | None:
    metrics = cve.get("metrics") or {}
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in metrics.get(metric_key) or []:
            cvss_data = entry.get("cvssData") or {}
            severity = cvss_data.get("baseSeverity")
            if severity:
                return severity.title()
    return None


def extract_english_description(cve: dict) -> str:
    for entry in cve.get("descriptions") or []:
        if entry.get("lang") == "en" and entry.get("value"):
            return str(entry["value"])
    descriptions = cve.get("descriptions") or []
    if descriptions and descriptions[0].get("value"):
        return str(descriptions[0]["value"])
    return "No description available."


def parse_cve_example(vulnerability: dict) -> dict | None:
    cve = vulnerability.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None

    description = truncate_description(extract_english_description(cve))
    published = extract_published_date(cve.get("published"))

    return {
        "cve_id": cve_id,
        "description": description,
        "published": published,
        "severity": extract_severity(cve),
    }


def fetch_examples_for_keyword(keyword: str) -> tuple[list[dict], str | None]:
    """
    Query the NVD API for a keyword.

    Returns (examples, failure_reason) where failure_reason is one of:
    - None on success
    - "rate_limit" for HTTP 403/429
    - "network" for connectivity/timeouts/other request failures
    """
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": RESULTS_PER_PAGE,
    }

    try:
        response = requests.get(
            NVD_API_URL,
            params=params,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        print(f"[!] NVD API request failed for '{keyword}': {exc}")
        return [], "network"

    if response.status_code in (403, 429):
        print(
            f"[!] NVD API rate-limited ({response.status_code}) for '{keyword}' "
            "— keeping existing cache unchanged."
        )
        return [], "rate_limit"

    if response.status_code != 200:
        print(
            f"[!] NVD API returned HTTP {response.status_code} for '{keyword}' "
            f"— skipping this keyword."
        )
        return [], None

    try:
        payload = response.json()
    except json.JSONDecodeError as exc:
        print(f"[!] Invalid JSON from NVD API for '{keyword}': {exc}")
        return [], None

    examples: list[dict] = []
    seen_ids: set[str] = set()
    for vulnerability in payload.get("vulnerabilities") or []:
        example = parse_cve_example(vulnerability)
        if example is None:
            continue
        cve_id = example["cve_id"]
        if cve_id in seen_ids:
            continue
        seen_ids.add(cve_id)
        examples.append(example)

    return examples, None


# ---------------------------------------------------------------------------
# Update cycle
# ---------------------------------------------------------------------------

def run_update_cycle() -> bool:
    """
    Fetch NVD reference examples and write the cache file.

    Returns True when the cache was saved, False when the existing cache was kept.
    """
    if not os.path.exists(RISK_RULES_PATH):
        print(f"[!] Risk rules file not found: {RISK_RULES_PATH}")
        return False

    try:
        risk_rules = load_risk_rules()
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[!] Failed to load risk rules: {exc}")
        return False

    keywords_by_port = risk_rules.get("cve_reference_keywords") or {}
    if not keywords_by_port:
        print("[NVD] No cve_reference_keywords entries found in risk rules.")
        return False

    new_cache: dict = {
        "last_updated": datetime.now(timezone.utc).isoformat(),
    }
    total_examples = 0
    ports_covered = 0

    for port_number, keywords in keywords_by_port.items():
        port_key = f"port_{port_number}"
        merged_examples: dict[str, dict] = {}

        for keyword in keywords:
            examples, failure_reason = fetch_examples_for_keyword(keyword)

            if failure_reason in ("rate_limit", "network"):
                print(
                    "[!] NVD reference update aborted — existing cache left unchanged."
                )
                return False

            print(
                f"[NVD] Fetched {len(examples)} example(s) for "
                f"'{keyword}' (port {port_number})"
            )

            for example in examples:
                merged_examples[example["cve_id"]] = example

            time.sleep(REQUEST_DELAY_SECONDS)

        port_examples = sorted(
            merged_examples.values(),
            key=lambda item: item.get("published") or "",
            reverse=True,
        )
        new_cache[port_key] = {
            "keywords": list(keywords),
            "examples": port_examples,
        }
        ports_covered += 1
        total_examples += len(port_examples)

    save_cache(new_cache)
    print(
        f"[NVD] Reference cache updated: {ports_covered} ports covered, "
        f"{total_examples} total examples, cache saved to {NVD_CACHE_PATH}"
    )
    return True


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="NetGuard NVD reference cache updater"
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Fetch reference examples once and exit",
    )
    args = parser.parse_args()

    print("NetGuard NVD Reference Cache updater starting...")
    print(f"Risk rules:  {RISK_RULES_PATH}")
    print(f"Cache file:  {NVD_CACHE_PATH}")
    print(f"Request gap: {REQUEST_DELAY_SECONDS}s between NVD queries")
    print("No admin/root privileges required (HTTP read + local file write only).")
    print("Press Ctrl+C to stop.\n")

    if args.once:
        run_update_cycle()
        return

    try:
        while True:
            run_update_cycle()
            next_run = datetime.now(timezone.utc).timestamp() + REFRESH_INTERVAL_SECONDS
            next_run_iso = datetime.fromtimestamp(
                next_run, tz=timezone.utc
            ).isoformat()
            print(
                f"\n[*] Next NVD reference refresh in 7 days "
                f"(~{next_run_iso[:19]} UTC) ..."
            )
            time.sleep(REFRESH_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[*] NVD reference updater stopped by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
