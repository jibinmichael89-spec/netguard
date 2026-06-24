#!/usr/bin/env python3
"""
NetGuard DNS Monitor
Captures DNS queries on the local network using Scapy, classifies domains,
flags suspicious activity, and persists every query to SQLite.

Also tails a dnsmasq log file (when present) for DNS queries seen by the
local resolver — both sources write to the same dns_queries table.
"""

from __future__ import annotations

import os
import re
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone

from scapy.all import DNS, IP, sniff

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Path to the shared SQLite database (project root)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DB_PATH = os.path.join(PROJECT_ROOT, "netguard.db")

# BPF filter — capture all DNS traffic on UDP port 53
DNS_BPF_FILTER = "udp port 53"

# dnsmasq query log (Pi / router deployments)
DNSMASQ_LOG_PATH = os.environ.get(
    "DNSMASQ_LOG_PATH",
    "/home/netguard/netguard/logs/dnsmasq.log",
)
DNSMASQ_LOG_RETRY_SECONDS = 5
DNSMASQ_DEDUP_WINDOW_SECONDS = 10
DNSMASQ_TAIL_POLL_SECONDS = 0.2

# High-risk top-level domains
HIGH_RISK_TLDS = (".ru", ".cn", ".tk", ".pw", ".top")

# Keywords associated with malicious infrastructure
BAD_DOMAIN_KEYWORDS = (
    "malware",
    "botnet",
    "c2",
    "payload",
    "shell",
    "exploit",
)

# Known safe category keyword mappings
DOMAIN_CATEGORIES = {
    "Social media": ("facebook", "instagram", "twitter", "tiktok", "snapchat"),
    "Streaming": ("netflix", "youtube", "spotify", "disney", "amazon"),
    "Gaming": ("xbox", "playstation", "steam", "epicgames"),
    "IoT/Smart home": ("ring", "dreame", "xiaomi", "tuya", "alexa"),
    "Advertising": ("doubleclick", "googlesyndication", "adnxs", "tracking"),
    "Apple services": ("apple", "icloud", "itunes"),
    "Microsoft": ("microsoft", "windows", "azure"),
}

# Map numeric DNS query types to human-readable names
QUERY_TYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}

DNSMASQ_QUERY_RE = re.compile(
    r"query\[(A|AAAA)\]\s+(\S+)\s+from\s+(\S+)",
    re.IGNORECASE,
)
DNSMASQ_SYSLOG_TS_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
)

_dedup_lock = threading.Lock()
_recent_dnsmasq_queries: dict[tuple[str, str], float] = {}


# ---------------------------------------------------------------------------
# Privilege check
# ---------------------------------------------------------------------------

def require_root() -> None:
    """
    Ensure the process is running with administrator/root privileges.

    Raw packet capture requires elevated permissions on Linux/Pi and Windows.
    """
    if os.name == "nt":
        try:
            import ctypes

            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("[!] Error: Administrator privileges are required.")
                sys.exit(1)
        except (AttributeError, OSError):
            pass
        return

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[!] Error: Root privileges are required. Run with sudo.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Database operations
# ---------------------------------------------------------------------------

def init_database(db_path: str) -> None:
    """
    Create the dns_queries table if it does not already exist.

    Stores every captured DNS query with suspicion flags and reasons.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS dns_queries (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT    NOT NULL,
            source_ip     TEXT    NOT NULL,
            domain        TEXT    NOT NULL,
            query_type    TEXT    NOT NULL,
            response_ip   TEXT,
            is_suspicious INTEGER NOT NULL DEFAULT 0,
            reason        TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def save_dns_query(
    db_path: str,
    timestamp: str,
    source_ip: str,
    domain: str,
    query_type: str,
    response_ip: str | None,
    is_suspicious: int,
    reason: str | None,
) -> None:
    """Insert a single DNS query record into the database."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO dns_queries
                (timestamp, source_ip, domain, query_type, response_ip,
                 is_suspicious, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                source_ip,
                domain,
                query_type,
                response_ip,
                is_suspicious,
                reason,
            ),
        )
        conn.commit()
        conn.close()
    except sqlite3.Error as exc:
        print(f"[!] Database error: {exc}")


def update_response_ip(
    db_path: str,
    source_ip: str,
    domain: str,
    response_ip: str,
) -> None:
    """
    Attach a response IP to the most recent matching query row.

    Called when a DNS response packet is observed after the original query.
    """
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE dns_queries
            SET response_ip = ?
            WHERE id = (
                SELECT id FROM dns_queries
                WHERE source_ip = ?
                  AND domain = ?
                  AND response_ip IS NULL
                ORDER BY id DESC
                LIMIT 1
            )
            """,
            (response_ip, source_ip, domain),
        )
        conn.commit()
        conn.close()
    except sqlite3.Error as exc:
        print(f"[!] Database error updating response: {exc}")


# ---------------------------------------------------------------------------
# Domain analysis
# ---------------------------------------------------------------------------

def get_query_type_name(qtype: int) -> str:
    """Convert a numeric DNS query type to a readable label (A, AAAA, MX, etc.)."""
    return QUERY_TYPE_NAMES.get(qtype, str(qtype))


def categorize_domain(domain: str) -> str:
    """
    Assign a known safe category label based on domain keywords.

    Returns 'Other' when no category keyword matches.
    """
    domain_lower = domain.lower()
    for category, keywords in DOMAIN_CATEGORIES.items():
        for keyword in keywords:
            if keyword in domain_lower:
                return category
    return "Other"


def check_suspicious(domain: str) -> tuple[int, str | None]:
    """
    Evaluate a domain against suspicious-pattern rules.

    Returns (is_suspicious, reason) where is_suspicious is 0 or 1.
    """
    domain_lower = domain.lower()
    reasons: list[str] = []

    for tld in HIGH_RISK_TLDS:
        if domain_lower.endswith(tld):
            reasons.append(f"High-risk TLD: {tld}")

    labels = domain_lower.rstrip(".").split(".")
    subdomain_count = max(0, len(labels) - 2)
    if subdomain_count > 4:
        reasons.append("More than 4 subdomains (DNS tunneling indicator)")

    if len(domain) > 50:
        reasons.append("Domain longer than 50 characters (DNS tunneling indicator)")

    for keyword in BAD_DOMAIN_KEYWORDS:
        if keyword in domain_lower:
            reasons.append(f"Known bad keyword: {keyword}")

    if reasons:
        return 1, "; ".join(reasons)
    return 0, None


def extract_response_ip(dns_layer: DNS) -> str | None:
    """Extract the first A or AAAA answer from a DNS response packet."""
    if not dns_layer.an:
        return None
    try:
        for index in range(dns_layer.ancount):
            record = dns_layer.an[index]
            if record.type in (1, 28):
                return str(record.rdata)
    except (IndexError, AttributeError, TypeError):
        pass
    return None


def decode_domain(qname) -> str | None:
    """Decode a DNS question name from Scapy packet data."""
    try:
        if isinstance(qname, bytes):
            return qname.decode("utf-8", errors="replace").rstrip(".")
        return str(qname).rstrip(".")
    except (UnicodeDecodeError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Packet processing
# ---------------------------------------------------------------------------

def print_dns_query(
    timestamp: str,
    source_ip: str,
    domain: str,
    category: str,
    is_suspicious: int,
) -> None:
    """
    Print a captured DNS query to the console.

    Format: [TIME] SOURCE_IP → DOMAIN (CATEGORY) [SUSPICIOUS if flagged]
    """
    time_display = timestamp[:19].replace("T", " ")
    suspicious_tag = " [SUSPICIOUS]" if is_suspicious else ""
    print(f"[{time_display}] {source_ip} → {domain} ({category}){suspicious_tag}")


def process_packet(packet) -> None:
    """
    Scapy callback invoked for every captured DNS packet.

    Logs queries (QR=0) and attaches response IPs from matching responses (QR=1).
    """
    try:
        if not packet.haslayer(DNS):
            return

        dns_layer = packet[DNS]
        if dns_layer.qd is None:
            return

        domain = decode_domain(dns_layer.qd.qname)
        if not domain:
            return

        query_type = get_query_type_name(dns_layer.qd.qtype)

        # DNS query from a client device
        if dns_layer.qr == 0:
            if not packet.haslayer(IP):
                return

            source_ip = packet[IP].src
            timestamp = datetime.now(timezone.utc).isoformat()
            is_suspicious, reason = check_suspicious(domain)
            category = categorize_domain(domain)

            save_dns_query(
                DB_PATH,
                timestamp,
                source_ip,
                domain,
                query_type,
                None,
                is_suspicious,
                reason,
            )
            print_dns_query(timestamp, source_ip, domain, category, is_suspicious)
            return

        # DNS response — attach answer IP to the matching recent query
        if dns_layer.qr == 1 and packet.haslayer(IP):
            client_ip = packet[IP].dst
            response_ip = extract_response_ip(dns_layer)
            if response_ip:
                update_response_ip(DB_PATH, client_ip, domain, response_ip)

    except Exception as exc:
        print(f"[!] Error processing packet: {exc}")


# ---------------------------------------------------------------------------
# dnsmasq log parsing
# ---------------------------------------------------------------------------

def parse_dnsmasq_syslog_timestamp(line: str) -> str:
    """Parse a syslog-style timestamp prefix from a dnsmasq log line."""
    match = DNSMASQ_SYSLOG_TS_RE.match(line)
    if not match:
        return datetime.now(timezone.utc).isoformat()

    prefix = match.group(1)
    now = datetime.now()
    try:
        parsed = datetime.strptime(f"{now.year} {prefix}", "%Y %b %d %H:%M:%S")
        return parsed.replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return datetime.now(timezone.utc).isoformat()


def parse_dnsmasq_query_line(
    line: str,
) -> tuple[str, str, str, str] | None:
    """
    Parse a dnsmasq query log line.

    Returns (query_type, domain, source_ip, timestamp) or None when the line
    is not a query[A] / query[AAAA] entry.
    """
    match = DNSMASQ_QUERY_RE.search(line)
    if not match:
        return None

    query_type = match.group(1).upper()
    domain = match.group(2).rstrip(".")
    source_ip = match.group(3)
    timestamp = parse_dnsmasq_syslog_timestamp(line)
    return query_type, domain, source_ip, timestamp


def _is_recent_dnsmasq_duplicate(domain: str, source_ip: str, now: float) -> bool:
    """Return True when the same domain+IP was recorded within the dedup window."""
    key = (domain.lower(), source_ip)
    with _dedup_lock:
        last_seen = _recent_dnsmasq_queries.get(key)
        if last_seen is not None and (now - last_seen) < DNSMASQ_DEDUP_WINDOW_SECONDS:
            return True

        _recent_dnsmasq_queries[key] = now

        stale_before = now - DNSMASQ_DEDUP_WINDOW_SECONDS
        stale_keys = [
            entry_key
            for entry_key, seen_at in _recent_dnsmasq_queries.items()
            if seen_at < stale_before
        ]
        for entry_key in stale_keys:
            del _recent_dnsmasq_queries[entry_key]

        return False


def process_dnsmasq_query_line(line: str) -> None:
    """Parse and persist a single dnsmasq log line when it is a DNS query."""
    parsed = parse_dnsmasq_query_line(line)
    if parsed is None:
        return

    query_type, domain, source_ip, timestamp = parsed
    now = time.monotonic()
    if _is_recent_dnsmasq_duplicate(domain, source_ip, now):
        return

    is_suspicious, reason = check_suspicious(domain)
    category = categorize_domain(domain)

    save_dns_query(
        DB_PATH,
        timestamp,
        source_ip,
        domain,
        query_type,
        None,
        is_suspicious,
        reason,
    )
    print_dns_query(timestamp, source_ip, domain, category, is_suspicious)


def _tail_dnsmasq_log(log_path: str) -> None:
    """
    Follow a dnsmasq log file from the current end, handling rotation/truncation.
    """
    with open(log_path, encoding="utf-8", errors="replace") as handle:
        handle.seek(0, os.SEEK_END)
        inode = os.fstat(handle.fileno()).st_ino

        while True:
            line = handle.readline()
            if line:
                process_dnsmasq_query_line(line.strip())
                continue

            try:
                stat = os.stat(log_path)
            except OSError:
                print(f"[*] DNS masq log unavailable — will reopen: {log_path}")
                time.sleep(DNSMASQ_LOG_RETRY_SECONDS)
                return

            if stat.st_ino != inode or stat.st_size < handle.tell():
                print(f"[*] DNS masq log rotated — reopening: {log_path}")
                return

            time.sleep(DNSMASQ_TAIL_POLL_SECONDS)


def monitor_dnsmasq_log(log_path: str = DNSMASQ_LOG_PATH) -> None:
    """
    Tail a dnsmasq log file continuously and persist DNS queries.

    Waits for the log file to appear when missing and reopens the file after
    rotation or truncation.
    """
    print(f"[*] DNS masq log monitor watching: {log_path}")

    while True:
        while not os.path.exists(log_path):
            print(
                f"[*] DNS masq log not found ({log_path}) — "
                f"retrying in {DNSMASQ_LOG_RETRY_SECONDS}s"
            )
            time.sleep(DNSMASQ_LOG_RETRY_SECONDS)

        try:
            _tail_dnsmasq_log(log_path)
        except OSError as exc:
            print(f"[!] DNS masq log read error: {exc}")
            time.sleep(DNSMASQ_LOG_RETRY_SECONDS)
        except Exception as exc:
            print(f"[!] DNS masq log monitor error: {exc}")
            time.sleep(DNSMASQ_LOG_RETRY_SECONDS)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Entry point: initialise the database and start continuous DNS capture.

    Uses Scapy sniff to monitor all DNS traffic until interrupted, with a
    background thread tailing the dnsmasq log when available.
    """
    print("NetGuard DNS Monitor starting ...")
    print(f"Database: {DB_PATH}")

    init_database(DB_PATH)

    log_thread = threading.Thread(
        target=monitor_dnsmasq_log,
        args=(DNSMASQ_LOG_PATH,),
        name="dnsmasq-log-monitor",
        daemon=True,
    )
    log_thread.start()
    print(f"DNS masq log: {DNSMASQ_LOG_PATH}")

    require_root()

    print(f"Capture filter: {DNS_BPF_FILTER}")
    print("Press Ctrl+C to stop.\n")

    try:
        sniff(
            filter=DNS_BPF_FILTER,
            prn=process_packet,
            store=False,
        )
    except KeyboardInterrupt:
        print("\n[!] DNS monitor stopped by user.")
        sys.exit(0)
    except PermissionError:
        print("[!] Permission denied. Run with sudo / as Administrator.")
        sys.exit(1)
    except OSError as exc:
        print(f"[!] Network capture error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
