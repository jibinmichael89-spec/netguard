#!/usr/bin/env python3
"""
NetGuard DNS Monitor
Captures DNS queries on the local network using Scapy, classifies domains,
flags suspicious activity, and persists every query to SQLite.
"""

import os
import sqlite3
import sys
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
# Main entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Entry point: initialise the database and start continuous DNS capture.

    Uses Scapy sniff to monitor all DNS traffic until interrupted.
    """
    print("NetGuard DNS Monitor starting ...")
    print(f"Database: {DB_PATH}")

    require_root()
    init_database(DB_PATH)

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
