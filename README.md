# NetGuard — Local-First Network Security Monitor

Professional-grade network security monitoring for home and SOHO networks. Runs on Raspberry Pi. No cloud dependency. No subscription required.

---

## Why NetGuard Exists

Consumer network security tools have drifted toward subscription models and opaque cloud backends. Fing pivoted to paid tiers and discontinued Fingbox hardware. Bitdefender BOX has documented mesh reliability problems. Nothing in the consumer space offered transparent, non-cloud risk scoring with exportable audit evidence.

NetGuard was built to fill that gap: local-first architecture, inspectable detection logic, and honest disclosure of what the system can and cannot see on a typical home LAN.

---

## What It Does

Capabilities are grouped by outcome, not by internal module names.

### Network Visibility

Passive device discovery runs on 30-second ARP scan cycles, recording MAC, vendor, hostname, and online/offline state. OS fingerprinting infers device type and operating system from passive TCP SYN-ACK and DHCP signals—no active port scanning required for classification. Service version detection probes open HTTP, SSH, and TLS ports on a scheduled basis and records banners in the local database. Full DNS query capture covers all devices routed through the Pi's dnsmasq relay, with domain categorisation and per-device attribution.

### Threat Detection

Each device receives a composite risk score derived from open-port exposure, OS and category signals, trust status, and recent alerts—not a single CVE lookup. Threat intelligence uses the Steven Black unified hosts blocklist (~100k malicious domains), refreshed on a timer and matched against observed DNS queries. ARP spoofing detection flags unexpected MAC changes. Rogue DHCP detection identifies unauthorised DHCP servers. Inbound connection monitoring raises alerts on external connection attempts with per-device rate limits and pattern classification (single source vs. distributed scan). A policy engine evaluates network conditions continuously and can trigger automated response playbooks (isolation, repeated-threat alerts, incident email reports).

### Enforcement

Device blocking is implemented through the Linksys JNAP router API, confirmed working on Velop and similar mesh networks where ARP-level isolation is unreliable. When router enforcement is unavailable, DNS-based domain blocking provides a fallback. Per-device block and unblock is available from the dashboard and REST API.

### Compliance & Reporting

A GDPR Article 32 compliance report generates a structured PDF (asset inventory, controls, risk summary, incident log, automated actions, data-handling statement). SIEM integration exports alerts in RFC 5424 syslog format (UDP/TCP). A weekly email security summary covers the prior seven days when SMTP is configured. The alert workflow supports acknowledge, false-positive marking, and suppression rules with a full audit trail.

### Security of the Tool Itself

All write operations on the REST API require an `X-API-Key` header; keys are auto-generated on first start and stored in the local env file. Credentials are stored in an AES-256 encrypted vault (PBKDF2-HMAC-SHA256 key derivation). Password strength checking uses HIBP k-anonymity range queries—plaintext passwords never leave the host. Device inventory, DNS logs, and alerts remain on the local SQLite database; no cloud transmission unless MSP mode is explicitly configured. The database runs in WAL mode with a busy timeout to handle concurrent daemon writes safely.

---

## Architecture

NetGuard uses a local-first daemon architecture: independent Python processes collect telemetry, write to a shared SQLite database, and expose data through a FastAPI REST backend. A React dashboard is served from the same host. Core monitoring does not depend on any external cloud service.

On Raspberry Pi production deployments, nine monitoring daemons plus the API are managed by systemd (`netguard.target`). Threat-intel updates and weekly reports run on timers. Windows builds package the same logic as PyInstaller executables with scheduled-task auto-start.

```
[Network Devices] ──► [Raspberry Pi]
                           ├── ARP Scanner (+ port scan cycle)
                           ├── DNS Monitor (via dnsmasq)
                           ├── OS Fingerprinting
                           ├── Risk Scorer
                           ├── Threat Intel
                           ├── Policy Engine
                           ├── Detection engines (ARP spoof, rogue DHCP, inbound)
                           ├── FastAPI + Dashboard (:8000)
                           └── [Browser on any LAN device]
                                    │
                           SQLite (WAL) ──► Syslog export (optional)
```

**Stack:** Python 3.10+, FastAPI, React/TypeScript, SQLite, Scapy, fpdf2. See `API.md` for the full REST surface.

---

## Deployment

### Raspberry Pi (Production)

```bash
sudo bash install/profiles/pi-home/install.sh
```

Installs systemd units, dnsmasq relay, database under `/var/lib/netguard/`, and enables auto-start on boot. Dashboard: `http://<pi-ip>:8000`

Detailed steps, service list, and troubleshooting: `install/pi/README.md`

### Windows (Development / Testing)

Build the installer:

```powershell
.\build\windows\build-installer.ps1
```

Output: `build/installer/NetGuard-Setup.exe` — bundles the API, daemons, dashboard, and Npcap prerequisite. Post-install, `Register-NetGuard-AutoStart.ps1` registers scheduled tasks for core services and packet-capture engines. Launch **NetGuard** from the Start Menu to open the dashboard at `http://127.0.0.1:8000`.

Windows is suitable for development and lab testing. Packet capture requires Npcap. Router-based enforcement is the recommended block path on Windows; ARP isolation is Pi-only.

---

## Competitive Context

NetGuard sits between Fing (subscription pivot, discontinued hardware, limited audit export) and Firewalla (effective but closed-box rules and proprietary cloud dependency). It targets operators who want open architecture, exportable compliance evidence, and transparent detection logic—including documented limitations such as mesh DNS proxying gaps and incomplete passive fingerprint coverage—that closed products typically do not publish.

For MSP operators, optional heartbeat mode (`NETGUARD_MSP_COLLECTOR_URL`) sends summary telemetry only; full DNS and device detail stays local unless separately integrated.

---

## Design Decisions

**Local-first by default.** GDPR Article 32 evidence, no third-party cloud attack surface for core monitoring, and continued operation when upstream internet is unavailable. Cloud is opt-in, not assumed.

**No false CVE attribution.** Risk scoring uses confidence-tiered signals (open ports, OS guess confidence, device category, trust state). Port numbers map to reference guidance, not automatic CVE assignment—avoiding the false precision common in consumer scanners.

**Linksys JNAP over ARP isolation on mesh.** Consumer mesh networks break L2 isolation assumptions. NetGuard prioritises router API blocking (JNAP on Linksys Velop) where ARP cache poisoning is unreliable. ARP-based blocking remains available on Pi for flat LANs via an optional enforcer service.

**RFC 5424 syslog over proprietary SIEM formats.** Alerts export to any standard syslog collector (Splunk, Elastic, Wazuh, rsyslog) without vendor lock-in.

**API key on writes only.** Read endpoints stay open on localhost/LAN so the dashboard can poll without bootstrapping auth; mutating operations require explicit key configuration.

---

## Status

**v1.2 — Production.** Running on a live home network (Raspberry Pi + Windows development host).

**Known limitations**

- DNS visibility requires traffic to pass through the Pi's dnsmasq relay; devices with hard-coded external DNS may bypass monitoring.
- Passive OS fingerprinting does not cover all device types; unknown vendors and privacy-hardened phones often score as low-confidence.
- Router enforcement currently targets Linksys JNAP; other vendors require manual integration or DNS-only blocking.
- Banner grabbing runs on a 60-minute cycle and skips database service ports by design.
- Windows packet capture depends on Npcap and administrator privileges for capture engines.

**Roadmap**

- **Phase 3:** Multi-site MSP dashboard and centralised policy management
- **Phase 4:** Behavioural baseline and anomaly detection

---

## Author

**Jibin Michael** — Network Security Engineer, Ireland

[LinkedIn](https://www.linkedin.com/in/jibin-michael/)

For API reference, see `API.md`. For Pi installation and service management, see `install/pi/README.md`.
