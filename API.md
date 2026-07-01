# NetGuard REST API

NetGuard exposes a JSON REST API on port **8000** (default). The bundled dashboard
uses the same API. External tools, scripts, and SIEM integrations can poll read
endpoints on the LAN without authentication; mutating requests require an API key.

## Base URL

```
http://<netguard-host>:8000
```

When using ngrok or a reverse proxy, set the dashboard `API_BASE_URL` accordingly.

## Authentication

| Request type | Header | Notes |
|--------------|--------|-------|
| `GET` (read-only) | None | Open on localhost/LAN for monitoring |
| `POST`, `PUT`, `DELETE` | `X-API-Key: <key>` | Required for block, save settings, vault, reports |

The API key is stored in `netguard.env` (`NETGUARD_API_KEY`). On first API start a
key is auto-generated if missing. Copy it from **Settings → API key** in the
dashboard, or from:

- Windows: `%ProgramData%\NetGuard\netguard.env`
- Pi: `/etc/netguard/netguard.env`

### Example (authenticated write)

```bash
curl -X PUT "http://127.0.0.1:8000/devices/192.168.1.50/trust" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY_HERE" \
  -d '{"is_trusted": true}'
```

## Interactive documentation

| URL | Description |
|-----|-------------|
| `/docs` | Swagger UI (OpenAPI) |
| `/redoc` | ReDoc |
| `/api` | JSON list of core endpoint paths |

## Syslog / SIEM export

Alerts can be forwarded in **RFC 5424** format to an external syslog collector
(Wazuh, Elastic, Splunk, rsyslog). Configure via **Settings → SIEM / Syslog** or
`netguard.env`:

```
NETGUARD_SYSLOG_ENABLED=true
NETGUARD_SYSLOG_HOST=192.168.1.10
NETGUARD_SYSLOG_PORT=514
NETGUARD_SYSLOG_PROTOCOL=udp
```

The `syslog-export` daemon polls new `alerts` rows every 30 seconds.

---

## Top integration endpoints

### 1. Device inventory

```bash
curl "http://127.0.0.1:8000/devices"
```

Returns all discovered devices with IP, MAC, vendor, risk level, trust/block status.

### 2. Single device

```bash
curl "http://127.0.0.1:8000/devices/192.168.1.42"
```

### 3. Risk summary

```bash
curl "http://127.0.0.1:8000/risk/summary"
```

Network-wide risk distribution and top five risky devices.

### 4. Security alerts

```bash
curl "http://127.0.0.1:8000/alerts/security"
```

All security incidents (ARP spoof, inbound, rogue DHCP, etc.).

### 5. New / offline device alerts

```bash
curl "http://127.0.0.1:8000/alerts"
```

### 6. DNS activity

```bash
curl "http://127.0.0.1:8000/dns"
curl "http://127.0.0.1:8000/dns/suspicious"
curl "http://127.0.0.1:8000/dns/summary"
```

### 7. Inbound connection attempts

```bash
curl "http://127.0.0.1:8000/inbound/192.168.1.42"
```

### 8. Open / dangerous ports

```bash
curl "http://127.0.0.1:8000/ports"
curl "http://127.0.0.1:8000/ports/dangerous"
```

### 9. Monitoring health

```bash
curl "http://127.0.0.1:8000/monitoring/status"
```

Detector services, last activity, and restart hints.

### 10. Block a device (requires API key)

```bash
curl -X POST "http://127.0.0.1:8000/enforcement/block/192.168.1.99" \
  -H "X-API-Key: YOUR_KEY_HERE"
```

---

## Endpoint reference

### Core (`api/main.py`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | No | API and database health probe |
| GET | `/system/info` | No | Host OS and block-capability hint |
| GET | `/devices` | No | All devices (`?include_blocked=true`) |
| GET | `/devices/new` | No | Devices first seen in 24h |
| GET | `/devices/{ip}` | No | Single device |
| GET | `/devices/{ip}/risk` | No | Risk detail for one device |
| PUT | `/devices/{ip}/tag` | Key | Set device tag |
| PUT | `/devices/{ip}/trust` | Key | Trust / untrust |
| PUT | `/devices/{ip}/block` | Key | Block flag (DB) |
| PUT | `/devices/id/{id}/trust` | Key | Trust by device id |
| PUT | `/devices/id/{id}/block` | Key | Block by device id |
| GET | `/risk/summary` | No | Aggregate risk stats |
| GET | `/alerts` | No | New + offline device alerts |
| GET | `/alerts/security` | No | Security alert log |
| GET | `/alerts/security/critical` | No | Critical severity only |
| GET | `/inbound/{ip}` | No | Inbound connection attempts |
| GET | `/dhcp/servers` | No | Rogue DHCP inventory |
| GET | `/dns` | No | Recent DNS queries |
| GET | `/dns/devices` | No | Per-device DNS summary |
| GET | `/dns/suspicious` | No | Flagged DNS only |
| GET | `/dns/summary` | No | Category totals per device |
| GET | `/ports` | No | All open ports |
| GET | `/ports/dangerous` | No | Dangerous ports only |
| GET | `/ports/{ip}` | No | Ports for one device |
| GET | `/ports/{port}/instructions` | No | How to close a port |
| GET | `/reference/cve/{port}` | No | CVE reference examples |
| GET | `/monitoring/status` | No | Detector health |
| POST | `/monitoring/restart/{id}` | Key | Restart a detector |
| GET | `/settings/api-key` | Key | View API key |
| POST | `/vault/unlock` | Key | Unlock password vault |
| POST | `/vault/add` | Key | Add credential |
| POST | `/vault/list` | Key | List credentials |
| DELETE | `/vault/{id}` | Key | Delete credential |

### Features router (`api/features.py`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/alerts/{id}/acknowledge` | Key | Acknowledge alert |
| PUT | `/alerts/{id}/false-positive` | Key | Mark false positive |
| POST | `/alerts/suppressions` | Key | Add suppression rule |
| GET | `/alerts/suppressions` | No | List suppressions |
| GET | `/devices/pending-approval` | No | Unapproved devices |
| PUT | `/devices/{ip}/approve` | Key | Approve device |
| PUT | `/devices/{ip}/reject` | Key | Reject device |
| PUT | `/devices/{ip}/profile` | Key | Update owner/profile |
| GET | `/devices/{ip}/timeline` | No | Device event timeline |
| POST | `/domains/block` | Key | Block domain in DNS |
| GET | `/domains/blocked` | No | Blocked domain list |
| GET | `/threat-intel/status` | No | Threat feed stats |
| POST | `/threat-intel/update` | Key | Refresh threat feed |
| GET | `/policies` | No | Security policies |
| PUT | `/policies/{id}` | Key | Enable/disable policy |
| POST | `/policies/evaluate` | Key | Run policy engine |
| GET | `/policies/violations` | No | Policy violations |
| GET | `/notifications/config` | No | Telegram/SMTP settings |
| PUT | `/notifications/config` | Key | Save notifications |
| POST | `/notifications/test` | Key | Send test alert |
| GET | `/settings/syslog` | No | Syslog/SIEM export settings |
| PUT | `/settings/syslog` | Key | Save syslog settings |
| GET | `/settings/router` | No | Router enforcement config |
| PUT | `/settings/router` | Key | Save router settings |
| POST | `/settings/router/test` | Key | Test router login |
| POST | `/settings/restart-api` | Key | Restart API service |
| POST | `/enforcement/block/{ip}` | Key | Block device (router/DNS) |
| POST | `/enforcement/unblock/{ip}` | Key | Unblock device |
| POST | `/enforcement/pause/{ip}` | Key | Timed router pause |
| GET | `/reports/summary` | No | Weekly stats JSON |
| POST | `/reports/weekly/send` | Key | Email weekly report |
| POST | `/reports/compliance/generate` | Key | Download GDPR PDF |

### MSP collector (`api/msp.py`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/heartbeat` | Site token | Managed-site heartbeat |
| GET | `/sites` | No | List registered sites |
| POST | `/sites/register` | MSP admin key | Register a site |

---

## Error responses

HTTP errors return JSON: `{"detail": "message"}`. Common codes:

| Code | Meaning |
|------|---------|
| 401 | Missing or invalid `X-API-Key` |
| 404 | Device or resource not found |
| 503 | Database unavailable or detector restart failed |

## Version

API version is reported in OpenAPI metadata (`1.2.0`). Check `/health` for
database path and bundled dashboard status.
