# NetGuard

Home network security monitor for Raspberry Pi. NetGuard continuously scans your local network using ARP, tracks every device, and exposes the data through a REST API.

## Project Structure

```
netguard/
├── daemon/
│   └── scanner/
│       └── arp_scanner.py   # Continuous ARP network scanner
├── api/
│   └── main.py              # FastAPI REST server
├── requirements.txt
├── README.md
└── netguard.db              # Created automatically on first scan
```

## Requirements

- Python 3.10+
- Raspberry Pi (or any Linux host) on your local network
- Root/sudo privileges (required for raw ARP socket access)

## Installation

```bash
cd netguard
python3 -m venv venv
source venv/bin/activate        # Linux / Pi
pip install -r requirements.txt
```

## Usage

### 1. Start the ARP Scanner

The scanner must run with elevated privileges:

```bash
sudo python3 daemon/scanner/arp_scanner.py
```

The scanner will:

- Auto-detect your local subnet
- Send ARP requests to find active devices every 30 seconds
- Look up vendor names and hostnames for each device
- Save results to `netguard.db`
- Print a formatted table to the console
- Tag new devices with `[NEW]` and missing devices with `[OFFLINE]`

### 2. Start the API Server

In a separate terminal:

```bash
python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8000
```

Or from the `api/` directory:

```bash
cd api
python3 main.py
```

### 3. Query the API

| Endpoint           | Description                              |
|--------------------|------------------------------------------|
| `GET /devices`     | All discovered devices                   |
| `GET /devices/new` | Devices first seen in the last 24 hours  |
| `GET /alerts`      | New and offline device alerts            |

Example:

```bash
curl http://localhost:8000/devices
curl http://localhost:8000/devices/new
curl http://localhost:8000/alerts
```

Interactive API docs are available at [http://localhost:8000/docs](http://localhost:8000/docs).

## Device Data

Each device record includes:

| Field         | Description                          |
|---------------|--------------------------------------|
| `ip_address`  | Current IP on the network            |
| `mac_address` | Hardware MAC address (unique key)    |
| `vendor`      | Manufacturer from MAC OUI lookup       |
| `hostname`    | Reverse DNS hostname (if available)  |
| `first_seen`  | UTC timestamp of first discovery     |
| `last_seen`   | UTC timestamp of most recent sighting|
| `status`      | `online` or `offline`                |

## Notes

- ARP scanning requires root because Scapy uses raw sockets.
- MAC vendor lookup uses [macvendors.com](https://macvendors.com) and is rate-limited on free tier; lookups are cached in the database after the first scan.
- Hostname resolution depends on reverse DNS being configured on your network.
- The API returns HTTP 503 until the scanner has created `netguard.db`.
