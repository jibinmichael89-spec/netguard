# NetGuard — Raspberry Pi Installation

One-command install with **systemd** auto-start on boot.

## What gets installed

| Service | Purpose | Runs as |
|---------|---------|---------|
| `netguard-api` | Dashboard + REST API (`:8000`) | `netguard` |
| `netguard-arp-scanner` | Device discovery + port scans | `root` |
| `netguard-risk-scorer` | Risk scoring | `netguard` |
| `netguard-dns-monitor` | DNS capture (Scapy + dnsmasq log) | `root` |
| `netguard-arp-spoof` | ARP spoof / MAC change detection | `netguard` |

Optional SIEM export:

| Service | Purpose |
|---------|---------|
| `netguard-syslog-export` | RFC 5424 syslog (when `NETGUARD_SYSLOG_ENABLED=true`) |
| `netguard-sentinel-export` | Microsoft Sentinel HTTP API (when `NETGUARD_SENTINEL_WORKSPACE_ID` is set) |

Optional (disabled by default):

| Service | Purpose |
|---------|---------|
| `netguard-network-blocker` | ARP isolation for blocked devices |

Data: `/var/lib/netguard/netguard.db`  
Logs: `/var/log/netguard/`

---

## Option A — Build release tarball (on dev machine)

```bash
cd netguard
chmod +x install/pi/build-release.sh
./install/pi/build-release.sh
```

Creates: `dist/NetGuard-pi-YYYY.MM.DD.tar.gz` (includes pre-built dashboard and PDF install guide)

Copy to Pi and install:

```bash
scp dist/NetGuard-pi-*.tar.gz netguard@192.168.1.71:~/
ssh netguard@192.168.1.71
tar xzf NetGuard-pi-*.tar.gz
cd NetGuard-pi
chmod +x install.sh uninstall.sh
sudo ./install.sh
```

Open: `http://<pi-ip>:8000`

---

## Option B — Install directly from git clone on Pi

```bash
cd ~/netguard
chmod +x install/pi/install.sh install/pi/uninstall.sh
sudo install/pi/install.sh
```

---

## Update an existing Pi install

On your **dev machine**, build a new release:

```bash
./install/pi/build-release.sh
```

Copy to the Pi and update **in place** (keeps database and `/etc/netguard/netguard.env`):

```bash
scp dist/NetGuard-pi-*.tar.gz netguard@192.168.1.71:~/
ssh netguard@192.168.1.71
tar xzf NetGuard-pi-*.tar.gz
cd NetGuard-pi
sudo ./install/pi/update-netguard.sh
```

---

## Microsoft Sentinel auto-export

1. Get **Workspace ID** and **Primary Key** from Azure Portal → Log Analytics workspace → Agents.

2. On the Pi (one-time):

```bash
sudo /opt/netguard/install/pi/setup-sentinel-export.sh \
  "your-workspace-guid" \
  "your-primary-key"
```

This writes credentials to `/etc/netguard/netguard.env` and starts `netguard-sentinel-export.service`.

New alerts export every **60 seconds**. Verify:

```bash
sudo systemctl status netguard-sentinel-export
sudo journalctl -u netguard-sentinel-export -f
```

After a software update (`update-netguard.sh`), Sentinel restarts automatically if credentials are already in `netguard.env`.

---

## After install

```bash
# Status of all services
sudo systemctl status netguard.target

# Restart everything
sudo systemctl restart netguard.target

# Follow API logs
sudo journalctl -u netguard-api -f

# Enable network blocker (optional — limited on mesh WiFi)
sudo systemctl enable --now netguard-network-blocker.service
```

---

## Uninstall

```bash
sudo install/pi/uninstall.sh          # removes app + data
sudo install/pi/uninstall.sh --keep-data   # keeps database/logs
```

---

## dnsmasq log (optional)

To feed DNS queries from dnsmasq into NetGuard, point dnsmasq at:

```
log-queries
log-facility=/var/log/netguard/dnsmasq.log
```

Ensure the `netguard` user can read the log file (installer sets `664` on the log).

---

## Custom install path

```bash
sudo NETGUARD_INSTALL_DIR=/home/netguard/netguard install/pi/install.sh
```

Update systemd `WorkingDirectory` paths if you change the install directory.
