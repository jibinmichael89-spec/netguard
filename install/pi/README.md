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
