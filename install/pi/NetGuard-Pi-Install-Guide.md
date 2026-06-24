# NetGuard on a New Raspberry Pi — Installation Guide

**Version:** 1.0  
**Repository:** https://github.com/jibinmichael89-spec/netguard

---

## Overview

NetGuard is a home network security monitor for Raspberry Pi. It discovers devices on your LAN, scans open ports, scores risk, monitors DNS, and provides a web dashboard.

After installation:

- **Dashboard URL:** `http://<pi-ip-address>:8000`
- **Auto-start:** All core services start on boot via systemd
- **Install location:** `/opt/netguard`
- **Database:** `/var/lib/netguard/netguard.db`

### Services installed automatically

| Service | Purpose | Runs as |
|---------|---------|---------|
| netguard-api | Web dashboard + REST API (port 8000) | netguard |
| netguard-arp-scanner | Device discovery + port scanning | root |
| netguard-risk-scorer | Composite risk scoring | netguard |
| netguard-dns-monitor | DNS query capture | root |
| netguard-arp-spoof | ARP spoof / MAC change detection | netguard |

Optional (disabled by default):

| Service | Purpose |
|---------|---------|
| netguard-network-blocker | ARP isolation for blocked devices (limited on mesh WiFi) |

**New in v1.1:** Alerts page shows live **Monitoring Status** (last scan, detector health). ARP Spoof Guard suppresses mesh Wi-Fi false positives.

---

## Requirements

| Item | Details |
|------|---------|
| Hardware | Raspberry Pi 3, 4, or 5 with power supply |
| Operating system | Raspberry Pi OS (64-bit recommended) |
| Network | Pi connected to your home LAN (Ethernet recommended) |
| Access | SSH enabled, or keyboard + monitor |
| Internet | Required during install (apt, pip, npm) |

---

## Part 1 — Prepare the Raspberry Pi (One-Time Setup)

### Step 1: Flash Raspberry Pi OS

1. Download **Raspberry Pi Imager** from https://www.raspberrypi.com/software/
2. Flash **Raspberry Pi OS (64-bit)** to a microSD card
3. In Imager settings (gear icon), enable:
   - **SSH** (password or key authentication)
   - **Username and password** (example: user `netguard`)
   - **WiFi** (if not using Ethernet)
4. Insert the card, power on the Pi, and wait for it to boot

### Step 2: Find the Pi's IP address

From your PC:

```
ping raspberrypi.local
```

Or check your router's connected-devices list. Example IP: `192.168.1.71`

### Step 3: Connect via SSH

```
ssh netguard@192.168.1.71
```

Replace `netguard` with your username and use your Pi's IP address.

### Step 4: Update the operating system

```bash
sudo apt update
sudo apt upgrade -y
sudo reboot
```

SSH back in after the reboot completes.

---

## Part 2 — Install NetGuard

### Step 1: Install Git

```bash
sudo apt install -y git
```

### Step 2: Clone the repository

```bash
cd ~
git clone https://github.com/jibinmichael89-spec/netguard.git
cd netguard
```

### Step 3: Run the installer

```bash
chmod +x install/pi/install.sh install/pi/uninstall.sh
sudo install/pi/install.sh
```

The installer automatically:

1. Installs system packages (Python, Scapy, libpcap, iptables)
2. Creates the `netguard` system user if needed
3. Copies the application to `/opt/netguard`
4. Creates a Python virtual environment and installs dependencies
5. Builds the web dashboard (installs Node.js/npm if needed)
6. Creates data directories and configuration files
7. Installs and enables systemd services
8. Starts all core services immediately

**Expected install time:** 5–15 minutes (dashboard npm build is the slowest step).

### Step 4: Open the dashboard

When installation completes, the script prints your dashboard URL:

```
Dashboard: http://192.168.1.71:8000
```

Open that address in a browser on any device on your home network.

---

## Part 3 — Verify Installation

Run these commands on the Pi:

```bash
# Check all services
sudo systemctl status netguard.target

# Test API health endpoint
curl -s http://127.0.0.1:8000/health

# List discovered devices (may take 30–60 seconds on first run)
curl -s http://127.0.0.1:8000/devices
```

**Success indicators:**

- `netguard.target` shows all services as **active (running)**
- `/health` returns a successful response
- Devices appear in the dashboard within about one minute

---

## Part 4 — Day-to-Day Management

### Restart all NetGuard services

```bash
sudo systemctl restart netguard.target
```

### View live logs

```bash
sudo journalctl -u netguard-api -f
sudo journalctl -u netguard-arp-scanner -f
```

### Check service status

```bash
sudo systemctl status netguard-api
sudo systemctl status netguard-arp-scanner
sudo systemctl status netguard-risk-scorer
sudo systemctl status netguard-dns-monitor
```

---

## Optional Configuration

### DNS logging via dnsmasq

If your Pi runs dnsmasq as the LAN DNS server, add to `/etc/dnsmasq.conf`:

```
log-queries
log-facility=/var/log/netguard/dnsmasq.log
```

Then restart dnsmasq:

```bash
sudo systemctl restart dnsmasq
```

### Enable network block enforcer

```bash
sudo systemctl enable --now netguard-network-blocker.service
```

**Note:** On mesh WiFi systems (Linksys Velop, Eero, Orbi), ARP-based blocking is often ineffective. Use your router's parental controls or device-pause feature for guaranteed enforcement.

---

## Alternative Install Method — Offline Tarball

Use this when the Pi cannot clone from GitHub directly.

### On your development PC (with the repository):

```bash
cd netguard
chmod +x install/pi/build-release.sh
./install/pi/build-release.sh
scp dist/NetGuard-pi-*.tar.gz netguard@<pi-ip>:~/
```

### On the Raspberry Pi:

```bash
tar xzf NetGuard-pi-*.tar.gz
cd NetGuard-pi
chmod +x install.sh uninstall.sh
sudo ./install.sh
```

---

## Uninstall NetGuard

```bash
cd ~/netguard
sudo install/pi/uninstall.sh
```

To keep the database and logs:

```bash
sudo install/pi/uninstall.sh --keep-data
```

---

## File Locations Reference

| Item | Path |
|------|------|
| Application | `/opt/netguard` |
| Database | `/var/lib/netguard/netguard.db` |
| Logs | `/var/log/netguard/` |
| Environment config | `/etc/netguard/netguard.env` |
| Systemd units | `/etc/systemd/system/netguard-*.service` |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Dashboard won't load | Run `sudo systemctl status netguard-api` and check logs with `sudo journalctl -u netguard-api -n 50` |
| No devices in dashboard | Ensure `netguard-arp-scanner` is running; wait 60 seconds after boot |
| `install/pi/install.sh` not found | Run `git pull` in the repository to get the latest files |
| Port 8000 unreachable from other PCs | Check firewall: `sudo ufw allow 8000` (if ufw is enabled) |
| Block button doesn't stop internet | Expected on mesh WiFi; use router app to pause the device |

---

## Quick Install Cheat Sheet

```bash
sudo apt update && sudo apt install -y git
git clone https://github.com/jibinmichael89-spec/netguard.git
cd netguard
chmod +x install/pi/install.sh
sudo install/pi/install.sh
```

Then open: **http://\<pi-ip\>:8000**

---

*NetGuard — Home network security monitor*
