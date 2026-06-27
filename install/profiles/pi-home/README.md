# NetGuard — Raspberry Pi Home (single user)

For one household running NetGuard on a dedicated Raspberry Pi. No MSP central reporting.

## Requirements

- Raspberry Pi 4/5 (2 GB+ RAM recommended)
- Raspberry Pi OS (64-bit)
- Ethernet connection to your router (recommended)

## Install

```bash
cd ~/netguard
git pull
sudo install/profiles/pi-home/install.sh
```

Or explicitly:

```bash
sudo NETGUARD_PROFILE=home install/pi/install.sh
```

## After install

- Dashboard: **http://\<pi-ip\>:8000**
- Check services: `sudo systemctl status netguard.target`
- Logs: `sudo journalctl -u netguard-api -f`

## What gets configured

- Install path: `/opt/netguard`
- Database: `/var/lib/netguard/netguard.db`
- Config: `/etc/netguard/netguard.env`
- Device approval: **enabled**
- MSP heartbeat timer: **disabled**
- Weekly email report: **enabled** (Mondays 08:00)

## Optional settings

Edit `/etc/netguard/netguard.env` or use the dashboard **Settings** tab for notifications, threat intel, and policies.

Router block (OpenWrt / Linksys):

```bash
NETGUARD_ROUTER_TYPE=openwrt
NETGUARD_ROUTER_URL=http://192.168.1.1
NETGUARD_ROUTER_USER=root
NETGUARD_ROUTER_PASSWORD=yourpassword
```

Then: `sudo systemctl restart netguard.target`
