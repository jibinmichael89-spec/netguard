# NetGuard — Windows Home (single user)

For one household PC running NetGuard locally. No MSP central reporting.

## Requirements

- Windows 10/11 (64-bit)
- [Npcap](https://npcap.com) installed
- Npcap installed (required for DNS/DHCP/inbound packet capture)
- Administrator rights for install

## Install

1. Build or download NetGuard exes (see repo `build/exe/` or run `build\windows\build-installer.ps1`).

2. From an **Administrator** PowerShell in the repo root:

```powershell
cd C:\Users\jibin\netguard
.\build\windows\build-installer.ps1
.\install\profiles\windows-home\install.ps1
```

This installs to `C:\Program Files\NetGuard` by default.

3. Double-click **START-NetGuard.bat** (or the Start Menu shortcut if you used NetGuard-Setup.exe).

4. Open: **http://localhost:8000**

## What gets configured

- Install dir: `C:\Program Files\NetGuard`
- Database: `%ProgramData%\NetGuard\netguard.db`
- Config: `%ProgramData%\NetGuard\netguard.env`
- Device approval for new devices: **enabled**
- MSP heartbeat: **disabled**
- All v1.2 background services started at boot via scheduled task (hidden, no console windows)
- Engine logs: `%ProgramData%\NetGuard\logs\`
- **Settings → Router** — configure router block/unblock in the dashboard
- **Save & restart API** — applies router settings without manual restart

## Optional settings

Edit `%ProgramData%\NetGuard\netguard.env` after install, or use the dashboard **Settings** tab for notifications and router enforcement.

| Variable | Purpose |
|----------|---------|
| `NETGUARD_TELEGRAM_BOT_TOKEN` | Telegram alerts (or use Settings UI) |
| `NETGUARD_ALERT_EMAIL_TO` | Email alerts (or use Settings UI) |
| `NETGUARD_API_KEY` | Protect write API endpoints |
| `NETGUARD_ROUTER_*` | Optional env override for router (dashboard preferred) |

Configure notifications and router enforcement in the dashboard **Settings** tab.

## Uninstall

Use **Add/Remove Programs** → NetGuard, or run `NetGuard-Uninstall.exe`.
