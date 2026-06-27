# NetGuard — Windows Home (single user)

For one household PC running NetGuard locally. No MSP central reporting.

## Requirements

- Windows 10/11 (64-bit)
- [Npcap](https://npcap.com) installed
- Administrator rights for install

## Install

1. Build or download NetGuard exes (see repo `build/exe/` or run `build\windows\build-installer.ps1`).

2. From an **Administrator** PowerShell in the repo root:

```powershell
.\install\profiles\windows-home\install.ps1 -InstallDir "C:\Program Files\NetGuard"
```

3. Double-click **START-NetGuard.bat** (or the Start Menu shortcut).

4. Open: **http://localhost:8000**

## What gets configured

- Database: `%LOCALAPPDATA%\NetGuard\netguard.db`
- Device approval for new devices: **enabled**
- MSP heartbeat: **disabled**
- All v1.2 background services started via `START-NetGuard.bat`

## Optional settings

Edit `%LOCALAPPDATA%\NetGuard\netguard.env` after install, or set User environment variables:

| Variable | Purpose |
|----------|---------|
| `NETGUARD_TELEGRAM_BOT_TOKEN` | Telegram alerts |
| `NETGUARD_ALERT_EMAIL_TO` | Email alerts |
| `NETGUARD_API_KEY` | Protect write API endpoints |

Configure notifications in the dashboard **Settings** tab.

## Uninstall

Use **Add/Remove Programs** → NetGuard, or run `NetGuard-Uninstall.exe`.
