# NetGuard — Windows MSP (managed site)

For a Windows PC at a **customer site** managed by an MSP. Sends heartbeats to your central NetGuard collector.

## Requirements

- Windows 10/11 (64-bit)
- Npcap installed
- MSP collector URL and site token from your provider

## Before you install

Your MSP operator must give you:

| Value | Example |
|-------|---------|
| `NETGUARD_MSP_COLLECTOR_URL` | `https://msp.yourcompany.com:8000` |
| `NETGUARD_SITE_TOKEN` | `secret-token-for-this-site` |
| `NETGUARD_SITE_ID` | `customer-smith-home` |

## Install

1. Edit `netguard.env` in this folder — set collector URL, site token, and site ID.

2. Administrator PowerShell from repo root:

```powershell
cd C:\Users\jibin\netguard
.\build\windows\build-installer.ps1
.\install\profiles\windows-msp\install.ps1
```

Installs to `C:\Program Files\NetGuard` by default.

3. Run `START-NetGuard.bat` and open **http://localhost:8000**

## What gets configured

- Same local dashboard and scanners as Home profile
- Install dir: `C:\Program Files\NetGuard`
- Database: `%ProgramData%\NetGuard\netguard.db`
- **Scheduled task** `NetGuard MSP Heartbeat` runs every 5 minutes
- Heartbeat POSTs to `{collector}/msp/api/v1/heartbeat`
- **Settings → Router** — configure router enforcement in the dashboard
- **Save & restart API** — applies settings without manual restart

## MSP central server (for operators)

On your **central** NetGuard server (not at customer sites), set:

```
NETGUARD_MSP_ADMIN_KEY=your-admin-secret
NETGUARD_MSP_SITE_TOKENS=customer-smith-home:token1,office-acme:token2
```

Open the **MSP** tab to see all sites.

## Uninstall

Remove NetGuard via Add/Remove Programs. The install script removes the heartbeat scheduled task.
