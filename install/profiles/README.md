# NetGuard deployment profiles

NetGuard ships four ready-made configuration sets for different users and platforms.

| Profile | Path | Who it's for |
|---------|------|----------------|
| **Windows Home** | `windows-home/` | Single home user on Windows 10/11 |
| **Windows MSP** | `windows-msp/` | Managed Windows PC at a customer site (reports to MSP) |
| **Pi Home** | `pi-home/` | Single home user on Raspberry Pi |
| **Pi MSP** | `pi-msp/` | Managed Pi at a customer site (reports to MSP) |

## Quick start

### Raspberry Pi

```bash
# Home user
sudo NETGUARD_PROFILE=home install/profiles/pi-home/install.sh

# MSP-managed site
sudo NETGUARD_PROFILE=msp install/profiles/pi-msp/install.sh
```

### Windows

```powershell
# Home user (run as Administrator)
.\install\profiles\windows-home\install.ps1

# MSP-managed site (run as Administrator)
.\install\profiles\windows-msp\install.ps1
```

## Home vs MSP

| Feature | Home | MSP |
|---------|------|-----|
| Local dashboard | Yes | Yes |
| Device approval | Yes | Yes |
| Weekly email report | Yes | Yes |
| MSP heartbeat to central server | No | Yes (every 5 min) |
| MSP Sites dashboard tab | Local only | Central collector shows all sites |

## MSP central collector

The **MSP operator** runs one central NetGuard instance (any profile + these env vars):

```bash
NETGUARD_MSP_ADMIN_KEY=your-secret-admin-key
NETGUARD_MSP_SITE_TOKENS=site1:token1,site2:token2
```

Register sites via `POST /msp/sites/register` or pre-define tokens above.
Open the **MSP** tab on the central dashboard to see all customer sites.

## Files in each profile

Each folder contains:

- `netguard.env` — environment template for this profile
- `README.md` — step-by-step install guide
- `install.sh` or `install.ps1` — profile-specific installer wrapper
