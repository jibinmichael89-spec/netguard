# NetGuard — Raspberry Pi MSP (managed site)

For a Raspberry Pi at a **customer site** managed by an MSP. Sends heartbeats to your central NetGuard collector every 5 minutes.

## Before you install

Your MSP operator must provide:

| Value | Example |
|-------|---------|
| `NETGUARD_MSP_COLLECTOR_URL` | `https://msp.yourcompany.com:8000` |
| `NETGUARD_SITE_TOKEN` | `secret-token-for-this-site` |
| `NETGUARD_SITE_ID` | `customer-smith-pi` |

## Install

1. Edit `netguard.env` in this folder — set collector URL, site token, and site ID.

```bash
cd ~/netguard
git pull
sudo install/profiles/pi-msp/install.sh
```

## After install

- Local dashboard: **http://\<pi-ip\>:8000**
- Verify MSP agent: `systemctl list-timers | grep msp`
- Test heartbeat: `sudo /opt/netguard/venv/bin/python /opt/netguard/daemon/msp/agent_client.py`

## What gets configured

- Everything in the Home profile, plus:
- `netguard-msp-agent.timer` — heartbeat every 5 minutes
- Site appears on central server **MSP** tab after first heartbeat

## MSP central server (for operators)

On your **central** NetGuard Pi or server:

```bash
# /etc/netguard/netguard.env
NETGUARD_MSP_ADMIN_KEY=your-admin-secret
NETGUARD_MSP_SITE_TOKENS=customer-smith-pi:token1,office-acme:token2
```

Register additional sites:

```bash
curl -X POST http://localhost:8000/msp/sites/register \
  -H "X-API-Key: your-admin-secret" \
  -H "Content-Type: application/json" \
  -d '{"site_id":"new-site","site_name":"Customer Name","token":"unique-token"}'
```

Open **http://\<central-ip\>:8000/#/msp** to monitor all sites.
