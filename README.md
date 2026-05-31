# LEGION n8n Shield

Free CLI security audit tool for self-hosted n8n instances.

## What it checks

- n8n version exposure against recent critical CVEs
- public reachability
- missing security headers
- Docker Compose risks
- SQLite usage in production
- missing Docker volumes
- exposed port 5678
- missing restart policy
- missing N8N_ENCRYPTION_KEY

## Usage

```bash
pip install httpx
python3 legion_n8n_audit.py --host https://your-n8n-domain.com
python3 legion_n8n_audit.py --host https://your-n8n-domain.com --compose ./docker-compose.yml
```

## Example output

```
SECURITY SCORE: 24/100

CRITICAL:
- No Docker volumes

HIGH:
- SQLite detected in production
- Port 5678 directly exposed

MEDIUM:
- Missing restart policy
- Missing N8N_ENCRYPTION_KEY
```

## Services

If your score is low and you need help fixing it:

- Written Audit Report — €199
- Emergency Hardening — €750
- Full Secure Setup — €1,500
- Monthly Maintenance — €300/month

Contact: api@legion-api.com
Site: https://legion-api.com
