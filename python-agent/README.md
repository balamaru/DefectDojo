## 1. Directory Set Up
```sh
mkdir -p $HOME/wazuh-report-worker/{app,output,logs,tmp}
cd $HOME/wazuh-report-worker
python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn python-dotenv requests jinja2 reportlab pydantic matplotlib
touch app/__init__.py
```

## 2. API KEYS Source
### 2.1 VT_API_KEY
This is [VirusTotal](https://www.virustotal.com)
- Free tier: 500 request/day, 4 request/minute

### 2.2 OTX_API_KEY
This is [AlienVault OTX](https://otx.alienvault.com)
- Free, no limitation for lookup ip

### 2.3 ABUSEIPDB_API_KEY
This is [AbuseIPDB ](https://www.abuseipdb.com), after login need to [open this tab](https://www.abuseipdb.com/account/api)
- Free tier: 1000 request/day