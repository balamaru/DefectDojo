# Security Report WIth Wazuh and DefectDojo

Everybody knows that Wazuh was an powerful security tools, Wazuh can detect all treat in all of Wazuh agents. Here i would like to use DefectDojo as an vulnerability management platform to register all treat analys and made an reports, DefectDojo having limitation where it only made report as HTML file based, it was good, but for some reason adn reporting somtimes we wanna made it as legal document like file in pdf format, and i will use python script to handle it.

## 1. How To Made an pdf Report
The first thing we must to to is running the pytho script
```sh
source venv/bin/activate
pip install fastapi uvicorn python-dotenv requests jinja2 reportlab pydantic matplotlib

# Run the python script
# in app/ directory
uvicorn app.main:app --host 0.0.0.0 --port 8008
```
Health check
```sh
curl http://localhost:8008/health | python3 -m json.tool
```
Trigger report
```sh
# Preset Mode (last month)
curl -X POST "http://localhost:8008/run-report" \
  -H "Content-Type: application/json" \
  -d '{
    "report_name": "Wazuh Security Report",
    "date_mode": "preset",
    "preset": "last_month",
    "timezone": "Asia/Jakarta",
    "top_n": 10,
    "dojo_product": "SOC-Wazuh",
    "dojo_engagement": "Weekly Report",
    "ddos_rule_mode": "group",
    "ddos_rule_groups": ["ddos", "flood", "suricata"],
    "finding_severity_scope": ["Critical", "High"],
    "intel_confidence_threshold": "high_only",
    "output_format": "pdf"
  }' | python3 -m json.tool

# Custom Mode (Spesify date)
curl -X POST "http://localhost:8008/run-report" \
  -H "Content-Type: application/json" \
  -d '{
    "report_name": "Wazuh Security Report",
    "date_mode": "custom",
    "start_date": "2026-04-01",
    "end_date": "2026-04-22",
    "timezone": "Asia/Jakarta",
    "top_n": 10,
    "dojo_product": "SOC-Wazuh",
    "dojo_engagement": "Weekly Report",
    "ddos_rule_mode": "group",
    "ddos_rule_groups": ["ddos", "flood", "suricata"],
    "finding_severity_scope": ["Critical", "High"],
    "intel_confidence_threshold": "high_only",
    "output_format": "pdf"
  }' | python3 -m json.tool
```
The pdf result will be shown at output/ directory, like **~/app/output/wazuh_report_2026-04-23_08-52-19.pdf**.

## 2. What Next?
- (Normally) Schedulling with CronJob, or
- (Advanced) Integrate with Shuffle as trigger HTTP POST of payload
- (Recommended) Made as container, or
- (Optional) Create Service as systemd
```sh
# Create Systemd service
cat << EOF || sudo tee /etc/systemd/system/wazuh-report-worker.service 
[Unit]
Description=Wazuh Report Worker
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/wazuh-report-worker
ExecStart=/opt/wazuh-report-worker/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8008
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Run as systemd
systemctl daemon-reload
systemctl enable --now wazuh-report-worker
systemctl status wazuh-report-worker
```