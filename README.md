# Security Reporting with Wazuh and DefectDojo

Wazuh is widely recognized as a powerful security platform capable of detecting threats across all managed agents. In this project, I utilize DefectDojo as a vulnerability management platform to consolidate threat analysis and generate structured reports.

While DefectDojo’s native reporting is limited to HTML format, certain administrative or legal requirements often necessitate PDF documentation. To bridge this gap, I have implemented a Python-based automation script to handle the conversion and generation of these PDF reports.

## 1. How to Generate a PDF Report
To begin, you must activate the virtual environment and install the required dependencies, then initialize the FastAPI server.
```sh
# Activate virtual environment and install dependencies
source venv/bin/activate
pip install fastapi uvicorn python-dotenv requests jinja2 reportlab pydantic matplotlib

# Start the application (from the app/ directory)
uvicorn app.main:app --host 0.0.0.0 --port 8008
```
Health check, Verify that the service is running correctly:
```sh
curl http://localhost:8008/health | python3 -m json.tool
```
Triggering a Report, You can trigger report generation via an HTTP POST request. Below are two common methods:
```sh
# Preset Mode (Last Month)
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

# Custom Mode (Specific Date Range)
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
he generated PDF will be saved in the **output/** directory, for example: **~/app/output/wazuh_report_2026-04-23_08-52-19.pdf**.

## 2. Next Steps & Deployment Options
To move this project into production, consider the following deployment strategies:
- Automation: Schedule the script using CronJobs.
- SOAR Integration (Advanced): Use Shuffle to trigger the HTTP POST payload as part of an automated workflow.
- Containerization (Recommended): Package the application as a Docker container for better portability.
- Systemd Service (Optional): Run the application as a background service on Linux.

Configuration for Systemd, To set up the script as a system service, create the following unit file:
```sh
# Create Systemd service file
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

# Enable and start the service
systemctl daemon-reload
systemctl enable --now wazuh-report-worker
systemctl status wazuh-report-worker
```