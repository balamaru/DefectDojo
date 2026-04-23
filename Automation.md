# Automated Reporting with Systemd
Reports are automatically generated every Friday at 12:00 PM (WIB/Jakarta Time). This automation is handled by three Systemd components

- **Systemd Service (Worker)**: Keeps the Uvicorn worker running continuously.
- **Systemd Service (Generator)**: A one-shot service that executes the curl POST request to trigger the report.
- **Systemd Timer**: Triggers the Generator service every Friday.

## 1. Worker Service (Continuous)
This service ensures the FastAPI application is always available to handle report requests.
```sh
cat << EOF || sudo tee /etc/systemd/system/wazuh-report-worker.service
[Unit]
Description=Wazuh Report Worker
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
Group=$GROUP
WorkingDirectory=$HOME/wazuh-report-worker
ExecStart=$HOME/wazuh-report-worker/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8008
Restart=always
RestartSec=10
StandardOutput=append:$HOME/wazuh-report-worker/logs/worker.log
StandardError=append:$HOME/wazuh-report-worker/logs/worker.log

[Install]
WantedBy=multi-user.target
EOF
```

## 2. Report Generation Service (One-Shot)
This service is triggered by the timer to send the reporting payload to the worker.
```sh
cat << EOF || sudo tee /etc/systemd/system/wazuh-report-generate.service
[Unit]
Description=Wazuh Weekly Report Generator
After=wazuh-report-worker.service
Requires=wazuh-report-worker.service

[Service]
Type=oneshot
User=$USER
Group=$GROUP
WorkingDirectory=$HOME/wazuh-report-worker

# Wait for worker ready (grace period 10 seconds)
ExecStartPre=/bin/sleep 10

ExecStart=/usr/bin/curl -s -X POST "http://localhost:8008/run-report" \
    -H "Content-Type: application/json" \
    -d '{ \
        "report_name": "Wazuh Weekly Security Report", \
        "date_mode": "preset", \
        "preset": "last_7_days", \
        "timezone": "Asia/Jakarta", \
        "top_n": 10, \
        "dojo_product": "SOC-Wazuh", \
        "dojo_engagement": "Weekly Report", \
        "ddos_rule_mode": "group", \
        "ddos_rule_groups": ["ddos", "flood", "suricata"], \
        "finding_severity_scope": ["Critical", "High"], \
        "intel_confidence_threshold": "high_only", \
        "output_format": "pdf" \
    }' \
    --output $HOME/wazuh-report-worker/logs/last_report_response.json \
    --max-time 600

StandardOutput=append:$HOME/wazuh-report-worker/logs/generate.log
StandardError=append:$HOME/wazuh-report-worker/logs/generate.log
EOF
```

## 3. Systemd Timer (Weekly Schedule)
The timer is set to fire every Friday at 12:00 PM WIB (05:00 UTC).
```sh
cat << EOF || sudo tee /etc/systemd/system/wazuh-report-generate.timer
[Unit]
Description=Wazuh Weekly Report — Every Friday 08:00 WIB
Requires=wazuh-report-worker.service

[Timer]
# 12:00 WIB = 05:00 UTC (WIB = UTC+7)
OnCalendar=Fri *-*-* 05:00:00 UTC
Persistent=true
Unit=wazuh-report-generate.service

[Install]
WantedBy=timers.target
EOF
```

## 4. Activation
Reload the Systemd daemon and enable the services:
```sh
sudo systemctl daemon-reload

# Start and enable the worker
sudo systemctl enable --now wazuh-report-worker.service

# Enable the timer to automate Friday reports
sudo systemctl enable --now wazuh-report-generate.timer
```

## 5. Verification
To verify the setup and check the next scheduled execution:
```sh
# Check worker status
sudo systemctl status wazuh-report-worker.service

# Check registered timer status
systemctl list-timers wazuh-report-generate.timer

# View all Wazuh-related timers
systemctl list-timers --all | grep wazuh
```
Output list-timers will show:
```sh
NEXT                        LEFT LAST                        PASSED UNIT                        ACTIVATES
Fri 2026-04-24 12:00:00 WIB  22h Thu 2026-04-23 13:41:29 WIB      - wazuh-report-generate.timer wazuh-report-generate.service

1 timers listed.
Pass --all to see loaded but inactive timers, too.
```

Manual Trigger (Testing), To test the report generation immediately without waiting for Friday:
```sh
# Manually trigger the generation service
sudo systemctl start wazuh-report-generate.service

# Verify the output
cat $HOME/wazuh-report-worker/logs/last_report_response.json | python3 -m json.tool
ls -la $HOME/wazuh-report-worker/output/
```