# schemas.py
from pydantic import BaseModel
from typing import List, Optional

class RunReportRequest(BaseModel):
    report_name: str = "Wazuh Security Report"
    date_mode: str = "preset"
    preset: Optional[str] = "last_month"
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    timezone: str = "Asia/Jakarta"
    top_n: int = 10
    dojo_product: str = "SOC-Wazuh"
    dojo_engagement: str = "Weekly Report"
    ddos_rule_mode: str = "group"
    ddos_rule_groups: List[str] = ["attack", "web", "accesslog"]
    finding_severity_scope: List[str] = ["Critical", "High"]
    intel_confidence_threshold: str = "high_only"
    output_format: str = "pdf"
