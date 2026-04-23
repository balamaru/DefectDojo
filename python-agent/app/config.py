# config.py
import os
from dotenv import load_dotenv

load_dotenv("/opt/wazuh-report-worker/.env")

class Settings:
    WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
    WAZUH_INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "")
    WAZUH_INDEXER_PASS = os.getenv("WAZUH_INDEXER_PASS", "")
    WAZUH_VERIFY_SSL = os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true"

    DEFECTDOJO_URL = os.getenv("DEFECTDOJO_URL", "")
    DEFECTDOJO_TOKEN = os.getenv("DEFECTDOJO_TOKEN", "")
    DEFECTDOJO_PRODUCT = os.getenv("DEFECTDOJO_PRODUCT", "SOC-Wazuh")
    DEFECTDOJO_ENGAGEMENT = os.getenv("DEFECTDOJO_ENGAGEMENT", "Weekly Report")
    DEFECTDOJO_VERIFY_SSL = os.getenv("DEFECTDOJO_VERIFY_SSL", "false").lower() == "true"

    VT_API_KEY = os.getenv("VT_API_KEY", "")
    OTX_API_KEY = os.getenv("OTX_API_KEY", "")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

    DEFAULT_TIMEZONE = os.getenv("DEFAULT_TIMEZONE", "Asia/Jakarta")
    DEFAULT_TOP_N = int(os.getenv("DEFAULT_TOP_N", "10"))
    DEFAULT_OUTPUT_FORMAT = os.getenv("DEFAULT_OUTPUT_FORMAT", "pdf")
    DEFAULT_DDOS_RULE_MODE = os.getenv("DEFAULT_DDOS_RULE_MODE", "group")
    DEFAULT_SEVERITY_SCOPE = os.getenv("DEFAULT_SEVERITY_SCOPE", "Critical,High")
    DEFAULT_TI_THRESHOLD = os.getenv("DEFAULT_TI_THRESHOLD", "high_only")

    # field score default untuk vulnerability
    VULN_SCORE_FIELD = os.getenv("VULN_SCORE_FIELD", "vulnerability.score.base")

settings = Settings()
