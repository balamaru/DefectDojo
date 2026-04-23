# main.py
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pathlib import Path
from app.schemas import RunReportRequest
from app.report_runner import run_report_real_vuln
from app.config import settings
import requests

app = FastAPI(title="Wazuh Report Worker")

OUTPUT_DIR = Path("/opt/wazuh-report-worker/output")

@app.get("/health")
def health():
    try:
        r = requests.get(
            f"{settings.WAZUH_INDEXER_URL}/_cluster/health",
            auth=(settings.WAZUH_INDEXER_USER, settings.WAZUH_INDEXER_PASS),
            verify=False,
            timeout=10
        )
        return {
            "status": "ok",
            "indexer_health_http": r.status_code,
            "dojo_product": settings.DEFECTDOJO_PRODUCT,
            "dojo_engagement": settings.DEFECTDOJO_ENGAGEMENT
        }
    except Exception as e:
        return {
            "status": "degraded",
            "error": str(e)
        }

@app.post("/run-report")
def run_report(req: RunReportRequest):
    try:
        return run_report_real_vuln(req.model_dump())
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/download/{filename}")
def download_file(filename: str):
    file_path = OUTPUT_DIR / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(path=file_path, filename=filename, media_type="application/octet-stream")
