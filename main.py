"""FastAPI orchestrator + live HTML dashboard for the API Security Scanner."""
import os, sys, json, time, uuid, threading
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.discovery.api_discovery import APIDiscovery
from core.scanner.vuln_scanner import APIVulnerabilityScanner
from core.ai_risk.risk_engine import AIRiskAssessmentEngine
from reports.report_generator import generate_report

app = FastAPI(title="AI-Driven Adaptive API Security Scanner", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

LATEST_REPORT: Dict[str, Any] = {}
SCAN_JOBS: Dict[str, Dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()

class DiscoveryRequest(BaseModel):
    target_url: Optional[str] = Field(None, example="http://127.0.0.1:8888")
    spec_url: Optional[str] = Field(None, example="http://127.0.0.1:8888/openapi.json")
    spec_file_path: Optional[str] = None

class ScanRequest(BaseModel):
    target_url: str = Field("http://127.0.0.1:8888")
    endpoints: Optional[List[Dict[str, Any]]] = None

class AssessRequest(BaseModel):
    findings: List[Dict[str, Any]]

class FullPipelineRequest(BaseModel):
    target_url: str = Field("http://127.0.0.1:8888")
    spec_url: Optional[str] = None

class StartScanRequest(BaseModel):
    target_url: str = Field("http://127.0.0.1:8888")
    spec_url: Optional[str] = None

FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

@app.get("/")
def dashboard_home():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

@app.get("/dashboard")
def dashboard_alias():
    return dashboard_home()

def _load_latest_report():
    data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
    for name in ["latest_pipeline_report.json", "final_assessment_report.json"]:
        path = os.path.join(data_dir, name)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8-sig") as f:
                    data = json.load(f)
                if "risk_assessment" in data:
                    return data
                if "assessment" in data:
                    return {"target_url": data.get("target_url", "http://127.0.0.1:8888"),
                            "discovery_summary": data.get("discovery", {}),
                            "vulnerability_scan": data.get("scan", {}),
                            "risk_assessment": data.get("assessment", {})}
            except Exception:
                pass
    return {"status": "baseline", "message": "No live scan executed yet."}

@app.get("/api/reports/latest")
def get_latest_report():
    if LATEST_REPORT:
        return LATEST_REPORT
    return _load_latest_report()

@app.get("/api/reports/pdf")
def download_latest_pdf():
    report = get_latest_report()
    if report.get("status") == "baseline":
        raise HTTPException(404, "No security report available. Run a scan first.")
    try:
        return FileResponse(generate_report(report), media_type="application/pdf", filename="API_Security_Report.pdf")
    except Exception as e:
        raise HTTPException(500, f"Could not generate PDF: {e}")

@app.post("/api/discover")
def discover_endpoints(req: DiscoveryRequest):
    discovery = APIDiscovery()
    try:
        if req.spec_file_path:
            return discovery.load_spec_from_file(os.path.abspath(req.spec_file_path))
        if req.spec_url:
            return discovery.load_spec_from_url(req.spec_url)
        if req.target_url:
            return discovery.probe_live_api(req.target_url)
        raise HTTPException(400, "Provide target_url, spec_url, or spec_file_path.")
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/api/scan")
def run_scan(req: ScanRequest):
    endpoints = req.endpoints
    if not endpoints:
        endpoints = APIDiscovery().probe_live_api(req.target_url)["endpoints"]
    return APIVulnerabilityScanner(base_url=req.target_url).run_full_scan(endpoints)

@app.post("/api/assess")
def assess_risk(req: AssessRequest):
    return AIRiskAssessmentEngine().assess_findings(req.findings)

def _set_job(job_id, **updates):
    with JOBS_LOCK:
        SCAN_JOBS[job_id].update(updates)

def _run_pipeline_job(job_id: str, target_url: str, spec_url: Optional[str]):
    global LATEST_REPORT
    try:
        _set_job(job_id, status="running", phase="Discovery", progress=10, message="Discovering API endpoints...")
        discovery = APIDiscovery()
        if spec_url:
            disc_res = discovery.load_spec_from_url(spec_url)
        else:
            disc_res = discovery.probe_live_api(target_url)
        _set_job(job_id, phase="Discovery", progress=25,
                 message=f"Discovery complete: {disc_res['total_endpoints']} endpoints found",
                 endpoints_found=disc_res["total_endpoints"])

        def progress(message, percent):
            _set_job(job_id, phase="Vulnerability Scan", progress=percent, message=message)

        scanner = APIVulnerabilityScanner(base_url=target_url, progress_callback=progress)
        scan_report = scanner.run_full_scan(disc_res["endpoints"])
        _set_job(job_id, phase="AI Risk Assessment", progress=82,
                 message=f"Scan complete: {scan_report['total_vulnerabilities']} findings. Calculating AI risk...")
        risk_report = AIRiskAssessmentEngine().assess_findings(scan_report["findings"])

        complete_report = {
            "target_url": target_url,
            "discovery_summary": {"api_title": disc_res["api_info"].get("title"),
                                   "endpoints_found": disc_res["total_endpoints"],
                                   "endpoints": disc_res["endpoints"]},
            "vulnerability_scan": {"duration_seconds": scan_report["scan_duration_seconds"],
                                    "total_detected": scan_report["total_vulnerabilities"]},
            "risk_assessment": risk_report}
        LATEST_REPORT = complete_report
        out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "latest_pipeline_report.json"), "w", encoding="utf-8") as f:
            json.dump(complete_report, f, indent=2)
        _set_job(job_id, status="completed", phase="Complete", progress=100,
                 message=f"Scan complete: {scan_report['total_vulnerabilities']} vulnerabilities detected",
                 report=complete_report)
    except Exception as e:
        _set_job(job_id, status="failed", phase="Error", progress=100, message=str(e), error=str(e))

@app.post("/api/pipeline/full-scan/start")
def start_full_scan(req: StartScanRequest):
    job_id = uuid.uuid4().hex[:12]
    with JOBS_LOCK:
        SCAN_JOBS[job_id] = {"job_id": job_id, "status": "queued", "phase": "Starting", "progress": 0,
                              "message": "Scan queued...", "started_at": time.time()}
    threading.Thread(target=_run_pipeline_job, args=(job_id, req.target_url, req.spec_url), daemon=True).start()
    return SCAN_JOBS[job_id]

@app.get("/api/pipeline/full-scan/status/{job_id}")
def scan_status(job_id: str):
    with JOBS_LOCK:
        job = SCAN_JOBS.get(job_id)
        if not job:
            raise HTTPException(404, "Scan job not found")
        return dict(job)

@app.post("/api/pipeline/full-scan")
def full_pipeline_scan(req: FullPipelineRequest):
    """Synchronous compatibility endpoint for API/CLI clients."""
    job_id = start_full_scan(StartScanRequest(target_url=req.target_url, spec_url=req.spec_url))["job_id"]
    while True:
        job = scan_status(job_id)
        if job["status"] in ("completed", "failed"):
            if job["status"] == "failed":
                raise HTTPException(500, job.get("error", "Scan failed"))
            return job["report"]
        time.sleep(0.15)

if __name__ == "__main__":
    import uvicorn
    print("[*] Starting FastAPI Backend on http://127.0.0.1:8000 ...")
    uvicorn.run(app, host="127.0.0.1", port=8000)
