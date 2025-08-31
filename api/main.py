from __future__ import annotations

import asyncio
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List

from fastapi import BackgroundTasks, FastAPI, HTTPException, Form, Depends

from .models import AnalyzeRequest, AnalyzeStartResponse, JobStatus, JobStatusResponse, SowResponse, JobStep, ScannerName
from .cli_wrappers import (
    REPO_ROOT,
    clone_repo,
    run_gitleaks,
    run_indexer,
    run_semgrep,
    run_syft_grype,
    tools_available,
)
from .auth import require_auth, issue_token, authenticate_client


WORK_ROOT = Path((Path.cwd() / "jobs").resolve())


class Job:
    def __init__(self, job_id: str, req: AnalyzeRequest) -> None:
        self.id = job_id
        self.req = req
        self.status: JobStatus = JobStatus.pending
        self.message: Optional[str] = None
        self.created_at = datetime.utcnow()
        self.started_at: Optional[datetime] = None
        self.finished_at: Optional[datetime] = None
        self.job_dir: Path = WORK_ROOT / job_id
        self.repo_dir: Path = self.job_dir / "repo"
        self.reports_dir: Path = self.job_dir / "reports"
        self.index_dir: Path = self.job_dir / "data" / "index"
        self.out_dir: Path = self.job_dir / "out"
        self.sow_path: Path = self.out_dir / "sow.md"
        self.steps: List[JobStep] = []
        self.canceled: bool = False


JOBS: Dict[str, Job] = {}
JOBS_LOCK = threading.Lock()
# In-memory last artifacts by repo URL (non-persistent)
REPO_LAST: Dict[str, Dict[str, object]] = {}

app = FastAPI(title="Analyzer API", version="0.1.0")


@app.get("/health")
def health() -> Dict[str, str]:
    return {"ok": "true", "service": "analyzer-api", "version": "0.1.0"}


@app.get("/tools")
def tools() -> Dict[str, bool]:
    return tools_available()


def _validate_request(req: AnalyzeRequest) -> None:
    if not (req.repo_url.startswith("http://") or req.repo_url.startswith("https://")):
        raise HTTPException(status_code=400, detail="repo_url must be an HTTP(S) URL to a Git repo")
    if req.github_token and (len(req.github_token) < 20):
        raise HTTPException(status_code=400, detail="github_token looks invalid")


def _run_job(job: Job) -> None:
    try:
        job.status = JobStatus.running
        job.started_at = datetime.utcnow()

        timeout = job.req.timeout_seconds

        # Helper to manage steps
        def start_step(name: str, msg: Optional[str] = None) -> None:
            step = JobStep(name=name, status="running", started_at=datetime.utcnow().isoformat() + "Z", message=msg)
            job.steps.append(step)

        def finish_step(status: str = "succeeded", msg: Optional[str] = None) -> None:
            if not job.steps:
                return
            step = job.steps[-1]
            step.status = status
            step.finished_at = datetime.utcnow().isoformat() + "Z"
            if msg:
                step.message = msg

        def check_cancel() -> None:
            if job.canceled:
                raise RuntimeError("job canceled")

        # 1) Clone repo
        start_step("clone", f"branch={job.req.branch or 'default'}")
        clone_repo(job.req.repo_url, dest_dir=job.repo_dir, github_token=job.req.github_token, branch=job.req.branch, timeout=timeout)
        finish_step("succeeded")
        check_cancel()

        # 2) Run scanners according to selection
        config_path = REPO_ROOT / job.req.semgrep_config_path

        selected = [s.value for s in job.req.scanners]
        if "semgrep" in selected:
            start_step("semgrep")
            run_semgrep(repo_dir=job.repo_dir, reports_dir=job.reports_dir, config_path=config_path, timeout=timeout)
            finish_step("succeeded")
            check_cancel()
        if "gitleaks" in selected:
            start_step("gitleaks")
            run_gitleaks(repo_dir=job.repo_dir, reports_dir=job.reports_dir, timeout=timeout)
            finish_step("succeeded")
            check_cancel()
        if "sbom" in selected:
            start_step("sbom")
            run_syft_grype(repo_dir=job.repo_dir, reports_dir=job.reports_dir, timeout=timeout)
            finish_step("succeeded")
            check_cancel()

        # 3) Build index and generate SoW
        start_step("index")
        run_indexer(repo_dir=job.repo_dir, index_out_dir=job.index_dir, timeout=timeout)
        finish_step("succeeded")
        check_cancel()
        start_step("sow")
        job.sow_path.parent.mkdir(parents=True, exist_ok=True)
        from .cli_wrappers import run_sow

        run_sow(index_dir=job.index_dir, reports_dir=job.reports_dir, out_file=job.sow_path, timeout=timeout)
        finish_step("succeeded")

        job.status = JobStatus.succeeded
    except Exception as exc:  # pragma: no cover
        job.status = JobStatus.failed
        job.message = str(exc)
        # Mark current step as failed if running
        if job.steps and job.steps[-1].status == "running":
            job.steps[-1].status = "failed"
            job.steps[-1].finished_at = datetime.utcnow().isoformat() + "Z"
    finally:
        job.finished_at = datetime.utcnow()
        # Update repo history record
        try:
            reports_present: List[str] = []
            if job.reports_dir.exists():
                for p in job.reports_dir.glob("*"):
                    if p.is_file():
                        reports_present.append(p.name)
            REPO_LAST[job.req.repo_url] = {
                "job_id": job.id,
                "status": job.status.value,
                "when": datetime.utcnow().isoformat() + "Z",
                "reports_present": reports_present,
                "scanners_selected": [s.value for s in job.req.scanners],
            }
        except Exception:
            pass


@app.post("/oauth/token")
async def oauth_token(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    scope: str = Form(default="analyze:write"),
):
    if grant_type != "client_credentials":
        raise HTTPException(status_code=400, detail="unsupported_grant_type")
    if not authenticate_client(client_id, client_secret):
        raise HTTPException(status_code=401, detail="invalid_client")
    return issue_token(client_id, scope)


@app.post("/api/v1/analyze", response_model=AnalyzeStartResponse, dependencies=[Depends(require_auth)])
async def start_analyze(req: AnalyzeRequest, background_tasks: BackgroundTasks) -> AnalyzeStartResponse:
    _validate_request(req)
    job_id = uuid.uuid4().hex
    job = Job(job_id, req)
    with JOBS_LOCK:
        JOBS[job_id] = job

    background_tasks.add_task(_run_job, job)
    return AnalyzeStartResponse(job_id=job_id, status=job.status)


@app.get("/api/v1/jobs/{job_id}", response_model=JobStatusResponse, dependencies=[Depends(require_auth)])
def job_status(job_id: str) -> JobStatusResponse:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    reports_present: List[str] = []
    try:
        if job.reports_dir.exists():
            for p in job.reports_dir.glob("*"):
                if p.is_file():
                    reports_present.append(p.name)
    except Exception:
        pass
    return JobStatusResponse(
        job_id=job.id,
        status=job.status,
        message=job.message,
        reports_dir=str(job.reports_dir) if job.reports_dir.exists() else None,
        sow_path=str(job.sow_path) if job.sow_path.exists() else None,
        created_at=job.created_at.isoformat() + "Z" if job.created_at else None,
        started_at=job.started_at.isoformat() + "Z" if job.started_at else None,
        finished_at=job.finished_at.isoformat() + "Z" if job.finished_at else None,
        steps=job.steps,
        canceled=job.canceled,
        scanners_selected=[ScannerName(s) for s in [s.value for s in job.req.scanners]],
        reports_present=reports_present,
    )


@app.get("/api/v1/jobs/{job_id}/sow", response_model=SowResponse, dependencies=[Depends(require_auth)])
def get_sow(job_id: str) -> SowResponse:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    if not job.sow_path.exists():
        raise HTTPException(status_code=404, detail="sow not available for this job")
    content = job.sow_path.read_text(encoding="utf-8")
    return SowResponse(job_id=job_id, sow_markdown=content)


@app.post("/api/v1/jobs/{job_id}/cancel", dependencies=[Depends(require_auth)])
def cancel_job(job_id: str) -> Dict[str, str]:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    job.canceled = True
    return {"status": "cancellation_requested"}


@app.get("/api/v1/capabilities")
def capabilities() -> Dict[str, object]:
    avail = tools_available()
    scanners = [
        {"name": "semgrep", "available": bool(avail.get("semgrep"))},
        {"name": "gitleaks", "available": bool(avail.get("gitleaks"))},
        {"name": "sbom", "available": bool(avail.get("syft")) and bool(avail.get("grype"))},
    ]
    return {"scanners": scanners, "tools": avail}


@app.get("/api/v1/jobs/{job_id}/reports/{name}", dependencies=[Depends(require_auth)])
def get_report(job_id: str, name: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    path = job.reports_dir / name
    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="report not found")
    try:
        return {"name": name, "content": path.read_text(encoding="utf-8")}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/v1/plan", dependencies=[Depends(require_auth)])
def plan(req: AnalyzeRequest) -> Dict[str, object]:
    # Do not clone; return installed scanners and any last-known artifacts for this repo
    avail = tools_available()
    scanners = [
        {"name": "semgrep", "available": bool(avail.get("semgrep"))},
        {"name": "gitleaks", "available": bool(avail.get("gitleaks"))},
        {"name": "sbom", "available": bool(avail.get("syft")) and bool(avail.get("grype"))},
    ]
    history = REPO_LAST.get(req.repo_url, None)
    return {"scanners": scanners, "history": history}


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run("api.main:app", host="0.0.0.0", port=8080, reload=False)


