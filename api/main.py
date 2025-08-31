from __future__ import annotations

import asyncio
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, Form

from .models import AnalyzeRequest, AnalyzeStartResponse, JobStatus, JobStatusResponse, SowResponse
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


JOBS: Dict[str, Job] = {}
JOBS_LOCK = threading.Lock()

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

        # 1) Clone repo
        clone_repo(job.req.repo_url, dest_dir=job.repo_dir, github_token=job.req.github_token, branch=job.req.branch, timeout=timeout)

        # 2) Run scanners according to selection
        config_path = REPO_ROOT / job.req.semgrep_config_path

        if "semgrep" in [s.value for s in job.req.scanners]:
            run_semgrep(repo_dir=job.repo_dir, reports_dir=job.reports_dir, config_path=config_path, timeout=timeout)
        if "gitleaks" in [s.value for s in job.req.scanners]:
            run_gitleaks(repo_dir=job.repo_dir, reports_dir=job.reports_dir, timeout=timeout)
        if "sbom" in [s.value for s in job.req.scanners]:
            run_syft_grype(repo_dir=job.repo_dir, reports_dir=job.reports_dir, timeout=timeout)

        # 3) Build index and generate SoW
        run_indexer(repo_dir=job.repo_dir, index_out_dir=job.index_dir, timeout=timeout)
        job.sow_path.parent.mkdir(parents=True, exist_ok=True)
        from .cli_wrappers import run_sow

        run_sow(index_dir=job.index_dir, reports_dir=job.reports_dir, out_file=job.sow_path, timeout=timeout)

        job.status = JobStatus.succeeded
    except Exception as exc:  # pragma: no cover
        job.status = JobStatus.failed
        job.message = str(exc)
    finally:
        job.finished_at = datetime.utcnow()


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
    return JobStatusResponse(
        job_id=job.id,
        status=job.status,
        message=job.message,
        reports_dir=str(job.reports_dir) if job.reports_dir.exists() else None,
        sow_path=str(job.sow_path) if job.sow_path.exists() else None,
        created_at=job.created_at.isoformat() + "Z" if job.created_at else None,
        started_at=job.started_at.isoformat() + "Z" if job.started_at else None,
        finished_at=job.finished_at.isoformat() + "Z" if job.finished_at else None,
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


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run("api.main:app", host="0.0.0.0", port=8080, reload=False)


