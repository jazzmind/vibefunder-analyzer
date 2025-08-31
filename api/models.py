from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class ScannerName(str, Enum):
    semgrep = "semgrep"
    gitleaks = "gitleaks"
    sbom = "sbom"  # syft + grype


class AnalyzeRequest(BaseModel):
    repo_url: str = Field(..., description="Git repository HTTPS URL to analyze")
    github_token: Optional[str] = Field(
        default=None,
        description="GitHub token with repo read access; omit for public repos",
    )
    branch: Optional[str] = Field(default=None, description="Branch to clone (optional)")
    scanners: List[ScannerName] = Field(
        default_factory=lambda: [ScannerName.semgrep, ScannerName.gitleaks, ScannerName.sbom],
        description="Which scanners to run",
    )
    semgrep_config_path: str = Field(
        default="configs/semgrep.yml",
        description="Path to Semgrep config inside this container",
    )
    timeout_seconds: int = Field(
        default=900,
        ge=60,
        le=7200,
        description="Overall timeout budget for the analysis job",
    )


class JobStatus(str, Enum):
    pending = "pending"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"


class AnalyzeStartResponse(BaseModel):
    job_id: str
    status: JobStatus


class JobStep(BaseModel):
    name: str
    status: str  # pending|running|succeeded|failed|skipped
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    message: Optional[str] = None


class JobStatusResponse(BaseModel):
    job_id: str
    status: JobStatus
    message: Optional[str] = None
    reports_dir: Optional[str] = None
    sow_path: Optional[str] = None
    created_at: Optional[str] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    steps: List[JobStep] = []
    canceled: bool = False
    scanners_selected: List[ScannerName] = []
    reports_present: List[str] = []  # filenames present in reports_dir


class SowResponse(BaseModel):
    job_id: str
    sow_markdown: str


