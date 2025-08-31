from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Dict, Optional
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(cmd: list[str], cwd: Optional[Path] = None, timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    # Ensure non-interactive, predictable locale
    env.setdefault("LC_ALL", "C")
    env.setdefault("LANG", "C")
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env, capture_output=True, text=True, timeout=timeout, check=False)


def tools_available() -> Dict[str, bool]:
    tools = {
        "git": ["git", "--version"],
        "semgrep": ["semgrep", "--version"],
        "gitleaks": ["gitleaks", "version"],
        "syft": ["syft", "version"],
        "grype": ["grype", "version"],
    }
    availability: Dict[str, bool] = {}
    for name, cmd in tools.items():
        try:
            result = _run(cmd)
            availability[name] = result.returncode == 0
        except Exception:
            availability[name] = False
    return availability


def sanitize_url_for_logging(url: str) -> str:
    # Remove token if embedded like https://x-access-token:TOKEN@github.com/...
    return re.sub(r"(https?://)([^:@/]+):([^@/]+)@", r"\1\2:***@", url)


def clone_repo(repo_url: str, dest_dir: Path, github_token: Optional[str] = None, branch: Optional[str] = None, timeout: Optional[int] = None) -> str:
    dest_dir = Path(dest_dir)
    dest_dir.parent.mkdir(parents=True, exist_ok=True)
    url = repo_url
    if github_token and repo_url.startswith("https://"):
        # Embed token safely without logging it; use x-access-token per GitHub docs
        url = repo_url.replace("https://", f"https://x-access-token:{github_token}@")

    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [url, str(dest_dir)]

    result = _run(cmd, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {sanitize_url_for_logging(repo_url)}\n{result.stderr}")
    return sanitize_url_for_logging(repo_url)


def run_semgrep(repo_dir: Path, reports_dir: Path, config_path: Path, timeout: Optional[int] = None) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    out = reports_dir / "semgrep.sarif"
    cmd = [
        "semgrep", "ci",
        "--config", str(config_path),
        "--sarif", "-o", str(out),
    ]
    # semgrep returns non-zero for findings in some modes; ignore rc but capture output
    _run(cmd, cwd=repo_dir, timeout=timeout)
    return out


def run_gitleaks(repo_dir: Path, reports_dir: Path, timeout: Optional[int] = None) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    out = reports_dir / "gitleaks.sarif"
    cmd = [
        "gitleaks", "detect",
        "--source", str(repo_dir),
        "--report-format", "sarif",
        "--report-path", str(out),
    ]
    _run(cmd, timeout=timeout)
    return out


def run_syft_grype(repo_dir: Path, reports_dir: Path, timeout: Optional[int] = None) -> Dict[str, Path]:
    reports_dir.mkdir(parents=True, exist_ok=True)
    sbom = reports_dir / "sbom.json"
    grype_out = reports_dir / "grype.sarif"

    # syft dir scan to CycloneDX JSON
    with open(sbom, "w", encoding="utf-8") as f:
        _run(["syft", f"dir:{repo_dir}", "-o", "cyclonedx-json"], timeout=timeout, cwd=repo_dir)
        # Unfortunately syft writes to stdout; re-run capturing stdout
        proc = subprocess.Popen(["syft", f"dir:{repo_dir}", "-o", "cyclonedx-json"], stdout=f, stderr=subprocess.PIPE, text=True)
        proc.wait(timeout=timeout)

    # grype against SBOM
    with open(grype_out, "w", encoding="utf-8") as f:
        proc = subprocess.Popen(["grype", f"sbom:{sbom}", "-o", "sarif"], stdout=f, stderr=subprocess.PIPE, text=True)
        proc.wait(timeout=timeout)

    return {"sbom": sbom, "grype": grype_out}


def run_indexer(repo_dir: Path, index_out_dir: Path, timeout: Optional[int] = None) -> Path:
    index_out_dir.mkdir(parents=True, exist_ok=True)
    script = REPO_ROOT / "tools" / "indexer" / "index_repo.py"
    py = sys.executable or "python3"
    cmd = [py, str(script), "--repo", str(repo_dir), "--out", str(index_out_dir)]
    _run(cmd, timeout=timeout, cwd=REPO_ROOT)
    return index_out_dir


def run_sow(index_dir: Path, reports_dir: Path, out_file: Path, timeout: Optional[int] = None) -> Path:
    out_file.parent.mkdir(parents=True, exist_ok=True)
    script = REPO_ROOT / "agents" / "security_agent.py"
    py = sys.executable or "python3"
    cmd = [
        py,
        str(script),
        "--index", str(index_dir),
        "--reports", str(reports_dir),
        "--out", str(out_file),
    ]
    _run(cmd, timeout=timeout, cwd=REPO_ROOT)
    return out_file


