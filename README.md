# prod-readiness-starter

A pragmatic starter to evaluate a codebase and site for production readiness, now with an HTTP API suitable for hosted execution (e.g., Koyeb). It includes:
- **Security**: Semgrep, Gitleaks, SBOM (Syft) + vuln scan (Grype). Hooks for CodeQL, etc.
- **Web quality**: Lighthouse config scaffold (local).
- **Performance**: k6 smoke scaffold.
- **Observability**: OpenTelemetry sample app + Collector, Jaeger, Prometheus, Grafana via `docker-compose`.
- **LLM Assist**: Offline-first indexer and an agent that drafts a SoW from scanner outputs.

## API Overview

The API clones a target repo (optionally using a GitHub token), runs selected scanners, builds a source index, and generates a draft SoW.

Endpoints:
- `GET /health` – service status
- `GET /tools` – report installed CLI tools
- `POST /api/v1/analyze` – start an analysis job
  - body: `{ repo_url, github_token?, branch?, scanners?, semgrep_config_path?, timeout_seconds? }`
- `GET /api/v1/jobs/{job_id}` – job status and artifact paths
- `GET /api/v1/jobs/{job_id}/sow` – returns SoW markdown

Request example:
```bash
curl -s -X POST http://localhost:8080/api/v1/analyze \
  -H 'content-type: application/json' \
  -d '{
        "repo_url": "https://github.com/org/repo",
        "github_token": "ghp_***",
        "branch": "main",
        "scanners": ["semgrep", "gitleaks", "sbom"],
        "timeout_seconds": 1200
      }'
```

## Local Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -r tools/indexer/requirements.txt -r agents/requirements.txt

# Run API
make api-run  # uvicorn on :8080

# Optional: run local scans against this repo
make scans

# Optional: index + SoW for this repo
make tools
make sow
```

## Docker / Koyeb

Build and run container locally:
```bash
make api-build
make api-docker-run
```

Environment variables:
- `ASVS_LEVEL` – influences SoW acceptance language (default `L1`).

Deploy to Koyeb:
- Use the provided `Dockerfile` as the service image.
- Expose port `8080`.
- Provide `ASVS_LEVEL` as needed.
- Optionally mount ephemeral disk for `/app/jobs` workspace (default path for job artifacts).

## Security Notes
- GitHub tokens are only used for `git clone` over HTTPS. They are not logged; URLs are sanitized in logs.
- Findings may be incomplete when CLIs are missing. Check `GET /tools` before running.
- Ensure containers run with least privilege and no persistent secrets.

## Existing Tooling (local)

Quickstart for local non-API usage:
```bash
docker compose up -d
make scans
python tools/indexer/index_repo.py --repo . --out data/index
python agents/security_agent.py --index data/index --reports reports --out out/sow.md
```
