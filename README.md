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
- `POST /oauth/token` – OAuth2 client credentials token endpoint
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

## Auth (server-to-server)

This service issues and validates JWT bearer tokens for server-to-server access via the OAuth2 client credentials grant.

Environment variables:
- `OAUTH_SIGNING_KEY` – HMAC key to sign/verify access tokens (required for prod)
- `OAUTH_CLIENTS` – JSON map of client_id to client_secret, e.g. `{ "svc": "secret" }`
- `OAUTH_ISSUER` – token issuer string (default `vibefunder-analyzer`)
- `OAUTH_AUDIENCE` – token audience string (default `analyzer-api`)
- `OAUTH_TOKEN_TTL_SECONDS` – token lifetime (default `3600`)

Token request:
```bash
curl -s -X POST http://localhost:8080/oauth/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&client_id=local-client&client_secret=local-secret&scope=analyze:write'
```

Use returned `access_token` as `Authorization: Bearer ...` for `/api/v1/*` endpoints.

### Provision client credentials

Generate a `client_id`, `client_secret`, and a strong `OAUTH_SIGNING_KEY`, then print analyzer and vibefunder env snippets:
```bash
make gen-client
# or
python scripts/generate_client_credentials.py
```

Then on the analyzer service:
- Add/merge the printed JSON into `OAUTH_CLIENTS` (map of client_id → client_secret)
- Ensure `OAUTH_SIGNING_KEY` is set to a strong random value
- Redeploy/restart the analyzer service

On the vibefunder app:
- Set `ANALYZER_CLIENT_ID` and `ANALYZER_CLIENT_SECRET` from the output
- Set `ANALYZER_BASE_URL` to the analyzer service URL

## Local Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -r tools/indexer/requirements.txt -r agents/requirements.txt

# Run API
make api-run  # uvicorn on :8080

# Auth env & scripts
cp scripts/local.env.example .env  # customize secrets and repo settings
source .env
bash scripts/get_token.sh          # prints access token
bash scripts/run_analysis.sh       # uses .env and bearer token to start a job

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
