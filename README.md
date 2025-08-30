# prod-readiness-starter

A pragmatic starter repo to evaluate and lift a codebase + website to **production readiness**. It wires:
- **Security**: CodeQL, Semgrep, Gitleaks, SBOM (Syft) + vuln scan (Grype), IaC checks (tfsec, Checkov), container scan (Trivy), ZAP baseline DAST.
- **Web quality**: Lighthouse CI (+ thresholds), axe-core CLI a11y checks, Playwright E2E scaffold.
- **Performance**: k6 smoke test scaffold.
- **Observability**: OpenTelemetry (Node.js sample), Collector, Jaeger, Prometheus, Grafana via `docker-compose`.
- **Supply chain**: Cosign signing workflow + SLSA pointers.
- **LLM Assist**: Offline-first indexer (Tree-sitter + FAISS) and task-focused agents that **only** read relevant files and scanner outputs to draft Scopes-of-Work (SoWs).

## Quickstart
```bash
docker compose up -d
make scans
python tools/indexer/index_repo.py --repo . --out data/index
python agents/security_agent.py --index data/index --reports reports --out out/sow.md
```
