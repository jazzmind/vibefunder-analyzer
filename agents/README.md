Minimal agents scaffold; extend with LLM calls and ASVS mappings.

The `security_agent.py` consumes:
- `reports/semgrep.sarif`
- `reports/gitleaks.sarif`
- `reports/grype.sarif`
- an indexed source tree at `data/index/`

It outputs a draft Statement of Work (SoW) at `out/sow.md`, grouped by workstreams with acceptance criteria aligned to ASVS level via `ASVS_LEVEL` env var.

Typical API flow (performed by the API service):
1. Clone the target repository using a GitHub token if provided.
2. Run Semgrep, Gitleaks, and SBOM+Grype to generate SARIF reports.
3. Build a language-aware index with Tree-sitter.
4. Generate the SoW from findings and index metadata.

You can run the agent directly for local experimentation:
```bash
python agents/security_agent.py --index data/index --reports reports --out out/sow.md
```
