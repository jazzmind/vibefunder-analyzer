#!/usr/bin/env python3
import os, json, argparse

ASVS_LEVEL = os.getenv("ASVS_LEVEL", "L1")

def load_sarif(path: str):
    try:
        data = json.load(open(path, 'r', encoding='utf-8'))
        return data.get('runs', [])[0].get('results', [])
    except Exception:
        return []

def summarize(findings, name: str) -> str:
    if not findings:
        return f"### {name}\n- No findings (or report missing).\n"
    lines = [f"### {name}", f"- Findings: {len(findings)}"]
    return "\n".join(lines) + "\n"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--index', required=True, help='path to index dir')
    ap.add_argument('--reports', default='reports', help='path to reports dir')
    ap.add_argument('--out', default='out/sow.md', help='output markdown file')
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    semgrep = load_sarif(os.path.join(args.reports, 'semgrep.sarif'))
    codeql = load_sarif(os.path.join(args.reports, 'codeql.sarif'))
    gitleaks = load_sarif(os.path.join(args.reports, 'gitleaks.sarif'))
    grype = load_sarif(os.path.join(args.reports, 'grype.sarif'))

    sections = []
    sections.append("# Production Readiness SoW (Draft)")
    sections.append(f"_Target ASVS Level: **{ASVS_LEVEL}**_  ")
    sections.append("This draft groups scanner findings by workstream and proposes priceable scopes with acceptance criteria.")

    sections.append(summarize(semgrep, "SAST (Semgrep)"))
    sections.append(summarize(codeql, "SAST (CodeQL)"))
    sections.append(summarize(gitleaks, "Secrets (Gitleaks)"))
    sections.append(summarize(grype, "Dependencies/Vulns (Grype from Syft SBOM)"))

    scopes = f"""## Proposed Scopes
1) **SAST + Secrets Remediation Sprint**
   - **Acceptance**: No Critical findings; Highs <= 3; PR checks enforcing SARIF gates.
   - **Deliverables**: Fixed PRs, rule suppressions with rationale, updated docs.

2) **Supply Chain Hardening**
   - **Acceptance**: Cosign-signed images; SBOM published; SLSA build provenance (Level 1→2).
   - **Deliverables**: CI pipeline, release notes, verification docs.

3) **AuthN/Z Review + Controls**
   - **Acceptance**: ASVS {ASVS_LEVEL} controls met for session mgmt, SSO, authorization checks.
   - **Deliverables**: Threat model notes, unit/integration tests, enforcement middleware.

4) **Observability MVP**
   - **Acceptance**: OTel traces across request path, p95 latency SLO alarms, error budget policy.
   - **Deliverables**: Dashboards (Grafana), runbook.

5) **Web Quality Gate**
   - **Acceptance**: Lighthouse perf ≥ 0.8; axe critical = 0; Playwright smoke green.

6) **Perf Smoke**
   - **Acceptance**: k6 p95 < 500ms for top 3 endpoints at VU=5 for 1m.
"""
    sections.append(scopes)

    with open(args.out, 'w', encoding='utf-8') as f:
        f.write("\n\n".join(sections))

    print(f"Wrote {args.out}")

if __name__ == '__main__':
    main()
