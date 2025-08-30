#!/usr/bin/env bash
set -euo pipefail
mkdir -p reports

echo ">> Running gitleaks"
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --report-format sarif --report-path reports/gitleaks.sarif || true
else
  echo "gitleaks not installed (skipping)"
fi

echo ">> Running semgrep"
if command -v semgrep >/dev/null 2>&1; then
  semgrep ci --config configs/semgrep.yml --sarif -o reports/semgrep.sarif || true
else
  echo "semgrep not installed (skipping)"
fi

echo ">> SBOM (syft) + grype"
if command -v syft >/dev/null 2>&1 && command -v grype >/dev/null 2>&1; then
  syft dir:. -o cyclonedx-json > sbom.json
  grype sbom:sbom.json -o sarif > reports/grype.sarif || true
else
  echo "syft/grype not installed (skipping)"
fi

echo ">> Done; see reports/"
