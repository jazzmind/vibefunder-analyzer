#!/usr/bin/env bash
set -euo pipefail

# Load env if present
if [ -f .env ]; then
  set -o allexport
  source .env
  set +o allexport
fi

PORT="${PORT:-8080}"
HOST="${HOST:-http://localhost:$PORT}"
CLIENT_ID="${CLIENT_ID:-local-client}"
CLIENT_SECRET="${CLIENT_SECRET:-local-secret}"

REPO_URL="${REPO_URL:-}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
BRANCH="${BRANCH:-}"
SCANNERS_CSV="${SCANNERS:-semgrep,gitleaks,sbom}"

if [ -z "$REPO_URL" ]; then
  echo "REPO_URL is required (set in .env or env)" >&2
  exit 1
fi

ACCESS_TOKEN=$(CLIENT_ID="$CLIENT_ID" CLIENT_SECRET="$CLIENT_SECRET" bash scripts/get_token.sh)

read -r -d '' BODY << EOF || true
{
  "repo_url": "$REPO_URL",
  "github_token": "${GITHUB_TOKEN}",
  "branch": "${BRANCH}",
  "scanners": [$(echo "$SCANNERS_CSV" | awk -F, '{for (i=1;i<=NF;i++) { if (i>1) printf ", "; printf "\""$i"\"" }}')]
}
EOF

curl -s -X POST "$HOST/api/v1/analyze" \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d "$BODY"


