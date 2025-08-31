#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-8080}"
HOST="${HOST:-http://localhost:$PORT}"
CLIENT_ID="${CLIENT_ID:-local-client}"
CLIENT_SECRET="${CLIENT_SECRET:-local-secret}"

curl -s -X POST "$HOST/oauth/token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=analyze:write" | jq -r .access_token


