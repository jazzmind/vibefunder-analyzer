.PHONY: scans sow up down api-run api-build api-docker-run tools gen-client

# Run local scanners (gitleaks, semgrep, syft+grype) against this repo into ./reports
scans:
	bash scripts/run_local_scans.sh

# Generate a draft SoW from existing ./data/index and ./reports into ./out/sow.md
sow:
	mkdir -p out
	python agents/security_agent.py --index data/index --reports reports --out out/sow.md

# Start the observability sandbox (sample app + OTel Collector + Jaeger/Prometheus/Grafana)
up:
	docker compose up -d

# Stop and clean sandbox containers and volumes
down:
	docker compose down -v

# Run the FastAPI service locally with reload on port 8080
api-run:
	uvicorn api.main:app --host 0.0.0.0 --port 8080 --reload

# Build the Analyzer API container image
api-build:
	docker build -t analyzer-api:local .

# Run the Analyzer API container locally on port 8080
api-docker-run:
	docker run --rm -p 8080:8080 -e ASVS_LEVEL=L1 analyzer-api:local

# Build a local code index into ./data/index
tools:
	python tools/indexer/index_repo.py --repo . --out data/index

# Generate OAuth client credentials and example env snippets
gen-client:
	python scripts/generate_client_credentials.py
