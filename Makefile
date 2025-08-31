.PHONY: scans sow up down api-run api-build api-docker-run tools

scans:
	bash scripts/run_local_scans.sh

sow:
	mkdir -p out
	python agents/security_agent.py --index data/index --reports reports --out out/sow.md

up:
	docker compose up -d

down:
	docker compose down -v

api-run:
	uvicorn api.main:app --host 0.0.0.0 --port 8080 --reload

api-build:
	docker build -t analyzer-api:local .

api-docker-run:
	docker run --rm -p 8080:8080 -e ASVS_LEVEL=L1 analyzer-api:local

tools:
	python tools/indexer/index_repo.py --repo . --out data/index
