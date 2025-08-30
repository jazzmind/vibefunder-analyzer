.PHONY: scans sow up down

scans:
	bash scripts/run_local_scans.sh

sow:
	mkdir -p out
	python agents/security_agent.py --index data/index --reports reports --out out/sow.md

up:
	docker compose up -d

down:
	docker compose down -v
