.PHONY: up down logs ps test fmt benchmark benchmark-cluster gate readiness dev-bootstrap dev-test dev-check deploy

up:
	docker compose up -d --build

deploy:
	bash scripts/deploy-compose.sh

down:
	docker compose down

logs:
	docker compose logs -f --tail=200

ps:
	docker compose ps

test:
	python -m pytest -q

fmt:
	python -m compileall app

benchmark:
	python scripts/benchmark_m12.py --base-url http://127.0.0.1:8080 --duration 30 --concurrency 64

benchmark-cluster:
	bash scripts/benchmark_cluster_m12.sh 4 20 64

gate:
	bash scripts/m15_premerge_gate.sh

readiness:
	bash scripts/m16_release_readiness.sh

dev-bootstrap:
	bash scripts/dev-bootstrap.sh

dev-test:
	bash scripts/dev-test.sh

dev-check:
	bash scripts/dev-check.sh
