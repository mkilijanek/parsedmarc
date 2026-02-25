.PHONY: up down logs ps test fmt benchmark

up:
	docker compose up -d --build

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
