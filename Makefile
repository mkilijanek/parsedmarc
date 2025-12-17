.PHONY: up down logs ps test fmt

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
