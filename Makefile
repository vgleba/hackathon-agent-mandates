-include .env
export

# Docker image, terraform and release targets live in platform.mk. Teams never need them.
-include platform.mk

# The walkthrough UI and the gateway's /demo routes, which sign mandates for anyone who asks. Local only: plain
# `docker compose` (make run) starts what gets deployed, without them (adr/0001-gateway-image-is-the-security-boundary.md)
COMPOSE_DEMO = docker compose -f docker-compose.yaml -f docker-compose.demo.yaml

install:
	cd frontend && npm install
	uv sync --extra fastapi --extra gateway --extra synth
	$(COMPOSE_DEMO) build

.PHONY: synth
synth:  ## Regenerate mcp_server/data/synthetic (pupil census, deprivation, schools, display names) from mcp_server/synth/synth.yaml
	uv run python -m mcp_server.synth

hack: install  ## One command start: keys, one-school mandate, eval pack, containers, first signed call
	cp -n .env.example .env || true
	test -f gateway/state/trusted_list.json || uv run python -m gateway.cli init
	uv run python -m gateway.cli issue --agent-key gateway/state/agent.pem -o gateway/state/mandate.jwt
	uv run python -m gateway.eval build -o eval_pack
	$(COMPOSE_DEMO) up -d --wait
	uv run python -m gateway.cli call --mandate gateway/state/mandate.jwt --agent-key gateway/state/agent.pem \
		--tool search --args '{"query": "P0004", "urn": "SCH01"}'

.PHONY: demo run stop
demo:  ## The walkthrough at localhost:8081/demo, with the gateway's /demo routes on. Local only, never deployed
	$(COMPOSE_DEMO) up -d --wait

run:  ## What gets deployed: the data server and the gateway, no demo routes and no UI
	docker compose up -d --wait --remove-orphans

stop:
	$(COMPOSE_DEMO) down

gateway_init:  ## Generate gateway keys, trusted list and status list in gateway/state
	uv run python -m gateway.cli init

gateway_issue:  ## Issue a default one-school (SCH01) mandate to gateway/state/agent.pem
	uv run python -m gateway.cli issue --agent-key gateway/state/agent.pem -o gateway/state/mandate.jwt

eval_build:  ## Mint the eval mandates + keys from gateway/state into eval_pack/
	uv run python -m gateway.eval build -o eval_pack

eval_run:  ## Fire the eval cases for questions 0 to 5 at GATEWAY_URL (default localhost:8082)
	uv run python -m gateway.eval run --pack eval_pack --url $${GATEWAY_URL:-http://localhost:8082}

.PHONY: eval_open eval_local preflight
eval_open:  ## Fire our cases for open questions 6 to 16 at GATEWAY_URL; mints and revokes mandates in gateway/state
	uv run python -m gateway.eval open --url $${GATEWAY_URL:-http://localhost:8082}

eval_local:  ## Every eval case, questions 0 to 16, on a gateway of its own: no keys or Docker needed, takes a few minutes
	uv run --extra fastapi --extra gateway python -m gateway.eval local

preflight:  ## Refuse to post a gateway URL while demo routes are visible or questions 0 to 5 fail
	@set -eu; \
	url="$${GATEWAY_URL:-http://localhost:8082}"; \
	for route in issuer trust mandate call revoke; do \
		code=$$(curl --connect-timeout 5 --max-time 15 -sS -o /dev/null -w '%{http_code}' "$$url/demo/$$route"); \
		echo "GET /demo/$$route: $$code"; \
		[ "$$code" = 404 ] || { echo "unsafe: /demo/$$route is present"; exit 1; }; \
	done
	$(MAKE) eval_run

attack_mandates:  ## Day 2: issue the default mandate, and a feature mandate if FEATURE_SCOPE/FEATURE_CLAIMS are set, to each day_2_attack/keys/<team>.jwk
	mkdir -p day_2_attack/keys day_2_attack/mandates
	for key in day_2_attack/keys/*.jwk; do \
		[ -e "$$key" ] || { echo "no keys in day_2_attack/keys"; exit 1; }; \
		team=$$(basename "$$key" .jwk); \
		uv run python -m gateway.cli person --principal "attacker:$$team" --name "$$team" --urns '*' --clearance 4 --daily-pupils 300 > /dev/null; \
		uv run python -m gateway.cli issue --agent-key "$$key" --ttl 86400 -o "day_2_attack/mandates/$$team.jwt" \
			--principal "attacker:$$team" --purpose "Day 2 attack mandate for $$team"; \
		if [ -n "$(FEATURE_SCOPE)$(FEATURE_CLAIMS)" ]; then \
			uv run python -m gateway.cli issue --agent-key "$$key" --ttl 86400 -o "day_2_attack/mandates/$$team.feature.jwt" \
				--principal "attacker:$$team" --purpose "Day 2 feature mandate for $$team" \
				$(if $(FEATURE_SCOPE),--scope "$$(cat $(FEATURE_SCOPE))") $(if $(FEATURE_CLAIMS),--claims "$$(cat $(FEATURE_CLAIMS))"); \
		fi; \
	done

test:
	cd mcp_server && uv sync --group dev --extra fastapi --extra synth && uv run python -m pytest --cov=mcp_server -v --cov-report=term-missing --cov-fail-under=0
	uv run python -m pytest gateway/tests desk/tests

.PHONY: lint
lint:  ## Check code formatting & linting
	uv run ruff format . --check
	uv run ruff check .

.PHONY: format
format:  ## Format and fix code
	uv run ruff format .
	uv run ruff check . --fix

run_frontend:
	cd frontend && npm run dev

run_backend:
	uv run python -m uvicorn mcp_server.main:app --reload

pre-commit-install:
	pre-commit install

.PHONY: safe
safe:
	uv run bandit -ll -r ./mcp_server
