-include .env
export

# Docker image, terraform and release targets live in platform.mk. Teams never need them.
-include platform.mk

install:
	cd frontend && npm install
	uv sync --extra fastapi --extra gateway --extra synth
	docker compose build 

.PHONY: synth
synth:  ## Regenerate mcp_server/data/synthetic (pupil census, deprivation, schools, display names) from mcp_server/synth/synth.yaml
	uv run python -m mcp_server.synth

hack: install  ## One command start: keys, one-school mandate, eval pack, containers, first signed call
	cp -n .env.example .env || true
	test -f gateway/state/trusted_list.json || uv run python -m gateway.cli init
	uv run python -m gateway.cli issue --agent-key gateway/state/agent.pem -o gateway/state/mandate.jwt
	uv run python -m gateway.eval build -o eval_pack
	docker compose up -d --wait
	uv run python -m gateway.cli call --mandate gateway/state/mandate.jwt --agent-key gateway/state/agent.pem \
		--tool search --args '{"query": "P0004", "urn": "SCH01"}'

run:
	docker compose up -d --wait

stop:
	docker compose down

gateway_init:  ## Generate gateway keys, trusted list and status list in gateway/state
	uv run python -m gateway.cli init

gateway_issue:  ## Issue a default one-school (SCH01) mandate to gateway/state/agent.pem
	uv run python -m gateway.cli issue --agent-key gateway/state/agent.pem -o gateway/state/mandate.jwt

eval_build:  ## Mint the eval mandates + keys from gateway/state into eval_pack/
	uv run python -m gateway.eval build -o eval_pack

eval_run:  ## Fire the eval cases for questions 0 to 5 at GATEWAY_URL (default localhost:8082)
	uv run python -m gateway.eval run --pack eval_pack --url $${GATEWAY_URL:-http://localhost:8082}

eval_open:  ## Fire our cases for open questions 7, 10, 11 and 14 at GATEWAY_URL; mints and revokes mandates in gateway/state
	uv run python -m gateway.eval open --url $${GATEWAY_URL:-http://localhost:8082}

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
