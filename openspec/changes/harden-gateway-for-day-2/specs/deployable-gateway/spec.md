## ADDED Requirements

### Requirement: The production gateway image serves no demo routes
The gateway image built from `gateway/Dockerfile` SHALL NOT contain the demo router, whatever environment it runs with.
The mint, sign and revoke routes then cannot be switched on by an environment variable the team does not control.

#### Scenario: Demo flag set on the production image
- **WHEN** the image built from `gateway/Dockerfile` runs with `GATEWAY_DEMO=1`
- **THEN** `GET /demo/issuer`, `GET /demo/trust`, `POST /demo/mandate`, `POST /demo/call` and `POST /demo/revoke` each answer 404
- **AND** no mandate is issued and no status bit changes

#### Scenario: Gateway starts without the demo module
- **WHEN** the gateway starts and `gateway/demo.py` is not present
- **THEN** it starts and serves `/healthcheck` and `/tools/call`

#### Scenario: Demo module present but switched off
- **WHEN** the gateway runs from a checkout that has `gateway/demo.py` and `GATEWAY_DEMO` is not `1`
- **THEN** every `/demo/*` route answers 404

### Requirement: The committed compose file is safe to deploy
`docker-compose.yaml` MUST define only the backend and the gateway, and MUST NOT switch on demo mode.
The walkthrough UI and demo mode SHALL live in a separate `docker-compose.demo.yaml`. Compose only loads that file when asked by name.

#### Scenario: Compose file checked in the test suite
- **WHEN** the test suite reads `docker-compose.yaml`
- **THEN** the gateway service has no `GATEWAY_DEMO` setting and there is no frontend service

#### Scenario: No auto-loaded override file
- **WHEN** the test suite lists the repository root
- **THEN** there is no `docker-compose.override.yaml`, `docker-compose.override.yml`, `compose.override.yaml` or `compose.override.yml`

#### Scenario: Local walkthrough on request
- **WHEN** a developer runs `make hack` or `make demo`
- **THEN** compose starts with both `docker-compose.yaml` and `docker-compose.demo.yaml`
- **AND** the walkthrough at `localhost:8081/demo` can issue a mandate, call and revoke

#### Scenario: Plain run is deploy-shaped
- **WHEN** a developer runs `make run`
- **THEN** only the backend and the gateway start, and `/demo/mandate` answers 404

### Requirement: The image carries only the state files the gateway reads
The gateway image MUST NOT contain any file from `gateway/state/` except the trusted list, the status list (`status_list.json`, `status_list.jwt`), the people policy (`people.json`, `people.jwt`) and the gateway's own key (`gateway_key.pem`).
The empty `.gitkeep` also stays, so the folder exists in the image and is owned by the app user.

#### Scenario: Image built from a working state directory
- **WHEN** `gateway/state/` holds `issuer_key.pem`, `agent.pem`, `demo_agent.pem`, `person_*.pem`, `*.jwt` mandates, `gateway.db` and `record.jsonl`, and the gateway image is built
- **THEN** the image's `gateway/state/` contains none of those files
- **AND** it contains whichever of the allowed files existed

#### Scenario: Allowlist checked in the test suite
- **WHEN** the test suite reads `.dockerignore`
- **THEN** it ignores everything under `gateway/state/` except the allowed files, and ignores `gateway/demo.py`

### Requirement: Private keys are written owner-only
Every private key file the CLI writes SHALL be readable and writable by its owner only (mode `0600`).
This covers the issuer, gateway, agent and person keys.

#### Scenario: Fresh initialisation
- **WHEN** `gateway.cli init` writes `issuer_key.pem` and `gateway_key.pem`
- **THEN** both files have mode `0600`

#### Scenario: Key created on demand
- **WHEN** the CLI creates an agent or person key that did not exist
- **THEN** the new file has mode `0600`

### Requirement: Preflight check before posting the gateway URL
`make preflight GATEWAY_URL=<url>` SHALL fail unless every `/demo/*` route on that URL refuses and questions 0 to 5 pass there.

#### Scenario: Demo route reachable
- **WHEN** preflight runs and any of the five `/demo/*` routes answers with a 2xx status
- **THEN** preflight prints that route and its status, and exits non-zero

#### Scenario: Deployed gateway is clean and correct
- **WHEN** every `/demo/*` route refuses and `make eval_run` passes questions 0 to 5 against the URL
- **THEN** preflight exits zero
