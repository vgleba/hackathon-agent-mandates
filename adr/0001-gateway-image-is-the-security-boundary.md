# ADR-0001: The gateway image is the security boundary

- Status: accepted
- Date: 2026-11-23
- Supersedes: none
- Change: `openspec/changes/harden-gateway-for-day-2`

## Context

On Day 2 the organisers run the gateway on AWS, and the team cannot see that config. Nothing the team writes outside the image is guaranteed to apply:
- environment variables;
- replica count;
- storage;
- ingress;
- restart policy;
- whether `docker-compose.yaml` is read at all.

The red-team report showed what happens when safety depends on a deploy setting. The committed compose file switched on the demo routes, so an unauthenticated caller could have the gateway mint and sign for them. The production image also carried every file in `gateway/state/`, including the issuer's private key, which the running gateway never reads.

## Decision

The image built from `gateway/Dockerfile` must be safe whatever deployment config it runs under:

1. It contains no code path that issues mandates or signs for a caller. The demo router is left out of the image, not merely switched off.
2. It carries only the state files the running gateway reads: trusted list, status list, people policy and the gateway's own key. It carries no issuer, agent or person private keys.
3. Limits that protect availability and freshness are enforced in the application, not left to ingress or the platform: body and field sizes, expiry, timestamp window, start-time floor.
4. What cannot be enforced inside the image is made observable from outside instead, for example several replicas or restarts reported on `/healthcheck`. It is then raised with whoever runs the platform.

Developer conveniences that would break these rules (the demo routes, the walkthrough UI) live in an opt-in compose overlay that the deploy path does not load.

## Consequences

- The deploy is safe even if the platform sets `GATEWAY_DEMO=1`, publishes extra ports or copies our state directory in.
- Local demo runs need the overlay (`make hack` or `make demo`). `make run` matches the deploy and has no demo.
- Every new runtime state file must be added to the `.dockerignore` allowlist on purpose. A test that boots the gateway from only the allowlisted files catches an omission.
- Replicas and lost storage stay platform risks. The image can detect them and limit replay after a restart, but it cannot share state across replicas.
- Future changes that add a privileged route or a new secret must keep it out of the image, or justify it in a superseding ADR.
