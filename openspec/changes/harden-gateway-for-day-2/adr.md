# ADR Review Manifest

## ADR Review Completed

- Date: 2026-11-23
- Reviewer: Claude (Opus 5.5), for Volodymyr Gleba
- Change: harden-gateway-for-day-2

## In-Force ADR Context Reviewed

- None: no repository-level ADRs existed (`adr/` was absent before this change).

## Repository-Level ADRs Created

- adr/0001-gateway-image-is-the-security-boundary.md: the image built from `gateway/Dockerfile` must be safe under any deployment config. It has no mint or sign route and carries only the state files the gateway reads. Limits are enforced in the application, and anything it cannot enforce is made observable.

## Notes

- Not recorded as an ADR: the signed people policy (design D10). It is the last task group in this change and may be dropped for Day 2. If it lands, a follow-up ADR can record "every control file the gateway trusts is signed by the issuer", which the status list already follows.
- The design's decisions on body-cap placement, nonce digests and the start-time floor are tactical. They implement ADR-0001 rather than adding new commitments.
