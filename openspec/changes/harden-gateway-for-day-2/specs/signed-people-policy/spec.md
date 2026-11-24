## ADDED Requirements

### Requirement: The people policy is signed by the issuer
Every write of the people policy through the CLI MUST also write `people.jwt`. That file is a token of type `people+jwt`, signed with the issuer key and carrying the whole policy.
This covers `cli person`, `cli init`, and Desk, lab and eval runs that call the CLI.

#### Scenario: Adding a person
- **WHEN** `cli person --principal officer:new ...` runs against a state directory
- **THEN** `people.json` and `people.jwt` both hold `officer:new`
- **AND** `people.jwt` verifies against the issuer key on the trusted list

#### Scenario: Attack mandates add attacker entries
- **WHEN** `make attack_mandates` adds an `attacker:<team>` person
- **THEN** the signed policy holds that person

### Requirement: The gateway reads only the signed policy
The gateway MUST take people, clearances, budgets and person keys only from `people.jwt`.
It verifies that file against its trusted list on every read, and MUST NOT read `people.json`.

#### Scenario: Hand-edited plain policy
- **WHEN** someone edits `people.json` to raise a person's clearance and leaves `people.jwt` unchanged
- **THEN** the gateway keeps applying the clearance from `people.jwt`

#### Scenario: Policy signed by an untrusted key
- **WHEN** `people.jwt` is signed by a key that is not on the trusted list
- **THEN** every call that needs the policy is refused with reason code `POLICY_UNAVAILABLE`

### Requirement: Missing or unreadable policy fails closed
When `people.jwt` is missing, unreadable, of the wrong type or fails verification, the gateway MUST refuse every call and person request that needs the policy, with reason code `POLICY_UNAVAILABLE`. It MUST answer with a 4xx status, never 500.

#### Scenario: Policy file missing
- **WHEN** `people.jwt` does not exist and a valid call arrives
- **THEN** the gateway answers `DENY` with reason code `POLICY_UNAVAILABLE`

#### Scenario: Policy file cut short
- **WHEN** `people.jwt` holds a truncated token
- **THEN** the gateway answers `DENY` with reason code `POLICY_UNAVAILABLE`
- **AND** it keeps answering later requests
