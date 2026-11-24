## ADDED Requirements

### Requirement: A root mandate is refused from its expiry second
The gateway MUST refuse a root mandate with reason code `EXPIRED` when the decision time is at or after the mandate's `exp`, with no grace period.

#### Scenario: One second before expiry
- **WHEN** a correctly signed call arrives and the decision time is `exp - 1`
- **THEN** the mandate passes the expiry check

#### Scenario: At expiry
- **WHEN** a correctly signed call arrives and the decision time equals `exp`
- **THEN** the gateway answers `DENY` with reason code `EXPIRED`

#### Scenario: Five seconds after expiry
- **WHEN** a correctly signed call arrives and the decision time is `exp + 5`
- **THEN** the gateway answers `DENY` with reason code `EXPIRED`

### Requirement: A child mandate is refused from its expiry second
The gateway MUST refuse a helper's child mandate with reason code `EXPIRED` when the decision time is at or after the child's `exp`.
The parent's expiry is still checked as for any root mandate.

#### Scenario: Child at expiry
- **WHEN** a helper calls with a child mandate and the decision time equals the child's `exp`
- **THEN** the gateway answers `DENY` with reason code `EXPIRED`

#### Scenario: Parent expired, child not
- **WHEN** a helper calls with a child mandate whose own `exp` is ahead, but the decision time is at or after the parent's `exp`
- **THEN** the gateway answers `DENY` with reason code `EXPIRED`

### Requirement: Clock tolerance applies only to the start of validity
The gateway SHALL accept a mandate whose `nbf` is up to 30 seconds after the decision time, and SHALL NOT extend any mandate past its `exp`.

#### Scenario: Issuer clock slightly ahead
- **WHEN** a mandate's `nbf` is 20 seconds after the decision time
- **THEN** the mandate passes the validity checks

#### Scenario: Not yet valid
- **WHEN** a mandate's `nbf` is 40 seconds after the decision time
- **THEN** the gateway answers `DENY` with reason code `NOT_YET_VALID`

### Requirement: One decision reads the clock once
Every time check within one decision MUST use the same instant, read once when the decision starts.
This covers mandate `nbf` and `exp`, child `exp`, request freshness and the start-time floor.

#### Scenario: Clock passes expiry during a decision
- **WHEN** a decision starts at `exp - 1` and the clock reaches `exp` before the decision finishes
- **THEN** every check in that decision uses `exp - 1`, and the mandate passes the expiry check

### Requirement: Held calls are released only while the mandate is valid
A call waiting for a person's approval MUST be refused at release with reason code `EXPIRED` if its mandate's `exp` has passed by then.

#### Scenario: Approved after the mandate expired
- **WHEN** a person approves a held call after the mandate's `exp`
- **THEN** the call is not run, and the agent collecting it gets a refusal with reason code `EXPIRED`
