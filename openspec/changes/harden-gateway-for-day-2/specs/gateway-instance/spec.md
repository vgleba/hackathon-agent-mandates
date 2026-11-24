## ADDED Requirements

### Requirement: Calls signed before the gateway started are refused
The gateway MUST refuse, with reason code `POP_FAILED`, any call or person request whose `ts` is earlier than the second its process started.
A restart that lost the nonce table therefore cannot accept a replay of a request signed before it.

#### Scenario: Replay after a restart
- **WHEN** a request signed and accepted before a restart is sent again after the restart, still inside the 300-second freshness window
- **THEN** the gateway answers `DENY` with reason code `POP_FAILED`, whether or not the nonce table survived

#### Scenario: Fresh call after a restart
- **WHEN** a request is signed after the gateway started
- **THEN** the start-time floor does not refuse it

#### Scenario: Person request signed before start
- **WHEN** a person request to `/holds/answer` has a `ts` earlier than the gateway's start
- **THEN** it is refused, and nothing is approved

### Requirement: Requests may not be dated far ahead
The gateway MUST refuse, with reason code `POP_FAILED`, any call or person request whose `ts` is more than 30 seconds after the decision time.
Requests up to 300 seconds old are still accepted.
Without this limit, a request future-dated before a restart could carry a `ts` past the start-time floor.

#### Scenario: Future-dated request
- **WHEN** a call carries a `ts` 31 seconds after the decision time
- **THEN** the gateway answers `DENY` with reason code `POP_FAILED`

#### Scenario: Slightly fast client clock
- **WHEN** a call carries a `ts` 20 seconds after the decision time
- **THEN** the freshness check accepts it

#### Scenario: Old but in window
- **WHEN** a call carries a `ts` 290 seconds before the decision time, after the gateway started
- **THEN** the freshness check accepts it

### Requirement: Healthcheck reports the instance
`GET /healthcheck` SHALL report an `instance` id and the `started` time in unix seconds.
The id is random per process and stays the same for that process's lifetime.

#### Scenario: Same process
- **WHEN** `/healthcheck` is called twice against one gateway process
- **THEN** both answers carry the same `instance` and `started`

#### Scenario: Restart or second replica
- **WHEN** `/healthcheck` answers come from two gateway processes, after a restart or from two replicas
- **THEN** the answers carry different `instance` values

### Requirement: Several processes may share one local state directory
The gateway MUST NOT refuse to start because another gateway process uses the same state directory.
Nonce, budget and hold updates stay atomic across those processes through SQLite transactions on a local filesystem.

#### Scenario: Two processes on one state directory
- **WHEN** two processes of this gateway start against one local state directory, as the lab does
- **THEN** both start
- **AND** a nonce used through one is refused as a replay through the other
