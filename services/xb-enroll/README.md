# xb-enroll

Thin public front for device-pairing enrolment of an original Xbox. Stateless
(rate-limit counters only, in memory). It exposes only:

- `POST /v1/enrol` `{machineID, machineKey, clientInfo?}` -> `{pairingCode, expiresAt, pollToken}`
- `GET /v1/enrol/{pollToken}` -> `{status: pending|approved|expired, expiresAt}`
- `GET /healthz` (container probe, touches nothing)

All state and decisions live in xb-account, reached over mTLS with the client
identity `spiffe://openpak/xb-enroll`; xb-account authorizes that identity for
the two enrolment routes only. The console-facing contract, limits, error codes
and the state machine are in workspace `docs/xbox/enrolment-contract.md`.

Configuration: `deploy/env/xb-enroll.env.example`. Image: `deploy/docker/Dockerfile.xb-enroll`
(or this directory's Dockerfile). Quadlet template: `deploy/quadlet/openpak-xb-enroll.container`.
Nothing here is deployed. Local verification: `GOWORK=off go test -race ./...`.
