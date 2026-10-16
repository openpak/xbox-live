# xb-account

Original Xbox identity adapter for OpenPak. This independently built service
calls account core's existing gRPC Links and Identity contracts. It never reads
core tables or exports passwords, Kerberos keys, email or web sessions.

`POST /internal/v1/resolve` accepts `{"gamertag":"Player One"}` and returns
`{"xuid":"0009000000000001","account_id":"…","display_name":"…"}` only for
an active `xbox` link and active account. Provisioning must publish the native
gamertag as that link's public code and use a canonical 16-character lowercase
hexadecimal XUID as its subject. This lookup does not prove possession of a
native credential: xb-auth/xb-gateway must validate native tickets separately.
Machine/device principals and provisioning are not implemented by this lookup.

The server requires TLS 1.3 and a client certificate signed by its dedicated CA,
with URI SAN `spiffe://openpak/xb-auth` or `spiffe://openpak/xb-gateway`.
`GET /livez` uses the same mutual TLS and only reports listener liveness.
No readiness or successful native-sign-in claim follows from that endpoint.

Configuration (all secrets are service-managed files):

- `XB_LISTEN_ADDR`: private bind address and port, chosen after host port audit.
- `XB_TLS_CERT_FILE`, `XB_TLS_KEY_FILE`: server certificate chain and key.
- `XB_CLIENT_CA_FILE`: dedicated client CA for authorized Xbox workloads.
- `XB_CORE_ADDR`, `XB_CORE_KEY_FILE`: core gRPC target and internal bearer secret.
- `XB_CORE_CA_FILE`, optionally `XB_CORE_SERVER_NAME`: core TLS trust/identity.
- `XB_CORE_PLAINTEXT_INTERNAL=1`: explicit alternative only on the existing
  private container network when core uses its current plaintext gRPC listener.

Every lookup has a three-second total core deadline, checks account status, and
rechecks its link before returning. No positive identity cache is used. Core
unavailability returns 503; unknown/revoked identity 404; disabled account 403.
Requests and core responses are never logged. In-flight sessions still require
future invalidation/event handling; this lookup only governs admission.

Build this directory's Dockerfile as the separate `xb-account` image. Local
verification: `GOWORK=off go test -race ./...` and `GOWORK=off go vet ./...`.
Use a workspace scratch directory as TMPDIR. No production unit is enabled by
this source change.

## Principals, provisioning and revocation

State lives in an embedded SQLite file (`XB_DB_PATH`, pure-Go modernc driver,
WAL). Chosen over Postgres because the state is small and single-writer, it
needs no new database/role in production, and the image stays CGO-free. The
core's Postgres is never shared. `XB_PEPPER_FILE` holds >=32 bytes of hex used
to key the device-proof MAC (proofs are never stored).

Distinct principal spaces: user (XUID, link namespace `xbox`, never `xbl`) and
device (machine ID). One primary Xbox user per core account; gamertags are
unique, case-insensitive aliases released on unlink/delete.

Contract `internal/xbaccountapi` (mTLS; xb-auth and xb-gateway): `ResolveUser`,
`ResolveGamertag`, `ResolveDevice`, and the `Revocations` poll stream. Each
resolve re-reads core (link + account status) and denies banned, unlinked,
revoked, deleted or unavailable. Revocations are a durable outbox fed by the
core event cursor (`account_banned/unbanned`, `link_unlinked`,
`account_delete_started/deleted`, `credential_revoked`), idempotent by event id.
An unlink also revokes the account's devices.

Provisioning (`xb-provisioner` begins, `xb-auth` finalizes): web approval mints
a 10-minute single-use token bound to a core account, machine ID and a
device-generated challenge. Finalize resumes/replays safely: mint XUID,
ReserveLink, ActivateLink, SetLinkPublicCode(gamertag), local commit, with
deterministic idempotency keys; terminal failures UnlinkLink and burn the token.

**Generic password verification is not Kerberos proof.** Neither a core password
check, a provisioning token, nor the stored device proof MAC authenticates a
native Kerberos exchange; xb-auth must validate pre-authentication itself.

## Device-pairing enrolment and subscription codes

`internal/enrol` and `internal/voucher` add enrolment without the dashboard
supplying the machine key: a console tool registers a pending enrolment through
`xb-enroll` (SPIFFE `spiffe://openpak/xb-enroll`, two routes only), the website
approves it for a core account (SPIFFE `xb-provisioner`), and the device is
linked (ReserveLink/ActivateLink, XUID reserved, no gamertag yet). Subscription
codes are issued by the website and consumed by `enrol.CompleteSignup`. Routes,
states, limits and error codes: workspace `docs/xbox/enrolment-contract.md`.
The service-5 wire handling for verifyvoucher/createowneracct is not implemented.
