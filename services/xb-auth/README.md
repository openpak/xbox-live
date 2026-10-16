# xb-auth

Original Xbox Kerberos service (KDC), Go port of Xombie's `services/kdc`.
UDP 88 plus a private health listener. AGPL-3.0-only. Not deployed.

Flows (all in `internal/kdc`, structures in `internal/krb`):

- MACS (realm `MACS.XBOX.COM`): console proves its machine key (client-version
  MAC and encrypted timestamp) and receives its machine account `SN.<serial>`
  sealed under that key. No ticket is issued.
- AS: users and machine accounts sign in with pre-authentication. A user may
  add a machine TGT as compound identity; the reply is sealed with the
  compound key. Machine TGTs never work at the TGS.
- TGS: validates the TGT, authenticator and replay, re-checks the user with
  xb-account on every request, and issues a gateway ticket (sealed with the
  shared SG keyring) plus PA_XBOX_SERVICE_ADDRESS naming the public gateway.

Admission always comes from `xbaccountapi.Resolver` (ResolveGamertag,
ResolveUser, ResolveDevice) over mutual TLS. Unknown, banned, unlinked,
revoked or unreachable principals are refused; nothing is invented.
Devices additionally need proof material (`kdc.DeviceKeys`), fetched per MACS
request from xb-account (`GET /internal/v1/devices/{id}/key`, xb-auth peer
only, released only for an admitted device): without it MACS answers
"principal unknown".

## Configuration (environment; secrets are files)

| Variable | Meaning |
|---|---|
| `XB_AUTH_UDP_ADDR` | default `:88` (needs CAP_NET_BIND_SERVICE or the unprivileged-port sysctl) |
| `XB_AUTH_HEALTH_ADDR` | default `127.0.0.1:8088`; `/livez`, `/readyz` (listener only, not sign-in health) |
| `XB_GATEWAY_PUBLIC_IPV4` | advertised gateway; default 145.241.228.207; private/loopback/CGNAT refused |
| `XB_TGS_KEYRING_FILE` | TGT keys, 16 bytes each, local to xb-auth |
| `XB_SG_KEYRING_FILE` | gateway ticket keys, 16 bytes each, shared with xb-gateway |
| `XB_USER_KEY_SECRETS_FILE` | 32-byte secrets deriving user and machine-account keys |
| `XB_ACCOUNT_URL`, `XB_ACCOUNT_CA_FILE`, `XB_TLS_CERT_FILE`, `XB_TLS_KEY_FILE` | xb-account (https, TLS 1.3, client cert) |
| `XB_TGT_LIFETIME`, `XB_TICKET_LIFETIME`, `XB_CLOCK_SKEW`, `XB_REPLAY_MAX` | defaults 24h, 24h, 5m, 65536 |

Keyring files: `{"active":2,"keys":{"1":"<hex>","2":"<hex>"}}`. The id is the
key version carried in tickets; add a key and make it active, remove an old id
once its tickets have expired. Group/world-writable files, zero keys and the
published Xombie prototype keys are refused.

Machine id = the 12-digit serial as a number, 16 lowercase hex digits
(see docs/go-service-contracts.md item 4).

Open items: `KDC.UserAccountBlob` builds the account blob for a provisioned
user, but no network path hands it to a console yet; MACS still delivers only
the machine account (Xombie's MACS delivered the user account instead). Which
of the two a retail console expects is unverified on hardware.

Tests: `GOWORK=off go test -race ./internal/krb/ ./services/xb-auth/...`
(use a scratch TMPDIR). Everything is unit/in-process; no console or emulator
has signed in against it.
