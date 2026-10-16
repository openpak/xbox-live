# Go service contracts (coordination file)

Module `openpak/xb-live`. All new backend code is Go. Rust trees are reference only.

Ownership (no overlapping edits):
- protocol/auth agent: `internal/xbcrypto`, `internal/krb` (new), `services/xb-auth`
- account/social agent: `services/xb-account`, `services/xb-social`, `internal/xbaccountapi` (new, the xb-account client/server contract)
- gateway/deploy agent: `internal/sgwire`, `services/xb-gateway`, `deploy/` (new: per-service Dockerfiles, quadlets, firewall notes)
- Coordinator owns this file, go.mod/go.sum (agents may add deps; tell coordinator), docs/.

Contracts:
1. xb-account -> others: `internal/xbaccountapi` Go interface `Resolver` with
   ResolveUser(xuid) / ResolveDevice(machineID) -> {principalID, coreAccountID, status}
   and `Revocations` stream (event cursor, idempotent). Implemented by xb-account;
   consumed by xb-auth and xb-gateway. Auth between services: mutual TLS.
2. xb-auth -> xb-gateway: tickets are validated by the gateway using keys it
   shares with xb-auth (ticket validation key + rotation id); xb-auth exposes
   nothing the gateway needs beyond the ticket format. Gateway advertises
   public IP via config (secondary 145.241.228.207:3074), never a ZeroTier address.
3. gateway -> features: authenticated gRPC/mTLS over ZeroTier, connection context
   (principal, account, title, connection generation) bound by the gateway, never
   taken from the client. Unimplemented services return a native "unavailable",
   never a fabricated success.
