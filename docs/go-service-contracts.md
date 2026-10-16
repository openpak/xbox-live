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
4. Machine ID (xb-account, xb-auth, xb-gateway): the console's 12-digit serial
   read as a decimal number, written as 16 lowercase hex digits
   (`xbaccountapi.MachineID`; serial 123456789012 = `0000001cbe991a14`).
   Valid range 1..999999999999 (`ValidMachineID`); XUIDs (`0009...`) are never
   valid machine IDs. xb-auth maps the MACS serial with `krb.MachineIDFromSerial`.
   xb-account enforces it at provisioning (Begin/Finalize) and in ResolveDevice.
5. Device proof material: provisioning's `proof` is the console's 16-byte machine
   key (`xbcrypto.MachineKey(hdd, online)`). xb-account stores it sealed
   (AES-GCM under a pepper-derived key, bound to the machine ID) plus a keyed
   MAC. `GET /internal/v1/devices/{id}/key` (`xbaccountapi.DeviceKeys`) returns
   it to `spiffe://openpak/xb-auth` only, and only after the full ResolveDevice
   admission (active device, active core link, active account). 403 denied,
   404 none. xb-auth's `devicekeys.Remote` is the production source;
   `XB_DEVICE_KEYS_FILE` is gone (the file store is test-only).
6. User account blob: `Principal.Gamertag` (users) lets xb-auth build the
   84-byte account blob (xuid, gamertag, domain, realm, `krb.DeriveUserKey`)
   via `KDC.UserAccountBlob`; the key is the one AS pre-authentication checks.
   The channel that delivers it to a console is not built (see xb-auth README).
7. In-process end-to-end: `test/e2e` (uses `services/*/testkit`, thin wrappers
   exposing the internal packages to tests only).
8. Gateway -> feature stream (`internal/xbfeature`): one bidirectional gRPC
   stream (`openpak.xb.v1.Feature/Connect`, `BytesValue` frames, no codegen) per
   console TCP connection. Frame 1 up = JSON `Info` bound by the gateway from the
   ticket; frame 1 down = empty ack; then raw bytes. mTLS, and the service must
   check the client cert URI `spiffe://openpak/xb-gateway` (`PeerIsGateway`).
   Wired through `XBGW_BACKENDS=<service id>=host:port`. Service 11 (Terms of Use,
   port 111) is plain HTTP/1.1: the stock 5960 dashboard first asks
   `GET /Country/America/CountryMaster2.INX` (`Content-type: xon/b`). `xb-tou`
   serves operator-supplied files only and answers 404 for anything else; the INX
   format and content are not yet known (no fabricated content).
9. SG packets to a console carry the console's own init SPI; packets from the
   console carry the gateway-chosen SPI (Xombie `client_to_sg_spi`).
