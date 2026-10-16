# Xbox backend source migration plan

The canonical cross-repository architecture is
[Original Xbox on OpenPak](https://github.com/openpak/docs/blob/main/xbox/native-service-architecture.md).
It defines the account-core boundary, service-specific runtime images, native
client path, routing conflict and acceptance milestones. Do not duplicate that
contract here.

This repository is a candidate native-protocol base, not a deployed backend.
The initial source migration is:

1. Audit the locked dependencies and per-file provenance; preserve AGPL notices.
2. Remove credential-bearing connection-string and raw authentication logging.
3. Replace the placeholder API and forwarding stub with the account/provisioning
   adapter; bind Xbox XUIDs to core accounts using the existing core contract.
4. Separate KDC/auth and security gateway behind explicit authenticated APIs;
   keep protocol proof keys out of account core and public logs.
5. Extract presence/friends and matchmaking from the gateway. Replace empty
   success replies with implemented behavior or native unavailable errors.
6. Build one runtime image per service, with isolated configuration/state and
   health checks. Do not deploy the inherited all-binaries Dockerfile/compose.
7. Complete native sign-in fixtures, account-core invalidation handling and
   physical-console acceptance before any production release.

No Xbox backend container is running as a result of this planning work.
See [provenance](provenance.md) for the initial review scope.
