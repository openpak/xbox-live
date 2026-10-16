# OpenPak original Xbox service plan

## Requirements confirmed 2026-10-16

Each Xbox service runs independently on the OpenPak server, in its own runtime
container image. Never put the whole network into one container or omnibus
runtime image. Shared protocol libraries and a source workspace are allowed.
Each service needs separate configuration, secret inputs, health checks and
independent deployment. Databases and caches remain private infrastructure.

The Xbox account adapter integrates with the existing account core, which stays
console-neutral. Native Xbox identity/protocol/credential translation belongs
in the adapter; Xombie's database is not a second OpenPak account authority.
Berth and physical Xbox consoles use the same native protocol endpoints.

## Candidate base and limits

Xombie is an AGPL-3.0 original Xbox Live proof of concept. It already separates
API, DNS, Kerberos and security gateway processes, but shares an omnibus runtime
image. That image is not the production design. Gateway transport may be shared
on the wire while application work routes to independently deployed services.
Upstream matchmaking state currently lives inside the security gateway and
needs explicit separation. Native coverage and console parity are unverified.

## Proposed runtime services

These are responsibilities, not existing deployments or reserved image names.

| Service | Responsibility | Starting point |
|---|---|---|
| Xbox account adapter | Native accounts/provisioning; account-core integration | Review API/provisioning code |
| Xbox authentication | Kerberos ticket operations | `services/kdc` |
| Xbox security gateway | Native secure transport; route application requests | `services/sg` |
| Xbox friends/presence | Native representation of shared account-core state | Protocol research |
| Xbox matchmaking | Session discovery and lifecycle | Review `libs/xombie-matchmaking` and gateway coupling |
| Xbox statistics | Per-title scores and leaderboards | Protocol research |
| Xbox content | Update/content delivery where needed | Protocol research |
| Xbox DNS | Native discovery/redirection if required | Review `services/faux-dns` |
| Title servers | Title-owned game protocols | Separate image per implementation |

## Implementation gates

1. Audit locked dependencies, per-file provenance, protocol coverage and
   inherited development constants. Preserve all license notices.
2. Establish the official-dashboard baseline in Berth and physical hardware.
3. Specify account-core integration and console/user credential lifecycle from
   observed native traffic, keeping console secrets out of source control.
4. Build separate service runtime images, remove omnibus production packaging,
   and separate gateway transport from application state/handlers.
5. Validate account linking/authentication, then friends and matchmaking between
   Berth and a physical Xbox using the same service endpoints.
6. Prepare established OpenPak deployment artifacts after local validation.

No container build, backend deployment, account-core integration or native
service compatibility has been demonstrated by this initial fork.
