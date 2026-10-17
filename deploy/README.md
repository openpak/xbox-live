# Xbox Live backend: deployment artifacts

Nothing here has been deployed. These are reviewed-by-hand templates; no host,
firewall or DNS was touched. Placement and rollback policy come from
`docs/xbox/secondary-gateway-deployment.md` (workspace docs); this directory
only supplies the files.

## Layout

- `docker/` per-service Dockerfiles (`xb-gateway`, `xb-account`, `xb-auth`) and the image table. `xb-social` has a Dockerfile, quadlet and env template but is not to be deployed until its wire handlers exist.
- `quadlet/` Podman quadlet units (`openpak-xb-*.container`), same conventions as `servers/playfab/deploy`: `Network=openpak.network` on main, `%h/openpak/deploy/...` paths, `Restart=always`, `WantedBy=default.target`.
- `env/` example configuration. Contains **no secrets**; every key, certificate and the ticket validation key is a file mounted read-only under `/run/xb`.

Deliberate differences from older units: images are pinned by digest with no
`AutoUpdate=` (rollback needs a known image); read-only root filesystem, all
capabilities dropped, uid 10001; secrets are files, not entries in the shared
`.env`.

## Topology

| Host | Unit | Exposure |
|---|---|---|
| Secondary (public 145.241.228.207, ZeroTier 10.212.63.175) | `openpak-xb-gateway` | host network, UDP 3074 on the public interface; health on 127.0.0.1:3075 |
| Main (public 145.241.199.19, ZeroTier 10.212.63.196) | `openpak-xb-account` | private API published on 10.212.63.196 only |
| Main | `openpak-xb-auth` | native auth listener(s) per xb-auth; advertises the secondary public IP |

Gateway configuration separates **bind** (`XBGW_BIND`, a local interface) from
**advertise** (`XBGW_ADVERTISE_IP`, the public IP baked into tickets). The
secondary's public address is not local (NAT), so binding to it would fail and
advertising a local or ZeroTier address would break consoles. Startup rejects
private advertise addresses.

## Contracts the three services must agree on

1. **Ticket verification.** `gateway.TicketVerifier` (services/xb-gateway/internal/gateway/interfaces.go) takes the AP-REQ bytes and returns an `Identity` (XUID, session key, issued-for gateway IP, validity window, service-port list, authenticator time and checksum, key rotation id). xb-auth's `internal/krb` implements it using the shared ticket validation key. The gateway then enforces time window, clock skew (5 min), issued-for address == `XBGW_ADVERTISE_IP`, init checksum, AP-REQ replay cache, and an active account via xb-account. Without `XBGW_SG_KEYRING_FILE` the gateway reports **not ready** and rejects every init.
2. **Key distribution/rotation.** One ticket validation key plus a rotation id; xb-auth signs with the current id, the gateway must hold current and previous keys during rotation. Distribute as a file (`ticket.key`) over a channel that is not the repo or an image.
3. **mTLS.** Gateway client certificate must carry URI SAN `spiffe://openpak/xb-gateway`; xb-auth `spiffe://openpak/xb-auth` (xb-account enforces this). Feature backends use the same CA. TLS 1.3 minimum.
4. **Features.** `gateway.Backend` per numeric service id; the gateway binds principal, account, title and connection generation. An id without a backend, or a backend returning `ErrUnavailable`, gets a TCP reset: the native unavailable outcome. `GRPCBackend` is a dial/mTLS/health stub that always reports unavailable until a feature RPC contract exists.

## Firewall notes (proposed, not applied; provider ingress unverified)

Secondary (draughts-server). INPUT currently ends with a terminating REJECT and
has no UDP 3074 exception. Insert **before** that REJECT, idempotently, on the
public interface (`ens3` at inspection time) and persist with the host's
existing mechanism:

```sh
iptables -C INPUT -i ens3 -p udp --dport 3074 -j ACCEPT 2>/dev/null \
  || iptables -I INPUT <position before the REJECT rule> -i ens3 -p udp --dport 3074 -j ACCEPT
```

- UDP only. TCP 3074 stays closed unless a native protocol need is proven.
- The cloud provider's ingress rules (security list / network ACL) for UDP 3074 to the instance have **not been inspected**; confirm before relying on the host rule.
- The health port is loopback; do not publish it.
- Secondary needs outbound to main's ZeroTier address on the xb-account port (and later feature ports) only.

Main (quilted-waffle):

- xb-account (and later feature) ports are bound to 10.212.63.196 (ZeroTier) via `PublishPort=`. Allow them on the ZeroTier interface only from 10.212.63.175 and drop everything else to those ports; application mTLS is still required on top.
- UDP 3074 on main is occupied (Demonware) and must not be disturbed.
- Pick ports only after the main-host listener audit; every `REPLACE_PORT` is a placeholder.

## Deployment checklist

Do not skip ahead; each step has an observable pass condition.

1. Build images in CI (one repo at a time; locally under `flock /tmp/openpak-build.lock`). Confirm secondary CPU architecture and headroom; publish to a registry the secondary can reach (Docker Hub is not reachable there). Record digests.
2. Generate PKI: dedicated CA, server cert for xb-account, client certs with the URI SANs above, ticket validation key + rotation id. Store under `~/openpak/deploy/xbox/` with mode 0700/0600. Nothing secret enters git, an image or an env file.
3. Back up units/firewall that will change; note rollback image digests.
4. Start xb-account privately; verify authenticated calls succeed and calls with no/wrong certificate are rejected. Start xb-auth; verify it and the gateway agree on the ticket key id.
5. Start the gateway with ingress still closed. `curl 127.0.0.1:3075/healthz`: `listener` = `listening`, `ticket_verifier` and `directory` = `ok`, `e2e.state` = `never`. `/readyz` must be 200.
6. Add the UDP 3074 INPUT rule; verify provider ingress.
7. From outside both hosts, capture a native SG-init exchange (Berth first): AP-REQ with a valid ticket gets the init response; an invalid, expired, replayed or wrong-gateway ticket gets no reply. Then a physical console with one agreed title. `e2e.state` becomes `observed` only after a real handshake.
8. Confirm existing status and game services are healthy. Monitor `/metricsz` (init rejects, auth/replay/rate drops, unavailable services) and session counts; no keys or packets are logged.
9. Only after 7 change native DNS/TGS to advertise the gateway.

Rollback: remove only the new INPUT rule, stop `openpak-xb-gateway`, restore only the affected Xbox units/images. Leave Demonware on main and existing secondary services untouched.

## Known limits (honest status)

- Handshake, encryption, replay window, expiry, limits and service dispatch are unit-tested against Xombie's published vectors and a simulated native client over loopback. No real console or Berth session has been through this Go gateway.
- The in-tunnel TCP is minimal: in-order receive, no reassembly, no retransmission of gateway-sent data. Fine for request/response services on a clean path; loss recovery is future work.
- Revocation follows the xb-account stream from cursor 0 at startup (sessions are memory-only).
- The KDC-issued ticket path is tested with a ticket built exactly as `xb-auth`'s kdc builds it (internal/krb), not with the kdc package itself (it is `internal` to xb-auth and not importable here).
