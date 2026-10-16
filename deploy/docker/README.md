# Images

| Image | Dockerfile | Status |
|---|---|---|
| xb-gateway | Dockerfile.xb-gateway | builds from `services/xb-gateway` |
| xb-account | Dockerfile.xb-account | builds from `services/xb-account` (the service's own Dockerfile is equivalent) |
| xb-auth | Dockerfile.xb-auth | builds once `services/xb-auth/cmd/xb-auth` exists |
| xb-enroll | Dockerfile.xb-enroll | builds from `services/xb-enroll`; template only, not deployed (public exposure is a decision) |
| xb-social | none | planned; no Dockerfile or unit is shipped so nothing can be mistaken for a working endpoint |

Later feature services (presence, matchmaking, stats, etc.) follow the same
pattern: one image per service, no shared state in the gateway.

All builds use the module root as context and are static (`CGO_ENABLED=0`).
The runtime image is `scratch`: no shell, no package manager, uid 10001.
Container HEALTHCHECK is not used because scratch has no probe tool; the
gateway ships `xb-gateway healthcheck` and the quadlet uses it as `HealthCmd`.
Multi-arch: pass `--platform linux/arm64` (main host is arm64; confirm the
secondary's CPU architecture before pulling images there).
