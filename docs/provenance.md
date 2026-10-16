# Provenance review — 2026-10-16

Base: https://github.com/XombieOnline/xombie at
`7a1ef08045271437efc5938c996cb0c209a31408`.
Fork: https://github.com/openpak/xbox-live .

Root `LICENSE` and bundled `third_party/kerbeiros/LICENSE` and
`third_party/red_asn1/LICENSE` contain AGPL version 3. Preserve nested notices.
A complete Cargo.lock dependency and per-file provenance audit is pending.
Do not copy AGPL backend code into Berth's upstream emulator tree.

The upstream README labels the stack a proof of concept. Its compose exposes
cache/database ports and shares an all-binaries image. These defaults are not
adopted for production. No Insignia or leaked Microsoft source was used.

XboxLive.Server (zzVertigo) is archived and GitHub reports no license: not forked
or used as implementation input. OpenSpy core also has no detected root license
in GitHub metadata: potential GameSpy-specific follow-up only after explicit
per-component review, not a selected Xbox Live authentication base.

Reviewed upstream paths: README.md, LICENSE, Cargo.toml, Dockerfile,
docker-compose.yml, services/kdc/Cargo.toml, services/sg/Cargo.toml and the two
bundled license files above. Protocol implementation work must add packet or
public-document references; inherited code is not proof of hardware parity.

## Native gateway port follow-up

The supplied dashboard online module has a literal UDP destination 3074 store
in its native SG-init packet builder. Full evidence and capture limitations:
https://github.com/openpak/docs/blob/main/xbox/gateway-port-audit-2026-10-16.md .
This is independent client-code evidence; do not describe --sg-port as native
port negotiation. No backend service was started by the isolated capture test.
