# OpenPak original Xbox services

> **Split 2026-10-17.** The Go services and shared packages in this repository
> now live in one repository each. This repository is the legacy Rust (Xombie)
> reference and provenance record; the Go trees under `services/xb-*` and
> `internal/` are frozen at commit `7fc575dd21485791ed80149deba4f158e66044ae`
> and are no longer maintained here.
>
> | Repo | Replaces |
> |---|---|
> | [xb-common](https://github.com/openpak/xb-common) | `internal/{xbcrypto,krb,xbaccountapi,xbenrolapi,xbfeature,ratelimit}` |
> | [xb-account](https://github.com/openpak/xb-account) | `services/xb-account`, `internal/xbcodes` |
> | [xb-auth](https://github.com/openpak/xb-auth) | `services/xb-auth` |
> | [xb-gateway](https://github.com/openpak/xb-gateway) | `services/xb-gateway`, `internal/sgwire` |
> | [xb-social](https://github.com/openpak/xb-social) | `services/xb-social` |
> | [xb-enroll](https://github.com/openpak/xb-enroll) | `services/xb-enroll` |
> | [xb-tou](https://github.com/openpak/xb-tou) | `services/xb-tou` |
> | [xb-dns](https://github.com/openpak/xb-dns) | `services/xb-dns` |
> | [xb-e2e](https://github.com/openpak/xb-e2e) | `test/e2e` |
>
> Git history of each service is preserved in its new repository.

Fork of [Xombie](https://github.com/XombieOnline/xombie), AGPL-3.0.
This is an evaluation base, not a deployed OpenPak service stack.

Xbox services must have separate runtime images and independent deployments.
The Xbox account adapter talks to existing account core. Berth and physical
Xbox consoles use the same native endpoints. Do not deploy the inherited
omnibus Dockerfile or example compose setup to production.

See [the implementation plan](docs/openpak-plan.md) and
[provenance](docs/provenance.md).

The inherited README follows as historical context; its host DNS modification
instructions are not OpenPak setup instructions.

---

Xombie
======

Replacement Original Xbox Live Infrastructure

Notes
-----

**This is a proof of concept!  Some keys are chosen by fair dice rolls,
databases are exposed on default ports with default credentials, etc. Run at
your own risk.**

Running
-------

```docker-compose up -d```

Notes:

Ubuntu 20.04 runs dnsmasq by default.  To disable dnsmasq first disable systemd-resolved with

```$ sudo service systemd-resolved stop```


Then edit systemd's config to remove it by adding ```DNSStubListener=no``` to ```/etc/systemd/resolved.conf```.

Then keep NetworkManager from overwriting your /etc/resolv.conf by adding
```dns=none``` to the ```[main]``` section of ```/etc/NetworkManager/NetworkManager.conf```.

Then remove the symlink to systemctl's ```/etc/resolv.conf``` with 
```$ rm /etc/resolv.conf```

Then write your own resolv.conf containing (for instance to use google's DNS
servers)

```nameserver  8.8.8.8```
