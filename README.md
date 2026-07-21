# scion-hev3

Happy Eyeballs v3 for [SCION](https://scion-architecture.net/): a racing
client library, CLI, and demo server that connect over native SCION and
plain IPv6/IPv4 in parallel and use whichever wins. The companion IETF
draft work that makes SCION endpoints discoverable through DNS lives in
[netsys-lab/draft-scion-svcb](https://github.com/netsys-lab/draft-scion-svcb).

Built for the SCION testbed at the IETF 126 hackathon
([ietf-scion-testbed](https://github.com/netsys-lab/ietf-scion-testbed)).

## Contents

- `pkg/hev3/` — the racer: resolves a name (HTTPS/SVCB `scion=`/
  `scion-policy=` SvcParams, A/AAAA, ipv4hint/ipv6hint), builds candidates,
  races SCION (QUIC/h3 via [snet](https://github.com/lschulz/scion))
  against IP legs with HEv3-style staggering, live DNS merge and
  latency-adaptive staggering, returns the winning connection.
- `cmd/hev3` — CLI: `hev3 https://web.scion/` fetches over whichever
  transport wins and can dump the race timeline (`--json`,
  `--rr-type https|svcb|both`, `-pfc` for preferred-family count per
  interleave round, `--scion-grace` as an optional demo knob: hold IP legs
  while SCION looks up paths).
- `cmd/hev3-server` — demo target: serves h3/h2 on plain-IP listeners and
  native SCION (dispatcherless snet/squic) on a separate bind address.

The companion Internet-Drafts — *The scion SVCB Service Parameter* (the
`scion` 65280 and `scion-policy` 65281 SvcParamKeys: wire formats, fail-open
rules, test vectors) and *SCION-Aware Happy Eyeballs* (the client algorithm
this library implements: asynchronous path expansion, three-family sorting,
adaptive staggering, the optional Expansion Delay) — are maintained in
[netsys-lab/draft-scion-svcb](https://github.com/netsys-lab/draft-scion-svcb).

## Build & test

```
make build   # bin/hev3, bin/hev3-server
make test
make deb     # dist/scion-hev3_<version>_amd64.deb
```

The full DNS→race→fetch integration test needs a checkout of the testbed
repo (zone files, demo CA, SCION-patched CoreDNS build script):

```
TESTBED_ROOT=/path/to/ietf-scion-testbed bash integration/devbox_test.sh
```

## Notes

- SCION support relies on the [lschulz/scion](https://github.com/lschulz/scion)
  fork (snet/squic) and a
  [forked miekg/dns](https://github.com/netsys-lab/dns-scion-svcb) (branch
  `scion`) with typed `scion`/`scion-policy` SvcParamKeys (see `go.mod`).
- The TLS material the demo server presents (and the CA the CLI trusts at
  `/etc/hev3/ca.pem`) is throwaway, committed-on-purpose testbed key
  material — never trust it outside a testbed.
