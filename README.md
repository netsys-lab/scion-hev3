# scion-hev3

Happy Eyeballs v3 for SCION: a racing
client library, CLI, and demo server that connect over native SCION and
plain IPv6/IPv4 in parallel and use whichever wins. It implements
*SCION-Aware Happy Eyeballs* (draft-john-scion-happy-eyeballs,
[netsys-lab/draft-scion-happy-eyeballs](https://github.com/netsys-lab/draft-scion-happy-eyeballs));
SCION endpoints are discovered through the `scion` SvcParam of
draft-john-scion-svcb
([netsys-lab/draft-scion-svcb](https://github.com/netsys-lab/draft-scion-svcb)).

Built for the SCION testbed at the IETF 126 hackathon
([ietf-scion-testbed](https://github.com/netsys-lab/ietf-scion-testbed)).

## Contents

- `pkg/hev3/` - the racer: resolves a name (by default the HTTPS query
  only; `scion=` SvcParam, A/AAAA, ipv4hint/ipv6hint) and builds endpoints.
  Each SCION address of each ServiceMode record is one endpoint with that
  record's port and priority; the path belongs to the connection attempt.
  The path lookup is shared per ISD-AS and limited to 2 s, daemon connect
  included. Paths are looked up for at most 4 distinct destination ASes
  (the own AS does not count); endpoints in further ASes are not attempted.
  When the attempt starts, it selects
  up to Path Attempt Count paths (fewest AS hops, random order among equals,
  then least overlap with the paths already selected: shared transit ASes,
  then shared pairs of adjacent ASes, then shared inter-AS links; paths that expire within 5 minutes or
  have too small an MTU are excluded) and starts a separate QUIC connection
  on each, one Path Attempt Delay (50 ms) apart, each from its own local
  port. The first connection to complete the handshake is used; the others
  are closed. SCMP errors are recorded and do not end an attempt. SCION
  attempts race IP attempts with HEv3 staggering (SCION first by default,
  then the first IP family after RFC 6724) and live DNS merge. No two
  attempts start less than 10 ms apart, counting the attempts over further
  paths of a SCION endpoint. A SCION-first client waits for a path lookup
  no longer than the Resolution Delay (25 ms) after the first IP answer. Uses
  [scionproto/scion](https://github.com/scionproto/scion) snet
  (dispatcherless) and quic-go.
- `cmd/hev3` - CLI: `hev3 https://web.scion/` fetches over whichever
  endpoint wins and prints the race table (`-json` for a JSON summary).
  SCION knobs: `-k` (Path Attempt Count, default 2), `-path-attempt-delay`
  (default 50ms, not below 10ms), `-family-order scion-first|ip-first`,
  `-daemon`, `-max-ases` (limit on destination ASes with a path lookup,
  default 4), `-rr-type https|svcb|both` (default `https`; `both` also
  sends an SVCB query, for zones that publish only SVCB records).
  `-adaptive-delay` (off by default, not in the draft) shortens the race
  stagger after a SCION endpoint from the declared latency of its first
  path; `-no-adaptive-delay` is still accepted and has no effect.
  `-path-mode copy` selects an alternative (one QUIC
  connection whose datagrams are copied onto several paths, with
  `-path-delay`); it is kept for comparison only. Experiment knobs:
  `-scion ISD-AS,IP:port` (direct SCION target, no DNS; the URL host stays
  the TLS name), `-repeat N` (N fetches in one process, fresh connection
  each, shared daemon connection), `-stats` (per-run path lookup time, path
  attempts with start offsets, packets and octets per path, winning path,
  SCMP events; also in `-json`), `-exp-corrupt-path N` (corrupt the first
  hop MAC of path N so the first router drops it), `-exp-refresh-paths`
  (ask the daemon to fetch paths anew), `-linger` (how long a losing
  connection is kept so that it can be closed with CONNECTION_CLOSE),
  `-deterministic-paths` (no random order among equal paths).
- `cmd/hev3-server` - demo target: serves h3/h2 on plain-IP listeners and
  HTTP/3 over native SCION (dispatcherless snet, `-scion -scion-ip IP
  -scion-port PORT`) on a separate bind address. `-conn-log FILE` writes one
  JSON line per ended SCION QUIC connection (lifetime, packets and octets
  in each direction, how it was closed).

Example against a SCION endpoint, skipping DNS:

```
hev3 -scion 1-152,10.152.0.81:443 -stats -repeat 5 https://web.scion/
```

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

- DNS parsing uses a
  [forked miekg/dns](https://github.com/netsys-lab/dns-scion-svcb) (branch
  `scion`) with a typed `scion` SvcParamKey (Private Use key 65280 until
  IANA assigns one; see `go.mod`).
- The TLS material the demo server presents (and the CA the CLI trusts at
  `/etc/hev3/ca.pem`) is throwaway, committed-on-purpose testbed key
  material — never trust it outside a testbed.
