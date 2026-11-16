// Package hev3 implements a SCION-aware Happy Eyeballs v3 dialer:
// draft-ietf-happy-happyeyeballs-v3 extended with SCION as a third address
// family per draft-john-scion-happy-eyeballs. SCION addresses come from the
// `scion` SvcParam of draft-john-scion-svcb. A SCION address is one endpoint.
// A connection attempt to it selects up to Path Attempt Count paths
// (pathset.go) and starts a separate QUIC connection on each, one Path
// Attempt Delay apart (attempts.go). The earlier design, one QUIC connection
// copied onto several paths (racer.go), remains as PathModeCopy.
package hev3

import "time"

// Family identifies the address/transport family a Candidate belongs to.
type Family int

const (
	FamilySCION Family = iota
	FamilyIPv6
	FamilyIPv4
)

// SCIONPath describes one path of a SCION endpoint's ranked path set
// (pathset.go).
type SCIONPath struct {
	Fingerprint string
	Latency     time.Duration // summed declared latency; 0 = unknown (no entry set)
	Hops        int           // AS hops: ASes on the path (pathASHops)
	Interfaces  string        // human-readable interface sequence, for stats
	Down        bool          // ranked last: traverses an interface in the SCMP down cache
	SNET        any           // holds snet.Path; typed as any so pure-logic packages need no scionproto import
}

// Candidate is one dialable destination: an IP address+port, or a SCION
// endpoint (address+port) with its ranked path set.
type Candidate struct {
	Family    Family
	Host      string // IP literal, or SCION host IP
	Port      uint16
	IA        string      // "1-150"; empty for IP families
	Path      *SCIONPath  // top-ranked path of PathSet (== &PathSet[0]); nil for IP families, the scitra leg and unexpanded SCION endpoints
	PathSet   []SCIONPath // ranked path set, at most K paths (draft-john-scion-happy-eyeballs Path Selection)
	ViaScitra bool        // SCION-derived candidate dialed as mapped IPv6
	ALPN      []string    // from SVCB; empty = default (https => try h2/h1.1 TCP)
	GroupALPN []string    // the covering record's full supported ALPN set, used for Sec 5.1 grouping; nil = group by ALPN
	Priority  uint16      // SvcPriority
	Label     string      // stable human id, e.g. "scion:1-150,10.0.0.1#paths", "v6:2001:db8::1", "v4+tcp:..."
}
