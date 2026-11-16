package hev3

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

// Candidate path selection for a SCION endpoint
// (draft-john-scion-happy-eyeballs, "Candidate Paths"): from the paths the
// client knows to the endpoint's AS, select at most Path Attempt Count
// candidate paths.

const (
	// defaultPathAttemptDelay is the default Path Attempt Delay: the time
	// between the starts of the attempts to one SCION endpoint over its
	// candidate paths.
	defaultPathAttemptDelay = 50 * time.Millisecond
	// minPathAttemptDelay is the lowest Path Attempt Delay allowed (the
	// lower bound of HEv3, Section 6, for the time between two attempts).
	minPathAttemptDelay = 10 * time.Millisecond
	// pathLookupLimit is how long a path lookup may take before the client
	// gives up on it.
	pathLookupLimit = 2 * time.Second
	// defaultPathDelay is the default Path Delay of the copy-racing mode
	// (racer.go), which is not part of the draft.
	defaultPathDelay = 50 * time.Millisecond
	// pathExpiryMargin: a path expiring within it is selected only if no
	// other path is left.
	pathExpiryMargin = 5 * time.Minute
	// quicMinDatagram is the smallest UDP payload of a client's first QUIC
	// datagram (RFC 9000 Sec 14.1). SCION dials pin quic.Config's
	// InitialPacketSize to it, so the MTU check matches what is sent.
	quicMinDatagram = 1200
	// downCacheTTL is how long an interface reported down by SCMP demotes
	// paths through it.
	downCacheTTL = 10 * time.Second

	scionCommonHdrLen = 12
	udpHdrLen         = 8
)

// scionHdrLen returns the size of the SCION common + address + path header
// for the given host address lengths (4 or 16) and raw path length.
// Address header = 2 x 8 (ISD-AS) + destination host + source host
// (24 octets for two IPv4 hosts, 48 for two IPv6 hosts).
func scionHdrLen(dstHostLen, srcHostLen, pathLen int) int {
	return scionCommonHdrLen + 16 + dstHostLen + srcHostLen + pathLen
}

// hostLen is the SCION address-header length of a host address.
func hostLen(a netip.Addr) int {
	if a.Unmap().Is4() {
		return 4
	}
	return 16
}

// dataplaneLen returns the length of the path header of p (for the SCION
// path type, 4 + 8*numInfo + 12*numHops = len(Raw)); 0 for an empty or
// unknown dataplane path.
func dataplaneLen(p snet.Path) int {
	if p == nil {
		return 0
	}
	if sp, ok := p.Dataplane().(snetpath.SCION); ok {
		return len(sp.Raw)
	}
	return 0
}

// pathASHops is the number of ASes a path traverses: an inter-AS path's
// metadata lists two interfaces per crossed link, so N interfaces cross N/2
// links and traverse N/2+1 ASes. An AS-local path (no interfaces) is 1.
func pathASHops(md *snet.PathMetadata) int {
	if md == nil {
		return 1
	}
	return len(md.Interfaces)/2 + 1
}

// ifKey identifies one SCION interface.
type ifKey struct {
	IA addr.IA
	ID uint64
}

func (k ifKey) String() string { return fmt.Sprintf("%s#%d", k.IA, k.ID) }

// linkKey is an inter-AS link: the unordered pair of interfaces at its ends.
type linkKey struct{ a, b ifKey }

func newLinkKey(x, y ifKey) linkKey {
	if y.IA < x.IA || (y.IA == x.IA && y.ID < x.ID) {
		x, y = y, x
	}
	return linkKey{x, y}
}

// pathAttemptDelay returns the Path Attempt Delay in use for a configured
// value: 0 (or negative) is the default; a value below minPathAttemptDelay
// is raised to it; a value above the Connection Attempt Delay in use
// (attemptDelay, 0 = unknown) is lowered to it.
func pathAttemptDelay(configured, attemptDelay time.Duration) time.Duration {
	d := configured
	if d <= 0 {
		d = defaultPathAttemptDelay
	}
	if attemptDelay > 0 && d > attemptDelay {
		d = attemptDelay
	}
	if d < minPathAttemptDelay {
		d = minPathAttemptDelay
	}
	return d
}

// asPair is a pair of adjacent ASes of a path (unordered).
type asPair struct{ a, b addr.IA }

func newASPair(x, y addr.IA) asPair {
	if y < x {
		x, y = y, x
	}
	return asPair{x, y}
}

// pathPairs lists the pairs of adjacent ASes of a path, one per inter-AS
// link (several links between the same two ASes give the same pair).
func pathPairs(md *snet.PathMetadata) []asPair {
	var out []asPair
	seen := map[asPair]bool{}
	for _, l := range pathLinks(md) {
		p := newASPair(l.a.IA, l.b.IA)
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// pathTransit lists the transit ASes of a path: the ASes of its hops other
// than the first and the last.
func pathTransit(md *snet.PathMetadata) []addr.IA {
	if md == nil || len(md.Interfaces) < 2 {
		return nil
	}
	first, last := md.Interfaces[0].IA, md.Interfaces[len(md.Interfaces)-1].IA
	var out []addr.IA
	seen := map[addr.IA]bool{first: true, last: true}
	for _, pi := range md.Interfaces {
		if !seen[pi.IA] {
			seen[pi.IA] = true
			out = append(out, pi.IA)
		}
	}
	return out
}

// pathLinks lists the inter-AS links of a path: consecutive metadata
// interfaces whose ISD-AS differ.
func pathLinks(md *snet.PathMetadata) []linkKey {
	if md == nil {
		return nil
	}
	var out []linkKey
	for i := 0; i+1 < len(md.Interfaces); i++ {
		a, b := md.Interfaces[i], md.Interfaces[i+1]
		if a.IA == b.IA {
			continue
		}
		out = append(out, newLinkKey(ifKey{a.IA, uint64(a.ID)}, ifKey{b.IA, uint64(b.ID)}))
	}
	return out
}

// declaredLatency sums the declared per-hop latencies, ignoring unset (-1)
// entries. known is false if no entry is set.
func declaredLatency(md *snet.PathMetadata) (total time.Duration, known bool) {
	if md == nil {
		return 0, false
	}
	for _, d := range md.Latency {
		if d >= 0 {
			total += d
			known = true
		}
	}
	return total, known
}

func interfacesString(md *snet.PathMetadata) string {
	if md == nil || len(md.Interfaces) == 0 {
		return "(AS-local)"
	}
	parts := make([]string, len(md.Interfaces))
	for i, pi := range md.Interfaces {
		parts[i] = fmt.Sprintf("%s#%d", pi.IA, pi.ID)
	}
	return strings.Join(parts, " ")
}

// downCache is the process-wide negative cache of interfaces reported down
// by SCMP External Interface Down / Internal Connectivity Down. Entries
// demote paths through them for downCacheTTL.
type downCache struct {
	mu sync.Mutex
	m  map[ifKey]time.Time // expiry
}

var scmpDownCache = &downCache{m: map[ifKey]time.Time{}}

func (c *downCache) add(ia addr.IA, id uint64, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[ifKey{ia, id}] = now.Add(downCacheTTL)
}

// pathDown reports whether md traverses an interface reported down within
// the TTL.
func (c *downCache) pathDown(md *snet.PathMetadata, now time.Time) bool {
	if c == nil || md == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, pi := range md.Interfaces {
		if exp, ok := c.m[ifKey{pi.IA, uint64(pi.ID)}]; ok {
			if now.Before(exp) {
				return true
			}
			delete(c.m, ifKey{pi.IA, uint64(pi.ID)})
		}
	}
	return false
}

func (c *downCache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m = map[ifKey]time.Time{}
}

// pathSetParams configures selectPathSet.
type pathSetParams struct {
	K          int
	Now        time.Time
	DstHostLen int // 4 or 16
	SrcHostLen int // 4 or 16; 16 when the local address is unknown (conservative)
	Down       *downCache
	// Random makes the ranking break ties at random (the draft's default
	// policy). Without it ties go to the lower declared latency, then the
	// fingerprint (deterministic; tests and the copy-racing mode).
	Random bool
	// AllowSoon also selects paths expiring within pathExpiryMargin, after
	// all others (the list of the paths known for an endpoint).
	AllowSoon bool
}

// rankedPath is one path with the keys the ranking compares.
type rankedPath struct {
	p        snet.Path
	down     bool
	hops     int
	lat      time.Duration
	latKnown bool
	fp       string
	links    []linkKey
	pairs    []asPair
	transit  []addr.IA
	expiry   time.Time
	random   bool
}

// overlap is what a path shares with the paths already selected, compared
// from the widest scope of failure to the narrowest.
type overlap struct{ transit, pairs, links int }

func (a overlap) less(b overlap) bool {
	if a.transit != b.transit {
		return a.transit < b.transit
	}
	if a.pairs != b.pairs {
		return a.pairs < b.pairs
	}
	return a.links < b.links
}

// pathSetExclusion records why a path was not eligible, for diagnostics.
type pathSetExclusion struct {
	Fingerprint string
	Reason      string
}

// selectPathSet selects the candidate paths for one SCION endpoint, in the
// order in which they are attempted:
//
//   - only eligible paths are selected: not expired, and with a metadata MTU
//     (if known) that carries a quicMinDatagram UDP payload plus the SCION
//     and UDP headers;
//   - paths with the same inter-AS links are one path, with the latest of
//     their expiry times;
//   - paths expiring within pathExpiryMargin only when no other is left;
//   - ranking is greedy: first the path with the fewest AS hops, then
//     repeatedly the path with the least overlap with those already
//     selected. Overlap is compared by the number of shared transit ASes,
//     then of shared pairs of adjacent ASes, then of shared inter-AS links;
//     each counts once, however many selected paths have it. Ties by fewer
//     AS hops, then at random (o.Random) or by lower summed declared
//     latency and fingerprint. Paths through an
//     interface in the SCMP down cache (o.Down, if set) rank after all
//     others.
func selectPathSet(paths []snet.Path, o pathSetParams) ([]rankedPath, []pathSetExclusion) {
	if o.K <= 0 {
		o.K = defaultK
	}
	fresh, soon, excl := eligiblePaths(paths, o)
	pool := fresh
	if o.AllowSoon {
		ranked := rankGreedy(fresh, o.K)
		return append(ranked, rankGreedy(soon, o.K-len(ranked))...), excl
	}
	if len(pool) == 0 {
		pool = soon
	} else {
		for _, rp := range soon {
			excl = append(excl, pathSetExclusion{rp.fp, "expires within " + pathExpiryMargin.String()})
		}
	}
	if o.Random {
		rand.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
	}
	return rankGreedy(pool, o.K), excl
}

// eligiblePaths returns the eligible paths among paths, one per set of
// inter-AS links, split into those expiring after pathExpiryMargin (fresh)
// and within it (soon), and the reasons the others are not eligible.
func eligiblePaths(paths []snet.Path, o pathSetParams) (fresh, soon []rankedPath, excl []pathSetExclusion) {
	if o.DstHostLen == 0 {
		o.DstHostLen = 16
	}
	if o.SrcHostLen == 0 {
		o.SrcHostLen = 16
	}
	var all []rankedPath
	byLinks := map[string]int{}
	for _, p := range paths {
		md := p.Metadata()
		fp := ""
		if md != nil {
			fp = snet.Fingerprint(md.Interfaces).String()
		}
		if md != nil && !md.Expiry.IsZero() && !o.Now.Before(md.Expiry) {
			excl = append(excl, pathSetExclusion{fp, "expired"})
			continue
		}
		if md != nil && md.MTU > 0 {
			need := scionHdrLen(o.DstHostLen, o.SrcHostLen, dataplaneLen(p)) + udpHdrLen + quicMinDatagram
			if int(md.MTU) < need {
				excl = append(excl, pathSetExclusion{fp, fmt.Sprintf("MTU %d < %d", md.MTU, need)})
				continue
			}
		}
		lat, known := declaredLatency(md)
		rp := rankedPath{
			p: p, down: o.Down.pathDown(md, o.Now), hops: pathASHops(md),
			lat: lat, latKnown: known, fp: fp, links: pathLinks(md), random: o.Random,
			pairs: pathPairs(md), transit: pathTransit(md),
		}
		if md != nil {
			rp.expiry = md.Expiry
		}
		if len(rp.links) > 0 {
			key := fmt.Sprint(rp.links)
			if i, ok := byLinks[key]; ok {
				// Same inter-AS links: one path; keep the later expiry.
				if !all[i].expiry.IsZero() && (rp.expiry.IsZero() || rp.expiry.After(all[i].expiry)) {
					excl = append(excl, pathSetExclusion{all[i].fp, "same links as " + rp.fp})
					all[i] = rp
				} else {
					excl = append(excl, pathSetExclusion{rp.fp, "same links as " + all[i].fp})
				}
				continue
			}
			byLinks[key] = len(all)
		}
		all = append(all, rp)
	}
	for _, rp := range all {
		if !rp.expiry.IsZero() && rp.expiry.Sub(o.Now) < pathExpiryMargin {
			soon = append(soon, rp)
		} else {
			fresh = append(fresh, rp)
		}
	}
	return fresh, soon, excl
}

// rankGreedy picks up to k paths from pool in rank order (see selectPathSet).
func rankGreedy(pool []rankedPath, k int) []rankedPath {
	rem := append([]rankedPath(nil), pool...)
	usedLinks := map[linkKey]bool{}
	usedPairs := map[asPair]bool{}
	usedTransit := map[addr.IA]bool{}
	shared := func(rp rankedPath) overlap {
		var o overlap
		for _, a := range rp.transit {
			if usedTransit[a] {
				o.transit++
			}
		}
		for _, p := range rp.pairs {
			if usedPairs[p] {
				o.pairs++
			}
		}
		for _, l := range rp.links {
			if usedLinks[l] {
				o.links++
			}
		}
		return o
	}
	var out []rankedPath
	for len(out) < k && len(rem) > 0 {
		best := 0
		bestShared := shared(rem[0])
		for i := 1; i < len(rem); i++ {
			s := shared(rem[i])
			if rankLess(rem[i], s, rem[best], bestShared) {
				best, bestShared = i, s
			}
		}
		out = append(out, rem[best])
		for _, l := range rem[best].links {
			usedLinks[l] = true
		}
		for _, p := range rem[best].pairs {
			usedPairs[p] = true
		}
		for _, a := range rem[best].transit {
			usedTransit[a] = true
		}
		rem = append(rem[:best], rem[best+1:]...)
	}
	return out
}

func rankLess(a rankedPath, aShared overlap, b rankedPath, bShared overlap) bool {
	if a.down != b.down {
		return !a.down
	}
	if aShared != bShared {
		return aShared.less(bShared)
	}
	if a.hops != b.hops {
		return a.hops < b.hops
	}
	if a.random {
		return false // tie: the pool was shuffled, the earlier one stays
	}
	if a.latKnown != b.latKnown {
		return a.latKnown
	}
	if a.latKnown && a.lat != b.lat {
		return a.lat < b.lat
	}
	return a.fp < b.fp
}

// toSCIONPath converts a ranked path to the Candidate representation.
func (rp rankedPath) toSCIONPath() SCIONPath {
	md := rp.p.Metadata()
	sp := SCIONPath{
		Fingerprint: rp.fp,
		Hops:        rp.hops,
		Interfaces:  interfacesString(md),
		Down:        rp.down,
		SNET:        rp.p,
	}
	if rp.latKnown {
		sp.Latency = rp.lat
	}
	return sp
}

// hopPair is the (ConsIngress, ConsEgress) pair of one hop field: the part
// of a SCION path that stays the same in flight and across reversal
// (routers rewrite SegID and CurrINF/CurrHF; reversal reorders info fields
// and flips ConsDir but keeps each hop field's construction-direction
// interface IDs and re-reverses the hop order on the reply).
type hopPair struct{ in, eg uint16 }

// hopPairsFromRaw decodes a raw SCION-type path and returns its hop pairs.
func hopPairsFromRaw(raw []byte) ([]hopPair, bool) {
	if len(raw) == 0 {
		return nil, true // empty path: AS-local
	}
	var d scion.Decoded
	if err := d.DecodeFromBytes(raw); err != nil {
		return nil, false
	}
	out := make([]hopPair, len(d.HopFields))
	for i, h := range d.HopFields {
		out[i] = hopPair{h.ConsIngress, h.ConsEgress}
	}
	return out, true
}

// hopPairsOfPath extracts hop pairs from a slayers path.Path of the SCION
// type (as found in a reply path or an SCMP quote).
func hopPairsOfPath(p path.Path) ([]hopPair, bool) {
	if p == nil {
		return nil, false
	}
	switch v := p.(type) {
	case *scion.Decoded:
		out := make([]hopPair, len(v.HopFields))
		for i, h := range v.HopFields {
			out[i] = hopPair{h.ConsIngress, h.ConsEgress}
		}
		return out, true
	case *scion.Raw:
		out := make([]hopPair, 0, v.NumHops)
		for i := 0; i < v.NumHops; i++ {
			h, err := v.GetHopField(i)
			if err != nil {
				return nil, false
			}
			out = append(out, hopPair{h.ConsIngress, h.ConsEgress})
		}
		return out, true
	}
	if p.Type() != scion.PathType {
		return nil, false
	}
	buf := make([]byte, p.Len())
	if err := p.SerializeTo(buf); err != nil {
		return nil, false
	}
	return hopPairsFromRaw(buf)
}

// hopPairsOf extracts hop pairs from an snet dataplane path: a daemon path
// (snetpath.SCION), a received reply path (snet.RawReplyPath, already
// reversed by snet's reply pather), or an empty path.
func hopPairsOf(dp snet.DataplanePath) ([]hopPair, bool) {
	switch v := dp.(type) {
	case snetpath.SCION:
		return hopPairsFromRaw(v.Raw)
	case snet.RawReplyPath:
		return hopPairsOfPath(v.Path)
	case snet.RawPath:
		if v.PathType != scion.PathType {
			return nil, false
		}
		return hopPairsFromRaw(v.Raw)
	case snetpath.Empty:
		return nil, true
	}
	return nil, false
}

func hopPairsEqual(a, b []hopPair) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// corruptFirstHopMAC returns a copy of p whose first hop field has one MAC
// byte flipped, so the first border router drops it (it answers with an
// SCMP Parameter Problem, not an interface-down error). For experiments
// only; paths that are not of the SCION type are returned unchanged.
func corruptFirstHopMAC(p snet.Path) snet.Path {
	sp, ok := p.Dataplane().(snetpath.SCION)
	if !ok || len(sp.Raw) < scion.MetaLen {
		return p
	}
	var meta scion.MetaHdr
	if err := meta.DecodeFromBytes(sp.Raw); err != nil {
		return p
	}
	numINF := 0
	for _, l := range meta.SegLen {
		if l > 0 {
			numINF++
		}
	}
	// Hop field 0 starts after the meta header and the info fields; its
	// 6-octet MAC is at offset 6 within the 12-octet hop field.
	off := scion.MetaLen + numINF*path.InfoLen + 6
	if off >= len(sp.Raw) {
		return p
	}
	raw := append([]byte(nil), sp.Raw...)
	raw[off] ^= 0xff
	return corruptedPath{Path: p, dp: snetpath.SCION{Raw: raw}}
}

// corruptedPath overrides the dataplane of a path; everything else
// (metadata, next hop) is the original's.
type corruptedPath struct {
	snet.Path
	dp snet.DataplanePath
}

func (c corruptedPath) Dataplane() snet.DataplanePath { return c.dp }
