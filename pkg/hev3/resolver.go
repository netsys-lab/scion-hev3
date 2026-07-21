package hev3

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	rand "math/rand/v2"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// defaultResolutionDelay is the §4.2 "Resolution Delay": once the first
// positive answer arrives while the release gate (owner-AAAA final AND
// every service qtype final) is unsatisfied, this timer arms, and its
// expiry releases Initial from whatever has answered so far. Queries
// still outstanding at release (any of HTTPS/SVCB/AAAA/A) keep running
// and merge their answers via Updates (§4.3).
const defaultResolutionDelay = 50 * time.Millisecond

// queryTimeout bounds one per-server network attempt (UDP, or the TCP retry
// after truncation) within an exchange; a full exchange may take up to
// len(servers) attempts plus one TCP retry, so it is not an end-to-end cap
// (qtypes: HTTPS/SVCB/AAAA/A).
const queryTimeout = 2 * time.Second

// maxAliasChase caps SVCB AliasMode (SvcPriority 0, RFC 9460 §2.4.2) target
// following, guarding against loops or unreasonably long alias chains.
const maxAliasChase = 4

// ResolveOptions tunes ResolveHost. The zero value is valid.
type ResolveOptions struct {
	Resolver        string        // "ip:53"[,"ip:53"...]; empty ⇒ system resolver via /etc/resolv.conf. Comma-separated servers are tried in order (F9 failover); each element is already "host:port".
	ResolutionDelay time.Duration // 0 ⇒ defaultResolutionDelay (50ms)
	Timeline        *Timeline     // optional; records query/answer/candidate events
	RRType          RRType        // which service-binding RR type(s) to query; 0 (RRBoth) is the default
	ShuffleSeed     int64         // seeds the equal-priority record shuffle (§5.2); 0 ⇒ a fresh crypto/rand seed per run. Fix it in tests for a deterministic order.
}

// RRType selects which service-binding RR type(s) ResolveHost queries.
// RRBoth (the zero value) queries HTTPS and SVCB in parallel and prefers
// HTTPS answers — the migration default while deployed zones still use
// SVCB; draft-ietf-happy-happyeyeballs-v3-04 §4.1 wants HTTPS for HTTP(S)
// clients.
type RRType int

const (
	RRBoth RRType = iota
	RRHTTPS
	RRSVCB
)

// ParseRRType parses the CLI's -rr-type value.
func ParseRRType(s string) (RRType, error) {
	switch s {
	case "both":
		return RRBoth, nil
	case "https":
		return RRHTTPS, nil
	case "svcb":
		return RRSVCB, nil
	}
	return 0, fmt.Errorf("hev3: unknown rr-type %q (want https, svcb or both)", s)
}

// serviceQtypes returns the DNS qtypes an RRType implies, HTTPS first.
func (t RRType) serviceQtypes() []uint16 {
	switch t {
	case RRHTTPS:
		return []uint16{dns.TypeHTTPS}
	case RRSVCB:
		return []uint16{dns.TypeSVCB}
	}
	return []uint16{dns.TypeHTTPS, dns.TypeSVCB}
}

// serviceRecords extracts the SVCB machinery from an answer regardless of
// RR type: dns.HTTPS embeds dns.SVCB, so both cases yield *dns.SVCB.
func serviceRecords(msg *dns.Msg) []*dns.SVCB {
	if msg == nil {
		return nil
	}
	var out []*dns.SVCB
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.HTTPS:
			out = append(out, &v.SVCB)
		case *dns.SVCB:
			out = append(out, v)
		}
	}
	return out
}

// Resolved is the outcome of ResolveHost: an Initial candidate set (released
// once the §4.2 Resolution Delay gate clears) plus an Updates channel that
// delivers later, merged candidate sets as slower answers (a late-arriving
// service record, the non-preferred address family, or a TargetName's
// addresses chased mid-flight) complete — draft §4.3 mid-race merge. Updates
// is closed once every outstanding query has resolved one way or another.
//
// A caller must keep draining Updates until it closes, or cancel ctx: the
// internal goroutine that resolved Initial holds at least one query
// outstanding until it completes and then blocks trying to send the merged
// result on Updates. That send only has a ctx.Done() escape, not a
// reader-dropped one, so an abandoned Updates channel whose ctx is never
// cancelled delays that goroutine's cleanup until ctx ends on its own (e.g.
// a caller-supplied deadline), not until the caller stops reading.
type Resolved struct {
	Initial []Candidate
	Updates <-chan []Candidate
	ttl     *atomic.Int64 // smallest contributing TTL, nanoseconds; 0 = unknown
}

// ResolveHost issues service (HTTPS and/or SVCB per o.RRType), AAAA and A
// queries for host against a single resolver and turns the answers into
// Candidates. It follows a dynamic query set: every ServiceMode record whose
// TargetName names a host not yet queried spawns its own AAAA/A lookups
// mid-flight (RFC 9460 §4.2.1), so all queries run concurrently, not a fixed
// three. SCION candidates come from a ServiceMode record's "scion" SvcParam
// (one Candidate per SCIONAddr, Path left nil — path expansion is a later
// stage); every record contributes candidates carrying its OWN ALPN/port/
// priority. AliasMode records (SvcPriority 0) are followed by re-querying the
// TargetName (RFC 9460 §2.4.2), up to maxAliasChase steps.
func ResolveHost(ctx context.Context, host string, port uint16, o ResolveOptions) (Resolved, error) {
	servers, err := resolverAddresses(o.Resolver)
	if err != nil {
		return Resolved{}, err
	}
	delay := o.ResolutionDelay
	if delay <= 0 {
		delay = defaultResolutionDelay
	}
	seed := o.ShuffleSeed
	if seed == 0 {
		seed = int64(cryptoRandUint64())
	}

	ttl := &atomic.Int64{}
	r := &resolveRun{
		ctx:     ctx,
		servers: servers,
		host:    dns.CanonicalName(host),
		port:    port,
		tl:      o.Timeline,
		rrType:  o.RRType,
		rng:     rand.New(rand.NewPCG(uint64(seed), uint64(seed))),
		ttl:     ttl,
		initial: make(chan []Candidate, 1),
		updates: make(chan []Candidate),
	}
	go r.run(delay)

	select {
	case cands := <-r.initial:
		return Resolved{Initial: cands, Updates: r.updates, ttl: ttl}, nil
	case <-ctx.Done():
		return Resolved{}, ctx.Err()
	}
}

// MinTTL reports the smallest TTL among the DNS answers that produced
// the current candidate set — the natural cache lifetime for it. Zero
// until a positive answer has arrived.
func (r Resolved) MinTTL() time.Duration {
	if r.ttl == nil {
		return 0
	}
	return time.Duration(r.ttl.Load())
}

// resolverAddresses resolves ResolveOptions.Resolver to one or more
// "host:port" dial targets. A non-empty option is split on commas (each
// element already host:port). Otherwise every nameserver in
// /etc/resolv.conf is used, IPv6 server addresses first (draft §4.5:
// prefer transporting DNS over IPv6), preserving file order per family.
func resolverAddresses(resolver string) ([]string, error) {
	if resolver != "" {
		return strings.Split(resolver, ","), nil
	}
	cc, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("hev3: resolve: reading /etc/resolv.conf: %w", err)
	}
	if len(cc.Servers) == 0 {
		return nil, errors.New("hev3: resolve: /etc/resolv.conf has no nameserver")
	}
	var v6, v4 []string
	for _, s := range cc.Servers {
		if ip := net.ParseIP(s); ip != nil && ip.To4() == nil {
			v6 = append(v6, net.JoinHostPort(s, cc.Port))
		} else {
			v4 = append(v4, net.JoinHostPort(s, cc.Port))
		}
	}
	return append(v6, v4...), nil
}

// resolveRun holds the state of one ResolveHost call across its service
// (HTTPS/SVCB), owner and TargetName AAAA/A queries and any service-record
// alias chase.
type resolveRun struct {
	ctx     context.Context
	servers []string
	host    string
	port    uint16
	tl      *Timeline
	rrType  RRType
	rng     *rand.Rand      // run-stable; seeds the §5.2 equal-priority shuffle
	noted   map[string]bool // keys already recorded via noteOnce (dedup across rebuilds)
	ttl     *atomic.Int64   // smallest contributing TTL, nanoseconds; 0 = unknown

	initial chan []Candidate
	updates chan []Candidate
}

// addrState is one address-family answer for one name: the resolved IPs plus
// whether the query for them has settled. final distinguishes "no addresses
// yet" (query outstanding) from "confirmed no addresses" (final && empty),
// which governs whether ipv4hint/ipv6hint may stand in (RFC 9460 §7.3).
type addrState struct {
	ips   []net.IP
	final bool
}

// addrPair holds a name's AAAA and A answers.
type addrPair struct{ aaaa, a addrState }

type queryKind int

const (
	qkService queryKind = iota
	qkAddr
)

// queryResult is one settled query delivered to run's unified results channel.
type queryResult struct {
	kind  queryKind
	qtype uint16 // service: TypeHTTPS/TypeSVCB; addr: TypeAAAA/TypeA
	name  string // addr queries: FQDN queried
	recs  []*svcRecord
	ips   []net.IP
}

// run drives the dynamic query set to completion: service queries per
// rrType, AAAA/A for the owner, and AAAA/A for every ServiceMode TargetName
// discovered along the way. Initial releases once the §4.2 gate clears; every
// subsequent change to the merged candidate set streams on Updates until
// nothing is left outstanding.
func (r *resolveRun) run(delay time.Duration) {
	defer close(r.updates)

	results := make(chan queryResult)
	outstanding := 0

	launchService := func(qtype uint16) {
		outstanding++
		go func() {
			recs, _ := r.resolveService(qtype)
			select {
			case results <- queryResult{kind: qkService, qtype: qtype, recs: recs}:
			case <-r.ctx.Done():
			}
		}()
	}
	launchAddr := func(name string, qtype uint16) {
		outstanding++
		go func() {
			ips, _ := r.resolveIPs(name, qtype)
			select {
			case results <- queryResult{kind: qkAddr, qtype: qtype, name: name, ips: ips}:
			case <-r.ctx.Done():
			}
		}()
	}

	addrs := map[string]*addrPair{r.host: {}}
	for _, qt := range r.rrType.serviceQtypes() {
		launchService(qt)
	}
	launchAddr(r.host, dns.TypeAAAA)
	launchAddr(r.host, dns.TypeA)

	svcRecs := map[uint16][]*svcRecord{} // ordered once per qtype (see below)
	svcFinal := map[uint16]bool{}
	svcNeeded := len(r.rrType.serviceQtypes())

	var (
		delayElapsed bool
		timerArmed   bool
		sent         bool
		prev         []Candidate
	)
	// The timer starts DISARMED and is armed only on the first positive
	// answer while set 1 (owner AAAA final AND every service qtype final) is
	// still unsatisfied — draft §4.2 starts the Resolution Delay clock at the
	// first positive response, not at query dispatch (Task 6 pins this).
	timer := time.NewTimer(delay)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	// chosen picks the record set buildCandidates uses: the HTTPS answer's
	// records when present (migration default prefers HTTPS), else SVCB's. A
	// mode that never queries one qtype (RRHTTPS/RRSVCB) simply never
	// populates svcRecs for the other, so this falls through without a mode
	// switch. Records are stored pre-ordered (see the qkService case), so
	// chosen()'s slice is already in §5.2 priority+shuffle order.
	chosen := func() []*svcRecord {
		if r.rrType != RRSVCB {
			if recs := svcRecs[dns.TypeHTTPS]; len(recs) > 0 {
				return recs
			}
		}
		return svcRecs[dns.TypeSVCB]
	}
	serviceFinal := func() bool { return len(svcFinal) == svcNeeded }
	// positive reports whether any positive answer has arrived: a final,
	// non-empty AAAA/A for ANY queried name, or a chosen record carrying a
	// scion= address or a hint. Iterating the addrs map here is order-safe:
	// the result is a boolean OR, independent of iteration order.
	positive := func() bool {
		for _, p := range addrs {
			if (p.aaaa.final && len(p.aaaa.ips) > 0) || (p.a.final && len(p.a.ips) > 0) {
				return true
			}
		}
		for _, rec := range chosen() {
			if len(rec.scion) > 0 || len(rec.hint4) > 0 || len(rec.hint6) > 0 {
				return true
			}
		}
		return false
	}
	ownerAAAAFinal := func() bool { return addrs[r.host].aaaa.final }

	// release checks the §4.2 gate: proceed once at least one positive answer
	// has been received AND EITHER (a) the owner's AAAA is final and every
	// service qtype is final, OR (b) the Resolution Delay has elapsed — draft
	// §4.2. A is never itself a gate requirement, only a possible source of a
	// positive answer. A chosen record that itself bears a candidate source
	// (scion= or a hint) also counts as positive, so a SCION-only name clears
	// path (b) instead of waiting on address families that never go positive.
	//
	// Independent of the gate: once nothing is outstanding, release
	// unconditionally, even with zero positive answers — an empty candidate
	// set is a valid, immediate answer and withholding it would only hang the
	// caller to its own ctx deadline. The Updates send escapes via ctx.Done()
	// (see the Resolved doc comment for the abandon-without-cancel case).
	release := func() {
		allFinal := outstanding == 0
		if !allFinal {
			if !positive() {
				return
			}
			if !(ownerAAAAFinal() && serviceFinal()) && !delayElapsed {
				return
			}
		}
		cands := r.buildCandidates(chosen(), addrs)
		if !sent {
			sent = true
			r.emitNewCandidates(nil, cands)
			prev = cands
			r.initial <- cands // buffered cap 1; never blocks
			return
		}
		if reflect.DeepEqual(prev, cands) {
			return
		}
		r.emitNewCandidates(prev, cands)
		prev = cands
		select {
		case r.updates <- cands:
		case <-r.ctx.Done():
		}
	}

	// The loop runs until every outstanding query has settled. outstanding is
	// dynamic: a service answer can INCREASE it mid-loop by chasing AAAA/A for
	// newly discovered TargetNames (§4.2.1), so the guard is re-evaluated each
	// iteration rather than fixed at three.
	for outstanding > 0 {
		select {
		case res := <-results:
			outstanding--
			switch res.kind {
			case qkService:
				// Order records once, here, with the run-stable rng: the
				// equal-priority shuffle (§5.2) must be fixed for the whole
				// resolution so rebuilds don't reshuffle and produce spurious
				// Updates. buildCandidates then consumes this stable order.
				recs := orderRecords(res.recs, r.rng)
				svcRecs[res.qtype] = recs
				svcFinal[res.qtype] = true
				// Chase addresses for every new target name (§4.2.1).
				for _, rec := range recs {
					if _, ok := addrs[rec.target]; !ok {
						addrs[rec.target] = &addrPair{}
						launchAddr(rec.target, dns.TypeAAAA)
						launchAddr(rec.target, dns.TypeA)
					}
				}
			case qkAddr:
				p := addrs[res.name]
				if res.qtype == dns.TypeAAAA {
					p.aaaa = addrState{ips: res.ips, final: true}
				} else {
					p.a = addrState{ips: res.ips, final: true}
				}
			}
			if !timerArmed && positive() && !(ownerAAAAFinal() && serviceFinal()) {
				timer.Reset(delay)
				timerArmed = true
			}
			release()
		case <-timer.C:
			delayElapsed = true
			release()
		case <-r.ctx.Done():
			return
		}
	}
}

// resolveService queries qtype (dns.TypeHTTPS or dns.TypeSVCB) for r.host and
// returns EVERY ServiceMode record, following AliasMode (SvcPriority 0) chains
// up to maxAliasChase steps (RFC 9460 §2.4.2) — each chase step re-queries the
// SAME qtype. Per RFC 9460 §2.4.2 an RRset that contains an AliasMode record
// has its ServiceMode members ignored and the alias chased; TargetName "."
// therefore resolves against the name that ANSWERED (the end of the chase),
// not the original owner. Individual records that fail to parse (e.g. an
// unsupported mandatory key) are noted once and skipped. It returns (nil, nil)
// when there is no record of that qtype at all, and a non-nil error only for
// transport failures/timeouts or a malformed chase (self-alias, loop, chase
// exhausted) — all non-fatal to the caller, which simply proceeds without this
// qtype's records.
func (r *resolveRun) resolveService(qtype uint16) ([]*svcRecord, error) {
	name := r.host
	// visited and the self-alias check below key on dns.CanonicalName
	// (lowercase + Fqdn), not the raw literal name: DNS names are
	// case-insensitive (RFC 4343), so an AliasMode chain that revisits an
	// earlier name in different letter case is still a loop and must be
	// caught, not requeried as if it were a distinct name.
	visited := map[string]bool{}
	for step := 0; step < maxAliasChase; step++ {
		key := dns.CanonicalName(name)
		if visited[key] {
			return nil, fmt.Errorf("hev3: resolve: %s alias loop at %s", dns.TypeToString[qtype], name)
		}
		visited[key] = true

		msg, err := r.exchange(name, qtype)
		if err != nil {
			return nil, err
		}
		svcbs := serviceRecords(msg)
		if len(svcbs) == 0 {
			return nil, nil
		}
		// RFC 9460 §2.4.2: a present AliasMode record suppresses ServiceMode
		// siblings and is chased.
		var alias string
		for _, rr := range svcbs {
			if rr.Priority == 0 {
				alias = dns.Fqdn(rr.Target)
				break
			}
		}
		if alias != "" {
			if dns.CanonicalName(alias) == key {
				return nil, fmt.Errorf("hev3: resolve: %s alias to self at %s", dns.TypeToString[qtype], name)
			}
			name = alias
			continue
		}
		var recs []*svcRecord
		for _, rr := range svcbs {
			rec, err := parseServiceRecord(rr, key)
			if err != nil {
				r.noteOnce("rec:"+key+err.Error(), queryLabel(name, qtype), err.Error())
				continue
			}
			r.captureTTL(rr.Hdr.Ttl)
			recs = append(recs, rec)
		}
		return recs, nil
	}
	return nil, fmt.Errorf("hev3: resolve: %s alias chase exceeded %d steps", dns.TypeToString[qtype], maxAliasChase)
}

// resolveIPs queries qtype (AAAA or A) for name and extracts the answer
// addresses.
func (r *resolveRun) resolveIPs(name string, qtype uint16) ([]net.IP, error) {
	msg, err := r.exchange(name, qtype)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.AAAA:
			r.captureTTL(v.Hdr.Ttl)
			ips = append(ips, v.AAAA)
		case *dns.A:
			r.captureTTL(v.Hdr.Ttl)
			ips = append(ips, v.A)
		}
	}
	return ips, nil
}

// noteOnce records a timeline "fail" note exactly once per key, so
// rebuild-triggered re-parses (and re-emissions) don't duplicate drop notes.
func (r *resolveRun) noteOnce(key, label, detail string) {
	if r.tl == nil || r.noted[key] {
		return
	}
	if r.noted == nil {
		r.noted = map[string]bool{}
	}
	r.noted[key] = true
	r.tl.Add("fail", label, detail)
}

// captureTTL records the smallest TTL seen in any DNS answer that produced
// candidates. If header is 0 (empty TTL), it's ignored; otherwise it's
// compared against any previously recorded value and the smaller is kept.
func (r *resolveRun) captureTTL(header uint32) {
	if header == 0 {
		return
	}
	d := int64(time.Duration(header) * time.Second)
	for {
		cur := r.ttl.Load()
		if cur != 0 && cur <= d {
			return
		}
		if r.ttl.CompareAndSwap(cur, d) {
			return
		}
	}
}

// cryptoRandUint64 reads 8 bytes from crypto/rand for the default per-run
// shuffle seed; it falls back to the wall clock if the entropy source fails.
func cryptoRandUint64() uint64 {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		return uint64(time.Now().UnixNano())
	}
	return binary.LittleEndian.Uint64(b[:])
}

// exchange sends one query and waits for the reply, trying each
// configured server in order (F9). Every query carries EDNS0 with a
// 1232-byte UDP size; a truncated UDP reply triggers one TCP retry
// against the same server, falling back to the truncated answer if TCP
// fails. Timeline "query"/"answer" events wrap the whole exchange.
func (r *resolveRun) exchange(name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.SetEdns0(1232, false)

	label := queryLabel(name, qtype)
	if r.tl != nil {
		r.tl.Add("query", label, "")
	}
	resp, err := r.exchangeServers(m)
	if r.tl != nil {
		detail := ""
		if err != nil {
			detail = err.Error()
		}
		r.tl.Add("answer", label, detail)
	}
	return resp, err
}

func (r *resolveRun) exchangeServers(m *dns.Msg) (*dns.Msg, error) {
	var lastErr error
	for _, server := range r.servers {
		c := &dns.Client{Net: "udp", Timeout: queryTimeout}
		resp, _, err := c.ExchangeContext(r.ctx, m, server)
		if err != nil {
			lastErr = err
			if r.ctx.Err() != nil {
				return nil, r.ctx.Err()
			}
			continue
		}
		if resp.Truncated {
			tc := &dns.Client{Net: "tcp", Timeout: queryTimeout}
			if tresp, _, terr := tc.ExchangeContext(r.ctx, m, server); terr == nil {
				return tresp, nil
			}
		}
		return resp, nil
	}
	return nil, lastErr
}

// orderRecords sorts service records by SvcPriority ascending; runs of equal
// priority are shuffled (§5.2 SHOULD) with the caller-supplied rng. run calls
// it ONCE per qtype with the run-stable rng so the shuffle is fixed for the
// whole resolution and rebuilds don't reshuffle (which would emit spurious
// Updates). It returns a new slice; the input is untouched.
func orderRecords(recs []*svcRecord, rng *rand.Rand) []*svcRecord {
	out := append([]*svcRecord(nil), recs...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].prio < out[j].prio })
	for lo := 0; lo < len(out); {
		hi := lo + 1
		for hi < len(out) && out[hi].prio == out[lo].prio {
			hi++
		}
		rng.Shuffle(hi-lo, func(i, j int) { out[lo+i], out[lo+j] = out[lo+j], out[lo+i] })
		lo = hi
	}
	return out
}

// buildCandidates turns the chosen ServiceMode records (already in §5.2
// priority+shuffle order) plus per-name address answers into Candidates.
//
// With no service records the owner's A/AAAA yield plain candidates
// (pre-SVCB behavior): empty ALPN, caller's default port, priority 0.
//
// With records, each record emits its own candidates (recordCandidates) in
// priority order. The IP addresses of a shared TargetName are emitted only by
// the FIRST (lowest-priority) record covering that name — later records
// covering it re-emit only their own scion= addresses, so a target's A/AAAA
// carry the lowest-priority covering record's params and never duplicate.
// Owner A/AAAA that no record targets are "unassociated" and trail the list
// with the worst priority (65535, §5.2).
func (r *resolveRun) buildCandidates(recs []*svcRecord, addrs map[string]*addrPair) []Candidate {
	var out []Candidate
	if len(recs) == 0 {
		if pair := addrs[r.host]; pair != nil {
			for _, ip := range pair.aaaa.ips {
				out = append(out, ipCandidate(FamilyIPv6, "v6:", ip, r.port, nil, 0, nil))
			}
			for _, ip := range pair.a.ips {
				out = append(out, ipCandidate(FamilyIPv4, "v4:", ip, r.port, nil, 0, nil))
			}
		}
		return out
	}
	covered := false
	// emitted tracks TargetNames whose IP addresses (and hints) have already
	// been emitted, so a name shared by several records contributes its
	// A/AAAA exactly once, under the lowest-priority covering record.
	emitted := map[string]bool{}
	for _, rec := range recs {
		if rec.target == r.host {
			covered = true
		}
		out = append(out, r.recordCandidates(rec, addrs, emitted)...)
	}
	if !covered {
		if pair := addrs[r.host]; pair != nil {
			for _, ip := range pair.aaaa.ips {
				out = append(out, ipCandidate(FamilyIPv6, "v6:", ip, r.port, nil, 65535, nil))
			}
			for _, ip := range pair.a.ips {
				out = append(out, ipCandidate(FamilyIPv4, "v4:", ip, r.port, nil, 65535, nil))
			}
		}
	}
	return out
}

// recordCandidates emits one record's candidates: its scion= addresses (only
// when the record's supported ALPN set includes h3 — SCION transport is
// QUIC-only, F10; otherwise each is dropped with a "no QUIC ALPN" note),
// then — unless another record already claimed this TargetName's IP
// addresses (emitted) — the target's real A/AAAA answers, or its
// ipv4hint/ipv6hint when the corresponding family is final-and-empty (RFC
// 9460 §7.3). Each IP address contributes up to two candidates: a QUIC
// candidate (ALPN [h3]) when h3 is supported, and a TCP candidate (ALPN =
// supported minus h3, the "+tcp" label suffix) when anything besides h3 is
// supported — so a UDP-blackholed network still converges on h2/http1.1
// (F8). Both carry the record's port (falling back to the caller's default)
// and priority. A record offering no client-supported ALPN contributes
// nothing at all (draft §6.2).
func (r *resolveRun) recordCandidates(rec *svcRecord, addrs map[string]*addrPair, emitted map[string]bool) []Candidate {
	supported := rec.supportedALPN()
	if len(supported) == 0 {
		r.noteOnce("alpn:"+rec.target, "svcb "+rec.target, "no client-supported ALPN")
		return nil
	}
	port := rec.port
	if port == 0 {
		port = r.port
	}
	quic := false
	for _, a := range supported {
		if a == alpnH3 {
			quic = true
		}
	}
	tcp := tcpALPN(supported)

	var out []Candidate
	for _, addr := range rec.scion {
		ia := scionIA(addr)
		if !quic {
			r.noteOnce("scion-alpn:"+rec.target, "scion:"+ia+","+addr.Host.String(), "no QUIC ALPN in record; SCION transport is QUIC-only")
			continue
		}
		out = append(out, Candidate{
			Family:    FamilySCION,
			Host:      addr.Host.String(),
			Port:      port,
			IA:        ia,
			ALPN:      supported,
			GroupALPN: supported,
			Priority:  rec.prio,
			Policy:    rec.policy,
			// Label uses the same canonical scionIA form as IA, not
			// addr.String(): the latter renders a wire-round-tripped
			// hex-range ASN in decimal (SVCBScion's wire pack/unpack loses
			// the hex-presentation bit — see scionIA's doc comment), which
			// would make Label disagree with IA for the exact deployed
			// zone's "games" record.
			Label: "scion:" + ia + "," + addr.Host.String(),
		})
	}
	if emitted[rec.target] {
		return out
	}
	emitted[rec.target] = true
	pair := addrs[rec.target]
	if pair == nil {
		return out
	}

	emitIP := func(fam Family, prefix string, ip net.IP) {
		if quic {
			out = append(out, ipCandidate(fam, prefix, ip, port, []string{alpnH3}, rec.prio, supported))
		}
		if len(tcp) > 0 {
			out = append(out, ipCandidateLabel(fam, tcpLabel(prefix), ip, port, tcp, rec.prio, supported))
		}
	}

	for _, ip := range pair.aaaa.ips {
		emitIP(FamilyIPv6, "v6:", ip)
	}
	if pair.aaaa.final && len(pair.aaaa.ips) == 0 {
		for _, ip := range rec.hint6 {
			emitIP(FamilyIPv6, "v6hint:", ip)
		}
	}
	for _, ip := range pair.a.ips {
		emitIP(FamilyIPv4, "v4:", ip)
	}
	if pair.a.final && len(pair.a.ips) == 0 {
		for _, ip := range rec.hint4 {
			emitIP(FamilyIPv4, "v4hint:", ip)
		}
	}
	return out
}

// tcpALPN strips h3 (UDP-only) from the supported set for the TCP leg.
func tcpALPN(supported []string) []string {
	var out []string
	for _, a := range supported {
		if a != alpnH3 {
			out = append(out, a)
		}
	}
	return out
}

// tcpLabel turns a QUIC label prefix into its TCP sibling: "v6:" → "v6+tcp:".
// The types.go Label examples always promised this form.
func tcpLabel(prefix string) string {
	return strings.TrimSuffix(prefix, ":") + "+tcp:"
}

func ipCandidate(fam Family, labelPrefix string, ip net.IP, port uint16, alpn []string, priority uint16, groupALPN []string) Candidate {
	return ipCandidateLabel(fam, labelPrefix, ip, port, alpn, priority, groupALPN)
}

// ipCandidateLabel is ipCandidate with the full label prefix supplied.
// groupALPN is the covering record's full supported ALPN set (Candidate's
// §5.1 grouping key — see GroupALPN's doc comment); nil for the legacy
// no-service-record and unassociated-trailing candidates, which have no
// covering record.
func ipCandidateLabel(fam Family, labelPrefix string, ip net.IP, port uint16, alpn []string, priority uint16, groupALPN []string) Candidate {
	return Candidate{
		Family:    fam,
		Host:      ip.String(),
		Port:      port,
		ALPN:      alpn,
		GroupALPN: groupALPN,
		Priority:  priority,
		Label:     labelPrefix + ip.String(),
	}
}

// maxBGPAS is the largest AS number in the classic 32-bit BGP AS-number
// space (scionproto/scion pkg/addr.MaxBGPAS). SCION's canonical ISD-ASN
// presentation format prints AS numbers at or below it in decimal, and
// larger ("SCION-only") AS numbers as three colon-separated 16-bit hex
// groups, e.g. "71-2:0:4a".
const maxBGPAS = (1 << 32) - 1

// scionIA derives the "ISD-ASN" Candidate.IA from a SCIONAddr, formatting
// the AS number per the maxBGPAS rule above. This is computed from
// addr.ISD/addr.ASN directly rather than via addr.String(): SCIONAddr
// remembers whether its AS was written in hex-group form in the zone file,
// but SVCBScion's wire pack/unpack (used for every real DNS answer, not
// just an in-process shortcut) carries only the numeric ASN — the
// hex-vs-decimal preference bit does not survive a real query, so
// addr.String() prints a large hex-range ASN like 0x2_0000_004a as the
// plain decimal "8589934666" once the answer has round-tripped over the
// wire. Recomputing the presentation form here keeps it correct regardless
// of how the answer arrived.
func scionIA(addr dns.SCIONAddr) string {
	if addr.ASN <= maxBGPAS {
		return fmt.Sprintf("%d-%d", addr.ISD, addr.ASN)
	}
	return fmt.Sprintf("%d-%x:%x:%x", addr.ISD, (addr.ASN>>32)&0xffff, (addr.ASN>>16)&0xffff, addr.ASN&0xffff)
}

// emitNewCandidates records a "candidate" Timeline event for every Candidate
// in next that was not already in prev (by Label), so a rebuild that repeats
// already-announced candidates (e.g. AAAA/A carried over into a post-SVCB
// merge) doesn't re-log them.
func (r *resolveRun) emitNewCandidates(prev, next []Candidate) {
	if r.tl == nil {
		return
	}
	seen := make(map[string]bool, len(prev))
	for _, c := range prev {
		seen[c.Label] = true
	}
	for _, c := range next {
		if seen[c.Label] {
			continue
		}
		r.tl.Add("candidate", c.Label, c.IA)
	}
}

func queryLabel(name string, qtype uint16) string {
	return dns.TypeToString[qtype] + " " + name
}

// svcRecord is the flattened, typed view of one ServiceMode SVCB/HTTPS
// record, produced by parseServiceRecord.
type svcRecord struct {
	prio      uint16
	target    string // FQDN the record's addresses come from (owner when ".")
	port      uint16 // 0 = inherit the caller's port
	alpn      []string
	noDefault bool
	scion     []dns.SCIONAddr
	policy    *PathPolicy
	hint4     []net.IP
	hint6     []net.IP
}

// supportedParams are the SvcParamKeys this client implements; a record
// marking anything else mandatory is ignored per RFC 9460 §8.
var supportedParams = map[dns.SVCBKey]bool{
	dns.SVCB_ALPN:            true,
	dns.SVCB_NO_DEFAULT_ALPN: true,
	dns.SVCB_PORT:            true,
	dns.SVCB_IPV4HINT:        true,
	dns.SVCB_IPV6HINT:        true,
	dns.SVCB_SCION:           true,
	dns.SVCB_SCION_POLICY:    true,
}

// parseServiceRecord flattens one ServiceMode record. owner is the FQDN
// the record was answered for; a TargetName of "." resolves to it
// (RFC 9460 §2.5).
func parseServiceRecord(rr *dns.SVCB, owner string) (*svcRecord, error) {
	rec := &svcRecord{prio: rr.Priority, target: dns.CanonicalName(rr.Target)}
	if rec.target == "." {
		rec.target = owner
	}
	for _, v := range rr.Value {
		switch kv := v.(type) {
		case *dns.SVCBMandatory:
			for _, k := range kv.Code {
				if !supportedParams[k] {
					return nil, fmt.Errorf("mandatory param %s unsupported", k)
				}
			}
		case *dns.SVCBPort:
			rec.port = kv.Port
		case *dns.SVCBAlpn:
			rec.alpn = kv.Alpn
		case *dns.SVCBNoDefaultAlpn:
			rec.noDefault = true
		case *dns.SVCBScion:
			rec.scion = kv.Addrs
		case *dns.SVCBScionPolicy:
			rec.policy = pathPolicyFrom(kv)
		case *dns.SVCBIPv4Hint:
			rec.hint4 = kv.Hint
		case *dns.SVCBIPv6Hint:
			rec.hint6 = kv.Hint
		}
	}
	return rec, nil
}

// clientALPN is what this client speaks, most preferred first.
var clientALPN = []string{alpnH3, alpnH2, alpnHTTP11}

// supportedALPN computes the record's effective SVCB ALPN set (RFC 9460
// §7.1.2: alpn values plus the https default of http/1.1 unless
// no-default-alpn) intersected with clientALPN, in client preference
// order. nil means the endpoint offers nothing we speak (draft §6.2:
// do not attempt it).
func (rec *svcRecord) supportedALPN() []string {
	set := map[string]bool{}
	for _, a := range rec.alpn {
		set[a] = true
	}
	if !rec.noDefault {
		set[alpnHTTP11] = true
	}
	var out []string
	for _, a := range clientALPN {
		if set[a] {
			out = append(out, a)
		}
	}
	return out
}

// pathPolicyFrom converts the wire SvcParam to the client-side PathPolicy.
// Duplicate metrics/thresholds keep the first occurrence (draft §4 wire
// format rules). A policy with no usable items collapses to nil.
func pathPolicyFrom(v *dns.SVCBScionPolicy) *PathPolicy {
	metric := map[dns.PolicyMetric]PolicyMetric{
		dns.PolicyMetricLatency:   MetricLatency,
		dns.PolicyMetricBandwidth: MetricBandwidth,
		dns.PolicyMetricHops:      MetricHops,
	}
	p := &PathPolicy{}
	seen := map[PolicyMetric]bool{}
	for _, it := range v.Items {
		switch {
		case it.Prefer != nil:
			if m, ok := metric[*it.Prefer]; ok && !seen[m] {
				seen[m] = true
				p.Prefer = append(p.Prefer, m)
			}
		case it.MaxLatencyUs != nil:
			if p.MaxLatency == 0 {
				p.MaxLatency = time.Duration(*it.MaxLatencyUs) * time.Microsecond
			}
		case it.MinBandwidthKbps != nil:
			if p.MinBandwidthKbps == 0 {
				p.MinBandwidthKbps = uint64(*it.MinBandwidthKbps)
			}
		}
	}
	if len(p.Prefer) == 0 && p.MaxLatency == 0 && p.MinBandwidthKbps == 0 {
		return nil
	}
	return p
}
