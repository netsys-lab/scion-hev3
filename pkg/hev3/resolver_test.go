package hev3

import (
	"context"
	rand "math/rand/v2"
	"net"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeDNS is a minimal in-process nameserver: a per-(qtype,qname) map of
// canned RRs, with an optional injectable per-question response delay for
// exercising Resolution Delay.
type fakeDNS struct {
	addr string

	mu       sync.Mutex
	records  map[string][]dns.RR
	delays   map[string]time.Duration
	truncate map[string]bool
}

func newFakeDNS(t *testing.T) *fakeDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeDNS{records: map[string][]dns.RR{}, delays: map[string]time.Duration{}, truncate: map[string]bool{}, addr: pc.LocalAddr().String()}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", f.handle)
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go srv.ActivateAndServe()
	<-started
	t.Cleanup(func() { srv.Shutdown() })

	ln, err := net.Listen("tcp", f.addr)
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	tsrv := &dns.Server{Listener: ln, Handler: mux}
	tstarted := make(chan struct{})
	tsrv.NotifyStartedFunc = func() { close(tstarted) }
	go tsrv.ActivateAndServe()
	<-tstarted
	t.Cleanup(func() { tsrv.Shutdown() })
	return f
}

func fakeKey(name string, qtype uint16) string {
	return dns.TypeToString[qtype] + " " + dns.Fqdn(name)
}

func (f *fakeDNS) set(name string, qtype uint16, rrs ...dns.RR) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[fakeKey(name, qtype)] = rrs
}

func (f *fakeDNS) setDelay(name string, qtype uint16, d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delays[fakeKey(name, qtype)] = d
}

func (f *fakeDNS) setTruncateUDP(name string, qtype uint16) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.truncate[fakeKey(name, qtype)] = true
}

func (f *fakeDNS) handle(w dns.ResponseWriter, req *dns.Msg) {
	q := req.Question[0]
	k := fakeKey(q.Name, q.Qtype)
	f.mu.Lock()
	rrs := f.records[k]
	d := f.delays[k]
	f.mu.Unlock()
	if d > 0 {
		time.Sleep(d)
	}
	m := new(dns.Msg)
	m.SetReply(req)
	m.Answer = rrs
	f.mu.Lock()
	trunc := f.truncate[k]
	f.mu.Unlock()
	if trunc && w.RemoteAddr().Network() == "udp" {
		m.Truncated = true
		m.Answer = nil
	}
	_ = w.WriteMsg(m)
}

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("dns.NewRR(%q): %v", s, err)
	}
	return rr
}

func mustSVCB(t *testing.T, s string) *dns.SVCB {
	t.Helper()
	rr := mustRR(t, s)
	switch v := rr.(type) {
	case *dns.HTTPS:
		return &v.SVCB
	case *dns.SVCB:
		return v
	}
	t.Fatalf("mustSVCB: %q parsed to %T", s, rr)
	return nil
}

// RFC 9460 §8: a record whose mandatory list names a key we do not
// implement must be ignored entirely (F6).
func TestParseServiceRecord_UnsupportedMandatoryRejected(t *testing.T) {
	rr := mustSVCB(t, `web.scion. 300 IN SVCB 1 . mandatory=ech alpn=h3 ech=AEX+DQBB3gAgACCm`)
	if _, err := parseServiceRecord(rr, "web.scion."); err == nil {
		t.Fatalf("parseServiceRecord: mandatory=ech accepted, want rejection")
	}
	// All params we DO support may be mandatory.
	ok := mustSVCB(t, `web.scion. 300 IN SVCB 1 . mandatory=alpn,port alpn=h3 port=443`)
	if _, err := parseServiceRecord(ok, "web.scion."); err != nil {
		t.Fatalf("parseServiceRecord(mandatory=alpn,port): %v", err)
	}
}

// RFC 9460 §7.1.2: effective ALPN set = alpn values plus http/1.1 unless
// no-default-alpn; intersected with client protocols in h3,h2,http/1.1
// order.
func TestSupportedALPN(t *testing.T) {
	cases := []struct {
		record string
		want   []string
	}{
		{`x. 300 IN SVCB 1 . alpn=h3,h2`, []string{"h3", "h2", "http/1.1"}},
		{`x. 300 IN SVCB 1 . alpn=h3 no-default-alpn`, []string{"h3"}},
		{`x. 300 IN SVCB 1 . alpn=h2`, []string{"h2", "http/1.1"}},
		{`x. 300 IN SVCB 1 . port=443`, []string{"http/1.1"}}, // no alpn param ⇒ default only
		{`x. 300 IN SVCB 1 . alpn=imap no-default-alpn`, nil}, // nothing we speak
	}
	for _, c := range cases {
		rec, err := parseServiceRecord(mustSVCB(t, c.record), "x.")
		if err != nil {
			t.Fatalf("parseServiceRecord(%q): %v", c.record, err)
		}
		if got := rec.supportedALPN(); !reflect.DeepEqual(got, c.want) {
			t.Errorf("supportedALPN(%q) = %v, want %v", c.record, got, c.want)
		}
	}
}

// TargetName "." resolves to the owner; an explicit target is kept as
// its FQDN (RFC 9460 §2.5).
func TestParseServiceRecord_TargetName(t *testing.T) {
	dot, err := parseServiceRecord(mustSVCB(t, `web.scion. 300 IN SVCB 1 . alpn=h3`), "web.scion.")
	if err != nil {
		t.Fatalf("parseServiceRecord(.): %v", err)
	}
	if dot.target != "web.scion." {
		t.Errorf("target = %q, want owner web.scion.", dot.target)
	}
	alt, err := parseServiceRecord(mustSVCB(t, `web.scion. 300 IN SVCB 1 alt.scion alpn=h3`), "web.scion.")
	if err != nil {
		t.Fatalf("parseServiceRecord(alt): %v", err)
	}
	if alt.target != "alt.scion." {
		t.Errorf("target = %q, want alt.scion. (FQDN)", alt.target)
	}
	mixed, err := parseServiceRecord(mustSVCB(t, `web.scion. 300 IN SVCB 1 Alt.SCION alpn=h3`), "web.scion.")
	if err != nil {
		t.Fatalf("parseServiceRecord(mixed): %v", err)
	}
	if mixed.target != "alt.scion." {
		t.Errorf("target = %q, want canonical alt.scion. (RFC 4343 case folding)", mixed.target)
	}
}

func drainUpdates(ch <-chan []Candidate, timeout time.Duration) ([][]Candidate, bool) {
	var got [][]Candidate
	deadline := time.After(timeout)
	for {
		select {
		case cands, ok := <-ch:
			if !ok {
				return got, true
			}
			got = append(got, cands)
		case <-deadline:
			return got, false
		}
	}
}

// (a) SVCB with scion param + ipv6hint + AAAA + A, all answered promptly:
// candidates carry ALPN/port/priority from SVCB; real AAAA/A answers win
// over the ipv6hint; SCION address is parsed via the typed *dns.SVCBScion.
func TestResolveHost_SVCBWithScionAndRealAnswers(t *testing.T) {
	f := newFakeDNS(t)
	f.set("web.scion.", dns.TypeSVCB, mustRR(t,
		`web.scion. 300 IN SVCB 1 . alpn=h3 port=8443 ipv6hint=2001:db8::9 scion=1-150_10.20.3.215`))
	f.set("web.scion.", dns.TypeAAAA, mustRR(t, `web.scion. 300 IN AAAA 2001:db8::215`))
	f.set("web.scion.", dns.TypeA, mustRR(t, `web.scion. 300 IN A 10.20.3.215`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := ResolveHost(ctx, "web.scion", 443, ResolveOptions{Resolver: f.addr, RRType: RRSVCB})
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}

	if len(res.Initial) == 0 {
		t.Fatalf("Initial = %v, want at least one candidate", labels(res.Initial))
	}

	// SVCB, AAAA and A are all answered promptly with no injected delay, so
	// which pair clears the §4.2 gate first (AAAA+SVCB vs. also having A)
	// is a genuine race — the gate no longer waits on A once AAAA and SVCB
	// are both final (see the dedicated gate tests). Whatever didn't make
	// Initial must arrive via exactly one merged Update.
	updates, closed := drainUpdates(res.Updates, time.Second)
	if !closed {
		t.Fatal("Updates did not close")
	}
	if len(updates) > 1 {
		t.Fatalf("got %d updates, want at most 1 (the fully-merged set)", len(updates))
	}
	final := res.Initial
	if len(updates) == 1 {
		final = updates[0]
	}

	if len(final) != 5 {
		t.Fatalf("final candidate set = %v, want 5 candidates", labels(final))
	}

	// ALPN is the record's EFFECTIVE supported set (RFC 9460 §7.1.2): alpn=h3
	// implies http/1.1 as well (no no-default-alpn), intersected with the
	// client's protocols. The SCION candidate carries the full supported set
	// [h3 http/1.1] (Task 5's pre-authorized ALPN expectation update); each IP
	// address now splits into a QUIC candidate (ALPN [h3]) and a TCP sibling
	// (ALPN [http/1.1], "+tcp" label suffix) — Task 7's F8 dual-transport
	// emission.
	// GroupALPN carries the record's full supported ALPN set on every
	// candidate it emits (Task 9 plan amendment: unified §5.1 record
	// grouping), so both QUIC and TCP siblings of the same record share it
	// regardless of their own (narrower) dial ALPN.
	recordALPN := []string{"h3", "http/1.1"}
	want := map[string]Candidate{
		"scion:1-150,10.20.3.215": {Family: FamilySCION, Host: "10.20.3.215", Port: 8443, IA: "1-150", ALPN: []string{"h3", "http/1.1"}, GroupALPN: recordALPN, Priority: 1, Label: "scion:1-150,10.20.3.215"},
		"v6:2001:db8::215":        {Family: FamilyIPv6, Host: "2001:db8::215", Port: 8443, ALPN: []string{"h3"}, GroupALPN: recordALPN, Priority: 1, Label: "v6:2001:db8::215"},
		"v6+tcp:2001:db8::215":    {Family: FamilyIPv6, Host: "2001:db8::215", Port: 8443, ALPN: []string{"http/1.1"}, GroupALPN: recordALPN, Priority: 1, Label: "v6+tcp:2001:db8::215"},
		"v4:10.20.3.215":          {Family: FamilyIPv4, Host: "10.20.3.215", Port: 8443, ALPN: []string{"h3"}, GroupALPN: recordALPN, Priority: 1, Label: "v4:10.20.3.215"},
		"v4+tcp:10.20.3.215":      {Family: FamilyIPv4, Host: "10.20.3.215", Port: 8443, ALPN: []string{"http/1.1"}, GroupALPN: recordALPN, Priority: 1, Label: "v4+tcp:10.20.3.215"},
	}
	for _, c := range final {
		w, ok := want[c.Label]
		if !ok {
			t.Errorf("unexpected candidate %+v", c)
			continue
		}
		if !reflect.DeepEqual(c, w) {
			t.Errorf("candidate %s = %+v, want %+v", c.Label, c, w)
		}
		if c.Path != nil {
			t.Errorf("candidate %s: Path = %+v, want nil (path expansion is a later task)", c.Label, c.Path)
		}
		if c.ViaScitra {
			t.Errorf("candidate %s: ViaScitra = true, want false", c.Label)
		}
	}
}

// (b) SVCB answer delayed 80ms with the default 50ms Resolution Delay:
// Initial carries only the AAAA/A candidates, and the SCION candidate
// (from the SVCB "scion" param) arrives later on Updates.
func TestResolveHost_ResolutionDelayGatesSVCB(t *testing.T) {
	f := newFakeDNS(t)
	// alpn=h3 no-default-alpn: this test is about Resolution Delay timing,
	// not transport splitting (see TestRecordCandidates_TransportSplit for
	// that), so the record deliberately offers ONLY h3 — a QUIC-only
	// candidate set, matching this test's pre-Task-7 shape exactly (h3 is
	// also required for the SCION candidate to survive at all: F10, SCION
	// transport is QUIC-only).
	f.set("web.scion.", dns.TypeSVCB, mustRR(t, `web.scion. 300 IN SVCB 1 . alpn=h3 no-default-alpn scion=1-150_10.20.3.215`))
	f.setDelay("web.scion.", dns.TypeSVCB, 80*time.Millisecond)
	f.set("web.scion.", dns.TypeAAAA, mustRR(t, `web.scion. 300 IN AAAA 2001:db8::215`))
	f.set("web.scion.", dns.TypeA, mustRR(t, `web.scion. 300 IN A 10.20.3.215`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	res, err := ResolveHost(ctx, "web.scion", 443, ResolveOptions{Resolver: f.addr, RRType: RRSVCB})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}

	if elapsed < 15*time.Millisecond || elapsed > 79*time.Millisecond {
		t.Fatalf("Initial released after %v, want ~25ms (before the 80ms SVCB answer)", elapsed)
	}
	if got := labels(res.Initial); len(got) != 2 {
		t.Fatalf("Initial = %v, want exactly the AAAA/A candidates", got)
	}
	for _, c := range res.Initial {
		if c.Family == FamilySCION {
			t.Fatalf("Initial contains a SCION candidate before the SVCB answer arrived: %+v", c)
		}
	}

	updates, closed := drainUpdates(res.Updates, 2*time.Second)
	if !closed {
		t.Fatal("Updates did not close")
	}
	if len(updates) != 1 {
		t.Fatalf("got %d updates, want exactly 1 (the SVCB-merged set)", len(updates))
	}
	final := updates[0]
	if len(final) != 3 {
		t.Fatalf("merged update = %v, want 3 candidates", labels(final))
	}
	var sawSCION bool
	for _, c := range final {
		if c.Family == FamilySCION {
			sawSCION = true
			if c.IA != "1-150" || c.Host != "10.20.3.215" {
				t.Errorf("SCION candidate = %+v, want IA=1-150 Host=10.20.3.215", c)
			}
		}
	}
	if !sawSCION {
		t.Fatalf("merged update has no SCION candidate: %v", labels(final))
	}
}

// (c) No SVCB record at all: plain AAAA/A candidates with default ALPN
// (empty) and the caller's default port.
func TestResolveHost_NoSVCB(t *testing.T) {
	f := newFakeDNS(t)
	f.set("plain.scion.", dns.TypeAAAA, mustRR(t, `plain.scion. 300 IN AAAA 2001:db8::9`))
	f.set("plain.scion.", dns.TypeA, mustRR(t, `plain.scion. 300 IN A 10.20.3.9`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := ResolveHost(ctx, "plain.scion", 8080, ResolveOptions{Resolver: f.addr, ResolutionDelay: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}

	// With no SVCB record, SVCB and A each independently race AAAA to
	// clear the §4.2 gate (path (a): AAAA+SVCB final; path (b): the 10ms
	// delay). Which of AAAA/A lands in Initial vs. arrives right after via
	// one merged Update is no longer guaranteed — only that both end up in
	// the final candidate set.
	updates, closed := drainUpdates(res.Updates, time.Second)
	if !closed {
		t.Fatal("Updates did not close")
	}
	if len(updates) > 1 {
		t.Fatalf("got %d updates, want at most 1 (the fully-merged set)", len(updates))
	}
	final := res.Initial
	if len(updates) == 1 {
		final = updates[0]
	}

	if len(final) != 2 {
		t.Fatalf("final candidate set = %v, want 2 candidates", labels(final))
	}
	for _, c := range final {
		if len(c.ALPN) != 0 {
			t.Errorf("candidate %s: ALPN = %v, want empty (no SVCB)", c.Label, c.ALPN)
		}
		if c.Port != 8080 {
			t.Errorf("candidate %s: Port = %d, want caller default 8080", c.Label, c.Port)
		}
		if c.Family == FamilySCION {
			t.Errorf("unexpected SCION candidate with no SVCB record: %+v", c)
		}
	}
}

// (d) AliasMode chase: SVCB "0 target.scion." at the queried name is
// followed to target.scion., whose ServiceMode record supplies the SCION
// candidate.
func TestResolveHost_AliasModeChase(t *testing.T) {
	f := newFakeDNS(t)
	f.set("alias.scion.", dns.TypeSVCB, mustRR(t, `alias.scion. 300 IN SVCB 0 target.scion.`))
	f.set("target.scion.", dns.TypeSVCB, mustRR(t, `target.scion. 300 IN SVCB 1 . alpn=h3 scion=1-161_10.20.3.161`))
	f.set("alias.scion.", dns.TypeAAAA, mustRR(t, `alias.scion. 300 IN AAAA 2001:db8::161`))
	f.set("alias.scion.", dns.TypeA, mustRR(t, `alias.scion. 300 IN A 10.20.3.161`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := ResolveHost(ctx, "alias.scion", 443, ResolveOptions{Resolver: f.addr, RRType: RRSVCB})
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}

	var sawSCION bool
	for _, c := range res.Initial {
		if c.Family == FamilySCION {
			sawSCION = true
			if c.IA != "1-161" || c.Host != "10.20.3.161" || c.Port != 443 {
				t.Errorf("chased SCION candidate = %+v, want IA=1-161 Host=10.20.3.161 Port=443", c)
			}
			// Effective ALPN set (RFC 9460 §7.1.2): the record's alpn=h3
			// implies http/1.1, so candidates carry [h3 http/1.1] (Task 5
			// brief's pre-authorized ALPN expectation update).
			if !reflect.DeepEqual(c.ALPN, []string{"h3", "http/1.1"}) {
				t.Errorf("chased SCION candidate ALPN = %v, want [h3 http/1.1] (from target.scion.'s record)", c.ALPN)
			}
		}
	}
	if !sawSCION {
		t.Fatalf("Initial has no SCION candidate after alias chase: %v", labels(res.Initial))
	}

	if _, closed := drainUpdates(res.Updates, time.Second); !closed {
		t.Fatal("Updates did not close")
	}
}

// (e) SVCB query unreachable/times out: plain AAAA/A candidates still
// resolve via the 50ms Resolution Delay gate; the failed SVCB query is
// non-fatal and Updates still closes once the (2s-bounded) SVCB query gives
// up.
func TestResolveHost_SVCBTimeoutNonFatal(t *testing.T) {
	f := newFakeDNS(t)
	// No SVCB record registered and a delay far past queryTimeout so the
	// resolver's own 2s per-query ceiling is what ends the SVCB query.
	f.setDelay("unreachable.scion.", dns.TypeSVCB, 3*time.Second)
	f.set("unreachable.scion.", dns.TypeAAAA, mustRR(t, `unreachable.scion. 300 IN AAAA 2001:db8::42`))
	f.set("unreachable.scion.", dns.TypeA, mustRR(t, `unreachable.scion. 300 IN A 10.20.3.42`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	res, err := ResolveHost(ctx, "unreachable.scion", 443, ResolveOptions{Resolver: f.addr, RRType: RRSVCB})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Initial released after %v, want it gated only by the 50ms Resolution Delay", elapsed)
	}
	if len(res.Initial) != 2 {
		t.Fatalf("Initial = %v, want the 2 AAAA/A candidates despite the hung SVCB query", labels(res.Initial))
	}

	// The SVCB query's own ~2s ceiling still has to expire before Updates
	// closes; give it generous headroom.
	if _, closed := drainUpdates(res.Updates, 3*time.Second); !closed {
		t.Fatal("Updates did not close after the SVCB query timed out")
	}
}

// (f) §4.2 gate path (a): SVCB and AAAA both answer promptly; A is held back
// well past the default 50ms Resolution Delay. Per draft-ietf-happy-
// happyeyeballs-v3-04 §4.2, release does not wait on A once there is a
// positive address answer, AAAA is final, and SVCB is final — Initial must
// release almost immediately, carrying the SCION+v6 candidates, with the A
// candidate arriving later via Updates.
func TestResolveHost_ReleasesWithoutAWhenSVCBAndAAAAComplete(t *testing.T) {
	f := newFakeDNS(t)
	f.set("early.scion.", dns.TypeSVCB, mustRR(t,
		`early.scion. 300 IN SVCB 1 . alpn=h3 scion=1-150_10.20.3.215`))
	f.set("early.scion.", dns.TypeAAAA, mustRR(t, `early.scion. 300 IN AAAA 2001:db8::215`))
	f.set("early.scion.", dns.TypeA, mustRR(t, `early.scion. 300 IN A 10.20.3.215`))
	f.setDelay("early.scion.", dns.TypeA, 500*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	res, err := ResolveHost(ctx, "early.scion", 443, ResolveOptions{Resolver: f.addr, RRType: RRSVCB})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}

	if elapsed >= 100*time.Millisecond {
		t.Fatalf("Initial released after %v, want well before 100ms (A must not gate release once AAAA+SVCB are final)", elapsed)
	}
	if got := labels(res.Initial); len(got) != 3 {
		t.Fatalf("Initial = %v, want exactly the SCION+v6+v6-tcp candidates", got)
	}
	var sawSCION, sawV6 bool
	for _, c := range res.Initial {
		switch c.Family {
		case FamilySCION:
			sawSCION = true
		case FamilyIPv6:
			sawV6 = true
		case FamilyIPv4:
			t.Fatalf("Initial contains an A candidate before the delayed A answer arrived: %+v", c)
		}
	}
	if !sawSCION || !sawV6 {
		t.Fatalf("Initial = %v, want a SCION and a v6 candidate", labels(res.Initial))
	}

	updates, closed := drainUpdates(res.Updates, 2*time.Second)
	if !closed {
		t.Fatal("Updates did not close")
	}
	if len(updates) != 1 {
		t.Fatalf("got %d updates, want exactly 1 (the A-merged set)", len(updates))
	}
	final := updates[0]
	if len(final) != 5 {
		t.Fatalf("merged update = %v, want 5 candidates (SCION, v6/v6+tcp, v4/v4+tcp)", labels(final))
	}
	var gotA bool
	for _, c := range final {
		if c.Family == FamilyIPv4 {
			gotA = true
			if c.Host != "10.20.3.215" {
				t.Errorf("A candidate = %+v, want Host=10.20.3.215", c)
			}
		}
	}
	if !gotA {
		t.Fatalf("merged update has no A candidate: %v", labels(final))
	}
}

// (g) §4.2 gate path (b): only A answers positively and promptly; AAAA (no
// record, and slow) never becomes the required "AAAA final" for gate path
// (a) within the Resolution Delay. Initial must still release at ~50ms via
// the delay path, carrying the A candidate — a positive answer for ANY
// family plus an elapsed Resolution Delay is sufficient; A is never itself
// a release requirement, but it is a sufficient trigger.
func TestResolveHost_ResolutionDelayReleasesWithAOnly(t *testing.T) {
	f := newFakeDNS(t)
	f.set("aonly.scion.", dns.TypeA, mustRR(t, `aonly.scion. 300 IN A 10.20.3.9`))
	f.setDelay("aonly.scion.", dns.TypeAAAA, 500*time.Millisecond) // no AAAA record; answers negative, late

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	res, err := ResolveHost(ctx, "aonly.scion", 8080, ResolveOptions{Resolver: f.addr})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}

	if elapsed < 15*time.Millisecond || elapsed > 200*time.Millisecond {
		t.Fatalf("Initial released after %v, want ~25ms (Resolution Delay path, AAAA still outstanding)", elapsed)
	}
	if got := labels(res.Initial); len(got) != 1 {
		t.Fatalf("Initial = %v, want exactly the A candidate", got)
	}
	if res.Initial[0].Family != FamilyIPv4 || res.Initial[0].Host != "10.20.3.9" {
		t.Fatalf("Initial candidate = %+v, want the A answer 10.20.3.9", res.Initial[0])
	}

	updates, closed := drainUpdates(res.Updates, 2*time.Second)
	if !closed {
		t.Fatal("Updates did not close")
	}
	if len(updates) != 0 {
		t.Fatalf("got %d updates, want none (the late AAAA answer is negative, so the candidate set doesn't change): %v", len(updates), updates)
	}
}

// (h) A caller that reads Initial but abandons Updates without ever
// cancelling ctx would (per the ResolveHost doc comment) delay run()'s
// cleanup until ctx ends; a caller that DOES cancel ctx must see that
// escape trigger promptly instead of blocking on the send forever. This
// pins the ctx.Done() escape on the internal Updates send (resolver.go).
func TestResolveHost_ContextCancelUnblocksAbandonedUpdatesSend(t *testing.T) {
	f := newFakeDNS(t)
	f.set("leak.scion.", dns.TypeSVCB, mustRR(t,
		`leak.scion. 300 IN SVCB 1 . alpn=h3 scion=1-150_10.20.3.215`))
	f.setDelay("leak.scion.", dns.TypeSVCB, 300*time.Millisecond) // arrives after Initial, forcing an Update send
	f.set("leak.scion.", dns.TypeAAAA, mustRR(t, `leak.scion. 300 IN AAAA 2001:db8::215`))
	f.set("leak.scion.", dns.TypeA, mustRR(t, `leak.scion. 300 IN A 10.20.3.215`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	res, err := ResolveHost(ctx, "leak.scion", 443, ResolveOptions{Resolver: f.addr, RRType: RRSVCB})
	if err != nil {
		cancel()
		t.Fatalf("ResolveHost: %v", err)
	}
	if len(res.Initial) == 0 {
		cancel()
		t.Fatal("Initial unexpectedly empty")
	}

	// Deliberately never read from res.Updates — only cancel ctx. This must
	// unblock run()'s pending Updates send (the delayed SVCB answer is still
	// 250ms+ away) well before that answer would otherwise arrive.
	cancel()

	select {
	case _, ok := <-res.Updates:
		if ok {
			t.Fatal("Updates delivered a value after abandonment+cancel; want it to close with no send observed")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Updates did not close promptly after ctx cancellation (no ctx.Done() escape on the Updates send)")
	}
}

// (i) End-to-end hex-ASN scenario using the exact deployed zone form
// (config/coredns/scion.zone's "games" record): the SCION candidate's IA
// and Host must round-trip untouched through scionIA/SCIONAddr parsing.
func TestResolveHost_HexASNScionParam(t *testing.T) {
	f := newFakeDNS(t)
	f.set("games.scion.", dns.TypeSVCB, mustRR(t,
		`games.scion. 300 IN SVCB 1 . alpn=h3 scion=71-2:0:4a_10.44.25.3`))
	f.set("games.scion.", dns.TypeAAAA, mustRR(t, `games.scion. 300 IN AAAA 2001:db8::44`))
	f.set("games.scion.", dns.TypeA, mustRR(t, `games.scion. 300 IN A 10.44.25.9`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := ResolveHost(ctx, "games.scion", 443, ResolveOptions{Resolver: f.addr, RRType: RRSVCB})
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}

	final := res.Initial
	updates, closed := drainUpdates(res.Updates, time.Second)
	if !closed {
		t.Fatal("Updates did not close")
	}
	if len(updates) > 0 {
		final = updates[len(updates)-1]
	}

	var scion *Candidate
	for i := range final {
		if final[i].Family == FamilySCION {
			scion = &final[i]
		}
	}
	if scion == nil {
		t.Fatalf("no SCION candidate in final set: %v", labels(final))
	}
	if scion.IA != "71-2:0:4a" {
		t.Errorf("IA = %q, want 71-2:0:4a", scion.IA)
	}
	if scion.Host != "10.44.25.3" {
		t.Errorf("Host = %q, want 10.44.25.3", scion.Host)
	}
	if scion.Label != "scion:71-2:0:4a,10.44.25.3" {
		t.Errorf("Label = %q, want scion:71-2:0:4a,10.44.25.3 (same canonical form as IA, not addr.String()'s decimal-ASN rendering)", scion.Label)
	}
}

// (k) SCION-only name (no A/AAAA records at all — NODATA for both, matching
// the deployed zone's "games" pattern: SVCB scion= with no address RRs):
// ResolveHost must still release promptly instead of hanging, because
// hasPositiveAddrs required at least one positive AAAA/A answer and neither
// family is ever positive here. A final SVCB that produced a SCION candidate
// must itself count as a positive answer for the delay-path gate, and once
// every query (SVCB/AAAA/A) is final there is nothing left to wait for
// regardless.
func TestResolveHost_SCIONOnlyNoAddresses(t *testing.T) {
	f := newFakeDNS(t)
	f.set("games.scion.", dns.TypeSVCB, mustRR(t,
		`games.scion. 300 IN SVCB 1 . alpn=h3 scion=1-150_10.20.3.215`))
	// Deliberately no AAAA/A records registered: both are NODATA.

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	res, err := ResolveHost(ctx, "games.scion", 443, ResolveOptions{Resolver: f.addr, RRType: RRSVCB})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ResolveHost: %v, want nil error (SCION-only names must resolve, not hang to ctx deadline)", err)
	}
	if elapsed >= 500*time.Millisecond {
		t.Fatalf("ResolveHost took %v, want a prompt return (<500ms) for a SCION-only name with a 2s ctx", elapsed)
	}

	final := res.Initial
	updates, closed := drainUpdates(res.Updates, time.Second)
	if !closed {
		t.Fatal("Updates did not close")
	}
	if len(updates) > 0 {
		final = updates[len(updates)-1]
	}

	if len(final) != 1 {
		t.Fatalf("final candidate set = %v, want exactly the SCION candidate", labels(final))
	}
	if final[0].Family != FamilySCION || final[0].IA != "1-150" || final[0].Host != "10.20.3.215" {
		t.Fatalf("candidate = %+v, want the SCION candidate 1-150,10.20.3.215", final[0])
	}
}

// (l) Every query (SVCB, AAAA, A) resolves negative — no SVCB record, no
// AAAA/A records (the NXDOMAIN/no-records case): ResolveHost must return
// promptly with an empty candidate set and a nil error once all three
// queries are final. An empty Initial is a valid outcome; the caller (not
// the resolver) decides what to do with no candidates.
func TestResolveHost_AllNegativeReturnsEmptyPromptly(t *testing.T) {
	f := newFakeDNS(t) // no records registered for this name at all

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	res, err := ResolveHost(ctx, "nowhere.scion", 443, ResolveOptions{Resolver: f.addr})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ResolveHost: %v, want nil error even though every query answered negative", err)
	}
	if elapsed >= 500*time.Millisecond {
		t.Fatalf("ResolveHost took %v, want a prompt return (<500ms) once all queries are final-negative", elapsed)
	}
	if len(res.Initial) != 0 {
		t.Fatalf("Initial = %v, want empty (no SVCB/AAAA/A records at all)", labels(res.Initial))
	}

	updates, closed := drainUpdates(res.Updates, time.Second)
	if !closed {
		t.Fatal("Updates did not close")
	}
	if len(updates) != 0 {
		t.Fatalf("got %d updates, want none", len(updates))
	}
}

// (m) SCION-only name whose AAAA answer is negative but held back well past
// the default 50ms Resolution Delay (A answers promptly negative): the SCION
// candidate from the completed SVCB must release at ~delay via the §4.2
// delay path, not block until AAAA's slow final answer.
func TestResolveHost_SCIONOnlyReleasesAtDelayWithSlowAAAA(t *testing.T) {
	f := newFakeDNS(t)
	f.set("slowv6.scion.", dns.TypeSVCB, mustRR(t,
		`slowv6.scion. 300 IN SVCB 1 . alpn=h3 scion=1-150_10.20.3.215`))
	f.setDelay("slowv6.scion.", dns.TypeAAAA, 500*time.Millisecond) // no AAAA record; negative, late

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	res, err := ResolveHost(ctx, "slowv6.scion", 443, ResolveOptions{Resolver: f.addr, RRType: RRSVCB})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}

	if elapsed < 15*time.Millisecond || elapsed > 200*time.Millisecond {
		t.Fatalf("Initial released after %v, want ~25ms (delay path; AAAA still outstanding)", elapsed)
	}
	if got := labels(res.Initial); len(got) != 1 {
		t.Fatalf("Initial = %v, want exactly the SCION candidate", got)
	}
	if res.Initial[0].Family != FamilySCION || res.Initial[0].IA != "1-150" || res.Initial[0].Host != "10.20.3.215" {
		t.Fatalf("Initial candidate = %+v, want the SCION candidate 1-150,10.20.3.215", res.Initial[0])
	}

	updates, closed := drainUpdates(res.Updates, 2*time.Second)
	if !closed {
		t.Fatal("Updates did not close")
	}
	if len(updates) != 0 {
		t.Fatalf("got %d updates, want none (the late AAAA answer is negative, so the candidate set doesn't change): %v", len(updates), updates)
	}
}

// (j) Alias chase visited-set/self-alias comparison must be case-
// insensitive (RFC 9460 names are compared canonically): a ServiceMode-0
// alias whose Target differs from the queried name only in case is a
// self-alias and must be rejected immediately, without re-querying the
// case-variant name.
func TestResolveSVCB_AliasChaseCaseInsensitiveSelfAlias(t *testing.T) {
	f := newFakeDNS(t)
	// Deliberately no record registered for "CASE.scion." — if the case
	// variant were (incorrectly) treated as a distinct name, the chase
	// would requery it, find nothing, and silently return (nil, nil)
	// instead of catching the self-alias.
	f.set("case.scion.", dns.TypeSVCB, mustRR(t, `case.scion. 300 IN SVCB 0 CASE.scion.`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tl := &Timeline{}
	r := &resolveRun{ctx: ctx, servers: []string{f.addr}, host: dns.Fqdn("case.scion"), port: 443, tl: tl}

	_, err := r.resolveService(dns.TypeSVCB)
	if err == nil {
		t.Fatal("resolveService: want a self-alias error for a case-variant self-alias, got nil")
	}
	if !strings.Contains(err.Error(), "alias to self") {
		t.Fatalf("resolveService error = %v, want an alias-to-self error", err)
	}

	queries := 0
	for _, ev := range tl.Events() {
		if ev.Kind == "query" {
			queries++
		}
	}
	if queries != 1 {
		t.Fatalf("issued %d SVCB queries, want exactly 1 (case-variant self-alias must be caught before requerying)", queries)
	}
}

// A truncated UDP answer must be retried over TCP against the same
// server (F9): the full RRset arrives via TCP, not the empty TC reply.
func TestResolve_TruncatedUDPFallsBackToTCP(t *testing.T) {
	f := newFakeDNS(t)
	f.set("web.scion.", dns.TypeSVCB, mustRR(t,
		`web.scion. 300 IN SVCB 1 . alpn=h3 scion=1-150_10.20.3.215`))
	f.set("web.scion.", dns.TypeAAAA, mustRR(t, `web.scion. 300 IN AAAA 2001:db8::215`))
	f.setTruncateUDP("web.scion.", dns.TypeSVCB)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := ResolveHost(ctx, "web.scion", 443, ResolveOptions{Resolver: f.addr, RRType: RRSVCB})
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	all := res.Initial
	if more, _ := drainUpdates(res.Updates, 2*time.Second); len(more) > 0 {
		all = more[len(more)-1]
	}
	var haveSCION bool
	for _, c := range all {
		if c.Family == FamilySCION {
			haveSCION = true
		}
	}
	if !haveSCION {
		t.Fatalf("candidates %v: truncated-UDP SVCB answer was not recovered over TCP", labels(all))
	}
}

// An HTTPS (type 65) record must be usable exactly like SVCB: the fork's
// dns.HTTPS embeds dns.SVCB, so scion=/alpn=/port= all apply (F2).
func TestResolve_HTTPSRecordType(t *testing.T) {
	f := newFakeDNS(t)
	f.set("web.scion.", dns.TypeHTTPS, mustRR(t,
		`web.scion. 300 IN HTTPS 1 . alpn=h3 port=8443 scion=1-150_10.20.3.215`))
	f.set("web.scion.", dns.TypeAAAA, mustRR(t, `web.scion. 300 IN AAAA 2001:db8::215`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := ResolveHost(ctx, "web.scion", 443, ResolveOptions{Resolver: f.addr, RRType: RRHTTPS})
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	all := res.Initial
	if more, _ := drainUpdates(res.Updates, 2*time.Second); len(more) > 0 {
		all = more[len(more)-1]
	}
	var scion *Candidate
	for i := range all {
		if all[i].Family == FamilySCION {
			scion = &all[i]
		}
	}
	if scion == nil {
		t.Fatalf("candidates %v: HTTPS record produced no SCION candidate", labels(all))
	}
	if scion.Port != 8443 || scion.IA != "1-150" {
		t.Errorf("SCION candidate = %+v, want port 8443 IA 1-150", scion)
	}
}

// RRBoth queries both types in parallel and prefers HTTPS answers when both
// exist.
func TestResolve_BothPrefersHTTPS(t *testing.T) {
	f := newFakeDNS(t)
	f.set("web.scion.", dns.TypeHTTPS, mustRR(t,
		`web.scion. 300 IN HTTPS 1 . alpn=h3 port=1111 scion=1-150_10.20.3.215`))
	f.set("web.scion.", dns.TypeSVCB, mustRR(t,
		`web.scion. 300 IN SVCB 1 . alpn=h3 port=2222 scion=1-150_10.20.3.215`))
	f.set("web.scion.", dns.TypeAAAA, mustRR(t, `web.scion. 300 IN AAAA 2001:db8::215`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := ResolveHost(ctx, "web.scion", 443, ResolveOptions{Resolver: f.addr, RRType: RRBoth})
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	all := res.Initial
	if more, _ := drainUpdates(res.Updates, 2*time.Second); len(more) > 0 {
		all = more[len(more)-1]
	}
	for _, c := range all {
		if c.Family == FamilySCION && c.Port != 1111 {
			t.Errorf("SCION candidate port = %d, want 1111 (HTTPS answer preferred over SVCB)", c.Port)
		}
	}
}

// A dead first server must not sink the query: the resolver fails over
// to the next configured server (F9 / draft §4.5).
func TestResolve_FailsOverToSecondServer(t *testing.T) {
	f := newFakeDNS(t)
	f.set("web.scion.", dns.TypeAAAA, mustRR(t, `web.scion. 300 IN AAAA 2001:db8::215`))

	// 198.51.100.1:9 is TEST-NET; nothing answers. Short ctx bounds the run.
	dead := "198.51.100.1:9"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := ResolveHost(ctx, "web.scion", 443, ResolveOptions{Resolver: dead + "," + f.addr})
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	all := res.Initial
	if more, _ := drainUpdates(res.Updates, 8*time.Second); len(more) > 0 {
		all = more[len(more)-1]
	}
	found := false
	for _, c := range all {
		if c.Label == "v6:2001:db8::215" {
			found = true
		}
	}
	if !found {
		t.Fatalf("candidates %v: second server was never consulted", labels(all))
	}
}

// Two ServiceMode records: each contributes candidates with ITS OWN
// alpn/port/priority; priorities order the records (§5.2) (F3).
func TestResolve_MultipleServiceRecords(t *testing.T) {
	f := newFakeDNS(t)
	f.set("web.scion.", dns.TypeSVCB,
		mustRR(t, `web.scion. 300 IN SVCB 2 . alpn=h3 port=2222 scion=1-151_10.20.3.216`),
		mustRR(t, `web.scion. 300 IN SVCB 1 . alpn=h3 port=1111 scion=1-150_10.20.3.215`))
	f.set("web.scion.", dns.TypeAAAA, mustRR(t, `web.scion. 300 IN AAAA 2001:db8::215`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := ResolveHost(ctx, "web.scion", 443, ResolveOptions{Resolver: f.addr, RRType: RRSVCB, ShuffleSeed: 1})
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	all := res.Initial
	if more, _ := drainUpdates(res.Updates, 2*time.Second); len(more) > 0 {
		all = more[len(more)-1]
	}
	byLabel := map[string]Candidate{}
	for _, c := range all {
		byLabel[c.Label] = c
	}
	a, okA := byLabel["scion:1-150,10.20.3.215"]
	b, okB := byLabel["scion:1-151,10.20.3.216"]
	if !okA || !okB {
		t.Fatalf("candidates %v: want SCION candidates from BOTH records", labels(all))
	}
	if a.Port != 1111 || a.Priority != 1 {
		t.Errorf("record-1 candidate = %+v, want port 1111 prio 1", a)
	}
	if b.Port != 2222 || b.Priority != 2 {
		t.Errorf("record-2 candidate = %+v, want port 2222 prio 2", b)
	}
	// The owner AAAA is covered by the "." records; its candidates carry
	// the LOWEST-priority covering record's params (prio 1, port 1111).
	v6 := byLabel["v6:2001:db8::215"]
	if v6.Port != 1111 || v6.Priority != 1 {
		t.Errorf("owner v6 candidate = %+v, want port 1111 prio 1 (first covering record)", v6)
	}
}

// The same SCION address in two ServiceMode records yields one endpoint per
// record, each with its record's port and priority: the first keeps the
// plain label, the others get the port and priority in their labels.
func TestResolve_SameSCIONAddressInTwoRecords(t *testing.T) {
	f := newFakeDNS(t)
	f.set("web.scion.", dns.TypeHTTPS,
		mustRR(t, `web.scion. 300 IN HTTPS 1 . alpn=h3 port=1111 scion=1-150_10.20.3.215`),
		mustRR(t, `web.scion. 300 IN HTTPS 2 . alpn=h3 port=2222 scion=1-150_10.20.3.215`),
		mustRR(t, `web.scion. 300 IN HTTPS 3 . alpn=h3 port=2222 scion=1-150_10.20.3.215`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := ResolveHost(ctx, "web.scion", 443, ResolveOptions{Resolver: f.addr})
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	all := res.Initial
	if more, _ := drainUpdates(res.Updates, 2*time.Second); len(more) > 0 {
		all = more[len(more)-1]
	}
	want := map[string][2]uint16{
		"scion:1-150,10.20.3.215":         {1111, 1},
		"scion:1-150,10.20.3.215@2222/p2": {2222, 2},
		"scion:1-150,10.20.3.215@2222/p3": {2222, 3},
	}
	got := map[string][2]uint16{}
	for _, c := range all {
		if c.Family == FamilySCION {
			got[c.Label] = [2]uint16{c.Port, c.Priority}
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SCION endpoints (label: port, priority) = %v, want %v", got, want)
	}
}

// alpn=h3,h2 must yield BOTH a QUIC and a TCP candidate per address, so
// a UDP-blackholed network still converges on h2 (F8). alpn=h3 +
// no-default-alpn yields only QUIC. alpn=h2 yields only TCP and drops
// the scion= addresses (SCION transport is QUIC-only, F10).
func TestRecordCandidates_TransportSplit(t *testing.T) {
	f := newFakeDNS(t)
	f.set("web.scion.", dns.TypeSVCB, mustRR(t,
		`web.scion. 300 IN SVCB 1 . alpn=h3,h2 scion=1-150_10.20.3.215`))
	f.set("web.scion.", dns.TypeAAAA, mustRR(t, `web.scion. 300 IN AAAA 2001:db8::215`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := ResolveHost(ctx, "web.scion", 443, ResolveOptions{Resolver: f.addr, RRType: RRSVCB, ShuffleSeed: 1})
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	all := res.Initial
	if more, _ := drainUpdates(res.Updates, 2*time.Second); len(more) > 0 {
		all = more[len(more)-1]
	}
	byLabel := map[string]Candidate{}
	for _, c := range all {
		byLabel[c.Label] = c
	}
	q, okQ := byLabel["v6:2001:db8::215"]
	tc, okT := byLabel["v6+tcp:2001:db8::215"]
	if !okQ || !okT {
		t.Fatalf("candidates %v: want QUIC + TCP split for the AAAA answer", labels(all))
	}
	if !reflect.DeepEqual(q.ALPN, []string{"h3"}) {
		t.Errorf("QUIC candidate ALPN = %v, want [h3]", q.ALPN)
	}
	if !reflect.DeepEqual(tc.ALPN, []string{"h2", "http/1.1"}) {
		t.Errorf("TCP candidate ALPN = %v, want [h2 http/1.1]", tc.ALPN)
	}
	if _, ok := byLabel["scion:1-150,10.20.3.215"]; !ok {
		t.Errorf("candidates %v: SCION candidate missing (h3 IS in the set)", labels(all))
	}
}

func TestRecordCandidates_QUICOnlyAndTCPOnly(t *testing.T) {
	f := newFakeDNS(t)
	f.set("q.scion.", dns.TypeSVCB, mustRR(t,
		`q.scion. 300 IN SVCB 1 . alpn=h3 no-default-alpn`))
	f.set("q.scion.", dns.TypeAAAA, mustRR(t, `q.scion. 300 IN AAAA 2001:db8::1`))
	f.set("t.scion.", dns.TypeSVCB, mustRR(t,
		`t.scion. 300 IN SVCB 1 . alpn=h2 scion=1-150_10.20.3.215`))
	f.set("t.scion.", dns.TypeAAAA, mustRR(t, `t.scion. 300 IN AAAA 2001:db8::2`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := ResolveHost(ctx, "q.scion", 443, ResolveOptions{Resolver: f.addr, RRType: RRSVCB, ShuffleSeed: 1})
	if err != nil {
		t.Fatalf("ResolveHost(q): %v", err)
	}
	all := res.Initial
	if more, _ := drainUpdates(res.Updates, 2*time.Second); len(more) > 0 {
		all = more[len(more)-1]
	}
	for _, c := range all {
		if c.Label == "v6+tcp:2001:db8::1" {
			t.Errorf("q.scion (h3, no-default-alpn) must not get a TCP candidate: %v", labels(all))
		}
	}

	tl := &Timeline{}
	res, err = ResolveHost(ctx, "t.scion", 443, ResolveOptions{Resolver: f.addr, RRType: RRSVCB, ShuffleSeed: 1, Timeline: tl})
	if err != nil {
		t.Fatalf("ResolveHost(t): %v", err)
	}
	all = res.Initial
	if more, _ := drainUpdates(res.Updates, 2*time.Second); len(more) > 0 {
		all = more[len(more)-1]
	}
	for _, c := range all {
		if c.Family == FamilySCION {
			t.Errorf("t.scion (alpn=h2): SCION candidate must be dropped, got %v", labels(all))
		}
		if c.Label == "v6:2001:db8::2" {
			t.Errorf("t.scion (alpn=h2): no QUIC candidate expected, got %v", labels(all))
		}
	}
	// The drop leaves an explanatory note.
	found := false
	for _, ev := range tl.Events() {
		if ev.Kind == "fail" && strings.Contains(ev.Detail, "no QUIC ALPN") {
			found = true
		}
	}
	if !found {
		t.Errorf("timeline %v: want a 'no QUIC ALPN' fail note for the dropped scion addresses", tl.Events())
	}
}

// A ServiceMode record with TargetName != "." takes its addresses from
// AAAA/A queries for the TARGET, merged in via Updates (F3, §4.2.1).
func TestResolve_ServiceModeTargetName(t *testing.T) {
	f := newFakeDNS(t)
	f.set("web.scion.", dns.TypeSVCB, mustRR(t,
		`web.scion. 300 IN SVCB 1 alt.scion. alpn=h3 port=8443`))
	f.set("alt.scion.", dns.TypeAAAA, mustRR(t, `alt.scion. 300 IN AAAA 2001:db8::a17`))
	// owner has no addresses of its own
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := ResolveHost(ctx, "web.scion", 443, ResolveOptions{Resolver: f.addr, RRType: RRSVCB, ShuffleSeed: 1})
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	all := res.Initial
	if more, ok := drainUpdates(res.Updates, 3*time.Second); len(more) > 0 {
		all = more[len(more)-1]
		_ = ok
	}
	found := false
	for _, c := range all {
		if c.Host == "2001:db8::a17" && c.Port == 8443 {
			found = true
		}
	}
	if !found {
		t.Fatalf("candidates %v: target-name AAAA never merged in", labels(all))
	}
}

// Owner A/AAAA answers not covered by any ServiceMode record (all records
// target elsewhere) trail the list with worst priority (§5.2) (F3).
func TestResolve_UnassociatedAddressesTrail(t *testing.T) {
	f := newFakeDNS(t)
	f.set("web.scion.", dns.TypeSVCB, mustRR(t,
		`web.scion. 300 IN SVCB 1 alt.scion. alpn=h3`))
	f.set("alt.scion.", dns.TypeAAAA, mustRR(t, `alt.scion. 300 IN AAAA 2001:db8::a17`))
	f.set("web.scion.", dns.TypeAAAA, mustRR(t, `web.scion. 300 IN AAAA 2001:db8::215`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := ResolveHost(ctx, "web.scion", 443, ResolveOptions{Resolver: f.addr, RRType: RRSVCB, ShuffleSeed: 1})
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	all := res.Initial
	if more, _ := drainUpdates(res.Updates, 3*time.Second); len(more) > 0 {
		all = more[len(more)-1]
	}
	var owner *Candidate
	for i := range all {
		if all[i].Host == "2001:db8::215" {
			owner = &all[i]
		}
	}
	if owner == nil {
		t.Fatalf("candidates %v: unassociated owner AAAA must still be present", labels(all))
	}
	if owner.Priority != 65535 {
		t.Errorf("unassociated owner candidate = %+v, want Priority 65535", owner)
	}
}

// A mixed-case input host must still be covered by a "."-target record:
// all name keying happens on the canonical (lowercased, FQDN) form.
func TestResolve_MixedCaseHostCoveredByDotRecord(t *testing.T) {
	f := newFakeDNS(t)
	f.set("web.scion.", dns.TypeSVCB, mustRR(t,
		`web.scion. 300 IN SVCB 1 . alpn=h3 port=8443 scion=1-150_10.20.3.215`))
	f.set("web.scion.", dns.TypeAAAA, mustRR(t, `web.scion. 300 IN AAAA 2001:db8::215`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := ResolveHost(ctx, "Web.SCION", 443, ResolveOptions{Resolver: f.addr, RRType: RRSVCB, ShuffleSeed: 1})
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	all := res.Initial
	if more, _ := drainUpdates(res.Updates, 2*time.Second); len(more) > 0 {
		all = more[len(more)-1]
	}
	var v6 *Candidate
	for i := range all {
		if all[i].Label == "v6:2001:db8::215" {
			v6 = &all[i]
		}
	}
	if v6 == nil {
		t.Fatalf("candidates %v: owner AAAA missing for mixed-case host", labels(all))
	}
	if v6.Port != 8443 || v6.Priority != 1 {
		t.Errorf("owner v6 = %+v, want port 8443 prio 1 (covered by the \".\" record)", v6)
	}
}

// A TargetName spelling the OWNER in different case still covers the
// owner (RFC 4343): no duplicate mis-prioritized owner candidate, no
// redundant chase.
func TestResolve_MixedCaseTargetNameCoversOwner(t *testing.T) {
	f := newFakeDNS(t)
	f.set("web.scion.", dns.TypeSVCB, mustRR(t,
		`web.scion. 300 IN SVCB 1 WEB.scion. alpn=h3 port=8443`))
	f.set("web.scion.", dns.TypeAAAA, mustRR(t, `web.scion. 300 IN AAAA 2001:db8::215`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := ResolveHost(ctx, "web.scion", 443, ResolveOptions{Resolver: f.addr, RRType: RRSVCB, ShuffleSeed: 1})
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	all := res.Initial
	if more, _ := drainUpdates(res.Updates, 2*time.Second); len(more) > 0 {
		all = more[len(more)-1]
	}
	var count int
	for _, c := range all {
		if c.Label == "v6:2001:db8::215" {
			count++
			if c.Port != 8443 || c.Priority != 1 {
				t.Errorf("owner v6 = %+v, want port 8443 prio 1 (covered)", c)
			}
		}
	}
	if count != 1 {
		t.Fatalf("candidates %v: want exactly one owner v6 candidate, got %d", labels(all), count)
	}
}

// Equal-priority records are shuffled deterministically under a fixed
// seed, and the order is stable across rebuilds within one resolution
// (§5.2 SHOULD).
func TestOrderRecords_EqualPriorityShuffleDeterministic(t *testing.T) {
	mk := func(tgt string) *svcRecord { return &svcRecord{prio: 1, target: tgt} }
	recs := []*svcRecord{mk("a."), mk("b."), mk("c."), mk("d.")}
	r1 := rand.New(rand.NewPCG(7, 7))
	r2 := rand.New(rand.NewPCG(7, 7))
	o1 := orderRecords(recs, r1)
	o2 := orderRecords(recs, r2)
	if !reflect.DeepEqual(o1, o2) {
		t.Errorf("same seed gave different orders: %v vs %v", o1, o2)
	}
	lo := rand.New(rand.NewPCG(1, 1))
	mixed := []*svcRecord{{prio: 2, target: "z."}, mk("a."), mk("b.")}
	got := orderRecords(mixed, lo)
	if got[len(got)-1].prio != 2 {
		t.Errorf("priority ordering violated by shuffle: %+v", got)
	}
}

// §4.2 examples: the Resolution Delay timer is set when the first
// positive answer arrives with the gate unsatisfied — NOT at query
// start. An A answer at ~150ms must still grant AAAA a further ~100ms
// grace (old behavior would release immediately, 150ms > delay) (F7).
func TestResolve_DelayTimerArmsAtFirstPositiveAnswer(t *testing.T) {
	f := newFakeDNS(t)
	f.set("web.scion.", dns.TypeA, mustRR(t, `web.scion. 300 IN A 10.20.3.215`))
	f.set("web.scion.", dns.TypeAAAA, mustRR(t, `web.scion. 300 IN AAAA 2001:db8::215`))
	f.setDelay("web.scion.", dns.TypeA, 150*time.Millisecond)
	f.setDelay("web.scion.", dns.TypeAAAA, 220*time.Millisecond) // lands inside A+100ms grace
	f.setDelay("web.scion.", dns.TypeSVCB, 600*time.Millisecond) // keeps gate set 1 unsatisfied
	f.setDelay("web.scion.", dns.TypeHTTPS, 600*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := ResolveHost(ctx, "web.scion", 443, ResolveOptions{
		Resolver: f.addr, ResolutionDelay: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	got := labels(res.Initial)
	want6, want4 := false, false
	for _, l := range got {
		if l == "v6:2001:db8::215" {
			want6 = true
		}
		if l == "v4:10.20.3.215" {
			want4 = true
		}
	}
	if !want6 || !want4 {
		t.Fatalf("Initial = %v: AAAA at A+70ms missed the delay window — timer armed too early (at query start?)", got)
	}
	// drain to let the resolver goroutine finish cleanly
	drainUpdates(res.Updates, 2*time.Second)
}

// The proxy's cache needs the answer TTLs: MinTTL reports the smallest
// TTL across the RRsets that contributed candidates.
func TestResolved_MinTTL(t *testing.T) {
	f := newFakeDNS(t)
	f.set("web.scion.", dns.TypeSVCB, mustRR(t,
		`web.scion. 300 IN SVCB 1 . alpn=h3 scion=1-150_10.20.3.215`))
	f.set("web.scion.", dns.TypeAAAA, mustRR(t, `web.scion. 60 IN AAAA 2001:db8::215`))
	f.set("web.scion.", dns.TypeA, mustRR(t, `web.scion. 3600 IN A 10.20.3.215`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := ResolveHost(ctx, "web.scion", 443, ResolveOptions{Resolver: f.addr, RRType: RRSVCB})
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	drainUpdates(res.Updates, 2*time.Second) // all queries final
	if got := res.MinTTL(); got != 60*time.Second {
		t.Errorf("MinTTL = %v, want 60s", got)
	}
}

// The default sends the HTTPS query only: the draft adds no other DNS
// queries to those of HEv3, which maps an https URL to one HTTPS query.
func TestResolve_DefaultQueriesHTTPSOnly(t *testing.T) {
	f := newFakeDNS(t)
	f.set("web.scion.", dns.TypeHTTPS, mustRR(t, `web.scion. 300 IN HTTPS 1 . alpn=h3 scion=1-150_10.20.3.215`))
	f.set("web.scion.", dns.TypeAAAA, mustRR(t, `web.scion. 300 IN AAAA 2001:db8::215`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tl := &Timeline{}
	res, err := ResolveHost(ctx, "web.scion", 443, ResolveOptions{Resolver: f.addr, Timeline: tl})
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	drainUpdates(res.Updates, 2*time.Second)
	var queries []string
	for _, ev := range tl.Events() {
		if ev.Kind == "query" {
			queries = append(queries, ev.Label)
		}
	}
	for _, q := range queries {
		if strings.HasPrefix(q, "SVCB ") {
			t.Fatalf("queries %v: default sent an SVCB query", queries)
		}
	}
	if !slices.Contains(queries, "HTTPS web.scion.") {
		t.Fatalf("queries %v: no HTTPS query", queries)
	}
}

// A SCION-first client gets the SCION endpoints of the service answer as
// soon as that answer is final, without waiting for the address answers;
// the IP endpoints follow. This holds with the default single HTTPS query
// and with the single SVCB query.
func TestResolveHost_SCIONFirstReleasesSCIONEarly(t *testing.T) {
	t.Run("https", func(t *testing.T) { testSCIONFirstReleasesSCIONEarly(t, RRHTTPS) })
	t.Run("svcb", func(t *testing.T) { testSCIONFirstReleasesSCIONEarly(t, RRSVCB) })
}

func testSCIONFirstReleasesSCIONEarly(t *testing.T, rt RRType) {
	f := newFakeDNS(t)
	if rt == RRSVCB {
		f.set("web.scion.", dns.TypeSVCB, mustRR(t, `web.scion. 300 IN SVCB 1 . alpn=h3 no-default-alpn scion=1-150_10.20.3.215`))
	} else {
		f.set("web.scion.", dns.TypeHTTPS, mustRR(t, `web.scion. 300 IN HTTPS 1 . alpn=h3 no-default-alpn scion=1-150_10.20.3.215`))
	}
	f.set("web.scion.", dns.TypeAAAA, mustRR(t, `web.scion. 300 IN AAAA 2001:db8::215`))
	f.set("web.scion.", dns.TypeA, mustRR(t, `web.scion. 300 IN A 10.20.3.215`))
	f.setDelay("web.scion.", dns.TypeAAAA, 200*time.Millisecond)
	f.setDelay("web.scion.", dns.TypeA, 200*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	res, err := ResolveHost(ctx, "web.scion", 443, ResolveOptions{Resolver: f.addr, SCIONFirst: true, RRType: rt})
	if err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}
	if el := time.Since(start); el > 150*time.Millisecond {
		t.Fatalf("Initial released after %v, want before the 200ms address answers", el)
	}
	if len(res.Initial) != 1 || res.Initial[0].Family != FamilySCION {
		t.Fatalf("Initial = %v, want the SCION endpoint only", labels(res.Initial))
	}
	if !res.FirstIPAnswer().IsZero() {
		t.Fatalf("FirstIPAnswer set before any address answer")
	}
	select {
	case set := <-res.Updates:
		if len(set) < 2 || set[0].Family == set[len(set)-1].Family {
			t.Fatalf("update = %v, want the SCION endpoint and IP endpoints", labels(set))
		}
		if a := res.FirstIPAnswer(); a.IsZero() || a.Sub(start) < 150*time.Millisecond {
			t.Fatalf("FirstIPAnswer = %v after start, want ~200ms", a.Sub(start))
		}
	case <-ctx.Done():
		t.Fatal("no update with the IP endpoints")
	}
}
