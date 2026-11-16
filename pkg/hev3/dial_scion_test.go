package hev3

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
)

const ms = time.Millisecond

// fakePath is a minimal snet.Path carrying only the metadata ExpandSCION reads.
type fakePath struct {
	md *snet.PathMetadata
}

func (p fakePath) UnderlayNextHop() *net.UDPAddr { return nil }
func (p fakePath) Dataplane() snet.DataplanePath { return nil }
func (p fakePath) Source() addr.IA               { return 0 }
func (p fakePath) Destination() addr.IA          { return 0 }
func (p fakePath) Metadata() *snet.PathMetadata  { return p.md }

func makePath(latencies []time.Duration, ifaceIDs []uint64) snet.Path {
	ifs := make([]snet.PathInterface, len(ifaceIDs))
	for i, id := range ifaceIDs {
		ifs[i] = snet.PathInterface{ID: iface.ID(id), IA: addr.MustParseIA("1-150")}
	}
	return fakePath{md: &snet.PathMetadata{Interfaces: ifs, Latency: latencies}}
}

type fakeQuerier struct {
	paths  []snet.Path
	err    error
	gotDst addr.IA
}

func (q *fakeQuerier) Paths(_ context.Context, dst addr.IA) ([]snet.Path, error) {
	q.gotDst = dst
	return q.paths, q.err
}

func withQuerier(t *testing.T, q pathQuerier, err error) {
	t.Helper()
	orig := resolveQuerier
	resolveQuerier = func(context.Context, DialerOptions) (pathQuerier, error) { return q, err }
	t.Cleanup(func() { resolveQuerier = orig })
}

func protoCand() Candidate {
	return Candidate{
		Family: FamilySCION,
		IA:     "1-150",
		Host:   "10.20.3.216",
		Port:   443,
		ALPN:   []string{"h3"},
		Label:  "scion:1-150,10.20.3.216",
	}
}

// One SCION endpoint becomes one candidate carrying all eligible paths
// known, in the deterministic order of the selection: fewest AS hops first,
// then known declared latency ascending, unknown latency after. The
// candidate paths are selected from them when the endpoint is attempted.
func TestExpandSCIONNativeRankingAndCap(t *testing.T) {
	fast := makePath([]time.Duration{10 * ms}, []uint64{1, 2})               // 2 AS hops, 10ms
	three := makePath([]time.Duration{1 * ms, 1 * ms}, []uint64{3, 4, 5, 6}) // 3 AS hops, 2ms
	slow := makePath([]time.Duration{30 * ms}, []uint64{7, 8})               // 2 AS hops, 30ms
	unset := makePath([]time.Duration{-1}, []uint64{9, 10})                  // 2 AS hops, unknown
	q := &fakeQuerier{paths: []snet.Path{three, slow, unset, fast}}
	withQuerier(t, q, nil)

	ipc := Candidate{Family: FamilyIPv6, Host: "2001:db8::1", Port: 443, Label: "v6:2001:db8::1"}
	stats := &statsCollector{}
	out := ExpandSCION(context.Background(), []Candidate{protoCand(), ipc}, DialerOptions{Stats: stats})

	if q.gotDst != addr.MustParseIA("1-150") {
		t.Fatalf("querier queried dst %s, want 1-150", q.gotDst)
	}
	if len(out) != 2 {
		t.Fatalf("got %d candidates, want 2 (passthrough + one SCION endpoint): %v", len(out), labels(out))
	}
	if out[0].Label != "v6:2001:db8::1" {
		t.Fatalf("out[0] = %q, want passthrough IP candidate", out[0].Label)
	}
	c := out[1]
	if c.Label != "scion:1-150,10.20.3.216#paths" || c.Family != FamilySCION {
		t.Fatalf("SCION candidate = %q family %v", c.Label, c.Family)
	}
	if len(c.PathSet) != 4 {
		t.Fatalf("candidate has %d paths, want all 4 eligible paths", len(c.PathSet))
	}
	if c.Path != &c.PathSet[0] {
		t.Errorf("Path must point at PathSet[0]")
	}
	want := []snet.Path{fast, slow, unset} // three (3 AS hops) is ranked 4th
	wantLat := []time.Duration{10 * ms, 30 * ms, 0}
	for i, sp := range c.PathSet[:3] {
		if sp.SNET.(snet.Path).Metadata() != want[i].Metadata() {
			t.Errorf("PathSet[%d] = %s, want %s", i, sp.Interfaces, interfacesString(want[i].Metadata()))
		}
		if sp.Hops != 2 || sp.Latency != wantLat[i] {
			t.Errorf("PathSet[%d] hops=%d lat=%v, want 2/%v", i, sp.Hops, sp.Latency, wantLat[i])
		}
	}
	_, lookups := stats.snapshot()
	if len(lookups) != 1 || lookups[0].PathsFound != 4 || len(lookups[0].PathSet) != 4 {
		t.Errorf("lookup stats = %+v", lookups)
	}
}

// localFakeQuerier is a fakeQuerier in a known own AS that records every
// destination it is asked for.
type localFakeQuerier struct {
	fakeQuerier
	local addr.IA
	mu    sync.Mutex
	dsts  []addr.IA
}

func (q *localFakeQuerier) Paths(ctx context.Context, dst addr.IA) ([]snet.Path, error) {
	q.mu.Lock()
	q.dsts = append(q.dsts, dst)
	q.mu.Unlock()
	return q.fakeQuerier.paths, nil
}

func (q *localFakeQuerier) LocalIA() addr.IA { return q.local }

// Section 5.4 of draft-john-scion-svcb: paths are looked up for at most
// MaxDestinationASes distinct destination ASes, the first ones in the order
// the endpoints arrive. The own AS needs no lookup and does not count;
// endpoints sharing an admitted AS share its lookup; an endpoint in a
// further AS gets no lookup and is dropped with a note.
func TestExpandSCIONDestinationASLimit(t *testing.T) {
	q := &localFakeQuerier{fakeQuerier: fakeQuerier{paths: []snet.Path{makePath([]time.Duration{10 * ms}, []uint64{1, 2})}}, local: mustIA("1-153")}
	withQuerier(t, q, nil)
	mk := func(ia, host string) Candidate {
		return Candidate{Family: FamilySCION, IA: ia, Host: host, Port: 443, ALPN: []string{"h3"}, Label: "scion:" + ia + "," + host}
	}
	in := []Candidate{mk("1-153", "10.0.0.3"), mk("1-150", "10.0.0.1"), mk("1-151", "10.0.0.2"), mk("1-150", "10.0.0.4"), mk("1-152", "10.0.0.5")}
	tl := &Timeline{}
	stats := &statsCollector{}
	out := ExpandSCION(context.Background(), in, DialerOptions{Timeline: tl, Stats: stats, MaxDestinationASes: 2})
	want := []string{"scion:1-153,10.0.0.3#paths", "scion:1-150,10.0.0.1#paths", "scion:1-151,10.0.0.2#paths", "scion:1-150,10.0.0.4#paths"}
	if got := labels(out); !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
	if !hasFailNote(tl, "scion:1-152,10.0.0.5") {
		t.Fatal("no Timeline note for the endpoint beyond the destination AS limit")
	}
	for _, d := range q.dsts {
		if d == mustIA("1-152") || d == mustIA("1-153") {
			t.Fatalf("paths looked up for %s: %v", d, q.dsts)
		}
	}
	_, lookups := stats.snapshot()
	var limited int
	for _, l := range lookups {
		if l.Err == errDestinationASLimit.Error() {
			limited++
		}
	}
	if limited != 1 {
		t.Fatalf("lookup stats %+v: want one entry for the AS beyond the limit", lookups)
	}

	// The ASes within the limit are the first registered, not the first
	// whose lookup runs.
	g := &lookupGroup{}
	g.register(mustIA("1-152"))
	g.register(mustIA("1-150"))
	if g.admit(mustIA("1-150"), 0, 1) || !g.admit(mustIA("1-152"), 0, 1) {
		t.Fatal("admit does not follow the registration order")
	}
	if !g.admit(mustIA("1-150"), 0, -1) {
		t.Fatal("a negative limit must admit every AS")
	}
}

// Two endpoints with the same SCION address from different records (labels
// from scionLabel) stay two candidates, with one shared path lookup; with
// scitra instead of a daemon they stay two candidates too.
func TestExpandSCIONSameAddressTwoEndpoints(t *testing.T) {
	q := &localFakeQuerier{fakeQuerier: fakeQuerier{paths: []snet.Path{makePath([]time.Duration{10 * ms}, []uint64{1, 2})}}, local: mustIA("1-153")}
	withQuerier(t, q, nil)
	a := protoCand()
	b := protoCand()
	b.Port, b.Priority, b.Label = 8443, 2, a.Label+"@8443/p2"
	out := ExpandSCION(context.Background(), []Candidate{a, b}, DialerOptions{Lookups: &lookupGroup{}})
	if len(out) != 2 || out[0].Label != a.Label+"#paths" || out[1].Label != b.Label+"#paths" || out[1].Port != 8443 {
		t.Fatalf("candidates = %v, want both endpoints", labels(out))
	}
	if len(q.dsts) != 1 {
		t.Fatalf("path lookups for %v, want one shared lookup", q.dsts)
	}

	withQuerier(t, nil, errors.New("no daemon"))
	setRoute(t, true)
	out = ExpandSCION(context.Background(), []Candidate{a, b}, DialerOptions{})
	if len(out) != 2 || out[0].Label == out[1].Label || out[1].Label != "scitra:1-150,fc00:1000:9600::ffff:a14:3d8@8443/p2" {
		t.Fatalf("scitra candidates = %v, want two distinct labels", labels(out))
	}
}

func TestExpandSCIONNoPathsDrops(t *testing.T) {
	q := &fakeQuerier{paths: nil}
	withQuerier(t, q, nil)
	tl := &Timeline{}
	out := ExpandSCION(context.Background(), []Candidate{protoCand()}, DialerOptions{Timeline: tl})
	if len(out) != 0 {
		t.Fatalf("got %d candidates, want 0", len(out))
	}
	if !hasFailNote(tl, "scion:1-150,10.20.3.216") {
		t.Fatal("expected a Timeline fail note for the dropped SCION candidate")
	}
}

func TestExpandSCIONScitraFallback(t *testing.T) {
	withQuerier(t, nil, errors.New("no daemon"))
	setRoute(t, true)

	ipc := Candidate{Family: FamilyIPv4, Host: "203.0.113.1", Port: 443, Label: "v4:203.0.113.1"}
	out := ExpandSCION(context.Background(), []Candidate{protoCand(), ipc}, DialerOptions{})

	if len(out) != 2 {
		t.Fatalf("got %d candidates, want 2 (passthrough + scitra): %v", len(out), labels(out))
	}
	if out[0].Label != "v4:203.0.113.1" {
		t.Fatalf("out[0] = %q, want passthrough", out[0].Label)
	}
	sc := out[1]
	if !sc.ViaScitra || sc.Family != FamilyIPv6 {
		t.Fatalf("scitra candidate = %+v, want ViaScitra IPv6", sc)
	}
	if sc.Host != "fc00:1000:9600::ffff:a14:3d8" {
		t.Fatalf("scitra host = %q, want mapped fc00:1000:9600::ffff:a14:3d8", sc.Host)
	}
	if sc.Port != 443 || len(sc.ALPN) != 1 || sc.ALPN[0] != "h3" {
		t.Fatalf("scitra candidate lost port/ALPN: %+v", sc)
	}
	if sc.Path != nil {
		t.Fatalf("scitra candidate must have no SCION path, got %+v", sc.Path)
	}
}

func TestExpandSCIONNoDaemonNoScitraDrops(t *testing.T) {
	withQuerier(t, nil, errors.New("no daemon"))
	setRoute(t, false)
	tl := &Timeline{}
	out := ExpandSCION(context.Background(), []Candidate{protoCand()}, DialerOptions{Timeline: tl})
	if len(out) != 0 {
		t.Fatalf("got %d candidates, want 0", len(out))
	}
	if !hasFailNote(tl, "scion:1-150,10.20.3.216") {
		t.Fatal("expected a Timeline fail note when no daemon and no scitra route")
	}
}

// setRoute points procNetIPv6Route at a fixture with or without an fc00::/8 entry.
func setRoute(t *testing.T, present bool) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ipv6_route")
	content := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 " +
		"00000000000000000000000000000000 ffffffff 00000000 00000000 00000000 lo\n"
	if present {
		content += "fc000000000000000000000000000000 08 00000000000000000000000000000000 00 " +
			"00000000000000000000000000000000 00000064 00000001 00000000 00000001 sci01\n"
	}
	writeFile(t, path, content)
	orig := procNetIPv6Route
	procNetIPv6Route = path
	t.Cleanup(func() { procNetIPv6Route = orig })
}

// F12: expansion of multiple proto-candidates through one scionContext
// resolves the querier exactly once (previously: one daemon connect per
// ExpandSCION call).
func TestSCIONContext_QuerierResolvedOnce(t *testing.T) {
	old := resolveQuerier
	defer func() { resolveQuerier = old }()
	var calls atomic.Int32
	resolveQuerier = func(ctx context.Context, o DialerOptions) (pathQuerier, error) {
		calls.Add(1)
		return &fakeQuerier{paths: nil}, nil
	}

	sctx := newSCIONContext(DialerOptions{})
	defer sctx.Close()
	o := DialerOptions{SCION: sctx}
	p1 := Candidate{Family: FamilySCION, IA: "1-150", Host: "10.0.0.1", Label: "scion:1-150,10.0.0.1"}
	p2 := Candidate{Family: FamilySCION, IA: "1-151", Host: "10.0.0.2", Label: "scion:1-151,10.0.0.2"}
	ExpandSCION(context.Background(), []Candidate{p1}, o)
	ExpandSCION(context.Background(), []Candidate{p2}, o)
	if n := calls.Load(); n != 1 {
		t.Fatalf("resolveQuerier called %d times through one scionContext, want 1", n)
	}
}

// recordingConnector is a minimal daemon.Connector that records whether
// Close was called. All other methods are unused by this test and would
// panic via the nil embedded interface if ever invoked.
type recordingConnector struct {
	daemon.Connector
	closed atomic.Bool
}

func (r *recordingConnector) Close() error {
	r.closed.Store(true)
	return nil
}

// F12 regression: Close racing an in-flight querier() sync.Once body must
// not let the Once cache a live, un-reaped daemon connection. Two
// independent sync.Once/mutex values give no happens-before relationship
// with each other, so a naive Close could observe "nothing stored yet",
// return, and then have the Once store a connection that is never closed
// (a leak). The fake resolveQuerier blocks on a channel the test controls,
// which deterministically guarantees Close runs and completes before the
// connection is ever produced — this is not a "run it enough times and
// hope" race test.
func TestSCIONContext_CloseDuringInFlightQuerierReapsConn(t *testing.T) {
	old := resolveQuerier
	defer func() { resolveQuerier = old }()

	block := make(chan struct{})
	rc := &recordingConnector{}
	resolveQuerier = func(ctx context.Context, o DialerOptions) (pathQuerier, error) {
		<-block // released only after the test's Close() call below returns
		return daemonQuerier{conn: rc, localIA: addr.MustParseIA("1-150")}, nil
	}

	sctx := newSCIONContext(DialerOptions{})
	o := DialerOptions{SCION: sctx}

	done := make(chan struct{})
	var qErr error
	go func() {
		_, qErr = sctx.querier(context.Background(), o)
		close(done)
	}()

	if err := sctx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	close(block)
	<-done

	if !rc.closed.Load() {
		t.Fatal("Close raced the in-flight querier() Once and the just-produced connector was never reaped (leak)")
	}
	if qErr == nil {
		t.Fatal("querier() returned a nil error after Close raced it, want a closed-context error")
	}
}

func hasFailNote(tl *Timeline, label string) bool {
	for _, e := range tl.Events() {
		if e.Kind == "fail" && e.Label == label {
			return true
		}
	}
	return false
}

type addrIA = addr.IA

func mustIA(s string) addr.IA { return addr.MustParseIA(s) }
