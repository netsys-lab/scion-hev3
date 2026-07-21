package hev3

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
)

const ms = time.Millisecond

// fakePath is a minimal snet.Path carrying only the metadata ExpandSCION reads,
// plus an optional name used by policy-ranking tests to identify a path (see fp).
type fakePath struct {
	name string
	md   *snet.PathMetadata
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

// namedPath builds a fakePath identified by name (retrieved via fp), carrying
// latency and per-hop bandwidth metadata for scion-policy ranking/filter tests.
// Interfaces are synthesized 1:1 with the latency entries (plus one), with IDs
// derived deterministically from name so distinct paths get distinct
// fingerprints; the exact hop topology is irrelevant to these tests.
func namedPath(name string, latencies []time.Duration, bandwidths []uint64) snet.Path {
	var h uint64 = 1
	for _, b := range []byte(name) {
		h = h*31 + uint64(b)
	}
	n := len(latencies) + 1
	ifs := make([]snet.PathInterface, n)
	for i := range ifs {
		ifs[i] = snet.PathInterface{ID: iface.ID(h + uint64(i)), IA: addr.MustParseIA("1-150")}
	}
	return fakePath{name: name, md: &snet.PathMetadata{Interfaces: ifs, Latency: latencies, Bandwidth: bandwidths}}
}

// fp returns a fakePath's identifying name, for policy-ranking test assertions.
func fp(p snet.Path) string {
	return p.(fakePath).name
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

func TestExpandSCIONNativeRankingAndCap(t *testing.T) {
	fast := makePath([]time.Duration{10 * ms}, []uint64{1, 2})             // 10ms, 2 hops
	mid := makePath([]time.Duration{5 * ms, 5 * ms}, []uint64{3, 4, 5, 6}) // 10ms, 4 hops
	slow := makePath([]time.Duration{30 * ms}, []uint64{7, 8})             // 30ms, 2 hops
	unset := makePath([]time.Duration{-1}, []uint64{9, 10})                // unset ⇒ last
	q := &fakeQuerier{paths: []snet.Path{slow, unset, fast, mid}}
	withQuerier(t, q, nil)

	ipc := Candidate{Family: FamilyIPv6, Host: "2001:db8::1", Port: 443, Label: "v6:2001:db8::1"}
	out := ExpandSCION(context.Background(), []Candidate{protoCand(), ipc}, DialerOptions{})

	if q.gotDst != addr.MustParseIA("1-150") {
		t.Fatalf("querier queried dst %s, want 1-150", q.gotDst)
	}
	// passthrough IP candidate first, then 3 ranked natives (unset dropped by K=3).
	if len(out) != 4 {
		t.Fatalf("got %d candidates, want 4: %+v", len(out), labels(out))
	}
	if out[0].Label != "v6:2001:db8::1" {
		t.Fatalf("out[0] = %q, want passthrough IP candidate", out[0].Label)
	}
	natives := out[1:]
	wantLabels := []string{
		"scion:1-150,10.20.3.216#p1",
		"scion:1-150,10.20.3.216#p2",
		"scion:1-150,10.20.3.216#p3",
	}
	// Ranking: fast(10ms,2h) < mid(10ms,4h) < slow(30ms).
	wantHops := []int{2, 4, 2}
	wantLat := []time.Duration{10 * ms, 10 * ms, 30 * ms}
	for i, c := range natives {
		if c.Label != wantLabels[i] {
			t.Errorf("native[%d] label = %q, want %q", i, c.Label, wantLabels[i])
		}
		if c.Family != FamilySCION || c.Path == nil {
			t.Fatalf("native[%d] = %+v, want SCION with pinned path", i, c)
		}
		if c.Path.Hops != wantHops[i] || c.Path.Latency != wantLat[i] {
			t.Errorf("native[%d] hops=%d lat=%v, want hops=%d lat=%v",
				i, c.Path.Hops, c.Path.Latency, wantHops[i], wantLat[i])
		}
		if _, ok := c.Path.SNET.(snet.Path); !ok {
			t.Errorf("native[%d] SNET is %T, want snet.Path", i, c.Path.SNET)
		}
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

// scion-policy prefer items reorder path ranking: bw ranks by bottleneck
// (minimum announced hop bandwidth) descending, before the default
// latency ordering (draft-john-scion-svcb §4, F11).
func TestRankPaths_PolicyBandwidthFirst(t *testing.T) {
	fast := namedPath("fast", []time.Duration{10 * ms}, []uint64{10_000})
	fat := namedPath("fat", []time.Duration{40 * ms}, []uint64{100_000})
	paths := []snet.Path{fast, fat}

	rankPaths(paths, nil)
	if fp(paths[0]) != "fast" {
		t.Errorf("nil policy: want latency-first ranking, got %v first", fp(paths[0]))
	}

	paths = []snet.Path{fast, fat}
	rankPaths(paths, &PathPolicy{Prefer: []PolicyMetric{MetricBandwidth}})
	if fp(paths[0]) != "fat" {
		t.Errorf("bw policy: want bottleneck-bandwidth-first ranking, got %v first", fp(paths[0]))
	}
}

// Threshold items filter the path set; when EVERY path violates, the
// thresholds are ignored entirely (draft MUST fail-open).
func TestFilterByPolicy_ThresholdsAndFailOpen(t *testing.T) {
	near := namedPath("near", []time.Duration{10 * ms}, []uint64{10_000})
	far := namedPath("far", []time.Duration{200 * ms}, []uint64{10_000})

	kept, failedOpen := filterByPolicy([]snet.Path{near, far}, &PathPolicy{MaxLatency: 50 * ms})
	if failedOpen || len(kept) != 1 || fp(kept[0]) != "near" {
		t.Errorf("filter = %d paths (failedOpen=%v), want just 'near'", len(kept), failedOpen)
	}

	kept, failedOpen = filterByPolicy([]snet.Path{far}, &PathPolicy{MaxLatency: 50 * ms})
	if !failedOpen || len(kept) != 1 {
		t.Errorf("all-violating set must fail open with every path kept, got %d (failedOpen=%v)", len(kept), failedOpen)
	}

	// A path with unknown latency can not violate a latency threshold.
	unknown := namedPath("unknown", []time.Duration{-1}, []uint64{10_000})
	kept, failedOpen = filterByPolicy([]snet.Path{unknown, far}, &PathPolicy{MaxLatency: 50 * ms})
	if failedOpen || len(kept) != 1 || fp(kept[0]) != "unknown" {
		t.Errorf("unknown-latency path must survive a maxlat filter, got %v (failedOpen=%v)", len(kept), failedOpen)
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
