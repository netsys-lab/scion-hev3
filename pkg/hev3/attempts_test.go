package hev3

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/snet"
)

// dialAttempts over the emulated network of racer_test.go.
func (e *emuEnv) attempts(t *testing.T, ctx context.Context, d attemptsDial) (attemptsResult, error) {
	t.Helper()
	d.Remote = &snet.UDPAddr{IA: emuServerIA, Host: e.srvAddr}
	if d.Paths == nil {
		d.Paths = e.paths
	}
	d.Topology = emuTopo(emuClientIA, func(uint16) (netip.AddrPort, bool) {
		return e.relays[0].sockC.LocalAddr().(*net.UDPAddr).AddrPort(), true
	})
	d.LocalIP = net.IPv4(127, 0, 0, 1)
	d.TLS = e.tlsCli.Clone()
	res, err := dialAttempts(ctx, d)
	if err == nil {
		t.Cleanup(func() {
			_ = res.conn.CloseWithError(0, "")
			_ = res.tr.Close()
			_ = res.pc.Close()
		})
	}
	return res, err
}

// Both paths work and the handshake takes longer than the Path Attempt
// Delay: a separate connection is attempted over each path, from a local
// port of its own, 10 ms apart; the first wins, the second is closed with
// CONNECTION_CLOSE once its handshake completes.
func TestAttempts_SeparateConnectionPerPath(t *testing.T) {
	e := newEmuEnv(t, []relayMode{relayForward, relayForward}, 15*time.Millisecond)
	var bg sync.WaitGroup
	var starts []time.Time
	var mu sync.Mutex
	res, err := e.attempts(t, context.Background(), attemptsDial{
		Delay:   10 * time.Millisecond,
		BG:      &bg,
		OnStart: func(ts time.Time) { mu.Lock(); starts = append(starts, ts); mu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.winner != 0 {
		t.Fatalf("winner = path %d, want path 1", res.winner+1)
	}
	bg.Wait()
	w, ps := res.set.snapshot()
	if w != 1 || len(ps) != 2 {
		t.Fatalf("snapshot: winner %d, %d paths", w, len(ps))
	}
	if ps[0].Outcome != "won" || ps[1].Outcome != "closed" {
		t.Fatalf("outcomes = %q, %q; want won, closed", ps[0].Outcome, ps[1].Outcome)
	}
	if gap := ps[1].StartMs - ps[0].StartMs; gap < 9.5 || gap > 40 {
		t.Fatalf("second attempt started %.1fms after the first, want ~10ms", gap)
	}
	if ps[0].LocalPort == 0 || ps[0].LocalPort == ps[1].LocalPort {
		t.Fatalf("local ports %d and %d: want two different ports", ps[0].LocalPort, ps[1].LocalPort)
	}
	if len(starts) != 2 {
		t.Fatalf("OnStart called %d times, want 2", len(starts))
	}
	// The server sees two connections; the cancelled one may be closed
	// before the server's Accept returns it, so only one is required here.
	if n := e.waitAccepted(1); n < 1 || n > 2 {
		t.Fatalf("server accepted %d connections, want 1 or 2", n)
	}
	if e.relays[0].up.Load() == 0 || e.relays[1].up.Load() == 0 {
		t.Fatalf("packets per path: %d, %d; want both used", e.relays[0].up.Load(), e.relays[1].up.Load())
	}
}

// The 10 ms between attempts also holds between an attempt over a further
// path and an attempt to another endpoint: the second path attempt is due
// 20 ms after the first, but another endpoint's attempt started at about
// 14 ms, so it waits until 10 ms after that.
func TestAttempts_FurtherPathKeepsTenMillisToOtherEndpoint(t *testing.T) {
	e := newEmuEnv(t, []relayMode{relayForward, relayForward}, 30*time.Millisecond)
	var clock attemptClock
	var mu sync.Mutex
	var starts []time.Time
	var other time.Time
	otherDone := make(chan struct{})
	time.AfterFunc(14*time.Millisecond, func() {
		// Another endpoint's attempt, started through the same clock as
		// the engine does.
		for clock.reserve() > 0 {
			time.Sleep(time.Millisecond)
		}
		mu.Lock()
		other = time.Now()
		mu.Unlock()
		close(otherDone)
	})
	_, err := e.attempts(t, context.Background(), attemptsDial{
		Delay:   20 * time.Millisecond,
		Linger:  -1,
		Reserve: clock.reserve,
		OnStart: func(ts time.Time) {
			clock.record(ts)
			mu.Lock()
			starts = append(starts, ts)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	<-otherDone
	mu.Lock()
	defer mu.Unlock()
	if len(starts) != 2 {
		t.Fatalf("%d path attempts started, want 2", len(starts))
	}
	for i, s := range starts {
		gap := s.Sub(other)
		if gap < 0 {
			gap = -gap
		}
		if gap < 9500*time.Microsecond {
			t.Fatalf("path attempt %d started %v from the other endpoint's attempt, want at least 10ms", i+1, s.Sub(other))
		}
	}
}

// A handshake that completes within the Path Attempt Delay: the second
// attempt is never started.
func TestAttempts_FirstWinsBeforeSecondStarts(t *testing.T) {
	e := newEmuEnv(t, []relayMode{relayForward, relayForward}, 0)
	res, err := e.attempts(t, context.Background(), attemptsDial{Delay: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	_, ps := res.set.snapshot()
	if ps[0].Outcome != "won" || ps[1].Outcome != "not-started" || ps[1].Started {
		t.Fatalf("outcomes = %q, %q (started %v); want won, not-started", ps[0].Outcome, ps[1].Outcome, ps[1].Started)
	}
	if up := e.relays[1].up.Load(); up != 0 {
		t.Fatalf("path 2 carried %d packets, want 0", up)
	}
}

// The first path fails silently: the connection is established over the
// second path, one Path Attempt Delay later.
func TestAttempts_SecondPathWinsWhenFirstDrops(t *testing.T) {
	e := newEmuEnv(t, []relayMode{relayDrop, relayForward}, time.Millisecond)
	start := time.Now()
	res, err := e.attempts(t, context.Background(), attemptsDial{Linger: -1})
	if err != nil {
		t.Fatal(err)
	}
	if res.winner != 1 {
		t.Fatalf("winner = path %d, want path 2", res.winner+1)
	}
	if el := time.Since(start); el > 300*time.Millisecond {
		t.Fatalf("established after %v, want about the 50ms Path Attempt Delay plus a handshake", el)
	}
	deadline := time.Now().Add(time.Second)
	for {
		_, ps := res.set.snapshot()
		if ps[0].Outcome == "cancelled" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("path 1 outcome = %q, want cancelled", ps[0].Outcome)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// An SCMP error does not end an attempt: path 1 answers every packet with
// External Interface Down, yet its attempt goes on until path 2 wins.
func TestAttempts_SCMPDoesNotEndAttempt(t *testing.T) {
	e := newEmuEnv(t, []relayMode{relaySCMP, relayForward}, 5*time.Millisecond)
	res, err := e.attempts(t, context.Background(), attemptsDial{Delay: 60 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if res.winner != 1 {
		t.Fatalf("winner = path %d, want path 2", res.winner+1)
	}
	_, ps := res.set.snapshot()
	if len(ps[0].SCMP) == 0 {
		t.Fatalf("no SCMP error recorded on path 1")
	}
	if ps[1].StartMs < 55 {
		t.Fatalf("path 2 started at %.1fms: the SCMP error on path 1 must not start it early", ps[1].StartMs)
	}
}

// All paths fail silently: the attempts go on until the endpoint's attempt
// is cancelled.
func TestAttempts_AllPathsDrop(t *testing.T) {
	e := newEmuEnv(t, []relayMode{relayDrop, relayDrop}, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	var bg sync.WaitGroup
	_, err := e.attempts(t, ctx, attemptsDial{Linger: -1, BG: &bg})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	done := make(chan struct{})
	go func() { bg.Wait(); close(done) }()
	waitClosed(t, done, 2*time.Second, "end of the cancelled attempts")
}

// No attempt is started on an expired path, and an attempt fails when its
// path expires.
func TestAttempts_ExpiredPath(t *testing.T) {
	e := newEmuEnv(t, []relayMode{relayDrop, relayDrop}, 0)
	p1 := withExpiry(emuPath(t, 1, e.relays[0]), time.Now().Add(-time.Second))
	p2 := withExpiry(emuPath(t, 2, e.relays[1]), time.Now().Add(120*time.Millisecond))
	start := time.Now()
	res, err := e.attempts(t, context.Background(), attemptsDial{Paths: []snet.Path{p1, p2}, Linger: -1})
	if !errors.Is(err, errAllAttemptsFailed) {
		t.Fatalf("err = %v, want errAllAttemptsFailed", err)
	}
	if el := time.Since(start); el < 100*time.Millisecond || el > time.Second {
		t.Fatalf("failed after %v, want at the expiry of path 2 (~120ms)", el)
	}
	_, ps := res.set.snapshot()
	if ps[0].Started || e.relays[0].up.Load() != 0 {
		t.Fatalf("an attempt was started on the expired path")
	}
}

type expiryPath struct {
	snet.Path
	md *snet.PathMetadata
}

func (p expiryPath) Metadata() *snet.PathMetadata { return p.md }

func withExpiry(p snet.Path, at time.Time) snet.Path {
	md := *p.Metadata()
	md.Expiry = at
	return expiryPath{Path: p, md: &md}
}

func TestAttempts_NoPaths(t *testing.T) {
	res, err := dialAttempts(context.Background(), attemptsDial{})
	if !errors.Is(err, errNoEligiblePath) || res.set == nil {
		t.Fatalf("err = %v, set = %v", err, res.set)
	}
}

// Endpoints in the same AS share one path lookup.
func TestLookupGroup_SharesPerAS(t *testing.T) {
	q := &countingQuerier{paths: []snet.Path{makePath([]time.Duration{ms}, []uint64{1, 2})}, delay: 30 * time.Millisecond}
	withQuerier(t, q, nil)
	a := protoCand()
	b := protoCand()
	b.Host, b.Label = "10.20.3.217", "scion:1-150,10.20.3.217"
	o := DialerOptions{Lookups: &lookupGroup{}, Stats: &statsCollector{}}
	var wg sync.WaitGroup
	for _, c := range []Candidate{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if out := ExpandSCION(context.Background(), []Candidate{c}, o); len(out) != 1 {
				t.Errorf("%s: %d candidates", c.Label, len(out))
			}
		}()
	}
	wg.Wait()
	if n := q.calls(); n != 1 {
		t.Fatalf("%d lookups, want 1 for two endpoints in one AS", n)
	}
	_, ls := o.Stats.snapshot()
	if len(ls) != 2 || ls[0].Shared == ls[1].Shared {
		t.Fatalf("lookup stats: %+v", ls)
	}
}

type countingQuerier struct {
	mu    sync.Mutex
	n     int
	paths []snet.Path
	delay time.Duration
}

func (q *countingQuerier) Paths(ctx context.Context, _ addrIA) ([]snet.Path, error) {
	q.mu.Lock()
	q.n++
	q.mu.Unlock()
	select {
	case <-time.After(q.delay):
		return q.paths, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (q *countingQuerier) calls() int { q.mu.Lock(); defer q.mu.Unlock(); return q.n }

// A lookup that takes longer than the limit fails, and the endpoint is
// discarded.
func TestExpandSCION_LookupLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the 2s lookup limit")
	}
	q := &countingQuerier{delay: 5 * time.Second}
	withQuerier(t, q, nil)
	start := time.Now()
	out := ExpandSCION(context.Background(), []Candidate{protoCand()}, DialerOptions{})
	if len(out) != 0 {
		t.Fatalf("got %d candidates, want none", len(out))
	}
	if el := time.Since(start); el < 1900*time.Millisecond || el > 3*time.Second {
		t.Fatalf("gave up after %v, want 2s", el)
	}
}

// The lookup limit also bounds the shared daemon connect: with a daemon that
// does not answer, the endpoint is given up 2s after its lookup started, not
// after the longer timeout of the detached connect.
func TestExpandSCION_LookupLimitHangingDaemon(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the 2s lookup limit")
	}
	release := make(chan struct{})
	orig := resolveQuerier
	resolveQuerier = func(ctx context.Context, _ DialerOptions) (pathQuerier, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, errors.New("daemon did not answer")
	}
	t.Cleanup(func() { resolveQuerier = orig })
	setRoute(t, false)
	o := DialerOptions{}
	o.SCION = newSCIONContext(o)
	defer o.SCION.Close()
	defer func() {
		// Let the shared connect finish before resolveQuerier is restored.
		close(release)
		_, _ = o.SCION.querier(context.Background(), o)
	}()
	start := time.Now()
	out := ExpandSCION(context.Background(), []Candidate{protoCand()}, o)
	if len(out) != 0 {
		t.Fatalf("got %d candidates, want none", len(out))
	}
	if el := time.Since(start); el < 1900*time.Millisecond || el > 2500*time.Millisecond {
		t.Fatalf("gave up after %v, want 2s", el)
	}
}

// An endpoint in the client's own AS needs no lookup and uses the empty path.
func TestExpandSCION_OwnAS(t *testing.T) {
	q := &ownASQuerier{}
	withQuerier(t, q, nil)
	stats := &statsCollector{}
	out := ExpandSCION(context.Background(), []Candidate{protoCand()}, DialerOptions{Stats: stats})
	if len(out) != 1 || len(out[0].PathSet) != 1 {
		t.Fatalf("out = %+v", out)
	}
	p := out[0].PathSet[0].SNET.(snet.Path)
	if hp, ok := hopPairsOf(p.Dataplane()); !ok || len(hp) != 0 {
		t.Fatalf("path is not the empty path: %T", p.Dataplane())
	}
	if q.called {
		t.Fatalf("a lookup was made for an endpoint in the client's own AS")
	}
	if _, ls := stats.snapshot(); len(ls) != 1 || !ls[0].OwnAS {
		t.Fatalf("lookup stats: %+v", ls)
	}
	// The empty path is eligible at attempt time.
	set, _ := selectPathSet([]snet.Path{p}, pathSetParams{K: 2, Now: time.Now(), Random: true})
	if len(set) != 1 {
		t.Fatalf("empty path not selected")
	}
}

type ownASQuerier struct{ called bool }

func (q *ownASQuerier) Paths(context.Context, addrIA) ([]snet.Path, error) {
	q.called = true
	return nil, errors.New("unexpected lookup")
}
func (q *ownASQuerier) LocalIA() addrIA { return mustIA("1-150") }
