package hev3

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

// The engine with a static set must behave exactly like Race. This test
// drives runEngine directly (Race delegates to it after this task): launch
// order follows the input list, most-recent failure promotes immediately,
// and the all-fail error names every candidate.
func TestEngine_StaticParityLaunchOrderAndAllFail(t *testing.T) {
	a, b, c := cand("a"), cand("b"), cand("c")
	errX := errors.New("x")
	ctls := map[string]*ctl{"a": newCtl(), "b": newCtl(), "c": newCtl()}
	ctls["a"].err, ctls["b"].err, ctls["c"].err = errX, errX, errX

	var tl Timeline
	_, err := runEngine(context.Background(), engineConfig{
		dial:       fakeDialer(ctls),
		initial:    []Candidate{a, b, c},
		delay:      20 * time.Millisecond,
		tl:         &tl,
		noCandsErr: errors.New("hev3: no candidates to race"),
	})
	if err == nil {
		t.Fatal("want joined failure error")
	}
	for _, lbl := range []string{"a", "b", "c"} {
		if !labelsOf(tl.Events(), "attempt")[lbl] {
			t.Fatalf("missing attempt event for %s: %+v", lbl, tl.Events())
		}
	}
	if !errors.Is(err, errX) {
		t.Fatalf("error does not wrap the dial error: %v", err)
	}
}

// An empty static set (updates nil) returns noCandsErr immediately.
func TestEngine_StaticEmpty(t *testing.T) {
	want := errors.New("nothing")
	_, err := runEngine(context.Background(), engineConfig{
		dial:       fakeDialer(nil),
		noCandsErr: want,
	})
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want noCandsErr", err)
	}
}

// F13: after launching a SCION candidate with known path latency L, the
// next attempt fires at ~clamp(2L+60ms, MinAttemptDelay, base) instead of
// the full base stagger. Here L=5ms ⇒ adaptive 70ms, min 20ms ⇒ next leg
// starts ~70ms later, far below the 500ms base.
func TestEngine_AdaptiveStaggerTightensAfterSCION(t *testing.T) {
	sc := Candidate{Family: FamilySCION, Host: "10.0.0.1", IA: "1-150",
		Label: "scion:1-150,10.0.0.1#p1",
		Path:  &SCIONPath{Latency: 5 * time.Millisecond, Hops: 2}}
	ip := cand("v4")
	ctls := map[string]*ctl{sc.Label: newCtl(), "v4": newCtl()}
	ctls[sc.Label].block = true // hangs; stagger decides when v4 starts
	ctls["v4"].block = true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runEngine(ctx, engineConfig{
			dial:     fakeDialer(ctls),
			initial:  []Candidate{sc, ip},
			delay:    500 * time.Millisecond,
			minDelay: 20 * time.Millisecond,
			maxDelay: 2 * time.Second,
			adaptive: true,
		})
		close(done)
	}()
	waitClosed(t, ctls[sc.Label].started, time.Second, "start of scion")
	waitClosed(t, ctls["v4"].started, time.Second, "start of v4")
	gap := ctls["v4"].startedAt.Sub(ctls[sc.Label].startedAt)
	if gap >= 300*time.Millisecond {
		t.Fatalf("v4 started %v after SCION; adaptive stagger (~70ms) never applied", gap)
	}
	if gap < 20*time.Millisecond-5*time.Millisecond {
		t.Fatalf("v4 started %v after SCION; below the 20ms min floor", gap)
	}
	cancel()
	waitClosed(t, done, time.Second, "engine return")
}

// The adaptive stagger is not in the draft: without RaceOptions.AdaptiveDelay
// the next attempt after a SCION endpoint with a known path latency waits
// the full Connection Attempt Delay.
func TestRace_AdaptiveStaggerOffByDefault(t *testing.T) {
	sc := Candidate{Family: FamilySCION, Host: "10.0.0.1", IA: "1-150",
		Label: "scion:1-150,10.0.0.1#p1",
		Path:  &SCIONPath{Latency: 5 * time.Millisecond, Hops: 2}}
	ip := cand("v4")
	ctls := map[string]*ctl{sc.Label: newCtl(), "v4": newCtl()}
	ctls[sc.Label].block = true
	ctls["v4"].block = true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		Race(ctx, []Candidate{sc, ip}, fakeDialer(ctls), RaceOptions{AttemptDelay: 200 * time.Millisecond})
		close(done)
	}()
	waitClosed(t, ctls[sc.Label].started, time.Second, "start of scion")
	waitClosed(t, ctls["v4"].started, time.Second, "start of v4")
	if gap := ctls["v4"].startedAt.Sub(ctls[sc.Label].startedAt); gap < 190*time.Millisecond {
		t.Fatalf("v4 started %v after SCION; want the full 200ms Connection Attempt Delay", gap)
	}
	cancel()
	waitClosed(t, done, time.Second, "engine return")
}

// F5: the draft's MUST — no two attempts within 10ms. A 1ms configured
// delay is floored.
func TestEngine_HardFloorTenMillis(t *testing.T) {
	a, b := cand("a"), cand("b")
	ctls := map[string]*ctl{"a": newCtl(), "b": newCtl()}
	ctls["a"].block, ctls["b"].block = true, true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runEngine(ctx, engineConfig{dial: fakeDialer(ctls),
			initial: []Candidate{a, b}, delay: time.Millisecond})
		close(done)
	}()
	waitClosed(t, ctls["a"].started, time.Second, "start of a")
	waitClosed(t, ctls["b"].started, time.Second, "start of b")
	if gap := ctls["b"].startedAt.Sub(ctls["a"].startedAt); gap < 10*time.Millisecond-2*time.Millisecond {
		t.Fatalf("b started %v after a; draft MUST NOT start within 10ms", gap)
	}
	cancel()
	waitClosed(t, done, time.Second, "engine return")
}

// §4.3/§7: a late-arriving candidate is sorted as if present from the
// start. v6 arrives while v4 hangs; the interleave-aware sortFn puts v6
// ahead of the unlaunched v4b, so v6 is the next launch.
func TestEngine_LateArrivalSortedAsIfPresent(t *testing.T) {
	v4a, v4b := cand("v4a"), cand("v4b")
	v6 := Candidate{Family: FamilyIPv6, Host: "2001:db8::1", Label: "v6"}
	ctls := map[string]*ctl{"v4a": newCtl(), "v4b": newCtl(), "v6": newCtl()}
	for _, k := range ctls {
		k.block = true
	}
	updates := make(chan []Candidate)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runEngine(ctx, engineConfig{
			dial:    fakeDialer(ctls),
			initial: []Candidate{v4a, v4b},
			updates: updates,
			sortFn:  func(cs []Candidate) []Candidate { return Sort(cs, false, 1) },
			delay:   80 * time.Millisecond,
		})
		close(done)
	}()

	waitClosed(t, ctls["v4a"].started, time.Second, "start of v4a")
	updates <- []Candidate{v4a, v4b, v6} // complete set, v6 new
	waitClosed(t, ctls["v6"].started, time.Second, "start of v6")
	select {
	case <-ctls["v4b"].started:
		t.Fatalf("v4b launched before v6: late v6 was not re-sorted ahead (family interleave)")
	default:
	}
	close(updates)
	cancel()
	waitClosed(t, done, time.Second, "engine return")
}

// §7: a candidate removed from the resolved set before launching is never
// dialed; an already-launched one is not cancelled.
func TestEngine_RemovalDropsUnlaunchedOnly(t *testing.T) {
	a, b := cand("a"), cand("b")
	ctls := map[string]*ctl{"a": newCtl(), "b": newCtl()}
	ctls["a"].block = true
	updates := make(chan []Candidate)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runEngine(ctx, engineConfig{
			dial:    fakeDialer(ctls),
			initial: []Candidate{a, b},
			updates: updates,
			delay:   time.Hour, // b can only launch via promotion — which must not happen
		})
		close(done)
	}()
	waitClosed(t, ctls["a"].started, time.Second, "start of a")
	updates <- []Candidate{a} // b removed before launch
	select {
	case <-ctls["a"].ctxCancelled:
		t.Fatalf("launched attempt a was cancelled by a DNS update (§7 forbids)")
	case <-time.After(50 * time.Millisecond):
	}
	close(updates)
	cancel()
	waitClosed(t, done, time.Second, "engine return")
	select {
	case <-ctls["b"].started:
		t.Fatalf("removed candidate b was dialed")
	default:
	}
}

// All attempts failed but updates remain open ⇒ the engine keeps waiting;
// a late update launches and can win. Then: updates closing with an empty
// table yields noCandsErr.
func TestEngine_WaitsOnOpenUpdatesAfterAllFail(t *testing.T) {
	a, b := cand("a"), cand("b")
	ctls := map[string]*ctl{"a": newCtl(), "b": newCtl()}
	ctls["a"].err = errors.New("down")
	ctls["b"].est = fakeEstablished(b)
	updates := make(chan []Candidate)

	done := make(chan struct{})
	var got *Established
	var err error
	go func() {
		got, err = runEngine(context.Background(), engineConfig{
			dial:    fakeDialer(ctls),
			initial: []Candidate{a},
			updates: updates,
			delay:   20 * time.Millisecond,
		})
		close(done)
	}()
	waitClosed(t, ctls["a"].started, time.Second, "start of a")
	time.Sleep(30 * time.Millisecond) // a has failed; engine must still be alive
	updates <- []Candidate{a, b}
	waitClosed(t, done, 2*time.Second, "engine return")
	if err != nil || got == nil || got.Cand.Label != "b" {
		t.Fatalf("got %+v err %v, want b to win from the late update", got, err)
	}
	// drain: channel stays open; engine already returned — close for hygiene.
	close(updates)
}

// Empty updates are tolerated (a late no-supported-ALPN record can revoke
// everything); the engine neither crashes nor treats it as terminal while
// the channel is open.
func TestEngine_EmptyUpdateTolerated(t *testing.T) {
	a := cand("a")
	ctls := map[string]*ctl{"a": newCtl()}
	ctls["a"].block = true
	updates := make(chan []Candidate)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runEngine(ctx, engineConfig{dial: fakeDialer(ctls),
			initial: []Candidate{a}, updates: updates, delay: 20 * time.Millisecond})
		close(done)
	}()
	waitClosed(t, ctls["a"].started, time.Second, "start of a")
	updates <- []Candidate{} // must not panic or cancel a
	select {
	case <-ctls["a"].ctxCancelled:
		t.Fatalf("empty update cancelled a launched attempt")
	case <-time.After(30 * time.Millisecond):
	}
	cancel()
	close(updates)
	waitClosed(t, done, time.Second, "engine return")
}

// F15: expansion must not block other candidates. A slow expander (200ms)
// must not delay the IP leg's launch (~0ms).
func TestEngine_SlowExpansionDoesNotBlockIPLaunch(t *testing.T) {
	proto := Candidate{Family: FamilySCION, IA: "1-150", Host: "10.0.0.1",
		Label: "scion:1-150,10.0.0.1"}
	ip := cand("v4")
	ctls := map[string]*ctl{"v4": newCtl(), "scion:1-150,10.0.0.1#p1": newCtl()}
	ctls["v4"].block = true
	ctls["scion:1-150,10.0.0.1#p1"].block = true

	expanded := proto
	expanded.Label = proto.Label + "#p1"
	expanded.Path = &SCIONPath{Latency: 5 * time.Millisecond}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	start := time.Now()
	go func() {
		runEngine(ctx, engineConfig{
			dial:    fakeDialer(ctls),
			initial: []Candidate{proto, ip},
			updates: make(chan []Candidate), // dynamic mode, never sends
			isProto: func(c Candidate) bool { return c.Family == FamilySCION && c.Path == nil && !c.ViaScitra },
			expand: func(ctx context.Context, c Candidate) []Candidate {
				time.Sleep(200 * time.Millisecond)
				return []Candidate{expanded}
			},
			delay: 20 * time.Millisecond,
		})
		close(done)
	}()

	waitClosed(t, ctls["v4"].started, time.Second, "start of v4")
	if d := time.Since(start); d > 150*time.Millisecond {
		t.Fatalf("v4 launched %v after start — it waited for SCION expansion (F15 regression)", d)
	}
	waitClosed(t, ctls["scion:1-150,10.0.0.1#p1"].started, time.Second, "start of expanded SCION leg")
	cancel()
	waitClosed(t, done, time.Second, "engine return")
}

// The family filter applies to RESOLVED candidates, not expanded children:
// under NoIP a SCION proto survives, and its scitra (FamilyIPv6) child must
// still race — the scitra leg is the SCION fallback, not an IP candidate
// (deleted expandAndSort's documented contract).
func TestEngine_FilterSparesExpandedScitraChild(t *testing.T) {
	proto := Candidate{Family: FamilySCION, IA: "1-150", Host: "10.0.0.1", Label: "scion:1-150,10.0.0.1"}
	scitra := Candidate{Family: FamilyIPv6, ViaScitra: true, Host: "fc00::1", Label: "scitra:1-150,fc00::1"}
	ctls := map[string]*ctl{scitra.Label: newCtl()}
	ctls[scitra.Label].est = fakeEstablished(scitra)

	got, err := runEngine(context.Background(), engineConfig{
		dial:    fakeDialer(ctls),
		initial: []Candidate{proto},
		updates: make(chan []Candidate),                                    // scitra child wins inline, so an open (never-closed) channel does not hang the engine
		filter:  func(c Candidate) bool { return c.Family == FamilySCION }, // NoIP semantics
		isProto: func(c Candidate) bool { return c.Family == FamilySCION && c.Path == nil && !c.ViaScitra },
		expand: func(ctx context.Context, c Candidate) []Candidate {
			return []Candidate{scitra}
		},
		delay: 20 * time.Millisecond,
	})
	if err != nil || got == nil || got.Cand.Label != scitra.Label {
		t.Fatalf("got %+v err %v: scitra child must survive the NoIP filter and win", got, err)
	}
}

// register sees the proto candidates in arrival order, before their
// expansions run, so the destination AS limit picks the first ASes of the
// list rather than the first lookups to run.
func TestEngine_RegisterInArrivalOrder(t *testing.T) {
	p1 := Candidate{Family: FamilySCION, IA: "1-152", Host: "10.0.0.1", Label: "scion:1-152,10.0.0.1"}
	p2 := Candidate{Family: FamilySCION, IA: "1-150", Host: "10.0.0.2", Label: "scion:1-150,10.0.0.2"}
	var got []string
	_, _ = runEngine(context.Background(), engineConfig{
		dial:     fakeDialer(nil),
		initial:  []Candidate{p1, p2},
		isProto:  func(c Candidate) bool { return c.Family == FamilySCION && c.Path == nil },
		register: func(c Candidate) { got = append(got, c.Label) },
		expand:   func(ctx context.Context, c Candidate) []Candidate { return nil },
		delay:    20 * time.Millisecond,
	})
	if !reflect.DeepEqual(got, []string{p1.Label, p2.Label}) {
		t.Fatalf("registered %v, want %v", got, []string{p1.Label, p2.Label})
	}
}

// Memoization: a proto label re-sent by every subsequent update expands
// exactly once (expandCached's replacement), and an expansion yielding
// nothing leaves the engine waiting rather than failing while updates are
// open.
func TestEngine_ExpansionMemoizedAcrossUpdates(t *testing.T) {
	proto := Candidate{Family: FamilySCION, IA: "1-150", Host: "10.0.0.1",
		Label: "scion:1-150,10.0.0.1"}
	var calls atomic.Int32
	updates := make(chan []Candidate)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runEngine(ctx, engineConfig{
			dial:    fakeDialer(map[string]*ctl{}),
			initial: []Candidate{proto},
			updates: updates,
			isProto: func(c Candidate) bool { return c.Family == FamilySCION && c.Path == nil && !c.ViaScitra },
			expand: func(ctx context.Context, c Candidate) []Candidate {
				calls.Add(1)
				return nil // daemonless drop
			},
			delay: 20 * time.Millisecond,
		})
		close(done)
	}()

	updates <- []Candidate{proto} // resolver re-sends the same set
	updates <- []Candidate{proto}
	time.Sleep(50 * time.Millisecond)
	if n := calls.Load(); n != 1 {
		t.Fatalf("expand called %d times for one proto label, want exactly 1", n)
	}
	cancel() // engine was correctly still waiting (empty table, updates open)
	close(updates)
	waitClosed(t, done, time.Second, "engine return")
}

// Watch-point (a)+(b) extended: an armed stagger timer can fire into
// launchNext's pending-empty guard (a §4.3 update tombstoned the only
// pending candidate first) and disarm without rearming. A *later* update
// that adds a fresh candidate while the sole in-flight attempt is still
// running must not be stranded until that attempt finishes — the stagger
// clock must resume so the new candidate launches within one normal
// interval, not indefinitely.
func TestEngine_LateAddResumesStaggerAfterTimerFiredEmpty(t *testing.T) {
	a, b, c := cand("a"), cand("b"), cand("c")
	ctls := map[string]*ctl{"a": newCtl(), "b": newCtl(), "c": newCtl()}
	ctls["a"].block = true
	ctls["b"].block = true
	ctls["c"].block = true
	updates := make(chan []Candidate)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runEngine(ctx, engineConfig{
			dial:    fakeDialer(ctls),
			initial: []Candidate{a, b},
			updates: updates,
			delay:   30 * time.Millisecond,
		})
		close(done)
	}()

	waitClosed(t, ctls["a"].started, time.Second, "start of a")
	updates <- []Candidate{a} // b removed before its stagger fires: pending -> empty
	// Let the 30ms timer fire on the now-empty pending (disarm-and-no-op).
	time.Sleep(80 * time.Millisecond)
	select {
	case <-ctls["b"].started:
		t.Fatalf("removed candidate b was dialed")
	default:
	}
	updates <- []Candidate{a, c} // a still in flight; c is new
	select {
	case <-ctls["c"].started:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("c not launched within one stagger interval of being added, though a is still in flight — stranded by the disarmed timer")
	}
	close(updates)
	cancel()
	waitClosed(t, done, time.Second, "engine return")
}

// §6 MUST: an explicit sub-10ms max-attempt-delay cannot drag the stagger
// below the 10ms floor.
func TestEngine_MaxDelayCannotDefeatFloor(t *testing.T) {
	a, b := cand("a"), cand("b")
	ctls := map[string]*ctl{"a": newCtl(), "b": newCtl()}
	ctls["a"].block, ctls["b"].block = true, true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runEngine(ctx, engineConfig{dial: fakeDialer(ctls),
			initial: []Candidate{a, b}, delay: 250 * time.Millisecond, maxDelay: 5 * time.Millisecond})
		close(done)
	}()
	waitClosed(t, ctls["a"].started, time.Second, "start of a")
	waitClosed(t, ctls["b"].started, time.Second, "start of b")
	if gap := ctls["b"].startedAt.Sub(ctls["a"].startedAt); gap < 10*time.Millisecond-2*time.Millisecond {
		t.Fatalf("gap %v: sub-10ms maxDelay defeated the MUST floor", gap)
	}
	cancel()
	waitClosed(t, done, time.Second, "engine return")
}

// SCION grace: with grace enabled and a proto expanding, the IP leg is
// held until expansion completes; the SCION child then launches first.
func TestEngine_ExpansionDelayHoldsIPUntilExpansion(t *testing.T) {
	proto := Candidate{Family: FamilySCION, IA: "1-150", Host: "10.0.0.1", Label: "scion:1-150,10.0.0.1"}
	child := proto
	child.Label = proto.Label + "#paths"
	child.Path = &SCIONPath{Latency: 2 * time.Millisecond}
	ip := cand("v4")
	ctls := map[string]*ctl{child.Label: newCtl(), "v4": newCtl()}
	ctls[child.Label].block, ctls["v4"].block = true, true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runEngine(ctx, engineConfig{
			dial:    fakeDialer(ctls),
			initial: []Candidate{proto, ip},
			updates: make(chan []Candidate),
			isProto: func(c Candidate) bool { return c.Family == FamilySCION && c.Path == nil && !c.ViaScitra },
			expand: func(ctx context.Context, c Candidate) []Candidate {
				time.Sleep(80 * time.Millisecond)
				return []Candidate{child}
			},
			sortFn:     func(cs []Candidate) []Candidate { return Sort(cs, hasSCION(cs), 1) },
			delay:      30 * time.Millisecond,
			lookupWait: 500 * time.Millisecond,
		})
		close(done)
	}()

	waitClosed(t, ctls[child.Label].started, time.Second, "start of SCION child")
	select {
	case <-ctls["v4"].started:
		t.Fatalf("v4 launched before the SCION child: grace hold not applied")
	default:
	}
	waitClosed(t, ctls["v4"].started, time.Second, "start of v4 (post-child stagger)")
	if gap := ctls["v4"].startedAt.Sub(ctls[child.Label].startedAt); gap < 25*time.Millisecond {
		t.Fatalf("v4 started %v after the SCION child, want >= ~30ms stagger", gap)
	}
	cancel()
	waitClosed(t, done, time.Second, "engine return")
}

// Grace expiry releases the hold even while expansion is still running.
func TestEngine_ExpansionDelayExpiryReleasesHold(t *testing.T) {
	proto := Candidate{Family: FamilySCION, IA: "1-150", Host: "10.0.0.1", Label: "scion:1-150,10.0.0.1"}
	ip := cand("v4")
	ctls := map[string]*ctl{"v4": newCtl()}
	ctls["v4"].block = true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	start := time.Now()
	go func() {
		runEngine(ctx, engineConfig{
			dial:    fakeDialer(ctls),
			initial: []Candidate{proto, ip},
			updates: make(chan []Candidate),
			isProto: func(c Candidate) bool { return c.Family == FamilySCION && c.Path == nil && !c.ViaScitra },
			expand: func(ctx context.Context, c Candidate) []Candidate {
				time.Sleep(400 * time.Millisecond) // far beyond the grace
				return nil
			},
			delay:      20 * time.Millisecond,
			lookupWait: 60 * time.Millisecond,
		})
		close(done)
	}()

	waitClosed(t, ctls["v4"].started, time.Second, "start of v4")
	held := time.Since(start)
	if held < 55*time.Millisecond {
		t.Fatalf("v4 started after %v, want the ~60ms grace to have been honored", held)
	}
	if held > 250*time.Millisecond {
		t.Fatalf("v4 started after %v: hold outlasted the 60ms grace", held)
	}
	cancel()
	waitClosed(t, done, time.Second, "engine return")
}

// A dropped expansion (no children) releases the hold immediately — long
// before the grace would expire.
func TestEngine_ExpansionDelayEmptyExpansionReleasesImmediately(t *testing.T) {
	proto := Candidate{Family: FamilySCION, IA: "1-150", Host: "10.0.0.1", Label: "scion:1-150,10.0.0.1"}
	ip := cand("v4")
	ctls := map[string]*ctl{"v4": newCtl()}
	ctls["v4"].block = true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	start := time.Now()
	go func() {
		runEngine(ctx, engineConfig{
			dial:    fakeDialer(ctls),
			initial: []Candidate{proto, ip},
			updates: make(chan []Candidate),
			isProto: func(c Candidate) bool { return c.Family == FamilySCION && c.Path == nil && !c.ViaScitra },
			expand: func(ctx context.Context, c Candidate) []Candidate {
				time.Sleep(30 * time.Millisecond)
				return nil // daemonless drop
			},
			delay:      20 * time.Millisecond,
			lookupWait: 2 * time.Second,
		})
		close(done)
	}()

	waitClosed(t, ctls["v4"].started, time.Second, "start of v4")
	if held := time.Since(start); held > 300*time.Millisecond {
		t.Fatalf("v4 started after %v: empty expansion must release the hold at ~30ms, not the 2s grace", held)
	}
	cancel()
	waitClosed(t, done, time.Second, "engine return")
}

// Grace with no protos at all is inert: the IP leg launches immediately.
func TestEngine_ExpansionDelayInertWithoutProtos(t *testing.T) {
	ip := cand("v4")
	ctls := map[string]*ctl{"v4": newCtl()}
	ctls["v4"].block = true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	start := time.Now()
	go func() {
		runEngine(ctx, engineConfig{
			dial:       fakeDialer(ctls),
			initial:    []Candidate{ip},
			lookupWait: time.Second,
			delay:      20 * time.Millisecond,
		})
		close(done)
	}()
	waitClosed(t, ctls["v4"].started, time.Second, "start of v4")
	if held := time.Since(start); held > 200*time.Millisecond {
		t.Fatalf("v4 started after %v: grace must be inert with no expanding protos", held)
	}
	cancel()
	waitClosed(t, done, time.Second, "engine return")
}

// Edge (beyond the brief): the updates channel closing while the grace gate is
// holding must not strand the held IP leg. During the hold nothing is in flight
// and no stagger timer is armed; closing updates flips updatesOpen false but
// cannot trip the terminal condition (pending is non-empty), and the grace
// timer remains the backstop that fires to release the hold.
func TestEngine_ExpansionDelayUpdatesCloseDuringHold(t *testing.T) {
	proto := Candidate{Family: FamilySCION, IA: "1-150", Host: "10.0.0.1", Label: "scion:1-150,10.0.0.1"}
	ip := cand("v4")
	ctls := map[string]*ctl{"v4": newCtl()}
	ctls["v4"].block = true
	updates := make(chan []Candidate)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	start := time.Now()
	go func() {
		runEngine(ctx, engineConfig{
			dial:    fakeDialer(ctls),
			initial: []Candidate{proto, ip},
			updates: updates,
			isProto: func(c Candidate) bool { return c.Family == FamilySCION && c.Path == nil && !c.ViaScitra },
			expand: func(ctx context.Context, c Candidate) []Candidate {
				time.Sleep(400 * time.Millisecond) // outlives the grace
				return nil
			},
			delay:      20 * time.Millisecond,
			lookupWait: 60 * time.Millisecond,
		})
		close(done)
	}()

	close(updates) // sources close while the gate is still holding
	waitClosed(t, ctls["v4"].started, time.Second, "start of v4")
	held := time.Since(start)
	if held < 55*time.Millisecond {
		t.Fatalf("v4 started after %v, want the ~60ms grace honored despite updates closing mid-hold", held)
	}
	if held > 250*time.Millisecond {
		t.Fatalf("v4 started after %v: grace timer failed to release the hold after updates closed", held)
	}
	cancel()
	waitClosed(t, done, time.Second, "engine return")
}

// The adaptive shortcut never LENGTHENS the stagger: base 80ms with the
// default 100ms adaptive floor must still fire at <=80ms.
func TestEngine_AdaptiveNeverExceedsBase(t *testing.T) {
	sc := Candidate{Family: FamilySCION, Host: "10.0.0.1", IA: "1-150",
		Label: "scion:1-150,10.0.0.1#p1", Path: &SCIONPath{Latency: time.Millisecond}}
	ip := cand("v4")
	ctls := map[string]*ctl{sc.Label: newCtl(), "v4": newCtl()}
	ctls[sc.Label].block, ctls["v4"].block = true, true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runEngine(ctx, engineConfig{dial: fakeDialer(ctls),
			initial: []Candidate{sc, ip}, delay: 80 * time.Millisecond, adaptive: true})
		close(done)
	}()
	waitClosed(t, ctls[sc.Label].started, time.Second, "start of scion")
	waitClosed(t, ctls["v4"].started, time.Second, "start of v4")
	if gap := ctls["v4"].startedAt.Sub(ctls[sc.Label].startedAt); gap > 95*time.Millisecond {
		t.Fatalf("gap %v: adaptive floor (100ms default) exceeded the 80ms base", gap)
	}
	cancel()
	waitClosed(t, done, time.Second, "engine return")
}

// When an attempt to a SCION endpoint fails, the next attempt starts
// without waiting for the Connection Attempt Delay, but not within 10 ms of
// the start of the failed one.
func TestEngine_SCIONFailureAdvancesAfterFloor(t *testing.T) {
	sc := Candidate{Family: FamilySCION, Host: "10.0.0.1", IA: "1-150",
		Label: "scion:1-150,10.0.0.1#paths", Path: &SCIONPath{Hops: 2}}
	ip := cand("v4")
	ctls := map[string]*ctl{sc.Label: newCtl(), "v4": newCtl()}
	ctls[sc.Label].err = errAllPathsFailed // fails at once
	ctls["v4"].block = true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runEngine(ctx, engineConfig{
			dial:     fakeDialer(ctls),
			initial:  []Candidate{sc, ip},
			delay:    time.Second,
			minDelay: 80 * time.Millisecond,
		})
		close(done)
	}()
	waitClosed(t, ctls[sc.Label].started, time.Second, "start of scion")
	waitClosed(t, ctls["v4"].started, time.Second, "start of v4")
	gap := ctls["v4"].startedAt.Sub(ctls[sc.Label].startedAt)
	if gap < 9*time.Millisecond {
		t.Fatalf("v4 started %v after the failed SCION attempt, want >= 10ms", gap)
	}
	if gap > 500*time.Millisecond {
		t.Fatalf("v4 started %v after the failed SCION attempt: waited for the 1s attempt delay", gap)
	}
	cancel()
	waitClosed(t, done, time.Second, "engine return")
}

// A SCION endpoint with no eligible path at attempt time is skipped: the
// next endpoint is attempted at once, not 10 ms later.
func TestEngine_NoEligiblePathAdvancesAtOnce(t *testing.T) {
	sc := Candidate{Family: FamilySCION, Host: "10.0.0.1", IA: "1-150",
		Label: "scion:1-150,10.0.0.1#paths", Path: &SCIONPath{Hops: 2}}
	ctls := map[string]*ctl{sc.Label: newCtl(), "v4": newCtl()}
	ctls[sc.Label].err = fmt.Errorf("dial: %w", errNoEligiblePath)
	ctls["v4"].block = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runEngine(ctx, engineConfig{dial: fakeDialer(ctls), initial: []Candidate{sc, cand("v4")}, delay: time.Second})
		close(done)
	}()
	waitClosed(t, ctls["v4"].started, time.Second, "start of v4")
	if gap := ctls["v4"].startedAt.Sub(ctls[sc.Label].startedAt); gap > 8*time.Millisecond {
		t.Fatalf("v4 started %v after the skipped SCION endpoint, want at once", gap)
	}
	cancel()
	waitClosed(t, done, time.Second, "engine return")
}

// No attempt starts within 10 ms of the start of an attempt over a
// candidate path of a SCION endpoint: the endpoint's second path attempt
// starts 30 ms in, the endpoint fails 35 ms in, the next attempt starts
// 40 ms in.
func TestEngine_FloorCountsPathAttempts(t *testing.T) {
	sc := Candidate{Family: FamilySCION, Host: "10.0.0.1", IA: "1-150",
		Label: "scion:1-150,10.0.0.1#paths", Path: &SCIONPath{Hops: 2}}
	v4 := newCtl()
	v4.block = true
	var scStart, pathStart time.Time
	scStarted := make(chan struct{})
	dial := func(ctx context.Context, c Candidate) (*Established, error) {
		if c.Label != sc.Label {
			return fakeDialer(map[string]*ctl{"v4": v4})(ctx, c)
		}
		scStart = time.Now()
		time.Sleep(30 * time.Millisecond)
		pathStart = time.Now()
		pathStartHookFrom(ctx)(pathStart)
		time.Sleep(5 * time.Millisecond)
		close(scStarted)
		return nil, errAllAttemptsFailed
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runEngine(ctx, engineConfig{dial: dial, initial: []Candidate{sc, cand("v4")}, delay: time.Second})
		close(done)
	}()
	waitClosed(t, v4.started, time.Second, "start of v4")
	<-scStarted
	if gap := v4.startedAt.Sub(pathStart); gap < 9500*time.Microsecond || gap > 60*time.Millisecond {
		t.Fatalf("v4 started %v after the last path attempt (%v after the endpoint), want ~10ms", gap, v4.startedAt.Sub(scStart))
	}
	cancel()
	waitClosed(t, done, time.Second, "engine return")
}

// A path lookup is waited for no longer than the Resolution Delay after
// the first positive IP answer: if that passed before the IP endpoint was
// due, the IP attempt starts at once.
func TestEngine_LookupWaitCountsFromFirstIPAnswer(t *testing.T) {
	for _, tc := range []struct {
		name     string
		answered time.Duration // how long ago the first IP answer arrived
		min, max time.Duration
	}{
		{"just answered", 0, 50 * time.Millisecond, 150 * time.Millisecond},
		{"answered 40ms ago", 40 * time.Millisecond, 10 * time.Millisecond, 45 * time.Millisecond},
		{"answered long ago", time.Second, 0, 15 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proto := Candidate{Family: FamilySCION, IA: "1-150", Host: "10.0.0.1", Label: "scion:1-150,10.0.0.1"}
			ctls := map[string]*ctl{"v4": newCtl()}
			ctls["v4"].block = true
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			start := time.Now()
			at := start.Add(-tc.answered)
			done := make(chan struct{})
			go func() {
				runEngine(ctx, engineConfig{
					dial: fakeDialer(ctls), initial: []Candidate{proto, cand("v4")},
					updates: make(chan []Candidate),
					isProto: func(c Candidate) bool { return c.Family == FamilySCION && c.Path == nil },
					expand: func(ctx context.Context, c Candidate) []Candidate {
						select {
						case <-time.After(time.Second):
						case <-ctx.Done():
						}
						return nil
					},
					sortFn:     func(cs []Candidate) []Candidate { return Sort(cs, true, 1) },
					delay:      time.Second,
					lookupWait: 60 * time.Millisecond,
					ipAnswerAt: func() time.Time { return at },
				})
				close(done)
			}()
			waitClosed(t, ctls["v4"].started, time.Second, "start of v4")
			if w := ctls["v4"].startedAt.Sub(start); w < tc.min || w > tc.max {
				t.Fatalf("v4 started after %v, want within [%v, %v]", w, tc.min, tc.max)
			}
			cancel()
			waitClosed(t, done, time.Second, "engine return")
		})
	}
}
