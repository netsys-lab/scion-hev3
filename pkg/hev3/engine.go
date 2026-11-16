package hev3

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// This file is the §4-§7 connection engine: a single goroutine owning a
// candidate table, a sorted pending list, and the attempt scheduler.
// Race (race.go) is a thin static-set wrapper; Fetch (hev3.go) feeds it
// resolver updates and async SCION expansion into the running race.

const (
	// minAttemptDelayFloor is the draft §6 MUST: implementations must not
	// start connection attempts less than 10ms apart.
	minAttemptDelayFloor = 10 * time.Millisecond
	// defaultMinAttemptDelay is the floor applied to the adaptive SCION
	// shortcut when RaceOptions.MinAttemptDelay is left zero.
	defaultMinAttemptDelay = 100 * time.Millisecond
	// defaultMaxAttemptDelay caps every stagger (base or adaptive) when
	// RaceOptions.MaxAttemptDelay is left zero.
	defaultMaxAttemptDelay = 2 * time.Second
)

// engineConfig drives one runEngine call. Zero-value fields disable their
// feature: nil updates ⇒ static set; nil sortFn ⇒ table insertion order;
// nil filter ⇒ accept all; nil isProto/expand ⇒ no expansion interception.
type engineConfig struct {
	dial    DialFunc
	initial []Candidate
	updates <-chan []Candidate
	sortFn  func([]Candidate) []Candidate
	filter  func(Candidate) bool
	isProto func(Candidate) bool
	expand  func(context.Context, Candidate) []Candidate
	// register, if set, is called for each proto candidate in the order the
	// candidates arrive, before its expansion starts.
	register func(Candidate)
	delay    time.Duration // effective base stagger (defaulted here if <= 0)
	minDelay time.Duration // adaptive-shortcut floor (defaulted/hard-floored here if <= 0)
	maxDelay time.Duration // cap on the base stagger (defaulted here if <= 0)
	adaptive bool          // enables the SCION path-latency shortcut in nextDelay (not in the draft; opt-in)
	// lookupWait: the first attempt to an IP endpoint is not started while
	// the path lookup of a SCION endpoint that would precede it is in
	// progress, until lookupWait (the Resolution Delay) after the first
	// positive IP answer; <= 0 = lookups are not waited for.
	lookupWait time.Duration
	// ipAnswerAt reports when the first positive IP answer arrived (zero =
	// none yet); nil or zero => the time the engine first saw an IP endpoint.
	ipAnswerAt func() time.Time
	tl         *Timeline
	noCandsErr error // returned when every source closes with nothing to try
}

type candStatus int

const (
	candNew candStatus = iota
	candInflight
	candFailed
	candDone      // received a result that won or lost after success
	candExpanding // proto candidate handed to the expander
	candExpanded  // proto candidate whose children are in the table
)

type tableEntry struct {
	cand   Candidate
	status candStatus
	parent string // proto label this entry was expanded from; "" otherwise
	err    error
	cancel context.CancelFunc
}

// attemptResult carries one finished dial back to the engine loop.
type attemptResult struct {
	label string
	est   *Established
	err   error
}

// expandResult carries one finished proto expansion back to the engine loop:
// the parent proto label and the dialable children it produced (possibly
// none, e.g. a daemonless drop).
type expandResult struct {
	parent string
	cands  []Candidate
}

type engine struct {
	cfg           engineConfig
	table         map[string]*tableEntry
	order         []string // label insertion order — the stable base for sorting
	pending       []string // labels not yet launched, in racing order
	results       chan attemptResult
	expandResults chan expandResult // proto expansions complete here
	expandCtx     context.Context   // scoped to the loop's lifetime; expander goroutines dial against it and are cancelled when loop returns

	inflight     int
	lastLaunched string
	updatesOpen  bool
	expanding    int // proto candidates handed to the expander, not yet returned

	graceArmed bool // the lookup-wait timer has been Reset and not yet fired/drained
	graceOver  bool // the lookup wait has ended - one-way; holdForGrace is inert thereafter
	heldDue    bool // launchNext held the pending head: it is due as soon as the hold ends
	ipLaunched bool // an attempt to an IP endpoint has started (lookups are waited for only before the first)
	ipSeen     time.Time
	lastStart  time.Time
	prevStart  time.Time // lastStart before the most recent launch
	// clock is the start of the most recent connection attempt, counting
	// each attempt over a candidate path of a SCION endpoint. The engine and
	// the SCION dials both start attempts only through it.
	clock     attemptClock
	clockAt   time.Time // the clock's reservation for the most recent launch
	clockPrev time.Time // clock before that reservation
}

// attemptClock keeps the start of the most recent connection attempt so
// that no two attempts start less than minAttemptDelayFloor apart, whether
// they are attempts to endpoints started by the engine or attempts over the
// further candidate paths of a SCION endpoint started by its dial.
type attemptClock struct {
	mu   sync.Mutex
	last time.Time
}

// reserve records now as the start of an attempt and returns 0, or, if an
// attempt started less than minAttemptDelayFloor ago, returns how long to
// wait before trying again.
func (c *attemptClock) reserve() time.Duration {
	_, _, wait := c.reserveAt()
	return wait
}

// reserveAt is reserve that also returns the reserved time and the start
// time before it, for undo.
func (c *attemptClock) reserveAt() (at, prev time.Time, wait time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if !c.last.IsZero() {
		if wait = minAttemptDelayFloor - now.Sub(c.last); wait > 0 {
			return time.Time{}, c.last, wait
		}
	}
	prev, c.last = c.last, now
	return now, prev, 0
}

// record notes an attempt that started at t.
func (c *attemptClock) record(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t.After(c.last) {
		c.last = t
	}
}

// undo takes back the reservation made at at, restoring prev, unless an
// attempt started after it.
func (c *attemptClock) undo(at, prev time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last.Equal(at) {
		c.last = prev
	}
}

// lookupDeadline is when waiting for path lookups ends: lookupWait after
// the first positive IP answer.
func (e *engine) lookupDeadline() time.Time {
	t := e.ipSeen
	if e.cfg.ipAnswerAt != nil {
		if a := e.cfg.ipAnswerAt(); !a.IsZero() && (t.IsZero() || a.Before(t)) {
			t = a
		}
	}
	if t.IsZero() {
		t = time.Now()
	}
	return t.Add(e.cfg.lookupWait)
}

// holdForGrace implements the wait for path lookups
// (draft-john-scion-happy-eyeballs, "SCION Endpoints"): when the first
// attempt to an IP endpoint would start and a path lookup is in progress
// for a SCION endpoint that would precede it in the sorted list, hold it,
// no longer than the Resolution Delay after the first positive IP answer.
// Completion of those lookups ends the hold (holdForGrace turns false once
// e.expanding drops or no expanding endpoint precedes the head).
func (e *engine) holdForGrace(lbl string) bool {
	if e.cfg.lookupWait <= 0 || e.graceOver || e.ipLaunched || e.expanding == 0 {
		return false
	}
	head := e.table[lbl].cand
	if head.Family == FamilySCION {
		return false
	}
	if !time.Now().Before(e.lookupDeadline()) {
		e.graceOver = true
		return false
	}
	return e.expandingPrecedes(head)
}

// expandingPrecedes reports whether an endpoint whose path lookup is in
// progress sorts before head when sorted together with the live candidates.
func (e *engine) expandingPrecedes(head Candidate) bool {
	if e.cfg.sortFn == nil {
		return true
	}
	list := e.liveCandidates()
	for _, lbl := range e.order {
		if ent := e.table[lbl]; ent.status == candExpanding {
			list = append(list, ent.cand)
		}
	}
	for _, c := range e.cfg.sortFn(list) {
		if c.Label == head.Label {
			return false
		}
		if e.table[c.Label].status == candExpanding {
			return true
		}
	}
	return false
}

func runEngine(ctx context.Context, cfg engineConfig) (*Established, error) {
	if cfg.delay <= 0 {
		cfg.delay = defaultAttemptDelay
	}
	if cfg.minDelay <= 0 {
		cfg.minDelay = defaultMinAttemptDelay
	}
	if cfg.minDelay < minAttemptDelayFloor {
		cfg.minDelay = minAttemptDelayFloor
	}
	if cfg.maxDelay <= 0 {
		cfg.maxDelay = defaultMaxAttemptDelay
	}
	if cfg.maxDelay < minAttemptDelayFloor {
		cfg.maxDelay = minAttemptDelayFloor // draft §6 MUST: an explicit sub-10ms cap cannot defeat the floor
	}
	if cfg.delay < minAttemptDelayFloor {
		cfg.delay = minAttemptDelayFloor // draft §6 MUST: never within 10ms
	}
	if cfg.delay > cfg.maxDelay {
		cfg.delay = cfg.maxDelay
	}
	e := &engine{
		cfg:           cfg,
		table:         map[string]*tableEntry{},
		results:       make(chan attemptResult, 64),
		expandResults: make(chan expandResult, 8),
		updatesOpen:   cfg.updates != nil,
	}
	// ingest(cfg.initial) is deferred into loop (after e.expandCtx is set) so
	// proto candidates in the initial set spawn their expander goroutines with
	// the loop ctx rather than a not-yet-known one.
	return e.loop(ctx)
}

// ingest merges one complete candidate set into the table (§4.3/§7): new
// labels are added, known labels keep their status, and — in dynamic mode —
// labels missing from the set that were never launched are removed (§7:
// started attempts are never cancelled by a DNS change). Expanded children
// follow their parent proto label's membership.
func (e *engine) ingest(set []Candidate) {
	seen := map[string]bool{}
	for _, c := range set {
		if e.cfg.filter != nil && !e.cfg.filter(c) {
			continue
		}
		seen[c.Label] = true
		if _, ok := e.table[c.Label]; ok {
			continue
		}
		if e.cfg.isProto != nil && e.cfg.isProto(c) {
			// Proto candidate: hand it to the expander instead of dialing it.
			// The table entry (candExpanding) both memoizes the label — a
			// re-send by a later update finds it here and never re-expands
			// (the expandCached guarantee, keeping Timeline drop-notes single)
			// — and lets §7 child-removal test the parent's set membership.
			e.table[c.Label] = &tableEntry{cand: c, status: candExpanding}
			e.order = append(e.order, c.Label)
			e.expanding++
			if e.cfg.register != nil {
				e.cfg.register(c)
			}
			proto := c
			go func() {
				cands := e.cfg.expand(e.expandCtx, proto)
				select {
				case e.expandResults <- expandResult{proto.Label, cands}:
				case <-e.expandCtx.Done():
				}
			}()
			continue
		}
		if c.Family != FamilySCION && e.ipSeen.IsZero() {
			e.ipSeen = time.Now()
		}
		e.table[c.Label] = &tableEntry{cand: c, status: candNew}
		e.order = append(e.order, c.Label)
	}
	if e.cfg.updates != nil { // dynamic mode: §7 removal of unlaunched entries
		// An EMPTY update set (seen == {}) legitimately tombstones every
		// unlaunched candidate — a late no-supported-ALPN record can revoke
		// the whole set (draft §6.2). This is more §7-correct than the old
		// mergeResolved, which ignored empty updates outright; deliberate.
		// Tombstones are permanent within a run: a label already in e.table
		// is always skipped above (the `if _, ok := e.table[c.Label]; ok`
		// check), so a candDone entry never comes back even if a later
		// update re-adds its label — deliberate, DNS flapping within one
		// Fetch is not re-raced. A re-added proto parent likewise never
		// re-expands, so it cannot resurrect children tombstoned while it
		// was briefly missing.
		for _, lbl := range e.order {
			ent := e.table[lbl]
			if ent.status != candNew {
				continue
			}
			member := seen[lbl]
			if ent.parent != "" {
				member = seen[ent.parent] // children follow their proto parent
			}
			if !member {
				ent.status = candDone // tombstone: never launched, never will be
			}
		}
	}
	e.resort()
}

// resort rebuilds pending: the sort function sees the COMPLETE current
// candidate list (all live statuses) so a late arrival is positioned as if
// it had been present from the start (§7); pending is then the sorted order
// minus everything already launched.
func (e *engine) resort() {
	live := e.liveCandidates()
	if e.cfg.sortFn != nil {
		live = e.cfg.sortFn(live)
	}
	e.pending = e.pending[:0]
	for _, c := range live {
		if e.table[c.Label].status == candNew {
			e.pending = append(e.pending, c.Label)
		}
	}
}

// liveCandidates lists every candidate that is or was dialable (all live
// statuses), excluding proto placeholders and Sec 7 tombstones.
func (e *engine) liveCandidates() []Candidate {
	live := make([]Candidate, 0, len(e.order))
	for _, lbl := range e.order {
		ent := e.table[lbl]
		if ent.status == candExpanding || ent.status == candExpanded {
			continue // proto parents are placeholders, not dialable
		}
		if ent.status == candDone && ent.cancel == nil && ent.err == nil {
			continue // §7 tombstone
		}
		live = append(live, ent.cand)
	}
	return live
}

func (e *engine) launch(ctx context.Context, lbl string) {
	ent := e.table[lbl]
	cctx, cancel := context.WithCancel(ctx)
	ent.status = candInflight
	ent.cancel = cancel
	e.inflight++
	e.lastLaunched = lbl
	e.prevStart = e.lastStart
	e.lastStart = time.Now()
	if ent.cand.Family != FamilySCION {
		e.ipLaunched = true
	}
	if e.cfg.tl != nil {
		e.cfg.tl.Add("attempt", lbl, "")
	}
	c := ent.cand
	// The dialer sees the Connection Attempt Delay in use, so a racing
	// SCION attempt can fit its path set into it.
	cctx = withAttemptDelay(cctx, e.nextDelay(c))
	// A SCION dial reports the start of each attempt over a candidate path,
	// and starts an attempt over a further path only through the shared
	// clock: no two attempts start within minAttemptDelayFloor.
	cctx = withPathStartHook(cctx, e.clock.record)
	cctx = withPathAttemptGate(cctx, e.clock.reserve)
	go func() {
		est, err := e.cfg.dial(cctx, c)
		e.results <- attemptResult{c.Label, est, err}
	}()
}

// nextDelay computes the stagger armed after launching c: the base delay,
// tightened for a SCION candidate with known path latency to
// clamp(2·Latency+60ms, minDelay, base) — the §6 "nuanced implementation"
// driven by the path metadata we already carry (F13). The result always
// lands in [10ms, base]: the adaptive shortcut can only shorten the base
// stagger, never lengthen it, so a non-SCION or non-adaptive candidate gets
// the base delay back unchanged, and a misconfigured minDelay (above base,
// or above maxDelay) can't drag the next attempt out past base either — the
// final re-cap at e.cfg.delay (itself already hard-floored at 10ms and
// capped at maxDelay in runEngine's defaulting) guarantees both ends.
func (e *engine) nextDelay(c Candidate) time.Duration {
	d := e.cfg.delay
	if e.cfg.adaptive && c.Family == FamilySCION && c.Path != nil && c.Path.Latency > 0 {
		if a := 2*c.Path.Latency + 60*time.Millisecond; a < d {
			d = a
			if d < e.cfg.minDelay {
				d = e.cfg.minDelay
			}
		}
	}
	if d > e.cfg.delay {
		d = e.cfg.delay
	}
	return d
}

// sourcesDone reports whether no further candidates can ever arrive.
func (e *engine) sourcesDone() bool {
	return !e.updatesOpen && e.expanding == 0
}

func (e *engine) loop(ctx context.Context) (*Established, error) {
	ectx, ecancel := context.WithCancel(ctx)
	defer ecancel()
	e.expandCtx = ectx // expander goroutines spawned by ingest dial against this;
	// cancelled the instant loop returns (any path — success, ctx.Done, or
	// terminal failure), so an expander can never outlive the engine: it
	// can neither block writing to the (buffer-8) expandResults channel
	// after nothing is left to read it, nor keep doing expansion work once
	// the race is already decided.
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	timerArmed := false
	arm := func(d time.Duration) {
		if timerArmed {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		timer.Reset(d)
		timerArmed = true
	}
	disarm := func() {
		if timerArmed && !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timerArmed = false
	}
	defer timer.Stop()

	// graceTimer backs the optional Expansion Delay hold (cfg.expansionDelay): while a
	// proto expansion is in flight the gate holds non-SCION launches, and this
	// timer is the backstop that releases them if expansion outlasts the grace.
	// Same disarmed-start / drain discipline as the stagger timer above.
	graceTimer := time.NewTimer(time.Hour)
	if !graceTimer.Stop() {
		<-graceTimer.C
	}
	defer graceTimer.Stop()
	// graceDisarm stops and drains the grace timer (mirrors disarm). Used when
	// expansion completes before the grace expires, so a stale tick never fires
	// into the select after graceOver is already latched.
	graceDisarm := func() {
		if e.graceArmed && !graceTimer.Stop() {
			select {
			case <-graceTimer.C:
			default:
			}
		}
		e.graceArmed = false
	}

	// launchNext starts the pending head, arming the stagger for the one
	// after it. No-op when nothing is pending.
	launchNext := func() {
		if len(e.pending) == 0 {
			disarm()
			e.heldDue = false
			return
		}
		if e.holdForGrace(e.pending[0]) {
			// Expansion Delay hold: the head is a non-SCION leg and a proto is
			// still expanding. Keep it in pending (do not pop), arm the grace
			// timer once, and leave the stagger disarmed. The release paths —
			// expansion completing (expandResults) or the grace expiring
			// (graceTimer.C) — resume launching through this same closure.
			if !e.graceArmed {
				graceTimer.Reset(time.Until(e.lookupDeadline()))
				e.graceArmed = true
			}
			e.heldDue = true
			return
		}
		e.heldDue = false
		// No attempt starts within 10 ms of the previous one, also counting
		// the attempts over the paths of a SCION endpoint.
		at, prev, wait := e.clock.reserveAt()
		if wait > 0 {
			arm(wait)
			return
		}
		e.clockAt, e.clockPrev = at, prev
		lbl := e.pending[0]
		e.pending = e.pending[1:]
		e.launch(ctx, lbl)
		if len(e.pending) > 0 {
			arm(e.nextDelay(e.table[lbl].cand))
		} else {
			disarm()
		}
	}

	// rearm sets the stagger for candidates that entered pending while no
	// stagger was running: the next attempt starts when the timer set by
	// the most recent attempt would have fired, or at once if that has
	// passed.
	rearm := func() {
		if d := e.nextDelay(e.table[e.lastLaunched].cand) - time.Since(e.lastStart); d > 0 {
			arm(d)
		} else {
			launchNext()
		}
	}

	// finish tears down after a winner: cancel in-flight, drain stragglers.
	finish := func(winner attemptResult) *Established {
		if e.cfg.tl != nil {
			e.cfg.tl.Add("success", winner.label, "")
			e.cfg.tl.Add("winner", winner.label, "")
		}
		winnerCancel := e.table[winner.label].cancel
		for _, lbl := range e.order {
			ent := e.table[lbl]
			if ent.status == candInflight && lbl != winner.label {
				ent.cancel()
				if e.cfg.tl != nil {
					e.cfg.tl.Add("cancel", lbl, "")
				}
			}
		}
		if e.inflight > 0 {
			go drainClose(e.results, e.inflight)
		}
		return withCancelOnClose(winner.est, winnerCancel)
	}

	// Initial ingest happens here (not in runEngine) so proto candidates spawn
	// their expanders with e.expandCtx already set to the loop ctx above.
	e.ingest(e.cfg.initial)

	if len(e.pending) > 0 {
		launchNext()
	}

	for {
		// Terminal condition: nothing running, nothing runnable, nothing
		// coming. Success returns happen inline below.
		if e.inflight == 0 && len(e.pending) == 0 && e.sourcesDone() {
			return nil, e.failure()
		}

		select {
		case <-ctx.Done():
			// Abort: cancel every in-flight attempt, then drain their
			// results so no attempt goroutine blocks writing to the buffered
			// channel (the buffer is a fixed 64, but in-flight can exceed it
			// in dynamic mode) and any straggler that succeeded despite the
			// cancel is Closed rather than leaked. Counts match exactly:
			// each launched goroutine writes one result, drainClose reads
			// e.inflight of them.
			for _, lbl := range e.order {
				if ent := e.table[lbl]; ent.status == candInflight {
					ent.cancel()
				}
			}
			if e.inflight > 0 {
				go drainClose(e.results, e.inflight)
			}
			return nil, ctx.Err()

		case <-timer.C:
			timerArmed = false
			launchNext()

		case <-graceTimer.C:
			// Grace expired while a proto was still expanding: release the
			// hold permanently (graceOver is one-way) and resume launching.
			// When the gate first held, nothing had launched yet, so the
			// inflight==0 branch is the live one; the else mirrors the other
			// resume sites for the multi-proto case where a SCION child was
			// already racing when a later IP head got held past the grace.
			e.graceArmed = false
			e.graceOver = true
			if e.heldDue {
				launchNext()
			} else if e.inflight == 0 && !timerArmed && len(e.pending) > 0 {
				launchNext()
			} else if !timerArmed && len(e.pending) > 0 {
				rearm()
			}

		case res := <-e.results:
			ent := e.table[res.label]
			e.inflight--
			if res.err == nil {
				ent.status = candDone
				return finish(res), nil
			}
			ent.status = candFailed
			ent.err = res.err
			if e.cfg.tl != nil {
				e.cfg.tl.Add("fail", res.label, res.err.Error())
			}
			if res.label == e.lastLaunched && errors.Is(res.err, errNoEligiblePath) {
				// The SCION endpoint had no eligible path: no attempt was
				// started, so it does not count as one.
				e.clock.undo(e.clockAt, e.clockPrev)
				e.lastStart = e.prevStart
			}
			if res.label == e.lastLaunched && len(e.pending) > 0 {
				// Sec 6: most-recent attempt failed inside its stagger slot -
				// promote the next candidate without waiting for the timer
				// (launchNext keeps the 10 ms between attempt starts).
				disarm()
				launchNext()
			}

		case res := <-e.expandResults:
			e.expanding--
			parent := e.table[res.parent]
			parent.status = candExpanded // never nil: proto entries are never removed
			// No re-check of the parent's current set membership happens here:
			// a proto tombstoned by an update that landed WHILE its expansion
			// was still in flight still has its children ingested below. This
			// is self-healing rather than a bug — the resolver always re-sends
			// complete sets, so if the proto is genuinely gone the very next
			// update's §7 removal pass (below) re-tombstones these children too.
			// Expanded children are NOT re-filtered: the family filter applies
			// to resolved candidate families, never to expanded sub-candidates.
			// A NoIP filter that spares the SCION proto must also spare its
			// scitra (FamilyIPv6) child — the scitra leg is the SCION fallback,
			// not an IP candidate (deleted expandAndSort's documented contract;
			// design spec §CLI contract). Children inherit the parent's verdict.
			for _, c := range res.cands {
				if _, ok := e.table[c.Label]; ok {
					continue
				}
				ent := &tableEntry{cand: c, status: candNew, parent: res.parent}
				e.table[c.Label] = ent
				e.order = append(e.order, c.Label)
			}
			e.resort()
			// Mirrors the update-ingest re-arm below: fresh candidates just
			// entered pending with no stagger clock ticking.
			if e.heldDue {
				// The Expansion Delay held a due attempt: re-evaluate now
				// (launches the new head, or holds again if another
				// preceding lookup is still in progress).
				launchNext()
			} else if !timerArmed && len(e.pending) > 0 {
				if e.inflight == 0 || e.lastLaunched == "" {
					// Nothing running to stagger against — or nothing ever
					// launched (a proto-only initial set whose children only
					// now materialised, so e.lastLaunched is unset and
					// e.table[e.lastLaunched] would be nil): start the head now.
					launchNext()
				} else {
					// An attempt is still in flight but no stagger clock is
					// ticking (a §4.3 update emptied pending under an armed
					// timer, which fired into launchNext's pending-empty guard
					// and disarmed). Re-arm relative to now so these children
					// launch within one normal interval instead of being
					// stranded until the in-flight attempt finishes.
					rearm()
				}
			}
			// Expansion Delay: once no proto is still expanding, the gate can never
			// hold again — close the window (one-way) and drain the backstop
			// timer so a stale tick cannot fire after the fact. The re-arm block
			// above already resumed launching (children sorted first when
			// present, the freed IP head otherwise) because holdForGrace
			// short-circuits on expanding == 0.
			if e.expanding == 0 && e.graceArmed && !e.graceOver {
				e.graceOver = true
				graceDisarm()
			}

		case set, ok := <-e.updatesSrc():
			if !ok {
				e.updatesOpen = false
				continue
			}
			e.ingest(set)
			if e.heldDue {
				launchNext()
			} else if !timerArmed && len(e.pending) > 0 {
				if e.inflight == 0 {
					// Nothing running to stagger against (mirrors the §6
					// fail-and-promote exception): start now.
					launchNext()
				} else {
					// Something is still in flight but no stagger clock is
					// ticking — most likely §4.3 ingest/resort emptied
					// pending out from under an armed timer (watch-point a),
					// which fires into launchNext's pending-empty guard and
					// disarms without rearming. Without this, a candidate
					// added by a later update would be stranded until the
					// in-flight attempt finishes, however long that takes.
					// Re-arm the stagger relative to now so it launches
					// within one normal interval instead of indefinitely.
					rearm()
				}
			}
		}
	}
}

type attemptDelayKey struct{}

// withAttemptDelay records in ctx the Connection Attempt Delay the engine
// armed after starting this attempt.
func withAttemptDelay(ctx context.Context, d time.Duration) context.Context {
	return context.WithValue(ctx, attemptDelayKey{}, d)
}

// attemptDelayFrom returns the Connection Attempt Delay in use for this
// attempt, or 0 if unknown.
func attemptDelayFrom(ctx context.Context) time.Duration {
	d, _ := ctx.Value(attemptDelayKey{}).(time.Duration)
	return d
}

// updatesSrc returns the updates channel, or a nil channel (blocks forever)
// once closed/absent, so the select above needs no restructuring.
func (e *engine) updatesSrc() <-chan []Candidate {
	if !e.updatesOpen {
		return nil
	}
	return e.cfg.updates
}

// failure builds the terminal error: attempts happened ⇒ joined per-label
// failures in insertion order; otherwise the caller's no-candidates error.
func (e *engine) failure() error {
	var joined []error
	for _, lbl := range e.order {
		if ent := e.table[lbl]; ent.status == candFailed && ent.err != nil {
			joined = append(joined, fmt.Errorf("%s: %w", lbl, ent.err))
		}
	}
	if len(joined) == 0 {
		if e.cfg.noCandsErr != nil {
			return e.cfg.noCandsErr
		}
		return errors.New("hev3: no candidates to race")
	}
	return fmt.Errorf("hev3: all %d candidates failed: %w", len(joined), errors.Join(joined...))
}

// drainClose reads n straggler results and closes any that succeeded, so a
// connection that won its dial after losing the race is not leaked (§6).
func drainClose(results <-chan attemptResult, n int) {
	for k := 0; k < n; k++ {
		r := <-results
		if r.err == nil && r.est != nil && r.est.Close != nil {
			_ = r.est.Close()
		}
	}
}

// withCancelOnClose defers the winner's dial-context cancellation until the
// caller closes the connection, so the context is released (not leaked) without
// tearing down the freshly established transport mid-use.
func withCancelOnClose(est *Established, cancel context.CancelFunc) *Established {
	if est == nil {
		return est
	}
	orig := est.Close
	est.Close = func() error {
		if cancel != nil {
			cancel()
		}
		if orig != nil {
			return orig()
		}
		return nil
	}
	return est
}
