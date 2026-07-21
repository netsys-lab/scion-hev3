package hev3

import (
	"context"
	"errors"
	"fmt"
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
	dial       DialFunc
	initial    []Candidate
	updates    <-chan []Candidate
	sortFn     func([]Candidate) []Candidate
	filter     func(Candidate) bool
	isProto    func(Candidate) bool
	expand     func(context.Context, Candidate) []Candidate
	delay      time.Duration // effective base stagger (defaulted here if <= 0)
	minDelay   time.Duration // adaptive-shortcut floor (defaulted/hard-floored here if <= 0)
	maxDelay   time.Duration // cap on the base stagger (defaulted here if <= 0)
	adaptive   bool          // enables the SCION path-latency shortcut in nextDelay
	scionGrace time.Duration // hold non-SCION launches while any proto is candExpanding, up to this duration; 0 = disabled
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

	graceArmed bool // the SCION-grace timer has been Reset and not yet fired/drained
	graceOver  bool // the SCION-grace window has closed — one-way; holdForGrace is inert thereafter
}

// holdForGrace reports whether the grace gate blocks launching lbl now:
// grace configured and unexpired, at least one expansion in flight, and the
// candidate is not itself SCION. SCION children never wait; scitra children
// only exist after their parent's expansion completes, so once expanding hits
// zero (which drops the gate) they cannot be held either.
func (e *engine) holdForGrace(lbl string) bool {
	if e.cfg.scionGrace <= 0 || e.graceOver {
		return false
	}
	if e.expanding == 0 {
		return false
	}
	return e.table[lbl].cand.Family != FamilySCION
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

func (e *engine) launch(ctx context.Context, lbl string) {
	ent := e.table[lbl]
	cctx, cancel := context.WithCancel(ctx)
	ent.status = candInflight
	ent.cancel = cancel
	e.inflight++
	e.lastLaunched = lbl
	if e.cfg.tl != nil {
		e.cfg.tl.Add("attempt", lbl, "")
	}
	c := ent.cand
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

	// graceTimer backs the optional SCION-grace hold (cfg.scionGrace): while a
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
			return
		}
		if e.holdForGrace(e.pending[0]) {
			// SCION-grace hold: the head is a non-SCION leg and a proto is
			// still expanding. Keep it in pending (do not pop), arm the grace
			// timer once, and leave the stagger disarmed. The release paths —
			// expansion completing (expandResults) or the grace expiring
			// (graceTimer.C) — resume launching through this same closure.
			if !e.graceArmed {
				graceTimer.Reset(e.cfg.scionGrace)
				e.graceArmed = true
			}
			return
		}
		lbl := e.pending[0]
		e.pending = e.pending[1:]
		e.launch(ctx, lbl)
		if len(e.pending) > 0 {
			arm(e.nextDelay(e.table[lbl].cand))
		} else {
			disarm()
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
			if e.inflight == 0 && !timerArmed && len(e.pending) > 0 {
				launchNext()
			} else if !timerArmed && len(e.pending) > 0 {
				arm(e.nextDelay(e.table[e.lastLaunched].cand))
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
			if res.label == e.lastLaunched && len(e.pending) > 0 {
				// §6: most-recent attempt failed inside its stagger slot —
				// promote the next candidate immediately.
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
			if !timerArmed && len(e.pending) > 0 {
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
					arm(e.nextDelay(e.table[e.lastLaunched].cand))
				}
			}
			// SCION-grace: once no proto is still expanding, the gate can never
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
			if !timerArmed && len(e.pending) > 0 {
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
					arm(e.nextDelay(e.table[e.lastLaunched].cand))
				}
			}
		}
	}
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
