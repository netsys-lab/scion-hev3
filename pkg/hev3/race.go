package hev3

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// defaultAttemptDelay is the stagger between attempt launches when
// RaceOptions.AttemptDelay is left zero (draft-ietf-happy-happyeyeballs-v3-04
// §6 "Connection Attempt Delay", default 250ms).
const defaultAttemptDelay = 250 * time.Millisecond

// Established is a completed connection to one Candidate, ready for use.
type Established struct {
	Cand  Candidate
	RT    http.RoundTripper
	Close func() error
	ALPN  string
}

// DialFunc dials one Candidate. It must honour ctx cancellation and, on
// success, return a non-nil *Established whose Close releases the connection.
type DialFunc func(ctx context.Context, c Candidate) (*Established, error)

// RaceOptions tunes a Race. The zero value is valid.
type RaceOptions struct {
	AttemptDelay    time.Duration // stagger between launches; 0 means defaultAttemptDelay (250ms); hard-floored at 10ms, capped at MaxAttemptDelay (2s default)
	MinAttemptDelay time.Duration // adaptive-stagger floor; 0 ⇒ 100ms; hard-floored at 10ms
	MaxAttemptDelay time.Duration // cap on every stagger; 0 ⇒ 2s
	AdaptiveDelay   bool          // enable the SCION path-latency shortcut (not in the draft; off by default)
	Timeline        *Timeline     // optional; records attempt/success/fail/cancel/winner events
}

// Race dials cands concurrently per draft-ietf-happy-happyeyeballs-v3-04 §6:
// attempts start in list order staggered by AttemptDelay, a failing most-recent
// attempt promotes the next candidate immediately, and the first success wins —
// cancelling every other in-flight attempt and abandoning the unlaunched rest.
// The winner's *Established is returned; a straggler that succeeds anyway is
// closed. If all attempts fail, the returned error names every candidate; if
// ctx is cancelled, its error is returned.
//
// Race is a thin static-set wrapper over the connection engine (engine.go):
// attempts start in list order (no re-sort), with no update source and no
// expansion.
func Race(ctx context.Context, cands []Candidate, dial DialFunc, o RaceOptions) (*Established, error) {
	if len(cands) == 0 {
		return nil, errors.New("hev3: no candidates to race")
	}
	return runEngine(ctx, engineConfig{
		dial:     dial,
		initial:  cands,
		delay:    o.AttemptDelay,
		minDelay: o.MinAttemptDelay,
		maxDelay: o.MaxAttemptDelay,
		adaptive: o.AdaptiveDelay,
		tl:       o.Timeline,
	})
}
