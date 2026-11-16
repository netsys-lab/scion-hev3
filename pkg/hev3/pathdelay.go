package hev3

import (
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/scionproto/scion/pkg/snet"
)

// Path Delay (draft-john-scion-happy-eyeballs, "Racing Paths Within One
// QUIC Connection"): the delay that follows the adding of a path is
// smoothed_rtt + 2*rttvar (RFC 9002, Section 5.3) of that path, from
// historical data of an earlier connection over a path through the same AS
// interfaces; without it, four times the declared latency (twice it taken
// as a first sample); otherwise defaultPathDelay. It is at least
// minPathDelay and at most the Connection Attempt Delay in use.

const (
	// minPathDelay is the hard floor of the Path Delay, that of the
	// Connection Attempt Delay (HEv3, Section 6).
	minPathDelay = 10 * time.Millisecond
	// rttHistoryTTL bounds the age of historical RTT data, so that clients
	// with different history converge (HEv3, Section 5.3).
	rttHistoryTTL = 10 * time.Minute
)

// Sources of a path's Path Delay, as reported in PathStats.DelaySrc.
const (
	delaySrcHistory  = "history"
	delaySrcMetadata = "metadata"
	delaySrcDefault  = "default"
	delaySrcFixed    = "fixed"
)

// rttEntry is the RTT estimate of one path at the end of a connection.
type rttEntry struct {
	srtt, rttvar time.Duration
	expiry       time.Time
}

// rttHistory is historical RTT data per path, keyed by the path's
// interface fingerprint (which includes the ASes). One process uses one
// network, so it is not partitioned further.
type rttHistory struct {
	mu sync.Mutex
	m  map[string]rttEntry
}

func newRTTHistory() *rttHistory { return &rttHistory{m: map[string]rttEntry{}} }

// pathRTTHistory is the process-wide historical RTT data.
var pathRTTHistory = newRTTHistory()

// record stores the estimate of a connection over the path with
// fingerprint fp. Zero estimates (no RTT sample) are ignored.
func (h *rttHistory) record(fp string, srtt, rttvar time.Duration, now time.Time) {
	if h == nil || fp == "" || srtt <= 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.m[fp] = rttEntry{srtt: srtt, rttvar: rttvar, expiry: now.Add(rttHistoryTTL)}
}

func (h *rttHistory) lookup(fp string, now time.Time) (srtt, rttvar time.Duration, ok bool) {
	if h == nil || fp == "" {
		return 0, 0, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.m[fp]
	if !ok {
		return 0, 0, false
	}
	if !now.Before(e.expiry) {
		delete(h.m, fp)
		return 0, 0, false
	}
	return e.srtt, e.rttvar, true
}

// pathDelayFor returns the Path Delay that follows the adding of a path
// with fingerprint fp and metadata md, and its source. configured > 0 is a
// fixed Path Delay; attemptDelay (0 = unknown) caps the result.
func pathDelayFor(configured time.Duration, fp string, md *snet.PathMetadata,
	hist *rttHistory, now time.Time, attemptDelay time.Duration) (time.Duration, string) {

	var d time.Duration
	var src string
	switch {
	case configured > 0:
		d, src = configured, delaySrcFixed
	default:
		if srtt, rttvar, ok := hist.lookup(fp, now); ok {
			d, src = srtt+2*rttvar, delaySrcHistory
		} else if lat, known := declaredLatency(md); known && lat > 0 {
			// First sample 2*lat: smoothed_rtt = 2*lat, rttvar = lat.
			d, src = 4*lat, delaySrcMetadata
		} else {
			d, src = defaultPathDelay, delaySrcDefault
		}
	}
	if attemptDelay > 0 && d > attemptDelay {
		d = attemptDelay
	}
	if d < minPathDelay {
		d = minPathDelay
	}
	return d, src
}

// pathDelays returns the Path Delay that follows the adding of each path of
// a ranked path set, and its source. configured < 0 adds all paths at once
// (nil, nil); configured > 0 is a fixed Path Delay; 0 derives it per path.
func pathDelays(configured time.Duration, paths []snet.Path, hist *rttHistory,
	now time.Time, attemptDelay time.Duration) ([]time.Duration, []string) {

	if configured < 0 {
		return nil, nil
	}
	ds := make([]time.Duration, len(paths))
	srcs := make([]string, len(paths))
	for i, p := range paths {
		md := p.Metadata()
		var fp string
		if md != nil {
			fp = snet.Fingerprint(md.Interfaces).String()
		}
		ds[i], srcs[i] = pathDelayFor(configured, fp, md, hist, now, attemptDelay)
	}
	return ds, srcs
}

// recordHistory stores historical RTT data of the selected path of a
// connection at its end: QUIC's estimate if the path was added at the
// start; else the racer's own sample of the path, as a first sample
// (smoothed_rtt = sample, rttvar = sample/2, RFC 9002 Section 5.3).
func recordHistory(h *rttHistory, r *pathRacer, cs quic.ConnectionStats, now time.Time) {
	fp, fromStart, sample := r.historySource()
	switch {
	case fromStart:
		h.record(fp, cs.SmoothedRTT, cs.MeanDeviation, now)
	case sample > 0:
		h.record(fp, sample, sample/2, now)
	}
}
