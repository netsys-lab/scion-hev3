package hev3

import "sync"

// Per-attempt statistics for experiments (CLI -json / -stats output).
// Times are milliseconds; offsets inside RacerStats are relative to the
// racer's creation (socket open, just before the QUIC dial).

// SCMPEvent is one SCMP error the racer's socket received.
type SCMPEvent struct {
	AtMs    float64 `json:"at_ms"`
	Type    string  `json:"type"` // external-interface-down / internal-connectivity-down
	IA      string  `json:"ia"`
	IfID    uint64  `json:"ifid"`
	Path    int     `json:"path"`              // 1-based rank of the failed path; -1 if not matched
	Ignored string  `json:"ignored,omitempty"` // why it did not fail a path
}

// PathStats describes one path of a racing attempt's path set.
type PathStats struct {
	Rank        int     `json:"rank"`
	Fingerprint string  `json:"fingerprint"`
	Interfaces  string  `json:"interfaces"`
	Added       bool    `json:"added"`
	AddedAtMs   float64 `json:"added_at_ms,omitempty"`
	AddReason   string  `json:"add_reason,omitempty"` // start / path-delay / all-added-failed / selected
	DelayMs     float64 `json:"delay_ms,omitempty"`   // Path Delay that follows the adding of this path
	DelaySrc    string  `json:"delay_src,omitempty"`  // history / metadata / default / fixed
	Failed      bool    `json:"failed,omitempty"`
	FailReason  string  `json:"fail_reason,omitempty"`
	Pkts        int     `json:"pkts"`   // datagrams sent on the path, copies included
	Copies      int     `json:"copies"` // copies of stored datagrams sent when the path was added
	Bytes       int     `json:"bytes"`  // UDP payload octets sent on the path
}

// RacerStats is the state of one racing QUIC attempt.
type RacerStats struct {
	PathDelayMs  float64     `json:"path_delay_ms"` // Path Delay after the first path; 0 with all paths at once
	AllAtOnce    bool        `json:"all_at_once,omitempty"`
	FirstSendMs  float64     `json:"first_send_ms"`
	Selected     int         `json:"selected"` // 1-based rank; 0 = none
	SelectReason string      `json:"select_reason,omitempty"`
	SelectedAtMs float64     `json:"selected_at_ms,omitempty"`
	Paths        []PathStats `json:"paths"`
	SCMP         []SCMPEvent `json:"scmp,omitempty"`
	RecvPkts     int         `json:"recv_pkts"`
	RecvBytes    int         `json:"recv_bytes"`
	RecvForeign  int         `json:"recv_foreign,omitempty"` // datagrams from the remote ignored before selection: DCID not this connection's
}

// PathAttemptStats is one connection attempt over one candidate path.
type PathAttemptStats struct {
	Rank        int         `json:"rank"` // 1-based position among the candidate paths
	Fingerprint string      `json:"fingerprint"`
	Interfaces  string      `json:"interfaces"`
	Started     bool        `json:"started"`
	StartMs     float64     `json:"start_ms"`             // after the first attempt's start
	LocalPort   int         `json:"local_port,omitempty"` // the attempt's own local port
	HandshakeMs float64     `json:"handshake_ms"`         // this attempt's start to handshake done, failure or cancellation
	DelayMs     float64     `json:"delay_ms,omitempty"`   // Path Attempt Delay that follows the start of this attempt (not set on the last path)
	DelaySrc    string      `json:"delay_src,omitempty"`  // fixed (configured or default value) / history / default (derived delay, no history for the path)
	Outcome     string      `json:"outcome"`              // won / closed (handshake done after the decision, CONNECTION_CLOSE sent) / cancelled / failed / not-started / in-progress
	Err         string      `json:"error,omitempty"`
	SentPkts    int         `json:"sent_pkts"`
	SentBytes   int         `json:"sent_bytes"` // UDP payload octets
	RecvPkts    int         `json:"recv_pkts"`
	RecvBytes   int         `json:"recv_bytes"`
	SCMP        []SCMPEvent `json:"scmp,omitempty"`
}

// SCIONAttemptStats is the attempts to one SCION endpoint.
type SCIONAttemptStats struct {
	Label               string             `json:"label"`
	Remote              string             `json:"remote"`
	Mode                string             `json:"mode"`                             // attempts (one connection per candidate path) / copy (one connection, datagrams copied)
	PathAttemptDelayMs  float64            `json:"path_attempt_delay_ms,omitempty"`  // attempts mode: the Path Attempt Delay after the first attempt
	PathAttemptDelaySrc string             `json:"path_attempt_delay_src,omitempty"` // attempts mode: its source (see PathAttemptStats.DelaySrc)
	ExpSamePath         bool               `json:"exp_same_path,omitempty"`          // attempts mode, experiment: every attempt used candidate path 1
	Winner              int                `json:"winner,omitempty"`                 // attempts mode: 1-based rank of the path whose attempt succeeded
	HandshakeMs         float64            `json:"handshake_ms"`                     // first attempt's start to QUIC handshake done (or failure)
	SetupMs             float64            `json:"setup_ms"`                         // daemon/topology setup and path selection before the first attempt
	Err                 string             `json:"error,omitempty"`
	Paths               []PathAttemptStats `json:"path_attempts,omitempty"` // attempts mode
	Racer               *RacerStats        `json:"racer,omitempty"`         // copy mode
}

// LookupStats is one path lookup for a SCION endpoint.
type LookupStats struct {
	Label         string   `json:"label"`
	DaemonSetupMs float64  `json:"daemon_setup_ms,omitempty"` // daemon connection set up within this lookup
	LookupMs      float64  `json:"lookup_ms"`                 // the Paths RPC
	Shared        bool     `json:"shared,omitempty"`          // used the lookup of another endpoint in the same AS
	OwnAS         bool     `json:"own_as,omitempty"`          // endpoint in the client's AS: no lookup
	PathsFound    int      `json:"paths_found"`
	PathSet       []string `json:"path_set,omitempty"` // eligible paths (interfaces)
	Excluded      []string `json:"excluded,omitempty"`
	Err           string   `json:"error,omitempty"`
}

// statsCollector gathers stats of one Fetch; safe for concurrent use. A nil
// collector discards everything.
type statsCollector struct {
	mu       sync.Mutex
	attempts []func() SCIONAttemptStats
	lookups  []LookupStats
}

func (c *statsCollector) addAttempt(a SCIONAttemptStats) {
	c.addAttemptFunc(func() SCIONAttemptStats { return a })
}

// addAttemptFunc registers an attempt whose statistics can still change
// (cancelled path attempts that go on for the linger time).
func (c *statsCollector) addAttemptFunc(f func() SCIONAttemptStats) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attempts = append(c.attempts, f)
}

func (c *statsCollector) addLookup(l LookupStats) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lookups = append(c.lookups, l)
}

func (c *statsCollector) snapshot() ([]SCIONAttemptStats, []LookupStats) {
	if c == nil {
		return nil, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	attempts := make([]SCIONAttemptStats, 0, len(c.attempts))
	for _, f := range c.attempts {
		attempts = append(attempts, f())
	}
	return attempts, append([]LookupStats(nil), c.lookups...)
}
