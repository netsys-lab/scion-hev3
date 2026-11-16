// Package hev3's Fetch ties resolver.go, engine.go and the dialers together
// into the full draft-ietf-happy-happyeyeballs-v3-04 pipeline (resolve →
// engine (expand+sort+race live) → GET), extended with SCION. The engine
// merges resolver updates and async SCION expansion into the running race;
// see local-docs/2026-07-15-hev3-v2-design.md §4.1.
package hev3

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
)

// defaultCAFile is the root CA PEM Fetch trusts when Options.CAFile is unset
// and the file exists. It matches the testbed's one-off *.scion CA (see
// Section 4 of the companion spec).
const defaultCAFile = "/etc/hev3/ca.pem"

// maxBodyBytes caps how much of the winning response body Fetch reads.
const maxBodyBytes = 4096

// Options configures Fetch.
type Options struct {
	Resolver        string        // "ip:53"[,"ip:53"...]; empty ⇒ system resolver via /etc/resolv.conf. Comma-separated servers are tried in order (F9 failover); each element is already "host:port".
	K               int           // Path Attempt Count: the most candidate paths attempted for one SCION endpoint; 0 => 2
	NoSCION         bool          // drop SCION candidates once resolved, before racing
	NoIP            bool          // drop IPv6/IPv4 candidates once resolved, before racing
	Insecure        bool          // tls.Config.InsecureSkipVerify on every leg
	CAFile          string        // PEM root CA file; "" ⇒ defaultCAFile if it exists, else the system pool
	AttemptDelay    time.Duration // Race stagger; 0 ⇒ Race's default (250ms); hard-floored at 10ms, capped at MaxAttemptDelay (2s default)
	ResolutionDelay time.Duration // ResolveHost §4.2 gate; 0 ⇒ ResolveHost's default (25ms)
	DaemonAddr      string        // sciond address passed through to DialerOptions; "" ⇒ DialerOptions' own default
	RRType          RRType        // which service-binding RR type(s) ResolveHost queries; 0 (RRHTTPS, the HTTPS query only) is the default
	ShuffleSeed     int64         // seeds ResolveHost's equal-priority record shuffle (§5.2); 0 ⇒ a fresh crypto/rand seed per run

	PreferredFamilyCount int           // §5.3 interleave width passed to Sort; 0 ⇒ 1
	MinAttemptDelay      time.Duration // adaptive-stagger floor; 0 ⇒ engine default (100ms, hard-floored at 10ms)
	MaxAttemptDelay      time.Duration // stagger cap; 0 ⇒ engine default (2s)
	// AdaptiveDelay shortens the Connection Attempt Delay after a SCION
	// endpoint to clamp(2 x the declared latency of its first path + 60ms,
	// MinAttemptDelay, AttemptDelay). Not in the draft; off by default.
	AdaptiveDelay bool
	// MaxDestinationASes limits the number of distinct destination ASes
	// for which paths are looked up (draft-john-scion-svcb, Section 5.4).
	// SCION endpoints in further ASes are not attempted. The client's own
	// AS does not count. 0 => 4; negative => no limit.
	MaxDestinationASes int
	// IPFirst orders the SCION family after both IP families instead of
	// first. Path lookups are then not waited for.
	IPFirst bool
	// PathMode: PathModeAttempts ("" too): a separate connection attempt
	// over each candidate path of a SCION endpoint, started one
	// PathAttemptDelay apart. PathModeCopy: one QUIC connection whose
	// datagrams are copied to the candidate paths (not in the draft).
	PathMode string
	// PathAttemptDelay is the time between the starts of the attempts over
	// the candidate paths of one SCION endpoint. 0 => 50ms; values below
	// 10ms are raised to 10ms, values above the Connection Attempt Delay
	// are lowered to it.
	PathAttemptDelay time.Duration
	// Linger bounds how long a cancelled path attempt goes on so that its
	// connection can be closed with CONNECTION_CLOSE. 0 => twice the time
	// the attempts took, within [50ms, 1s]; negative => dropped at once.
	Linger time.Duration
	// WaitLinger makes Fetch return only when no cancelled path attempt
	// is running any more, so that Result.SCIONAttempts is final.
	WaitLinger bool
	// DeterministicPaths breaks ties in the candidate path selection by
	// declared latency and fingerprint instead of at random.
	DeterministicPaths bool
	// PathDelay (PathModeCopy only) is the delay between adding paths of a SCION endpoint's
	// path set to its racing QUIC attempt. 0 => derived per path:
	// smoothed RTT + 2*RTT variation of an earlier connection over the path,
	// else 4x its declared latency, else 50ms; positive => fixed; negative
	// => all paths at once. Kept within [10ms, Connection Attempt Delay].
	PathDelay time.Duration
	// SCIONTarget, if set, skips DNS and attempts only this SCION endpoint:
	// "ISD-AS,IP:port" (IPv6 as "[ip]:port"; ":port" may be omitted to use
	// the URL's port). The URL's host is still the TLS server name and
	// the request authority.
	SCIONTarget string
	// Session, if non-nil, shares the SCION daemon connection across Fetch
	// calls (repeated runs): only the first call pays the connection setup.
	Session *Session
	// ExpCorruptPath (experiments only): see DialerOptions.ExpCorruptPath.
	ExpCorruptPath int
	// ExpRefreshPaths (experiments only): see DialerOptions.ExpRefreshPaths.
	ExpRefreshPaths bool
}

// Session shares SCION daemon state (connection, topology, local IP) across
// Fetch calls. Failures are cached for the Session's lifetime.
type Session struct{ sctx *scionContext }

// NewSession returns a Session for the daemon at daemonAddr ("" =>
// $SCION_DAEMON_ADDRESS or 127.0.0.1:30255). Close it when done.
func NewSession(daemonAddr string) *Session {
	return &Session{sctx: newSCIONContext(DialerOptions{DaemonAddr: daemonAddr})}
}

// Close releases the daemon connection.
func (s *Session) Close() error { return s.sctx.Close() }

// Result is the outcome of a Fetch (partial when Fetch also returns an error).
type Result struct {
	Winner   Candidate // the Candidate that won the race
	ALPN     string    // protocol negotiated on the winning connection (h3/h2/http1.1)
	Status   string    // e.g. "HTTP/2.0 200 OK"
	Body     []byte    // first 4KiB of the response body
	Timeline []Event   // every query/candidate/attempt/success/fail/cancel/winner event

	SCIONAttempts []SCIONAttemptStats // the attempts to every SCION endpoint, in completion order
	Elapsed       time.Duration       // start of Fetch to the end of the request (before any wait for cancelled attempts)
	Lookups       []LookupStats       // every SCION path lookup
}

// Fetch resolves rawURL (which must be an https:// URL — hev3 only speaks
// h3/h2 over TLS), expands and races its SCION/IPv6/IPv4 candidates per
// draft-ietf-happy-happyeyeballs-v3-04 §4-6 and draft-john-scion-happy-eyeballs,
// and issues one GET over the winning connection. If the race or the GET
// fails, the returned Result, if non-nil, carries the Timeline and SCION
// statistics gathered so far (Winner is set only if the race was won).
func Fetch(ctx context.Context, rawURL string, o Options) (*Result, error) {
	u, host, port, err := parseTarget(rawURL)
	if err != nil {
		return nil, err
	}

	fetchStart := time.Now()
	tl := &Timeline{}

	resolveCtx, cancelResolve := context.WithCancel(ctx)
	defer cancelResolve()

	var resolved Resolved
	if o.SCIONTarget != "" {
		c, err := parseSCIONTarget(o.SCIONTarget, port)
		if err != nil {
			return nil, err
		}
		tl.Add("candidate", c.Label, "direct SCION target (no DNS)")
		resolved = Resolved{Initial: []Candidate{c}}
	} else {
		resolved, err = ResolveHost(resolveCtx, host, port, ResolveOptions{
			Resolver:        o.Resolver,
			ResolutionDelay: o.ResolutionDelay,
			SCIONFirst:      !o.IPFirst && !o.NoSCION,
			Timeline:        tl,
			RRType:          o.RRType,
			ShuffleSeed:     o.ShuffleSeed,
		})
		if err != nil {
			return nil, fmt.Errorf("hev3: fetch: resolve %s: %w", host, err)
		}
	}

	tlsConfig, err := buildTLSConfig(o, host)
	if err != nil {
		return nil, err
	}
	stats := &statsCollector{}
	dOpts := DialerOptions{
		TLS: tlsConfig, K: o.K, Timeline: tl, DaemonAddr: o.DaemonAddr,
		PathDelay: o.PathDelay, ExpCorruptPath: o.ExpCorruptPath, ExpRefreshPaths: o.ExpRefreshPaths, Stats: stats,
		PathMode: o.PathMode, PathAttemptDelay: o.PathAttemptDelay, Linger: o.Linger,
		DeterministicPaths: o.DeterministicPaths, MaxDestinationASes: o.MaxDestinationASes,
		Lookups: &lookupGroup{}, BG: &sync.WaitGroup{},
	}
	if dOpts.PathMode != "" && dOpts.PathMode != PathModeAttempts && dOpts.PathMode != PathModeCopy {
		return nil, fmt.Errorf("hev3: fetch: unknown path mode %q", dOpts.PathMode)
	}
	if o.Session != nil {
		dOpts.SCION = o.Session.sctx
	} else {
		sctx := newSCIONContext(dOpts)
		defer sctx.Close() // LIFO: runs after est.Close
		dOpts.SCION = sctx
	}
	// A client that orders SCION first waits for path lookups, no longer
	// than the Resolution Delay after the first positive IP answer.
	var lookupWait time.Duration
	if !o.IPFirst {
		lookupWait = o.ResolutionDelay
		if lookupWait <= 0 {
			lookupWait = defaultResolutionDelay
		}
	}

	pfc := o.PreferredFamilyCount
	if pfc < 1 {
		pfc = 1
	}
	noCands := fmt.Errorf("hev3: fetch: no candidates for %s", host)
	est, err := runEngine(ctx, engineConfig{
		dial:    NewDialer(dOpts),
		initial: resolved.Initial,
		updates: resolved.Updates,
		sortFn: func(cs []Candidate) []Candidate {
			return SortOrder(cs, hasSCION(cs), pfc, o.IPFirst)
		},
		filter: func(c Candidate) bool {
			if o.NoSCION && c.Family == FamilySCION {
				return false
			}
			if o.NoIP && c.Family != FamilySCION {
				return false
			}
			return true
		},
		isProto: func(c Candidate) bool {
			return c.Family == FamilySCION && c.Path == nil && !c.ViaScitra
		},
		expand: func(ectx context.Context, c Candidate) []Candidate {
			return ExpandSCION(ectx, []Candidate{c}, dOpts)
		},
		register: func(c Candidate) {
			if ia, err := addr.ParseIA(c.IA); err == nil {
				dOpts.Lookups.register(ia)
			}
		},
		delay:      o.AttemptDelay,
		minDelay:   o.MinAttemptDelay,
		maxDelay:   o.MaxAttemptDelay,
		adaptive:   o.AdaptiveDelay,
		lookupWait: lookupWait,
		ipAnswerAt: resolved.FirstIPAnswer,
		tl:         tl,
		noCandsErr: noCands,
	})
	// waitLinger waits until no cancelled path attempt is running.
	waitLinger := func() {
		if !o.WaitLinger {
			return
		}
		done := make(chan struct{})
		go func() { dOpts.BG.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(maxLinger + 500*time.Millisecond):
		}
	}
	partial := func() *Result {
		elapsed := time.Since(fetchStart)
		waitLinger()
		attempts, lookups := stats.snapshot()
		return &Result{Timeline: tl.Events(), SCIONAttempts: attempts, Lookups: lookups, Elapsed: elapsed}
	}
	if err != nil {
		if errors.Is(err, noCands) {
			// The no-candidates error is already fully prefixed; don't
			// double-wrap it under "race:" (it's not a race failure).
			return partial(), err
		}
		return partial(), fmt.Errorf("hev3: fetch: race: %w", err)
	}
	cancelResolve() // §6 MAY: the winner is chosen; stop outstanding queries
	defer est.Close()

	status, body, err := getOverWinner(ctx, est, u)
	if err != nil {
		res := partial()
		res.Winner, res.ALPN = est.Cand, est.ALPN
		return res, err
	}

	elapsed := time.Since(fetchStart)
	waitLinger()
	attempts, lookups := stats.snapshot()
	return &Result{
		Elapsed:       elapsed,
		Winner:        est.Cand,
		ALPN:          est.ALPN,
		Status:        status,
		Body:          body,
		Timeline:      tl.Events(),
		SCIONAttempts: attempts,
		Lookups:       lookups,
	}, nil
}

// parseTarget parses rawURL, requiring the https scheme (hev3 only speaks
// h3/h2 over TLS) and defaulting the port to 443 when the URL has none.
func parseTarget(rawURL string) (*url.URL, string, uint16, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, "", 0, fmt.Errorf("hev3: fetch: parsing URL %q: %w", rawURL, err)
	}
	if u.Scheme != "https" {
		return nil, "", 0, fmt.Errorf("hev3: fetch: unsupported scheme %q (hev3 only speaks h3/h2 over https)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, "", 0, fmt.Errorf("hev3: fetch: URL %q has no host", rawURL)
	}
	port := uint16(443)
	if p := u.Port(); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, "", 0, fmt.Errorf("hev3: fetch: bad port %q in URL %q: %w", p, rawURL, err)
		}
		port = uint16(n)
	}
	return u, host, port, nil
}

// hasSCION reports whether cands holds a SCION endpoint (expanded, or
// with its path lookup in progress): the client then has SCION connectivity
// and orders the SCION family first. Without a daemon, endpoints become
// scitra (FamilyIPv6) candidates or are dropped, so none remain.
func hasSCION(cands []Candidate) bool {
	for _, c := range cands {
		if c.Family == FamilySCION && !c.ViaScitra {
			return true
		}
	}
	return false
}

// parseSCIONTarget parses an Options.SCIONTarget, "ISD-AS,IP[:port]" (IPv6
// with a port as "[ip]:port"), into an unexpanded SCION endpoint.
func parseSCIONTarget(s string, defPort uint16) (Candidate, error) {
	iaStr, hostPort, ok := strings.Cut(s, ",")
	if !ok {
		return Candidate{}, fmt.Errorf("hev3: SCION target %q: want ISD-AS,IP[:port]", s)
	}
	ia, err := addr.ParseIA(iaStr)
	if err != nil {
		return Candidate{}, fmt.Errorf("hev3: SCION target %q: %w", s, err)
	}
	var host netip.Addr
	port := defPort
	if ap, err := netip.ParseAddrPort(hostPort); err == nil {
		host, port = ap.Addr(), ap.Port()
	} else if a, err2 := netip.ParseAddr(strings.Trim(hostPort, "[]")); err2 == nil {
		host = a
	} else {
		return Candidate{}, fmt.Errorf("hev3: SCION target %q: bad host %q", s, hostPort)
	}
	host = host.Unmap()
	return Candidate{
		Family:    FamilySCION,
		Host:      host.String(),
		Port:      port,
		IA:        ia.String(),
		ALPN:      []string{alpnH3},
		GroupALPN: []string{alpnH3},
		Label:     "scion:" + ia.String() + "," + host.String(),
	}, nil
}

// buildTLSConfig builds the single tls.Config shared by every race leg:
// ServerName pinned to the URL's hostname (so the demo CA's *.scion cert
// verifies identically on SCION, v6 and v4 legs), RootCAs from o.CAFile (or
// defaultCAFile when it exists and o.CAFile is unset), InsecureSkipVerify
// from o.Insecure.
func buildTLSConfig(o Options, hostname string) (*tls.Config, error) {
	cfg := &tls.Config{ServerName: hostname, InsecureSkipVerify: o.Insecure}

	caFile := o.CAFile
	if caFile == "" {
		if _, err := os.Stat(defaultCAFile); err == nil {
			caFile = defaultCAFile
		}
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("hev3: fetch: reading CA file %q: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("hev3: fetch: no certificates found in CA file %q", caFile)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// getOverWinner issues one GET for the original URL over est.RT and returns
// an "HTTP/x.y 200 OK"-style status line plus up to maxBodyBytes of the
// response body.
func getOverWinner(ctx context.Context, est *Established, u *url.URL) (string, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", nil, fmt.Errorf("hev3: fetch: building request: %w", err)
	}
	resp, err := est.RT.RoundTrip(req)
	if err != nil {
		return "", nil, fmt.Errorf("hev3: fetch: GET over %s: %w", est.Cand.Label, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return "", nil, fmt.Errorf("hev3: fetch: reading body from %s: %w", est.Cand.Label, err)
	}
	status := resp.Status
	if resp.Proto != "" {
		status = resp.Proto + " " + resp.Status
	}
	return status, body, nil
}
