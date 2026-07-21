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
	"net/url"
	"os"
	"strconv"
	"time"
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
	K               int           // ranked SCION paths per candidate; 0 ⇒ ExpandSCION's default
	NoSCION         bool          // drop SCION candidates once resolved, before racing
	NoIP            bool          // drop IPv6/IPv4 candidates once resolved, before racing
	Insecure        bool          // tls.Config.InsecureSkipVerify on every leg
	CAFile          string        // PEM root CA file; "" ⇒ defaultCAFile if it exists, else the system pool
	AttemptDelay    time.Duration // Race stagger; 0 ⇒ Race's default (250ms); hard-floored at 10ms, capped at MaxAttemptDelay (2s default)
	ResolutionDelay time.Duration // ResolveHost §4.2 gate; 0 ⇒ ResolveHost's default (50ms)
	DaemonAddr      string        // sciond address passed through to DialerOptions; "" ⇒ DialerOptions' own default
	RRType          RRType        // which service-binding RR type(s) ResolveHost queries; 0 (RRBoth) is the default
	ShuffleSeed     int64         // seeds ResolveHost's equal-priority record shuffle (§5.2); 0 ⇒ a fresh crypto/rand seed per run

	PreferredFamilyCount int           // §5.3 interleave width passed to Sort; 0 ⇒ 1
	MinAttemptDelay      time.Duration // adaptive-stagger floor; 0 ⇒ engine default (100ms, hard-floored at 10ms)
	MaxAttemptDelay      time.Duration // stagger cap; 0 ⇒ engine default (2s)
	NoAdaptiveDelay      bool          // disable the SCION-latency stagger tightening
	SCIONGrace           time.Duration // hold IPv6/IPv4 attempts while native SCION path lookup is in flight, up to this duration; 0 disables (default). Demo/deployment knob — trades first-attempt latency for SCION-first racing when path lookup is slower than the IP legs.
}

// Result is the outcome of a successful Fetch.
type Result struct {
	Winner   Candidate // the Candidate that won the race
	ALPN     string    // protocol negotiated on the winning connection (h3/h2/http1.1)
	Status   string    // e.g. "HTTP/2.0 200 OK"
	Body     []byte    // first 4KiB of the response body
	Timeline []Event   // every query/candidate/attempt/success/fail/cancel/winner event
}

// Fetch resolves rawURL (which must be an https:// URL — hev3 only speaks
// h3/h2 over TLS), expands and races its SCION/IPv6/IPv4 candidates per
// draft-ietf-happy-happyeyeballs-v3-04 §4-6, and issues one GET over the
// winning connection.
func Fetch(ctx context.Context, rawURL string, o Options) (*Result, error) {
	u, host, port, err := parseTarget(rawURL)
	if err != nil {
		return nil, err
	}

	tl := &Timeline{}

	resolveCtx, cancelResolve := context.WithCancel(ctx)
	defer cancelResolve()

	resolved, err := ResolveHost(resolveCtx, host, port, ResolveOptions{
		Resolver:        o.Resolver,
		ResolutionDelay: o.ResolutionDelay,
		Timeline:        tl,
		RRType:          o.RRType,
		ShuffleSeed:     o.ShuffleSeed,
	})
	if err != nil {
		return nil, fmt.Errorf("hev3: fetch: resolve %s: %w", host, err)
	}

	tlsConfig, err := buildTLSConfig(o, host)
	if err != nil {
		return nil, err
	}
	dOpts := DialerOptions{TLS: tlsConfig, K: o.K, Timeline: tl, DaemonAddr: o.DaemonAddr}
	sctx := newSCIONContext(dOpts)
	defer sctx.Close() // LIFO: runs after est.Close — the winner's SCMP
	// revocation handler references the shared daemon connector.
	dOpts.SCION = sctx

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
			return Sort(cs, hasNativeSCIONPath(cs), pfc)
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
		delay:      o.AttemptDelay,
		minDelay:   o.MinAttemptDelay,
		maxDelay:   o.MaxAttemptDelay,
		adaptive:   !o.NoAdaptiveDelay,
		scionGrace: o.SCIONGrace,
		tl:         tl,
		noCandsErr: noCands,
	})
	if err != nil {
		if errors.Is(err, noCands) {
			// The no-candidates error is already fully prefixed; don't
			// double-wrap it under "race:" (it's not a race failure).
			return nil, err
		}
		return nil, fmt.Errorf("hev3: fetch: race: %w", err)
	}
	cancelResolve() // §6 MAY: the winner is chosen; stop outstanding queries
	defer est.Close()

	status, body, err := getOverWinner(ctx, est, u)
	if err != nil {
		return nil, err
	}

	return &Result{
		Winner:   est.Cand,
		ALPN:     est.ALPN,
		Status:   status,
		Body:     body,
		Timeline: tl.Events(),
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

// hasNativeSCIONPath reports whether any candidate carries a pinned SCION
// path — the signal that ExpandSCION found a live sciond (native expansion),
// as opposed to a scitra fallback (FamilyIPv6, Path nil) or no SCION at all.
func hasNativeSCIONPath(cands []Candidate) bool {
	for _, c := range cands {
		if c.Path != nil {
			return true
		}
	}
	return false
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
