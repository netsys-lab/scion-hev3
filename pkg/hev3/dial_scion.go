package hev3

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	daemon_types "github.com/scionproto/scion/pkg/daemon/types"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/addrutil"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

// pathQuerier lists SCION paths to a destination IA. It is the seam tests use
// to feed ExpandSCION synthetic paths without a live daemon.
type pathQuerier interface {
	Paths(ctx context.Context, dst addr.IA) ([]snet.Path, error)
}

// daemonQuerier is the production pathQuerier: it asks sciond for paths from the
// local IA.
type daemonQuerier struct {
	conn    daemon.Connector
	localIA addr.IA
	local   *lazyIP // nil: local IP unknown
	refresh bool    // experiments: ask the daemon to fetch the paths anew
}

type lazyIP struct {
	once sync.Once
	ip   net.IP
	err  error
}

// LocalIP returns the default local underlay IP (resolved once).
func (q daemonQuerier) LocalIP(ctx context.Context) (net.IP, error) {
	if q.local == nil {
		return nil, errors.New("hev3: local IP unknown")
	}
	q.local.once.Do(func() {
		q.local.ip, q.local.err = addrutil.DefaultLocalIP(ctx, daemon.TopoQuerier{Connector: q.conn})
	})
	return q.local.ip, q.local.err
}

func (q daemonQuerier) Paths(ctx context.Context, dst addr.IA) ([]snet.Path, error) {
	return q.conn.Paths(ctx, dst, q.localIA, daemon_types.PathReqFlags{Refresh: q.refresh})
}

// resolveQuerier connects to sciond and returns a daemonQuerier. It is a var so
// tests can inject a fake querier or force the daemon-absent branch.
var resolveQuerier = func(ctx context.Context, o DialerOptions) (pathQuerier, error) {
	conn, err := daemon.NewService(daemonAddress(o)).Connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("hev3: connecting to daemon: %w", err)
	}
	localIA, err := conn.LocalIA(ctx)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("hev3: querying local IA: %w", err)
	}
	return daemonQuerier{conn: conn, localIA: localIA, local: &lazyIP{}, refresh: o.ExpRefreshPaths}, nil
}

// scionContextConnectTimeout bounds the detached context each scionContext
// RPC (daemon connect, LoadTopology, DefaultLocalIP, resolveQuerier) runs
// under — see the WithoutCancel note below.
const scionContextConnectTimeout = 3 * time.Second

// errSCIONContextClosed is returned by querier/dialParams when Close raced
// the in-flight sync.Once body and won: the just-produced connection was
// reaped instead of stored.
var errSCIONContextClosed = errors.New("hev3: scion context closed")

// scionContext shares the sciond-derived state every SCION operation needs:
// one pathQuerier for expansion and one (connector, topology, local IP)
// triple for dials — resolved once, reused across the K path attempts that
// previously each paid 3 daemon RPCs (F12). Close is idempotent; the owner
// (Fetch) closes it after the winning connection is done, because the
// winner's SCMP revocation handler references the shared connector.
//
// One-shot semantics: querier and dialParams each resolve at most once per
// scionContext (sync.Once) and cache failures for the context's lifetime —
// a transient daemon error on the first call disables native SCION
// expansion/dialing for the rest of this Fetch's attempts and Updates
// batches (deliberate F12 trade: correctness over one retry). o.DaemonAddr
// is frozen at construction time (newSCIONContext); the per-call
// DialerOptions passed to querier/dialParams afterward is used for
// everything else (the resolveQuerier seam, TLS, Timeline) but never
// re-resolves the daemon address.
//
// Close is mutex-guarded rather than built on its own sync.Once: a bare
// closeOnce cannot be given a happens-before relationship with the
// independent qOnce/dOnce that might still be mid-flight (Once values don't
// synchronize with each other), so a naive Close could run between a
// connection's RPCs completing and its result being stored, see nothing to
// close, and let the Once then cache a live connection that never gets
// closed. Guarding both "am I closed" and every read/write of the cached
// conns with one mutex closes that window: whichever of Close vs. the Once
// body's final store observes `closed` second either reaps the
// just-produced connection (Once loses) or has nothing left to reap because
// Close already ran (Close loses) — either way nothing leaks.
type scionContext struct {
	daemonAddr string

	qOnce sync.Once
	q     pathQuerier
	qConn io.Closer // non-nil when the querier owns a daemon connection
	qErr  error

	dOnce   sync.Once
	conn    daemon.Connector
	topo    snet.Topology
	localIP net.IP
	dErr    error

	mu     sync.Mutex
	closed bool
}

// newSCIONContext creates a scionContext scoped to one Fetch. o is used only
// to resolve the daemon address at construction time; querier and dialParams
// each still take a DialerOptions so callers can pass per-call overrides
// (Timeline, TLS, ...) while the daemon connection itself is shared.
func newSCIONContext(o DialerOptions) *scionContext {
	return &scionContext{daemonAddr: daemonAddress(o)}
}

// detachedConnectContext returns a context that survives cancellation of a
// losing attempt's ctx (so one race loser can't poison the shared connect
// for every other attempt) but stays bounded, since sciond is always local.
// context.WithoutCancel strips ALL upstream cancellation here, including the
// top-level Fetch ctx (e.g. its overall timeout) — scionContextConnectTimeout
// is the only thing that can still stop this connect.
func detachedConnectContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), scionContextConnectTimeout)
}

// querier returns the shared pathQuerier, connecting via the resolveQuerier
// seam on first call and caching the result (and its underlying daemon
// connection, if any) for every subsequent call.
func (s *scionContext) querier(ctx context.Context, o DialerOptions) (pathQuerier, error) {
	s.qOnce.Do(func() {
		cctx, cancel := detachedConnectContext(ctx)
		defer cancel()
		q, err := resolveQuerier(cctx, o)
		var qConn io.Closer
		if dq, ok := q.(daemonQuerier); ok {
			qConn = dq.conn
		}

		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed {
			if qConn != nil {
				_ = qConn.Close()
			}
			s.qErr = errSCIONContextClosed
			return
		}
		s.q, s.qErr, s.qConn = q, err, qConn
	})
	return s.q, s.qErr
}

// dialParams returns the shared (connector, topology, local IP) triple that
// dialSCION needs, connecting to sciond and loading topology once and
// caching the result for every subsequent attempt.
func (s *scionContext) dialParams(ctx context.Context, o DialerOptions) (daemon.Connector, snet.Topology, net.IP, error) {
	s.dOnce.Do(func() {
		cctx, cancel := detachedConnectContext(ctx)
		defer cancel()

		sciond, err := daemon.NewService(s.daemonAddr).Connect(cctx)
		if err != nil {
			s.dErr = fmt.Errorf("hev3: dial scion: connecting to daemon: %w", err)
			return
		}
		topo, err := daemon.LoadTopology(cctx, sciond)
		if err != nil {
			_ = sciond.Close()
			s.dErr = fmt.Errorf("hev3: dial scion: loading topology: %w", err)
			return
		}
		localIP, err := addrutil.DefaultLocalIP(cctx, daemon.TopoQuerier{Connector: sciond})
		if err != nil {
			_ = sciond.Close()
			s.dErr = fmt.Errorf("hev3: dial scion: resolving local IP: %w", err)
			return
		}

		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed {
			_ = sciond.Close()
			s.dErr = errSCIONContextClosed
			return
		}
		s.conn, s.topo, s.localIP = sciond, topo, localIP
	})
	return s.conn, s.topo, s.localIP, s.dErr
}

// Close releases the shared daemon connections (querier and dial-params, if
// either was ever resolved). Idempotent (guarded by closed, not its own
// sync.Once — see the type doc comment); safe to call concurrently with an
// in-flight querier/dialParams call or with itself.
func (s *scionContext) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.qConn != nil {
		_ = s.qConn.Close()
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
	return nil
}

// defaultMaxDestinationASes is the default limit on the number of distinct
// destination ASes for which one connection establishment looks up paths
// (draft-john-scion-svcb, Section 5.4, which sets no number).
const defaultMaxDestinationASes = 4

// errDestinationASLimit drops a SCION endpoint whose AS is beyond the limit
// on destination ASes.
var errDestinationASLimit = errors.New("destination AS beyond the limit on path lookups")

// lookupGroup shares one path lookup per destination ISD-AS among the SCION
// endpoints of one connection establishment, and limits the number of
// distinct destination ASes that get a lookup.
type lookupGroup struct {
	mu sync.Mutex
	m  map[addr.IA]*lookupCall
	// order lists the destination ASes in the order their first endpoint
	// was created; the first ones, up to the limit, get a lookup.
	order []addr.IA
}

// register records that an endpoint in ia was created. Registering in the
// order the endpoints arrive makes the choice of the ASes within the limit
// independent of the order in which the lookups run.
func (g *lookupGroup) register(ia addr.IA) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.registerLocked(ia)
}

func (g *lookupGroup) registerLocked(ia addr.IA) {
	for _, x := range g.order {
		if x == ia {
			return
		}
	}
	g.order = append(g.order, ia)
}

// admit reports whether paths to ia may be looked up: ia is among the first
// limit destination ASes registered, not counting local, the client's own
// AS, which needs no lookup. limit 0 means defaultMaxDestinationASes, a
// negative limit means no limit.
func (g *lookupGroup) admit(ia, local addr.IA, limit int) bool {
	if g == nil || limit < 0 {
		return true
	}
	if limit == 0 {
		limit = defaultMaxDestinationASes
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.registerLocked(ia)
	n := 0
	for _, x := range g.order {
		if x == local {
			continue
		}
		if x == ia {
			return n < limit
		}
		n++
	}
	return false
}

type lookupCall struct {
	done  chan struct{}
	paths []snet.Path
	err   error
	dur   time.Duration
}

// do returns the result of the lookup for ia, running fn if no lookup for
// ia was started yet. shared reports that another caller's lookup was used.
func (g *lookupGroup) do(ctx context.Context, ia addr.IA, fn func() ([]snet.Path, error)) (paths []snet.Path, err error, dur time.Duration, shared bool) {
	if g == nil {
		start := time.Now()
		paths, err = fn()
		return paths, err, time.Since(start), false
	}
	g.mu.Lock()
	if g.m == nil {
		g.m = map[addr.IA]*lookupCall{}
	}
	c, ok := g.m[ia]
	if !ok {
		c = &lookupCall{done: make(chan struct{})}
		g.m[ia] = c
	}
	g.mu.Unlock()
	if !ok {
		start := time.Now()
		c.paths, c.err = fn()
		c.dur = time.Since(start)
		close(c.done)
		return c.paths, c.err, c.dur, false
	}
	select {
	case <-c.done:
		return c.paths, c.err, c.dur, true
	case <-ctx.Done():
		return nil, ctx.Err(), 0, true
	}
}

// ExpandSCION performs the path lookups of unexpanded SCION endpoints
// (FamilySCION, no path set) and turns them into dialable candidates. With
// a reachable daemon, an endpoint whose lookup returns at least one
// eligible path becomes ONE candidate carrying all eligible paths known
// (PathSet), labelled "<label>#paths"; the candidate paths are selected
// from them when the endpoint is attempted (dialSCION). An endpoint in the
// client's own AS needs no lookup and uses the empty path. A lookup that
// fails, takes longer than pathLookupLimit or returns no eligible path
// drops the endpoint. With no daemon but an fc00 scitra route present,
// each endpoint becomes one ViaScitra candidate dialed as its mapped IPv6
// address; with neither, the SCION candidates are dropped (recorded as
// Timeline "fail" notes). Non-SCION and already-expanded candidates pass
// through unchanged.
func ExpandSCION(ctx context.Context, cands []Candidate, o DialerOptions) []Candidate {
	var passthrough, proto []Candidate
	for _, c := range cands {
		if c.Family == FamilySCION && c.Path == nil && !c.ViaScitra {
			proto = append(proto, c)
		} else {
			passthrough = append(passthrough, c)
		}
	}
	if len(proto) == 0 {
		return passthrough
	}
	if o.Lookups == nil {
		o.Lookups = &lookupGroup{}
	}
	for _, c := range proto {
		if ia, err := addr.ParseIA(c.IA); err == nil {
			o.Lookups.register(ia)
		}
	}
	// The client gives up on a lookup pathLookupLimit after it started.
	ctx, cancel := context.WithTimeout(ctx, pathLookupLimit)
	defer cancel()

	out := passthrough
	var q pathQuerier
	var err error
	setupStart := time.Now()
	if o.SCION != nil {
		// The shared daemon connect runs on a detached context with a
		// longer timeout (detachedConnectContext); this endpoint still
		// gives up on it at the lookup limit.
		type querierResult struct {
			q   pathQuerier
			err error
		}
		ch := make(chan querierResult, 1)
		go func() {
			q, err := o.SCION.querier(ctx, o)
			ch <- querierResult{q, err}
		}()
		select {
		case r := <-ch:
			q, err = r.q, r.err
		case <-ctx.Done():
			err = fmt.Errorf("hev3: connecting to daemon: %w", ctx.Err())
		}
	} else {
		q, err = resolveQuerier(ctx, o)
	}
	setup := time.Since(setupStart)
	if err != nil {
		for _, c := range proto {
			o.Stats.addLookup(LookupStats{Label: c.Label, DaemonSetupMs: msec(setup), Err: err.Error()})
		}
		// Daemon absent: fall back to scitra when the route exists, else drop.
		return append(out, fallbackNoDaemon(proto, o)...)
	}
	for i, c := range proto {
		ls := LookupStats{Label: c.Label}
		if i == 0 {
			ls.DaemonSetupMs = msec(setup)
		}
		if nc, ok := expandOne(ctx, q, c, o, &ls); ok {
			out = append(out, nc)
		}
		o.Stats.addLookup(ls)
	}
	return out
}

// localIPQuerier is optionally implemented by a pathQuerier that knows the
// local underlay IP (used for the exact SCION header size in the MTU check).
type localIPQuerier interface {
	LocalIP(ctx context.Context) (net.IP, error)
}

// localIAQuerier is optionally implemented by a pathQuerier that knows the
// client's own ISD-AS.
type localIAQuerier interface {
	LocalIA() addr.IA
}

// LocalIA returns the client's ISD-AS.
func (q daemonQuerier) LocalIA() addr.IA { return q.localIA }

// expandOne performs the path lookup for one SCION endpoint. A parse
// failure, a failed lookup, or no eligible path drops the endpoint with a
// Timeline note (the daemon is present, so scitra - the no-daemon fallback
// - does not apply here).
func expandOne(ctx context.Context, q pathQuerier, c Candidate, o DialerOptions, ls *LookupStats) (Candidate, bool) {
	dst, err := addr.ParseIA(c.IA)
	if err != nil {
		note(o, c, fmt.Sprintf("bad IA %q: %v", c.IA, err))
		ls.Err = err.Error()
		return Candidate{}, false
	}
	host, err := netip.ParseAddr(c.Host)
	if err != nil {
		note(o, c, fmt.Sprintf("bad host %q: %v", c.Host, err))
		ls.Err = err.Error()
		return Candidate{}, false
	}
	nc := c
	nc.Label = c.Label + "#paths"
	var local addr.IA
	if lq, ok := q.(localIAQuerier); ok {
		local = lq.LocalIA()
	}
	if local != dst && !o.Lookups.admit(dst, local, o.MaxDestinationASes) {
		// Section 5.4 of draft-john-scion-svcb: no lookup, not attempted.
		note(o, c, errDestinationASLimit.Error())
		ls.Err = errDestinationASLimit.Error()
		return Candidate{}, false
	}
	if local == dst {
		// An endpoint in the client's own AS: no lookup, the empty path.
		ls.OwnAS = true
		p := snetpath.Path{Src: dst, Dst: dst, DataplanePath: snetpath.Empty{}}
		nc.PathSet = []SCIONPath{{Hops: 1, Interfaces: interfacesString(nil), SNET: snet.Path(p)}}
		nc.Path = &nc.PathSet[0]
		ls.PathSet = []string{nc.PathSet[0].Interfaces}
		return nc, true
	}
	srcLen := 16 // conservative when the local address is unknown
	var localDone chan struct{}
	if lq, ok := q.(localIPQuerier); ok {
		localDone = make(chan struct{})
		go func() {
			defer close(localDone)
			if ip, err := lq.LocalIP(ctx); err == nil {
				if a, ok := netip.AddrFromSlice(ip); ok {
					srcLen = hostLen(a)
				}
			}
		}()
	}
	paths, err, dur, shared := o.Lookups.do(ctx, dst, func() ([]snet.Path, error) { return q.Paths(ctx, dst) })
	ls.LookupMs, ls.Shared = msec(dur), shared
	if localDone != nil {
		<-localDone
	}
	ls.PathsFound = len(paths)
	if err != nil {
		note(o, c, fmt.Sprintf("path lookup failed: %v", err))
		ls.Err = err.Error()
		return Candidate{}, false
	}
	if len(paths) == 0 {
		note(o, c, "no SCION paths")
		ls.Err = "no SCION paths"
		return Candidate{}, false
	}
	// All eligible paths, in the deterministic order of the selection.
	set, excl := selectPathSet(paths, pathSetParams{
		K: len(paths), Now: time.Now(), DstHostLen: hostLen(host), SrcHostLen: srcLen, AllowSoon: true,
	})
	for _, e := range excl {
		ls.Excluded = append(ls.Excluded, e.Fingerprint+": "+e.Reason)
	}
	if len(set) == 0 {
		note(o, c, "no eligible SCION path (expired or MTU too small)")
		ls.Err = "no eligible path"
		return Candidate{}, false
	}
	nc.PathSet = make([]SCIONPath, len(set))
	for i, rp := range set {
		nc.PathSet[i] = rp.toSCIONPath()
		ls.PathSet = append(ls.PathSet, nc.PathSet[i].Interfaces)
	}
	nc.Path = &nc.PathSet[0]
	return nc, true
}

// fallbackNoDaemon maps each proto-candidate to one ViaScitra candidate when an
// fc00 route exists, or drops them all with Timeline notes otherwise.
func fallbackNoDaemon(proto []Candidate, o DialerOptions) []Candidate {
	if !scitraAvailable() {
		for _, c := range proto {
			note(o, c, "no SCION daemon and no scitra route")
		}
		return nil
	}
	var out []Candidate
	for _, c := range proto {
		sc, err := scitraCandidate(c)
		if err != nil {
			note(o, c, err.Error())
			continue
		}
		out = append(out, sc)
	}
	return out
}

// scitraCandidate rewrites a proto-SCION candidate into an IPv6 ViaScitra
// candidate whose Host is the SCION-IP-translator mapping of IA+Host, keeping
// port and ALPN.
func scitraCandidate(c Candidate) (Candidate, error) {
	host, err := netip.ParseAddr(c.Host)
	if err != nil {
		return Candidate{}, fmt.Errorf("bad host %q: %w", c.Host, err)
	}
	mapped, err := ScitraMap(c.IA, host, scitraPrefixDefault)
	if err != nil {
		return Candidate{}, err
	}
	nc := c
	nc.Family = FamilyIPv6
	nc.ViaScitra = true
	nc.Host = mapped.String()
	nc.Path = nil
	// Keep the suffix that tells apart endpoints with the same SCION
	// address (scionLabel), so that they stay distinct after the mapping.
	nc.Label = "scitra:" + c.IA + "," + mapped.String()
	if suffix, ok := strings.CutPrefix(c.Label, "scion:"+c.IA+","+c.Host); ok {
		nc.Label += suffix
	}
	return nc, nil
}

func note(o DialerOptions, c Candidate, detail string) {
	if o.Timeline != nil {
		o.Timeline.Add("fail", c.Label, detail)
	}
}

// dialSCION attempts a native HTTP/3 over SCION QUIC connection to the
// candidate's SCION endpoint. The candidate paths are selected now, from
// the candidate's paths that are eligible now; if there is none, the error
// is errNoEligiblePath and no attempt was started.
//
// In the default mode (PathModeAttempts) a separate QUIC connection is
// attempted over each candidate path (attempts.go). In PathModeCopy the
// candidate paths are raced within one QUIC connection (racer.go).
//
// quic-go is dialed directly over an snet.Conn rather than through
// pkg/snet/squic: HTTP/3 needs the raw *quic.Conn, and the wrapper around
// the snet.Conn decides which SCION path each datagram goes out on.
func dialSCION(ctx context.Context, c Candidate, o DialerOptions) (*Established, error) {
	if len(c.PathSet) == 0 {
		return nil, errors.New("hev3: dial scion: candidate has no paths")
	}
	known := make([]snet.Path, 0, len(c.PathSet))
	for i, sp := range c.PathSet {
		p, ok := sp.SNET.(snet.Path)
		if !ok {
			return nil, fmt.Errorf("hev3: dial scion: path %d is %T, not snet.Path", i+1, sp.SNET)
		}
		known = append(known, p)
	}
	dstIA, err := addr.ParseIA(c.IA)
	if err != nil {
		return nil, fmt.Errorf("hev3: dial scion: bad IA %q: %w", c.IA, err)
	}
	host, err := netip.ParseAddr(c.Host)
	if err != nil {
		return nil, fmt.Errorf("hev3: dial scion: bad host %q: %w", c.Host, err)
	}
	setupStart := time.Now()

	// With a shared scionContext (o.SCION != nil) the daemon connect,
	// topology load, and local-IP resolution happen at most once per Fetch
	// (F12) and this call must never close that shared connector - it is
	// owned by o.SCION and released by scionContext.Close. With no shared
	// context (library callers, existing tests) this call owns the daemon
	// connection: connect/load/resolve inline and close it on every error
	// path and on Established.Close.
	var (
		sciond   daemon.Connector
		topo     snet.Topology
		localIP  net.IP
		ownsConn bool
	)
	if o.SCION != nil {
		sciond, topo, localIP, err = o.SCION.dialParams(ctx, o)
		if err != nil {
			return nil, err
		}
	} else {
		ownsConn = true
		sciond, err = daemon.NewService(daemonAddress(o)).Connect(ctx)
		if err != nil {
			return nil, fmt.Errorf("hev3: dial scion: connecting to daemon: %w", err)
		}
		topo, err = daemon.LoadTopology(ctx, sciond)
		if err != nil {
			_ = sciond.Close()
			return nil, fmt.Errorf("hev3: dial scion: loading topology: %w", err)
		}
		localIP, err = addrutil.DefaultLocalIP(ctx, daemon.TopoQuerier{Connector: sciond})
		if err != nil {
			_ = sciond.Close()
			return nil, fmt.Errorf("hev3: dial scion: resolving local IP: %w", err)
		}
	}
	closeDaemon := func() {
		if ownsConn {
			_ = sciond.Close()
		}
	}

	// Candidate paths: selected at the time of the attempt.
	copyMode := o.PathMode == PathModeCopy
	k := o.K
	if k <= 0 {
		k = defaultK
	}
	params := pathSetParams{K: k, Now: time.Now(), DstHostLen: hostLen(host), SrcHostLen: 16}
	if a, ok := netip.AddrFromSlice(localIP); ok {
		params.SrcHostLen = hostLen(a)
	}
	if copyMode {
		params.Down = scmpDownCache
	} else {
		params.Random = !o.DeterministicPaths
	}
	set, _ := selectPathSet(known, params)
	if len(set) == 0 {
		closeDaemon()
		return nil, fmt.Errorf("hev3: dial scion %s,%s: %w", c.IA, c.Host, errNoEligiblePath)
	}
	paths := attemptPaths(set, o.ExpCorruptPath, o.ExpSamePath && !copyMode)

	remote := &snet.UDPAddr{IA: dstIA, Host: net.UDPAddrFromAddrPort(netip.AddrPortFrom(host, c.Port))}
	tlsConf := h3TLSConfig(o.TLS, host.String())
	if !copyMode {
		// Default 50 ms (or derived per path from historical RTT data),
		// not below 10 ms, not above the Connection Attempt Delay in use.
		delays, srcs := pathAttemptDelays(o.PathAttemptDelay, o.PathAttemptDelayDerived, paths,
			pathRTTHistory, time.Now(), attemptDelayFrom(ctx))
		res, err := dialAttempts(ctx, attemptsDial{
			Remote: remote, Paths: paths, Delay: delays[0], Delays: delays, DelaySrcs: srcs,
			Topology: topo, LocalIP: localIP,
			TLS: tlsConf, Linger: o.Linger, OnStart: pathStartHookFrom(ctx), Reserve: pathAttemptGateFrom(ctx), BG: o.BG,
		})
		st := SCIONAttemptStats{
			Label: c.Label, Remote: remote.String(), Mode: PathModeAttempts,
			PathAttemptDelayMs: msec(delays[0]), PathAttemptDelaySrc: srcs[0], ExpSamePath: o.ExpSamePath,
			SetupMs:     msec(time.Since(setupStart) - res.handshake),
			HandshakeMs: msec(res.handshake),
		}
		if err != nil {
			st.Err = err.Error()
		}
		set := res.set
		o.Stats.addAttemptFunc(func() SCIONAttemptStats {
			out := st
			out.Winner, out.Paths = set.snapshot()
			return out
		})
		if err != nil {
			closeDaemon()
			return nil, fmt.Errorf("hev3: dial scion %s: %w", remote, err)
		}
		// Historical RTT data of the winning path: each attempt is a
		// connection of its own, so QUIC's estimate is that path's. It is
		// recorded now (handshake samples only) and again at the close,
		// which is within the Fetch, so a later Fetch in the same process
		// finds it.
		tr, pc, qconn := res.tr, res.pc, res.conn
		fp := pathFingerprint(paths[res.winner])
		recordConnHistory(pathRTTHistory, fp, qconn)
		return newH3Established(c, qconn, func() error {
			recordConnHistory(pathRTTHistory, fp, qconn)
			_ = tr.Close()
			err := pc.Close()
			closeDaemon()
			return err
		}), nil
	}

	delays, srcs := pathDelays(o.PathDelay, paths, pathRTTHistory, time.Now(), attemptDelayFrom(ctx))
	res, err := dialRacing(ctx, racingDial{
		Remote:     remote,
		Paths:      paths,
		PathDelays: delays,
		DelaySrcs:  srcs,
		Topology:   topo,
		LocalIP:    localIP,
		TLS:        tlsConf,
	})
	st := SCIONAttemptStats{
		Label: c.Label, Remote: remote.String(), Mode: PathModeCopy,
		SetupMs: msec(time.Since(setupStart) - res.handshake), HandshakeMs: msec(res.handshake),
	}
	if res.racer != nil {
		rs := res.racer.Stats()
		st.Racer = &rs
	}
	if err != nil {
		closeDaemon()
		st.Err = err.Error()
		o.Stats.addAttempt(st)
		return nil, fmt.Errorf("hev3: dial scion %s: %w", remote, err)
	}
	o.Stats.addAttempt(st)
	tr, racer, qconn := res.tr, res.racer, res.conn
	return newH3Established(c, qconn, func() error {
		recordHistory(pathRTTHistory, racer, qconn.ConnectionStats(), time.Now())
		_ = tr.Close()
		err := racer.Close()
		closeDaemon()
		return err
	}), nil
}

// racingDial is the input of dialRacing.
type racingDial struct {
	Remote *snet.UDPAddr // remote IA + host:port
	Paths  []snet.Path   // ranked path set
	// PathDelays[i] follows the adding of Paths[i]; nil = PathDelay for
	// every path, and PathDelay <= 0 adds all paths at once.
	PathDelays []time.Duration
	DelaySrcs  []string
	PathDelay  time.Duration
	Topology   snet.Topology
	LocalIP    net.IP
	TLS        *tls.Config
	Down       *downCache // nil = the process-wide SCMP down cache
}

type racingResult struct {
	conn      *quic.Conn
	tr        *quic.Transport
	racer     *pathRacer // non-nil once the socket is open (also on failure, for stats)
	handshake time.Duration
}

// dialRacing opens a dispatcherless SCION socket and dials one QUIC
// connection over a pathRacer racing d.Paths. On error everything is
// closed. Separate from dialSCION (daemon, candidate, stats) so tests can
// drive it over an emulated network.
func dialRacing(ctx context.Context, d racingDial) (racingResult, error) {
	var res racingResult
	dctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil) // quic-go uses the dial context for the handshake only
	racer := newPathRacer(racerConfig{
		Remote:     d.Remote,
		Paths:      d.Paths,
		PathDelays: d.PathDelays,
		DelaySrcs:  d.DelaySrcs,
		PathDelay:  d.PathDelay,
		Fail:       cancel,
		Down:       d.Down,
	})
	// Dispatcherless snet (v0.12+): a concrete local IP, port 0 = a free
	// port from the topology's dispatched_ports range.
	sn := &snet.SCIONNetwork{Topology: d.Topology, SCMPHandler: racer}
	conn, err := sn.Listen(ctx, "udp", &net.UDPAddr{IP: d.LocalIP, Port: 0})
	if err != nil {
		_ = racer.Close()
		return res, fmt.Errorf("opening socket: %w", err)
	}
	racer.under = conn
	res.racer = racer

	tr := &quic.Transport{Conn: racer}
	// The dial address carries the top-ranked path; the racer overrides the
	// path per datagram. quic-go compares addresses by String(), which
	// omits the path.
	dialAddr := &snet.UDPAddr{
		IA:      d.Remote.IA,
		Host:    d.Remote.Host,
		Path:    d.Paths[0].Dataplane(),
		NextHop: d.Paths[0].UnderlayNextHop(),
	}
	start := time.Now()
	// InitialPacketSize pinned to the 1200-octet minimum, so the path MTU
	// check of selectPathSet matches what is sent.
	qconn, err := tr.Dial(dctx, dialAddr, d.TLS, &quic.Config{InitialPacketSize: quicMinDatagram})
	res.handshake = time.Since(start)
	if err != nil {
		_ = tr.Close()
		_ = racer.Close()
		return res, err
	}
	racer.markEstablished()
	res.conn, res.tr = qconn, tr
	return res, nil
}
