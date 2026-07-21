package hev3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	daemon_types "github.com/scionproto/scion/pkg/daemon/types"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/addrutil"
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
}

func (q daemonQuerier) Paths(ctx context.Context, dst addr.IA) ([]snet.Path, error) {
	return q.conn.Paths(ctx, dst, q.localIA, daemon_types.PathReqFlags{})
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
	return daemonQuerier{conn: conn, localIA: localIA}, nil
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

// ExpandSCION turns proto-SCION candidates (FamilySCION, no pinned Path) into
// dialable candidates. With a reachable daemon each proto-candidate becomes up
// to K native per-path candidates ranked by advertised latency then hop count,
// labelled "…#p1".."…#pK". With no daemon but an fc00 scitra route present,
// each becomes one ViaScitra candidate dialed as its mapped IPv6 address; with
// neither, the SCION candidates are dropped (recorded as Timeline "fail"
// notes). Non-SCION and already-expanded candidates pass through unchanged.
func ExpandSCION(ctx context.Context, cands []Candidate, o DialerOptions) []Candidate {
	k := o.K
	if k <= 0 {
		k = defaultK
	}

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

	out := passthrough
	var q pathQuerier
	var err error
	if o.SCION != nil {
		q, err = o.SCION.querier(ctx, o)
	} else {
		q, err = resolveQuerier(ctx, o)
	}
	if err != nil {
		// Daemon absent: fall back to scitra when the route exists, else drop.
		return append(out, fallbackNoDaemon(proto, o)...)
	}
	for _, c := range proto {
		out = append(out, expandOne(ctx, q, c, k, o)...)
	}
	return out
}

// expandOne queries and ranks paths for one proto-candidate and emits up to k
// native per-path candidates. A parse failure or a daemon that reports no paths
// drops the candidate with a Timeline note (the daemon is present, so scitra —
// the no-daemon fallback — does not apply here).
func expandOne(ctx context.Context, q pathQuerier, c Candidate, k int, o DialerOptions) []Candidate {
	dst, err := addr.ParseIA(c.IA)
	if err != nil {
		note(o, c, fmt.Sprintf("bad IA %q: %v", c.IA, err))
		return nil
	}
	paths, err := q.Paths(ctx, dst)
	if err != nil {
		note(o, c, fmt.Sprintf("path lookup failed: %v", err))
		return nil
	}
	if len(paths) == 0 {
		note(o, c, "no SCION paths")
		return nil
	}
	paths, failedOpen := filterByPolicy(paths, c.Policy)
	if failedOpen {
		note(o, c, "scion-policy thresholds exclude every path; ignored (fail-open)")
	}
	rankPaths(paths, c.Policy)
	if len(paths) > k {
		paths = paths[:k]
	}
	out := make([]Candidate, 0, len(paths))
	for i, p := range paths {
		md := p.Metadata()
		nc := c
		nc.Label = fmt.Sprintf("%s#p%d", c.Label, i+1)
		nc.Path = &SCIONPath{
			Fingerprint: snet.Fingerprint(md.Interfaces).String(),
			Latency:     knownLatency(md),
			Hops:        len(md.Interfaces),
			SNET:        p,
		}
		out = append(out, nc)
	}
	return out
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
	nc.Label = "scitra:" + c.IA + "," + mapped.String()
	return nc, nil
}

func note(o DialerOptions, c Candidate, detail string) {
	if o.Timeline != nil {
		o.Timeline.Add("fail", c.Label, detail)
	}
}

// knownLatency sums the advertised (non-negative) per-hop latencies; unset
// (negative) entries are skipped.
func knownLatency(md *snet.PathMetadata) time.Duration {
	var total time.Duration
	for _, d := range md.Latency {
		if d >= 0 {
			total += d
		}
	}
	return total
}

// pathKey is the ranking/filtering projection of a path's metadata: the
// aggregate metrics rankPaths and filterByPolicy compare paths on.
type pathKey struct {
	latUnset bool
	lat      time.Duration
	bwUnset  bool
	bw       uint64 // bottleneck: minimum announced hop bandwidth
	hops     int
	fp       string
}

func pathKeyOf(p snet.Path) pathKey {
	md := p.Metadata()
	k := pathKey{hops: len(md.Interfaces), fp: snet.Fingerprint(md.Interfaces).String()}
	for _, d := range md.Latency {
		if d < 0 {
			k.latUnset = true
		} else {
			k.lat += d
		}
	}
	if len(md.Bandwidth) == 0 {
		k.bwUnset = true
	}
	for _, bw := range md.Bandwidth {
		if bw == 0 {
			k.bwUnset = true
			continue
		}
		if k.bw == 0 || bw < k.bw {
			k.bw = bw
		}
	}
	return k
}

// metricCmp compares two paths on one metric; negative = a first. A path
// missing the metric always sorts after one that has it; bandwidth is
// better when larger.
func metricCmp(a, b pathKey, m PolicyMetric) int {
	switch m {
	case MetricLatency:
		switch {
		case a.latUnset && b.latUnset:
			return 0
		case a.latUnset:
			return 1
		case b.latUnset:
			return -1
		case a.lat != b.lat:
			if a.lat < b.lat {
				return -1
			}
			return 1
		}
	case MetricBandwidth:
		switch {
		case a.bwUnset && b.bwUnset:
			return 0
		case a.bwUnset:
			return 1
		case b.bwUnset:
			return -1
		case a.bw != b.bw:
			if a.bw > b.bw {
				return -1
			}
			return 1
		}
	case MetricHops:
		if a.hops != b.hops {
			return a.hops - b.hops
		}
	}
	return 0
}

// rankPaths orders paths by the policy's preference metrics (default:
// latency then hops), with the remaining default metrics as trailing
// tie-breaks and the fingerprint as the deterministic last resort.
func rankPaths(paths []snet.Path, policy *PathPolicy) {
	prefer := []PolicyMetric{MetricLatency, MetricHops}
	if policy != nil && len(policy.Prefer) > 0 {
		prefer = append([]PolicyMetric(nil), policy.Prefer...)
		for _, m := range []PolicyMetric{MetricLatency, MetricHops} {
			found := false
			for _, p := range prefer {
				if p == m {
					found = true
				}
			}
			if !found {
				prefer = append(prefer, m)
			}
		}
	}
	keys := make([]pathKey, len(paths))
	for i, p := range paths {
		keys[i] = pathKeyOf(p)
	}
	idx := make([]int, len(paths))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(i, j int) bool {
		a, b := keys[idx[i]], keys[idx[j]]
		for _, m := range prefer {
			if c := metricCmp(a, b, m); c != 0 {
				return c < 0
			}
		}
		return a.fp < b.fp
	})
	sorted := make([]snet.Path, len(paths))
	for i, j := range idx {
		sorted[i] = paths[j]
	}
	copy(paths, sorted)
}

// filterByPolicy drops paths that provably violate a threshold item; a
// path missing the relevant metric cannot violate it. If every path
// violates, thresholds are ignored entirely (draft fail-open MUST) and
// failedOpen reports it so the caller can leave a timeline note.
func filterByPolicy(paths []snet.Path, policy *PathPolicy) ([]snet.Path, bool) {
	if policy == nil || (policy.MaxLatency == 0 && policy.MinBandwidthKbps == 0) {
		return paths, false
	}
	var kept []snet.Path
	for _, p := range paths {
		k := pathKeyOf(p)
		if policy.MaxLatency > 0 && !k.latUnset && k.lat > policy.MaxLatency {
			continue
		}
		if policy.MinBandwidthKbps > 0 && !k.bwUnset && k.bw < policy.MinBandwidthKbps {
			continue
		}
		kept = append(kept, p)
	}
	if len(kept) == 0 {
		return paths, true
	}
	return kept, false
}

// dialSCION dials native HTTP/3 over SCION QUIC on the candidate's pinned path.
//
// It dials quic-go directly over an snet.Conn (quic.Transport{Conn: snetConn})
// rather than pkg/snet/squic: squic.ConnDialer wraps the QUIC session as a
// single-stream net.Conn for control-plane RPC, whereas HTTP/3 needs the raw
// *quic.Conn. The remote *snet.UDPAddr pins the dataplane path and next hop.
func dialSCION(ctx context.Context, c Candidate, o DialerOptions) (*Established, error) {
	if c.Path == nil {
		return nil, errors.New("hev3: dial scion: candidate has no pinned path")
	}
	p, ok := c.Path.SNET.(snet.Path)
	if !ok {
		return nil, fmt.Errorf("hev3: dial scion: pinned path is %T, not snet.Path", c.Path.SNET)
	}
	dstIA, err := addr.ParseIA(c.IA)
	if err != nil {
		return nil, fmt.Errorf("hev3: dial scion: bad IA %q: %w", c.IA, err)
	}
	host, err := netip.ParseAddr(c.Host)
	if err != nil {
		return nil, fmt.Errorf("hev3: dial scion: bad host %q: %w", c.Host, err)
	}

	// With a shared scionContext (o.SCION != nil) the daemon connect,
	// topology load, and local-IP resolution happen at most once per Fetch
	// (F12) and this call must never close that shared connector — it is
	// owned by o.SCION and released by scionContext.Close. With no shared
	// context (library callers, existing tests) this call owns the daemon
	// connection exactly as before: connect/load/resolve inline and close
	// it on every error path and on Established.Close.
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

	sn := &snet.SCIONNetwork{
		Topology: topo,
		SCMPHandler: snet.SCMPPropagationStopper{
			Handler: snet.DefaultSCMPHandler{
				RevocationHandler: daemon.RevHandler{Connector: sciond},
			},
		},
	}
	conn, err := sn.Listen(ctx, "udp", &net.UDPAddr{IP: localIP, Port: 0})
	if err != nil {
		if ownsConn {
			_ = sciond.Close()
		}
		return nil, fmt.Errorf("hev3: dial scion: opening socket: %w", err)
	}

	tr := &quic.Transport{Conn: conn}
	remote := &snet.UDPAddr{
		IA:      dstIA,
		Host:    net.UDPAddrFromAddrPort(netip.AddrPortFrom(host, c.Port)),
		Path:    p.Dataplane(),
		NextHop: p.UnderlayNextHop(),
	}
	qconn, err := tr.Dial(ctx, remote, h3TLSConfig(o.TLS, host.String()), nil)
	if err != nil {
		_ = tr.Close()
		_ = conn.Close()
		if ownsConn {
			_ = sciond.Close()
		}
		return nil, fmt.Errorf("hev3: dial scion %s: %w", remote, err)
	}
	return newH3Established(c, qconn, func() error {
		_ = tr.Close()
		_ = conn.Close()
		if ownsConn {
			return sciond.Close()
		}
		return nil
	}), nil
}
