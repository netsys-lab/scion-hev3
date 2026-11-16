package hev3

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/scionproto/scion/pkg/snet"
)

// Connection attempts over the candidate paths of one SCION endpoint
// (draft-john-scion-happy-eyeballs, "Attempts over Paths"): a separate QUIC
// connection per candidate path, each on its own socket and local port,
// each started one Path Attempt Delay after the previous one until all are
// started or one succeeds. The first handshake to complete establishes the
// connection; the other attempts are cancelled.
//
// Cancelling: quic-go cannot send CONNECTION_CLOSE for a dial that is
// cancelled before the handshake completes (it drops the connection
// silently, and the server keeps its state until its handshake timeout).
// A cancelled attempt is therefore left running for a short time (the
// linger time): if its handshake completes within it, the connection is
// closed at once with CONNECTION_CLOSE; otherwise it is dropped.

var (
	// errNoEligiblePath: no path to the endpoint's AS is eligible at the
	// time of the attempt. The engine attempts the next endpoint at once.
	errNoEligiblePath = errors.New("hev3: no eligible SCION path")
	// errAllAttemptsFailed fails an endpoint whose attempts over all
	// candidate paths failed.
	errAllAttemptsFailed = errors.New("hev3: the attempts over all candidate paths failed")
	errPathExpired       = errors.New("path expired")
)

const (
	minLinger = 50 * time.Millisecond
	maxLinger = time.Second
)

// pathConn is the net.PacketConn of one path attempt, between quic-go and
// the *snet.Conn: every datagram is sent on the attempt's path, whatever
// path the replies arrive on. It is also the socket's SCMP handler: SCMP
// errors are recorded and never end the attempt.
type pathConn struct {
	under   net.PacketConn // the *snet.Conn; set before the first read/write
	dst     *snet.UDPAddr  // remote with the attempt's dataplane path and next hop
	created time.Time

	sentPkts, sentBytes, recvPkts, recvBytes atomic.Int64
	closed                                   atomic.Bool

	mu   sync.Mutex
	scmp []SCMPEvent
}

func (c *pathConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	n, err := c.under.WriteTo(b, c.dst)
	if err == nil {
		c.sentPkts.Add(1)
		c.sentBytes.Add(int64(len(b)))
	}
	return n, err
}

func (c *pathConn) ReadFrom(b []byte) (int, net.Addr, error) {
	errs := 0
	for {
		n, a, err := c.under.ReadFrom(b)
		if err != nil {
			var ne net.Error
			if errors.Is(err, net.ErrClosed) || (errors.As(err, &ne) && ne.Timeout()) || c.closed.Load() {
				return n, a, err
			}
			// A per-packet snet error: quic-go would close its transport
			// on it, so drop the packet instead.
			errs++
			if errs > readErrorBudget {
				return n, a, err
			}
			continue
		}
		c.recvPkts.Add(1)
		c.recvBytes.Add(int64(n))
		return n, a, nil
	}
}

func (c *pathConn) Close() error {
	c.closed.Store(true)
	if c.under == nil {
		return nil
	}
	return c.under.Close()
}

func (c *pathConn) LocalAddr() net.Addr                { return c.under.LocalAddr() }
func (c *pathConn) SetDeadline(t time.Time) error      { return c.under.SetDeadline(t) }
func (c *pathConn) SetReadDeadline(t time.Time) error  { return c.under.SetReadDeadline(t) }
func (c *pathConn) SetWriteDeadline(t time.Time) error { return c.under.SetWriteDeadline(t) }

// Handle implements snet.SCMPHandler. It records the error and returns nil:
// an SCMP error does not end the attempt, and a non-nil error would close
// quic-go's transport.
func (c *pathConn) Handle(pkt *snet.Packet) error {
	ev := SCMPEvent{AtMs: msec(time.Since(c.created)), Path: -1}
	switch m := pkt.Payload.(type) {
	case snet.SCMPExternalInterfaceDown:
		ev.Type, ev.IA, ev.IfID = "external-interface-down", m.IA.String(), m.Interface
	case snet.SCMPInternalConnectivityDown:
		ev.Type, ev.IA, ev.IfID = "internal-connectivity-down", m.IA.String(), m.Egress
	case snet.SCMPParameterProblem:
		ev.Type = "parameter-problem"
	case snet.SCMPDestinationUnreachable:
		ev.Type = "destination-unreachable"
	case snet.SCMPPacketTooBig:
		ev.Type = "packet-too-big"
	default:
		ev.Type = fmt.Sprintf("%T", pkt.Payload)
	}
	ev.Ignored = "SCMP errors do not end an attempt"
	c.mu.Lock()
	c.scmp = append(c.scmp, ev)
	c.mu.Unlock()
	return nil
}

// attemptsDial is the input of dialAttempts.
type attemptsDial struct {
	Remote   *snet.UDPAddr // remote IA + host:port
	Paths    []snet.Path   // candidate paths, in attempt order
	Delay    time.Duration // Path Attempt Delay
	Topology snet.Topology
	LocalIP  net.IP
	TLS      *tls.Config
	// Linger: how long a cancelled attempt may go on so that it can be
	// closed with CONNECTION_CLOSE. 0 = twice the time since the first
	// attempt started, within [50 ms, 1 s]; negative = drop at once.
	Linger  time.Duration
	OnStart func(time.Time) // called when a path attempt starts; may be nil
	// Reserve, if set, is called before an attempt over the second or a
	// further path: it returns 0 and records the start if no other
	// connection attempt started within the last 10 ms, else how long to
	// wait. It keeps the 10 ms between these attempts and attempts to other
	// endpoints.
	Reserve func() time.Duration
	BG      *sync.WaitGroup // tracks attempts still running after the return; may be nil
}

// pathAttempt is one attempt over one candidate path.
type pathAttempt struct {
	stats   PathAttemptStats
	expiry  time.Time
	pc      *pathConn
	cancel  context.CancelFunc
	started bool
	done    bool
}

// attemptSet is the state of the attempts to one SCION endpoint.
type attemptSet struct {
	mu      sync.Mutex
	start   time.Time
	delay   time.Duration
	decided bool // an attempt has succeeded, or the endpoint was cancelled
	winner  int  // index into paths; -1 = none
	paths   []*pathAttempt
}

// snapshot returns the current statistics of the attempts.
func (s *attemptSet) snapshot() (winner int, out []PathAttemptStats) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, pa := range s.paths {
		st := pa.stats
		if pc := pa.pc; pc != nil {
			st.SentPkts, st.SentBytes = int(pc.sentPkts.Load()), int(pc.sentBytes.Load())
			st.RecvPkts, st.RecvBytes = int(pc.recvPkts.Load()), int(pc.recvBytes.Load())
			pc.mu.Lock()
			st.SCMP = append([]SCMPEvent(nil), pc.scmp...)
			pc.mu.Unlock()
		}
		if !pa.started {
			st.Outcome = "not-started"
		} else if !pa.done {
			st.Outcome = "in-progress"
		}
		out = append(out, st)
	}
	return s.winner + 1, out
}

type attemptsResult struct {
	set       *attemptSet
	winner    int // index into the dial's Paths
	conn      *quic.Conn
	tr        *quic.Transport
	pc        *pathConn
	handshake time.Duration // first attempt's start to the result
}

type attemptOutcome struct {
	i    int
	conn *quic.Conn
	tr   *quic.Transport
	pc   *pathConn
	err  error
}

// dialAttempts attempts a QUIC connection to d.Remote over each of d.Paths.
// On success the winning connection is returned; the caller closes conn,
// tr and pc. The returned attemptSet is never nil.
func dialAttempts(ctx context.Context, d attemptsDial) (attemptsResult, error) {
	d.Delay = pathAttemptDelay(d.Delay, 0) // default 50 ms; MUST NOT be below 10 ms
	n := len(d.Paths)
	set := &attemptSet{start: time.Now(), delay: d.Delay, winner: -1}
	for i, p := range d.Paths {
		pa := &pathAttempt{stats: PathAttemptStats{Rank: i + 1}}
		if md := p.Metadata(); md != nil {
			pa.stats.Fingerprint = snet.Fingerprint(md.Interfaces).String()
			pa.stats.Interfaces = interfacesString(md)
			pa.expiry = md.Expiry
		} else {
			pa.stats.Interfaces = interfacesString(nil)
		}
		set.paths = append(set.paths, pa)
	}
	res := attemptsResult{set: set, winner: -1}
	if n == 0 {
		return res, errNoEligiblePath
	}
	results := make(chan attemptOutcome, n)

	startOne := func(i int) {
		pa := set.paths[i]
		now := time.Now()
		if !pa.expiry.IsZero() && !now.Before(pa.expiry) {
			// A connection attempt is not started on an expired path.
			set.mu.Lock()
			pa.started, pa.done = true, true
			pa.stats.Started = false
			pa.stats.Outcome, pa.stats.Err = "failed", errPathExpired.Error()
			set.mu.Unlock()
			results <- attemptOutcome{i: i, err: errPathExpired}
			return
		}
		// The attempt has its own lifetime: it outlives ctx for the linger
		// time, and it fails when its path expires.
		base := context.WithoutCancel(ctx)
		var actx context.Context
		var cancel context.CancelFunc
		if pa.expiry.IsZero() {
			actx, cancel = context.WithCancel(base)
		} else {
			actx, cancel = context.WithDeadline(base, pa.expiry)
		}
		set.mu.Lock()
		pa.started = true
		pa.cancel = cancel
		pa.stats.Started = true
		pa.stats.StartMs = msec(now.Sub(set.start))
		set.mu.Unlock()
		if d.OnStart != nil {
			d.OnStart(now)
		}
		if d.BG != nil {
			d.BG.Add(1)
		}
		go func() {
			if d.BG != nil {
				defer d.BG.Done()
			}
			defer cancel()
			conn, tr, pc, err := dialOnePath(actx, d, set, i)
			hs := time.Since(now)
			set.mu.Lock()
			pa.done = true
			pa.stats.HandshakeMs = msec(hs)
			won := err == nil && !set.decided
			switch {
			case won:
				set.decided, set.winner = true, i
				pa.stats.Outcome = "won"
			case err == nil:
				pa.stats.Outcome = "closed" // handshake done after the decision: CONNECTION_CLOSE sent
			case set.decided:
				pa.stats.Outcome, pa.stats.Err = "cancelled", err.Error()
			default:
				pa.stats.Outcome, pa.stats.Err = "failed", err.Error()
			}
			set.mu.Unlock()
			if err == nil && !won {
				_ = conn.CloseWithError(0, "")
				_ = tr.Close()
				_ = pc.Close()
				err = context.Canceled
			}
			results <- attemptOutcome{i: i, conn: conn, tr: tr, pc: pc, err: err}
		}()
	}

	// cancelOthers cancels every attempt but keep that has started and not
	// finished, at once or after the linger time.
	cancelOthers := func(keep int) {
		linger := d.Linger
		if linger == 0 {
			linger = min(max(2*time.Since(set.start), minLinger), maxLinger)
		}
		set.mu.Lock()
		defer set.mu.Unlock()
		for i, pa := range set.paths {
			if i == keep || !pa.started || pa.done || pa.cancel == nil {
				continue
			}
			if linger < 0 {
				pa.cancel()
			} else {
				time.AfterFunc(linger, pa.cancel)
			}
		}
	}
	succeed := func(o attemptOutcome) (attemptsResult, error) {
		res.winner, res.conn, res.tr, res.pc = o.i, o.conn, o.tr, o.pc
		res.handshake = time.Since(set.start)
		cancelOthers(o.i)
		return res, nil
	}

	startOne(0)
	next := 1
	timer := time.NewTimer(d.Delay)
	defer timer.Stop()
	if next >= n {
		timer.Stop()
	}
	var errs []error
	for {
		select {
		case <-timer.C:
			if next < n {
				if d.Reserve != nil {
					if wait := d.Reserve(); wait > 0 {
						timer.Reset(wait)
						continue
					}
				}
				startOne(next)
				next++
				if next < n {
					timer.Reset(d.Delay)
				}
			}
		case o := <-results:
			if o.err == nil {
				return succeed(o)
			}
			errs = append(errs, fmt.Errorf("path %d: %w", o.i+1, o.err))
			if len(errs) == n {
				res.handshake = time.Since(set.start)
				return res, errors.Join(append([]error{errAllAttemptsFailed}, errs...)...)
			}
		case <-ctx.Done():
			set.mu.Lock()
			w := set.winner
			set.decided = true
			set.mu.Unlock()
			if w >= 0 {
				// An attempt succeeded as the endpoint was cancelled:
				// hand the connection over; the caller closes it.
				for o := range results {
					if o.i == w {
						return succeed(o)
					}
				}
			}
			res.handshake = time.Since(set.start)
			cancelOthers(-1)
			return res, ctx.Err()
		}
	}
}

// dialOnePath opens a socket of its own (so the attempt has a local port of
// its own) and dials one QUIC connection over path i.
func dialOnePath(ctx context.Context, d attemptsDial, set *attemptSet, i int) (*quic.Conn, *quic.Transport, *pathConn, error) {
	p := d.Paths[i]
	pc := &pathConn{
		dst: &snet.UDPAddr{
			IA:      d.Remote.IA,
			Host:    d.Remote.Host,
			Path:    p.Dataplane(),
			NextHop: p.UnderlayNextHop(),
		},
		created: time.Now(),
	}
	// Dispatcherless snet: a concrete local IP, port 0 = a free port from
	// the topology's dispatched_ports range. The pathConn handles SCMP, so
	// an SCMP error neither ends the attempt nor closes the socket.
	sn := &snet.SCIONNetwork{Topology: d.Topology, SCMPHandler: pc}
	conn, err := sn.Listen(ctx, "udp", &net.UDPAddr{IP: d.LocalIP, Port: 0})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("opening socket: %w", err)
	}
	pc.under = conn
	set.mu.Lock()
	set.paths[i].pc = pc
	if la, ok := conn.LocalAddr().(*snet.UDPAddr); ok && la.Host != nil {
		set.paths[i].stats.LocalPort = la.Host.Port
	}
	set.mu.Unlock()

	tr := &quic.Transport{Conn: pc}
	// InitialPacketSize pinned to the 1200-octet minimum, so the eligibility
	// check (path MTU) matches what is sent. No session cache: no ticket,
	// token or early data is used in any attempt.
	qconn, err := tr.Dial(ctx, pc.dst, d.TLS.Clone(), &quic.Config{InitialPacketSize: quicMinDatagram})
	if err != nil {
		_ = tr.Close()
		_ = pc.Close()
		return nil, nil, pc, err
	}
	return qconn, tr, pc, nil
}

type pathStartHookKey struct{}

// withPathStartHook records in ctx a function the SCION dialer calls when
// it starts an attempt over a path.
func withPathStartHook(ctx context.Context, f func(time.Time)) context.Context {
	return context.WithValue(ctx, pathStartHookKey{}, f)
}

func pathStartHookFrom(ctx context.Context) func(time.Time) {
	f, _ := ctx.Value(pathStartHookKey{}).(func(time.Time))
	return f
}

type pathAttemptGateKey struct{}

// withPathAttemptGate records in ctx a function the SCION dialer calls
// before it starts an attempt over a further path (attemptsDial.Reserve).
func withPathAttemptGate(ctx context.Context, f func() time.Duration) context.Context {
	return context.WithValue(ctx, pathAttemptGateKey{}, f)
}

func pathAttemptGateFrom(ctx context.Context) func() time.Duration {
	f, _ := ctx.Value(pathAttemptGateKey{}).(func() time.Duration)
	return f
}
