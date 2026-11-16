package hev3

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"
)

// pathRacer races the paths of a SCION endpoint's path set within ONE QUIC
// connection (draft-john-scion-happy-eyeballs, "Racing Paths Within One QUIC
// Connection"). It is a net.PacketConn between quic-go and the *snet.Conn,
// so quic-go is unchanged: quic-go sees one peer address, and the racer
// decides which SCION path(s) each datagram goes out on.
//
// Before a path is selected, every datagram quic-go writes is stored and
// sent, with an identical UDP payload, on every added path that has not
// failed. The top-ranked path is added first; the next-ranked path is added
// every Path Delay while nothing is selected, and at once when every added
// path has failed. A newly added path first gets copies of all stored
// datagrams, in order. When every path of the set has failed, the attempt
// is failed through the fail callback (which cancels the dial context).
//
// A path is selected when (a) a datagram arrives from the remote whose
// (reversed) path matches, by hop-field interface IDs, an added set path
// that has not failed, and whose first QUIC packet carries a Destination
// Connection ID the client chose (so a late datagram of an earlier
// connection on the same SCION addresses and ports does not select), or (b)
// quic-go sends its first 1-RTT packet, in which case the reversed path of
// the most recently received datagram is taken if it matches a set path,
// else the highest-ranked added path that has not failed. After selection
// only the selected path is used.
//
// The racer is also the snet.SCMPHandler of its socket: External Interface
// Down and Internal Connectivity Down errors that quote a datagram sent on
// one of its paths to the remote fail that path and enter the process-wide
// down cache. It always returns nil, because a non-nil error would surface
// from ReadFrom and quic-go closes its transport on read errors.
type pathRacer struct {
	under     net.PacketConn // the *snet.Conn; set before the first read/write
	remote    *snet.UDPAddr  // remote IA + host:port; Path/NextHop ignored
	remoteIP  netip.Addr
	allAtOnce bool // add all paths at the start (no Path Delay)
	fail      func(error)
	down      *downCache
	clock     func() time.Time

	mu          sync.Mutex
	created     time.Time
	started     bool
	startAt     time.Time
	paths       []*racerPath
	stored      [][]byte
	selected    int // index into paths; -1 = none
	lastAdded   int // index of the most recently added path; -1 = none
	selReason   string
	selAt       time.Duration
	lastRecv    int // path index of the most recent datagram from the remote; -1 = none/unmatched
	established bool
	closed      bool
	failErr     error
	timer       *time.Timer
	scmp        []SCMPEvent
	recvPkts    int
	recvBytes   int
	recvForeign int      // datagrams from the remote ignored before selection: not for this connection's CIDs
	scids       [][]byte // Source Connection IDs of the client's long-header packets
}

type racerPath struct {
	rank    int
	fp      string
	ifaces  string
	dst     *snet.UDPAddr // remote with this path's dataplane and next hop
	pairs   []hopPair
	pairsOK bool
	expiry  time.Time
	expT    *time.Timer

	added      bool
	addedAt    time.Duration
	addReason  string
	delay      time.Duration // Path Delay that follows the adding of this path
	delaySrc   string        // history / metadata / default / fixed
	failed     bool
	failReason string
	pkts       int // datagrams sent on this path (copies included)
	copies     int // of which copies of stored datagrams, sent when added
	bytes      int // UDP payload octets sent
}

// errAllPathsFailed fails an attempt whose whole path set has failed.
var errAllPathsFailed = errors.New("hev3: all SCION paths of the path set failed")

// racerConfig configures newPathRacer.
type racerConfig struct {
	Remote *snet.UDPAddr
	Paths  []snet.Path // ranked path set (rank order)
	// PathDelays[i] is the Path Delay that follows the adding of path i,
	// DelaySrcs[i] its source (stats only). If PathDelays is nil, every
	// path uses PathDelay, and PathDelay <= 0 adds all paths at once.
	PathDelays []time.Duration
	DelaySrcs  []string
	PathDelay  time.Duration
	Fail       func(error)
	Down       *downCache
	Clock      func() time.Time // nil = time.Now
}

func newPathRacer(c racerConfig) *pathRacer {
	clock := c.Clock
	if clock == nil {
		clock = time.Now
	}
	ip, _ := netip.AddrFromSlice(c.Remote.Host.IP)
	if c.Down == nil {
		c.Down = scmpDownCache
	}
	r := &pathRacer{
		remote:    c.Remote,
		remoteIP:  ip.Unmap(),
		allAtOnce: c.PathDelays == nil && c.PathDelay <= 0,
		fail:      c.Fail,
		down:      c.Down,
		clock:     clock,
		created:   clock(),
		selected:  -1,
		lastAdded: -1,
		lastRecv:  -1,
	}
	for i, p := range c.Paths {
		md := p.Metadata()
		rp := &racerPath{
			rank: i,
			dst: &snet.UDPAddr{
				IA:      c.Remote.IA,
				Host:    c.Remote.Host,
				Path:    p.Dataplane(),
				NextHop: p.UnderlayNextHop(),
			},
		}
		rp.pairs, rp.pairsOK = hopPairsOf(p.Dataplane())
		rp.delay = c.PathDelay
		if i < len(c.PathDelays) {
			rp.delay = c.PathDelays[i]
		}
		if i < len(c.DelaySrcs) {
			rp.delaySrc = c.DelaySrcs[i]
		}
		if md != nil {
			rp.fp = snet.Fingerprint(md.Interfaces).String()
			rp.ifaces = interfacesString(md)
			rp.expiry = md.Expiry
		}
		r.paths = append(r.paths, rp)
	}
	r.mu.Lock()
	for i, rp := range r.paths {
		if rp.expiry.IsZero() {
			continue
		}
		d := rp.expiry.Sub(r.created)
		if d <= 0 {
			rp.failed, rp.failReason = true, "expired"
			continue
		}
		idx := i
		rp.expT = time.AfterFunc(d, func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.failPathLocked(idx, "expired")
		})
	}
	r.mu.Unlock()
	return r
}

func (r *pathRacer) since() time.Duration { return r.clock().Sub(r.created) }

// --- net.PacketConn --------------------------------------------------------

func (r *pathRacer) WriteTo(b []byte, _ net.Addr) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, net.ErrClosed
	}
	if !r.started {
		r.startLocked()
	}
	if r.selected < 0 {
		r.noteSCIDLocked(b)
	}
	if r.selected < 0 && containsOneRTT(b) {
		r.selectLocked(r.oneRTTChoiceLocked(), "1rtt")
	}
	if r.selected >= 0 {
		r.sendLocked(r.paths[r.selected], b, false)
		return len(b), nil
	}
	r.stored = append(r.stored, append([]byte(nil), b...))
	for _, rp := range r.paths {
		if rp.added && !rp.failed {
			r.sendLocked(rp, b, false)
		}
	}
	return len(b), nil
}

// readErrorBudget bounds how many consecutive per-packet snet read errors
// ReadFrom swallows before reporting one (so a persistent socket error is
// not spun on forever).
const readErrorBudget = 64

func (r *pathRacer) ReadFrom(b []byte) (int, net.Addr, error) {
	errs := 0
	for {
		n, a, err := r.under.ReadFrom(b)
		if err != nil {
			var ne net.Error
			if errors.Is(err, net.ErrClosed) || (errors.As(err, &ne) && ne.Timeout()) || r.isClosed() {
				return n, a, err
			}
			// A per-packet snet error (undecodable packet, wrong
			// destination): quic-go would close its transport on it, so
			// drop the packet instead.
			errs++
			if errs > readErrorBudget {
				return n, a, err
			}
			continue
		}
		if ua, ok := a.(*snet.UDPAddr); ok && r.isRemote(ua) {
			pairs, pok := hopPairsOf(ua.Path)
			r.mu.Lock()
			r.onRecvLocked(b[:n], pairs, pok)
			r.mu.Unlock()
		}
		return n, a, nil
	}
}

// onRecvLocked applies selection rule (a) to a datagram from the remote
// whose reversed path has hop pairs pairs (pok false: undecodable path).
// Before selection, a datagram counts only if its first packet is addressed
// to a connection ID of this connection; it then selects its path if that
// path is an added set path that has not failed, and is remembered for rule
// (b) if it is any set path.
func (r *pathRacer) onRecvLocked(b []byte, pairs []hopPair, pok bool) {
	r.recvPkts++
	r.recvBytes += len(b)
	if r.selected >= 0 {
		return
	}
	if !r.ownCIDLocked(b) {
		r.recvForeign++
		return
	}
	idx := -1
	if pok {
		idx = r.matchLocked(pairs, false)
	}
	r.lastRecv = idx
	if idx >= 0 && r.paths[idx].added && !r.paths[idx].failed {
		r.selectLocked(idx, "reply")
	}
}

// noteSCIDLocked records the Source Connection ID of a client datagram's
// first packet, if it has a long header (RFC 9000 Sec 17.2).
func (r *pathRacer) noteSCIDLocked(b []byte) {
	if len(b) < 6 || b[0]&0x80 == 0 {
		return
	}
	off := 6 + int(b[5])
	if off >= len(b) {
		return
	}
	scil := int(b[off])
	if off+1+scil > len(b) {
		return
	}
	scid := b[off+1 : off+1+scil]
	for _, c := range r.scids {
		if string(c) == string(scid) {
			return
		}
	}
	r.scids = append(r.scids, append([]byte(nil), scid...))
}

// ownCIDLocked reports whether the first packet of a datagram from the
// server carries, as its Destination Connection ID, a Source Connection ID
// the client used (RFC 9000 Sec 7.2: until the handshake completes, the
// server addresses the client by the client's chosen connection ID). A
// short header does not encode the DCID length; the length of the client's
// connection ID is used. Nothing is "own" before the client has sent.
func (r *pathRacer) ownCIDLocked(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range r.scids {
		var dcid []byte
		if b[0]&0x80 != 0 {
			if len(b) < 6 || len(b) < 6+int(b[5]) {
				return false
			}
			dcid = b[6 : 6+int(b[5])]
		} else {
			if len(b) < 1+len(c) {
				continue
			}
			dcid = b[1 : 1+len(c)]
		}
		if string(dcid) == string(c) {
			return true
		}
	}
	return false
}

func (r *pathRacer) Close() error {
	r.mu.Lock()
	r.closed = true
	r.stopTimersLocked()
	for _, rp := range r.paths {
		if rp.expT != nil {
			rp.expT.Stop()
		}
	}
	r.stored = nil
	under := r.under
	r.mu.Unlock()
	if under == nil {
		return nil
	}
	return under.Close()
}

func (r *pathRacer) LocalAddr() net.Addr                { return r.under.LocalAddr() }
func (r *pathRacer) SetDeadline(t time.Time) error      { return r.under.SetDeadline(t) }
func (r *pathRacer) SetReadDeadline(t time.Time) error  { return r.under.SetReadDeadline(t) }
func (r *pathRacer) SetWriteDeadline(t time.Time) error { return r.under.SetWriteDeadline(t) }

func (r *pathRacer) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

func (r *pathRacer) isRemote(ua *snet.UDPAddr) bool {
	if ua.IA != r.remote.IA || ua.Host == nil || ua.Host.Port != r.remote.Host.Port {
		return false
	}
	ip, ok := netip.AddrFromSlice(ua.Host.IP)
	return ok && ip.Unmap() == r.remoteIP
}

// --- racing state (r.mu held) ----------------------------------------------

// startLocked runs on the first datagram: the attempt starts with the
// top-ranked path, or with all paths at once if so configured.
func (r *pathRacer) startLocked() {
	r.started = true
	r.startAt = r.clock()
	if r.allAtOnce {
		for r.addNextLocked("start") {
		}
		r.checkAllFailedLocked()
		return
	}
	r.addNextLocked("start")
	r.armLocked()
	r.checkAllFailedLocked()
}

// armLocked arms the timer that adds the next path after the Path Delay
// of the most recently added path.
func (r *pathRacer) armLocked() {
	if r.allAtOnce || r.lastAdded < 0 || r.selected >= 0 || r.closed || !r.hasUnaddedLocked() {
		return
	}
	if r.timer != nil {
		r.timer.Stop()
	}
	r.timer = time.AfterFunc(r.paths[r.lastAdded].delay, r.onPathDelay)
}

func (r *pathRacer) onPathDelay() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.selected >= 0 || r.failErr != nil {
		return
	}
	r.addNextLocked("path-delay")
	r.armLocked()
}

func (r *pathRacer) hasUnaddedLocked() bool {
	for _, rp := range r.paths {
		if !rp.added && !rp.failed {
			return true
		}
	}
	return false
}

// addNextLocked adds the next-ranked path that is neither added nor failed
// and sends it copies of the stored datagrams. It reports whether a path
// was added.
func (r *pathRacer) addNextLocked(reason string) bool {
	for _, rp := range r.paths {
		if rp.added || rp.failed {
			continue
		}
		if !rp.expiry.IsZero() && !r.clock().Before(rp.expiry) {
			rp.failed, rp.failReason = true, "expired"
			continue
		}
		rp.added = true
		rp.addedAt = r.since()
		rp.addReason = reason
		r.lastAdded = rp.rank
		for _, d := range r.stored {
			r.sendLocked(rp, d, true)
		}
		return true
	}
	return false
}

func (r *pathRacer) sendLocked(rp *racerPath, b []byte, isCopy bool) {
	if _, err := r.under.WriteTo(b, rp.dst); err != nil {
		return // a local send error; the path keeps its state
	}
	rp.pkts++
	rp.bytes += len(b)
	if isCopy {
		rp.copies++
	}
}

func (r *pathRacer) selectLocked(idx int, reason string) {
	if idx < 0 || r.selected >= 0 {
		return
	}
	rp := r.paths[idx]
	r.selected = idx
	r.selReason = reason
	r.selAt = r.since()
	if !rp.added {
		rp.added = true
		rp.addedAt = r.selAt
		rp.addReason = "selected"
	}
	r.stored = nil
	r.stopTimersLocked()
}

func (r *pathRacer) stopTimersLocked() {
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
}

// oneRTTChoiceLocked implements rule (b): the path of the most recently
// received datagram if it matches a set path that has not failed, else the
// highest-ranked added path that has not failed.
func (r *pathRacer) oneRTTChoiceLocked() int {
	if r.lastRecv >= 0 && !r.paths[r.lastRecv].failed {
		return r.lastRecv
	}
	for i, rp := range r.paths {
		if rp.added && !rp.failed {
			return i
		}
	}
	return -1
}

// matchLocked returns the index of the set path whose hop pairs equal
// pairs, or -1. With addedOnly, only paths the racer has sent on match.
func (r *pathRacer) matchLocked(pairs []hopPair, addedOnly bool) int {
	for i, rp := range r.paths {
		if !rp.pairsOK || (addedOnly && !rp.added) {
			continue
		}
		if hopPairsEqual(rp.pairs, pairs) {
			return i
		}
	}
	return -1
}

func (r *pathRacer) failPathLocked(idx int, reason string) {
	rp := r.paths[idx]
	if rp.failed {
		return
	}
	rp.failed = true
	rp.failReason = reason
	if rp.expT != nil {
		rp.expT.Stop()
	}
	if r.closed {
		return
	}
	if r.selected >= 0 {
		if idx == r.selected && !r.established {
			r.failAttemptLocked(fmt.Errorf("hev3: selected SCION path %d failed before the handshake completed: %s", idx+1, reason))
		}
		// After the handshake a failed selected path is left to QUIC
		// (recorded in the stats only).
		return
	}
	r.checkAllFailedLocked()
}

// checkAllFailedLocked adds the next path when every added path has failed,
// and fails the attempt when no path of the set is left.
func (r *pathRacer) checkAllFailedLocked() {
	if r.selected >= 0 || r.failErr != nil {
		return
	}
	for _, rp := range r.paths {
		if rp.added && !rp.failed {
			return
		}
	}
	if r.started && r.addNextLocked("all-added-failed") {
		r.armLocked()
		return
	}
	for _, rp := range r.paths {
		if !rp.failed {
			return // not started yet; a path is still available
		}
	}
	r.failAttemptLocked(errAllPathsFailed)
}

func (r *pathRacer) failAttemptLocked(err error) {
	if r.failErr != nil {
		return
	}
	r.failErr = err
	r.stopTimersLocked()
	if r.fail != nil {
		r.fail(err)
	}
}

// markEstablished records that the QUIC handshake completed: from now on a
// failure of the selected path is QUIC's business.
func (r *pathRacer) markEstablished() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.established = true
	if r.selected < 0 {
		// The handshake completed without rule (a) or (b) firing (cannot
		// normally happen: completing it requires a 1-RTT packet); select
		// by rule (b) so later datagrams use one path.
		r.selectLocked(r.oneRTTChoiceLocked(), "established")
	}
}

// historySource describes what historical RTT data the connection can give
// its selected path (fingerprint fp). QUIC measures RTT samples from the
// time it sent a packet; for a packet copied to a path added later that is
// earlier than the copy, so QUIC's estimate is a sample of the selected
// path only if that path was added at the start (fromStart). Otherwise
// sample is the time from the adding of the selected path to the datagram
// that selected it (0 if it was not selected on a reply).
func (r *pathRacer) historySource() (fp string, fromStart bool, sample time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.selected < 0 {
		return "", false, 0
	}
	rp := r.paths[r.selected]
	if rp.addReason == "start" {
		return rp.fp, true, 0
	}
	if r.selReason == "reply" && r.selAt > rp.addedAt {
		sample = r.selAt - rp.addedAt
	}
	return rp.fp, false, sample
}

// --- SCMP --------------------------------------------------------------------

// Handle implements snet.SCMPHandler. It always returns nil.
func (r *pathRacer) Handle(pkt *snet.Packet) error {
	var (
		ev    SCMPEvent
		quote []byte
		ia    addr.IA
		ifid  uint64
	)
	switch m := pkt.Payload.(type) {
	case snet.SCMPExternalInterfaceDown:
		ev.Type, ia, ifid, quote = "external-interface-down", m.IA, m.Interface, m.Payload
	case snet.SCMPInternalConnectivityDown:
		// The default snet handler revokes the egress interface; do the same.
		ev.Type, ia, ifid, quote = "internal-connectivity-down", m.IA, m.Egress, m.Payload
	default:
		return nil
	}
	ev.IA, ev.IfID = ia.String(), ifid
	ev.Path = -1
	idx, why := r.matchQuote(quote)
	r.mu.Lock()
	defer r.mu.Unlock()
	ev.AtMs = msec(r.since())
	if idx >= 0 {
		ev.Path = idx + 1
		r.down.add(ia, ifid, r.clock())
		r.failPathLocked(idx, fmt.Sprintf("SCMP %s %s#%d", ev.Type, ia, ifid))
	} else {
		ev.Ignored = why
	}
	r.scmp = append(r.scmp, ev)
	return nil
}

// matchQuote decodes the offending packet quoted in an SCMP error and returns
// the index of the added set path it was sent on, if its destination is the
// remote. The quote may be truncated; only the SCION header (and the UDP
// destination port, when present) is needed.
func (r *pathRacer) matchQuote(quote []byte) (int, string) {
	var scn slayers.SCION
	if err := scn.DecodeFromBytes(quote, gopacket.NilDecodeFeedback); err != nil {
		return -1, "undecodable quote"
	}
	if scn.DstIA != r.remote.IA {
		return -1, "quote not to remote"
	}
	dst, err := scn.DstAddr()
	if err != nil || dst.Type() != addr.HostTypeIP || dst.IP().Unmap() != r.remoteIP {
		return -1, "quote not to remote"
	}
	if hl := int(scn.HdrLen) * 4; scn.NextHdr == slayers.L4UDP && len(quote) >= hl+4 {
		if int(binary.BigEndian.Uint16(quote[hl+2:hl+4])) != r.remote.Host.Port {
			return -1, "quote not to remote"
		}
	}
	pairs, ok := hopPairsOfPath(scn.Path)
	if !ok {
		return -1, "undecodable quoted path"
	}
	r.mu.Lock()
	idx := r.matchLocked(pairs, true)
	r.mu.Unlock()
	if idx < 0 {
		return -1, "quoted path not sent on"
	}
	return idx, ""
}

// --- stats -------------------------------------------------------------------

// Stats snapshots the racer's per-attempt statistics.
func (r *pathRacer) Stats() RacerStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := RacerStats{
		AllAtOnce:    r.allAtOnce,
		Selected:     0,
		SelectReason: r.selReason,
		SCMP:         append([]SCMPEvent(nil), r.scmp...),
		RecvPkts:     r.recvPkts,
		RecvBytes:    r.recvBytes,
		RecvForeign:  r.recvForeign,
	}
	if r.selected >= 0 {
		st.Selected = r.selected + 1
		st.SelectedAtMs = msec(r.selAt)
	}
	if r.started {
		st.FirstSendMs = msec(r.startAt.Sub(r.created))
	}
	for _, rp := range r.paths {
		ps := PathStats{
			Rank:        rp.rank + 1,
			Fingerprint: rp.fp,
			Interfaces:  rp.ifaces,
			Added:       rp.added,
			AddReason:   rp.addReason,
			Failed:      rp.failed,
			FailReason:  rp.failReason,
			Pkts:        rp.pkts,
			Copies:      rp.copies,
			Bytes:       rp.bytes,
		}
		if !r.allAtOnce {
			ps.DelayMs, ps.DelaySrc = msec(rp.delay), rp.delaySrc
		}
		if rp.added {
			ps.AddedAtMs = msec(rp.addedAt)
		}
		st.Paths = append(st.Paths, ps)
	}
	if !r.allAtOnce && len(r.paths) > 0 {
		st.PathDelayMs = msec(r.paths[0].delay)
	}
	return st
}

func msec(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// --- QUIC wire parsing -------------------------------------------------------

const (
	quicV1 = 0x00000001
	quicV2 = 0x6b3343cf
)

// containsOneRTT reports whether a client datagram contains a 1-RTT
// (short-header) packet. It walks the coalesced packets (RFC 9000 Sec
// 12.2): a long-header packet carries version, DCID and SCID; an Initial
// also a token; Initial, 0-RTT and Handshake packets then carry a Length
// field covering the rest of the packet. A short-header packet has no
// length and can only be the last packet of the datagram. Version
// Negotiation and Retry packets are never sent by clients; an unknown
// version or a malformed packet stops the walk (no 1-RTT found).
func containsOneRTT(b []byte) bool {
	for len(b) > 0 {
		first := b[0]
		if first&0x80 == 0 {
			// Short header: 1-RTT, if the fixed bit is set (quic-go does
			// not grease it); zero padding after the last packet is not.
			return first&0x40 != 0
		}
		if len(b) < 7 {
			return false
		}
		version := binary.BigEndian.Uint32(b[1:5])
		typ := (first >> 4) & 0x3
		var initial, retry bool
		switch version {
		case quicV1:
			initial, retry = typ == 0, typ == 3
		case quicV2: // RFC 9369 Sec 3.2: Initial 0b01, Retry 0b00
			initial, retry = typ == 1, typ == 0
		default:
			return false // version negotiation or unknown version
		}
		if retry {
			return false
		}
		off := 5
		dcil := int(b[off])
		off += 1 + dcil
		if off >= len(b) {
			return false
		}
		scil := int(b[off])
		off += 1 + scil
		if off > len(b) {
			return false
		}
		if initial {
			tl, n := quicVarint(b[off:])
			if n == 0 || uint64(len(b)-off-n) < tl {
				return false
			}
			off += n + int(tl)
		}
		l, n := quicVarint(b[off:])
		if n == 0 || uint64(len(b)-off-n) < l {
			return false
		}
		off += n + int(l)
		b = b[off:]
	}
	return false
}

// quicVarint decodes a QUIC variable-length integer (RFC 9000 Sec 16); n is
// 0 if b is too short.
func quicVarint(b []byte) (v uint64, n int) {
	if len(b) == 0 {
		return 0, 0
	}
	n = 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	v = uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n
}
