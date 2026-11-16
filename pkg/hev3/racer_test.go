package hev3

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

// In-memory emulation of path racing: a real snet client and server on
// 127.0.0.1, and one UDP relay per path standing in for that path's
// routers. The client's next hop for path k is relay k; relay k forwards to
// the server, drops, or answers with an SCMP External Interface Down that
// quotes the client's packet (as a border router would). Paths are 2-hop
// SCION paths client AS --(if k / if 100+k)--> server AS, so hop-field
// interface IDs identify the path in reply and quoted packets.

var (
	emuClientIA = addr.MustParseIA("1-ff00:0:110")
	emuServerIA = addr.MustParseIA("1-ff00:0:111")
)

type relayMode int32

const (
	relayForward relayMode = iota
	relayDrop
	relaySCMP // answer each client packet with SCMP External Interface Down
)

type emuRelay struct {
	k      int
	delay  time.Duration
	mode   atomic.Int32
	sockC  *net.UDPConn // client-facing: the client's underlay next hop
	sockS  *net.UDPConn // server-facing: the server's next hop for replies
	server *net.UDPAddr
	client atomic.Pointer[net.UDPAddr]
	up     atomic.Int64 // client packets received
}

func newEmuRelay(t *testing.T, k int, delay time.Duration, server *net.UDPAddr) *emuRelay {
	t.Helper()
	r := &emuRelay{k: k, delay: delay, server: server}
	var err error
	if r.sockC, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}); err != nil {
		t.Fatal(err)
	}
	if r.sockS, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}); err != nil {
		t.Fatal(err)
	}
	go r.loop(r.sockC, true)
	go r.loop(r.sockS, false)
	t.Cleanup(func() { r.sockC.Close(); r.sockS.Close() })
	return r
}

func (r *emuRelay) loop(c *net.UDPConn, up bool) {
	buf := make([]byte, 65535)
	for {
		n, from, err := c.ReadFromUDP(buf)
		if err != nil {
			return
		}
		b := append([]byte(nil), buf[:n]...)
		if !up {
			if ca := r.client.Load(); ca != nil && relayMode(r.mode.Load()) == relayForward {
				time.AfterFunc(r.delay, func() { _, _ = r.sockC.WriteToUDP(b, ca) })
			}
			continue
		}
		r.client.Store(from)
		r.up.Add(1)
		switch relayMode(r.mode.Load()) {
		case relayForward:
			time.AfterFunc(r.delay, func() { _, _ = r.sockS.WriteToUDP(b, r.server) })
		case relaySCMP:
			pkt := &snet.Packet{PacketInfo: snet.PacketInfo{
				Destination: snet.SCIONAddress{IA: emuClientIA, Host: addr.HostIP(netip.MustParseAddr("127.0.0.1"))},
				Source:      snet.SCIONAddress{IA: emuClientIA, Host: addr.HostIP(netip.MustParseAddr("127.0.0.1"))},
				Path:        snetpath.Empty{},
				Payload: snet.SCMPExternalInterfaceDown{
					IA: emuClientIA, Interface: uint64(r.k), Payload: b,
				},
			}}
			if err := pkt.Serialize(); err == nil {
				_, _ = r.sockC.WriteToUDP(pkt.Bytes, from)
			}
		}
	}
}

// emuPath builds path k (see above), routed via relay k. CurrHF points at
// the last hop, as the routers would have advanced it.
func emuPath(t *testing.T, k int, r *emuRelay) snet.Path {
	t.Helper()
	d := scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{CurrINF: 0, CurrHF: 1, SegLen: [3]uint8{2, 0, 0}},
			NumINF:   1, NumHops: 2,
		},
		InfoFields: []path.InfoField{{ConsDir: true, SegID: uint16(k), Timestamp: uint32(time.Now().Unix())}},
		HopFields: []path.HopField{
			{ExpTime: 63, ConsIngress: 0, ConsEgress: uint16(k)},
			{ExpTime: 63, ConsIngress: uint16(100 + k), ConsEgress: 0},
		},
	}
	raw := make([]byte, d.Len())
	if err := d.SerializeTo(raw); err != nil {
		t.Fatal(err)
	}
	return snetpath.Path{
		Src: emuClientIA, Dst: emuServerIA,
		DataplanePath: snetpath.SCION{Raw: raw},
		NextHop:       r.sockC.LocalAddr().(*net.UDPAddr),
		Meta: snet.PathMetadata{
			Interfaces: []snet.PathInterface{
				{IA: emuClientIA, ID: iface.ID(k)},
				{IA: emuServerIA, ID: iface.ID(100 + k)},
			},
			Expiry: time.Now().Add(time.Hour),
		},
	}
}

type emuEnv struct {
	relays   []*emuRelay
	paths    []snet.Path
	srvAddr  *net.UDPAddr
	accepted atomic.Int64
	tlsCli   *tls.Config
}

func emuTopo(ia addr.IA, ifaces func(uint16) (netip.AddrPort, bool)) snet.Topology {
	return snet.Topology{LocalIA: ia, PortRange: snet.TopologyPortRange{Start: 1, End: 65535}, Interface: ifaces}
}

func newEmuEnv(t *testing.T, modes []relayMode, delay time.Duration) *emuEnv {
	t.Helper()
	t.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	tlsSrv, tlsCli := emuTLS(t)
	e := &emuEnv{tlsCli: tlsCli}
	ifaces := &sync.Map{}
	sn := &snet.SCIONNetwork{
		Topology: emuTopo(emuServerIA, func(id uint16) (netip.AddrPort, bool) {
			v, ok := ifaces.Load(id)
			if !ok {
				return netip.AddrPort{}, false
			}
			return v.(netip.AddrPort), true
		}),
		SCMPHandler: snet.SCMPPropagationStopper{Handler: snet.DefaultSCMPHandler{}},
	}
	conn, err := sn.Listen(context.Background(), "udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: conn}
	ln, err := tr.Listen(tlsSrv, &quic.Config{HandshakeIdleTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); tr.Close() })
	go func() {
		for {
			qc, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			e.accepted.Add(1)
			go func() { <-qc.Context().Done() }()
		}
	}()
	e.srvAddr = conn.LocalAddr().(*snet.UDPAddr).Host
	for i, m := range modes {
		r := newEmuRelay(t, i+1, delay, e.srvAddr)
		r.mode.Store(int32(m))
		ifaces.Store(uint16(100+i+1), r.sockS.LocalAddr().(*net.UDPAddr).AddrPort())
		e.relays = append(e.relays, r)
		e.paths = append(e.paths, emuPath(t, i+1, r))
	}
	return e
}

func (e *emuEnv) dial(t *testing.T, pathDelay time.Duration, down *downCache) (racingResult, error) {
	t.Helper()
	return e.dialDelays(t, pathDelay, nil, down)
}

// dialDelays dials with per-path Path Delays (nil = pathDelay for all).
func (e *emuEnv) dialDelays(t *testing.T, pathDelay time.Duration, delays []time.Duration, down *downCache) (racingResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := dialRacing(ctx, racingDial{
		Remote:     &snet.UDPAddr{IA: emuServerIA, Host: e.srvAddr},
		Paths:      e.paths,
		PathDelay:  pathDelay,
		PathDelays: delays,
		Topology: emuTopo(emuClientIA, func(uint16) (netip.AddrPort, bool) {
			return e.relays[0].sockC.LocalAddr().(*net.UDPAddr).AddrPort(), true
		}),
		LocalIP: net.IPv4(127, 0, 0, 1),
		TLS:     e.tlsCli.Clone(),
		Down:    down,
	})
	if err == nil {
		t.Cleanup(func() {
			_ = res.conn.CloseWithError(0, "")
			_ = res.tr.Close()
			_ = res.racer.Close()
		})
	}
	return res, err
}

// waitAccepted waits up to 1s for the server to accept n connections (the
// server finishes its handshake after the client) and returns the count,
// after a short extra wait for duplicates.
func (e *emuEnv) waitAccepted(n int64) int64 {
	deadline := time.Now().Add(time.Second)
	for e.accepted.Load() < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	return e.accepted.Load()
}

func emuTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		DNSNames: []string{"example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	srv := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"t"}}
	cli := &tls.Config{RootCAs: pool, ServerName: "example.com", NextProtos: []string{"t"}}
	return srv, cli
}

// All paths work: the top-ranked path answers before the Path Delay, so it
// is selected on the reply and no other path is ever added.
func TestRacer_FirstPathAnswers(t *testing.T) {
	e := newEmuEnv(t, []relayMode{relayForward, relayForward, relayForward}, time.Millisecond)
	res, err := e.dial(t, 500*time.Millisecond, &downCache{m: map[ifKey]time.Time{}})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	st := res.racer.Stats()
	if st.Selected != 1 || st.SelectReason != "reply" {
		t.Fatalf("selected path %d (%s), want 1 (reply)", st.Selected, st.SelectReason)
	}
	for _, p := range st.Paths[1:] {
		if p.Added || p.Pkts != 0 {
			t.Errorf("path %d added=%v pkts=%d, want never added", p.Rank, p.Added, p.Pkts)
		}
	}
	if e.relays[1].up.Load() != 0 || e.relays[2].up.Load() != 0 {
		t.Errorf("relays 2/3 saw traffic")
	}
	if n := e.waitAccepted(1); n != 1 {
		t.Errorf("server accepted %d connections, want 1", n)
	}
}

// Path 1 drops everything: path 2 is added when the Path Delay elapses,
// first receives copies of the datagrams already sent, and is selected by
// the server's reply on it. The server sees one connection.
func TestRacer_BlackholedPathRacesNext(t *testing.T) {
	e := newEmuEnv(t, []relayMode{relayDrop, relayForward, relayForward}, time.Millisecond)
	const pd = 60 * time.Millisecond
	start := time.Now()
	res, err := e.dial(t, pd, &downCache{m: map[ifKey]time.Time{}})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if hs := time.Since(start); hs < pd {
		t.Errorf("handshake took %v, want >= the Path Delay %v", hs, pd)
	}
	st := res.racer.Stats()
	if st.Selected != 2 || st.SelectReason != "reply" {
		t.Fatalf("selected path %d (%s), want 2 (reply); stats %+v", st.Selected, st.SelectReason, st)
	}
	p2 := st.Paths[1]
	if !p2.Added || p2.AddReason != "path-delay" || p2.AddedAtMs < float64(pd.Milliseconds())-1 {
		t.Errorf("path 2 = %+v, want added by the Path Delay at >= %v", p2, pd)
	}
	if p2.Copies < 1 {
		t.Errorf("path 2 got %d copies, want the stored first flight", p2.Copies)
	}
	if st.Paths[0].Pkts < 1 || st.Paths[0].Failed {
		t.Errorf("path 1 = %+v, want sent on and not failed (silent loss)", st.Paths[0])
	}
	if n := e.waitAccepted(1); n != 1 {
		t.Errorf("server accepted %d connections, want 1", n)
	}
}

// Path 1 answers with SCMP External Interface Down quoting the client's
// packet: path 1 fails, path 2 is added at once (well before the Path
// Delay) and selected; the interface enters the down cache.
func TestRacer_SCMPFailsPathAndAddsNext(t *testing.T) {
	e := newEmuEnv(t, []relayMode{relaySCMP, relayForward, relayForward}, time.Millisecond)
	down := &downCache{m: map[ifKey]time.Time{}}
	start := time.Now()
	res, err := e.dial(t, 2*time.Second, down)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if hs := time.Since(start); hs > time.Second {
		t.Errorf("handshake took %v: path 2 was not added at once on the SCMP error", hs)
	}
	st := res.racer.Stats()
	if st.Selected != 2 {
		t.Fatalf("selected path %d, want 2; stats %+v", st.Selected, st)
	}
	if !st.Paths[0].Failed || st.Paths[1].AddReason != "all-added-failed" {
		t.Errorf("paths = %+v, want path 1 failed and path 2 added on all-added-failed", st.Paths)
	}
	if st.Paths[2].Added {
		t.Errorf("path 3 added, want not")
	}
	if len(st.SCMP) == 0 || st.SCMP[0].Path != 1 || st.SCMP[0].Type != "external-interface-down" {
		t.Errorf("SCMP events = %+v, want one matched to path 1", st.SCMP)
	}
	if !down.pathDown(e.paths[0].Metadata(), time.Now()) {
		t.Errorf("interface of path 1 not in the down cache")
	}
	if down.pathDown(e.paths[1].Metadata(), time.Now()) {
		t.Errorf("path 2 reported down")
	}
}

// Every path answers with SCMP: the attempt fails promptly with
// errAllPathsFailed instead of waiting for the handshake timeout.
func TestRacer_AllPathsSCMPFailsAttempt(t *testing.T) {
	e := newEmuEnv(t, []relayMode{relaySCMP, relaySCMP, relaySCMP}, time.Millisecond)
	start := time.Now()
	res, err := e.dial(t, 2*time.Second, &downCache{m: map[ifKey]time.Time{}})
	if !errors.Is(err, errAllPathsFailed) {
		t.Fatalf("dial err = %v, want errAllPathsFailed", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("failure took %v, want prompt", d)
	}
	st := res.racer.Stats()
	for _, p := range st.Paths {
		if !p.Added || !p.Failed {
			t.Errorf("path %d = %+v, want added and failed", p.Rank, p)
		}
	}
}

// A Path Delay of 0 adds all paths at once; identical datagrams go out on
// each, and the first reply selects its path.
func TestRacer_ZeroPathDelayAddsAll(t *testing.T) {
	e := newEmuEnv(t, []relayMode{relayDrop, relayDrop, relayForward}, time.Millisecond)
	res, err := e.dial(t, 0, &downCache{m: map[ifKey]time.Time{}})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	st := res.racer.Stats()
	if st.Selected != 3 {
		t.Fatalf("selected path %d, want 3", st.Selected)
	}
	for _, p := range st.Paths {
		if !p.Added || p.AddReason != "start" || p.Copies != 0 {
			t.Errorf("path %d = %+v, want added at start without copies", p.Rank, p)
		}
	}
	if st.Paths[0].Pkts != st.Paths[2].Pkts && st.Paths[0].Bytes == 0 {
		t.Errorf("paths 1 and 3 = %+v / %+v", st.Paths[0], st.Paths[2])
	}
}

// Each path's own Path Delay follows its adding: path 2 is added after
// path 1's delay, path 3 after path 2's.
func TestRacer_PerPathDelays(t *testing.T) {
	e := newEmuEnv(t, []relayMode{relayDrop, relayDrop, relayForward}, time.Millisecond)
	res, err := e.dialDelays(t, 0, []time.Duration{20 * time.Millisecond, 200 * time.Millisecond, time.Hour},
		&downCache{m: map[ifKey]time.Time{}})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	st := res.racer.Stats()
	if st.Selected != 3 || st.AllAtOnce {
		t.Fatalf("stats = %+v, want path 3 selected, staggered", st)
	}
	p2, p3 := st.Paths[1], st.Paths[2]
	if p2.AddReason != "path-delay" || p3.AddReason != "path-delay" {
		t.Fatalf("add reasons %q/%q, want path-delay", p2.AddReason, p3.AddReason)
	}
	if gap := p2.AddedAtMs - st.Paths[0].AddedAtMs; gap < 15 || gap > 150 {
		t.Errorf("path 2 added %.1f ms after path 1, want about 20", gap)
	}
	if gap := p3.AddedAtMs - p2.AddedAtMs; gap < 190 {
		t.Errorf("path 3 added %.1f ms after path 2, want about 200", gap)
	}
	if st.PathDelayMs != 20 || p2.DelayMs != 200 {
		t.Errorf("delays %v / %v, want 20 / 200", st.PathDelayMs, p2.DelayMs)
	}
}

// Historical RTT data: QUIC's estimate when the selected path was added at
// the start; the racer's own sample (first-sample rule) when it was added
// later, because QUIC's samples then include the wait before the copy.
func TestRacer_HistorySource(t *testing.T) {
	now := time.Now()
	cs := quic.ConnectionStats{SmoothedRTT: 500 * time.Millisecond, MeanDeviation: 100 * time.Millisecond}

	e := newEmuEnv(t, []relayMode{relayForward, relayForward}, time.Millisecond)
	res, err := e.dial(t, time.Hour, &downCache{m: map[ifKey]time.Time{}})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	h := newRTTHistory()
	recordHistory(h, res.racer, cs, now)
	fp, fromStart, _ := res.racer.historySource()
	if srtt, v, ok := h.lookup(fp, now); !fromStart || !ok || srtt != cs.SmoothedRTT || v != cs.MeanDeviation {
		t.Errorf("start path: fromStart=%v history=%v/%v/%v, want QUIC's estimate", fromStart, srtt, v, ok)
	}

	e = newEmuEnv(t, []relayMode{relayDrop, relayForward}, time.Millisecond)
	res, err = e.dial(t, 30*time.Millisecond, &downCache{m: map[ifKey]time.Time{}})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	h = newRTTHistory()
	recordHistory(h, res.racer, cs, now)
	fp, fromStart, sample := res.racer.historySource()
	srtt, v, ok := h.lookup(fp, now)
	if fromStart || !ok || sample <= 0 || sample >= 30*time.Millisecond || srtt != sample || v != sample/2 {
		t.Errorf("late path: fromStart=%v sample=%v history=%v/%v/%v, want the racer's sample", fromStart, sample, srtt, v, ok)
	}
}
