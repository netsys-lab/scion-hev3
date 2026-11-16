package hev3

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

// hopsPath builds a path through the given ASes (consecutive ASes linked by
// interfaces named by the link index plus base), with optional per-link
// latency and MTU / expiry.
type hopsSpec struct {
	ases   []string
	ifBase uint64
	lat    []time.Duration
	mtu    uint16
	expiry time.Time
	raw    []byte
}

func hopsPath(s hopsSpec) snet.Path {
	var ifs []snet.PathInterface
	for i := 0; i+1 < len(s.ases); i++ {
		id := s.ifBase + uint64(i)
		ifs = append(ifs,
			snet.PathInterface{IA: addr.MustParseIA(s.ases[i]), ID: iface.ID(id)},
			snet.PathInterface{IA: addr.MustParseIA(s.ases[i+1]), ID: iface.ID(id + 1000)})
	}
	exp := s.expiry
	if exp.IsZero() {
		exp = time.Now().Add(time.Hour)
	}
	return snetpath.Path{
		DataplanePath: snetpath.SCION{Raw: s.raw},
		Meta:          snet.PathMetadata{Interfaces: ifs, Latency: s.lat, MTU: s.mtu, Expiry: exp},
	}
}

// samePath compares paths by interfaces (snetpath.Path.Metadata returns a
// fresh pointer per call).
func samePath(a, b snet.Path) bool {
	return interfacesString(a.Metadata()) == interfacesString(b.Metadata())
}

func setIfaces(rs []rankedPath) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = interfacesString(r.p.Metadata())
	}
	return out
}

// Greedy ranking: fewest AS hops first, then repeatedly the path sharing the
// fewest inter-AS links with those already selected (before hop count and
// latency), ties by fewer AS hops.
func TestSelectPathSet_GreedyDisjoint(t *testing.T) {
	lat := func(d time.Duration) []time.Duration { return []time.Duration{d, 0} }
	short := hopsPath(hopsSpec{ases: []string{"1-1", "1-2", "1-9"}, ifBase: 1, lat: lat(1 * ms)}) // 3 AS hops
	// 3 AS hops, low latency, but shares the link 1-1#1 <-> 1-2#1001 with short.
	sharing := snetpath.Path{Meta: snet.PathMetadata{
		Expiry:  time.Now().Add(time.Hour),
		Latency: lat(2 * ms),
		Interfaces: []snet.PathInterface{
			{IA: addr.MustParseIA("1-1"), ID: 1}, {IA: addr.MustParseIA("1-2"), ID: 1001},
			{IA: addr.MustParseIA("1-2"), ID: 7}, {IA: addr.MustParseIA("1-9"), ID: 1007},
		}}}
	disjointShort := hopsPath(hopsSpec{ases: []string{"1-1", "1-5", "1-9"}, ifBase: 40, lat: lat(9 * ms)})       // 3 AS hops
	disjointLong := hopsPath(hopsSpec{ases: []string{"1-1", "1-3", "1-4", "1-9"}, ifBase: 20, lat: lat(9 * ms)}) // 4 AS hops
	got, _ := selectPathSet([]snet.Path{disjointLong, sharing, short, disjointShort},
		pathSetParams{K: 3, Now: time.Now()})
	want := []snet.Path{short, disjointShort, disjointLong}
	if len(got) != 3 {
		t.Fatalf("got %d paths", len(got))
	}
	for i := range want {
		if !samePath(got[i].p, want[i]) {
			t.Fatalf("set = %v, want [short disjointShort disjointLong]", setIfaces(got))
		}
	}
}

// Overlap is compared by shared transit ASes, then shared pairs of adjacent
// ASes, then shared inter-AS links: a parallel link between the same ASes
// shares no link with the first path but loses to a path through another
// transit AS, even a longer one.
func TestSelectPathSet_OverlapOrder(t *testing.T) {
	first := hopsPath(hopsSpec{ases: []string{"1-1", "1-2", "1-9"}, ifBase: 1})
	parallel := hopsPath(hopsSpec{ases: []string{"1-1", "1-2", "1-9"}, ifBase: 50})       // same ASes, other links
	otherAS := hopsPath(hopsSpec{ases: []string{"1-1", "1-3", "1-4", "1-9"}, ifBase: 20}) // longer, other transit ASes
	// Shares the transit AS 1-2 and the pair 1-1/1-2 with first, not the pair 1-2/1-9.
	halfPair := hopsPath(hopsSpec{ases: []string{"1-1", "1-2", "1-5", "1-9"}, ifBase: 70})
	got, _ := selectPathSet([]snet.Path{parallel, halfPair, otherAS, first}, pathSetParams{K: 4, Now: time.Now()})
	// first and parallel tie for the first pick (fewest AS hops); the
	// deterministic tie-break takes the lower fingerprint, so accept either.
	if len(got) != 4 {
		t.Fatalf("got %d paths: %v", len(got), setIfaces(got))
	}
	if !samePath(got[0].p, first) && !samePath(got[0].p, parallel) {
		t.Fatalf("first pick = %v, want a 3-AS path", setIfaces(got))
	}
	if !samePath(got[1].p, otherAS) {
		t.Fatalf("second pick = %v, want the path through other transit ASes", setIfaces(got))
	}
	// After {3-AS path, otherAS}: halfPair shares 1 transit AS and 1 pair;
	// the remaining 3-AS path shares 1 transit AS and 2 pairs.
	if !samePath(got[2].p, halfPair) {
		t.Fatalf("third pick = %v, want the path sharing fewer pairs of adjacent ASes", setIfaces(got))
	}
}

// The Path Attempt Delay defaults to 50 ms, is not below 10 ms and not above
// the Connection Attempt Delay in use.
func TestPathAttemptDelay(t *testing.T) {
	for _, c := range []struct{ conf, cad, want time.Duration }{
		{0, 0, 50 * ms}, {0, 250 * ms, 50 * ms}, {ms, 0, 10 * ms}, {10 * ms, 0, 10 * ms},
		{100 * ms, 0, 100 * ms}, {400 * ms, 250 * ms, 250 * ms}, {0, 20 * ms, 20 * ms}, {0, 5 * ms, 10 * ms},
	} {
		if got := pathAttemptDelay(c.conf, c.cad); got != c.want {
			t.Errorf("pathAttemptDelay(%v, %v) = %v, want %v", c.conf, c.cad, got, c.want)
		}
	}
}

// Declared latency breaks ties between equally long paths (known before
// unknown); K caps the set.
func TestSelectPathSet_LatencyTieBreakAndK(t *testing.T) {
	slow := hopsPath(hopsSpec{ases: []string{"1-1", "1-9"}, ifBase: 1, lat: []time.Duration{30 * ms}})
	fast := hopsPath(hopsSpec{ases: []string{"1-1", "1-9"}, ifBase: 3, lat: []time.Duration{10 * ms}})
	unknown := hopsPath(hopsSpec{ases: []string{"1-1", "1-9"}, ifBase: 5, lat: []time.Duration{-1}})
	got, _ := selectPathSet([]snet.Path{unknown, slow, fast}, pathSetParams{K: 2, Now: time.Now()})
	if len(got) != 2 || !samePath(got[0].p, fast) || !samePath(got[1].p, slow) {
		t.Fatalf("set = %v, want [fast slow]", setIfaces(got))
	}
}

// Expired paths are never selected; paths expiring within 2s only when no
// other path is left.
func TestSelectPathSet_Expiry(t *testing.T) {
	now := time.Now()
	expired := hopsPath(hopsSpec{ases: []string{"1-1", "1-9"}, ifBase: 1, expiry: now.Add(-time.Second)})
	soon := hopsPath(hopsSpec{ases: []string{"1-1", "1-9"}, ifBase: 3, expiry: now.Add(time.Second)})
	fresh := hopsPath(hopsSpec{ases: []string{"1-1", "1-2", "1-9"}, ifBase: 5})
	got, excl := selectPathSet([]snet.Path{expired, soon, fresh}, pathSetParams{K: 3, Now: now})
	if len(got) != 1 || !samePath(got[0].p, fresh) {
		t.Fatalf("set = %v, want only the fresh path", setIfaces(got))
	}
	if len(excl) != 2 {
		t.Errorf("exclusions = %+v, want expired + expiring", excl)
	}
	got, _ = selectPathSet([]snet.Path{expired, soon}, pathSetParams{K: 3, Now: now})
	if len(got) != 1 || !samePath(got[0].p, soon) {
		t.Fatalf("set = %v, want the expiring path as last resort", setIfaces(got))
	}
}

// The MTU check counts the SCION common, address and path headers, the UDP
// header and a 1200-octet QUIC datagram.
func TestSelectPathSet_MTU(t *testing.T) {
	raw := make([]byte, 4+8+2*12) // 1 info field, 2 hop fields
	// IPv4 hosts: 12 + 16 + 4 + 4 + 36 + 8 + 1200 = 1280.
	ok := hopsPath(hopsSpec{ases: []string{"1-1", "1-9"}, ifBase: 1, mtu: 1280, raw: raw})
	small := hopsPath(hopsSpec{ases: []string{"1-1", "1-9"}, ifBase: 3, mtu: 1279, raw: raw})
	got, excl := selectPathSet([]snet.Path{small, ok}, pathSetParams{K: 3, Now: time.Now(), DstHostLen: 4, SrcHostLen: 4})
	if len(got) != 1 || !samePath(got[0].p, ok) || len(excl) != 1 {
		t.Fatalf("set = %v excl = %+v, want only the 1280-MTU path", setIfaces(got), excl)
	}
	// IPv6 hosts need 24 more octets.
	got, _ = selectPathSet([]snet.Path{ok}, pathSetParams{K: 3, Now: time.Now(), DstHostLen: 16, SrcHostLen: 16})
	if len(got) != 0 {
		t.Fatalf("1280-MTU path selected for IPv6 hosts")
	}
}

// Paths through an interface reported down rank after all others.
func TestSelectPathSet_DownCacheRanksLast(t *testing.T) {
	now := time.Now()
	short := hopsPath(hopsSpec{ases: []string{"1-1", "1-9"}, ifBase: 1})
	long := hopsPath(hopsSpec{ases: []string{"1-1", "1-2", "1-3", "1-9"}, ifBase: 10})
	dc := &downCache{m: map[ifKey]time.Time{}}
	dc.add(addr.MustParseIA("1-1"), 1, now)
	got, _ := selectPathSet([]snet.Path{short, long}, pathSetParams{K: 3, Now: now, Down: dc})
	if len(got) != 2 || !samePath(got[0].p, long) || !got[1].down {
		t.Fatalf("set = %v, want the down path last", setIfaces(got))
	}
	// The entry expires after downCacheTTL.
	got, _ = selectPathSet([]snet.Path{short, long}, pathSetParams{K: 3, Now: now.Add(downCacheTTL + time.Second), Down: dc})
	if !samePath(got[0].p, short) {
		t.Fatalf("set = %v, want the short path first after the TTL", setIfaces(got))
	}
}

func TestPathDelayFor(t *testing.T) {
	now := time.Unix(1000, 0)
	hist := newRTTHistory()
	hist.record("h", 20*ms, 3*ms, now)
	hist.record("old", 20*ms, 3*ms, now.Add(-rttHistoryTTL))
	md := func(lat ...time.Duration) *snet.PathMetadata { return &snet.PathMetadata{Latency: lat} }
	for _, tc := range []struct {
		name          string
		conf          time.Duration
		fp            string
		md            *snet.PathMetadata
		attempt, want time.Duration
		src           string
	}{
		{"history", 0, "h", md(50 * ms), 250 * ms, 26 * ms, delaySrcHistory},
		{"expired history", 0, "old", md(5*ms, 6*ms), 250 * ms, 44 * ms, delaySrcMetadata},
		{"metadata, unset hops ignored", 0, "x", md(-1, 10*ms), 250 * ms, 40 * ms, delaySrcMetadata},
		{"no estimate", 0, "x", md(-1), 250 * ms, defaultPathDelay, delaySrcDefault},
		{"no metadata", 0, "", nil, 0, defaultPathDelay, delaySrcDefault},
		{"capped at attempt delay", 0, "x", md(60 * ms), 100 * ms, 100 * ms, delaySrcMetadata},
		{"floor", 0, "x", md(ms), 250 * ms, minPathDelay, delaySrcMetadata},
		{"fixed", 30 * ms, "h", md(50 * ms), 250 * ms, 30 * ms, delaySrcFixed},
		{"fixed capped", 300 * ms, "h", nil, 250 * ms, 250 * ms, delaySrcFixed},
	} {
		got, src := pathDelayFor(tc.conf, tc.fp, tc.md, hist, now, tc.attempt)
		if got != tc.want || src != tc.src {
			t.Errorf("%s: pathDelayFor = %v (%s), want %v (%s)", tc.name, got, src, tc.want, tc.src)
		}
	}
}

func TestRTTHistory_NoSample(t *testing.T) {
	h := newRTTHistory()
	h.record("p", 0, 0, time.Now())
	h.record("", 10*ms, ms, time.Now())
	if len(h.m) != 0 {
		t.Fatalf("history = %v, want empty", h.m)
	}
}

// --- hop-field matching -------------------------------------------------------

func decodedPath(t *testing.T) *scion.Decoded {
	t.Helper()
	return &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{CurrINF: 0, CurrHF: 0, SegLen: [3]uint8{2, 2, 0}},
			NumINF:   2, NumHops: 4,
		},
		InfoFields: []path.InfoField{{ConsDir: false, SegID: 0x1111}, {ConsDir: true, SegID: 0x2222}},
		HopFields: []path.HopField{
			{ExpTime: 63, ConsIngress: 11, ConsEgress: 0},
			{ExpTime: 63, ConsIngress: 0, ConsEgress: 12},
			{ExpTime: 63, ConsIngress: 0, ConsEgress: 21},
			{ExpTime: 63, ConsIngress: 22, ConsEgress: 0},
		},
	}
}

// A reply's path, reversed by the client, has the hop pairs of the path the
// client sent, even after routers rewrote SegID and CurrINF/CurrHF.
func TestHopPairs_MatchAfterDoubleReversal(t *testing.T) {
	d := decodedPath(t)
	raw := make([]byte, d.Len())
	if err := d.SerializeTo(raw); err != nil {
		t.Fatal(err)
	}
	sent, ok := hopPairsFromRaw(raw)
	if !ok || len(sent) != 4 {
		t.Fatalf("hopPairsFromRaw = %v %v", sent, ok)
	}
	// In flight: routers advance to the last hop and update SegIDs.
	fl := decodedPath(t)
	fl.PathMeta.CurrINF, fl.PathMeta.CurrHF = 1, 3
	fl.InfoFields[0].SegID, fl.InfoFields[1].SegID = 0xabcd, 0x1234
	srv, err := fl.Reverse() // the server's reply path (Reverse works in place)
	if err != nil {
		t.Fatal(err)
	}
	if mid, _ := hopPairsOfPath(srv); hopPairsEqual(mid, sent) {
		t.Fatalf("server-side (singly reversed) path must not match")
	}
	back, err := srv.Reverse() // the client's snet reply pather
	if err != nil {
		t.Fatal(err)
	}
	got, ok := hopPairsOfPath(back)
	if !ok || !hopPairsEqual(got, sent) {
		t.Fatalf("pairs after double reversal = %v, want %v", got, sent)
	}
	// Via the snet types.
	if got, ok := hopPairsOf(snet.RawReplyPath{Path: back}); !ok || !hopPairsEqual(got, sent) {
		t.Fatalf("hopPairsOf(RawReplyPath) = %v %v", got, ok)
	}
	if got, ok := hopPairsOf(snetpath.SCION{Raw: raw}); !ok || !hopPairsEqual(got, sent) {
		t.Fatalf("hopPairsOf(SCION) = %v %v", got, ok)
	}
}

func TestCorruptFirstHopMAC(t *testing.T) {
	d := decodedPath(t)
	d.HopFields[0].Mac = [6]byte{1, 2, 3, 4, 5, 6}
	raw := make([]byte, d.Len())
	if err := d.SerializeTo(raw); err != nil {
		t.Fatal(err)
	}
	p := snetpath.Path{DataplanePath: snetpath.SCION{Raw: raw}, Meta: snet.PathMetadata{MTU: 1400}}
	cp := corruptFirstHopMAC(p)
	craw := cp.Dataplane().(snetpath.SCION).Raw
	var cd scion.Decoded
	if err := cd.DecodeFromBytes(craw); err != nil {
		t.Fatal(err)
	}
	if cd.HopFields[0].Mac == d.HopFields[0].Mac {
		t.Fatalf("first hop MAC unchanged")
	}
	for i := 1; i < 4; i++ {
		if cd.HopFields[i] != d.HopFields[i] {
			t.Errorf("hop field %d changed", i)
		}
	}
	if !bytes.Equal(raw, p.DataplanePath.(snetpath.SCION).Raw) {
		t.Errorf("original path modified")
	}
	if cp.Metadata().MTU != 1400 {
		t.Errorf("metadata not kept")
	}
	if pairs, _ := hopPairsOf(cp.Dataplane()); !hopPairsEqual(pairs, mustPairs(t, raw)) {
		t.Errorf("corrupted path has different hop pairs")
	}
}

func mustPairs(t *testing.T, raw []byte) []hopPair {
	t.Helper()
	p, ok := hopPairsFromRaw(raw)
	if !ok {
		t.Fatal("bad raw path")
	}
	return p
}

// --- 1-RTT detection ----------------------------------------------------------

func longHdr(first byte, version uint32, token []byte, payload int) []byte {
	b := []byte{first}
	b = binary.BigEndian.AppendUint32(b, version)
	b = append(b, 8, 1, 2, 3, 4, 5, 6, 7, 8) // DCID
	b = append(b, 4, 9, 9, 9, 9)             // SCID
	if token != nil {
		b = append(b, byte(len(token))) // 1-byte varint
		b = append(b, token...)
	}
	b = append(b, 0x40|byte(payload>>8), byte(payload)) // 2-byte varint length
	return append(b, make([]byte, payload)...)
}

func TestContainsOneRTT(t *testing.T) {
	initV1 := longHdr(0xc3, quicV1, []byte{}, 1100)
	initTok := longHdr(0xc3, quicV1, []byte{7, 7, 7}, 50)
	hsV1 := longHdr(0xe3, quicV1, nil, 40)
	short := append([]byte{0x43}, make([]byte, 30)...)
	initV2 := longHdr(0xd3, quicV2, []byte{1}, 60) // v2 Initial: type 0b01
	hsV2 := longHdr(0xf3, quicV2, nil, 40)         // v2 Handshake: type 0b11
	cat := func(ps ...[]byte) []byte { return bytes.Join(ps, nil) }
	for _, tc := range []struct {
		name string
		b    []byte
		want bool
	}{
		{"initial", initV1, false},
		{"initial+zero padding", cat(initV1, make([]byte, 40)), false},
		{"initial with token+handshake", cat(initTok, hsV1), false},
		{"short header", short, true},
		{"handshake+1rtt coalesced", cat(hsV1, short), true},
		{"initial(token)+handshake+1rtt", cat(initTok, hsV1, short), true},
		{"v2 initial+handshake+1rtt", cat(initV2, hsV2, short), true},
		{"v2 initial", initV2, false},
		{"truncated", initV1[:20], false},
		{"unknown version", longHdr(0xc3, 0xff00001d, []byte{}, 10), false},
	} {
		if got := containsOneRTT(tc.b); got != tc.want {
			t.Errorf("%s: containsOneRTT = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// An SCMP error whose quote is not a datagram sent on an added path is
// recorded but fails nothing.
func TestRacer_SCMPForUnknownPathIgnored(t *testing.T) {
	remote := &snet.UDPAddr{IA: emuServerIA, Host: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}}
	d := decodedPath(t)
	raw := make([]byte, d.Len())
	_ = d.SerializeTo(raw)
	r := newPathRacer(racerConfig{
		Remote:    remote,
		Paths:     []snet.Path{snetpath.Path{DataplanePath: snetpath.SCION{Raw: raw}, Meta: snet.PathMetadata{Expiry: time.Now().Add(time.Hour)}}},
		PathDelay: time.Second,
		Down:      &downCache{m: map[ifKey]time.Time{}},
	})
	defer r.Close()
	_ = r.Handle(&snet.Packet{PacketInfo: snet.PacketInfo{Payload: snet.SCMPExternalInterfaceDown{
		IA: emuClientIA, Interface: 1, Payload: []byte{1, 2, 3},
	}}})
	st := r.Stats()
	if len(st.SCMP) != 1 || st.SCMP[0].Path != -1 || st.SCMP[0].Ignored == "" || st.Paths[0].Failed {
		t.Fatalf("stats = %+v, want one ignored SCMP event", st)
	}
}

// Rule (a) selects only on a datagram addressed to this connection's
// connection ID and arriving on an added path that has not failed: a late
// datagram of an earlier connection on the same addresses and ports (snet
// reuses the highest free port) or a reply on a path the client never sent
// on does not select.
func TestRacer_SelectOnlyOwnCIDOnAddedPath(t *testing.T) {
	remote := &snet.UDPAddr{IA: emuServerIA, Host: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}}
	mk := func(k int) (snet.Path, []hopPair) {
		d := decodedPath(t)
		d.HopFields[0].ConsEgress = uint16(k)
		raw := make([]byte, d.Len())
		if err := d.SerializeTo(raw); err != nil {
			t.Fatal(err)
		}
		return snetpath.Path{DataplanePath: snetpath.SCION{Raw: raw}, Meta: snet.PathMetadata{Expiry: time.Now().Add(time.Hour)}}, mustPairs(t, raw)
	}
	p1, h1 := mk(1)
	p2, h2 := mk(2)
	r := newPathRacer(racerConfig{
		Remote:    remote,
		Paths:     []snet.Path{p1, p2},
		PathDelay: time.Hour, // only path 1 is added
		Down:      &downCache{m: map[ifKey]time.Time{}},
	})
	r.under = discardConn{}
	defer r.Close()
	// Client Initial: DCID 8 bytes, SCID 9,9,9,9 (longHdr).
	if _, err := r.WriteTo(longHdr(0xc3, quicV1, []byte{}, 1100), nil); err != nil {
		t.Fatal(err)
	}
	srvInitial := func(dcid []byte) []byte {
		b := []byte{0xc3, 0, 0, 0, 1, byte(len(dcid))}
		b = append(b, dcid...)
		return append(b, 0, 0, 0x40, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	}
	r.mu.Lock()
	r.onRecvLocked(srvInitial([]byte{1, 1, 1, 1}), h1, true) // earlier connection
	r.onRecvLocked(srvInitial([]byte{9, 9, 9, 9}), h2, true) // own CID, path 2 not added
	r.onRecvLocked(append([]byte{0x40, 7, 7, 7, 7}, make([]byte, 20)...), h1, true)
	sel, foreign := r.selected, r.recvForeign
	r.mu.Unlock()
	if sel != -1 || foreign != 2 {
		t.Fatalf("selected=%d foreign=%d, want none selected and 2 foreign", sel, foreign)
	}
	r.mu.Lock()
	r.onRecvLocked(srvInitial([]byte{9, 9, 9, 9}), h1, true) // own CID on added path 1
	sel = r.selected
	r.mu.Unlock()
	if sel != 0 {
		t.Fatalf("selected=%d, want path 1 (index 0)", sel)
	}
}

type discardConn struct{ net.PacketConn }

func (discardConn) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (discardConn) Close() error                              { return nil }
