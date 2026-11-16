package hev3

import (
	"hash/maphash"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// bothFamiliesReachable stubs udpSource so every IPv6 and IPv4 destination
// is reachable from a global source of its family: RFC 6724 then puts IPv6
// first (higher precedence) independent of the test host's routes.
func bothFamiliesReachable(t *testing.T) {
	t.Helper()
	old := udpSource
	t.Cleanup(func() { udpSource = old })
	udpSource = func(dst netip.Addr) netip.Addr {
		if dst.Unmap().Is4() {
			return netip.MustParseAddr("198.51.100.1")
		}
		return netip.MustParseAddr("2001:db8:ffff::1")
	}
}

func labels(cands []Candidate) []string {
	out := make([]string, len(cands))
	for i, c := range cands {
		out[i] = c.Label
	}
	return out
}

// worked example, brief step 2: {v4a,v6a,scion-p1,scion-p2,v6b}, nativeSCION=true,
// preferredFamilyCount=1 -> SCION,IPv6,IPv4 preference, round-robin interleave.
func TestSort_FamilyInterleave_NativeSCION(t *testing.T) {
	bothFamiliesReachable(t)
	v4a := Candidate{Family: FamilyIPv4, Host: "203.0.113.1", Priority: 1, Label: "v4a"}
	v6a := Candidate{Family: FamilyIPv6, Host: "2001:db8::1", Priority: 1, Label: "v6a"}
	v6b := Candidate{Family: FamilyIPv6, Host: "2001:db8::2", Priority: 1, Label: "v6b"}
	scionP1 := Candidate{Family: FamilySCION, IA: "1-150", Priority: 1, Label: "scion-p1", Path: &SCIONPath{Fingerprint: "p1"}}
	scionP2 := Candidate{Family: FamilySCION, IA: "1-150", Priority: 1, Label: "scion-p2", Path: &SCIONPath{Fingerprint: "p2"}}

	in := []Candidate{v4a, v6a, scionP1, scionP2, v6b}
	got := Sort(in, true, 1)

	want := []string{"scion-p1", "v6a", "v4a", "scion-p2", "v6b"}
	if g := labels(got); !reflect.DeepEqual(g, want) {
		t.Fatalf("got %v, want %v", g, want)
	}
}

// §4.2/§5.1: candidates group by identical ALPN set (order-independent);
// a group's rank is its best (lowest) member Priority; groups sort ascending
// by rank; within a group members sort ascending by Priority.
func TestSort_ALPNGroupingAndPriorityOrder(t *testing.T) {
	// Group A: ALPN {h3} — best priority 1 (via a) -> group rank 1.
	a := Candidate{Family: FamilyIPv4, Host: "203.0.113.10", Priority: 1, ALPN: []string{"h3"}, Label: "a"}
	b := Candidate{Family: FamilyIPv4, Host: "203.0.113.11", Priority: 5, ALPN: []string{"h3"}, Label: "b"}
	// Group B: ALPN {h2,h3} (order-independent set, given here reversed vs a "canonical" order)
	// -> best priority 2, group rank 2, sorts after group A.
	c := Candidate{Family: FamilyIPv4, Host: "203.0.113.12", Priority: 2, ALPN: []string{"h3", "h2"}, Label: "c"}
	d := Candidate{Family: FamilyIPv4, Host: "203.0.113.13", Priority: 4, ALPN: []string{"h2", "h3"}, Label: "d"}

	// Feed in scrambled/interleaved order to prove grouping, not input order, drives result.
	in := []Candidate{d, b, a, c}
	got := Sort(in, false, 1)

	want := []string{"a", "b", "c", "d"}
	if g := labels(got); !reflect.DeepEqual(g, want) {
		t.Fatalf("got %v, want %v", g, want)
	}
}

// Multiple SCION path sub-candidates of the SAME address arrive pre-ranked
// (best path first); the sorter must preserve that relative order.
func TestSort_SCIONPathOrderPreserved(t *testing.T) {
	p1 := Candidate{Family: FamilySCION, IA: "1-150", Priority: 1, Label: "p1", Path: &SCIONPath{Fingerprint: "1"}}
	p2 := Candidate{Family: FamilySCION, IA: "1-150", Priority: 1, Label: "p2", Path: &SCIONPath{Fingerprint: "2"}}
	p3 := Candidate{Family: FamilySCION, IA: "1-150", Priority: 1, Label: "p3", Path: &SCIONPath{Fingerprint: "3"}}

	got := Sort([]Candidate{p1, p2, p3}, true, 1)
	want := []string{"p1", "p2", "p3"}
	if g := labels(got); !reflect.DeepEqual(g, want) {
		t.Fatalf("got %v, want %v", g, want)
	}
}

// nativeSCION=false: preference order is IPv6, IPv4 (no SCION-first).
func TestSort_NonNativeSCION_IPv6First(t *testing.T) {
	bothFamiliesReachable(t)
	v4a := Candidate{Family: FamilyIPv4, Host: "203.0.113.1", Priority: 1, Label: "v4a"}
	v6a := Candidate{Family: FamilyIPv6, Host: "2001:db8::1", Priority: 1, Label: "v6a"}

	got := Sort([]Candidate{v4a, v6a}, false, 1)
	want := []string{"v6a", "v4a"}
	if g := labels(got); !reflect.DeepEqual(g, want) {
		t.Fatalf("got %v, want %v", g, want)
	}
}

// ViaScitra candidates dial as IPv6 (belong to FamilyIPv6 for interleaving)
// but must tie-break after real IPv6 candidates at equal priority.
func TestSort_ScitraTiebreakAfterRealIPv6(t *testing.T) {
	bothFamiliesReachable(t)
	scitra := Candidate{Family: FamilyIPv6, Host: "fc00:961:9600::1", Priority: 1, ViaScitra: true, Label: "scitra"}
	realV6 := Candidate{Family: FamilyIPv6, Host: "2001:db8::1", Priority: 1, ViaScitra: false, Label: "realv6"}
	v4a := Candidate{Family: FamilyIPv4, Host: "203.0.113.1", Priority: 1, Label: "v4a"}

	// Feed scitra before realV6 to prove the tie-break reorders them.
	got := Sort([]Candidate{scitra, realV6, v4a}, false, 1)
	want := []string{"realv6", "v4a", "scitra"}
	if g := labels(got); !reflect.DeepEqual(g, want) {
		t.Fatalf("got %v, want %v", g, want)
	}
}

// nativeSCION=false with a stray SCION candidate present (should not happen
// in practice, but the sorter must not drop or crash on it): sorts last.
func TestSort_NonNativeSCION_StraySCIONSortsLast(t *testing.T) {
	bothFamiliesReachable(t)
	v4a := Candidate{Family: FamilyIPv4, Host: "203.0.113.1", Priority: 1, Label: "v4a"}
	v6a := Candidate{Family: FamilyIPv6, Host: "2001:db8::1", Priority: 1, Label: "v6a"}
	stray := Candidate{Family: FamilySCION, IA: "1-150", Priority: 1, Label: "stray", Path: &SCIONPath{Fingerprint: "x"}}

	got := Sort([]Candidate{stray, v4a, v6a}, false, 1)
	want := []string{"v6a", "v4a", "stray"}
	if g := labels(got); !reflect.DeepEqual(g, want) {
		t.Fatalf("got %v, want %v", g, want)
	}
}

// Sort must be stable: candidates with identical group/priority/family/
// ViaScitra keys keep their relative input order.
func TestSort_StableForEqualKeys(t *testing.T) {
	a := Candidate{Family: FamilyIPv4, Host: "203.0.113.1", Priority: 3, Label: "a"}
	b := Candidate{Family: FamilyIPv4, Host: "203.0.113.2", Priority: 3, Label: "b"}
	c := Candidate{Family: FamilyIPv4, Host: "203.0.113.3", Priority: 3, Label: "c"}

	got := Sort([]Candidate{a, b, c}, true, 1)
	want := []string{"a", "b", "c"}
	if g := labels(got); !reflect.DeepEqual(g, want) {
		t.Fatalf("got %v, want %v", g, want)
	}
}

// HEv3 §5.3 Preferred Address Family Count above 1: the list starts with
// that many endpoints of the first family; after that leading run the
// families take one endpoint each in turn.
func TestSort_PreferredFamilyCountAboveOne(t *testing.T) {
	bothFamiliesReachable(t)
	// SCION endpoints share IA and host, so their random order key is
	// equal and they keep their input order.
	s := func(l string) Candidate {
		return Candidate{Family: FamilySCION, IA: "1-150", Priority: 1, Label: l, Path: &SCIONPath{Fingerprint: l}}
	}
	x := func(l, host string) Candidate {
		return Candidate{Family: FamilyIPv6, Host: host, Priority: 1, Label: l}
	}
	y := func(l, host string) Candidate {
		return Candidate{Family: FamilyIPv4, Host: host, Priority: 1, Label: l}
	}
	x1, x2, x3, x4 := x("x1", "2001:db8::1"), x("x2", "2001:db8::2"), x("x3", "2001:db8::3"), x("x4", "2001:db8::4")
	y1, y2 := y("y1", "203.0.113.1"), y("y2", "203.0.113.2")

	cases := []struct {
		name      string
		in        []Candidate
		scionLast bool
		want      []string
	}{
		{
			name: "SCION first, short",
			in:   []Candidate{y1, x1, s("s1"), s("s2"), s("s3")},
			want: []string{"s1", "s2", "x1", "y1", "s3"},
		},
		{
			// N endpoints of the first family only at the start; N in
			// every round would give s1 s2 x1 y1 s3 s4 x2 y2.
			name: "SCION first, four SCION endpoints",
			in:   []Candidate{y1, y2, x1, x2, s("s1"), s("s2"), s("s3"), s("s4")},
			want: []string{"s1", "s2", "x1", "y1", "s3", "x2", "y2", "s4"},
		},
		{
			// The first family is IPv6; N in every round would give
			// x1 x2 y1 s1 x3 x4 y2 s2.
			name:      "SCION last, four IPv6 endpoints",
			in:        []Candidate{s("s1"), s("s2"), y1, y2, x1, x2, x3, x4},
			scionLast: true,
			want:      []string{"x1", "x2", "y1", "s1", "x3", "y2", "s2", "x4"},
		},
		{
			// No SCION endpoint: the count applies to IPv6, the family
			// that is first in the list.
			name: "SCION first, no SCION endpoints",
			in:   []Candidate{y1, y2, x1, x2, x3},
			want: []string{"x1", "x2", "y1", "x3", "y2"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := labels(SortOrder(tc.in, true, 2, tc.scionLast))
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// HEv3 §5.2: endpoints are grouped by service priority before the families
// are interleaved. A SCION endpoint of a priority-9 record comes after an
// IPv4 endpoint of a priority-1 record, although SCION is the first family.
func TestSort_ServicePriorityBeforeFamilyInterleave(t *testing.T) {
	v4 := Candidate{Family: FamilyIPv4, Host: "203.0.113.1", Priority: 1, Label: "v4"}
	scion := Candidate{Family: FamilySCION, IA: "1-150", Priority: 9, Label: "scion", Path: &SCIONPath{Fingerprint: "p"}}

	got := Sort([]Candidate{scion, v4}, true, 1)
	want := []string{"v4", "scion"}
	if g := labels(got); !reflect.DeepEqual(g, want) {
		t.Fatalf("got %v, want %v", g, want)
	}
}

// §5.1+§5.2 regression, pinning committed behavior: candidates interleave by
// family *within* each ALPN group, and the groups are concatenated by rank
// (best member Priority). Two groups, mixed families, fed scrambled.
func TestSort_MultiGroupMultiFamilyOrder(t *testing.T) {
	// Group {h3}: rank 1 (via scionA). Interleave (SCION,IPv6): scionA, v6A.
	scionA := Candidate{Family: FamilySCION, IA: "1-150", Priority: 1, ALPN: []string{"h3"}, Label: "scionA", Path: &SCIONPath{Fingerprint: "a"}}
	v6A := Candidate{Family: FamilyIPv6, Host: "2001:db8::1", Priority: 3, ALPN: []string{"h3"}, Label: "v6A"}
	// Group {} (default ALPN): rank 2. Interleave (SCION,IPv4): scionB, v4B.
	scionB := Candidate{Family: FamilySCION, IA: "1-151", Priority: 2, Label: "scionB", Path: &SCIONPath{Fingerprint: "b"}}
	v4B := Candidate{Family: FamilyIPv4, Host: "203.0.113.2", Priority: 2, Label: "v4B"}

	got := Sort([]Candidate{v4B, v6A, scionB, scionA}, true, 1)
	want := []string{"scionA", "v6A", "scionB", "v4B"}
	if g := labels(got); !reflect.DeepEqual(g, want) {
		t.Fatalf("got %v, want %v", g, want)
	}
}

// Empty and single-candidate inputs must not panic.
func TestSort_EmptyAndSingle(t *testing.T) {
	if got := Sort(nil, true, 1); len(got) != 0 {
		t.Fatalf("Sort(nil) = %v, want empty", got)
	}
	only := Candidate{Family: FamilyIPv4, Host: "203.0.113.1", Priority: 1, Label: "only"}
	got := Sort([]Candidate{only}, true, 1)
	if g := labels(got); !reflect.DeepEqual(g, []string{"only"}) {
		t.Fatalf("got %v, want [only]", g)
	}
}

// §5.3 MUST: within a family bucket, destinations follow RFC 6724 order;
// same-address transports keep QUIC before TCP.
func TestSort_RFC6724WithinFamilyAndTransportOrder(t *testing.T) {
	old := udpSource
	defer func() { udpSource = old }()
	udpSource = fixedSource(map[string]string{
		"fc00:1::10":   "fc00:1::1",
		"2001:db8::10": "2001:db8::1",
	})

	// All three come from one service record covering both addresses
	// (fc00:1::10's QUIC leg dropped e.g. by a per-address SCION/QUIC
	// constraint, only its TCP sibling survives) — the resolver stamps
	// GroupALPN with the record's full supported set on every candidate it
	// emits (types.go's GroupALPN doc comment), so they share one §5.1
	// group despite carrying different per-candidate dial ALPN.
	groupALPN := []string{"h3", "h2"}
	in := []Candidate{
		{Family: FamilyIPv6, Host: "fc00:1::10", ALPN: []string{"h2"}, GroupALPN: groupALPN, Label: "v6+tcp:fc00:1::10"},
		{Family: FamilyIPv6, Host: "2001:db8::10", ALPN: []string{"h2"}, GroupALPN: groupALPN, Label: "v6+tcp:2001:db8::10"},
		{Family: FamilyIPv6, Host: "2001:db8::10", ALPN: []string{"h3"}, GroupALPN: groupALPN, Label: "v6:2001:db8::10"},
	}
	got := labels(Sort(in, false, 1))
	want := []string{"v6:2001:db8::10", "v6+tcp:2001:db8::10", "v6+tcp:fc00:1::10"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Sort = %v, want %v (global before ULA; h3 before tcp per address)", got, want)
	}
}

// Plan amendment: dual-transport candidates from ONE service record carry
// different dial ALPN (QUIC ["h3"] vs TCP ["h2","http/1.1"]), but must land
// in the SAME §5.1 group — grouping keys off GroupALPN (the record's full
// supported set) when set, not the per-candidate dial ALPN. Two addresses,
// each with QUIC+TCP candidates sharing GroupALPN, equal Priority, equal
// rfc6724 rank (fixedSource maps both to the same key) — input order must
// be preserved exactly: per-address transport adjacency (QUIC before TCP),
// stable ties across addresses.
func TestSort_GroupALPNUnifiesDualTransportGroup(t *testing.T) {
	old := udpSource
	defer func() { udpSource = old }()
	// Empty map: udpSource returns an invalid source for every destination,
	// so both addresses are equally "unreachable" with identical
	// precedence/scope (both global 2001:db8::/32 documentation-prefix
	// addresses) -> equal rfc6724Key -> a true tie between a1 and a2.
	udpSource = fixedSource(map[string]string{})

	groupALPN := []string{"h3", "h2", "http/1.1"}
	a1h3 := Candidate{Family: FamilyIPv6, Host: "2001:db8::1", ALPN: []string{"h3"}, GroupALPN: groupALPN, Priority: 1, Label: "a1-h3"}
	a1tcp := Candidate{Family: FamilyIPv6, Host: "2001:db8::1", ALPN: []string{"h2", "http/1.1"}, GroupALPN: groupALPN, Priority: 1, Label: "a1-tcp"}
	a2h3 := Candidate{Family: FamilyIPv6, Host: "2001:db8::2", ALPN: []string{"h3"}, GroupALPN: groupALPN, Priority: 1, Label: "a2-h3"}
	a2tcp := Candidate{Family: FamilyIPv6, Host: "2001:db8::2", ALPN: []string{"h2", "http/1.1"}, GroupALPN: groupALPN, Priority: 1, Label: "a2-tcp"}

	in := []Candidate{a1h3, a1tcp, a2h3, a2tcp}
	got := labels(Sort(in, false, 1))
	want := []string{"a1-h3", "a1-tcp", "a2-h3", "a2-tcp"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Sort (GroupALPN set) = %v, want %v (unified group, order preserved)", got, want)
	}

	// Contrast: same candidates but GroupALPN nil on all of them -> grouping
	// falls back to dial ALPN, splitting QUIC and TCP into separate §5.1
	// groups (all-QUIC-then-all-TCP), proving GroupALPN is load-bearing.
	a1h3.GroupALPN, a1tcp.GroupALPN, a2h3.GroupALPN, a2tcp.GroupALPN = nil, nil, nil, nil
	in2 := []Candidate{a1h3, a1tcp, a2h3, a2tcp}
	got2 := labels(Sort(in2, false, 1))
	want2 := []string{"a1-h3", "a2-h3", "a1-tcp", "a2-tcp"}
	if !reflect.DeepEqual(got2, want2) {
		t.Errorf("Sort (GroupALPN nil) = %v, want %v (dial-ALPN grouping splits transports)", got2, want2)
	}
}

// Reviewer hardening follow-up: sortIPBucket's comparator must be a strict
// weak ordering, not merely order-preserving for already-valid inputs. Feed
// a transport-INVERTED input (a1's TCP candidate before a2's QUIC candidate
// before a1's own QUIC candidate) and assert Sort REPAIRS it into
// per-address QUIC-first, addresses-grouped order — a stronger property
// than TestSort_GroupALPNUnifiesDualTransportGroup's "preserves a
// well-formed input" check, and one the old conditional "same address"
// comparator clause could not deliver (it only reordered pairs the
// underlying sort happened to compare directly).
func TestSort_ComparatorRepairsTransportInvertedInput(t *testing.T) {
	old := udpSource
	defer func() { udpSource = old }()
	// Empty map: both addresses tie on rfc6724Key (see
	// TestSort_GroupALPNUnifiesDualTransportGroup's comment) — a genuine
	// tie, so any correct ordering is driven entirely by the comparator's
	// host-grouping and QUIC-before-TCP levels, not by address reachability.
	udpSource = fixedSource(map[string]string{})

	groupALPN := []string{"h3", "h2", "http/1.1"}
	a1h3 := Candidate{Family: FamilyIPv6, Host: "2001:db8::1", ALPN: []string{"h3"}, GroupALPN: groupALPN, Priority: 1, Label: "a1-h3"}
	a1tcp := Candidate{Family: FamilyIPv6, Host: "2001:db8::1", ALPN: []string{"h2", "http/1.1"}, GroupALPN: groupALPN, Priority: 1, Label: "a1-tcp"}
	a2h3 := Candidate{Family: FamilyIPv6, Host: "2001:db8::2", ALPN: []string{"h3"}, GroupALPN: groupALPN, Priority: 1, Label: "a2-h3"}
	a2tcp := Candidate{Family: FamilyIPv6, Host: "2001:db8::2", ALPN: []string{"h2", "http/1.1"}, GroupALPN: groupALPN, Priority: 1, Label: "a2-tcp"}

	in := []Candidate{a1tcp, a2h3, a1h3, a2tcp}
	got := labels(Sort(in, false, 1))
	want := []string{"a1-h3", "a1-tcp", "a2-h3", "a2-tcp"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Sort (transport-inverted input) = %v, want %v (comparator must repair, not just preserve)", got, want)
	}
}

// draft-john-scion-happy-eyeballs, Sorting Endpoints: with SCION
// connectivity, the family after SCION is the family of the first IP
// endpoint after Destination Address Selection - here IPv4, because the
// IPv6 address is unreachable (RFC 6724 rule 1).
func TestSort_NativeSCION_SecondFamilyFromRFC6724(t *testing.T) {
	old := udpSource
	defer func() { udpSource = old }()
	udpSource = fixedSource(map[string]string{"203.0.113.1": "198.51.100.1"})
	v6 := Candidate{Family: FamilyIPv6, Host: "2001:db8::1", Label: "v6"}
	v6b := Candidate{Family: FamilyIPv6, Host: "2001:db8::2", Label: "v6b"}
	v4 := Candidate{Family: FamilyIPv4, Host: "203.0.113.1", Label: "v4"}
	sc := Candidate{Family: FamilySCION, IA: "1-150", Label: "sc", Path: &SCIONPath{Hops: 2}}
	got := labels(Sort([]Candidate{v6, v6b, v4, sc}, true, 1))
	want := []string{"sc", "v4", "v6", "v6b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// SCION endpoints of one group are ordered at random among themselves:
// the order is the same when the same endpoints are sorted again, differs
// between seeds, and endpoints whose lookup is in progress (no path) are last.
func TestSort_SCIONEndpointsRandom(t *testing.T) {
	mk := func(host string, p *SCIONPath) Candidate {
		return Candidate{Family: FamilySCION, IA: "1-150", Host: host, Label: host, Path: p}
	}
	in := []Candidate{mk("proto", nil)}
	for _, h := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		in = append(in, mk(h, &SCIONPath{Hops: 2}))
	}
	old := scionOrderSeed
	defer func() { scionOrderSeed = old }()
	orders := map[string]bool{}
	for i := 0; i < 20; i++ {
		scionOrderSeed = maphash.MakeSeed()
		got := labels(Sort(in, true, 1))
		if again := labels(Sort(in, true, 1)); !reflect.DeepEqual(got, again) {
			t.Fatalf("order changed between two sorts: %v, %v", got, again)
		}
		if len(got) != len(in) || got[len(got)-1] != "proto" {
			t.Fatalf("got %v, want the endpoint without a path last", got)
		}
		orders[strings.Join(got, ",")] = true
	}
	if len(orders) < 2 {
		t.Fatalf("20 seeds gave one order: %v", orders)
	}
}
