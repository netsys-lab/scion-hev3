package hev3

import (
	"hash/maphash"
	"net/netip"
	"sort"
)

// scionOrderSeed makes the order of the SCION endpoints of one group random
// (draft-john-scion-happy-eyeballs, "Sorting Endpoints"). It is drawn once
// per process, so that sorting the same endpoints again (when DNS answers
// or path lookups arrive) keeps their order.
var scionOrderSeed = maphash.MakeSeed()

func scionOrderKey(c Candidate) uint64 {
	return maphash.String(scionOrderSeed, c.IA+","+c.Host)
}

// Sort orders cands per draft-ietf-happy-happyeyeballs-v3 §5, extended
// with SCION as a third address family per draft-john-scion-happy-eyeballs
// "Sorting Endpoints": SCION endpoints are ordered at random among
// themselves, and a client with SCION connectivity (nativeSCION) orders the
// families SCION, then the family of the first IP endpoint after
// Destination Address Selection, then the other IP family.
//
// preferredFamilyCount is the Preferred Address Family Count (§5.3,
// RFC 8305 §4): how many endpoints of the first family start the list
// before the first endpoint of another family. After that leading run the
// families take one endpoint each in turn.
func Sort(cands []Candidate, nativeSCION bool, preferredFamilyCount int) []Candidate {
	return SortOrder(cands, nativeSCION, preferredFamilyCount, false)
}

// SortOrder is Sort with a choice of where a client with SCION
// connectivity orders the SCION family: first (scionLast false), or after
// both IP families (scionLast true).
func SortOrder(cands []Candidate, nativeSCION bool, preferredFamilyCount int, scionLast bool) []Candidate {
	if len(cands) == 0 {
		return nil
	}
	if preferredFamilyCount < 1 {
		preferredFamilyCount = 1
	}

	groups := groupByALPN(cands)

	// §5.1: groups sort ascending by their best (lowest) member Priority.
	sort.SliceStable(groups, func(i, j int) bool {
		return groups[i].rank < groups[j].rank
	})

	out := make([]Candidate, 0, len(cands))
	for _, g := range groups {
		out = append(out, sortGroup(g.members, nativeSCION, preferredFamilyCount, scionLast)...)
	}
	return out
}

type alpnGroup struct {
	members []Candidate
	rank    uint16 // best (lowest) member Priority
}

// groupByALPN buckets candidates whose ALPN slice is set-equal (order and
// duplicates ignored — §4.1 SVCB ALPN is a set), preserving first-seen
// group order so equal-rank groups tie-break by input order (§5.1).
//
// Grouping keys off GroupALPN when the candidate has one, not off the
// per-candidate dial ALPN: a single service record's QUIC and TCP
// candidates carry different dial ALPN ("h3" vs "h2,http/1.1"), but must
// land in the SAME §5.1 group — otherwise the race becomes
// all-QUIC-then-all-TCP instead of per-address QUIC-before-TCP (§5.3).
// Legacy no-service-record and unassociated-trailing candidates have no
// GroupALPN (nil) and keep grouping by their own (also empty) ALPN.
func groupByALPN(cands []Candidate) []*alpnGroup {
	index := make(map[string]*alpnGroup, len(cands))
	var order []*alpnGroup
	for _, c := range cands {
		key := alpnKey(c.GroupALPN)
		if c.GroupALPN == nil {
			key = alpnKey(c.ALPN)
		}
		g, ok := index[key]
		if !ok {
			g = &alpnGroup{rank: c.Priority}
			index[key] = g
			order = append(order, g)
		} else if c.Priority < g.rank {
			g.rank = c.Priority
		}
		g.members = append(g.members, c)
	}
	return order
}

func alpnKey(alpn []string) string {
	if len(alpn) == 0 {
		return ""
	}
	sorted := append([]string(nil), alpn...)
	sort.Strings(sorted)
	key := sorted[0]
	for _, p := range sorted[1:] {
		key += "," + p
	}
	return key
}

// sortGroup orders one ALPN group: it groups the members by service
// priority (HEv3 §5.2), lowest value first, and orders each of these groups
// by sortPriorityGroup.
func sortGroup(members []Candidate, nativeSCION bool, preferredFamilyCount int, scionLast bool) []Candidate {
	byPrio := map[uint16][]Candidate{}
	var prios []uint16
	for _, c := range members {
		if _, ok := byPrio[c.Priority]; !ok {
			prios = append(prios, c.Priority)
		}
		byPrio[c.Priority] = append(byPrio[c.Priority], c)
	}
	sort.Slice(prios, func(i, j int) bool { return prios[i] < prios[j] })
	out := make([]Candidate, 0, len(members))
	for _, p := range prios {
		out = append(out, sortPriorityGroup(byPrio[p], nativeSCION, preferredFamilyCount, scionLast)...)
	}
	return out
}

// sortPriorityGroup orders the endpoints of one ALPN group and one service
// priority: buckets by family, orders each bucket (SCION endpoints at
// random; IP buckets by the §5.3 RFC 6724 + transport ordering, see
// sortIPBucket), then applies the family interleave.
func sortPriorityGroup(members []Candidate, nativeSCION bool, preferredFamilyCount int, scionLast bool) []Candidate {
	buckets := make(map[Family][]Candidate, 3)
	for _, c := range members {
		buckets[c.Family] = append(buckets[c.Family], c)
	}
	for f, b := range buckets {
		if f == FamilySCION {
			// Endpoints without a path set (lookup in progress) last;
			// the others at random.
			sort.SliceStable(b, func(i, j int) bool { return scionLess(b[i], b[j]) })
		} else {
			sortIPBucket(b)
		}
	}

	// §5.2: family preference order. A native SCION stack tries SCION
	// first, then IPv6, then IPv4. Without native SCION, IPv6 then IPv4
	// (ViaScitra candidates are FamilyIPv6, so they interleave normally
	// here); any FamilySCION candidate that shouldn't exist in this case
	// is appended last rather than interleaved.
	var order, trailing []Family
	if nativeSCION {
		order = []Family{FamilySCION, FamilyIPv6, FamilyIPv4}
		if firstIPFamily(buckets[FamilyIPv6], buckets[FamilyIPv4]) == FamilyIPv4 {
			order = []Family{FamilySCION, FamilyIPv4, FamilyIPv6}
		}
		if scionLast {
			order = []Family{order[1], order[2], FamilySCION}
		}
	} else {
		order = []Family{FamilyIPv6, FamilyIPv4}
		if firstIPFamily(buckets[FamilyIPv6], buckets[FamilyIPv4]) == FamilyIPv4 {
			order = []Family{FamilyIPv4, FamilyIPv6}
		}
		trailing = []Family{FamilySCION}
	}

	// §5.3 interleave (RFC 8305 §4), generalized to three families: the
	// list starts with preferredFamilyCount endpoints of the first family,
	// then the families take one endpoint each in turn. Families without
	// endpoints are skipped, so the count applies to the family that is
	// actually first in the list.
	present := order[:0:0]
	for _, f := range order {
		if len(buckets[f]) > 0 {
			present = append(present, f)
		}
	}
	order = present
	out := make([]Candidate, 0, len(members))
	first := preferredFamilyCount
	for hasRemaining(buckets, order) {
		out = append(out, take(buckets, order[0], first)...)
		first = 1
		for _, f := range order[1:] {
			out = append(out, take(buckets, f, 1)...)
		}
	}
	for _, f := range trailing {
		out = append(out, buckets[f]...)
	}
	return out
}

// scionLess orders two SCION endpoints of one group.
func scionLess(a, b Candidate) bool {
	if a.Priority != b.Priority {
		return a.Priority < b.Priority
	}
	pa, pb := a.Path, b.Path
	if (pa == nil) != (pb == nil) {
		return pa != nil
	}
	if pa == nil {
		return false
	}
	return scionOrderKey(a) < scionOrderKey(b)
}

// firstIPFamily returns the family of the first IP endpoint when the
// (already sorted) IPv6 and IPv4 buckets are ordered together by
// Destination Address Selection (sortIPBucket); IPv6 if there are none.
func firstIPFamily(v6, v4 []Candidate) Family {
	if len(v6) == 0 || len(v4) == 0 {
		if len(v4) > 0 {
			return FamilyIPv4
		}
		return FamilyIPv6
	}
	both := append(append([]Candidate(nil), v6...), v4...)
	sortIPBucket(both)
	return both[0].Family
}

func hasRemaining(buckets map[Family][]Candidate, order []Family) bool {
	for _, f := range order {
		if len(buckets[f]) > 0 {
			return true
		}
	}
	return false
}

// take removes and returns up to n candidates from the front of buckets[f].
func take(buckets map[Family][]Candidate, f Family, n int) []Candidate {
	b := buckets[f]
	if n > len(b) {
		n = len(b)
	}
	taken := b[:n]
	buckets[f] = b[n:]
	return taken
}

// sortIPBucket orders one IP family bucket in place via a fully
// lexicographic, five-level comparator: (a) §5.1 ascending Priority, (b)
// scitra legs after real ones (companion spec), (c) RFC 6724 §6 order
// between distinct addresses (§5.3 MUST), (d) same-Host candidates grouped
// contiguously in first-seen order, (e) same address: QUIC before TCP.
// Each level is a total preorder on its key, so the composition is a
// strict weak ordering — the contract sort.Slice/sort.SliceStable require.
// (An earlier version made level (e) conditional on "same address",
// producing only a partial relation: a1-h3 ~ a2-h3 and a2-h3 ~ a1-tcp by
// levels (a)-(c)/(d)-absent, yet a1-h3 < a1-tcp by (e) — intransitive.
// Level (d) closes that hole by making address-equality itself a strict
// total-ordered level, so (e) only ever compares candidates already forced
// adjacent.)
func sortIPBucket(b []Candidate) {
	keys := make(map[string]rfc6724Key, len(b))
	// firstSeen/hostIndex implement level (d): the bucket index of the
	// first candidate carrying a given Host, so all candidates sharing
	// that Host sort contiguously (and in first-seen relative order
	// against other hosts), independent of any per-candidate field.
	firstSeen := make(map[string]int, len(b))
	hostIndex := make([]int, len(b))
	for i, c := range b {
		if fi, ok := firstSeen[c.Host]; ok {
			hostIndex[i] = fi
		} else {
			firstSeen[c.Host] = i
			hostIndex[i] = i
		}
		if _, ok := keys[c.Host]; ok {
			continue
		}
		if a, err := netip.ParseAddr(c.Host); err == nil {
			keys[c.Host] = rfc6724KeyFor(a)
		}
		// unparseable host: no map entry, so keys[c.Host] resolves to the
		// zero rfc6724Key at comparison time — stable fallback.
	}
	idx := make([]int, len(b))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(x, y int) bool {
		i, j := idx[x], idx[y]
		if b[i].Priority != b[j].Priority { // (a)
			return b[i].Priority < b[j].Priority
		}
		if b[i].ViaScitra != b[j].ViaScitra { // (b)
			return !b[i].ViaScitra
		}
		if c := rfc6724Cmp(keys[b[i].Host], keys[b[j].Host]); c != 0 { // (c)
			return c < 0
		}
		if hostIndex[i] != hostIndex[j] { // (d)
			return hostIndex[i] < hostIndex[j]
		}
		if h3i, h3j := offersH3(b[i].ALPN), offersH3(b[j].ALPN); h3i != h3j { // (e)
			return h3i
		}
		return false // equal on all five levels: stable tie.
	})
	sorted := make([]Candidate, len(b))
	for x, i := range idx {
		sorted[x] = b[i]
	}
	copy(b, sorted)
}
