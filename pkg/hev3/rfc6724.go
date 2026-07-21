package hev3

import (
	"net"
	"net/netip"
)

// This file implements the subset of RFC 6724 §6 destination address
// selection that draft-ietf-happy-happyeyeballs-v3-04 §5.3 requires for
// ordering endpoints within a family bucket: rules 1 (avoid unreachable),
// 2 (matching scope), 6 (higher precedence), 8 (smaller scope) and 9
// (longest common prefix with the chosen source). Rules 3-5, 7 and 10
// need per-interface state we don't track; rule 10 (leave order) is the
// stable-sort fallback.

// udpSource returns the source address the kernel would choose for dst
// (connected-UDP trick; no packets leave the host). Invalid Addr = no
// route. Package var so tests inject fixed sources.
var udpSource = func(dst netip.Addr) netip.Addr {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, 53)))
	if err != nil {
		return netip.Addr{}
	}
	defer c.Close()
	if la, ok := c.LocalAddr().(*net.UDPAddr); ok {
		if a, ok2 := netip.AddrFromSlice(la.IP); ok2 {
			return a.Unmap()
		}
	}
	return netip.Addr{}
}

type rfc6724Key struct {
	unreachable bool
	scopeMatch  bool
	precedence  int
	scope       int
	prefixLen   int
}

type policyEntry struct {
	prefix     netip.Prefix
	precedence int
}

// rfc6724Policy is the RFC 6724 §2.1 default policy table (labels
// omitted: rule 5 needs source labels we don't evaluate).
var rfc6724Policy = []policyEntry{
	{netip.MustParsePrefix("::1/128"), 50},
	{netip.MustParsePrefix("::/0"), 40},
	{netip.MustParsePrefix("::ffff:0:0/96"), 35},
	{netip.MustParsePrefix("2002::/16"), 30},
	{netip.MustParsePrefix("2001::/32"), 5},
	{netip.MustParsePrefix("fc00::/7"), 3},
	{netip.MustParsePrefix("::/96"), 1},
	{netip.MustParsePrefix("fec0::/10"), 1},
	{netip.MustParsePrefix("3ffe::/16"), 1},
}

// as16 maps an address into its 16-byte form (v4 → v4-mapped v6), the
// representation the policy table and CommonPrefixLen operate on.
func as16(a netip.Addr) netip.Addr {
	if a.Is4() {
		return netip.AddrFrom16(a.As16())
	}
	return a
}

func precedenceOf(a netip.Addr) int {
	a16 := as16(a)
	best, bestBits := 40, -1
	for _, e := range rfc6724Policy {
		if e.prefix.Contains(a16) && e.prefix.Bits() > bestBits {
			best, bestBits = e.precedence, e.prefix.Bits()
		}
	}
	return best
}

// scopeOf per RFC 6724 §3.1: multicast scopes aside (we never dial
// multicast), loopback and link-local map to link-local scope 0x2,
// site-local to 0x5, everything else (including ULA and RFC 1918 v4,
// per §3.2) is global 0xe.
func scopeOf(a netip.Addr) int {
	u := a.Unmap()
	switch {
	case u.IsLoopback(), u.IsLinkLocalUnicast():
		return 0x2
	case u.Is6() && !u.Is4In6() && netip.MustParsePrefix("fec0::/10").Contains(u):
		return 0x5
	default:
		return 0xe
	}
}

// commonPrefixLen counts leading equal bits of the 16-byte forms.
func commonPrefixLen(a, b netip.Addr) int {
	ab, bb := as16(a).As16(), as16(b).As16()
	n := 0
	for i := 0; i < 16; i++ {
		x := ab[i] ^ bb[i]
		if x == 0 {
			n += 8
			continue
		}
		for x&0x80 == 0 {
			n++
			x <<= 1
		}
		break
	}
	return n
}

func rfc6724KeyFor(dst netip.Addr) rfc6724Key {
	src := udpSource(dst)
	k := rfc6724Key{
		unreachable: !src.IsValid(),
		precedence:  precedenceOf(dst),
		scope:       scopeOf(dst),
	}
	if src.IsValid() {
		k.scopeMatch = scopeOf(dst) == scopeOf(src)
		k.prefixLen = commonPrefixLen(dst, src)
	}
	return k
}

// rfc6724Cmp: negative = a sorts first. Rules implemented (subset of
// RFC 6724 §6, documented above): 1 (reachable first), 2 (scope match), 6
// (higher precedence), 8 (smaller scope), 9 (longer common prefix).
func rfc6724Cmp(a, b rfc6724Key) int {
	switch { // rule 1
	case a.unreachable && !b.unreachable:
		return 1
	case !a.unreachable && b.unreachable:
		return -1
	}
	if a.scopeMatch != b.scopeMatch { // rule 2
		if a.scopeMatch {
			return -1
		}
		return 1
	}
	if a.precedence != b.precedence { // rule 6
		return b.precedence - a.precedence
	}
	if a.scope != b.scope { // rule 8
		return a.scope - b.scope
	}
	if a.prefixLen != b.prefixLen { // rule 9
		return b.prefixLen - a.prefixLen
	}
	return 0
}
