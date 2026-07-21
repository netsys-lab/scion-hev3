package hev3

import (
	"net/netip"
	"testing"
)

func fixedSource(m map[string]string) func(netip.Addr) netip.Addr {
	return func(dst netip.Addr) netip.Addr {
		if s, ok := m[dst.String()]; ok {
			return netip.MustParseAddr(s)
		}
		return netip.Addr{}
	}
}

func TestRFC6724_PrecedenceAndReachability(t *testing.T) {
	old := udpSource
	defer func() { udpSource = old }()
	udpSource = fixedSource(map[string]string{
		"2001:db8::10": "2001:db8::1", // global with global source
		"fc00:1::10":   "fc00:1::1",   // ULA with ULA source
		"2002::10":     "2001:db8::1", // 6to4 dst
	})

	global := rfc6724KeyFor(netip.MustParseAddr("2001:db8::10"))
	ula := rfc6724KeyFor(netip.MustParseAddr("fc00:1::10"))
	sixToFour := rfc6724KeyFor(netip.MustParseAddr("2002::10"))
	unreachable := rfc6724KeyFor(netip.MustParseAddr("2001:db8:dead::1"))

	if rfc6724Cmp(global, ula) >= 0 {
		t.Errorf("global (prec 40) must sort before ULA (prec 3)")
	}
	if rfc6724Cmp(global, sixToFour) >= 0 {
		t.Errorf("native v6 (prec 40) must sort before 6to4 (prec 30)")
	}
	if rfc6724Cmp(ula, unreachable) >= 0 {
		t.Errorf("reachable ULA must sort before unreachable global (rule 1)")
	}
}

func TestRFC6724_LongestPrefixTieBreak(t *testing.T) {
	old := udpSource
	defer func() { udpSource = old }()
	udpSource = fixedSource(map[string]string{
		"2001:db8:aaaa::10": "2001:db8:aaaa::1", // 48-bit match
		"2001:db8:bbbb::10": "2001:db8:aaaa::1", // 32-bit match
	})
	near := rfc6724KeyFor(netip.MustParseAddr("2001:db8:aaaa::10"))
	far := rfc6724KeyFor(netip.MustParseAddr("2001:db8:bbbb::10"))
	if rfc6724Cmp(near, far) >= 0 {
		t.Errorf("longer common prefix with source must sort first (rule 9)")
	}
}
