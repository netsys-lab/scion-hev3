package hev3

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestFetch_EndToEndIPOnly exercises the full resolve → engine (live merge +
// async expansion) → GET pipeline against a local h2 server (the dev box has no
// SCION daemon or scitra route, so this is the IP-only path — SCION legs are
// exercised in testbed integration). It asserts the Timeline carries a
// query→candidate→attempt→winner sequence and the fetched body is non-empty.
func TestFetch_EndToEndIPOnly(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "hello-fetch-e2e")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	tcp := srv.Listener.Addr().(*net.TCPAddr)

	f := newFakeDNS(t)
	f.set("fetch.test.", dns.TypeA, mustRR(t, fmt.Sprintf("fetch.test. 300 IN A %s", tcp.IP.String())))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rawURL := fmt.Sprintf("https://fetch.test:%d/", tcp.Port)
	res, err := Fetch(ctx, rawURL, Options{
		Resolver:        f.addr,
		Insecure:        true,
		ResolutionDelay: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if len(res.Body) == 0 {
		t.Fatal("Result.Body is empty, want the served response")
	}
	if !strings.Contains(string(res.Body), "hello-fetch-e2e") {
		t.Fatalf("Result.Body = %q, want it to contain the served response", res.Body)
	}
	if res.Winner.Family != FamilyIPv4 {
		t.Fatalf("Winner.Family = %v, want FamilyIPv4 (dev box has no SCION)", res.Winner.Family)
	}
	if !strings.Contains(res.Status, "200") {
		t.Fatalf("Result.Status = %q, want it to mention 200", res.Status)
	}

	// query -> candidate -> attempt -> winner, in that relative order.
	idx := map[string]int{}
	for i, ev := range res.Timeline {
		if _, ok := idx[ev.Kind]; !ok {
			idx[ev.Kind] = i
		}
	}
	for _, kind := range []string{"query", "candidate", "attempt", "winner"} {
		if _, ok := idx[kind]; !ok {
			t.Fatalf("Timeline has no %q event: %+v", kind, res.Timeline)
		}
	}
	if !(idx["query"] < idx["candidate"] && idx["candidate"] < idx["attempt"] && idx["attempt"] < idx["winner"]) {
		t.Fatalf("Timeline kinds out of order: query=%d candidate=%d attempt=%d winner=%d",
			idx["query"], idx["candidate"], idx["attempt"], idx["winner"])
	}
}

// closedPort returns a "127.0.0.1:port" that is guaranteed to refuse
// connections: a listener is opened and immediately closed, so nothing is
// bound there when the caller dials it (the standard Go pattern for
// deterministically getting an address that won't accept a connection).
func closedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return addr
}

// TestFetch_SCIONOnlyInitialWithLateAStillFetches is the regression test for
// the race documented in .superpowers/sdd/task-13-report.md's "Concerns"
// section: `web`'s real SVCB record carries a scion= candidate but no AAAA
// record, exactly like this test's zone. ResolveHost's §4.2 gate can then
// release Initial as soon as SVCB+AAAA are both final (see resolver.go's
// release doc comment: "A is never itself a gate requirement"), containing
// ONLY the SCION candidate, while the A answer is still in flight. On a host
// with no SCION daemon (DaemonAddr pointed at a closed port) and no fc00
// scitra route (setRoute(t, false)), ExpandSCION drops that lone candidate.
// Pre-fix, Fetch decided "no candidates" right there. Post-fix, Fetch must
// keep waiting on Updates and succeed once the delayed A answer arrives.
//
// The fixture carries alpn=h3: Task 7 (F10) made SCION candidates require a
// QUIC ALPN, so a record with no alpn= param at all — this test's original
// shape — now has its SCION candidate dropped at the RESOLVER level before
// Initial is even built, silently degrading this test into exercising
// Fetch's ordinary empty-Initial wait instead of the engine behavior it
// exists to pin: the candidate table going empty AFTER ExpandSCION drops
// the lone SCION candidate must not end the race while resolver updates
// are still open (caught in review). alpn=h3 keeps the SCION candidate
// alive and means the late A answer now yields
// BOTH a QUIC candidate (v4:, ALPN [h3]) and a TCP sibling (v4+tcp:, ALPN
// [http/1.1]) — Task 7's dual-transport emission. The v4: h3 attempt fails
// fast (nothing is listening on UDP on the httptest server's port) and
// Race's most-recent-attempt-fails-before-its-stagger-slot promotion (§6)
// moves straight to v4+tcp:, which is a real TCP+TLS connection to the
// server and wins.
func TestFetch_SCIONOnlyInitialWithLateAStillFetches(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "late-a-wins")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	tcp := srv.Listener.Addr().(*net.TCPAddr)

	f := newFakeDNS(t)
	// SVCB carries alpn=h3 (required for the SCION candidate to survive
	// F10's SCION-requires-QUIC gate — see the doc comment above) and a
	// scion= candidate, no AAAA record at all (matches the deployed zone's
	// "web" shape). A is delayed well past ResolutionDelay, so Initial
	// releases via §4.2 gate path (a) — SVCB+AAAA final — with only the
	// SCION candidate; A only shows up on a later Update, now as a v4:/
	// v4+tcp: pair (Task 7).
	f.set("sciononly.test.", dns.TypeHTTPS, mustRR(t,
		`sciononly.test. 300 IN HTTPS 1 . alpn=h3 scion=1-150_10.20.3.215`))
	f.set("sciononly.test.", dns.TypeA, mustRR(t, fmt.Sprintf("sciononly.test. 300 IN A %s", tcp.IP.String())))
	f.setDelay("sciononly.test.", dns.TypeA, 150*time.Millisecond)

	setRoute(t, false) // no fc00 scitra route

	// Pin the invariant this test exists to guard, directly against the
	// layer that produces it (ResolveHost, same fixture/options Fetch will
	// use internally below): Initial must be non-empty AND SCION-only,
	// otherwise the race this test regression-guards (the engine's wait
	// after ExpandSCION empties the table post-expansion, not Fetch's
	// ordinary empty-Initial wait) is not actually being exercised below.
	func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		res, err := ResolveHost(ctx, "sciononly.test", uint16(tcp.Port), ResolveOptions{
			Resolver: f.addr, ResolutionDelay: 30 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("ResolveHost (invariant check): %v", err)
		}
		if len(res.Initial) == 0 {
			t.Fatalf("Initial is empty; want the SCION-only candidate — this test would silently stop exercising the engine's post-expansion-empty wait")
		}
		for _, c := range res.Initial {
			if c.Family != FamilySCION {
				t.Fatalf("Initial = %+v, want SCION-only (A is still in flight)", res.Initial)
			}
		}
		drainUpdates(res.Updates, 2*time.Second)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rawURL := fmt.Sprintf("https://sciononly.test:%d/", tcp.Port)
	start := time.Now()
	res, err := Fetch(ctx, rawURL, Options{
		Resolver:        f.addr,
		Insecure:        true,
		ResolutionDelay: 30 * time.Millisecond,
		DaemonAddr:      closedPort(t), // no SCION daemon
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Fetch: %v, want it to fall through to the late A candidate instead of erroring", err)
	}

	if elapsed < 150*time.Millisecond || elapsed > time.Second {
		t.Fatalf("Fetch took %v, want it bounded by the ~150ms delayed A answer, not ctx's 5s timeout", elapsed)
	}
	if !strings.Contains(string(res.Body), "late-a-wins") {
		t.Fatalf("Result.Body = %q, want it to contain the served response", res.Body)
	}
	if res.Winner.Family != FamilyIPv4 {
		t.Fatalf("Winner.Family = %v, want FamilyIPv4 (the SCION candidate must have been dropped, not raced)", res.Winner.Family)
	}
	// The h3 sibling (v4:) has nothing to talk to over UDP and fails; the
	// TCP sibling (v4+tcp:) is the one that actually wins (Task 7).
	wantWinner := "v4+tcp:" + tcp.IP.String()
	if res.Winner.Label != wantWinner {
		t.Errorf("Winner.Label = %q, want %q (the TCP sibling, since the h3 candidate can't reach a TCP-only listener)", res.Winner.Label, wantWinner)
	}

	// The dropped SCION candidate must be Timeline-noted exactly once, not
	// once per retried batch (the engine's proto-label memoization in
	// ingest: a re-sent proto label is already in the table and is never
	// re-expanded, so it never re-drops).
	var scionFails int
	for _, ev := range res.Timeline {
		if ev.Kind == "fail" && strings.HasPrefix(ev.Label, "scion:") {
			scionFails++
		}
	}
	if scionFails != 1 {
		t.Fatalf("got %d Timeline 'fail' notes for the SCION candidate, want exactly 1 (deduped across retried batches): %+v", scionFails, res.Timeline)
	}
}

// TestFetch_RejectsNonHTTPSScheme pins the "h3/h2 only" contract.
func TestFetch_RejectsNonHTTPSScheme(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := Fetch(ctx, "http://plain.test/", Options{})
	if err == nil {
		t.Fatal("Fetch: want an error for a non-https scheme, got nil")
	}
	if !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("error = %v, want it to mention the unsupported scheme", err)
	}
}

// TestFetch_NoCandidatesMessage: a Fetch whose resolve is all-negative fails
// with the no-candidates message (previously pinned at mergeResolved level;
// now the engine's noCandsErr flows through Fetch's race wrapper). Pins the
// message contract across the engine rewiring.
func TestFetch_NoCandidatesMessage(t *testing.T) {
	f := newFakeDNS(t) // nothing set: every query answers empty
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := Fetch(ctx, "https://nothing.test/", Options{Resolver: f.addr})
	if err == nil || !strings.Contains(err.Error(), "no candidates for nothing.test") {
		t.Fatalf("err = %v, want no-candidates message", err)
	}
	// Exact old shape: the no-candidates error is not a race failure, so it
	// must not be double-prefixed under "race:".
	if strings.Contains(err.Error(), "race:") {
		t.Fatalf("err = %v, want no \"race:\" prefix on the no-candidates error", err)
	}
}

// TestFetch_NoIPWithOnlyIPCandidatesErrors: the dev box's fake DNS answer is
// IP-only (no SVCB/scion param), so --no-ip must filter every candidate and
// Fetch must return the clear "no candidates" error, not hang or panic.
func TestFetch_NoIPWithOnlyIPCandidatesErrors(t *testing.T) {
	f := newFakeDNS(t)
	f.set("noip.test.", dns.TypeA, mustRR(t, "noip.test. 300 IN A 127.0.0.1"))

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := Fetch(ctx, "https://noip.test/", Options{
		Resolver:        f.addr,
		NoIP:            true,
		ResolutionDelay: 10 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("Fetch: want an error when --no-ip drops every candidate, got nil")
	}
	if !strings.Contains(err.Error(), "no candidates for noip.test") {
		t.Fatalf("error = %v, want it to say \"no candidates for noip.test\"", err)
	}
}

// TestBuildTLSConfig_ServerNameFromHostname pins the "one shared tls.Config"
// contract's most important field for the demo CA to work identically
// across legs: ServerName must come from the URL's hostname.
func TestBuildTLSConfig_ServerNameFromHostname(t *testing.T) {
	cfg, err := buildTLSConfig(Options{Insecure: true}, "web.scion")
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg.ServerName != "web.scion" {
		t.Errorf("ServerName = %q, want web.scion", cfg.ServerName)
	}
	if !cfg.InsecureSkipVerify {
		t.Errorf("InsecureSkipVerify = false, want true")
	}
	if _, ok := interface{}(cfg).(*tls.Config); !ok {
		t.Errorf("buildTLSConfig did not return a *tls.Config")
	}
}

func TestParseSCIONTarget(t *testing.T) {
	c, err := parseSCIONTarget("1-152,10.152.0.81:8443", 443)
	if err != nil {
		t.Fatal(err)
	}
	if c.Family != FamilySCION || c.IA != "1-152" || c.Host != "10.152.0.81" || c.Port != 8443 || c.ALPN[0] != "h3" {
		t.Fatalf("got %+v", c)
	}
	c, err = parseSCIONTarget("1-ff00:0:110,[2001:db8::1]:443", 1)
	if err != nil || c.Host != "2001:db8::1" || c.Port != 443 || c.IA != "1-ff00:0:110" {
		t.Fatalf("IPv6: %+v %v", c, err)
	}
	c, err = parseSCIONTarget("1-152,10.152.0.81", 443)
	if err != nil || c.Port != 443 {
		t.Fatalf("default port: %+v %v", c, err)
	}
	for _, bad := range []string{"10.152.0.81:443", "x,10.152.0.81", "1-152,host:443"} {
		if _, err := parseSCIONTarget(bad, 443); err == nil {
			t.Errorf("parseSCIONTarget(%q) accepted", bad)
		}
	}
}
