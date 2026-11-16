// Command hev3 is the SCION-aware Happy Eyeballs v3 CLI: it fetches one
// https:// URL, racing SCION/IPv6/IPv4 endpoints per
// draft-ietf-happy-happyeyeballs-v3 as extended by
// draft-john-scion-happy-eyeballs (a SCION endpoint is attempted over up
// to -k candidate paths, each attempt a QUIC connection of its own, started
// -path-attempt-delay apart), and prints either a human race table +
// response preview or a JSON summary. -repeat runs the fetch several times
// in one process (fresh connections, shared SCION daemon connection);
// -stats prints per-run SCION path lookup and path attempt statistics.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/netsys-lab/scion-hev3/pkg/hev3"
)

func main() {
	// quic-go warns on every SCION dial that it cannot set the receive
	// buffer (snet conns are not *net.UDPConn — inherent, not fixable by
	// sysctls). Pure log noise for a demo CLI; the knob is quic-go's own.
	os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("hev3", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: hev3 [flags] URL")
		fs.PrintDefaults()
	}

	resolver := fs.String("resolver", "", "DNS resolver \"ip:port\"; empty = system resolver (/etc/resolv.conf)")
	k := fs.Int("k", 2, "Path Attempt Count: the most candidate paths attempted for one SCION endpoint")
	pathAttemptDelay := fs.Duration("path-attempt-delay", 50*time.Millisecond, "Path Attempt Delay: time between the starts of the attempts over the candidate paths of one SCION endpoint (at least 10ms, at most the Connection Attempt Delay)")
	pathAttemptDelayDerived := fs.Bool("path-attempt-delay-derived", false, "derive the Path Attempt Delay that follows the start of an attempt over a path from that path's RTT history in this process (smoothed RTT + 2*RTT variation; 50ms without history; at least 10ms, at most the Connection Attempt Delay) instead of -path-attempt-delay")
	pathMode := fs.String("path-mode", "attempts", `how the candidate paths of a SCION endpoint are used: "attempts" (a separate QUIC connection per path) or "copy" (one QUIC connection, datagrams copied to the paths; not in the draft)`)
	familyOrder := fs.String("family-order", "scion-first", `where the SCION family is ordered: "scion-first" or "ip-first" (SCION after both IP families; path lookups are not waited for)`)
	linger := fs.Duration("linger", 0, "how long a cancelled path attempt may go on so that it can be closed with CONNECTION_CLOSE (0 = twice the time the attempts took, within 50ms..1s; negative = drop at once)")
	fixedPaths := fs.Bool("deterministic-paths", false, "break ties in the candidate path selection by declared latency and fingerprint instead of at random")
	pathDelay := fs.String("path-delay", "auto", `-path-mode=copy only: delay between adding paths: "auto" (smoothed RTT + 2*RTT variation of the path from history, else 4x its declared latency, else 50ms), a fixed duration, or 0 = all paths at once`)
	scionTarget := fs.String("scion", "", `direct SCION target "ISD-AS,IP[:port]" (IPv6: "ISD-AS,[ip]:port"); skips DNS, URL host is the TLS name`)
	maxASes := fs.Int("max-ases", 0, "limit on the number of distinct destination ASes (other than the own AS) whose paths are looked up; SCION endpoints in further ASes are not attempted (0 = library default, 4; negative = no limit)")
	daemon := fs.String("daemon", "", "SCION daemon address (default $SCION_DAEMON_ADDRESS or 127.0.0.1:30255)")
	repeat := fs.Int("repeat", 1, "run the fetch this many times in one process (fresh connection each run)")
	stats := fs.Bool("stats", false, "print SCION path lookup and path racing statistics per run")
	corruptPath := fs.Int("exp-corrupt-path", 0, "EXPERIMENT: corrupt the first hop field MAC of path N (1-based rank) of each SCION path set")
	samePath := fs.Bool("exp-same-path", false, "EXPERIMENT (-path-mode=attempts): the second and further attempts to a SCION endpoint use its first candidate path again instead of the next candidate path")
	refreshPaths := fs.Bool("exp-refresh-paths", false, "EXPERIMENT: every path lookup asks the SCION daemon to fetch the paths anew instead of answering from its cache")
	noSCION := fs.Bool("no-scion", false, "drop SCION candidates after resolve")
	noIP := fs.Bool("no-ip", false, "drop IPv6/IPv4 candidates after resolve")
	jsonOut := fs.Bool("json", false, "emit a JSON summary (incl. SCION stats) instead of the human output; an array of runs with -repeat > 1")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification on every leg")
	ca := fs.String("ca", "", "PEM root CA file (default: /etc/hev3/ca.pem if it exists)")
	attemptDelay := fs.Duration("attempt-delay", 0, "race attempt stagger (0 = library default, 250ms)")
	resolutionDelay := fs.Duration("resolution-delay", 0, "Resolution Delay (0 = library default, 25ms); a SCION-first client also waits for path lookups no longer than this after the first positive IP answer")
	timeout := fs.Duration("timeout", 15*time.Second, "overall fetch timeout")
	rrType := fs.String("rr-type", "https", `service RR type to query: "https" (the draft's single query for an https URL), "svcb", or "both" (HTTPS and SVCB in parallel, HTTPS answers preferred; not in the draft)`)
	pfc := fs.Int("pfc", 1, "preferred address family count: candidates the preferred family races per interleave round")
	minAttemptDelay := fs.Duration("min-attempt-delay", 0, "floor for the adaptive SCION stagger with -adaptive-delay (0 = library default, 100ms; hard floor 10ms)")
	maxAttemptDelay := fs.Duration("max-attempt-delay", 0, "cap on the race stagger (0 = library default, 2s)")
	adaptive := fs.Bool("adaptive-delay", false, "shorten the race stagger after a SCION endpoint to clamp(2 x declared latency of its first path + 60ms, -min-attempt-delay, -attempt-delay); not in the draft")
	_ = fs.Bool("no-adaptive-delay", false, "no effect, accepted for existing scripts: the adaptive stagger is off unless -adaptive-delay is given")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "hev3: expected exactly one URL argument")
		fs.Usage()
		return 2
	}
	rawURL := fs.Arg(0)

	// The library reads PathDelay 0 as "derive", negative as "all at once".
	var pd time.Duration
	if *pathDelay != "auto" {
		d, err := time.ParseDuration(*pathDelay)
		if err != nil || d < 0 {
			fmt.Fprintln(stderr, `hev3: -path-delay must be "auto" or a duration >= 0`)
			fs.Usage()
			return 2
		}
		pd = d
		if pd == 0 {
			pd = -1
		}
	}
	if *k < 1 || *repeat < 1 || *corruptPath < 0 {
		fmt.Fprintln(stderr, "hev3: -k and -repeat must be >= 1; -exp-corrupt-path must be >= 0")
		fs.Usage()
		return 2
	}
	if *pathMode != hev3.PathModeAttempts && *pathMode != hev3.PathModeCopy {
		fmt.Fprintln(stderr, `hev3: -path-mode must be "attempts" or "copy"`)
		fs.Usage()
		return 2
	}
	if *pathMode == hev3.PathModeCopy && (*samePath || *pathAttemptDelayDerived) {
		fmt.Fprintln(stderr, "hev3: -exp-same-path and -path-attempt-delay-derived apply to -path-mode=attempts only")
		fs.Usage()
		return 2
	}
	if *familyOrder != "scion-first" && *familyOrder != "ip-first" {
		fmt.Fprintln(stderr, `hev3: -family-order must be "scion-first" or "ip-first"`)
		fs.Usage()
		return 2
	}
	if *pathAttemptDelay < 10*time.Millisecond {
		fmt.Fprintln(stderr, "hev3: -path-attempt-delay below 10ms; using 10ms")
		*pathAttemptDelay = 10 * time.Millisecond
	}
	if *pathAttemptDelayDerived {
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "path-attempt-delay" {
				fmt.Fprintln(stderr, "hev3: -path-attempt-delay-derived is set; -path-attempt-delay is not used")
			}
		})
	}
	if *k > 3 {
		fmt.Fprintln(stderr, "hev3: a Path Attempt Count above 3 is NOT RECOMMENDED")
	}
	if *pfc < 1 {
		fmt.Fprintln(stderr, "hev3: -pfc must be >= 1")
		fs.Usage()
		return 2
	}
	if *minAttemptDelay > 0 && *minAttemptDelay < 10*time.Millisecond {
		fmt.Fprintln(stderr, "hev3: -min-attempt-delay below the 10ms floor (draft §6); clamping to 10ms")
	}
	if *attemptDelay > 0 && *attemptDelay < 10*time.Millisecond {
		fmt.Fprintln(stderr, "hev3: -attempt-delay below the 10ms floor (draft §6); clamping to 10ms")
	}
	if *maxAttemptDelay > 0 && *maxAttemptDelay < 10*time.Millisecond {
		fmt.Fprintln(stderr, "hev3: -max-attempt-delay below the 10ms floor (draft §6); clamping to 10ms")
	}

	rt, err := hev3.ParseRRType(*rrType)
	if err != nil {
		fmt.Fprintln(stderr, err)
		fs.Usage()
		return 2
	}

	var session *hev3.Session
	if !*noSCION {
		session = hev3.NewSession(*daemon)
		defer session.Close()
	}
	opts := hev3.Options{
		Resolver:                *resolver,
		K:                       *k,
		NoSCION:                 *noSCION,
		NoIP:                    *noIP,
		Insecure:                *insecure,
		CAFile:                  *ca,
		AttemptDelay:            *attemptDelay,
		ResolutionDelay:         *resolutionDelay,
		RRType:                  rt,
		PreferredFamilyCount:    *pfc,
		MinAttemptDelay:         *minAttemptDelay,
		MaxAttemptDelay:         *maxAttemptDelay,
		AdaptiveDelay:           *adaptive,
		DaemonAddr:              *daemon,
		IPFirst:                 *familyOrder == "ip-first",
		PathMode:                *pathMode,
		PathAttemptDelay:        *pathAttemptDelay,
		PathAttemptDelayDerived: *pathAttemptDelayDerived,
		Linger:                  *linger,
		WaitLinger:              *stats || *jsonOut,
		DeterministicPaths:      *fixedPaths,
		MaxDestinationASes:      *maxASes,
		PathDelay:               pd,
		SCIONTarget:             *scionTarget,
		Session:                 session,
		ExpCorruptPath:          *corruptPath,
		ExpSamePath:             *samePath,
		ExpRefreshPaths:         *refreshPaths,
	}

	code := 0
	var runs []jsonResult
	for i := 1; i <= *repeat; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		start := time.Now()
		res, err := hev3.Fetch(ctx, rawURL, opts)
		total := time.Since(start)
		if res != nil && res.Elapsed > 0 {
			total = res.Elapsed // without the wait for cancelled path attempts
		}
		cancel()
		if err != nil {
			code = 1
		}
		if *jsonOut {
			runs = append(runs, toJSON(i, res, err, total))
			continue
		}
		if *repeat > 1 {
			fmt.Fprintf(stdout, "=== run %d/%d (%.1fms) ===\n", i, *repeat, msec(total))
		}
		if err != nil {
			fmt.Fprintln(stderr, err)
			if *stats && res != nil {
				printStats(stdout, res)
			}
			continue
		}
		printHuman(stdout, res, *repeat == 1)
		if *stats {
			printStats(stdout, res)
		}
	}
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if len(runs) == 1 {
			_ = enc.Encode(runs[0])
		} else {
			_ = enc.Encode(runs)
		}
	}
	return code
}

func msec(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// --- human output ---------------------------------------------------------

// raceRow is one line of the printed race table, derived entirely from
// Timeline events (no side-channel bookkeeping): a candidate's Label first
// seen via a "candidate" event with no later "attempt" is "never-started";
// otherwise its outcome/timing come from "attempt" plus whichever of
// "success"/"fail"/"cancel" (and "winner") follows.
type raceRow struct {
	label     string
	started   bool
	startMs   int64
	outcome   string // won / failed / cancelled; "" until one of those events fires
	outcomeMs int64
	winner    bool
	detail    string
}

func buildRaceRows(events []hev3.Event) []raceRow {
	index := map[string]int{}
	var rows []raceRow
	row := func(label string) *raceRow {
		if i, ok := index[label]; ok {
			return &rows[i]
		}
		rows = append(rows, raceRow{label: label})
		index[label] = len(rows) - 1
		return &rows[len(rows)-1]
	}

	for _, ev := range events {
		switch ev.Kind {
		case "candidate":
			row(ev.Label)
		case "attempt":
			r := row(ev.Label)
			r.started = true
			r.startMs = ev.At.Milliseconds()
		case "success":
			r := row(ev.Label)
			r.outcome = "won"
			r.outcomeMs = ev.At.Milliseconds()
		case "winner":
			row(ev.Label).winner = true
		case "fail":
			r := row(ev.Label)
			r.outcome = "failed"
			r.outcomeMs = ev.At.Milliseconds()
			r.detail = ev.Detail
		case "cancel":
			r := row(ev.Label)
			r.outcome = "cancelled"
			r.outcomeMs = ev.At.Milliseconds()
		}
	}
	return suppressExpandedProtoRows(rows)
}

// suppressExpandedProtoRows drops a never-started row whose label plus "#"
// prefixes another row's label that did receive an attempt.
//
// Every SCION endpoint gets a "candidate" Timeline event under its
// un-suffixed label ("scion:<IA>,<host>"), but ExpandSCION turns it into
// the candidate "…#paths" (its path set) before racing, so "attempt" (and
// any outcome) only ever fires on the expanded child; the parent would be
// a misleading "never-started" ghost row. A never-started row with no
// started child (e.g. an unreachable IPv6/IPv4 candidate) is kept.
func suppressExpandedProtoRows(rows []raceRow) []raceRow {
	hasStartedChild := func(label string) bool {
		for _, r := range rows {
			if r.started && strings.HasPrefix(r.label, label+"#") {
				return true
			}
		}
		return false
	}
	out := make([]raceRow, 0, len(rows))
	for _, r := range rows {
		if !r.started && r.outcome == "" && hasStartedChild(r.label) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// familyFromLabel infers a Candidate's family from its Label prefix — the
// only place that survives into Timeline events. It mirrors the label
// conventions resolver.go/dial_scion.go actually use ("scion:", "scitra:",
// "v6:"/"v6hint:", "v4:"/"v4hint:", with SCION expansion appending "#paths"
// to a "scion:" prefix).
func familyFromLabel(label string) string {
	switch {
	case strings.HasPrefix(label, "scitra:"):
		return "SCION(scitra)"
	case strings.HasPrefix(label, "scion:"):
		return "SCION"
	case strings.HasPrefix(label, "v6"):
		return "IPv6"
	case strings.HasPrefix(label, "v4"):
		return "IPv4"
	default:
		return "?"
	}
}

func familyName(f hev3.Family) string {
	switch f {
	case hev3.FamilySCION:
		return "SCION"
	case hev3.FamilyIPv6:
		return "IPv6"
	case hev3.FamilyIPv4:
		return "IPv4"
	default:
		return "?"
	}
}

func printHuman(w *os.File, res *hev3.Result, body bool) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "LABEL\tFAMILY\tSTART(ms)\tOUTCOME\tWINNER")
	for _, r := range buildRaceRows(res.Timeline) {
		start := "-"
		if r.started {
			start = fmt.Sprintf("%d", r.startMs)
		}
		var outcome string
		switch {
		case r.outcome != "":
			outcome = fmt.Sprintf("%s %dms", r.outcome, r.outcomeMs)
		case r.started:
			// Reachable only if Race returned a winner while another
			// attempt's fail/cancel event has not yet been observed —
			// shouldn't happen given Race's synchronous event ordering,
			// but printed honestly rather than mislabeled "never-started".
			outcome = "in-flight"
		default:
			outcome = "never-started"
		}
		mark := ""
		if r.winner {
			mark = "<-- WINNER"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.label, familyFromLabel(r.label), start, outcome, mark)
	}
	tw.Flush()

	fmt.Fprintln(w)
	fmt.Fprintf(w, "winner: %s (%s, alpn=%s)\n", res.Winner.Label, familyName(res.Winner.Family), res.ALPN)
	fmt.Fprintln(w, res.Status)
	if body {
		fmt.Fprintln(w)
		printBodyPreview(w, res.Body)
	}
}

// printStats prints the SCION path lookups and racing attempts of one run.
func printStats(w *os.File, res *hev3.Result) {
	for _, l := range res.Lookups {
		fmt.Fprintf(w, "lookup %s: %.1fms", l.Label, l.LookupMs)
		if l.DaemonSetupMs > 0 {
			fmt.Fprintf(w, " (+ daemon setup %.1fms)", l.DaemonSetupMs)
		}
		switch {
		case l.OwnAS:
			fmt.Fprint(w, " (own AS: no lookup)")
		case l.Shared:
			fmt.Fprint(w, " (shared with another endpoint in the AS)")
		}
		fmt.Fprintf(w, ", %d paths found, %d eligible", l.PathsFound, len(l.PathSet))
		if l.Err != "" {
			fmt.Fprintf(w, ", error: %s", l.Err)
		}
		fmt.Fprintln(w)
		for _, x := range l.Excluded {
			fmt.Fprintf(w, "  excluded: %s\n", x)
		}
	}
	for _, a := range res.SCIONAttempts {
		if a.Racer == nil {
			fmt.Fprintf(w, "endpoint %s -> %s: handshake %.1fms (setup %.1fms), %d candidate paths, path attempt delay %.0fms (%s)", a.Label, a.Remote, a.HandshakeMs, a.SetupMs, len(a.Paths), a.PathAttemptDelayMs, a.PathAttemptDelaySrc)
			if a.ExpSamePath {
				fmt.Fprint(w, ", every attempt over path 1 (-exp-same-path)")
			}
			if a.Winner > 0 {
				fmt.Fprintf(w, ", established over path %d", a.Winner)
			}
			if a.Err != "" {
				fmt.Fprintf(w, ", error: %s", a.Err)
			}
			fmt.Fprintln(w)
			for _, p := range a.Paths {
				fmt.Fprintf(w, "  path %d %s: ", p.Rank, p.Interfaces)
				if !p.Started {
					fmt.Fprintf(w, "%s", p.Outcome)
				} else {
					fmt.Fprintf(w, "started at %.1fms from port %d, %s after %.1fms, sent %d pkts/%d B, recv %d pkts/%d B", p.StartMs, p.LocalPort, p.Outcome, p.HandshakeMs, p.SentPkts, p.SentBytes, p.RecvPkts, p.RecvBytes)
				}
				if p.DelayMs > 0 {
					fmt.Fprintf(w, ", path attempt delay %.0fms (%s)", p.DelayMs, p.DelaySrc)
				}
				if p.Err != "" {
					fmt.Fprintf(w, " (%s)", p.Err)
				}
				fmt.Fprintln(w)
				for _, e := range p.SCMP {
					fmt.Fprintf(w, "    scmp at %.1fms: %s", e.AtMs, e.Type)
					if e.IA != "" {
						fmt.Fprintf(w, " from %s ifid %d", e.IA, e.IfID)
					}
					fmt.Fprintln(w)
				}
			}
			continue
		}
		r := *a.Racer
		fmt.Fprintf(w, "attempt %s -> %s: handshake %.1fms (setup %.1fms)", a.Label, a.Remote, a.HandshakeMs, a.SetupMs)
		if r.AllAtOnce {
			fmt.Fprint(w, ", all paths at once")
		}
		if r.Selected > 0 {
			fmt.Fprintf(w, ", selected path %d (%s) at %.1fms", r.Selected, r.SelectReason, r.SelectedAtMs)
		}
		if a.Err != "" {
			fmt.Fprintf(w, ", error: %s", a.Err)
		}
		fmt.Fprintf(w, ", recv %d pkts/%d B", r.RecvPkts, r.RecvBytes)
		if r.RecvForeign > 0 {
			fmt.Fprintf(w, " (%d for another connection, ignored)", r.RecvForeign)
		}
		fmt.Fprintln(w)
		for _, p := range r.Paths {
			added := "not added"
			if p.Added {
				added = fmt.Sprintf("added at %.1fms (%s)", p.AddedAtMs, p.AddReason)
			}
			fmt.Fprintf(w, "  path %d %s: %s, %d pkts (%d copies), %d B", p.Rank, p.Interfaces, added, p.Pkts, p.Copies, p.Bytes)
			if p.DelaySrc != "" {
				fmt.Fprintf(w, ", path delay %.1fms (%s)", p.DelayMs, p.DelaySrc)
			}
			if p.Failed {
				fmt.Fprintf(w, ", failed: %s", p.FailReason)
			}
			fmt.Fprintln(w)
		}
		for _, e := range r.SCMP {
			fmt.Fprintf(w, "  scmp at %.1fms: %s from %s ifid %d, path %d", e.AtMs, e.Type, e.IA, e.IfID, e.Path)
			if e.Ignored != "" {
				fmt.Fprintf(w, " (ignored: %s)", e.Ignored)
			}
			fmt.Fprintln(w)
		}
	}
}

// printBodyPreview prints up to the first 20 lines of body (already capped
// at 4KiB by Fetch).
func printBodyPreview(w *os.File, body []byte) {
	const maxLines = 20
	lines := strings.SplitAfter(string(body), "\n")
	if len(lines) > maxLines {
		lines = lines[:maxLines]
	}
	for _, l := range lines {
		fmt.Fprint(w, l)
	}
	if len(lines) > 0 && !strings.HasSuffix(lines[len(lines)-1], "\n") {
		fmt.Fprintln(w)
	}
}

// --- JSON output -----------------------------------------------------------

type jsonWinner struct {
	Label  string `json:"label"`
	Family string `json:"family"`
}

type jsonEvent struct {
	AtMs   float64 `json:"at_ms"`
	Kind   string  `json:"kind"`
	Label  string  `json:"label"`
	Detail string  `json:"detail,omitempty"`
}

type jsonResult struct {
	Run           int                      `json:"run"`
	Error         string                   `json:"error,omitempty"`
	Winner        jsonWinner               `json:"winner"` // empty on a lost race
	ALPN          string                   `json:"alpn"`
	Status        string                   `json:"status"`
	TotalMs       float64                  `json:"total_ms"`             // Fetch call, incl. DNS and HTTP request
	ConnectMs     float64                  `json:"connect_ms,omitempty"` // winner's "success" event
	Lookups       []hev3.LookupStats       `json:"lookups,omitempty"`
	SCIONAttempts []hev3.SCIONAttemptStats `json:"scion_attempts,omitempty"`
	Timeline      []jsonEvent              `json:"timeline"`
}

func toJSON(run int, res *hev3.Result, err error, total time.Duration) jsonResult {
	out := jsonResult{Run: run, TotalMs: msec(total)}
	if err != nil {
		out.Error = err.Error()
	}
	if res == nil {
		return out
	}
	if res.Winner.Label != "" {
		out.Winner = jsonWinner{Label: res.Winner.Label, Family: familyName(res.Winner.Family)}
	}
	out.ALPN, out.Status = res.ALPN, res.Status
	out.Lookups, out.SCIONAttempts = res.Lookups, res.SCIONAttempts
	for _, ev := range res.Timeline {
		if ev.Kind == "success" && ev.Label == res.Winner.Label && out.ConnectMs == 0 {
			out.ConnectMs = msec(ev.At)
		}
		out.Timeline = append(out.Timeline, jsonEvent{
			AtMs:   msec(ev.At),
			Kind:   ev.Kind,
			Label:  ev.Label,
			Detail: ev.Detail,
		})
	}
	return out
}
