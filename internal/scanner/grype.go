package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// Grype runs the scanner of that name.
//
// It is a hard requirement of a deployment rather than a packaging
// consideration: without it there is nothing to triage, since the
// vulnerability data is produced here rather than sent to us.
type Grype struct {
	// Path is the executable. Empty means whatever the environment resolves.
	Path string
	// Timeout bounds one execution. A scanner that has stopped making progress
	// must fail as a run that failed rather than hold a worker for ever.
	//
	// Zero is unset, and the default below is used. It has to sit comfortably
	// below the queue's claim timeout, or a second worker claims a scan the
	// first is still running.
	Timeout time.Duration
	// Limits bound what one execution may produce. Anything left unset takes
	// the package default, so a deployment that wants one bound changed does
	// not have to restate the rest.
	Limits Limits
}

// DefaultTimeout bounds one execution where none is configured.
const DefaultTimeout = 30 * time.Minute

// waitDelay is how long the pipes are given once the scanner is killed.
//
// Killing a process does not close a pipe a helper it spawned still holds, and
// Wait blocks on the copy until every write end is closed. Without this the
// timeout above kills the scanner and the worker stays inside Run, holding a
// claim it goes on renewing — which is the one failure the timeout exists to
// prevent. The scanner shells out to container and registry tooling, so a
// helper outliving it is the ordinary case rather than a contrived one.
//
// What it costs is that what the scanner said can be cut short at the delay,
// which is the trade the field exists for.
const waitDelay = 10 * time.Second

// Name identifies this scanner in everything it finds.
func (g Grype) Name() string { return "grype" }

// executable is what to run.
func (g Grype) executable() string {
	if g.Path != "" {
		return g.Path
	}
	return "grype"
}

// Scan feeds an inventory to the scanner and reads back what it matched.
func (g Grype) Scan(ctx context.Context, inventory io.Reader) (Result, error) {
	timeout := g.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	limits := g.Limits.OrDefault()
	out := bounded{most: limits.MaxOutput}
	errs := bounded{most: limits.MaxComplaint}
	// Reading the inventory from standard input rather than from a file: a
	// component name is somebody else's text, and nothing from a scan file is
	// ever used as a path.
	// The inventory goes to the program's input rather than being named as a
	// path. That is deliberate — nothing from a scan file is ever used as a
	// path, so a component called something hostile stays data — and it is
	// also what the scanner actually accepts: asking it to read a file called
	// "-" makes it look for one.
	//
	// The executable is an operator's configuration and the arguments are
	// fixed.
	cmd := exec.CommandContext(ctx, g.executable(), "--output", "json") // #nosec G204
	cmd.Stdin = inventory
	cmd.Stdout = &out
	cmd.Stderr = &errs
	cmd.WaitDelay = waitDelay

	if err := cmd.Run(); err != nil {
		return Result{}, fmt.Errorf("run %s: %w: %s", g.executable(), err, tail(errs.String()))
	}
	// A report past its ceiling fails the run and complaints past theirs do
	// not: a report read in part reads as a product that stopped having
	// problems, while a scanner with a lot to say still scanned.
	if out.over {
		return Result{}, fmt.Errorf("the scanner wrote more than the %d byte report limit",
			limits.MaxOutput)
	}
	// Read from the buffer rather than from a copy of it. The ceiling on a
	// report is about half of what the chart ships for the whole process, so
	// a second full copy taken to read from spends the other half — which is
	// the thing the ceiling was chosen to prevent.
	result, err := ParseGrype(bytes.NewReader(out.Bytes()), limits)
	if err != nil {
		return Result{}, err
	}
	// What it said while succeeding, bounded the same way the failure is. A
	// scanner writes progress to this stream as well, which it suppresses when
	// nothing is watching — as nothing is here.
	result.Caution = tail(strings.TrimSpace(errs.String()))
	return result, nil
}

// matchDetail is how the scanner says it reached one match.
//
// Named rather than written inline because three things read it, and the same
// anonymous struct repeated in three signatures is one edit away from two of
// them disagreeing.
type matchDetail struct {
	Type string `json:"type"`
	// Found is what the match was made against. The version range is the
	// evidence for the judgment recording how the scanner matched asks
	// somebody to make: for a distribution's package reached by identifier
	// it is an upstream range, which is precisely what cannot see a
	// backported fix.
	Found struct {
		VersionConstraint string `json:"versionConstraint"`
	} `json:"found"`
}

// grypeMatch is one thing the scanner matched.
//
// Named rather than an element of an anonymous slice because the matches are
// read one at a time: the array is walked with the decoder rather than decoded
// whole, which is what lets the count be charged on the way in.
type grypeMatch struct {
	Vulnerability struct {
		ID          string `json:"id"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		// DataSource is where the issue is written up. Every match
		// carries one, and for the great majority it is the only route
		// to a patch.
		DataSource string `json:"dataSource"`
		// Namespace is which body of data answered, as the scanner
		// names it — "nvd:cpe" against "alpine:distro:alpine:3.24".
		// Finer than the two words a finding records for how it was
		// reached, and the difference between them is the whole of
		// what recording the match is for.
		Namespace  string   `json:"namespace"`
		URLs       []string `json:"urls"`
		Advisories []struct {
			Link string `json:"link"`
		} `json:"advisories"`
		// EPSS is what the published estimates say about it being
		// used.
		EPSS []struct {
			EPSS float64 `json:"epss"`
			// Percentile is where that estimate stands among all
			// of them, and the day it was computed for. A reader
			// cannot act on 0.00042 and can act on "higher than
			// 91% of everything published", and the day is what
			// says whether this estimate is newer than the stored
			// one.
			Percentile float64 `json:"percentile"`
			Date       string  `json:"date"`
		} `json:"epss"`
		Risk float64 `json:"risk"`
		KEV  []struct {
			ID string `json:"id"`
		} `json:"knownExploited"`
		CVSS []struct {
			Version string `json:"version"`
			Vector  string `json:"vector"`
			// Source is who published this rating and whether it
			// is the primary one. Provenance is recorded for
			// everything else a scan says — what found it, what it
			// was matched from, what it was matched in — and the
			// number a deadline is set from had none, so a reader
			// asking "who says 5.9" had nowhere to go. Absent in
			// some reports, which is itself an answer.
			Source  string `json:"source"`
			Type    string `json:"type"`
			Metrics struct {
				BaseScore float64 `json:"baseScore"`
			} `json:"metrics"`
		} `json:"cvss"`
		// CWEs is what kind of weakness this is. Several entries
		// usually say the same thing from different sources, and the
		// interesting part is the identifier rather than who said it.
		CWEs []struct {
			CWE  string `json:"cwe"`
			Type string `json:"type"`
		} `json:"cwes"`
		Fix struct {
			State     string   `json:"state"`
			Versions  []string `json:"versions"`
			Available []struct {
				Version string `json:"version"`
				Date    string `json:"date"`
			} `json:"available"`
		} `json:"fix"`
	} `json:"vulnerability"`
	// The same issue under its other identifiers, which is where the
	// references usually are. A match against a distribution's package
	// resolves to that distribution's record, and a distribution's record
	// points at its own tracker and nothing else — the commits that carry
	// the fix are on the upstream record, which arrives here.
	//
	// This declared only the identifier for a long time, so the scanner
	// read those addresses and threw them away: a kernel CVE that lists
	// eight `git.kernel.org` commits on its NVD record showed one Debian
	// tracker link and no patches at all.
	RelatedVulnerabilities []struct {
		ID         string   `json:"id"`
		DataSource string   `json:"dataSource"`
		URLs       []string `json:"urls"`
	} `json:"relatedVulnerabilities"`
	Artifact struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Purl    string `json:"purl"`
	} `json:"artifact"`
	// MatchDetails is how the match was made. A scanner tries the advisory
	// data for the package's own ecosystem first and falls back to
	// comparing a published identifier against an upstream version range,
	// and those two answers mean very different things about a
	// distribution's package.
	MatchDetails []matchDetail `json:"matchDetails"`
}

// grypeDescriptor is what the scanner says about itself and its data.
type grypeDescriptor struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// DB is where the database describes itself moved between versions of
	// the scanner: it used to sit directly under db and now sits under a
	// status within it. Both are read, because an operator running an
	// older build should not silently lose the record of what their
	// findings were matched against.
	DB struct {
		Built  string `json:"built"`
		Status struct {
			Built         string `json:"built"`
			SchemaVersion string `json:"schemaVersion"`
		} `json:"status"`
	} `json:"db"`
}

// ParseGrype reads a scanner's output.
//
// Separate from running it so that what the output means is testable without
// the scanner and its database being installed, which is the part most likely
// to be wrong and the part least convenient to reproduce.
//
// The matches are walked one at a time rather than decoded as a slice, so that
// the count is charged as each is read. What a bound has to stop is the walk:
// a count taken after the array has been decoded is taken after the work it
// was meant to prevent.
func ParseGrype(r io.Reader, limits Limits) (Result, error) {
	limits = limits.OrDefault()
	decoder := json.NewDecoder(r)

	var result Result
	var descriptor grypeDescriptor
	if err := object(decoder, func(key string) error {
		switch key {
		case "matches":
			return matches(decoder, limits, &result)
		case "descriptor":
			return decoder.Decode(&descriptor)
		default:
			var ignored json.RawMessage
			return decoder.Decode(&ignored)
		}
	}); err != nil {
		return Result{}, fmt.Errorf("read the scanner's output: %w", err)
	}

	result.Version = descriptor.Version
	result.DatabaseVersion = databaseVersion(descriptor)
	return result, nil
}

// object walks a JSON object, calling each with the key it reached.
//
// each either reads that key's value or discards it; either way the value is
// consumed, which is what leaves the decoder on the next key.
func object(decoder *json.Decoder, each func(key string) error) error {
	opening, err := decoder.Token()
	if err != nil {
		return err
	}
	if opening != json.Delim('{') {
		return fmt.Errorf("expected an object, got %v", opening)
	}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := key.(string)
		if !ok {
			return fmt.Errorf("expected a field name, got %v", key)
		}
		if err := each(name); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

// matches reads the match array, charging each one against the limit as it is
// read, and records what each one says.
func matches(decoder *json.Decoder, limits Limits, result *Result) error {
	opening, err := decoder.Token()
	if err != nil {
		return err
	}
	if opening != json.Delim('[') {
		return fmt.Errorf("expected the matches to be an array, got %v", opening)
	}
	read := 0
	for decoder.More() {
		read++
		if read > limits.MaxMatches {
			return fmt.Errorf("the scanner reported more than the %d match limit", limits.MaxMatches)
		}
		var match grypeMatch
		if err := decoder.Decode(&match); err != nil {
			return err
		}
		reported, err := reported(match, limits)
		if err != nil {
			return err
		}
		if reported == nil {
			continue
		}
		result.Reported = append(result.Reported, *reported)
	}
	_, err = decoder.Token()
	return err
}

// reported turns one match into what is recorded, or nothing where the match
// names no component.
func reported(match grypeMatch, limits Limits) (*finding.Reported, error) {
	if match.Artifact.Name == "" {
		return nil, nil
	}
	published := rating(match.Vulnerability.CVSS)
	aliases := make([]string, 0, len(match.RelatedVulnerabilities))
	// Where else this issue is written up, from every identifier it
	// answers to. Deduplicated by `references`, which the matched
	// record's own addresses go through as well.
	related := make([]string, 0, len(match.RelatedVulnerabilities))
	for _, other := range match.RelatedVulnerabilities {
		if other.ID != "" && other.ID != match.Vulnerability.ID {
			aliases = append(aliases, other.ID)
		}
		related = append(related, other.URLs...)
		if other.DataSource != "" {
			related = append(related, other.DataSource)
		}
	}
	pointing, err := references(limits, match.Vulnerability.URLs,
		advisoryLinks(match.Vulnerability.Advisories), related)
	if err != nil {
		return nil, err
	}
	epss := firstEPSS(match.Vulnerability.EPSS)
	named, primary := weaknesses(match.Vulnerability.CWEs)
	return &finding.Reported{
		Issue: finding.Named{
			Identifier:           match.Vulnerability.ID,
			Aliases:              aliases,
			Severity:             strings.ToLower(match.Vulnerability.Severity),
			Description:          strings.TrimSpace(match.Vulnerability.Description),
			Advisory:             strings.TrimSpace(match.Vulnerability.DataSource),
			References:           pointing,
			Exploited:            len(match.Vulnerability.KEV) > 0,
			Likelihood:           epss.value,
			LikelihoodPercentile: epss.percentile,
			LikelihoodOn:         epss.on,
			Score:                published.score,
			Vector:               published.vector,
			ScoreVersion:         published.version,
			ScoreSource:          published.source,
			ScoreKind:            published.kind,
			Weaknesses:           named,
			PrimaryWeakness:      primary,
		},
		Component: graph.Described{
			Name: match.Artifact.Name, Version: match.Artifact.Version,
			Purl: match.Artifact.Purl,
		},
		FixState: fixState(match.Vulnerability.Fix.State),
		FixedIn:  strings.Join(match.Vulnerability.Fix.Versions, ", "),
		FixedAt:  firstFixDate(match.Vulnerability.Fix.Available),
		Matched:  matched(match.MatchDetails),
		// Where *this* match came from, which is not always where the
		// issue is written up. One issue reached through two ecosystems
		// has two answers, and the issue can only hold one.
		MatchedFrom:  strings.TrimSpace(match.Vulnerability.DataSource),
		MatchedIn:    strings.TrimSpace(match.Vulnerability.Namespace),
		MatchedRange: matchedRange(match.MatchDetails),
	}, nil
}

// matchedRange is the version range the match fired on, taken from the detail
// the kind was decided by.
//
// A match often carries two — an ecosystem advisory and a comparison against
// an upstream range — and taking the kind from one and the range from the
// other would print packaging-aware evidence beside a verdict that says the
// packaging was not considered. The two halves are read together and would
// then argue with each other.
//
// A detail stating a range but deciding no kind is the fallback, because a
// range is evidence and having none is worse than having the other one's.
func matchedRange(details []matchDetail) string {
	for _, detail := range details {
		if strings.Contains(strings.ToLower(detail.Type), "cpe") {
			return strings.TrimSpace(detail.Found.VersionConstraint)
		}
	}
	for _, detail := range details {
		if stated := strings.TrimSpace(detail.Found.VersionConstraint); stated != "" {
			return stated
		}
	}
	return ""
}

// weaknesses reads what kind of flaw this is, deduplicated and in a stable
// order.
//
// A report usually names the same weakness two or three times from different
// sources, and which source said it is not something anybody triaging acts on
// — what they act on is that this is a use-after-free and so are eleven other
// findings. Ordering it makes the stored value the same for the same report,
// which is what keeps a re-scan from writing.
//
// **Which one the data calls the root cause is carried separately.** A
// published advisory states one weakness and a report commonly carries several,
// so something has to say which — and taking whichever sorts first is an answer
// with nothing behind it. The feeds say it, in the word beside each entry, and
// it was read and dropped.
//
// It is answered apart from the list rather than by the list's order, because
// a list cannot say "nobody said". A report that marks none is the ordinary
// case and it has to stay distinguishable from one that marks the first.
//
// Where two entries are marked, the first stands: a report naming two root
// causes disagrees with itself, and one weakness is what gets stated.
func weaknesses(cwes []struct {
	CWE  string `json:"cwe"`
	Type string `json:"type"`
}) (named []string, primary string) {
	seen := map[string]bool{}
	for _, entry := range cwes {
		name := strings.ToUpper(strings.TrimSpace(entry.CWE))
		if name == "" {
			continue
		}
		// Asked before the duplicate is dropped. A feed carries one entry per
		// source and the same weakness commonly appears twice under different
		// words, so testing this after the skip below reads the first spelling
		// and never sees the one that called it the root cause.
		if primary == "" && strings.EqualFold(strings.TrimSpace(entry.Type), "primary") {
			primary = name
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		named = append(named, name)
	}
	sort.Strings(named)
	return named, primary
}

// databaseVersion says which vulnerability data a run matched against.
//
// When it was built identifies the data; the schema version only identifies
// its shape, so it stands in only when there is nothing better. Without either,
// a finding that appeared or vanished because the data moved is unexplainable.
func databaseVersion(descriptor grypeDescriptor) string {
	switch {
	case descriptor.DB.Status.Built != "":
		return descriptor.DB.Status.Built
	case descriptor.DB.Built != "":
		return descriptor.DB.Built
	default:
		return descriptor.DB.Status.SchemaVersion
	}
}

// fixState reads what upstream has done about an issue.
//
// The scanner's own words are mapped rather than kept, because a second
// scanner will use different ones for the same three situations and the
// difference between them is what a person acts on.
func fixState(state string) finding.FixState {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "fixed":
		return finding.FixedUpstream
	case "wont-fix":
		return finding.WontFix
	case "not-fixed":
		return finding.NoFix
	default:
		// Including the scanner's own "unknown", and anything a later version
		// of it invents. Not "no fix": that is a statement about upstream, and
		// this is the absence of one.
		return finding.FixUnknown
	}
}

// tail bounds what a failure quotes back from a program's complaints.
//
// The end rather than the beginning: a scanner that failed says why on its
// last lines, and the banner it opened with is the same every run.
func tail(s string) string {
	const most = 500
	s = strings.TrimSpace(s)
	if len(s) <= most {
		return s
	}
	return "…" + bound.Tail(s, most)
}

// A reference is recognized by its host or by its path, never by the raw
// string.
//
// Matched on the shape of the address, which is the only thing available: a
// report gives a flat list of references and does not say what any of them
// is. Recognizing them is worth the guess — somebody deciding whether to
// backport rather than upgrade needs the change itself, and hunting for it by
// hand is the step that does not happen when a thousand findings are waiting.
//
// A wrong guess costs a label, not the address, so this errs toward saying
// less: an unrecognized reference is reported as a discussion rather than
// asserted to be a patch.
//
// Matched against the raw string, a query or a fragment decided the label:
// `https://unrelated.test/?from=git.kernel.org` read as a patch. And a host
// alternative matched a substring of the host, so `git.kernel.org.evil.test`
// read as one too. Both err in the direction the paragraph above refuses, so
// the address is parsed and each half is asked of the part it is about.
var (
	// patchPath is a path that names a change.
	patchPath = regexp.MustCompile(
		`(?i)(/commit/|/commits/|/pull/|/merge_requests?/|/changeset/|\.patch$|\.diff$)`)
	// advisoryPath is a path that names a write-up of the issue itself.
	advisoryPath = regexp.MustCompile(
		`(?i)(/security/advisories/|/advisories/|GHSA-|CVE-)`)
	// patchHosts serve changes whatever the path says.
	patchHosts = []string{"git.kernel.org"}
	// advisoryHosts serve write-ups whatever the path says.
	advisoryHosts = []string{"nvd.nist.gov", "cve.org", "security-tracker.debian.org"}
	// patchNames are the first label of a host, because these two are
	// software many projects run under a domain of their own —
	// patchwork.kernel.org, patchwork.freedesktop.org, cgit.freedesktop.org
	// — so there is no list of the hosts to name.
	patchNames = []string{"patchwork", "cgit"}
)

// kindOf says what an address is, from its host and its path.
func kindOf(address string) finding.ReferenceKind {
	parsed, err := url.Parse(address)
	if err != nil {
		// Nothing can be said about an address nothing can read, and the
		// weaker label is the one that hides nothing.
		return finding.Report
	}
	host := strings.ToLower(parsed.Hostname())
	switch {
	case servedBy(host, patchHosts) || namedBy(host, patchNames) || patchPath.MatchString(parsed.Path):
		return finding.Patch
	case servedBy(host, advisoryHosts) || advisoryPath.MatchString(parsed.Path):
		return finding.AdvisoryRef
	default:
		return finding.Report
	}
}

// servedBy says whether host is one of these or sits under one.
//
// The dot is what makes the suffix a host rather than a string: without it
// `git.kernel.org.evil.test` ends with the name and is served by somebody
// else entirely.
func servedBy(host string, known []string) bool {
	for _, name := range known {
		if host == name || strings.HasSuffix(host, "."+name) {
			return true
		}
	}
	return false
}

// namedBy says whether the host's first label is one of these.
func namedBy(host string, known []string) bool {
	label, _, _ := strings.Cut(host, ".")
	for _, name := range known {
		if label == name {
			return true
		}
	}
	return false
}

// references turns what a report points at into what it is.
//
// Deduplicated, because the same address arrives from several places in one
// report and a person reading a list of eleven identical links learns nothing
// from ten of them.
//
// Bounded per match rather than per report: the two multiply, and a report
// within the match ceiling can still be a report of one match pointing at
// everything. Charged as each address is read, which is what leaves the walk
// bounded rather than the result.
func references(limits Limits, lists ...[]string) ([]finding.Reference, error) {
	seen := map[string]bool{}
	var kept []finding.Reference
	for _, list := range lists {
		for _, url := range list {
			url = strings.TrimSpace(url)
			if url == "" || seen[url] {
				continue
			}
			if len(kept) >= limits.MaxReferences {
				return nil, fmt.Errorf(
					"one match points at more than the %d reference limit", limits.MaxReferences)
			}
			seen[url] = true
			kept = append(kept, finding.Reference{URL: url, Kind: kindOf(url)})
		}
	}
	return kept, nil
}

// advisoryLinks flattens the structured advisory list to its addresses.
func advisoryLinks(advisories []struct {
	Link string `json:"link"`
}) []string {
	links := make([]string, 0, len(advisories))
	for _, advisory := range advisories {
		links = append(links, advisory.Link)
	}
	return links
}

// rated is a published severity with what it assumes and who published it.
type rated struct {
	score   float64
	vector  string
	version string
	source  string
	kind    string
}

// rating picks the severity score to record, and the vector it assumes.
//
// The first that states both. A report carries several ratings from different
// sources and they disagree; taking the first stated is at least a stable
// answer, and the vector travels with the number so that what the number
// assumed is readable rather than lost. Who published it travels with them for
// the same reason: everything else a scan says carries its provenance.
func rating(ratings []struct {
	Version string `json:"version"`
	Vector  string `json:"vector"`
	Source  string `json:"source"`
	Type    string `json:"type"`
	Metrics struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"metrics"`
}) rated {
	for _, published := range ratings {
		if published.Metrics.BaseScore > 0 && published.Vector != "" {
			return rated{
				score: published.Metrics.BaseScore, vector: published.Vector,
				version: strings.TrimSpace(published.Version),
				source:  strings.TrimSpace(published.Source),
				kind:    strings.TrimSpace(published.Type),
			}
		}
	}
	return rated{}
}

// estimate is the published likelihood, where it stands, and the day it is
// about.
type estimate struct {
	value      float64
	percentile float64
	on         *time.Time
}

// firstEPSS reads the published estimate that an issue will be exploited.
//
// The day it was computed for travels with it, because the estimate is a
// thirty-day forecast recomputed daily and legitimately falls: which of two
// reports carries the newer estimate is a question about that day rather than
// about which scan ran last.
func firstEPSS(estimates []struct {
	EPSS       float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date"`
}) estimate {
	for _, published := range estimates {
		if published.EPSS <= 0 {
			continue
		}
		answer := estimate{value: published.EPSS, percentile: published.Percentile}
		// Not a day that has not happened. A scan file is hostile input and
		// this day decides which of two reports is newer, so one stating a
		// date ahead of now would pin the issue at whatever that report said
		// with no later report able to replace it — and nothing would say the
		// number had stopped moving.
		if on, err := time.Parse(time.DateOnly, strings.TrimSpace(published.Date)); err == nil &&
			!on.After(time.Now().UTC()) {
			answer.on = &on
		}
		return answer
	}
	return estimate{}
}

// firstFixDate reads when a fix became available.
//
// The earliest stated, because what matters is how long the fix has existed
// rather than which version somebody happens to be looking at.
func firstFixDate(available []struct {
	Version string `json:"version"`
	Date    string `json:"date"`
}) *time.Time {
	var earliest *time.Time
	for _, fix := range available {
		stated, err := time.Parse(time.DateOnly, strings.TrimSpace(fix.Date))
		if err != nil {
			continue
		}
		if earliest == nil || stated.Before(*earliest) {
			copied := stated
			earliest = &copied
		}
	}
	return earliest
}

// matched folds how a scanner made a match into the distinction that matters.
//
// Two answers, and the difference is what a distribution's packaging does to
// them. An advisory for the package in its own ecosystem knows the packaging:
// it says "fixed in 1.37.0-r15", counting the release number a backported
// patch moves. A comparison against a published identifier and an upstream
// version range knows none of that — it reads 1.37.0-r14 as "1.37.0 or
// earlier" and fires whether or not the distribution patched it.
//
// Anything unrecognized reads as the weaker of the two. A word this does not
// know is a word whose strength nobody here has checked, and treating it as
// authoritative is the direction that hides something.
func matched(details []matchDetail) finding.Matched {
	for _, detail := range details {
		if strings.Contains(strings.ToLower(detail.Type), "cpe") {
			return finding.ByIdentifier
		}
	}
	if len(details) == 0 {
		return ""
	}
	// An allowlist, which is what makes the paragraph above true. A denylist
	// here — anything not naming a CPE is the ecosystem advisory — would read
	// a match kind this does not know as the authoritative one, and that is
	// the direction that hides something. A word nobody here has checked is a
	// word whose strength nobody here has checked.
	for _, detail := range details {
		switch strings.ToLower(detail.Type) {
		case "exact-direct-match", "exact-indirect-match":
			return finding.ByAdvisory
		}
	}
	return finding.ByIdentifier
}
