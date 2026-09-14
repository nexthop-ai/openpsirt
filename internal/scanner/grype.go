package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

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
	Timeout time.Duration
}

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
		timeout = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var out, errs bytes.Buffer
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

	if err := cmd.Run(); err != nil {
		return Result{}, fmt.Errorf("run %s: %w: %s", g.executable(), err, tail(errs.String()))
	}
	result, err := ParseGrype(&out)
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

// grypeDocument is the part of the scanner's output that is read.
type grypeDocument struct {
	Matches []struct {
		Vulnerability struct {
			ID          string `json:"id"`
			Severity    string `json:"severity"`
			Description string `json:"description"`
			// Where the issue is written up. Every match carries one, and for
			// the great majority it is the only route to a patch.
			DataSource string `json:"dataSource"`
			// Which body of data answered, as the scanner names it
			// — "nvd:cpe" against "alpine:distro:alpine:3.24".
			// Finer than the two words a finding records for how
			// it was reached, and the difference between them is
			// the whole of what recording the match is for.
			Namespace  string   `json:"namespace"`
			URLs       []string `json:"urls"`
			Advisories []struct {
				Link string `json:"link"`
			} `json:"advisories"`
			// What the published estimates say about it being used.
			EPSS []struct {
				EPSS float64 `json:"epss"`
			} `json:"epss"`
			Risk float64 `json:"risk"`
			KEV  []struct {
				ID string `json:"id"`
			} `json:"knownExploited"`
			CVSS []struct {
				Version string `json:"version"`
				Vector  string `json:"vector"`
				Metrics struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"metrics"`
			} `json:"cvss"`
			// What kind of weakness this is. Several entries usually say the
			// same thing from different sources, and the interesting part is
			// the identifier rather than who said it.
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
		// How the match was made. A scanner tries the advisory data
		// for the package's own ecosystem first and falls back to
		// comparing a published identifier against an upstream version
		// range, and those two answers mean very different things
		// about a distribution's package.
		MatchDetails []matchDetail `json:"matchDetails"`
	} `json:"matches"`
	Descriptor struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		// Where the database describes itself moved between versions of the
		// scanner: it used to sit directly under db and now sits under a
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
	} `json:"descriptor"`
}

// ParseGrype reads a scanner's output.
//
// Separate from running it so that what the output means is testable without
// the scanner and its database being installed, which is the part most likely
// to be wrong and the part least convenient to reproduce.
func ParseGrype(r io.Reader) (Result, error) {
	var doc grypeDocument
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return Result{}, fmt.Errorf("read the scanner's output: %w", err)
	}

	result := Result{
		Version:         doc.Descriptor.Version,
		DatabaseVersion: databaseVersion(doc),
	}
	for _, match := range doc.Matches {
		if match.Artifact.Name == "" {
			continue
		}
		score, vector := rating(match.Vulnerability.CVSS)
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
		result.Reported = append(result.Reported, finding.Reported{
			Issue: finding.Named{
				Identifier:  match.Vulnerability.ID,
				Aliases:     aliases,
				Severity:    strings.ToLower(match.Vulnerability.Severity),
				Description: strings.TrimSpace(match.Vulnerability.Description),
				Advisory:    strings.TrimSpace(match.Vulnerability.DataSource),
				References: references(match.Vulnerability.URLs,
					advisoryLinks(match.Vulnerability.Advisories), related),
				Exploited:  len(match.Vulnerability.KEV) > 0,
				Likelihood: firstEPSS(match.Vulnerability.EPSS),
				Score:      score,
				Vector:     vector,
				Weaknesses: weaknesses(match.Vulnerability.CWEs),
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
		})
	}
	return result, nil
}

// matchedRange is the version range the match fired on.
//
// The first one that states a range. A match usually has one detail and
// occasionally several — the same package reached two ways — and they agree
// about the package while differing about the route. Taking the first stated
// keeps this a description of the match rather than an attempt to reconcile
// two, which is what the match kind beside it already refuses to do.
func matchedRange(details []matchDetail) string {
	// From the detail the kind was decided by, not merely the first that
	// states one. A match often carries two — an ecosystem's advisory and a
	// comparison against an upstream range — and taking the kind from one and
	// the range from the other prints packaging-aware evidence beside a
	// verdict that says the packaging was not considered. The two halves are
	// read together and would then argue with each other.
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
func weaknesses(cwes []struct {
	CWE  string `json:"cwe"`
	Type string `json:"type"`
}) []string {
	seen := map[string]bool{}
	var named []string
	for _, entry := range cwes {
		name := strings.ToUpper(strings.TrimSpace(entry.CWE))
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		named = append(named, name)
	}
	sort.Strings(named)
	return named
}

// databaseVersion says which vulnerability data a run matched against.
//
// When it was built identifies the data; the schema version only identifies
// its shape, so it stands in only when there is nothing better. Without either,
// a finding that appeared or vanished because the data moved is unexplainable.
func databaseVersion(doc grypeDocument) string {
	switch {
	case doc.Descriptor.DB.Status.Built != "":
		return doc.Descriptor.DB.Status.Built
	case doc.Descriptor.DB.Built != "":
		return doc.Descriptor.DB.Built
	default:
		return doc.Descriptor.DB.Status.SchemaVersion
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
func tail(s string) string {
	const most = 500
	s = strings.TrimSpace(s)
	if len(s) <= most {
		return s
	}
	return "…" + s[len(s)-most:]
}

// patchLike recognizes an address that is a change rather than a write-up.
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
var patchLike = regexp.MustCompile(
	`(?i)(/commit/|/commits/|/pull/|/merge_requests?/|/changeset/|\.patch$|\.diff$|patchwork|git\.kernel\.org|cgit)`)

// advisoryLike recognizes a write-up of the issue itself.
var advisoryLike = regexp.MustCompile(
	`(?i)(/security/advisories/|/advisories/|nvd\.nist\.gov|cve\.org|security-tracker|\bGHSA-|\bCVE-)`)

// references turns what a report points at into what it is.
//
// Deduplicated, because the same address arrives from several places in one
// report and a person reading a list of eleven identical links learns nothing
// from ten of them.
func references(lists ...[]string) []finding.Reference {
	seen := map[string]bool{}
	var kept []finding.Reference
	var all []string
	for _, list := range lists {
		all = append(all, list...)
	}
	for _, url := range all {
		url = strings.TrimSpace(url)
		if url == "" || seen[url] {
			continue
		}
		seen[url] = true
		kept = append(kept, finding.Reference{URL: url, Kind: kindOf(url)})
	}
	return kept
}

func kindOf(url string) finding.ReferenceKind {
	switch {
	case patchLike.MatchString(url):
		return finding.Patch
	case advisoryLike.MatchString(url):
		return finding.AdvisoryRef
	default:
		return finding.Report
	}
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

// rating picks the severity score to record, and the vector it assumes.
//
// The first that states both. A report carries several ratings from different
// sources and they disagree; taking the first stated is at least a stable
// answer, and the vector travels with the number so that what the number
// assumed is readable rather than lost.
func rating(ratings []struct {
	Version string `json:"version"`
	Vector  string `json:"vector"`
	Metrics struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"metrics"`
}) (float64, string) {
	for _, rated := range ratings {
		if rated.Metrics.BaseScore > 0 && rated.Vector != "" {
			return rated.Metrics.BaseScore, rated.Vector
		}
	}
	return 0, ""
}

// firstEPSS reads the published estimate that an issue will be exploited.
func firstEPSS(estimates []struct {
	EPSS float64 `json:"epss"`
}) float64 {
	for _, estimate := range estimates {
		if estimate.EPSS > 0 {
			return estimate.EPSS
		}
	}
	return 0
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
	// An allowlist, so that the paragraph above is true. It used to be a
	// denylist — anything not naming a CPE read as the ecosystem advisory —
	// which meant a match kind this does not know read as the *authoritative*
	// one, the direction that hides something, and the comment said the
	// opposite. A word nobody here has checked is a word whose strength
	// nobody here has checked.
	for _, detail := range details {
		switch strings.ToLower(detail.Type) {
		case "exact-direct-match", "exact-indirect-match":
			return finding.ByAdvisory
		}
	}
	return finding.ByIdentifier
}
