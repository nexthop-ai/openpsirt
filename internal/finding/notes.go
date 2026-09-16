package finding

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/markdown"
)

// Note is what a release note says about itself: which two builds it compares,
// when it was produced, and what it was produced against.
//
// The names are what the releases are called rather than the stream and
// variant this deployment files them under. A customer reading "main
// container" does not know what that is, and a heading naming our internals is
// the first line of a document going to them.
type Note struct {
	From string
	To   string
	// At is when the later build was last measured, not when somebody asked
	// for the note. That is the moment the answer actually reflects, and it is
	// the same for everybody who asks — a note dated by the request would
	// differ between two people reading the same comparison.
	At time.Time
	// Scanner and Database are what the later build was last measured with.
	// A note somebody kept for a year is re-checkable only if it says what
	// produced it — a vulnerability database ships bad data and is corrected,
	// and "which data said so" is then the question.
	Scanner  string
	Database string
	// Omitted is how many fixes were left out for not having been disclosed.
	// The count and not the entries: without it a reader cannot tell a release
	// that fixed nothing undisclosed from one whose undisclosed fixes were
	// taken off the page.
	Omitted int
}

// Notes renders a comparison as prose somebody pastes into a release note .
//
// **Markdown, and generated here rather than in a browser**, so that what an
// API caller gets and what the screen shows are the same words. A second
// implementation of "how a release note reads" is one that drifts, and the
// half that drifts is always the one nobody is looking at.
//
// **It carries what was fixed, and nothing else**. Not what is still
// present, not what newly appeared, and not a bump that fell short. Those are
// dispositions and statements about what a build contains, and the document
// for those is a VEX, which is machine-readable and is what a customer's own
// scanner consumes — carrying the same judgments in prose as well lets the two
// drift, and prose is the copy nobody regenerates. Publishing "we know this
// critical is present" in a release note is also a disclosure act rather than
// a template choice.
//
// The comparison keeps all three sets. This is the one that goes to somebody.
//
// **A release that fixed nothing says so.** It answered nothing at all, and a
// caller cannot tell that from a truncated response, from the wrong pair of
// builds, or from a request that went astray — every one of which is also
// zero bytes. The reasoning that produced the empty answer still holds: a
// heading over nothing is a question in a reader's mind, which is why what is
// returned here is a sentence and not a heading.
func Notes(about Note, c *Comparison) string {
	if c == nil {
		return ""
	}
	fixed := onlyFixes(c.Fixed)
	if len(fixed) == 0 && about.Omitted == 0 {
		return nothingFixed(about)
	}

	var out strings.Builder
	if to := strings.TrimSpace(about.To); to != "" {
		fmt.Fprintf(&out, "## Security fixes in %s\n", to)
	} else {
		out.WriteString("## Security fixes\n")
	}
	lead(&out, about)
	section(&out, fixed)
	return out.String()
}

// nothingFixed is the whole document where a release fixed nothing.
//
// One sentence, naming the builds where they are known, and carrying what
// measured them as the document with fixes does: a note somebody keeps is
// re-checkable only if it says what produced it, and "nothing was fixed" is a
// claim worth being able to re-check.
func nothingFixed(about Note) string {
	var out strings.Builder
	switch to := strings.TrimSpace(about.To); {
	case to != "" && strings.TrimSpace(about.From) != "":
		fmt.Fprintf(&out, "No security fixes in %s since %s.\n",
			to, strings.TrimSpace(about.From))
	case to != "":
		fmt.Fprintf(&out, "No security fixes in %s.\n", to)
	default:
		out.WriteString("No security fixes.\n")
	}
	if measured := measuredWith(about); measured != "" {
		fmt.Fprintf(&out, "\n%s.\n", measured)
	}
	return out.String()
}

// scannedWith is the "measured with" clause both notes carry.
//
// One spelling, because the two notes describe the same thing: written twice,
// a release that fixed nothing and one that fixed something would come to
// describe their provenance differently, and the half nobody looks at is the
// half that drifts.
func scannedWith(about Note) string {
	switch {
	case about.Scanner != "" && about.Database != "":
		return fmt.Sprintf("measured with %s against vulnerability data of %s",
			about.Scanner, about.Database)
	case about.Scanner != "":
		return "measured with " + about.Scanner
	case about.Database != "":
		return "measured against vulnerability data of " + about.Database
	}
	return ""
}

// measuredWith is what the later build was last measured with, as a clause,
// or nothing where nothing has measured it.
func measuredWith(about Note) string {
	var said []string
	if !about.At.IsZero() {
		said = append(said, "Last measured "+about.At.UTC().Format("2006-01-02"))
	}
	if with := scannedWith(about); with != "" {
		said = append(said, with)
	}
	if len(said) == 0 {
		return ""
	}
	// The first clause opens the sentence where it is there, and the second
	// opens it where it is not.
	line := strings.Join(said, ", ")
	if about.At.IsZero() {
		line = strings.ToUpper(line[:1]) + line[1:]
	}
	return line
}

// lead writes the line that makes the note re-checkable: which two builds, on
// what day, measured against what.
//
// One line rather than a table, because it is prose somebody pastes into a
// document of their own and a table there is somebody else's formatting.
func lead(out *strings.Builder, about Note) {
	var said []string
	if from := strings.TrimSpace(about.From); from != "" {
		if to := strings.TrimSpace(about.To); to != "" {
			said = append(said, fmt.Sprintf("Comparing %s with %s", from, to))
		} else {
			said = append(said, "Comparing against "+from)
		}
	}
	if !about.At.IsZero() {
		said = append(said, "last measured "+about.At.UTC().Format("2006-01-02"))
	}
	if with := scannedWith(about); with != "" {
		said = append(said, with)
	}
	if len(said) > 0 {
		fmt.Fprintf(out, "\n%s.\n", strings.Join(said, ", "))
	}
	if about.Omitted > 0 {
		// A number, never the entries. What is left out has not been
		// announced, and saying how many says nothing about any of them —
		// while saying nothing at all leaves a reader unable to tell this
		// release from one that fixed nothing undisclosed.
		fmt.Fprintf(out, "\n%s\n", omitted(about.Omitted))
	}
}

// omitted words the count of what is not on the page.
func omitted(n int) string {
	if n == 1 {
		return "One further fix is not listed here, for a finding that has not been disclosed."
	}
	return fmt.Sprintf(
		"%d further fixes are not listed here, for findings that have not been disclosed.", n)
}

// onlyFixes keeps what was actually fixed.
//
// **A bump that carried the issue with it is not a fix**, and neither is a
// record taken back. The first closed a row and is superseded; the second
// means the build was never affected, so there is nothing to tell a customer
// about it at all — it leaves the affected list rather than moving within it,
// and mentioning it would describe a mistake of ours as news about their
// software.
func onlyFixes(rows []Changed) []Changed {
	fixed, _ := partition(rows)
	return fixed
}

// partition splits what left the affected list into what was fixed and what
// was not.
//
// **One spelling of the judgment, and both halves of it.** An allow-list
// rather than named exclusions, and the same list the remediation rate counts:
// a closure added later is not a fix on any surface until somebody says it is,
// rather than progress on one and churn on the other. Returning the other half
// as well is what stops a screen deciding it again — that is how a column
// headed "Fixed" came to carry two scanner faults.
func partition(rows []Changed) (fixed, closed []Changed) {
	for _, row := range rows {
		if row.Because.Resolves() {
			fixed = append(fixed, row)
			continue
		}
		closed = append(closed, row)
	}
	return fixed, closed
}

// section writes the lines, or nothing where there are none.
//
// **Grouped by the remediation, not by the issue.** One kernel upgrade closes
// 917 issues at once, and a bullet per issue repeats the same version pair 917
// times in a document going to a customer. The upgrade is stated once and the
// issues it closed are listed under it, which is the shape the reader is
// looking for: they want to know what to move to, and then which advisories
// that answers.
func section(out *strings.Builder, rows []Changed) {
	if len(rows) == 0 {
		return
	}
	out.WriteString("\n")
	for _, g := range grouped(rows) {
		fmt.Fprintf(out, "- %s%s\n", g.component, how(g.rows[0]))
		for _, row := range g.rows {
			fmt.Fprintf(out, "  - %s%s%s\n", row.Vulnerability, said(row), writtenUp(row))
		}
	}
}

// said is what is known about one issue, in the parenthesis after its name.
//
// **What a reader acts on, and not the description.** One upgrade closes
// hundreds of issues and they are listed under it, so a sentence apiece is a
// document nobody reads to the end — while the number, the word and whether
// somebody is known to be exploiting it are what decides whether this upgrade
// is taken tonight or next month.
func said(row Changed) string {
	var parts []string
	if row.Severity != "" {
		parts = append(parts, row.Severity)
	}
	if row.ScoreCenti > 0 {
		parts = append(parts, fmt.Sprintf("%.1f", float64(row.ScoreCenti)/100))
	}
	if row.Exploited {
		parts = append(parts, "known exploited")
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// writtenUp is where the issue is written up, as a link, or nothing.
//
// The address comes from a scan or a feed and goes into a document somebody
// publishes, so it passes the same rule an address stored beside a claim
// does: a scheme a reader's machine would act on is not something to hand
// them, and one that fails it is left out rather than printed as text.
func writtenUp(row Changed) string {
	url := strings.TrimSpace(row.Advisory)
	if url == "" || markdown.Addressable(url) != nil {
		return ""
	}
	return " — <" + url + ">"
}

// remediation is one thing that was done and every issue it closed.
type remediation struct {
	component string
	rows      []Changed
}

// grouped folds the fixed entries onto what was done about them, worst first.
//
// The key is the component with the closure reason and the version pair,
// because those are what the line above the list states: two upgrades of the
// same component in one comparison are two different answers to "what do I
// move to", and folding them together would state one of them over both.
//
// Ordered worst first at both levels, and by name where two rank alike, so two
// runs over the same comparison produce the same document — a release note
// that reorders between reads is one nobody can diff.
func grouped(rows []Changed) []remediation {
	at := map[string]int{}
	var groups []remediation
	for _, row := range rows {
		k := strings.Join([]string{
			row.Component, string(row.Because), row.FromVersion, row.MovedTo,
		}, "\x00")
		i, seen := at[k]
		if !seen {
			i = len(groups)
			at[k] = i
			groups = append(groups, remediation{component: row.Component})
		}
		groups[i].rows = append(groups[i].rows, row)
	}

	worst := func(g remediation) int {
		high := -1
		for _, row := range g.rows {
			if r := Ranks(row.Severity); r > high {
				high = r
			}
		}
		return high
	}
	for i := range groups {
		sort.SliceStable(groups[i].rows, func(a, b int) bool {
			ra, rb := Ranks(groups[i].rows[a].Severity), Ranks(groups[i].rows[b].Severity)
			if ra != rb {
				return ra > rb
			}
			return groups[i].rows[a].Vulnerability < groups[i].rows[b].Vulnerability
		})
	}
	sort.SliceStable(groups, func(a, b int) bool {
		wa, wb := worst(groups[a]), worst(groups[b])
		if wa != wb {
			return wa > wb
		}
		if groups[a].component != groups[b].component {
			return groups[a].component < groups[b].component
		}
		return groups[a].rows[0].MovedTo < groups[b].rows[0].MovedTo
	})
	return groups
}

// how says what was done about it, and to what version where the version
// moved.
//
// "Upgraded" on its own answers a question nobody asked: whoever reads this
// wants to know which version to move to, and the pair is recorded when the
// scan closed the finding precisely so it can be said here.
func how(row Changed) string {
	said := fixedBecause(row.Because)
	if said == "" {
		return ""
	}
	if row.MovedTo != "" {
		if row.FromVersion != "" {
			return fmt.Sprintf(" — %s, %s → %s", said, row.FromVersion, row.MovedTo)
		}
		return fmt.Sprintf(" — %s to %s", said, row.MovedTo)
	}
	return " — " + said
}

// fixedBecause says how something was fixed, in the words a reader needs.
//
// Every closure in Resolving has a sentence here, which is what keeps a
// release note from carrying a line with nothing after it. A table test over
// Resolving is what holds that.
func fixedBecause(because Closure) string {
	switch because {
	case Upgraded:
		return "the component was upgraded"
	case Revised:
		return "a carried patch"
	case Removed:
		return "the component is no longer shipped"
	case Fixed:
		return "fixed here"
	}
	return ""
}
