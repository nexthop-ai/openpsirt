package finding

import (
	"fmt"
	"sort"
	"strings"
	"time"
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
func Notes(about Note, c *Comparison) string {
	if c == nil {
		return ""
	}
	fixed := onlyFixes(c.Fixed)
	if len(fixed) == 0 && about.Omitted == 0 {
		return ""
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
	switch {
	case about.Scanner != "" && about.Database != "":
		said = append(said, fmt.Sprintf("measured with %s against vulnerability data of %s",
			about.Scanner, about.Database))
	case about.Scanner != "":
		said = append(said, "measured with "+about.Scanner)
	case about.Database != "":
		said = append(said, "measured against vulnerability data of "+about.Database)
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
	var fixed []Changed
	for _, row := range rows {
		switch row.Because {
		case Invalid, Superseded, Unexplained:
			continue
		}
		fixed = append(fixed, row)
	}
	return fixed
}

// section writes the lines, or nothing where there are none.
func section(out *strings.Builder, rows []Changed) {
	if len(rows) == 0 {
		return
	}
	// Worst first, then by name, so two runs over the same pair of builds
	// produce the same document — a release note that reorders between reads
	// is one nobody can diff.
	ordered := append([]Changed(nil), rows...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := Ranks(ordered[i].Severity), Ranks(ordered[j].Severity)
		if a != b {
			return a > b
		}
		if ordered[i].Vulnerability != ordered[j].Vulnerability {
			return ordered[i].Vulnerability < ordered[j].Vulnerability
		}
		return ordered[i].Component < ordered[j].Component
	})

	out.WriteString("\n")
	for _, row := range ordered {
		fmt.Fprintf(out, "- %s in %s", row.Vulnerability, row.Component)
		if row.Severity != "" {
			fmt.Fprintf(out, " (%s)", row.Severity)
		}
		out.WriteString(how(row))
		out.WriteString("\n")
	}
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
