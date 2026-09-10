package markdown_test

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/markdown"
)

// REQ-65's internal half. Text could link out to anywhere and to a file held
// here, and could not say "the same root cause as this issue, wherever we have
// it" — which is the thing somebody writes on a claim.
//
// A written reference, not a detected one. A bare identifier in a sentence is
// text somebody wrote, and turning it into a link would edit their prose —
// including inside a quotation, or a list of identifiers they are explaining
// rather than citing.
func TestTextRefersToAnIssueByItsIdentifier(t *testing.T) {
	for _, one := range []struct {
		name   string
		source string
		want   []string
	}{
		{"a link", "See [the same flaw](issue:CVE-2026-1234).", []string{"CVE-2026-1234"}},
		{"a vendor identifier", "[ours](issue:SONIC-2026-245447)", []string{"SONIC-2026-245447"}},
		{"named twice, listed once", "[a](issue:CVE-2026-1) and [b](issue:CVE-2026-1)", []string{"CVE-2026-1"}},
		{"in order", "[b](issue:GHSA-bbbb) then [a](issue:CVE-2026-9)", []string{"GHSA-bbbb", "CVE-2026-9"}},
		// Being shown rather than cited. Somebody explaining how to write one
		// of these should not thereby cite it.
		{"inside a code span", "write `[x](issue:CVE-2026-1234)` like this", nil},
		{"inside a fence", "```\n[x](issue:CVE-2026-1234)\n```", nil},
		// A bare identifier is prose.
		{"bare in a sentence", "This is the same as CVE-2026-1234.", nil},
	} {
		t.Run(one.name, func(t *testing.T) {
			got := markdown.Issues(one.source)
			if strings.Join(got, ",") != strings.Join(one.want, ",") {
				t.Errorf("refers to %v, want %v", got, one.want)
			}
		})
	}
}

// The scheme being accepted while the half that lists references ignores what
// followed it is how a dead link gets written: accepted when it was typed,
// pointing at nothing when anybody read it. Judged at submission instead.
func TestAnIssueReferenceThatIsNotAnIdentifierIsRefusedWhenItIsWritten(t *testing.T) {
	for _, destination := range []string{
		"issue:../../secret",
		"issue:https://elsewhere.example/x",
		"issue:",
		"issue:CV",
		"issue:1234-not-starting-with-a-letter",
		"issue:" + strings.Repeat("A", 65),
	} {
		if err := markdown.Check("[x](" + destination + ")"); err == nil {
			t.Errorf("%q was accepted, and refers to nothing", destination)
		}
		// And it is refused for being the wrong shape rather than for
		// existing: whether we have an issue is not this package's question.
		if got := markdown.Issues("[x](" + destination + ")"); len(got) != 0 {
			t.Errorf("%q was refused and still listed as %v", destination, got)
		}
	}
}

// A destination markdown itself will not read as one is not a link at all, so
// there is nothing to refuse — and nothing to resolve either, which is the
// outcome that matters. Asserted rather than assumed: "refused" and "refers to
// nothing" are two claims and only the second holds here.
func TestADestinationMarkdownWillNotReadIsNeverAReference(t *testing.T) {
	for _, source := range []string{
		"[x](issue:has a space)",
		"[x](issue:tab\tseparated)",
	} {
		if got := markdown.Issues(source); len(got) != 0 {
			t.Errorf("%q refers to %v", source, got)
		}
	}
}

// Somebody writing about a flaw nothing has scanned yet is writing something
// true. Refusing it would make the text argue with the scan schedule.
func TestAnIssueWeHaveNotSeenIsStillWritable(t *testing.T) {
	source := "[a flaw nobody has filed here](issue:CVE-2099-0001)"
	if err := markdown.Check(source); err != nil {
		t.Errorf("refused an identifier we do not hold: %v", err)
	}
}
