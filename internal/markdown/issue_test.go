package markdown_test

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/markdown"
)

// A destination the scheme accepts and nothing can reach is a dead link
// written the moment somebody typed it. The shape is judged at submission,
// where the writer is there to be told, rather than by whoever reads it later.
func TestAnIssueReferenceThatIsNotAnIdentifierIsRefusedWhenItIsWritten(t *testing.T) {
	for _, destination := range []string{
		"issue:../../secret",
		"issue:https://elsewhere.example/x",
		"issue:",
		"issue:CV",
		"issue:1234-not-starting-with-a-letter",
		"issue:" + strings.Repeat("A", 65),
		// Destinations whose only defect is a character the per-byte
		// allowlist rejects. Every row above is decided by the length bound,
		// the first-character rule or the scheme, before the loop runs at all,
		// so none of them reaches what an identifier may be made of.
		"issue:CVE+2026-1",
		"issue:CVE%2f2026",
		"issue:CVE-2026-1234?x=1",
		"issue:CVE~2026",
		"issue:CVE@2026",
	} {
		if err := markdown.Check("[x](" + destination + ")"); err == nil {
			t.Errorf("%q was accepted, and refers to nothing", destination)
		}
	}
}

// A destination markdown itself will not read as one is not a link at all, so
// there is nothing to refuse. The text is prose carrying a colon, and the
// policy passes it for the same reason it passes any other sentence — which is
// a different outcome from accepting a reference it could not check.
func TestADestinationMarkdownWillNotReadIsNeverALink(t *testing.T) {
	for _, source := range []string{
		"[x](issue:has a space)",
		"[x](issue:tab\tseparated)",
	} {
		if err := markdown.Check(source); err != nil {
			t.Errorf("%q is not a link and was refused as one: %v", source, err)
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
