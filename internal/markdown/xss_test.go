// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package markdown_test

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/markdown"
)

// payload is one entry of the shared corpus, and what each half must do with
// it.
type payload struct {
	Text       string `json:"text"`
	Submission string `json:"submission"`
	Why        string `json:"why"`
}

// corpus is read from the file the interface's renderer reads.
//
// One file, read by both renderers. Two copies of a security corpus diverge in
// the direction of the one nobody is adding to, and a comment calling them the
// same corpus is what stops anybody checking.
func corpus(t *testing.T) []payload {
	t.Helper()
	// A literal path, in this file, for the reason the settings gate uses
	// one: a walk that stopped matching would read less and report the same
	// clean answer.
	source, err := os.ReadFile("../../testdata/xss-corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Payloads []payload `json:"payloads"`
	}
	if err := json.Unmarshal(source, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Payloads) < 40 {
		t.Fatalf("the corpus holds %d payloads, so this checked almost nothing",
			len(doc.Payloads))
	}
	return doc.Payloads
}

func TestTheSameCorpusIsAnsweredAtSubmission(t *testing.T) {
	// Refusing at submission is what tells somebody their text will not do
	// what they meant, and it is the whole of what the server enforces:
	// nothing here renders, so there is no second pass to fall back on.
	//
	// Both answers, because not every payload is refusable here and the
	// corpus says which — a fenced block holds whatever it holds, and escaped
	// text is text. Asserting "all refused" over a list that grew would have
	// meant trimming the list rather than reading the entry.
	refused, accepted := 0, 0
	for _, one := range corpus(t) {
		err := markdown.Check(one.Text)
		switch one.Submission {
		case "refused":
			refused++
			if err == nil {
				t.Errorf("%q was accepted at submission, and is there because %s",
					one.Text, one.Why)
			}
		case "accepted":
			accepted++
			if err != nil {
				t.Errorf("%q was refused at submission, and is accepted because %s:\n  %v",
					one.Text, one.Why, err)
			}
		default:
			t.Errorf("%q says its submission answer is %q, which is neither",
				one.Text, one.Submission)
		}
	}
	// Both arms reached. A corpus that drifted to one answer would check one
	// direction and read as though it checked two.
	if refused == 0 || accepted == 0 {
		t.Errorf("the corpus asked for %d refusals and %d acceptances", refused, accepted)
	}
}

func TestOrdinaryTriageWritingIsAccepted(t *testing.T) {
	// The other direction, and the one that makes the refusals worth having.
	// A policy that refused real justifications would teach people to write
	// plain sentences with no evidence in them, which is worse than no policy.
	accepted := []string{
		"The parser is never reached: we only call `Encode`.",
		"See [the advisory](https://nvd.nist.gov/vuln/detail/CVE-2026-1) for detail.",
		"Mail [the maintainer](mailto:security@example.com) about it.",
		"```go\nfunc main() { fmt.Println(\"hi\") }\n```",
		"```\nplain block\n```",
		"| component | version |\n|---|---|\n| libfoo | 1.2.3 |",
		"- [x] checked with upstream\n- [ ] backport written",
		"Relative link to [another finding](/v1/findings/12).",
		"> Quoting the advisory:\n> not exploitable without the debug flag.",
		"A stack trace:\n\n    at parse (parser.go:112)\n    at main (main.go:9)",
	}
	for _, text := range accepted {
		if err := markdown.Check(text); err != nil {
			t.Errorf("ordinary writing was refused: %q\n  %v", text, err)
		}
	}
}

func TestARefusalSaysWhereToLook(t *testing.T) {
	// A justification is forty lines and a refusal naming a category means
	// hunting. Somebody who cannot find what to fix rewrites the whole thing
	// or stops explaining themselves.
	err := markdown.Check("fine line\nanother fine line\nsee ![this](https://evil.example/x.png)")
	if err == nil {
		t.Fatal("a remote image was accepted")
	}
	faults, ok := err.(markdown.Faults)
	if !ok {
		t.Fatalf("a refusal came back as %T", err)
	}
	if len(faults) != 1 {
		t.Fatalf("reported %d faults, want 1: %v", len(faults), faults)
	}
	if faults[0].Line != 3 {
		t.Errorf("pointed at line %d, want 3", faults[0].Line)
	}
	if !strings.Contains(faults[0].Offending, "evil.example") {
		t.Errorf("did not quote what was wrong: %q", faults[0].Offending)
	}
}

func TestEverythingWrongIsReportedAtOnce(t *testing.T) {
	// Fixing one problem and resubmitting to find the next is how somebody
	// learns to write plain sentences with no evidence in them.
	err := markdown.Check("![a](https://evil.example/1.png)\n[b](javascript:alert(1))\n<script>x</script>")
	faults, ok := err.(markdown.Faults)
	if !ok {
		t.Fatalf("a refusal came back as %T", err)
	}
	if len(faults) < 3 {
		t.Errorf("reported %d of three problems: %v", len(faults), faults)
	}
}

func TestTextPastTheBoundIsRefused(t *testing.T) {
	// Rendering is work somebody else asked for, and what is stored is kept
	// forever.
	err := markdown.Check(strings.Repeat("a", markdown.MaxBytes+1))
	if err == nil {
		t.Fatal("text past the bound was accepted")
	}
	// And what a person is shown. A fault about the whole text carries no
	// line, which is the branch every whole-text refusal takes, so reading the
	// words out of one is what says the message somebody sees for "too long"
	// is a sentence rather than a line number and a blank.
	if !strings.Contains(err.Error(), "longer than") {
		t.Errorf("the refusal does not say what is wrong: %q", err)
	}
	if strings.Contains(err.Error(), "line ") {
		t.Errorf("a fault about the whole text names a line: %q", err)
	}
}

func TestWhatIsNotTextIsRefusedAsNotText(t *testing.T) {
	// Bytes that are not UTF-8 at all. Every other input in this file is text,
	// so nothing else reaches this arm or reads what it says.
	err := markdown.Check(string([]byte{0xff, 0xfe, 0x00}))
	if err == nil {
		t.Fatal("bytes that are not text were accepted")
	}
	if !strings.Contains(err.Error(), "not text this can read") {
		t.Errorf("the refusal does not say what is wrong: %q", err)
	}
}

func TestAFieldOfNothingButProblemsIsAnsweredWithACappedList(t *testing.T) {
	// A refusal many times the size of what was sent is a way to make
	// refusing expensive, and sixty problems told at once is not something
	// anybody reads. The cap and the row that says there are more had zero
	// executions: no test had ever submitted more than a handful of faults.
	err := markdown.Check(strings.Repeat("![a](https://evil.example/x.png)\n", 25))
	if err == nil {
		t.Fatal("a field of refused images was accepted")
	}
	var faults markdown.Faults
	if !errors.As(err, &faults) {
		t.Fatalf("refused with %T, want the fault list", err)
	}
	if len(faults) != markdown.MaxFaults+1 {
		t.Errorf("answered with %d faults, want the cap of %d plus the row saying "+
			"there are more", len(faults), markdown.MaxFaults)
	}
	if last := faults[len(faults)-1].Error(); !strings.Contains(last, "and more besides") {
		t.Errorf("the last row is %q, which does not say there are more", last)
	}
}

// A destination beginning with two separators is not a relative link.
//
// It carries no scheme, so the check read it as relative and accepted it —
// and for the same reason neither the referrer rule nor the new-tab rule
// applies to it when it is rendered. A reader clicking one navigates in the
// same tab to a third party, handing over this deployment's own address,
// which names the product, the build and the finding.
func TestAnAddressOnAnotherHostIsNotARelativeLink(t *testing.T) {
	for _, written := range []string{
		"See [the note](//evil.example/log?p=).",
		`See [the note](/\evil.example/log).`,
		"See [the note](//evil.example).",
		// All four spellings of two separators, because a browser reads them
		// alike and a list of the two somebody thought of is not a rule.
		`See [the note](\\evil.example/log).`,
		`See [the note](\/evil.example/log).`,
	} {
		if err := markdown.Check(written); err == nil {
			t.Errorf("an address on another host was accepted: %q", written)
		}
	}
	// And the relative links people actually write still pass.
	for _, written := range []string{
		"See [another finding](/v1/findings/12).",
		"See [the list](findings?state=waiting).",
		"See [the anchor](#why).",
	} {
		if err := markdown.Check(written); err != nil {
			t.Errorf("a relative link was refused: %q\n  %v", written, err)
		}
	}
}
