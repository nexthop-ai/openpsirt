package httpapi_test

import (
	"regexp"
	"strings"
	"testing"
)

// namesADecision matches a decision identifier, which belongs in REQUIREMENTS.md
// and the design documents and nowhere a client reads.
//
// Any three or four capitals and a number, rather than a list of prefixes.
// The list named eighteen, not one of which appears anywhere in this
// repository — every decision here is REQ-nn, which was not among them — so
// the control this gate is credited with could never have fired. A rule
// matching the shape cannot go stale the way a list of names does.
var namesADecision = regexp.MustCompile(`\b[A-Z]{3,4}-[0-9]+\b`)

// paraphrases is the shapes AGENTS.md names as the wrong way to write a
// summary, quoted from it: a verb that avoids naming the act, and a summary
// that is a question rather than an instruction.
var paraphrases = []string{"Agree to", "Send what", "What is", "Getting ", "Returns "}

func TestEveryOperationReadsAsReferenceDocumentation(t *testing.T) {
	// AGENTS.md: a summary is an imperative verb and the thing it acts on, in
	// the words the domain uses; a description says what the operation does,
	// what it takes, what comes back, and what a caller must know that is not
	// obvious. The reasoning belongs in REQUIREMENTS.md — somebody reading this
	// is trying to make a request work.
	//
	// **What this can check is the half that is mechanical.** Whether a
	// paragraph is an explanation of the design or a thing a caller has to
	// know is a person's judgment and stays one; two summaries reproduced
	// AGENTS.md's own counter-examples verbatim, and one description cited a
	// decision identifier into a document published to people who have no way
	// to look it up. Those are checkable, and this checks them.
	twoReach(t, func(t *testing.T, r *reach) {
		var checked int
		for path, item := range r.api.OpenAPI().Paths {
			for method, op := range operations(item) {
				where := method + " " + path
				checked++

				if strings.TrimSpace(op.Summary) == "" {
					t.Errorf("%s has no summary", where)
				}
				if strings.TrimSpace(op.Description) == "" {
					t.Errorf("%s has no description", where)
				}
				if strings.HasSuffix(strings.TrimSpace(op.Summary), ".") {
					t.Errorf("%s: the summary ends in a full stop, and it is a label "+
						"rather than a sentence: %q", where, op.Summary)
				}
				for _, shape := range paraphrases {
					if strings.HasPrefix(op.Summary, shape) {
						t.Errorf("%s: the summary begins %q, which AGENTS.md names as the "+
							"way not to write one — say the act: %q", where, shape, op.Summary)
					}
				}
				if found := namesADecision.FindString(op.Summary + " " + op.Description); found != "" {
					t.Errorf("%s cites %s, which names a file nobody outside this "+
						"repository has", where, found)
				}
				// The requirement line is rendered from the declaration rather
				// than written beside it, so its absence means an operation
				// went around requiring() altogether.
				if !strings.Contains(op.Description, "**Requires:**") {
					t.Errorf("%s does not say what it requires", where)
				}
			}
		}
		if checked < 120 {
			t.Fatalf("only %d operations checked: this is not walking the API", checked)
		}
	})
}
