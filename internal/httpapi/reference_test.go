package httpapi_test

import (
	"regexp"
	"strings"
	"testing"
)

// namesADecision matches a decision identifier, which belongs in
// REQUIREMENTS.md and the design documents and nowhere a client reads.
//
// Any three or four capitals and a number, rather than a list of prefixes.
// The list named eighteen, not one of which appears anywhere in this
// repository — every decision here is REQ-nn, which was not among them — so
// the control this gate is credited with could never have fired. A rule
// matching the shape cannot go stale the way a list of names does.
var namesADecision = regexp.MustCompile(`\b[A-Z]{3,4}-[0-9]+\b`)

// domainIdentifiers are the names of things this software is *about*, which
// share that shape and are exactly what a description should be free to use.
// A caller reading "CVE-2026-74280" is reading the domain's own vocabulary;
// the rule is about identifiers nobody outside this repository has.
//
// Filtered rather than excluded in the pattern, because Go's regexp has no
// lookahead — and the shape rule is the part worth keeping.
var domainIdentifiers = regexp.MustCompile(`^(CVE|GHSA|CWE|RHSA|DSA|DLA|USN|ALAS|ELSA|CAPEC)-`)

// paraphrases is the shapes AGENTS.md names as the wrong way to write a
// summary, quoted from it: a verb that avoids naming the act, and a summary
// that is a question rather than an instruction.
var paraphrases = []string{"Agree to", "Send what", "What is", "Getting ", "Returns "}

// decisionIn is the first decision identifier in a piece of text, or empty
// where the only things of that shape are the domain's own names.
func decisionIn(text string) string {
	for _, found := range namesADecision.FindAllString(text, -1) {
		if domainIdentifiers.MatchString(found) {
			continue
		}
		return found
	}
	return ""
}

func TestEveryOperationReadsAsReferenceDocumentation(t *testing.T) {
	// AGENTS.md: a summary is an imperative verb and the thing it acts on, in
	// the words the domain uses; a description says what the operation does,
	// what it takes, what comes back, and what a caller must know that is not
	// obvious. The reasoning belongs in REQUIREMENTS.md — somebody reading this
	// is trying to make a request work.
	//
	// The mechanical half is what this checks. Whether a paragraph is an
	// explanation of the design or a thing a caller has to know is a person's
	// judgment and stays one; a summary reproducing AGENTS.md's own
	// counter-examples verbatim, and a description citing a decision
	// identifier into a document published to people who have no way to look
	// it up, are checkable.
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
				if found := decisionIn(op.Summary + " " + op.Description); found != "" {
					t.Errorf("%s cites %s, which names a file nobody outside this "+
						"repository has", where, found)
				}
				// The requirement line is rendered from the declaration rather
				// than written beside it, so its absence means an operation
				// went around requiring() altogether.
				if !strings.Contains(op.Description, "Requires: ") {
					t.Errorf("%s does not say what it requires", where)
				}
			}
		}
		if checked < 120 {
			t.Fatalf("only %d operations checked: this is not walking the API", checked)
		}
	})
}

// One fact, described once, wherever two bodies carry it.
//
// A description lives in a struct tag, which has to be a literal, so a field
// two bodies both carry is written out twice with nothing holding the two
// equal. Left to drift, the person screen's body and the administration body
// describe `sees_nothing` differently, and the published reference carries
// whichever of the two was registered first.
//
// Named fields rather than every repeated name: plenty of names mean different
// things in different bodies — "places" is what a claim wrote in one and what
// is still open in another — and a rule over all of them would be a rule
// nobody could keep.
func TestAFactTwoBodiesCarryIsDescribedTheSameWay(t *testing.T) {
	said := map[string]map[string][]string{}
	twoReach(t, func(t *testing.T, r *reach) {
		for name, schema := range r.api.OpenAPI().Components.Schemas.Map() {
			for field, property := range schema.Properties {
				switch field {
				case "sees_nothing":
					if said[field] == nil {
						said[field] = map[string][]string{}
					}
					said[field][property.Description] = append(said[field][property.Description], name)
				}
			}
		}
		for field, descriptions := range said {
			if len(descriptions) > 1 {
				for description, bodies := range descriptions {
					t.Errorf("%s is described as %q in %s", field, description, strings.Join(bodies, ", "))
				}
				t.Errorf("%s carries %d descriptions, want one", field, len(descriptions))
			}
		}
		if len(said) == 0 {
			t.Fatal("no field was found to check: this is not walking the schemas")
		}
	})
}

// No bold in the published document.
//
// A description is read by somebody working through a parameter list, and a
// claim pressed at them there is noise in the one place a reader is most in a
// hurry. It is a gate rather than a judgment because a span survives a rewrite
// of the sentence around it: bold is added one field at a time, and one field
// at a time is exactly what nobody reviews.
//
// Every string the document publishes, not the operations alone: a summary, a
// description, a schema's own description and the description on each of its
// properties. A rule over half the document is a rule that holds until
// somebody writes in the other half.
func TestThePublishedDocumentCarriesNoBold(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		var checked int
		bold := func(where, what, text string) {
			checked++
			if strings.Contains(text, "**") {
				t.Errorf("%s: the %s carries a bold span: %q", where, what, text)
			}
		}
		document := r.api.OpenAPI()
		for path, item := range document.Paths {
			for method, op := range operations(item) {
				where := method + " " + path
				bold(where, "summary", op.Summary)
				bold(where, "description", op.Description)
				for _, parameter := range op.Parameters {
					bold(where+" "+parameter.Name, "parameter", parameter.Description)
				}
			}
		}
		for name, schema := range document.Components.Schemas.Map() {
			bold(name, "schema description", schema.Description)
			for field, property := range schema.Properties {
				bold(name+"."+field, "field description", property.Description)
			}
		}
		if checked < 500 {
			t.Fatalf("only %d strings checked: this is not walking the document", checked)
		}
	})
}
