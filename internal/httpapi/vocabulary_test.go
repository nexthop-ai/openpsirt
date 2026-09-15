package httpapi_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// words is a vocabulary as plain strings.
func words[T ~string](all []T) []string {
	out := make([]string, 0, len(all))
	for _, each := range all {
		out = append(out, string(each))
	}
	return out
}

// TestEveryVocabularyTheDocumentOffersIsOneTheDomainStates holds the shape,
// not a second copy of the lists.
//
// The vocabulary was retyped as a literal in struct tags at eight sites with
// four memberships, so an outcome added to `internal/triage` was accepted by
// the store and refused by every route — and a subset was a shorter literal
// rather than a rule, so nothing said what it left out or why. Each enum is
// built from the domain now, and what this asks is that a route offering our
// words offers one of the lists the domain names.
//
// Scoped by the words rather than by the field name: "outcome" also names what
// became of an upload, which is a different vocabulary and not this one's to
// police.
func TestEveryVocabularyTheDocumentOffersIsOneTheDomainStates(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		named := [][]string{
			words(triage.Outcomes()),
			words(triage.OutcomesOneAtATime()),
			words(triage.OutcomesInBulk()),
			words(triage.OutcomesThatHideRisk()),
			finding.OutcomesOffered(),
		}
		reasons := words(triage.Justifications())
		// Every word of it, not any of them. Other vocabularies share a word
		// with this one — a fix state is also "wont-fix", and a publisher's
		// status is also "affected" — and those are not this one's to police.
		ours := func(offered []string) bool {
			return len(offered) > 0 && !slices.ContainsFunc(offered, func(word string) bool {
				return !slices.Contains(named[0], word) && !slices.Contains(reasons, word)
			})
		}

		// Read out of the document the server builds rather than out of the
		// source, so a field added anywhere is examined without this being
		// edited.
		document, err := json.Marshal(r.api.OpenAPI())
		if err != nil {
			t.Fatal(err)
		}
		var walked map[string]any
		if err := json.Unmarshal(document, &walked); err != nil {
			t.Fatal(err)
		}

		checked := 0
		var visit func(at string, node any)
		visit = func(at string, node any) {
			switch held := node.(type) {
			case map[string]any:
				listed, carries := held["enum"].([]any)
				if carries {
					offered := make([]string, 0, len(listed))
					for _, one := range listed {
						word, ok := one.(string)
						if !ok {
							t.Fatalf("%s offers something that is not a word: %v", at, one)
						}
						offered = append(offered, word)
					}
					if ours(offered) {
						checked++
						switch {
						case slices.Equal(offered, reasons):
						case slices.ContainsFunc(named, func(one []string) bool {
							return slices.Equal(one, offered)
						}):
						default:
							t.Errorf("%s offers %v, which is none of the lists internal/triage "+
								"states — a subset is a named rule there, not a shorter "+
								"literal here", at, offered)
						}
					}
				}
				for key, value := range held {
					visit(at+"."+key, value)
				}
			case []any:
				for _, value := range held {
					visit(at, value)
				}
			}
		}
		visit("", walked)
		if checked == 0 {
			t.Fatal("the document offers no outcome and no justification, so this checked nothing")
		}
		// More than one, or a change that closed one field and opened the
		// rest would pass.
		if checked < len(triage.Outcomes()) {
			t.Errorf("only %d fields were examined, which is fewer than the routes that carry one",
				checked)
		}
	})
}

// A field beside one of our outcomes carries our reasons.
//
// The bulk route's justification carried no words, so the generated client
// typed it as a bare string where its two neighbours gave a union — and a
// caller passing a free word found out at the server rather than at compile
// time. Asked only where the schema also states one of our outcomes: a
// justification beside a producer's own status is their word for it, and not
// ours to close.
func TestAJustificationBesideOurOutcomeCarriesOurReasons(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		open, seen := []string{}, 0
		for name, schema := range r.api.OpenAPI().Components.Schemas.Map() {
			if schema == nil {
				continue
			}
			said, states := schema.Properties["outcome"], schema.Properties["justification"]
			if said == nil || states == nil {
				continue
			}
			if !slices.ContainsFunc(said.Enum, func(one any) bool {
				word, ok := one.(string)
				return ok && slices.Contains(words(triage.Outcomes()), word)
			}) {
				continue
			}
			seen++
			if len(states.Enum) == 0 {
				open = append(open, name+".justification")
			}
		}
		if seen == 0 {
			t.Fatal("no schema states an outcome of ours beside a reason, so this checked nothing")
		}
		if len(open) > 0 {
			t.Errorf("%s sit beside one of our outcomes and state none of our reasons, so the "+
				"generated client types them as a bare string", strings.Join(open, ", "))
		}
	})
}
