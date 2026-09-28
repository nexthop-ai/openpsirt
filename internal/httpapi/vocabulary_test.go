// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
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

// enumsIn is every closed vocabulary the document the server builds offers,
// by where it sits.
func enumsIn(t *testing.T, r *reach) map[string][]string {
	t.Helper()
	document, err := json.Marshal(r.api.OpenAPI())
	if err != nil {
		t.Fatal(err)
	}
	var walked map[string]any
	if err := json.Unmarshal(document, &walked); err != nil {
		t.Fatal(err)
	}
	found := map[string][]string{}
	var visit func(at string, node any)
	visit = func(at string, node any) {
		switch held := node.(type) {
		case map[string]any:
			if listed, carries := held["enum"].([]any); carries {
				offered := make([]string, 0, len(listed))
				for _, one := range listed {
					word, ok := one.(string)
					if !ok {
						t.Fatalf("%s offers something that is not a word: %v", at, one)
					}
					offered = append(offered, word)
				}
				found[at] = offered
			}
			for key, value := range held {
				visit(at+"."+key, value)
			}
		case []any:
			for i, value := range held {
				visit(at+"."+strconv.Itoa(i), value)
			}
		}
	}
	visit("", walked)
	return found
}

// keeping is the words of a vocabulary one of its rules keeps, in its order.
func keeping[T ~string](all []T, keeps func(T) bool) []string {
	return words(slices.DeleteFunc(all, func(one T) bool { return !keeps(one) }))
}

// TestEveryEnumOfADomainVocabularyIsOneTheDomainNames holds the rest of the
// closed vocabularies to the lists their packages state: roles, embargo acts,
// dispositions, what became of a claim, decision states, claim kinds,
// standings and the severity words.
//
// An enum made only of one vocabulary's words is that vocabulary offered, and
// it has to be one of the lists the owning package names, in its order. A
// retyped literal fails here whether it is the whole list, a shorter one or
// the same words reordered. An enum reaching outside every vocabulary is some
// other list, and not this one's to police.
func TestEveryEnumOfADomainVocabularyIsOneTheDomainNames(t *testing.T) {
	vocabularies := []struct {
		name  string
		named [][]string
	}{
		{"roles", [][]string{
			words(access.Roles()),
			append(words(access.Roles()), words(access.OverTheDeployment())...),
		}},
		{"embargo acts", [][]string{words(finding.Acts())}},
		{"dispositions", [][]string{
			words(finding.Dispositions()),
			keeping(finding.Dispositions(), finding.Disposition.Rulable),
			keeping(finding.Dispositions(), finding.Disposition.NeedsSecondPerson),
		}},
		{"words for what became of a claim", [][]string{words(triage.WhatHappenedAll())}},
		{"decision states", [][]string{
			words(triage.States()),
			keeping(triage.States(), triage.State.Live),
			keeping(triage.States(), triage.State.Ended),
		}},
		{"claim kinds", [][]string{words(triage.ClaimKinds())}},
		{"standings", [][]string{
			words(finding.ClaimStandings()),
			keeping(finding.ClaimStandings(), finding.ClaimStanding.Unsettled),
		}},
		{"severity words", [][]string{
			finding.Bands(), finding.LeastFirst(), finding.Recordable(),
			finding.TriageFloors(), append(finding.TriageFloors(), ""), finding.ScoreBands(),
		}},
	}

	twoReach(t, func(t *testing.T, r *reach) {
		checked := 0
		for at, offered := range enumsIn(t, r) {
			var of []string
			named := false
			for _, each := range vocabularies {
				all := []string{}
				for _, list := range each.named {
					all = append(all, list...)
				}
				if len(offered) < 2 || slices.ContainsFunc(offered, func(word string) bool {
					return !slices.Contains(all, word)
				}) {
					continue
				}
				of = append(of, each.name)
				named = named || slices.ContainsFunc(each.named, func(list []string) bool {
					return slices.Equal(list, offered)
				})
			}
			if len(of) == 0 {
				continue
			}
			checked++
			if !named {
				t.Errorf("%s offers %v, which is made of the %s and is none of the lists the "+
					"owning package names — a subset is a named rule there, not a shorter "+
					"literal here", at, offered, strings.Join(of, " or the "))
			}
		}
		if checked == 0 {
			t.Fatal("the document offers none of these vocabularies, so this checked nothing")
		}
	})
}
