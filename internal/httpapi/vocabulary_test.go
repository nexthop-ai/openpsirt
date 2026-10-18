// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/currency"
	"github.com/nexthop-ai/openpsirt/internal/cvss"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/obligation"
	"github.com/nexthop-ai/openpsirt/internal/patchbranch"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/trail"
	"github.com/nexthop-ai/openpsirt/internal/triage"
	"github.com/nexthop-ai/openpsirt/internal/vex"
)

// words is a vocabulary as plain strings.
func words[T ~string](all []T) []string {
	out := make([]string, 0, len(all))
	for _, each := range all {
		out = append(out, string(each))
	}
	return out
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
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		open, seen := []string{}, 0
		for name, schema := range r.API.OpenAPI().Components.Schemas.Map() {
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
func enumsIn(t *testing.T, r *httpapitest.Reach) map[string][]string {
	t.Helper()
	document, err := json.Marshal(r.API.OpenAPI())
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

// statedVocabularies is every closed vocabulary a domain package states, by
// name, as the document offers it.
func statedVocabularies() map[string][]string {
	return map[string][]string{
		"outcomes":                       words(triage.Outcomes()),
		"outcomes one at a time":         words(triage.OutcomesOneAtATime()),
		"outcomes in bulk":               words(triage.OutcomesInBulk()),
		"outcomes that hide risk":        words(triage.OutcomesThatHideRisk()),
		"outcomes a statement offers":    finding.OutcomesOffered(),
		"justifications":                 words(triage.Justifications()),
		"statement scopes":               words(triage.Scopes()),
		"roles":                          words(access.Roles()),
		"roles and rights":               append(words(access.Roles()), words(access.OverTheDeployment())...),
		"embargo acts":                   words(finding.Acts()),
		"release line kinds":             words(catalog.Kinds()),
		"dispositions":                   words(finding.Dispositions()),
		"dispositions a ruling carries":  keeping(finding.Dispositions(), finding.Disposition.Rulable),
		"dispositions that wait":         keeping(finding.Dispositions(), finding.Disposition.NeedsSecondPerson),
		"what became of a claim":         words(triage.WhatHappenedAll()),
		"decision states":                words(triage.States()),
		"live decision states":           keeping(triage.States(), triage.State.Live),
		"ended decision states":          keeping(triage.States(), triage.State.Ended),
		"decision states or several":     append(words(triage.States()), triage.SeveralStates),
		"queue reasons":                  words(triage.QueueReasons()),
		"claim kinds":                    words(triage.ClaimKinds()),
		"standings":                      words(finding.ClaimStandings()),
		"unsettled standings":            keeping(finding.ClaimStandings(), finding.ClaimStanding.Unsettled),
		"bands":                          finding.Bands(),
		"ratings":                        finding.LeastFirst(),
		"recordable severities":          finding.Recordable(),
		"triage lines":                   finding.TriageFloors(),
		"triage lines or clear":          append(finding.TriageFloors(), ""),
		"score bands":                    cvss.Bands(),
		"statement sources":              finding.Sources(),
		"publisher statuses":             finding.VexStatuses(),
		"build sayings":                  finding.BuildSayings(),
		"origins":                        words(finding.Origins()),
		"fix states":                     words(finding.FixStates()),
		"unmatchable reasons":            words(graph.Reasons),
		"reasons for no deadline":        words(finding.NoDeadlines()),
		"declared scopes":                sbom.Scopes(),
		"planned":                        {string(finding.PlannedOnly), string(finding.NotPlanned), core.PlannedEither},
		"support":                        finding.Supports(),
		"assignees":                      finding.Assignees(),
		"upgrade states":                 words(finding.UpgradeStates()),
		"match routes":                   words(finding.MatchRoutes()),
		"reference kinds":                words(finding.ReferenceKinds()),
		"assessment states":              finding.AssessmentStates(),
		"ruling states":                  words(finding.RulingStates()),
		"platforms":                      notify.Platforms(),
		"notification kinds":             words(notify.Kinds()),
		"destination kinds":              append(words(notify.Kinds()), notify.Everything),
		"notification lifetimes":         words(notify.Lifetimes()),
		"upload progress":                words(ingest.Progresses()),
		"document kinds":                 words(ingest.Kinds()),
		"access modes":                   words(access.Modes()),
		"grant sources":                  words(access.Sources()),
		"email sources":                  words(access.EmailSources()),
		"party kinds":                    words(access.PartyKinds()),
		"repository states":              words(patchbranch.States()),
		"visit steps":                    words(patchbranch.Steps()),
		"reasons for no upstream answer": words(currency.Whys()),
		"trail kinds":                    words(trail.Kinds()),
		"trail actors":                   words(trail.Actors()),
		"malice":                         obligation.Malice,
		"advisory statuses":              advisory.Statuses(),
		"release statuses":               advisory.ReleaseStatuses(),
		"setting kinds":                  words(setting.Kinds()),
		"setting sections":               words(setting.Sections()),
		"finding sorts":                  words(finding.SortKeys()),
		"bundle sorts":                   words(finding.BundleSortKeys()),
		"closures":                       words(finding.Closures()),
		"exchange document kinds":        words(vex.Kinds()),
		"visibilities":                   words(access.Visibilities()),
		"inventory changes":              words(graph.ChangeKinds()),
		"spread over variants":           words(finding.VariantSpreads()),
	}
}

// TestEveryEnumInTheDocumentIsAListSomethingStates holds every closed
// vocabulary the document offers to a list a package states.
//
// An enum is a domain vocabulary offered, so it has to be one of the lists
// the owning package names, in its order: a shorter copy or the same words
// reordered fails here. A whole list typed back as a literal builds the same
// document, so the source check below is what catches that one. The few
// enums no domain package owns are a format's or a route's own words, and are
// listed below by name, so a new enum is either built from its package or
// added there on purpose.
//
// Both directions: an entry no enum offers is a list this test carries for
// nothing, which is how a hand-kept table goes stale.
func TestEveryEnumInTheDocumentIsAListSomethingStates(t *testing.T) {
	stated := statedVocabularies()
	// What no domain package owns: a file format's words, or a route's own
	// answer that nothing beneath it names.
	owned := map[string][]string{
		"export formats":      {"csv", "json"},
		"register sides":      {"open", "closed"},
		"CVE record statuses": {"affected", "unaffected"},
		"commit lookups":      {"found", "absent"},
		"upload answers":      {"queued", "already_held"},
		"who answers":         {"person"},
	}

	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		offered := enumsIn(t, r)
		if len(offered) == 0 {
			t.Fatal("the document offers no enum, so this checked nothing")
		}
		used := map[string]bool{}
		for at, list := range offered {
			named := ""
			for _, table := range []map[string][]string{stated, owned} {
				for name, each := range table {
					if slices.Equal(each, list) {
						named = name
						used[name] = true
					}
				}
			}
			if named == "" {
				t.Errorf("%s offers %v, which is none of the lists a package states — build it "+
					"from the package that owns the words, or name it as a format's own", at, list)
			}
		}
		for _, table := range []map[string][]string{stated, owned} {
			for name := range table {
				if !used[name] {
					t.Errorf("no enum in the document offers the %s, so the entry checks nothing", name)
				}
			}
		}
	})
}

// enumTag is a struct tag's literal enum.
var enumTag = regexp.MustCompile(`enum:"([^"]*)"`)

// retypedIn is every stated vocabulary a source file types back as a literal
// enum tag, by name.
func retypedIn(source string, stated map[string][]string) []string {
	var found []string
	for _, tag := range enumTag.FindAllStringSubmatch(source, -1) {
		listed := strings.Split(tag[1], ",")
		for name, each := range stated {
			if slices.Equal(each, listed) {
				found = append(found, name)
			}
		}
	}
	return found
}

// A literal enum tag naming a stated vocabulary in full is caught in the
// source, because it builds the same document as the vocabulary type does.
func TestRetypedInFindsAStatedListTypedBack(t *testing.T) {
	stated := map[string][]string{"reference kinds": {"patch", "advisory", "report"}}
	if got := retypedIn("Kind string `json:\"kind\" enum:\"patch,advisory,report\"`", stated); !slices.Equal(got, []string{"reference kinds"}) {
		t.Errorf("a whole stated list typed back was reported as %v", got)
	}
	if got := retypedIn("Format string `query:\"format\" enum:\"csv,json\"`", stated); len(got) != 0 {
		t.Errorf("a format's own words were reported as %v", got)
	}
}

// TestNoEnumTagTypesBackAStatedVocabulary fails a literal enum tag anywhere in
// the API's source whose words are a list a domain package states.
func TestNoEnumTagTypesBackAStatedVocabulary(t *testing.T) {
	stated := statedVocabularies()
	read := 0
	tree := os.DirFS(".")
	err := fs.WalkDir(tree, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source, err := fs.ReadFile(tree, path)
		if err != nil {
			return err
		}
		read++
		for _, name := range retypedIn(string(source), stated) {
			t.Errorf("%s types the %s back as a literal enum tag — use the vocabulary type "+
				"that builds them from their package", path, name)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if read == 0 {
		t.Fatal("no source file was read, so this checked nothing")
	}
}
