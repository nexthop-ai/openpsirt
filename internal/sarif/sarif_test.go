// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

func limits() Limits {
	return Limits{
		MaxBytes: 1 << 20, MaxDepth: 32, MaxRuns: 4, MaxResults: 100, MaxRules: 100,
		MaxLocations: 10, MaxSteps: 20, MaxModules: 8, MaxBases: 8, MaxChain: 4,
		MaxProperties: 16, MaxText: 200, MaxHeld: 1000, MaxSnippet: 64,
	}
}

func readFile(t *testing.T, name string) Log {
	t.Helper()
	f, err := os.OpenInRoot("testdata", name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// A real tool's output is read within the bounds a deployment ships.
	log, err := NewUpload(DefaultLimits()).Read(f)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return log
}

func read(t *testing.T, doc string) Log {
	t.Helper()
	log, err := NewUpload(limits()).Read(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	return log
}

// refused asserts doc is refused as the sender's fault, with words holding
// want.
func refused(t *testing.T, doc string, lim Limits, want string) {
	t.Helper()
	_, err := NewUpload(lim).Read(strings.NewReader(doc))
	if err == nil {
		t.Fatalf("read; want a refusal holding %q", want)
	}
	var r refusal.Refusal
	if !errors.As(err, &r) {
		t.Fatalf("%v is not a refusal", err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("%v; want it to hold %q", err, want)
	}
}

// run wraps a run's members in a document.
func run(members string) string {
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t"}}` + members + `}]}`
}

func TestClangOutputIsReadWithItsRulesAndPath(t *testing.T) {
	log := readFile(t, "clang18-a.sarif")
	if len(log.Runs) != 1 {
		t.Fatalf("%d runs; want 1", len(log.Runs))
	}
	r := log.Runs[0]
	if r.Tool.Name != "clang" || !strings.Contains(r.Tool.Version, "18.1.3") {
		t.Errorf("tool %q %q", r.Tool.Name, r.Tool.Version)
	}
	if !r.Ran || len(r.Results) != 3 {
		t.Fatalf("ran %v with %d results; want 3", r.Ran, len(r.Results))
	}
	var leak *Result
	for i := range r.Results {
		if r.Results[i].RuleID == "unix.Malloc" {
			leak = &r.Results[i]
		}
	}
	if leak == nil {
		t.Fatal("no unix.Malloc result")
	}
	if leak.Locations[0].StartLine != 7 || len(leak.Steps) < 2 {
		t.Errorf("leak at line %d with %d steps", leak.Locations[0].StartLine, len(leak.Steps))
	}
	if leak.Steps[0].Message != "Memory is allocated" {
		t.Errorf("first step says %q", leak.Steps[0].Message)
	}
}

func TestAnAbsolutePathIsPlacedOnlyUnderTheStatedRoot(t *testing.T) {
	log := readFile(t, "clang18-a.sarif")
	placed, dropped := Prepare(&log.Runs[0], "/home/builder/sonic")
	if dropped.Outside != 0 || len(placed) != 3 {
		t.Fatalf("placed %d, dropped %+v", len(placed), dropped)
	}
	paths := map[string]bool{}
	for _, p := range placed {
		paths[p.Path] = true
	}
	if !paths["a.c"] || !paths["include/shared.h"] {
		t.Errorf("paths %v", paths)
	}

	// With no root, the build host's own layout is never kept.
	placed, dropped = Prepare(&log.Runs[0], "")
	if len(placed) != 0 || dropped.Outside != 3 {
		t.Errorf("placed %d with no root, dropped %+v", len(placed), dropped)
	}
	// Nor under a root the paths are not beneath.
	placed, _ = Prepare(&log.Runs[0], "/home/builder/other")
	if len(placed) != 0 {
		t.Errorf("placed %d under another root", len(placed))
	}
}

func TestAHeaderResultRepeatedPerUnitIsKeptOnce(t *testing.T) {
	a, b := readFile(t, "clang18-a.sarif"), readFile(t, "clang18-b.sarif")
	merged := a.Runs[0]
	merged.Results = append(append([]Result{}, a.Runs[0].Results...), b.Runs[0].Results...)
	placed, dropped := Prepare(&merged, "/home/builder/sonic")
	if dropped.Repeats != 1 {
		t.Errorf("collapsed %d; want the header's one repeat", dropped.Repeats)
	}
	header := 0
	for _, p := range placed {
		if p.Path == "include/shared.h" {
			header++
		}
	}
	if header != 1 || len(placed) != 4 {
		t.Errorf("%d results in the header of %d placed", header, len(placed))
	}
}

func TestCppcheckRelativePathsAreRelativeToTheRoot(t *testing.T) {
	log := readFile(t, "cppcheck222.sarif")
	r := log.Runs[0]
	if r.Tool.Name != "Cppcheck" || r.Tool.Version != "2.22.0" {
		t.Errorf("tool %q %q", r.Tool.Name, r.Tool.Version)
	}
	placed, dropped := Prepare(&r, "")
	if len(placed) != 4 || dropped != (Dropped{}) {
		t.Fatalf("placed %d, dropped %+v", len(placed), dropped)
	}
	if placed[1].Path != "include/shared.h" {
		t.Errorf("second result at %q", placed[1].Path)
	}
	rule, ok := r.RuleOf("memleak")
	if !ok || rule.SecuritySeverity != "9.9" || rule.Precision != "high" || rule.DefaultLevel != "error" {
		t.Errorf("memleak rule %+v", rule)
	}
	if len(rule.Tags) == 0 || rule.Tags[0] != "external/cwe/cwe-401" {
		t.Errorf("tags %v", rule.Tags)
	}
}

func TestResultsAbsentNullAndEmptyAreToldApart(t *testing.T) {
	for doc, ran := range map[string]bool{
		run(``):                false,
		run(`,"results":null`): false,
		run(`,"results":[]`):   true,
	} {
		r := read(t, doc).Runs[0]
		if r.Ran != ran {
			t.Errorf("%s: ran %v; want %v", doc, r.Ran, ran)
		}
	}
}

func TestOnlyVersionTwoOneZeroIsRead(t *testing.T) {
	refused(t, `{"version":"2.0.0","runs":[]}`, limits(), "is not 2.1.0")
	refused(t, `{"runs":[]}`, limits(), "is not 2.1.0")
}

func TestEachBoundRefusesTheDocumentNamingIt(t *testing.T) {
	location := `{"physicalLocation":{"artifactLocation":{"uri":"a.c"}}}`
	step := `{"location":` + location + `}`
	many := func(item string, n int) string {
		return strings.TrimSuffix(strings.Repeat(item+",", n), ",")
	}
	for name, c := range map[string]struct {
		doc  string
		lim  func(*Limits)
		want string
	}{
		"runs":    {`{"version":"2.1.0","runs":[{},{}]}`, func(l *Limits) { l.MaxRuns = 1 }, "runs"},
		"results": {run(`,"results":[{},{}]`), func(l *Limits) { l.MaxResults = 1 }, "results in a run"},
		"rules": {`{"version":"2.1.0","runs":[{"tool":{"driver":{"rules":[{},{}]}}}]}`,
			func(l *Limits) { l.MaxRules = 1 }, "rules in a run"},
		"locations": {run(`,"results":[{"locations":[` + location + `],"relatedLocations":[` + location + `]}]`),
			func(l *Limits) { l.MaxLocations = 1 }, "locations in a result"},
		"steps across flows": {run(`,"results":[{"codeFlows":[{"threadFlows":[{"locations":[` + step +
			`]}]},{"threadFlows":[{"locations":[` + step + `]}]}]}]`),
			func(l *Limits) { l.MaxSteps = 1 }, "flow steps in a result"},
		"modules": {run(`,"versionControlProvenance":[{},{}]`), func(l *Limits) { l.MaxModules = 1 }, "repositories in a run"},
		"bases":   {run(`,"originalUriBaseIds":{"A":{},"B":{}}`), func(l *Limits) { l.MaxBases = 1 }, "named starting points"},
		"properties": {run(`,"results":[{"properties":{"a":1,"b":2}}]`),
			func(l *Limits) { l.MaxProperties = 1 }, "members in a property bag"},
		"depth": {run(`,"results":[{"properties":{"a":` + strings.Repeat("[", 40) + strings.Repeat("]", 40) + `}}]`),
			func(*Limits) {}, "deeper than"},
		"size": {run(`,"results":[` + many(`{"ruleId":"x"}`, 100) + `]`),
			func(l *Limits) { l.MaxBytes = 200 }, "larger than the configured limit"},
		"held": {run(`,"results":[{"locations":[` + location + `]},{}]`),
			func(l *Limits) { l.MaxHeld = 3 }, "other entries across the upload's documents"},
	} {
		t.Run(name, func(t *testing.T) {
			lim := limits()
			c.lim(&lim)
			refused(t, c.doc, lim, c.want)
		})
	}
}

func TestEveryEntryReadCountsTowardWhatTheUploadHolds(t *testing.T) {
	step := `{"location":{"physicalLocation":{"artifactLocation":{"uri":"a.c"}}}}`
	rules := func(rules string) string {
		return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t","rules":[` + rules + `]}}}]}`
	}
	// held is everything the document holds: its run, and what each case
	// names, two of the kind it is for.
	for name, c := range map[string]struct {
		doc  string
		held int
	}{
		"invocations":     {run(`,"invocations":[{},{}]`), 3},
		"repositories":    {run(`,"versionControlProvenance":[{},{}]`), 3},
		"starting points": {run(`,"originalUriBaseIds":{"A":{},"B":{}}`), 3},
		"rules":           {rules(`{},{}`), 3},
		"message strings": {rules(`{"messageStrings":{"a":{"text":"x"},"b":{"text":"y"}}}`), 4},
		"tags":            {rules(`{"properties":{"tags":["a","b"]}}`), 4},
		"arguments":       {run(`,"results":[{"message":{"text":"x","arguments":["a","b"]}}]`), 4},
		"fingerprints":    {run(`,"results":[{"partialFingerprints":{"a":"1","b":"2"}}]`), 4},
		"kept steps": {run(`,"results":[{"codeFlows":[{"threadFlows":[{"locations":[` + step + `,` + step + `]}]}]}]`),
			4},
		"changed repositories": {run(`,"properties":{"openpsirt/changed":["a","b"]}`), 3},
	} {
		t.Run(name, func(t *testing.T) {
			lim := limits()
			lim.MaxHeld = c.held
			if _, err := NewUpload(lim).Read(strings.NewReader(c.doc)); err != nil {
				t.Fatalf("refused holding %d at a bound of %d: %v", c.held, c.held, err)
			}
			lim.MaxHeld = c.held - 1
			refused(t, c.doc, lim, "other entries across the upload's documents")
		})
	}
}

func TestATextPastItsBoundIsCut(t *testing.T) {
	long := strings.Repeat("é", 200)
	r := read(t, run(`,"results":[{"message":{"text":"`+long+`"}}]`)).Runs[0]
	if got := len(r.Results[0].Message); got > limits().MaxText || got == 0 {
		t.Errorf("message of %d bytes", got)
	}
}

func TestAChainOfStartingPointsThatLoopsIsRefused(t *testing.T) {
	refused(t, run(`,"originalUriBaseIds":{"A":{"uri":"x/","uriBaseId":"B"},"B":{"uri":"y/","uriBaseId":"A"}}`),
		limits(), "defined in terms of itself")
	lim := limits()
	lim.MaxChain = 2
	refused(t, run(`,"originalUriBaseIds":{"A":{"uri":"x/","uriBaseId":"B"},"B":{"uri":"y/","uriBaseId":"C"},"C":{"uri":"file:///r/"}}`),
		lim, "starting points in one chain")
}

func TestAddressesResolveThroughTheirStartingPoints(t *testing.T) {
	doc := run(`,"originalUriBaseIds":{
		"SRCROOT":{"uri":"file:///home/builder/sonic/"},
		"FRR":{"uri":"src/sonic-frr/frr/","uriBaseId":"SRCROOT"}},
	"versionControlProvenance":[
		{"repositoryUri":"https://github.com/sonic-net/sonic-buildimage","revisionId":"abc","mappedTo":{"uriBaseId":"SRCROOT"}},
		{"repositoryUri":"https://github.com/FRRouting/frr","revisionId":"def","mappedTo":{"uriBaseId":"FRR"}}],
	"results":[
		{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"bgpd/bgp_attr.c","uriBaseId":"FRR"}}}]},
		{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/swss/orch.cpp","uriBaseId":"SRCROOT"}}}]},
		{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///home/builder/sonic/src/x.c"}}}]},
		{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"../../etc/passwd","uriBaseId":"SRCROOT"}}}]},
		{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"y.c","uriBaseId":"UNDEFINED"}}}]},
		{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"https://example.com/z.c"}}}]}]`)
	r := read(t, doc).Runs[0]
	placed, dropped := Prepare(&r, "")
	if dropped.Outside != 2 || dropped.Web != 1 {
		t.Errorf("dropped %+v; want the escape and the undefined name outside, and the web address", dropped)
	}
	want := []struct {
		path, within string
		module       int
	}{
		{"src/sonic-frr/frr/bgpd/bgp_attr.c", "bgpd/bgp_attr.c", 1},
		{"src/swss/orch.cpp", "src/swss/orch.cpp", 0},
		{"src/x.c", "src/x.c", 0},
	}
	if len(placed) != len(want) {
		t.Fatalf("placed %d; want %d", len(placed), len(want))
	}
	paths := PathsOf(&r, "")
	for i, w := range want {
		if placed[i].Path != w.path || placed[i].Module != w.module {
			t.Errorf("result %d at %q in module %d; want %q in %d", i, placed[i].Path, placed[i].Module, w.path, w.module)
			continue
		}
		if got := paths.Within(placed[i].Module, placed[i].Path); got != w.within {
			t.Errorf("result %d is %q within its repository; want %q", i, got, w.within)
		}
	}
}

func TestAWindowsPathIsPlacedLikeAnyOther(t *testing.T) {
	r := read(t, run(`,"results":[
		{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///C:/build/sonic/src/a.c"}}}]},
		{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"c:\\build\\sonic\\src\\b.c"}}}]},
		{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src\\c.c"}}}]}]`)).Runs[0]
	placed, dropped := Prepare(&r, `C:\build\sonic`)
	if dropped.Outside != 0 || len(placed) != 3 {
		t.Fatalf("placed %d, dropped %+v", len(placed), dropped)
	}
	for i, want := range []string{"src/a.c", "src/b.c", "src/c.c"} {
		if placed[i].Path != want {
			t.Errorf("result %d at %q; want %q", i, placed[i].Path, want)
		}
	}
}

func TestAnAdvisoryIdentifierAsARuleIsADependencyFinding(t *testing.T) {
	for _, id := range []string{"CVE-2024-3094", "cve-2021-44228", "GHSA-jfh8-c2jp-5v3q", "GO-2023-1840",
		"RUSTSEC-2021-0145", "PYSEC-2021-19", "OSV-2020-111", "SNYK-JS-LODASH-567746", "DSA-5678-1",
		"DLA-3456", "RHSA-2024:1234", "ALAS2-2023-2001", "MAL-2024-1", "ALAS-2022-1580"} {
		if !advisory.MatchString(id) {
			t.Errorf("%s is not taken as an advisory", id)
		}
	}
	for _, id := range []string{"core.NullDereference", "CVE-checker", "cve-2024", "GHSA-1111-2222-3333",
		"cpp/uncontrolled-format-string", "bugprone-use-after-move", "RHSA-2024"} {
		if advisory.MatchString(id) {
			t.Errorf("%s is taken as an advisory", id)
		}
	}
	r := read(t, run(`,"results":[{"ruleId":"CVE-2024-3094","locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"}}}]}]`)).Runs[0]
	if placed, dropped := Prepare(&r, ""); len(placed) != 0 || dropped.Advisory != 1 {
		t.Errorf("placed %d, dropped %+v", len(placed), dropped)
	}
}

func TestADependencyOrSecretScannerIsKnownByItsDriver(t *testing.T) {
	for _, name := range []string{"Trivy", "govulncheck", " gitleaks ", "TruffleHog"} {
		if !Scanner(name) {
			t.Errorf("%q is not a scanner", name)
		}
	}
	for _, name := range []string{"clang", "Cppcheck", "CodeQL", "clang-tidy"} {
		if Scanner(name) {
			t.Errorf("%q is a scanner", name)
		}
	}
}

func TestWholeFilesAndFixesAreCountedAndNeverKept(t *testing.T) {
	doc := run(`,"artifacts":[{"contents":{"text":"int main(){}"}},{"location":{"uri":"a.c"}}],
	"results":[{"message":{"text":"plain","markdown":"**bold**"},
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},
			"region":{"startLine":3}}}],
		"fixes":[{"artifactChanges":[]}]}]`)
	r := read(t, doc).Runs[0]
	want := Discarded{Markdown: 1, Contents: 1, Fixes: 1}
	if r.Discarded != want {
		t.Errorf("discarded %+v; want %+v", r.Discarded, want)
	}
	if res := r.Results[0]; res.Message != "plain" || res.Locations[0].StartLine != 3 {
		t.Errorf("result %+v", res)
	}
}

func TestAMessageHoldingOnlyMarkdownIsReducedToItsText(t *testing.T) {
	doc := run(`,"results":[{"message":{"markdown":"**Null** [pointer](https://example.com) <b>p</b>"}}]`)
	r := read(t, doc).Runs[0]
	if got := r.Results[0].Message; got != "Null pointer p" {
		t.Errorf("message %q; want the words the markdown shows", got)
	}
	if r.Discarded.Markdown != 1 {
		t.Errorf("discarded %+v; want the markdown counted", r.Discarded)
	}
}

func TestALocationsSourceIsReadFromItsWidestRegion(t *testing.T) {
	for name, regions := range map[string]string{
		"context last":  `"region":{"startLine":3,"snippet":{"text":"secret();"}},"contextRegion":{"startLine":1,"endLine":5,"snippet":{"text":"a\nsecret();"}}`,
		"context first": `"contextRegion":{"startLine":1,"endLine":5,"snippet":{"text":"a\nsecret();"}},"region":{"startLine":3,"snippet":{"text":"secret();"}}`,
	} {
		doc := run(`,"results":[{"message":{"text":"m"},
			"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},` + regions + `}}]}]`)
		loc := read(t, doc).Runs[0].Results[0].Locations[0]
		if loc.Snippet != "a\nsecret();" || loc.SnippetLine != 1 {
			t.Errorf("%s: snippet %q at %d; want the context region's, at line 1", name, loc.Snippet, loc.SnippetLine)
		}
		if loc.StartLine != 3 || loc.EndLine != 0 {
			t.Errorf("%s: placed at %d-%d; want the region's own lines", name, loc.StartLine, loc.EndLine)
		}
	}
	most := limits().MaxSnippet
	long := strings.Repeat("x", most+10)
	doc := run(`,"results":[{"message":{"text":"m"},
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":3,"snippet":{"text":"` + long + `"}}}}]}]`)
	if got := read(t, doc).Runs[0].Results[0].Locations[0].Snippet; len(got) != most {
		t.Errorf("kept %d bytes of source; want the configured %d", len(got), most)
	}
}

func TestSourceIsKeptOnlyUnderAPathItIsKeptFor(t *testing.T) {
	doc := run(`,"results":[{"message":{"text":"m"},
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":"public/a.c"},"region":{"startLine":3,"snippet":{"text":"open();"}}}}],
		"relatedLocations":[{"physicalLocation":{"artifactLocation":{"uri":"private/b.c"},"region":{"startLine":9,"snippet":{"text":"hidden();"}}}}],
		"codeFlows":[{"threadFlows":[{"locations":[
			{"location":{"physicalLocation":{"artifactLocation":{"uri":"public/c.c"},"region":{"startLine":1,"snippet":{"text":"step();"}}}}},
			{"location":{"physicalLocation":{"artifactLocation":{"uri":"/elsewhere/d.c"},"region":{"startLine":1,"snippet":{"text":"outside();"}}}}}]}]}]}]`)
	r := read(t, doc).Runs[0]
	pl := NewPlacer(func(path string) bool { return strings.HasPrefix(path, "public/") })
	got := pl.Place(&r, "")[0]
	if got.Snippet != "open();" || got.SnippetLine != 3 {
		t.Errorf("the result kept %q at %d; want its source", got.Snippet, got.SnippetLine)
	}
	if got.Steps[0].Snippet != "step();" || got.Steps[1].Snippet != "" || got.Related[0].Snippet != "" {
		t.Errorf("steps kept %q and %q, related %q; want the public step's alone", got.Steps[0].Snippet, got.Steps[1].Snippet, got.Related[0].Snippet)
	}
	if pl.Snippets() != 2 {
		t.Errorf("%d discarded; want the private and the outside location's", pl.Snippets())
	}
	if placed, _ := Prepare(&r, ""); placed[0].Snippet != "" {
		t.Errorf("a placer keeping nothing kept %q", placed[0].Snippet)
	}
}

func TestAResultNamedByReferenceIsSettledFromItsRun(t *testing.T) {
	// The results precede the rules they cite.
	doc := `{"version":"2.1.0","runs":[{"results":[
		{"ruleIndex":1,"message":{"id":"default","arguments":["buf","12"]}},
		{"ruleId":"r0"},
		{"ruleId":"unknown"}],
	"tool":{"driver":{"name":"t","rules":[
		{"id":"r0","defaultConfiguration":{"level":"error"}},
		{"id":"r1","messageStrings":{"default":{"text":"{0} is leaked at line {1}; {2} stays"}}}]}}}]}`
	r := read(t, doc).Runs[0]
	if got := r.Results[0]; got.RuleID != "r1" || got.Message != "buf is leaked at line 12; {2} stays" || got.Level != "warning" {
		t.Errorf("first result %+v", got)
	}
	if got := r.Results[1].Level; got != "error" {
		t.Errorf("second result's level %q; want its rule's", got)
	}
	if got := r.Results[2].Level; got != "warning" {
		t.Errorf("third result's level %q; want the format's default", got)
	}
}

func TestWhatTheClientWritesIsRead(t *testing.T) {
	doc := run(`,"automationDetails":{"id":"clang-sa/default/2026-10-24T03:00:00Z"},
	"properties":{"openpsirt/unitsExpected":120,"openpsirt/unitsAnalyzed":118,
		"openpsirt/client":"0.11.0","openpsirt/changed":["src/sonic-frr/frr"],"other":{"x":1}},
	"invocations":[{"exitCode":1,"executionSuccessful":false,
		"toolExecutionNotifications":[{"level":"error","descriptor":{"id":"clang-diagnostic-error"}},{"level":"note"}]}]`)
	r := read(t, doc).Runs[0]
	p := r.Properties
	if p.UnitsExpected == nil || *p.UnitsExpected != 120 || p.UnitsAnalyzed == nil || *p.UnitsAnalyzed != 118 ||
		p.Client != "0.11.0" || len(p.Changed) != 1 {
		t.Errorf("properties %+v", p)
	}
	if r.AutomationID != "clang-sa/default/2026-10-24T03:00:00Z" {
		t.Errorf("automation %q", r.AutomationID)
	}
	inv := r.Invocations[0]
	if inv.ExitCode == nil || *inv.ExitCode != 1 || inv.Successful == nil || *inv.Successful ||
		inv.Errors != 1 || inv.Signals() != 1 {
		t.Errorf("invocation %+v", inv)
	}
	refused(t, run(`,"properties":{"openpsirt/unitsExpectd":1}`), limits(), "not one this deployment reads")
}

func TestADocumentFollowedByAnotherIsRefused(t *testing.T) {
	refused(t, run(``)+run(``), limits(), "continues after its top-level value")
}

func TestTheFunctionAndCallDepthTheClientWritesAreKept(t *testing.T) {
	doc := run(`,"results":[{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c","uriBaseId":"%SRCROOT%"}},
		"logicalLocations":[{"name":"leak","kind":"function"},{"fullyQualifiedName":"ns::leak"}]}],
		"codeFlows":[{"threadFlows":[{"locations":[
			{"nestingLevel":0,"location":{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":5}}}},
			{"nestingLevel":1,"location":{"physicalLocation":{"artifactLocation":{"uri":"/elsewhere/b.c"},"region":{"startLine":9}}}}]}]}]}]`)
	r := read(t, doc).Runs[0]
	placed, _ := Prepare(&r, "")
	if len(placed) != 1 {
		t.Fatalf("placed %d; an undefined root's name is relative to the root", len(placed))
	}
	p := placed[0]
	if p.Path != "a.c" || p.Function != "ns::leak" {
		t.Errorf("at %q in %q", p.Path, p.Function)
	}
	if len(p.Steps) != 2 || p.Steps[1].Depth == nil || *p.Steps[1].Depth != 1 {
		t.Fatalf("steps %+v", p.Steps)
	}
	if p.Steps[0].Path != "a.c" || p.Steps[1].Path != "" || p.Steps[1].StartLine != 9 {
		t.Errorf("steps %+v; a step outside the checkout keeps its line and loses its path", p.Steps)
	}
}

func TestAnUploadIsBoundedAcrossItsDocuments(t *testing.T) {
	doc := run(`,"results":[{"ruleId":"x"},{"ruleId":"y"}]`)
	for name, lim := range map[string]func(*Limits){
		"size": func(l *Limits) { l.MaxBytes = int64(len(doc)*2 - 1) },
		"held": func(l *Limits) { l.MaxHeld = 5 },
	} {
		t.Run(name, func(t *testing.T) {
			l := limits()
			lim(&l)
			upload := NewUpload(l)
			if _, err := upload.Read(strings.NewReader(doc)); err != nil {
				t.Fatalf("first document: %v", err)
			}
			_, err := upload.Read(strings.NewReader(doc))
			if err == nil || !strings.Contains(err.Error(), "across the upload's documents") {
				t.Fatalf("second document: %v; want the upload refused", err)
			}
			if _, err := NewUpload(l).Read(strings.NewReader(doc)); err != nil {
				t.Errorf("the same document alone: %v", err)
			}
		})
	}
}

func TestTextWordedForAResultCountsTowardTheUploadsSize(t *testing.T) {
	doc := run(`,"results":[` + strings.Repeat(`{"ruleId":"r","message":{"id":"m","arguments":["a"]}},`, 3) +
		`{"ruleId":"r","message":{"id":"m","arguments":["a"]}}]` +
		`,"tool":{"driver":{"name":"t","rules":[{"id":"r","messageStrings":{"m":{"text":"` +
		strings.Repeat("x", 150) + ` {0}"}}}]}}`)
	lim := limits()
	lim.MaxBytes = int64(len(doc) + 3*152)
	_, err := NewUpload(lim).Read(strings.NewReader(doc))
	if err == nil || !strings.Contains(err.Error(), "the text worded for their results") {
		t.Fatalf("%v; want the worded text counted", err)
	}
	lim.MaxBytes = int64(len(doc) + 4*152)
	if _, err := NewUpload(lim).Read(strings.NewReader(doc)); err != nil {
		t.Errorf("with room for the worded text: %v", err)
	}
}

func TestTextWordedEarlyInADocumentCountsOnceTheDocumentEnds(t *testing.T) {
	worded := `{"tool":{"driver":{"name":"t","rules":[{"id":"r","messageStrings":{"m":{"text":"` +
		strings.Repeat("x", 150) + ` {0}"}}}]}},"results":[{"ruleId":"r","message":{"id":"m","arguments":["a"]}}]}`
	padded := `{"tool":{"driver":{"name":"` + strings.Repeat("p", 100) + `"}},"results":[]}`
	doc := `{"version":"2.1.0","runs":[` + worded + `,` + padded + `]}`
	lim := limits()
	lim.MaxBytes = int64(len(doc) + 100)
	_, err := NewUpload(lim).Read(strings.NewReader(doc))
	if err == nil || !strings.Contains(err.Error(), "the text worded for their results") {
		t.Fatalf("%v; want the worded text counted with the rest of the document", err)
	}
}

func TestWordingPastTheBoundStopsTheDocumentThere(t *testing.T) {
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t","rules":[{"id":"r","messageStrings":{"m":{"text":"` +
		strings.Repeat("x", 150) + ` {0}"}}}]}},"results":[` +
		strings.Repeat(`{"ruleId":"r","message":{"id":"m","arguments":["a"]}},`, 3) +
		`{"ruleId":"r","message":{"id":"m","arguments":["a"]}}]},`
	lim := limits()
	lim.MaxBytes = int64(len(doc) + 200)
	_, err := NewUpload(lim).Read(strings.NewReader(doc + ` not JSON`))
	if err == nil || !strings.Contains(err.Error(), "the text worded for their results") {
		t.Fatalf("%v; want the run refused before the rest is read", err)
	}
}

func TestALaterDocumentIsReadOnlyWithinWhatIsLeft(t *testing.T) {
	first := run(`,"results":[]`)
	lim := limits()
	lim.MaxBytes = int64(len(first) + 40)
	upload := NewUpload(lim)
	if _, err := upload.Read(strings.NewReader(first)); err != nil {
		t.Fatal(err)
	}
	_, err := upload.Read(strings.NewReader(run(`,"results":[`+strings.Repeat(`{},`, 30)) + ` not JSON`))
	if err == nil || !strings.Contains(err.Error(), "across the upload's documents") {
		t.Fatalf("%v; want the second document stopped where the budget ran out", err)
	}
}

func TestFillingAMessageStopsAtItsBound(t *testing.T) {
	argument := strings.Repeat("a", 100)
	got := fill(strings.Repeat("{0}", 1000), []string{argument}, 250)
	if len(got) > 250+len(argument) {
		t.Errorf("filled %d bytes; want it to stop once past 250", len(got))
	}
}

func TestAResultReportingNoProblemIsLeftOut(t *testing.T) {
	at := `"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"}}}]`
	r := read(t, run(`,"results":[
		{"ruleId":"a",`+at+`},
		{"ruleId":"b","kind":"review",`+at+`},
		{"ruleId":"c","kind":"open",`+at+`},
		{"ruleId":"d","kind":"fail","suppressions":[{"kind":"inSource","status":"rejected"}],`+at+`},
		{"ruleId":"e","kind":"pass",`+at+`},
		{"ruleId":"f","kind":"notApplicable",`+at+`},
		{"ruleId":"g","kind":"informational",`+at+`},
		{"ruleId":"h","suppressions":[{"kind":"inSource"}],`+at+`},
		{"ruleId":"i","suppressions":[{"status":"underReview"},{"status":"accepted"}],`+at+`},
		{"ruleId":"j","baselineState":"absent",`+at+`},
		{"ruleId":"k","baselineState":"unchanged",`+at+`}]`)).Runs[0]
	placed, dropped := Prepare(&r, "")
	var kept []string
	for _, p := range placed {
		kept = append(kept, p.RuleID)
	}
	if strings.Join(kept, "") != "abcdk" {
		t.Errorf("kept %v", kept)
	}
	if dropped != (Dropped{NotAProblem: 3, Suppressed: 2, Absent: 1}) {
		t.Errorf("dropped %+v", dropped)
	}
}

func TestAFailureSignalOutsideTheCheckoutIsStillAFailure(t *testing.T) {
	r := read(t, run(`,"results":[
		{"ruleId":"clang-diagnostic-error","locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///tmp/build/gen.h"}}}]},
		{"ruleId":"syntaxError"}]`)).Runs[0]
	placed, dropped := Prepare(&r, "/src")
	if len(placed) != 0 || dropped != (Dropped{Failure: 2}) {
		t.Errorf("placed %d, dropped %+v", len(placed), dropped)
	}
}

func TestARuleIsFoundByIdentifierThenByPositionInItsComponent(t *testing.T) {
	doc := `{"version":"2.1.0","runs":[{"results":[
		{"rule":{"index":1,"toolComponent":{"index":0}}},
		{"ruleIndex":1},
		{"ruleId":"e0","ruleIndex":0},
		{"ruleId":"r0","rule":{"toolComponent":{"index":0}}},
		{"ruleId":"zz","ruleIndex":0},
		{"ruleId":"r0/md5","ruleIndex":0},
		{"ruleId":"r0x/md5"}],
	"tool":{"driver":{"name":"t","rules":[{"id":"r0","defaultConfiguration":{"level":"note"}}]},
		"extensions":[{"name":"pack","rules":[
			{"id":"e0","defaultConfiguration":{"level":"error"}},
			{"id":"e1","defaultConfiguration":{"level":"none"}}]}]}}]}`
	r := read(t, doc).Runs[0]
	for i, want := range []struct{ id, level string }{
		{"e1", "none"},
		{"", "warning"},
		{"e0", "error"},
		{"r0", "warning"},
		{"zz", "warning"},
		{"r0/md5", "note"},
		{"r0x/md5", "warning"},
	} {
		if got := r.Results[i]; got.RuleID != want.id || got.Level != want.level {
			t.Errorf("result %d: rule %q at %q; want %q at %q", i, got.RuleID, got.Level, want.id, want.level)
		}
	}
}

func TestClangTidyOutputIsReadWithNoFingerprintAndNoFunction(t *testing.T) {
	log := readFile(t, "clangtidy-artemis.sarif")
	r := log.Runs[0]
	if r.Tool.Name != "clang-tidy" || len(r.Tool.Rules) != 0 || !r.Ran || len(r.Results) != 1 {
		t.Fatalf("tool %q with %d rules, ran %v, %d results", r.Tool.Name, len(r.Tool.Rules), r.Ran, len(r.Results))
	}
	res := r.Results[0]
	if res.RuleID != "clang-analyzer-core.NullDereference" || res.Level != "warning" ||
		res.Message != "Dereference of null pointer (loaded from variable 'p')" {
		t.Errorf("result %+v", res)
	}
	// Nothing but the rule, the path, the line and the message identifies
	// it: the matching it gets is the line layer's.
	if len(res.Fingerprints) != 0 || res.Locations[0].Function != "" || len(res.Steps) != 0 {
		t.Errorf("fingerprints %v, function %q, %d steps", res.Fingerprints, res.Locations[0].Function, len(res.Steps))
	}
	placed, dropped := Prepare(&log.Runs[0], "/var/tmp/testing-dir/assignment")
	if len(placed) != 1 || dropped.Outside != 0 || placed[0].Path != "src/main.cpp" {
		t.Errorf("placed %+v, dropped %+v", placed, dropped)
	}
}

func TestCodeQLOutputIsReadWithItsRuleSetFingerprintsAndCoverage(t *testing.T) {
	log := readFile(t, "codeql2150-cpp.sarif")
	r := log.Runs[0]
	if r.Tool.Name != "CodeQL" || r.Tool.Version != "2.15.0" || !r.Ran || len(r.Results) != 22 {
		t.Fatalf("tool %q %q, ran %v, %d results", r.Tool.Name, r.Tool.Version, r.Ran, len(r.Results))
	}
	if len(r.Tool.Rules) <= len(r.Results) {
		t.Errorf("%d rules; CodeQL lists every query it ran", len(r.Tool.Rules))
	}
	for _, res := range r.Results {
		if res.Fingerprints["primaryLocationLineHash"] == "" {
			t.Errorf("%s carries no line hash: %v", res.RuleID, res.Fingerprints)
		}
	}
	inv := r.Invocations[0]
	if inv.Successful == nil || !*inv.Successful || inv.Expected != 13 || inv.Extracted != 13 || inv.Signals() != 0 {
		t.Errorf("invocation %+v, %d signals", inv, inv.Signals())
	}
	placed, dropped := Prepare(&log.Runs[0], "/src")
	if len(placed) != 22 || dropped.Outside != 0 {
		t.Errorf("placed %d, dropped %+v", len(placed), dropped)
	}
}

func TestACodeQLRunThatExtractedNothingItExpectedIsAFailure(t *testing.T) {
	notify := func(id string) string {
		return `{"level":"none","descriptor":{"id":"` + id + `"},
			"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"}}}]}`
	}
	cases := []struct {
		name          string
		notifications []string
		signals       int
	}{
		{"expected and extracted", []string{notify("cpp/baseline/expected-extracted-files"),
			notify("cpp/diagnostics/successfully-extracted-files")}, 0},
		{"expected and none extracted", []string{notify("cpp/baseline/expected-extracted-files")}, 1},
		{"no coverage stated", nil, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := run(`,"results":[],"invocations":[{"executionSuccessful":true,
				"toolExecutionNotifications":[` + strings.Join(c.notifications, ",") + `]}]`)
			inv := read(t, doc).Runs[0].Invocations[0]
			if got := inv.Signals(); got != c.signals {
				t.Errorf("%+v reports %d failures; want %d", inv, got, c.signals)
			}
		})
	}
}

func TestARelativeAddressIsRelativeToWhereTheToolRan(t *testing.T) {
	results := `,"results":[{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"lib/a.c"}}}]},
		{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.c","uriBaseId":"%SRCROOT%"}}}]}]`
	for _, c := range []struct {
		name, invocations, first string
	}{
		{"run in a directory of the checkout",
			`,"invocations":[{"workingDirectory":{"uri":"file:///home/builder/sonic/src"}}]`, "src/lib/a.c"},
		{"run in a directory named relative to the root",
			`,"invocations":[{"workingDirectory":{"uri":"src","uriBaseId":"SRCROOT"}}]`, "src/lib/a.c"},
		{"run at the top of the checkout",
			`,"invocations":[{"workingDirectory":{"uri":"file:///home/builder/sonic/"}}]`, "lib/a.c"},
		{"run outside the checkout",
			`,"invocations":[{"workingDirectory":{"uri":"file:///tmp/build"}}]`, "lib/a.c"},
		{"stating no working directory", ``, "lib/a.c"},
	} {
		t.Run(c.name, func(t *testing.T) {
			log := read(t, run(results+c.invocations))
			placed, _ := Prepare(&log.Runs[0], "/home/builder/sonic")
			if len(placed) != 2 || placed[0].Path != c.first || placed[1].Path != "b.c" {
				t.Errorf("placed %+v; want %s, then b.c under the root's own name", placed, c.first)
			}
		})
	}
}

func TestEveryPropertyBagIsBoundedWhereverItIs(t *testing.T) {
	bag := `"properties":{"a":1,"b":{"c":[1,2]}}`
	loc := func(inner string) string {
		return `{"physicalLocation":{"artifactLocation":{"uri":"a.c"` + inner + `}}}`
	}
	for name, doc := range map[string]string{
		"a run's":    run(`,` + bag),
		"a driver's": `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t",` + bag + `}}}]}`,
		"a rule's": `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t","rules":[{"id":"r",` +
			bag + `}]}}}]}`,
		"a result's":            run(`,"results":[{` + bag + `}]`),
		"a message's":           run(`,"results":[{"message":{"text":"m",` + bag + `}}]`),
		"a location's":          run(`,"results":[{"locations":[{` + bag + `}]}]`),
		"an artifact address's": run(`,"results":[{"locations":[` + loc(`,`+bag) + `]}]`),
		"a flow step's": run(`,"results":[{"codeFlows":[{"threadFlows":[{"locations":[{"location":` +
			loc("") + `,` + bag + `}]}]}]}]`),
		"an invocation's":    run(`,"invocations":[{` + bag + `}]`),
		"a notification's":   run(`,"invocations":[{"toolExecutionNotifications":[{"level":"note",` + bag + `}]}]`),
		"a member not read":  run(`,"taxonomies":[{"name":"CWE",` + bag + `}]`),
		"a bag within a bag": run(`,"results":[{"properties":{"x":{` + bag + `}}}]`),
	} {
		t.Run(name, func(t *testing.T) {
			lim := limits()
			lim.MaxProperties = 2
			if _, err := NewUpload(lim).Read(strings.NewReader(doc)); err != nil {
				t.Fatalf("refused at a bound the bag meets: %v", err)
			}
			lim.MaxProperties = 1
			refused(t, doc, lim, "members in a property bag")
		})
	}
}

func TestOneDocumentIsBoundedOnItsOwnAndAsSent(t *testing.T) {
	doc := run(`,"results":[{"ruleId":"x"},{"ruleId":"y"}]`)
	lim := limits()
	lim.MaxPart = int64(len(doc))
	upload := NewUpload(lim)
	for i := range 2 {
		if _, err := upload.Read(strings.NewReader(doc)); err != nil {
			t.Fatalf("document %d at its bound: %v", i+1, err)
		}
	}
	lim.MaxPart = int64(len(doc) - 1)
	refused(t, doc, lim, "bytes in one document once decompressed")

	lim = limits()
	lim.MaxPartCompressed = 100
	if err := lim.OrDefault().Sent(100); err != nil {
		t.Errorf("a document sent at its bound: %v", err)
	}
	if err := lim.OrDefault().Sent(101); err == nil || !strings.Contains(err.Error(), "one document as it was sent") {
		t.Errorf("a document sent past its bound: %v", err)
	}
}

func TestTheBoundsLeftUnsetFollowTheUploadsBound(t *testing.T) {
	got := Limits{MaxBytes: 1 << 30}.OrDefault()
	if got.MaxPart != 1<<30 || got.MaxCompressed != 1<<30 || got.MaxPartCompressed != 1<<30 {
		t.Errorf("an upload bound of 1 GiB left one document at %d, the upload as sent at %d and one document as sent at %d; want all three 1 GiB",
			got.MaxPart, got.MaxCompressed, got.MaxPartCompressed)
	}
	part := Limits{MaxBytes: 1 << 30, MaxPart: 1 << 20}.OrDefault()
	if part.MaxCompressed != 1<<30 || part.MaxPartCompressed != 1<<20 {
		t.Errorf("a document bound of 1 MiB left the upload as sent at %d and one document as sent at %d; want 1 GiB and 1 MiB",
			part.MaxCompressed, part.MaxPartCompressed)
	}
}
