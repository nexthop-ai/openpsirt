// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysisclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fakeGit answers as git does for a checkout holding files, at commit, with
// no remote and no submodule.
func fakeGit(files []string, commit string) git {
	return func(_ context.Context, _ string, args ...string) (string, error) {
		switch args[0] {
		case "ls-files":
			return strings.Join(files, "\x00") + "\x00", nil
		case "rev-parse":
			return commit + "\n", nil
		case "remote":
			return "", errors.New("no such remote")
		case "status", "submodule":
			return "", nil
		case "config":
			return "", errors.New("no .gitmodules")
		}
		return "", errors.New("unexpected git " + strings.Join(args, " "))
	}
}

// sources is the two units and the header the reader fixtures were made
// from, which the plist and XML outputs here describe.
func sources(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "sarif", "testdata", "src"))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

var sourceFiles = []string{"a.c", "b.c", "include/shared.h"}

func fixture(t *testing.T, name string) Input {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // G304: a path under the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	return Input{Name: name, Data: data}
}

// built is the run a build wrote, decoded.
func built(t *testing.T, opts Options, inputs ...Input) (obj, Report) {
	t.Helper()
	if opts.Series == "" {
		opts.Series = "clang-sa/default"
	}
	written, report, err := build(t.Context(), fakeGit(sourceFiles, "0123abcd"), opts, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 1 {
		t.Fatalf("%d documents; want one", len(written))
	}
	dec := json.NewDecoder(bytes.NewReader(written[0].Doc))
	dec.UseNumber()
	var out obj
	if err := dec.Decode(&out); err != nil {
		t.Fatal(err)
	}
	runs := objects(out, "runs")
	if len(runs) != 1 {
		t.Fatalf("%d runs; want one", len(runs))
	}
	return runs[0], report
}

// resultAt is the run's result of a rule whose own location is at a path and
// line.
func resultAt(t *testing.T, run obj, rule, path string, line int) obj {
	t.Helper()
	for _, res := range objects(run, "results") {
		loc := child(objects(res, "locations")[0], "physicalLocation")
		at, _ := num(child(loc, "region"), "startLine")
		if str(res, "ruleId") == rule && str(child(loc, "artifactLocation"), "uri") == path && at == line {
			return res
		}
	}
	t.Fatalf("no %s result at %s:%d", rule, path, line)
	return nil
}

func functionOf(loc obj) string {
	logical := objects(loc, "logicalLocations")
	if len(logical) == 0 {
		return ""
	}
	return str(logical[0], "name")
}

func TestAPlistGivesTheIssueHashTheFunctionAndTheCallChain(t *testing.T) {
	root := sources(t)
	run, _ := built(t, Options{Root: root, Work: root}, fixture(t, "clang18-a.plist"))
	if name := str(child(child(run, "tool"), "driver"), "name"); name != "clang" {
		t.Errorf("tool %q; want clang", name)
	}
	res := resultAt(t, run, "core.DivideZero", "include/shared.h", 4)
	if got := str(child(res, "partialFingerprints"), schemeClang); got != "ec310ac93875aca406dbcb429879a36c" {
		t.Errorf("issue hash %q", got)
	}
	loc := objects(res, "locations")[0]
	if base := str(child(child(loc, "physicalLocation"), "artifactLocation"), "uriBaseId"); base != rootBase {
		t.Errorf("based on %q; want the checkout's top", base)
	}
	if f := functionOf(loc); f != "header_div" {
		t.Errorf("function %q; want header_div", f)
	}
	var functions []string
	var depths []int
	for _, step := range objects(objects(objects(res, "codeFlows")[0], "threadFlows")[0], "locations") {
		functions = append(functions, functionOf(child(step, "location")))
		d, _ := num(step, "nestingLevel")
		depths = append(depths, d)
	}
	wantFunctions := []string{"leak", "leak", "header_div", "header_div", "header_div"}
	if !reflect.DeepEqual(functions, wantFunctions) || !reflect.DeepEqual(depths, []int{0, 0, 1, 1, 1}) {
		t.Errorf("steps in %v at depths %v; want %v at 0 0 1 1 1", functions, depths, wantFunctions)
	}
}

func TestAPlistIsOneUnitAnalyzed(t *testing.T) {
	root := sources(t)
	three := 3
	run, _ := built(t, Options{Root: root, Work: root, UnitsExpected: &three},
		fixture(t, "clang18-a.plist"), fixture(t, "clang18-b.plist"))
	props := child(run, "properties")
	expected, _ := num(props, propUnitsExpected)
	analyzed, _ := num(props, propUnitsAnalyzed)
	if expected != 3 || analyzed != 2 {
		t.Errorf("units %d of %d; want 2 of 3", analyzed, expected)
	}
	if _, ok := props[unitsKey]; ok {
		t.Error("the readers' own count was written")
	}
	if n := len(objects(run, "results")); n != 5 {
		t.Errorf("%d results; want the five the two units report", n)
	}
}

func TestCppcheckXMLGivesTheCWEAndThePlaceTheResultIsAbout(t *testing.T) {
	root := sources(t)
	run, _ := built(t, Options{Root: root, Work: root, Series: "cppcheck/default"}, fixture(t, "cppcheck222.xml"))
	if n := len(objects(run, "results")); n != 4 {
		t.Errorf("%d results; want four, without cppcheck's notes about its own run", n)
	}
	res := resultAt(t, run, "zerodiv", "include/shared.h", 4)
	related := objects(res, "relatedLocations")
	if len(related) != 1 || str(child(related[0], "message"), "text") != "Assignment 'z=0', assigned value is 0" {
		t.Errorf("related %v; want the assignment", related)
	}
	if got := str(child(res, "partialFingerprints"), schemeCppcheck); got != "7334605733346961071" {
		t.Errorf("hash %q", got)
	}
	var tags any
	for _, rule := range objects(child(child(run, "tool"), "driver"), "rules") {
		if str(rule, "id") == "zerodiv" {
			tags = child(rule, "properties")["tags"]
		}
	}
	if !reflect.DeepEqual(tags, list{"external/cwe/cwe-369"}) {
		t.Errorf("tags %v; want the CWE", tags)
	}
}

func TestOneToolsDocumentsAreOneRun(t *testing.T) {
	a, err := os.ReadFile(filepath.Join("..", "sarif", "testdata", "clang18-a.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join("..", "sarif", "testdata", "clang18-b.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	run, _ := built(t, Options{Root: "/home/builder/sonic", Work: "/home/builder/sonic"},
		Input{Name: "a.sarif", Data: a}, Input{Name: "b.sarif", Data: b})
	if n := len(objects(run, "results")); n != 5 {
		t.Errorf("%d results; want both documents' five", n)
	}
	seen := map[string]int{}
	for _, rule := range objects(child(child(run, "tool"), "driver"), "rules") {
		seen[str(rule, "id")]++
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("rule %s listed %d times", id, n)
		}
	}
	if _, ok := run["artifacts"]; ok {
		t.Error("the artifact list was forwarded")
	}
	for _, res := range objects(run, "results") {
		if _, ok := res["ruleIndex"]; ok {
			t.Error("a result cites its rule by a position the merge moved")
		}
		eachLocation(res, func(loc obj) {
			art := child(child(loc, "physicalLocation"), "artifactLocation")
			if uri := str(art, "uri"); strings.Contains(uri, "/home/builder") || str(art, "uriBaseId") != rootBase {
				t.Errorf("location %v; want a path in the checkout", art)
			}
		})
	}
}

func TestUnitsThatFoundNothingAreARunThatRan(t *testing.T) {
	empty := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"clang"}},"results":[]}]}`
	root := sources(t)
	run, _ := built(t, Options{Root: root, Work: root},
		Input{Name: "a.sarif", Data: []byte(empty)}, Input{Name: "b.sarif", Data: []byte(empty)})
	if got, ok := run["results"].(list); !ok || len(got) != 0 {
		t.Errorf("results %#v; want an empty list, which is a tool that ran", run["results"])
	}
}

func TestTheOutputOfTwoToolsIsARunOfEachUnderItsOwnSeries(t *testing.T) {
	root := sources(t)
	runs, _, err := build(t.Context(), fakeGit(sourceFiles, "c"),
		Options{Root: root, Work: root, SeriesOf: map[string]string{"clang": "clang-sa/default", "cppcheck": "cppcheck/all"}},
		[]Input{fixture(t, "clang18-a.plist"), fixture(t, "cppcheck222.xml")})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range runs {
		var doc struct {
			Runs []struct {
				Tool struct {
					Driver struct{ Name string } `json:"driver"`
				} `json:"tool"`
				Properties map[string]any `json:"properties"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(r.Doc, &doc); err != nil {
			t.Fatal(err)
		}
		if len(doc.Runs) != 1 || !strings.EqualFold(doc.Runs[0].Tool.Driver.Name, r.Tool) {
			t.Errorf("%s's document holds %+v; want its one run", r.Tool, doc.Runs)
			continue
		}
		got[r.Tool], _ = doc.Runs[0].Properties["openpsirt/series"].(string)
	}
	if got["clang"] != "clang-sa/default" || got["cppcheck"] != "cppcheck/all" || len(got) != 2 {
		t.Errorf("series %v; want each tool's own", got)
	}
}

func TestTheOutputOfTwoToolsNeedsASeriesForEach(t *testing.T) {
	root := sources(t)
	zero := 0
	for name, opts := range map[string]Options{
		"one for both":   {Root: root, Work: root, Series: "s"},
		"one named":      {Root: root, Work: root, SeriesOf: map[string]string{"clang": "s"}},
		"a tool version": {Root: root, Work: root, ToolVersion: "18", SeriesOf: map[string]string{"clang": "a", "cppcheck": "b"}},
		"an exit status": {Root: root, Work: root, ExitStatus: &zero, SeriesOf: map[string]string{"clang": "a", "cppcheck": "b"}},
		"units analyzed": {Root: root, Work: root, UnitsAnalyzed: &zero, SeriesOf: map[string]string{"clang": "a", "cppcheck": "b"}},
	} {
		_, _, err := build(t.Context(), fakeGit(sourceFiles, "c"), opts,
			[]Input{fixture(t, "clang18-a.plist"), fixture(t, "cppcheck222.xml")})
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, err := build(t.Context(), fakeGit(sourceFiles, "c"), Options{Root: root, Work: root, Series: "s"},
		[]Input{fixture(t, "clang18-a.plist"), fixture(t, "cppcheck222.xml")}); err == nil ||
		!strings.Contains(err.Error(), "--series clang=NAME --series cppcheck=NAME") {
		t.Errorf("err %v; want the flags to use named", err)
	}
}

func TestUnitsExpectedOfAToolCountingNoneAreReportedUnsent(t *testing.T) {
	root := sources(t)
	ten := 10
	for in, want := range map[string]string{"cppcheck222.xml": "Cppcheck", "clang18-a.plist": ""} {
		runs, report, err := build(t.Context(), fakeGit(sourceFiles, "c"),
			Options{Root: root, Work: root, Series: "s", UnitsExpected: &ten}, []Input{fixture(t, in)})
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(report.Uncounted, ","); got != want {
			t.Errorf("%s: uncounted %q; want %q", in, got, want)
		}
		if sent := bytes.Contains(runs[0].Doc, []byte(propUnitsExpected)); sent != (want == "") {
			t.Errorf("%s: units expected sent %v", in, sent)
		}
	}
}

func TestAnHTMLReportIsRefused(t *testing.T) {
	root := sources(t)
	for _, in := range []Input{
		{Name: "report-1a2b.html", Data: []byte("<html></html>")},
		{Name: "a.plist", Data: []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>diagnostics</key><array/>` +
			`<key>HTMLDiagnostics_files</key><array><string>report-1.html</string></array></dict></plist>`)},
	} {
		_, _, err := build(t.Context(), fakeGit(sourceFiles, "c"), Options{Root: root, Work: root, Series: "s"}, []Input{in})
		if err == nil || !strings.Contains(err.Error(), "HTML") {
			t.Errorf("%s: err %v; want HTML refused", in.Name, err)
		}
	}
}

// carrying is a SARIF document whose one result carries every kind of
// source text a document can.
const carrying = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL","rules":[
 {"id":"cpp/x","fullDescription":{"text":"x","markdown":"` + "`x`" + `"}}]}},
 "artifacts":[{"location":{"uri":"a.c"},"contents":{"text":"int main(void) { return 0; }"}}],
 "results":[{"ruleIndex":0,"message":{"markdown":"**leaks** buf"},
  "locations":[{"physicalLocation":{"artifactLocation":{"index":0},
   "region":{"startLine":7,"startColumn":9,"endLine":7,"endColumn":2,"snippet":{"text":"return 1;"}},
   "contextRegion":{"startLine":6,"endLine":8,"snippet":{"text":"if (n > 10) {"}}}}],
  "stacks":[{"frames":[{"location":{"physicalLocation":{"artifactLocation":{"uri":"a.c"},
   "region":{"startLine":3,"snippet":{"text":"frame text"}}}}}]}],
  "attachments":[{"artifactLocation":{"uri":"a.c"},"regions":[{"startLine":1,"snippet":{"text":"attached text"}}]}],
  "partialFingerprints":{"primaryLocationLineHash":"abc:1"},
  "fixes":[{"description":{"text":"free it"}}]}],
 "threadFlowLocations":[{"location":{"physicalLocation":{"artifactLocation":{"uri":"a.c"},
  "region":{"startLine":4,"snippet":{"text":"flow text"}}}}}],
 "invocations":[{"executionSuccessful":true,"toolExecutionNotifications":[{"message":{"text":"n"},
  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":5,"snippet":{"text":"notified text"}}}}]}]}]}]}`

func TestNoSourceLeavesWithoutSnippets(t *testing.T) {
	root := sources(t)
	run, report := built(t, Options{Root: root, Work: root}, Input{Name: "codeql.sarif", Data: []byte(carrying)})
	said, err := json.Marshal(run)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"return 0;", "return 1;", "if (n > 10)", "free it", "markdown", "`x`",
		"frame text", "attached text", "flow text", "notified text"} {
		if bytes.Contains(said, []byte(text)) {
			t.Errorf("the run carries %q: %s", text, said)
		}
	}
	want := map[string]int{"contents": 1, "fixes": 1, "snippets": 5, "markdown": 2, "attachments": 1}
	if !reflect.DeepEqual(report.Removed, want) {
		t.Errorf("removed %v; want %v", report.Removed, want)
	}
	res := objects(run, "results")[0]
	if id := str(res, "ruleId"); id != "cpp/x" {
		t.Errorf("rule %q; want the one its position named", id)
	}
	if text := str(child(res, "message"), "text"); text != "**leaks** buf" {
		t.Errorf("message %q; want the markdown kept as its text", text)
	}
	region := child(child(objects(res, "locations")[0], "physicalLocation"), "region")
	if _, ok := region["endColumn"]; ok {
		t.Errorf("region %v; want an end before the start left out", region)
	}
}

func TestSnippetsAreTheCheckoutsLines(t *testing.T) {
	root := sources(t)
	run, report := built(t, Options{Root: root, Work: root, Snippets: true}, Input{Name: "codeql.sarif", Data: []byte(carrying)})
	physical := child(objects(objects(run, "results")[0], "locations")[0], "physicalLocation")
	if got := str(child(child(physical, "region"), "snippet"), "text"); got != "        return 1;" {
		t.Errorf("snippet %q; want line 7 of a.c", got)
	}
	context := child(physical, "contextRegion")
	want := "    char *buf = malloc(n);\n    if (n > 10) {\n        return 1;\n    }\n    free(buf);"
	if got := str(child(context, "snippet"), "text"); got != want {
		t.Errorf("context %q; want lines 5 to 9", got)
	}
	if from, _ := num(context, "startLine"); from != 5 {
		t.Errorf("context from line %d; want 5", from)
	}
	if report.Snippets != 2 {
		t.Errorf("%d snippets; want the result's location and its stack frame", report.Snippets)
	}
}

func TestTheRunSaysWhatItIs(t *testing.T) {
	root := sources(t)
	exit := 0
	when := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
	run, _ := built(t, Options{Root: root, Work: root, Built: when, ExitStatus: &exit, Client: "openpsirt-analysis 1.2.3"},
		fixture(t, "clang18-a.plist"))
	if id := str(child(run, "automationDetails"), "id"); id != "clang-sa/default/2026-10-01T02:00:00Z" {
		t.Errorf("automation %q", id)
	}
	props := child(run, "properties")
	if str(props, propCommit) != "0123abcd" || str(props, propClient) != "openpsirt-analysis 1.2.3" {
		t.Errorf("properties %v", props)
	}
	inv := objects(run, "invocations")
	if len(inv) != 1 || inv[0]["executionSuccessful"] != true {
		t.Errorf("invocations %v", inv)
	}
	if _, ok := props[propSalt]; ok {
		t.Error("an unsalted run names a salt")
	}
}

func TestADateLessRunNamesItsSeriesInItsProperties(t *testing.T) {
	root := sources(t)
	run, _ := built(t, Options{Root: root, Work: root}, fixture(t, "clang18-a.plist"))
	if _, ok := run["automationDetails"]; ok {
		t.Error("a run with no build time states an automation identifier")
	}
	if s := str(child(run, "properties"), propSeries); s != "clang-sa/default" {
		t.Errorf("series %q", s)
	}
}

func TestASaltKeysTheFingerprintAndRemovesTheToolsOwn(t *testing.T) {
	root := sources(t)
	plain, _ := built(t, Options{Root: root, Work: root}, fixture(t, "clang18-a.plist"))
	salted, _ := built(t, Options{Root: root, Work: root, Salt: []byte("pipeline secret")}, fixture(t, "clang18-a.plist"))
	p := child(resultAt(t, plain, "unix.Malloc", "a.c", 7), "partialFingerprints")
	s := child(resultAt(t, salted, "unix.Malloc", "a.c", 7), "partialFingerprints")
	if str(p, schemeContext) == "" || str(s, schemeContext) == "" || str(p, schemeContext) == str(s, schemeContext) {
		t.Errorf("fingerprints %v and %v; want the salt to change the client's", p, s)
	}
	if _, ok := s[schemeClang]; ok || len(s) != 1 {
		t.Errorf("salted fingerprints %v; want the client's alone", s)
	}
	// The first eight bytes of SHA-256 over "pipeline secret".
	if got := str(child(salted, "properties"), propSalt); got != "86ecf09cedb47c2b" {
		t.Errorf("salt named %q", got)
	}
}
