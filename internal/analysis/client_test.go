// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/sarif"
	"github.com/nexthop-ai/openpsirt/internal/uploadclient"
)

// checkout is the reader fixtures' sources as a committed git checkout, with
// origin set to remote.
func checkout(t *testing.T, remote string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	from := filepath.Join("..", "sarif", "testdata", "src")
	for _, f := range []string{"a.c", "b.c", filepath.Join("include", "shared.h")} {
		data, err := os.ReadFile(filepath.Join(from, f)) //nolint:gosec // G304: a path under the test's own directory
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, f)), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), data, 0o600); err != nil { //nolint:gosec // G703: a path under the test's own directory
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"}, {"add", "."},
		{"-c", "user.email=b@example.com", "-c", "user.name=B", "commit", "-q", "-m", "sources"},
		{"remote", "add", "origin", remote},
	} {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...) //nolint:gosec // G204: the test's own arguments
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	return dir
}

// TestWhatTheClientWritesIsWhatTheDeploymentReads sends the client's run of
// two clang units through the reader and the placing a stored run is read
// with, so the two cannot come to disagree about a field.
func TestWhatTheClientWritesIsWhatTheDeploymentReads(t *testing.T) {
	root := checkout(t, "git@github.com:example/sonic.git")
	var inputs []uploadclient.Input
	for _, name := range []string{"clang18-a.plist", "clang18-b.plist"} {
		data, err := os.ReadFile(filepath.Join("..", "uploadclient", "testdata", name)) //nolint:gosec // G304: a path under the test's own directory
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, uploadclient.Input{Name: name, Data: data})
	}
	two, exit := 2, 0
	built := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
	runs, _, err := uploadclient.Build(t.Context(), uploadclient.Options{
		Root: root, Work: root, Series: "clang-sa/default", Built: built,
		UnitsExpected: &two, ExitStatus: &exit, Client: "openpsirt-upload test",
	}, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 {
		t.Fatalf("%d runs; want clang's alone", len(runs))
	}
	log, err := sarif.NewUpload(sarif.DefaultLimits()).Read(bytes.NewReader(runs[0].Doc))
	if err != nil {
		t.Fatalf("the deployment refuses what the client wrote: %v", err)
	}

	stated := Describe([]sarif.Log{log}, Stated{})
	if stated.Series != "clang-sa/default" || !stated.BuiltAt.Equal(built) {
		t.Errorf("series %q built %v", stated.Series, stated.BuiltAt)
	}
	p := stated.Params
	if p.ToolName != "clang" || p.ClientVersion != "openpsirt-upload test" ||
		p.UnitsExpected == nil || *p.UnitsExpected != 2 || p.UnitsAnalyzed == nil || *p.UnitsAnalyzed != 2 ||
		p.ExitStatus == nil || *p.ExitStatus != 0 || p.Completed == nil || !*p.Completed {
		t.Errorf("parameters %+v", p)
	}

	placed, err := Place([]sarif.Log{log}, "", sarif.DefaultLimits().MaxBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := placed.Receipt.Dropped[DroppedOutside]; n != 0 {
		t.Errorf("%d results placed outside the checkout", n)
	}
	// The header's result is reported by both units and kept once.
	if len(placed.Results) != 4 || placed.Receipt.Dropped[DroppedRepeat] != 1 {
		t.Errorf("%d results, %v dropped; want four and the header's repeat", len(placed.Results), placed.Receipt.Dropped)
	}
	if len(placed.Modules) != 1 || placed.Modules[0].Remote != "https://github.com/example/sonic" || placed.Modules[0].Path != "" {
		t.Errorf("repositories %+v; want the checkout's own", placed.Modules)
	}
	var header *sarif.Placed
	for i, res := range placed.Results {
		if res.Path == "include/shared.h" {
			header = &placed.Results[i]
		}
		if res.Fingerprints["openpsirt/context/v1"] == "" || res.Fingerprints["clang/issueHash/v1"] == "" {
			t.Errorf("%s:%d carries %v; want the client's fingerprint and clang's", res.Path, res.StartLine, res.Fingerprints)
		}
	}
	if header == nil {
		t.Fatal("no result in the header")
	}
	if header.Function != "header_div" {
		t.Errorf("function %q", header.Function)
	}
	if got := chain(header.Steps); got != "leak → header_div" {
		t.Errorf("call chain %q; want leak → header_div", got)
	}
	k := key(ruleName(placed.Runs[0].Tool, header.RuleID), *header)
	if k.Scheme != "openpsirt/context/v1" {
		t.Errorf("keyed on %q; want the client's fingerprint", k.Scheme)
	}
}

// everyMemberRead is a SARIF run carrying every member of a rule, a result, a
// location and an invocation that the deployment reads, each with a value
// the reading keeps.
const everyMemberRead = `{"version":"2.1.0","runs":[{
 "tool":{"driver":{"name":"lint","version":"1.2","semanticVersion":"1.2.0","rules":[
  {"id":"R1","name":"NullDeref","helpUri":"https://lint.example.test/R1",
   "shortDescription":{"text":"Short."},"fullDescription":{"text":"Full."},
   "messageStrings":{"default":{"text":"{0} is null here"}},
   "defaultConfiguration":{"level":"error"},
   "properties":{"tags":["security","external/cwe/cwe-476"],"security-severity":"7.5","precision":"high"}}]},
  "extensions":[{"name":"pack","version":"3","rules":[{"id":"E1","name":"Ext","defaultConfiguration":{"level":"note"}}]}]},
 "automationDetails":{"id":"lint/all/"},
 "invocations":[{"exitCode":1,"executionSuccessful":false,
  "toolExecutionNotifications":[{"level":"error","descriptor":{"id":"crash"}}],
  "toolConfigurationNotifications":[{"level":"error","descriptor":{"id":"cfg"}}]}],
 "results":[{"ruleId":"R1","level":"warning","kind":"review","baselineState":"absent",
  "suppressions":[{"status":"accepted"}],
  "message":{"id":"default","arguments":["p"]},
  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},
    "region":{"startLine":2,"startColumn":3,"endLine":2,"endColumn":9},
    "contextRegion":{"startLine":1,"endLine":3}},
   "logicalLocations":[{"fullyQualifiedName":"main","name":"main"}],
   "message":{"text":"here"}}],
  "relatedLocations":[{"physicalLocation":{"artifactLocation":{"uri":"b.c"},"region":{"startLine":1}},
   "message":{"text":"declared"}}],
  "codeFlows":[{"threadFlows":[{"locations":[
   {"location":{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}},
    "logicalLocations":[{"name":"main"}],"message":{"text":"enter"}},"nestingLevel":1}]}]}],
  "partialFingerprints":{"primaryLocationLineHash/v1":"abc"},
  "fingerprints":{"lint/v1":"def"}},
  {"ruleId":"E1","message":{"text":"from the extension"},
   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.c"},"region":{"startLine":1}}}]}]}]}`

// TestEveryMemberTheDeploymentReadsSurvivesTheClient sends a SARIF run
// carrying every member the deployment reads through the client and the
// reader, and reads each rule, result and invocation as it reads the run
// unforwarded. The client's shapes are a second copy of what the reader reads,
// and a member they leave out is stripped from every forwarded run.
func TestEveryMemberTheDeploymentReadsSurvivesTheClient(t *testing.T) {
	root := checkout(t, "git@github.com:example/sonic.git")
	runs, _, err := uploadclient.Build(t.Context(), uploadclient.Options{
		Root: root, Work: root, Series: "lint/all", Built: time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC),
		Client: "openpsirt-upload test",
	}, []uploadclient.Input{{Name: "lint.sarif", Data: []byte(everyMemberRead)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 {
		t.Fatalf("%d runs; want one", len(runs))
	}
	read := func(doc []byte) sarif.Run {
		t.Helper()
		log, err := sarif.NewUpload(sarif.DefaultLimits()).Read(bytes.NewReader(doc))
		if err != nil {
			t.Fatalf("the deployment refuses the run: %v", err)
		}
		return log.Runs[0]
	}
	sent, forwarded := read([]byte(everyMemberRead)), read(runs[0].Doc)

	// The client adds its own fingerprint and the source around each
	// location, and names each file from the checkout's root, so those are
	// left out of the comparison.
	for i := range forwarded.Results {
		res := &forwarded.Results[i]
		for scheme := range res.Fingerprints {
			if _, ok := sent.Results[i].Fingerprints[scheme]; !ok {
				delete(res.Fingerprints, scheme)
			}
		}
	}
	plain := func(r sarif.Run) string {
		for i := range r.Results {
			res := &r.Results[i]
			for _, locs := range [][]sarif.Location{res.Locations, res.Related} {
				for j := range locs {
					locs[j].Snippet, locs[j].SnippetLine, locs[j].Base = "", 0, ""
				}
			}
			for j := range res.Steps {
				res.Steps[j].Snippet, res.Steps[j].SnippetLine, res.Steps[j].Base = "", 0, ""
			}
			if len(res.Fingerprints) == 0 {
				res.Fingerprints = nil
			}
		}
		out, err := json.MarshalIndent(struct {
			Rules       []sarif.Rule
			Results     []sarif.Result
			Invocations []sarif.Invocation
		}{r.Tool.Rules, r.Results, r.Invocations}, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	if want, got := plain(sent), plain(forwarded); got != want {
		t.Errorf("the forwarded run reads as\n%s\nwant\n%s", got, want)
	}
	if forwarded.Tool.Name != "lint" || forwarded.Tool.Version != sent.Tool.Version || forwarded.AutomationID == "" {
		t.Errorf("tool %+v, automation %q", forwarded.Tool, forwarded.AutomationID)
	}
}

// forwarded is a SARIF document of a tool whose driver and an extension both
// define the rule X, at different levels, with the results given.
func forwarded(extensions, results string) []byte {
	return []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"codeql",` +
		`"rules":[{"id":"X","defaultConfiguration":{"level":"note"}}]},"extensions":[` + extensions + `]},` +
		`"results":[` + results + `]}]}`)
}

// forwardedAt is a result at a line of a.c citing its rule as given.
func forwardedAt(line, rule string) string {
	return `{` + rule + `,"message":{"text":"m"},"locations":[{"physicalLocation":` +
		`{"artifactLocation":{"uri":"a.c"},"region":{"startLine":` + line + `}}}]}`
}

func TestAForwardedResultKeepsTheRuleOfTheExtensionItNames(t *testing.T) {
	root := checkout(t, "git@github.com:example/sonic.git")
	pack := `{"name":"pack","rules":[{"id":"X","defaultConfiguration":{"level":"error"}}]}`
	other := `{"name":"other","rules":[{"id":"Y"}]}`
	inputs := []uploadclient.Input{
		{Name: "a.sarif", Data: forwarded(pack,
			forwardedAt("1", `"ruleId":"X","rule":{"id":"X","toolComponent":{"index":0}}`)+","+
				forwardedAt("2", `"ruleId":"X"`))},
		// The second document lists the pack second, so its position moves
		// when the two are merged.
		{Name: "b.sarif", Data: forwarded(other+","+pack,
			forwardedAt("3", `"rule":{"index":0,"toolComponent":{"index":1}}`))},
	}
	exit := 0
	runs, _, err := uploadclient.Build(t.Context(), uploadclient.Options{
		Root: root, Work: root, Series: "codeql/default", Built: time.Now().UTC(),
		ExitStatus: &exit, Client: "openpsirt-upload test",
	}, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 {
		t.Fatalf("%d runs; want the two documents merged", len(runs))
	}
	log, err := sarif.NewUpload(sarif.DefaultLimits()).Read(bytes.NewReader(runs[0].Doc))
	if err != nil {
		t.Fatalf("the deployment refuses what the client wrote: %v", err)
	}
	levels := map[int]string{}
	for _, res := range log.Runs[0].Results {
		if len(res.Locations) > 0 {
			levels[res.Locations[0].StartLine] = res.Level
		}
	}
	for line, want := range map[int]string{1: "error", 2: "note", 3: "error"} {
		if levels[line] != want {
			t.Errorf("the result on line %d is at %q; want %q, its own rule's", line, levels[line], want)
		}
	}
}

func TestTwoExtensionsSharingANameKeepTheirOwnRulesWhenForwarded(t *testing.T) {
	root := checkout(t, "git@github.com:example/sonic.git")
	strict := `{"name":"pack","guid":"11111111-1111-1111-1111-111111111111","rules":[{"id":"X","defaultConfiguration":{"level":"error"}}]}`
	lenient := `{"name":"pack","guid":"22222222-2222-2222-2222-222222222222","rules":[{"id":"X","defaultConfiguration":{"level":"note"}}]}`
	inputs := []uploadclient.Input{
		{Name: "a.sarif", Data: forwarded(strict,
			forwardedAt("1", `"rule":{"id":"X","toolComponent":{"index":0}}`))},
		{Name: "b.sarif", Data: forwarded(lenient,
			forwardedAt("2", `"rule":{"id":"X","toolComponent":{"index":0}}`))},
	}
	exit := 0
	runs, _, err := uploadclient.Build(t.Context(), uploadclient.Options{
		Root: root, Work: root, Series: "codeql/default", Built: time.Now().UTC(),
		ExitStatus: &exit, Client: "openpsirt-upload test",
	}, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 {
		t.Fatalf("%d runs; want the two documents merged", len(runs))
	}
	log, err := sarif.NewUpload(sarif.DefaultLimits()).Read(bytes.NewReader(runs[0].Doc))
	if err != nil {
		t.Fatalf("the deployment refuses what the client wrote: %v", err)
	}
	levels := map[int]string{}
	for _, res := range log.Runs[0].Results {
		if len(res.Locations) > 0 {
			levels[res.Locations[0].StartLine] = res.Level
		}
	}
	for line, want := range map[int]string{1: "error", 2: "note"} {
		if levels[line] != want {
			t.Errorf("the result on line %d is at %q; want %q, its own extension's", line, levels[line], want)
		}
	}
}
