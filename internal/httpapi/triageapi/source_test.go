// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// linuxPerf is a binary package built from a slice of the kernel's source.
var linuxPerf = graph.Described{
	Purl: "pkg:deb/debian/linux-perf@6.12.57-1", Name: "linux-perf", Version: "6.12.57-1",
}

// scannedThroughLinux is a build holding linux-perf with two issues matched
// through the kernel's source: one in a driver, one in perf itself.
func scannedThroughLinux(t *testing.T, r *httpapitest.Reach) {
	t.Helper()
	r.Scan(t, "through-linux",
		graph.Snapshot{
			Root:         httpapitest.SeededRoot,
			Components:   []graph.Described{linuxPerf},
			Dependencies: []graph.Dependency{{Parent: httpapitest.SeededRoot, Child: linuxPerf}},
		},
		[]finding.Reported{{
			Issue:     finding.Named{Identifier: "CVE-2024-26600", Severity: "high"},
			Component: linuxPerf, MatchedThrough: "linux",
			RecordRead: true, RecordFiles: []string{"drivers/phy/ti/phy-omap-usb2.c"},
		}, {
			Issue:     finding.Named{Identifier: "CVE-2026-9001", Severity: "high"},
			Component: linuxPerf, MatchedThrough: "linux",
			RecordRead: true, RecordFiles: []string{"tools/perf/util/evsel.c"},
		}})
}

// A correction by source paths is proposed against a product, answers the
// issue whose files lie outside the paths and not the one inside them, and
// reads back with what it names and the files that justified each answer.
// The finding says what it was matched through and which files its record
// lists, which is what the form is filled from.
func TestACorrectionBySourcePathsIsProposedAndReadBack(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		scannedThroughLinux(t, r)

		var evidence struct {
			MatchedThrough string   `json:"matched_through"`
			RecordFiles    []string `json:"record_files"`
		}
		httpapitest.Read(t, r, "triager", "/v1/products/mine/branches-and-tags/master/variants/broadcom"+
			"/findings/CVE-2024-26600/components/linux-perf", &evidence)
		if evidence.MatchedThrough != "linux" ||
			!slices.Equal(evidence.RecordFiles, []string{"drivers/phy/ti/phy-omap-usb2.c"}) {
			t.Errorf("the finding reads as matched through %q in %v", evidence.MatchedThrough, evidence.RecordFiles)
		}

		got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, "/v1/products/mine/source-corrections",
			`{"package":"Linux-Perf","source":"linux","paths":["tools/perf","/tools/lib/"],`+
				`"justification":"vulnerable_code_not_present",`+
				`"reasoning":"linux-perf is built from tools/ alone."}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("proposing answered %d: %s", got.Code, got.Body.String())
		}
		var made struct {
			DecisionID int64 `json:"decision_id"`
			Answered   int   `json:"answered"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &made); err != nil {
			t.Fatal(err)
		}
		if made.Answered != 1 {
			t.Errorf("the correction answers %d occurrences, want the driver's one", made.Answered)
		}

		var detail struct {
			Source *struct {
				Package string   `json:"package"`
				Source  string   `json:"source"`
				Paths   []string `json:"paths"`
			} `json:"source"`
		}
		httpapitest.Read(t, r, "triager", fmt.Sprintf("/v1/decisions/%d", made.DecisionID), &detail)
		if detail.Source == nil || detail.Source.Package != "linux-perf" || detail.Source.Source != "linux" ||
			!slices.Equal(detail.Source.Paths, []string{"tools/lib", "tools/perf"}) {
			t.Errorf("the decision reads back naming %+v", detail.Source)
		}

		// Its proposer's own list names the rule beside the one issue it is
		// stored against.
		var mine struct {
			Items []struct {
				Decision struct {
					ID int64 `json:"id"`
				} `json:"decision"`
				Source *struct {
					Package string   `json:"package"`
					Paths   []string `json:"paths"`
				} `json:"source"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "triager", "/v1/my-decisions", &mine)
		if len(mine.Items) != 1 || mine.Items[0].Decision.ID != made.DecisionID || mine.Items[0].Source == nil ||
			mine.Items[0].Source.Package != "linux-perf" ||
			!slices.Equal(mine.Items[0].Source.Paths, []string{"tools/lib", "tools/perf"}) {
			t.Errorf("the proposer's own decisions read as %+v", mine.Items)
		}

		var rows struct {
			Items []struct {
				Occurrence struct {
					Vulnerability string `json:"vulnerability"`
				} `json:"occurrence"`
				AnsweredOn []string `json:"answered_on"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "triager", "/v1/decision-occurrences?product=mine", &rows)
		if len(rows.Items) != 1 || rows.Items[0].Occurrence.Vulnerability != "CVE-2024-26600" ||
			!slices.Equal(rows.Items[0].AnsweredOn, []string{"drivers/phy/ti/phy-omap-usb2.c"}) {
			t.Errorf("the decision's occurrences read as %+v", rows.Items)
		}

		// The build's VEX document says nothing of it until a second person
		// agrees, then says not affected, with the reason, as of any wrong match.
		const vexAt = "/v1/products/mine/branches-and-tags/master/variants/broadcom/vex"
		type statement struct {
			Vulnerability struct {
				Name string `json:"name"`
			} `json:"vulnerability"`
			Status          string `json:"status"`
			Justification   string `json:"justification"`
			ImpactStatement string `json:"impact_statement"`
		}
		var waiting struct {
			Statements []statement `json:"statements"`
		}
		httpapitest.Read(t, r, "triager", vexAt, &waiting)
		if len(waiting.Statements) != 0 {
			t.Errorf("a correction nobody agreed to publishes %+v", waiting.Statements)
		}
		r.Agreed(t, made.DecisionID)
		var agreed struct {
			Statements []statement `json:"statements"`
		}
		httpapitest.Read(t, r, "triager", vexAt, &agreed)
		if len(agreed.Statements) != 1 || agreed.Statements[0].Vulnerability.Name != "CVE-2024-26600" ||
			agreed.Statements[0].Status != "not_affected" ||
			agreed.Statements[0].Justification != "vulnerable_code_not_present" ||
			agreed.Statements[0].ImpactStatement != "" {
			t.Errorf("the agreed correction publishes %+v, want the driver issue not affected", agreed.Statements)
		}

		// A later record naming a file in perf withdraws the answer, and the
		// row says so beside the files it was answered on.
		if _, err := r.DB.DB.NewUpdate().Table("vulnerability").
			Set(`"program_files" = ?`, "drivers/phy/ti/phy-omap-usb2.c\ntools/perf/util/evsel.c").
			Where(`"identifier" = ?`, "CVE-2024-26600").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		var buildID int64
		if err := r.DB.DB.NewSelect().Table("finding").Column("build_id").Limit(1).
			Scan(t.Context(), &buildID); err != nil {
			t.Fatal(err)
		}
		if _, err := triage.NewStore(r.DB.DB).AnswerBySource(t.Context(), buildID); err != nil {
			t.Fatal(err)
		}
		var recanted struct {
			Items []struct {
				AnsweredOn []string `json:"answered_on"`
				Recanted   bool     `json:"recanted"`
				RecantedOn []string `json:"recanted_on"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "triager", "/v1/decision-occurrences?product=mine", &recanted)
		if len(recanted.Items) != 1 || !recanted.Items[0].Recanted ||
			!slices.Equal(recanted.Items[0].AnsweredOn, []string{"drivers/phy/ti/phy-omap-usb2.c"}) ||
			!slices.Equal(recanted.Items[0].RecantedOn, []string{"drivers/phy/ti/phy-omap-usb2.c", "tools/perf/util/evsel.c"}) {
			t.Errorf("the withdrawn answer reads as %+v", recanted.Items)
		}

		// Naming the paths of the whole source answers nothing, and says so.
		none := httpapitest.AsPerson(t, r, "triager", http.MethodPost, "/v1/products/mine/source-corrections",
			`{"package":"linux-perf","source":"linux","paths":["drivers","tools"],`+
				`"justification":"vulnerable_code_not_present","reasoning":"Built from tools/."}`)
		if none.Code != http.StatusUnprocessableEntity || !strings.Contains(none.Body.String(), "name fewer paths") {
			t.Errorf("a correction answering nothing answered %d: %s", none.Code, none.Body.String())
		}

		// A reason about reachability is no correction.
		reach := httpapitest.AsPerson(t, r, "triager", http.MethodPost, "/v1/products/mine/source-corrections",
			`{"package":"linux-perf","source":"linux","paths":["tools/perf"],`+
				`"justification":"vulnerable_code_not_in_execute_path","reasoning":"Never reached."}`)
		if reach.Code != http.StatusUnprocessableEntity {
			t.Errorf("a reason about reachability answered %d: %s", reach.Code, reach.Body.String())
		}

		// Somebody who may only read is turned away.
		reader := httpapitest.AsPerson(t, r, "reader", http.MethodPost, "/v1/products/mine/source-corrections",
			`{"package":"linux-perf","source":"linux","paths":["tools/perf"],`+
				`"justification":"vulnerable_code_not_present","reasoning":"Built from tools/."}`)
		if reader.Code != http.StatusForbidden {
			t.Errorf("a reader proposing answered %d: %s", reader.Code, reader.Body.String())
		}
	})
}
