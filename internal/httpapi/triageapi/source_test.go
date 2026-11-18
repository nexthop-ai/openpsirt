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
		if reader.Code != http.StatusForbidden && reader.Code != http.StatusNotFound {
			t.Errorf("a reader proposing answered %d: %s", reader.Code, reader.Body.String())
		}
	})
}
