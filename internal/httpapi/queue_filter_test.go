// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"net/http"
	"strings"
	"testing"
)

func TestTheReviewQueueTakesItsFiltersFromTheAddress(t *testing.T) {
	// The queue and its file are narrowed by the same parameters, and a
	// proposer nobody holds leaves the queue empty rather than being ignored:
	// an unknown name that answered with the whole queue would read as a
	// filter that worked.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		if got := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom/components/linux-image/decisions",
			`{"vulnerabilities":["CVE-2026-9999","CVE-2026-1000"],"outcome":"wont-fix",`+
				`"selected_by":"the drivers","reasoning":"Not built for this image."}`); got.Code !=
			http.StatusCreated {
			t.Fatalf("the claim answered %d: %s", got.Code, got.Body.String())
		}

		for _, each := range []struct {
			query string
			want  int
		}{
			{"", 1},
			{"?proposed_by=triager", 1},
			{"?proposed_by=TRIAGER", 1},
			{"?proposed_by=nobody-at-all", 0},
			{"?outcome=wont-fix", 1},
			{"?outcome=not-applicable", 0},
			{"?severity=high", 1},
			{"?severity=critical", 0},
			{"?older_than=3", 0},
			{"?release=master", 1},
			{"?release=elsewhere", 0},
		} {
			var queue struct {
				Total int `json:"total"`
			}
			read(t, r, "assigner", "/v1/review-queue"+each.query, &queue)
			if queue.Total != each.want {
				t.Errorf("the queue under %q holds %d, want %d", each.query, queue.Total, each.want)
			}
		}

		for query, want := range map[string]int{"?outcome=not-applicable": 0, "?outcome=wont-fix": 1} {
			file := asPerson(t, r, "assigner", http.MethodGet, "/v1/review-queue.csv"+query, "")
			if file.Code != http.StatusOK {
				t.Fatalf("the export answered %d", file.Code)
			}
			rows := -1 // the header
			for _, line := range strings.Split(strings.TrimSpace(file.Body.String()), "\n") {
				if !strings.HasPrefix(line, "#") {
					rows++
				}
			}
			if rows != want {
				t.Errorf("the export under %q has %d rows, want %d", query, rows, want)
			}
		}
	})
}
