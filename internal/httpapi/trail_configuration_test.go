// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/csv"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// A change the deployment's configuration made reads as configuration's, with
// no person named, on the screen and in the export.
func TestAChangeConfigurationMadeReadsAsConfigurations(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		if _, err := trail.NameAdministrators(t.Context(), r.db.DB, []string{"operator"}); err != nil {
			t.Fatal(err)
		}

		var out struct {
			Items []struct {
				Actor  string `json:"actor"`
				By     string `json:"by"`
				About  string `json:"about"`
				Became string `json:"became"`
			} `json:"items"`
		}
		read(t, r, "admin", "/v1/administration/changes?kind=account&limit=1", &out)
		if len(out.Items) != 1 {
			t.Fatalf("naming an administrator in configuration left %d rows", len(out.Items))
		}
		if row := out.Items[0]; row.Actor != "configuration" || row.By != "" ||
			row.About != "operator" || row.Became != trail.NamedInConfiguration {
			t.Errorf("naming an administrator in configuration reads as %+v", row)
		}

		got := asPerson(t, r, "admin", http.MethodGet, "/v1/administration/changes.csv?kind=account", "")
		if got.Code != http.StatusOK {
			t.Fatalf("exporting answered %d: %s", got.Code, got.Body.String())
		}
		// The lines saying what the export is and when it was taken come first,
		// each marked as a comment.
		reader := csv.NewReader(strings.NewReader(got.Body.String()))
		reader.Comment = '#'
		rows, err := reader.ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		actor, by := -1, -1
		for i, name := range rows[0] {
			switch name {
			case "actor":
				actor = i
			case "by":
				by = i
			}
		}
		if actor < 0 || len(rows) != 2 {
			t.Fatalf("the export reads %v", rows)
		}
		if rows[1][actor] != "configuration" || rows[1][by] != "" {
			t.Errorf("the export names %q as the actor and %q as the person", rows[1][actor], rows[1][by])
		}
	})
}
