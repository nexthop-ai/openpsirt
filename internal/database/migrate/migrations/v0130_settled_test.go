// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/csaf"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
)

func TestTheV0130UpgradeDigestsAnAdvisoryAsTheApplicationDoes(t *testing.T) {
	// The upgrade carries its own copy of the rule, so a later change to the
	// application's leaves what the upgrade wrote as it was. Held to the
	// application's here, over real advisories and every part the rule
	// reads, the documents it refuses included.
	documents := []string{
		`{"document":{"title":"A flaw","tracking":{"id":"X-1","status":"final","version":"2",` +
			`"current_release_date":"2026-11-12T02:00:00Z","generator":{"engine":{"name":"x"}},` +
			`"revision_history":[{"number":"2"}]},` +
			`"references":[{"category":"self","url":"https://x/1.json"},{"category":"external","url":"https://y"}]},` +
			`"vulnerabilities":[{"cve":"CVE-2026-1","scores":[{"cvss_v3":{"baseScore":7.50}}]}]}`,
		`{"document":{"references":[{"category":"self","url":"https://x/1.json"}]}}`,
		`{"document":{"references":["text",{"category":"external"}],"tracking":"none"}}`,
		`{"document":{"z":1,"a":{"b":2,"a":1e3}}}`,
		`{"document":"text"}`,
		`{"product_tree":{}}`,
		`[]`,
		`not a document`,
		``,
	}
	found, err := filepath.Glob(filepath.Join("..", "..", "..", "sbom", "testdata", "*.csaf.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range found {
		body, err := os.ReadFile(path) //nolint:gosec // G304: this repository's own test data
		if err != nil {
			t.Fatal(err)
		}
		documents = append(documents, string(body))
	}
	if len(found) == 0 {
		t.Fatal("no advisory was found to compare, so this checked less than it says")
	}
	for _, document := range documents {
		want, wantErr := csaf.SettledDigest([]byte(document))
		got, gotErr := migrations.SettledDigestV0130([]byte(document))
		if got != want || (gotErr == nil) != (wantErr == nil) {
			t.Errorf("%.80q: the upgrade digests %q (%v), the application %q (%v)", document, got, gotErr, want, wantErr)
		}
	}
}
