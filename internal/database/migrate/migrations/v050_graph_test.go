// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/schema"
	"github.com/uptrace/bun"
)

// Upgraded, a component is identified the way the graph identifies it now, an
// open node holds its component's identifiers and a closed one holds none, and
// a sender is a key or a person rather than a name. Two components v0.4.0
// identifies alike refuse the roll back. Rolled back, each is what v0.4.0
// held.
func identitiesNodesAndSendersComeAcross() upgradeCheck {
	// Two components with v0.4.0's identities, one at an open node and one at
	// a closed one.
	described := []graph.Described{
		{Purl: "pkg:npm/lodash@4.17.22?arch=x", CPE: "cpe:2.3:a:lodash:lodash:4.17.22", Name: "lodash", Version: "4.17.22"},
		{Name: "vendored", Version: "1.0"},
	}
	// What the seed made, which the checks read by identifier: other checks
	// write rows to some of these tables too.
	var (
		person, key, targetID int64
		scans, components     []int64
	)
	return upgradeCheck{
		name: "AV040DatabaseTakesItsIdentitiesNodesAndSendersAcross",
		seed: func(t *testing.T, ctx context.Context, db *database.DB) {
			cat := catalog.NewStore(db.DB)
			product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
			if err != nil {
				t.Fatal(err)
			}
			stream, err := cat.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil)
			if err != nil {
				t.Fatal(err)
			}
			variant, err := cat.DeclareVariant(ctx, product.ID, "broadcom", true)
			if err != nil {
				t.Fatal(err)
			}
			target, err := cat.TargetFor(ctx, stream.ID, variant.ID)
			if err != nil {
				t.Fatal(err)
			}
			targetID = target.ID
			people := access.NewStore(db.DB)
			alice, err := people.Ensure(ctx, "alice", "", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			person = alice.ID
			made, _, err := people.NewKey(ctx, "ci-nightly", access.Scope{ProductID: product.ID})
			if err != nil {
				t.Fatal(err)
			}
			key = made.ID

			// v0.4.0 recorded a sender by name.
			now := time.Now().UTC().Truncate(time.Second)
			scans = nil
			for i, sender := range []string{"alice", "ci-nightly", "nobody-known"} {
				scan, _, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
					TargetID: target.ID, ContentHash: sender, ParserVersion: "test",
					BuiltAt: now.Add(time.Duration(i-5) * time.Hour), Credential: sender,
				})
				if err != nil {
					t.Fatal(err)
				}
				scans = append(scans, scan.ID)
			}
			if _, err := db.DB.NewRaw(`INSERT INTO "scan_refusal" ("target_id", "at", "reason", "credential")
				VALUES (?, ?, ?, ?)`, target.ID, now, "refused", "ci-nightly").Exec(ctx); err != nil {
				t.Fatal(err)
			}

			components = nil
			for _, d := range described {
				old := v040Identity(d)
				if _, err := db.DB.NewRaw(`INSERT INTO "component" ("identity", "purl", "cpe", "name",
					"version", "fold_key", "first_seen_at") VALUES (?, ?, ?, ?, ?, ?, ?)`,
					old, nullable(d.Purl), nullable(d.CPE), d.Name, d.Version, d.FoldKey(), now).
					Exec(ctx); err != nil {
					t.Fatal(err)
				}
				var id int64
				if err := db.DB.NewRaw(`SELECT "id" FROM "component" WHERE "identity" = ?`,
					old).Scan(ctx, &id); err != nil {
					t.Fatal(err)
				}
				components = append(components, id)
			}
			if _, err := db.DB.NewRaw(`INSERT INTO "graph_node" ("target_id", "component_id",
				"is_root", "opened_scan_id") VALUES (?, ?, ?, ?)`,
				target.ID, components[0], false, scans[0]).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB.NewRaw(`INSERT INTO "graph_node" ("target_id", "component_id",
				"is_root", "opened_scan_id", "closed_scan_id") VALUES (?, ?, ?, ?, ?)`,
				target.ID, components[1], false, scans[0], scans[1]).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		},
		upgraded: func(t *testing.T, ctx context.Context, db *database.DB) {
			identities := readWhere(t, ctx, db, "component", []string{"id", "identity"},
				`"id" IN (?)`, bun.List(components))
			if len(identities) != len(described) {
				t.Fatalf("upgraded, %d of the %d components are left", len(identities), len(described))
			}
			for i, row := range identities {
				if want := described[i].Identity(); row["identity"] != want {
					t.Errorf("upgraded, %s is identified as %s, and the graph identifies it as %s",
						described[i].Name, row["identity"], want)
				}
			}
			nodes := readWhere(t, ctx, db, "graph_node", []string{"id", "purl", "cpe"},
				`"component_id" IN (?)`, bun.List(components))
			if len(nodes) != 2 || nodes[0]["purl"] != described[0].Purl || nodes[0]["cpe"] != described[0].CPE {
				t.Errorf("upgraded, the open node holds %v, want its component's identifiers", nodes)
			}
			if len(nodes) == 2 && (nodes[1]["purl"] != "NULL" || nodes[1]["cpe"] != "NULL") {
				t.Errorf("upgraded, the closed node holds %v, want nothing", nodes[1])
			}
			wantSenders := []string{
				"person:" + strconv.FormatInt(person, 10),
				"key:" + strconv.FormatInt(key, 10),
				"nobody-known",
			}
			if got := columnOf(t, db, "scan", "credential", `"id" IN (?)`, bun.List(scans)); !slices.Equal(got, wantSenders) {
				t.Errorf("upgraded, the scans were sent by %v, want %v", got, wantSenders)
			}
			if got := columnOf(t, db, "scan_refusal", "credential", `"target_id" = ?`, targetID); !slices.Equal(got, wantSenders[1:2]) {
				t.Errorf("upgraded, the refusal was sent by %v, want %v", got, wantSenders[1:2])
			}
		},
		// A name shaped like the real package's identifier is its own
		// component here and the real one to v0.4.0, which cannot hold both.
		refused: func(t *testing.T, ctx context.Context, db *database.DB) {
			shaped := graph.Described{Name: "pkg:npm/lodash", Version: "4.17.22"}
			if _, err := db.DB.NewRaw(`INSERT INTO "component" ("identity", "name", "version",
				"fold_key", "first_seen_at") VALUES (?, ?, ?, ?, ?)`,
				shaped.Identity(), shaped.Name, shaped.Version, shaped.FoldKey(),
				time.Now().UTC().Truncate(time.Second)).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			err := schema.Down(ctx, db, quiet())
			if err == nil || !strings.Contains(err.Error(), "one component") ||
				!strings.Contains(err.Error(), "pkg:npm/lodash") {
				t.Errorf("rolled back over two components v0.4.0 identifies alike: %v", err)
			}
			if got := readWhere(t, ctx, db, "component", []string{"id", "identity"},
				`"id" IN (?) OR "identity" = ?`, bun.List(components), shaped.Identity()); len(got) != 3 ||
				got[0]["identity"] != described[0].Identity() {
				t.Errorf("a refused roll back left the components as %v", got)
			}
			if _, err := db.DB.NewRaw(`DELETE FROM "component" WHERE "identity" = ?`,
				shaped.Identity()).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		},
		rolledBack: func(t *testing.T, ctx context.Context, db *database.DB) {
			back := readWhere(t, ctx, db, "component", []string{"id", "identity"},
				`"id" IN (?)`, bun.List(components))
			if len(back) != len(described) {
				t.Fatalf("rolled back, %d of the %d components are left", len(back), len(described))
			}
			for i, row := range back {
				if want := v040Identity(described[i]); row["identity"] != want {
					t.Errorf("rolled back, %s is identified as %s, want v0.4.0's %s",
						described[i].Name, row["identity"], want)
				}
			}
			if got := columnOf(t, db, "scan", "credential", `"id" IN (?)`, bun.List(scans)); !slices.Equal(got,
				[]string{"alice", "ci-nightly", "nobody-known"}) {
				t.Errorf("rolled back, the scans were sent by %v, want the names", got)
			}
		},
	}
}

// v040Identity is a component's identity as v0.4.0 worked it out: the reduced
// package identifier, or the name and version joined by "@", hashed in one
// space. Spelled out per component rather than computed by the migration's
// own copy of the rule.
func v040Identity(d graph.Described) string {
	basis := map[string]string{
		"lodash":   "pkg:npm/lodash@4.17.22",
		"vendored": "vendored@1.0",
	}[d.Name]
	sum := sha256.Sum256([]byte(basis))
	return hex.EncodeToString(sum[:])
}

// columnOf is one column of the rows of a table where holds, in identifier
// order.
func columnOf(t *testing.T, db *database.DB, table, name, where string, args ...any) []string {
	t.Helper()
	var out []string
	for _, row := range readWhere(t, t.Context(), db, table, []string{"id", name}, where, args...) {
		out = append(out, row[name])
	}
	return out
}

// nullable is a value to insert, absent where it is empty.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
