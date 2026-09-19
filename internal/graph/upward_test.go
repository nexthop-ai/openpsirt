package graph_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// The tree seen upward, for somebody narrowed to their own work.
//
// The three things it must not do, each watched failing: ask for a reading on
// the product, count what the build holds rather than what they hold, and hand
// over an undisclosed row to somebody who may not read one.
func TestTheTreeSeenUpwardIsOnlyTheirOwnWork(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		// The product depends on curl and openssl; curl on openssl too, and
		// openssl on zlib. Work is handed to one person on zlib and on curl,
		// and nowhere else — so the tree they see is two chains and the
		// counts on the shared nodes are theirs rather than the build's.
		snap := tree()
		snap.Components = append(snap.Components, zlib)
		snap.Dependencies = append(snap.Dependencies,
			graph.Dependency{Parent: openssl, Child: zlib})
		if _, err := f.store.Apply(t.Context(), f.targetID, f.scan(t), snap); err != nil {
			t.Fatal(err)
		}
		findings := finding.NewStore(f.store.DB())
		run, err := findings.Begin(t.Context(), finding.Run{
			TargetID: f.targetID, Scanner: "grype", ScannerVersion: "0.100.0",
			DatabaseVersion: "2026-08-28", RanHere: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		reported := func(id string, component graph.Described) finding.Reported {
			return finding.Reported{
				Issue:     finding.Named{Identifier: id, Severity: "high"},
				Component: component, FixState: finding.FixedUpstream, FixedIn: "2.0",
			}
		}
		if _, err := findings.Apply(t.Context(), f.targetID, run.ID, []finding.Reported{
			reported("CVE-2026-1", zlib), reported("CVE-2026-2", zlib),
			reported("CVE-2026-3", curl), reported("CVE-2026-4", openssl),
		}); err != nil {
			t.Fatal(err)
		}

		// party is who hands the work out, and who holds it. The
		// holder reads nothing on the product at all, which is the
		// whole case: what gives their account content is what they
		// were handed.
		const party = 77
		boss := access.NewPerson(1, "boss", false,
			map[int64][]access.Role{*f.scope.ProductID: {access.PrivateTriage, access.Assigner}}, 1)
		holder := access.NewPerson(2, "holder", false, nil, party)
		to := int64(party)
		for _, each := range []struct {
			issue     string
			component graph.Described
		}{{"CVE-2026-1", zlib}, {"CVE-2026-2", zlib}, {"CVE-2026-3", curl}} {
			issue := issueID(t, f, each.issue)
			component, err := f.store.ComponentAt(t.Context(), f.targetID, each.component.Name)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := findings.Assign(t.Context(), boss, f.targetID,
				issue, component, &to); err != nil {
				t.Fatal(err)
			}
		}

		rows, complete, err := f.store.Ours(t.Context(), holder, f.targetID)
		if err != nil {
			t.Fatalf("somebody who holds work but reads nothing was refused the tree: %v", err)
		}
		if !complete {
			t.Error("three components read as more than the tree assembles")
		}
		// Parents before children, and every node on a chain to something of
		// theirs. openssl is on it because zlib sits under it — not because
		// they hold anything there.
		beneath := map[string]int{}
		own := map[string]int{}
		depth := map[string]int{}
		for _, row := range rows {
			beneath[row.Component] = row.Beneath
			own[row.Component] = row.Findings
			depth[row.Component] = row.Depth
		}
		if len(rows) != 4 {
			t.Fatalf("the tree drew %d nodes, wanted sonic, curl, openssl and zlib: %+v",
				len(rows), rows)
		}
		if depth["sonic"] != 0 || depth["curl"] != 1 || depth["openssl"] != 1 ||
			depth["zlib"] != 2 {
			t.Errorf("drawn at depths %v", depth)
		}
		// The counts are theirs. The build has four issues under its root and
		// they hold three; openssl carries one of the build's own and none of
		// theirs, and reads zero on itself with two beneath it.
		if beneath["sonic"] != 3 {
			t.Errorf("the root reads %d beneath, wanted the three they hold", beneath["sonic"])
		}
		if own["openssl"] != 0 || beneath["openssl"] != 2 {
			t.Errorf("openssl reads %d on itself and %d beneath, wanted 0 and 2",
				own["openssl"], beneath["openssl"])
		}
		if own["zlib"] != 2 || own["curl"] != 1 {
			t.Errorf("zlib reads %d and curl %d, wanted 2 and 1", own["zlib"], own["curl"])
		}

		// Somebody who holds nothing here gets nothing, which is not a
		// refusal: there is no work of theirs to hang a tree from.
		nobody := access.NewPerson(3, "nobody", false, nil, 78)
		empty, _, err := f.store.Ours(t.Context(), nobody, f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		if len(empty) != 0 {
			t.Errorf("somebody who holds nothing was drawn %d nodes", len(empty))
		}
	})
}

// An undisclosed row handed to somebody who may not read one does not reach
// them through this door either.
//
// Assigning refuses that pairing, so the row is written first and the grant
// taken away after — which is what a role being revoked looks like, and the
// tree has to answer for it rather than assume it cannot happen.
func TestUndisclosedWorkStaysOutOfTheTreeSeenUpward(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		snap := tree()
		snap.Components = append(snap.Components, zlib)
		snap.Dependencies = append(snap.Dependencies,
			graph.Dependency{Parent: openssl, Child: zlib})
		if _, err := f.store.Apply(t.Context(), f.targetID, f.scan(t), snap); err != nil {
			t.Fatal(err)
		}
		findings := finding.NewStore(f.store.DB())
		run, err := findings.Begin(t.Context(), finding.Run{
			TargetID: f.targetID, Scanner: "grype", ScannerVersion: "0.100.0",
			DatabaseVersion: "2026-08-28", RanHere: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := findings.Apply(t.Context(), f.targetID, run.ID, []finding.Reported{
			{Issue: finding.Named{Identifier: "CVE-2026-9", Severity: "high"}, Component: zlib},
		}); err != nil {
			t.Fatal(err)
		}
		const party = 79
		boss := access.NewPerson(1, "boss", false,
			map[int64][]access.Role{*f.scope.ProductID: {access.PrivateTriage, access.Assigner}}, 1)
		issue := issueID(t, f, "CVE-2026-9")
		component, err := f.store.ComponentAt(t.Context(), f.targetID, zlib.Name)
		if err != nil {
			t.Fatal(err)
		}
		to := int64(party)
		if _, _, err := findings.Assign(t.Context(), boss, f.targetID,
			issue, component, &to); err != nil {
			t.Fatal(err)
		}
		// Withheld after the fact, which is what a role being revoked looks
		// like: assigning refuses the pairing, so the only way to reach this
		// state is for it to change afterwards, and the tree has to answer
		// for it rather than assume it cannot happen.
		if _, err := f.store.DB().NewUpdate().
			Table("finding").
			Set("visibility = ?", access.Private).
			Where("target_id = ?", f.targetID).
			Where("vulnerability_id = ?", issue).
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		// They hold it, and they may not read undisclosed work here.
		holder := access.NewPerson(2, "holder", false,
			map[int64][]access.Role{*f.scope.ProductID: {access.PublicRead}}, party)
		rows, _, err := f.store.Ours(t.Context(), holder, f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Errorf("an undisclosed row they may not read drew %d nodes: %+v", len(rows), rows)
		}

		// Somebody who may read it sees it, so the emptiness above is the
		// visibility clause rather than the tree being broken.
		reader := access.NewPerson(3, "reader", false,
			map[int64][]access.Role{*f.scope.ProductID: {access.PrivateRead}}, party)
		rows, _, err = f.store.Ours(t.Context(), reader, f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			t.Error("somebody who may read undisclosed work was drawn nothing")
		}
	})
}

// issueID is the identifier a scan filed under, as a number.
func issueID(t *testing.T, f *fixture, identifier string) int64 {
	t.Helper()
	var id int64
	if err := f.store.DB().NewSelect().
		TableExpr("\"vulnerability\" AS \"v\"").Column("v.id").
		Where("v.identifier = ?", identifier).
		Scan(t.Context(), &id); err != nil {
		t.Fatalf("%s: %v", identifier, err)
	}
	return id
}
