// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// What a scan's application reports is what was applied, when the commit of a
// first attempt is refused and the whole of it runs again. A count carried over
// from the attempt that rolled back doubles, and the doubled number of
// unexplained closures is what raises the warning that findings disappeared.
func TestAScanAppliedAgainAfterALostCommitCountsOnce(t *testing.T) {
	db, race := dbtest.Racing(t, nil)
	ctx := t.Context()
	w := world.New(t, db)
	product, target := w.Product, w.Target
	f := &fixture{
		db: db, store: finding.NewStore(db.DB), graph: graph.NewStore(db.DB),
		target: target.ID, productID: product.ID, scans: ingest.NewStore(db.DB),
		built: time.Now().UTC().Add(-72 * time.Hour),
	}
	f.shipped(t, twoConsumers())
	if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
		found("CVE-2026-1", libnl),
	}); err != nil {
		t.Fatal(err)
	}

	// Reported by nothing, so every place closes with no reason given.
	quiet := f.run(t)
	race.Arm(1)
	applied, err := f.store.Apply(ctx, f.target, quiet, nil)
	if err != nil {
		t.Fatal(err)
	}
	if race.Unspent() != 0 {
		t.Fatal("the application committed nothing, so no attempt was retried and this checks nothing")
	}
	if applied.Closed != 2 || applied.Unexplained != 2 {
		t.Errorf("closed %d, %d of them unexplained; want the 2 places, counted once", applied.Closed, applied.Unexplained)
	}
}

// A document recorded again after a lost commit records what it says, and
// sets aside nothing it repeats. An attempt that narrowed the caller's claims
// to the ones it had left to insert handed the next attempt those alone, and
// every claim the document repeated read as withdrawn.
func TestAStatementSetRecordedAgainAfterALostCommitKeepsWhatItRepeats(t *testing.T) {
	db, race := dbtest.Racing(t, nil)
	ctx := t.Context()
	w := world.New(t, db)
	store := finding.NewStore(db.DB)
	who := access.Everything("a test recording statements")
	who.ID = w.Person.ID
	claim := func(i int) finding.Statement {
		return finding.Statement{
			Vulnerability: fmt.Sprintf("CVE-2026-%d", 100+i), Component: "libnl-3-200",
			Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path",
			Statement: "Never reached in our build.",
		}
	}
	var standing []finding.Statement
	for i := range 10 {
		standing = append(standing, claim(i))
	}
	from := finding.Supplied{Source: finding.FromVex, Publisher: "debian", Document: "set.json"}
	from.Digest = "sha256:one"
	if _, _, err := store.RecordStatements(ctx, who, w.Product.ID, from, slices.Clone(standing)); err != nil {
		t.Fatal(err)
	}

	said := append(slices.Clone(standing), claim(10), claim(11))
	from.Digest = "sha256:two"
	race.Arm(1)
	recorded, superseded, err := store.RecordStatements(ctx, who, w.Product.ID, from, said)
	if err != nil {
		t.Fatal(err)
	}
	if race.Unspent() != 0 {
		t.Fatal("the recording committed nothing, so no attempt was retried and this checks nothing")
	}
	if recorded != 12 || superseded != 0 {
		t.Errorf("recorded %d and set aside %d; want the twelve the document says and nothing it repeats",
			recorded, superseded)
	}
	if said[0].Vulnerability != "CVE-2026-100" || len(said) != 12 {
		t.Errorf("the caller's claims were changed in place: %d of them, the first about %q",
			len(said), said[0].Vulnerability)
	}
}
