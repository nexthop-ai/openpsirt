// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// What is said to people about findings names no lead. A critical on a
// release is told of a vulnerability, and of nothing where the same row is a
// lead: its kind is the only thing keeping it out, since it keeps the
// visibility, the rating and the release that would carry it. A lead's own
// notices are told through the lead consumers.
func TestACriticalOnAReleaseIsNeverALead(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		rights := access.NewStore(db.DB)
		released := w.TargetFor(w.Tag, w.Customer)
		triager := recordPerson(t, rights, "triager@example.com", false, w.Product.ID, access.PublicTriage)

		critical(t, db, released.ID, "CVE-2026-SHIPPED", "critical")
		critical(t, db, released.ID, "CVE-2026-LEAD", "critical")
		if _, err := db.DB.NewUpdate().Table("finding").Set(`"kind" = ?`, "analysis").
			Where(`"vulnerability_id" IN (SELECT "id" FROM "vulnerability" WHERE "identifier" = ?)`, "CVE-2026-LEAD").
			Exec(ctx); err != nil {
			t.Fatal(err)
		}
		sweep(t, db)
		told := openFor(t, db, triager, notify.CriticalOnRelease)
		if len(told) != 1 || !strings.Contains(told[0], "CVE-2026-SHIPPED") {
			t.Fatalf("the triager was told %q; want the vulnerability, or this checks nothing", told)
		}
		for _, line := range told {
			if strings.Contains(line, "CVE-2026-LEAD") {
				t.Errorf("the triager was told of a lead: %q", line)
			}
		}
	})
}
