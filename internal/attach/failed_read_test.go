// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package attach_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// Whether an issue is here, read and failing, is not an issue that is not
// here. Folded in with the refusals, an outage tells every caller their files
// are gone.
func TestAnIssueWhosePlacesCouldNotBeReadIsNotAnIssueThatIsNotHere(t *testing.T) {
	ctx := t.Context()
	handle := dbtest.Without(t, "finding")
	product, err := catalog.NewStore(handle.DB).DeclareProduct(ctx, "mine", "Mine")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finding.NewVulnerabilities(handle.DB).Intern(ctx,
		[]finding.Named{{Identifier: "CVE-2026-0001", Severity: "high"}}); err != nil {
		t.Fatal(err)
	}
	files, err := attach.NewFiles(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	who := access.NewPerson(1, "reader", false,
		map[int64][]access.Role{product.ID: {access.PublicRead}}, 101)
	_, _, err = attach.NewStore(handle.DB, files).Issue(ctx, who, "mine", "CVE-2026-0001")
	if err == nil {
		t.Fatal("an issue whose places could not be read was resolved")
	}
	if errors.Is(err, attach.ErrNoSuchIssue) {
		t.Errorf("a read that failed was answered as no such issue: %v", err)
	}
}
