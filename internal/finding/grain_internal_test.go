// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// unconnected formats statements and connects to nothing.
type unconnected struct{}

func (unconnected) Connect(context.Context) (driver.Conn, error) {
	return nil, errors.New("formatting only")
}
func (unconnected) Driver() driver.Driver { return nil }

// A filter's conditions over a group are exactly the ones asksOfGroups names
// and ofRows takes out. A view grouped at another grain than the list's picks
// the list's groups by the first and applies the second to its rows, so a
// field that writes a HAVING clause and is missing from either list is a
// condition asked of the wrong grain.
//
// Every field of the filter is set alone and the statement it writes is read.
func TestEveryConditionOverAGroupIsKnownAsOne(t *testing.T) {
	db := bun.NewDB(sql.OpenDB(unconnected{}), sqlitedialect.New())
	written := func(f Filter) string {
		return f.narrow(db.NewSelect().TableExpr(`"finding" AS "f"`).
			Column("f.vulnerability_id").GroupExpr("f.vulnerability_id")).String()
	}
	base := Filter{ProductID: 1, Builds: 2, HeldBy: []int64{1}, TargetID: 1}
	if strings.Contains(written(base), "HAVING") || base.asksOfGroups() {
		t.Fatal("the base filter asks something of a group, so this checks nothing")
	}

	// Set nowhere below. Each is a sort, a release narrowing applied where
	// the builds are resolved, or a condition on a row.
	unset := map[string]bool{
		"BundleSort": true, "SortBy": true, "Floor": true, "Workable": true,
		"Origin": true, "AcrossVariants": true,
	}
	now, one := time.Now(), int64(1)
	typ := reflect.TypeOf(Filter{})
	examined, grouped := 0, 0
	for i := range typ.NumField() {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		f := base
		value := reflect.ValueOf(&f).Elem().Field(i)
		switch v := value.Addr().Interface().(type) {
		case *bool:
			*v = true
		case *string:
			*v = "high"
		case *[]string:
			*v = []string{"agreed"}
		case *[]FixState:
			*v = []FixState{FixedUpstream}
		case *[]ClaimStanding:
			*v = []ClaimStanding{StandingAgreed}
		case *PlannedFilter:
			*v = PlannedOnly
		case **time.Time:
			*v = &now
		case *int:
			*v = 5
		case *int64:
			*v = 1
		case **int64:
			*v = &one
		case *[]int64:
			*v = []int64{1}
		case *[]access.Visibility:
			*v = []access.Visibility{access.Public}
		default:
			// A field of a named type this does not know how to set. The
			// ones named here write no condition over a group; any other is
			// a field nothing examines, which is how a new group condition
			// would pass unseen.
			if !unset[field.Name] {
				t.Errorf("%s is of a type this does not set, so nothing examines it", field.Name)
			}
			continue
		}
		examined++
		having := strings.Contains(written(f), "HAVING")
		if having {
			grouped++
		}
		if having != f.asksOfGroups() {
			t.Errorf("%s writes a HAVING clause: %v; asksOfGroups says %v", field.Name, having, f.asksOfGroups())
		}
		if strings.Contains(written(f.ofRows()), "HAVING") {
			t.Errorf("%s is still a condition over a group once ofRows has taken them out", field.Name)
		}
	}
	if examined == 0 || grouped == 0 {
		t.Fatalf("examined %d fields and %d were conditions over a group, so this checked nothing",
			examined, grouped)
	}
}
