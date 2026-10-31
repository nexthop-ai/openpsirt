// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"errors"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// Every security testing figure refuses a reader of the product who does not
// read security testing material in it, in the data layer and before the
// database is asked anything, so a handler that forgot to check still counts
// nothing. The database is nil: a figure reaching it fails another way.
func TestEverySecurityTestingFigureRefusesAReaderOfDependencyWorkAlone(t *testing.T) {
	reader := access.NewPerson(1, "reader", false, map[int64][]access.Role{7: {access.PublicRead, access.PrivateRead}}, 0)
	scope := Scope{ProductID: 7}
	now := time.Now()
	for name, figure := range map[string]func() error{
		"counts": func() error {
			_, err := CodeFindingCountsOf(t.Context(), nil, reader, scope)
			return err
		},
		"trend": func() error {
			_, err := Trend(t.Context(), nil, reader, scope, now, time.Hour, 1)
			return err
		},
		"time to judge": func() error {
			_, err := TimeToJudge(t.Context(), nil, reader, scope, now, now, now)
			return err
		},
		"time to fix": func() error {
			_, err := TimeToFix(t.Context(), nil, reader, scope, now, now)
			return err
		},
		"precision": func() error {
			_, err := PrecisionOf(t.Context(), nil, reader, scope)
			return err
		},
		"coverage": func() error {
			_, err := CoverageOf(t.Context(), nil, reader, scope, now, now, now)
			return err
		},
		"by release": func() error {
			_, err := ByRelease(t.Context(), nil, reader, scope, 1)
			return err
		},
	} {
		if err := refusedOrReached(figure); !errors.Is(err, access.ErrDenied) {
			t.Errorf("%s answered %v to a reader of dependency work alone; want a refusal", name, err)
		}
	}
}

// refusedOrReached is what a figure answers, or that it reached the database,
// which here is nil.
func refusedOrReached(figure func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("it reached the database")
		}
	}()
	return figure()
}

// Every security testing figure across products refuses a scope naming a
// product where the reader does not read security testing material, in the
// data layer and before the database is asked anything, though they read it
// in another product of the scope: each product is checked, never the first.
func TestEverySecurityTestingFigureAcrossProductsRefusesAProductNotReadAtSecurityTesting(t *testing.T) {
	reader := access.NewPerson(1, "reader", false, map[int64][]access.Role{
		7: {access.SecurityTestingRead},
		8: {access.PublicRead, access.PrivateRead},
	}, 0)
	scope := Scope{Across: []int64{7, 8}}
	now := time.Now()
	for name, figure := range map[string]func() error{
		"counts": func() error {
			_, err := CodeFindingCountsOf(t.Context(), nil, reader, scope)
			return err
		},
		"trend": func() error {
			_, err := Trend(t.Context(), nil, reader, scope, now, time.Hour, 1)
			return err
		},
		"time to judge": func() error {
			_, err := TimeToJudge(t.Context(), nil, reader, scope, now, now, now)
			return err
		},
		"coverage": func() error {
			_, err := CoverageOf(t.Context(), nil, reader, scope, now, now, now)
			return err
		},
	} {
		if err := refusedOrReached(figure); !errors.Is(err, access.ErrDenied) {
			t.Errorf("%s across products answered %v with a product read for dependency work alone; want a refusal", name, err)
		}
	}
}
