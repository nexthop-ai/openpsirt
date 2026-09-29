// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"sort"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// PackageKind is one kind of package something open sits at, and how much is
// open there.
type PackageKind struct {
	// Kind is the type the package identifier spells: deb, golang, pypi.
	Kind string
	// Open counts issues at components, which is what the findings list
	// counts, so ticking a kind asks for about this many rows.
	Open int
}

// PackageKinds is the kinds of package that what is open in a selection sits at, most
// open first.
//
// Over the whole selection. None of the list's other filters narrows it,
// because it answers what the filter can offer, and a kind offered only while
// the rest of the filter happens to admit it vanishes from the list the moment
// somebody changes something else. The triage line does not narrow it either:
// a kind below the line is still one the list can be asked for.
//
// Counted over what the reader may see, so a kind present only on an
// undisclosed finding is not offered to somebody who reads disclosed ones.
func (s *Store) PackageKinds(ctx context.Context, subject access.Subject, scope Scope) ([]PackageKind, error) {
	if scope.ProductID == nil {
		return nil, refusal.Errorf("read package kinds: the selection names no product")
	}
	visible, err := access.Readable(subject, *scope.ProductID)
	if err != nil {
		return nil, err
	}
	targets, err := s.Builds(ctx, scope)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return []PackageKind{}, nil
	}
	pairs := s.db.NewSelect().
		Distinct().
		TableExpr(`"finding" AS "f"`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`f.component_id AS "component_id"`).
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible))
	return s.kindsOf(ctx, pairs)
}

// PackageKindsAnywhere is PackageKinds across every product the reader may see.
//
// An issue at a component in two products is counted in each, because the
// list across products holds it as two rows.
func (s *Store) PackageKindsAnywhere(ctx context.Context, subject access.Subject) ([]PackageKind, error) {
	if subject.Kind != access.Person {
		return nil, access.Denied("read package kinds across products")
	}
	products, all := subject.Products()
	if !all && len(products) == 0 {
		return []PackageKind{}, nil
	}
	pairs := s.db.NewSelect().
		Distinct().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		ColumnExpr(`st.product_id AS "product_id"`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`f.component_id AS "component_id"`).
		Where("f.closed_at IS NULL")
	return s.kindsOf(ctx, onlyReadable(pairs, subject, products, all))
}

// kindsOf counts the issue-at-component pairs a query selects by the kind of
// package each component is.
//
// The kind is read out of each distinct package identifier here rather than in
// the statement, because reading a part of a string is spelled differently on
// every engine. The statement returns one row per component, and a switch
// image holds a few thousand of them.
func (s *Store) kindsOf(ctx context.Context, pairs *bun.SelectQuery) ([]PackageKind, error) {
	perComponent := s.db.NewSelect().
		TableExpr(`(?) AS "pairs"`, pairs).
		ColumnExpr(`"pairs"."component_id" AS "component_id"`).
		ColumnExpr(`COUNT(*) AS "open"`).
		GroupExpr(`"pairs"."component_id"`)
	var rows []struct {
		Purl string `bun:"purl"`
		Open int    `bun:"open"`
	}
	if err := s.db.NewSelect().
		TableExpr(`(?) AS "held"`, perComponent).
		Join(`JOIN "component" AS "c" ON c.id = "held"."component_id"`).
		ColumnExpr(`c.purl AS "purl"`).
		ColumnExpr(`"held"."open" AS "open"`).
		Where("c.purl IS NOT NULL").
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read the kinds of package open here: %w", err)
	}

	counted := map[string]int{}
	for _, row := range rows {
		// A component with no package identifier has no kind the filter can
		// ask for, so it is not offered as one.
		if kind := graph.EcosystemOf(row.Purl); kind != "" {
			counted[kind] += row.Open
		}
	}
	out := make([]PackageKind, 0, len(counted))
	for kind, open := range counted {
		out = append(out, PackageKind{Kind: kind, Open: open})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Open != out[j].Open {
			return out[i].Open > out[j].Open
		}
		return out[i].Kind < out[j].Kind
	})
	return out, nil
}
