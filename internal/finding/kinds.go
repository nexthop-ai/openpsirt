// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// PackageKind is one kind of package something open sits at, and how much is
// open there.
type PackageKind struct {
	// Kind is the type the package identifier spells: deb, golang, pypi.
	Kind string
	// Open counts issues at folds, which are the findings list's rows, so
	// ticking a kind asks for this many rows.
	Open int
}

// PackageKinds is the kinds of package that what is open in a selection sits
// at, most open first.
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
	return s.kindsOf(ctx, pairs, `"pairs"."vulnerability_id", `+FoldedOn)
}

// PackageKindsAnywhere is PackageKinds across every product the reader may see.
//
// An issue at a fold in two products is counted in each, because the list
// across products holds it as two rows.
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
	return s.kindsOf(ctx, onlyReadable(pairs, subject, products, all),
		`"pairs"."product_id", "pairs"."vulnerability_id", `+FoldedOn)
}

// kindsOf counts the list's rows by the kind of package each is at.
//
// pairs selects the distinct issues at components open in the scope, and
// grain is what folds them into the list's rows, over those pairs joined to
// their component as "c". Distinct pairs first, because they are a few
// thousand where the findings they come from are hundreds of thousands, and
// the component is joined to those alone.
//
// Every package in a fold is of one kind, so the fold's lowest identifier
// speaks for it. The rows are counted per identifier in the statement and the
// kind read out of each distinct identifier here, because reading a part of a
// string is spelled differently on every engine.
func (s *Store) kindsOf(ctx context.Context, pairs *bun.SelectQuery, grain string) ([]PackageKind, error) {
	perRow := s.db.NewSelect().
		TableExpr(`(?) AS "pairs"`, pairs).
		Join(`JOIN "component" AS "c" ON c.id = "pairs"."component_id"`).
		ColumnExpr(`MIN(c.purl) AS "purl"`).
		GroupExpr(grain)
	var rows []struct {
		Purl string `bun:"purl"`
		Open int    `bun:"open"`
	}
	if err := s.db.NewSelect().
		TableExpr(`(?) AS "listed"`, perRow).
		ColumnExpr(`"listed"."purl" AS "purl"`).
		ColumnExpr(`COUNT(*) AS "open"`).
		Where(`"listed"."purl" IS NOT NULL`).
		GroupExpr(`"listed"."purl"`).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read the kinds of package open here: %w", err)
	}

	counted := map[string]int{}
	for _, row := range rows {
		if kind := kindAsked(row.Purl); kind != "" {
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

// kindAsked is the kind the list's filter finds a package identifier by, or
// nothing where the filter cannot find it.
//
// Read the way the filter reads it: the identifier as stored, without regard
// to capitals, beginning "pkg:", the kind and a slash. An identifier the filter
// matches under no kind is not offered as one, because ticking it would empty
// the list.
func kindAsked(purl string) string {
	rest, found := strings.CutPrefix(strings.ToLower(purl), "pkg:")
	if !found {
		return ""
	}
	kind, _, slashed := strings.Cut(rest, "/")
	if !slashed {
		return ""
	}
	return kind
}
