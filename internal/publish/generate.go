// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package publish

import (
	"context"
	"fmt"
	"sort"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/triage"
	"github.com/nexthop-ai/openpsirt/internal/vex"
)

// Generator works out the documents one product publishes, from what stands
// now.
type Generator struct {
	db  bun.IDB
	vex *vex.Store
	who publisher.Named
	// base is the address this deployment is reached at, with no trailing
	// slash. Every address a document states is built from it.
	base string
}

// NewGenerator returns a generator over db, naming who as the publisher and
// stating addresses below base.
func NewGenerator(db *bun.DB, who publisher.Named, base string) *Generator {
	return &Generator{db: db, vex: vex.NewStore(db), who: who, base: base}
}

// built is one build of a product, as the documents name it, and what is
// stated about it.
type built struct {
	stream, streamShown   string
	variant, variantShown string
	// root is the package identifier the build's inventory gave itself,
	// where it gave one that states a version.
	root  string
	facts []vex.Fact
}

// id is what a CSAF document calls the build, and what an OpenVEX statement
// names it by where the inventory gave it no package identifier.
func (b *built) id(product string) string {
	return product + ":" + b.stream + ":" + b.variant
}

// Generated is one document as what stands now would write it, before it is
// given a revision.
type Generated struct {
	Kind    string
	Subject string
	// TrackingID and Title are what the lists name it by.
	TrackingID string
	Title      string
	// Settled is a digest of what it states.
	Settled string
	// path is where it is served, given when it was first released.
	path func(first revision) string
	// render is the bytes of one revision of it.
	render func(at revision) ([]byte, error)
}

// Product is every document one product publishes, under the statuses given.
//
// Every branch, tag and variant in use that has been scanned is read, at what
// it last scanned, as the subject reads it. The subject is anybody at all, so
// what is read is disclosed work in a product whose documents are published,
// and nothing else.
func (g *Generator) Product(ctx context.Context, subject access.Subject, product *catalog.Product,
	statuses string) ([]Generated, error) {

	if !subject.Reads(access.Public, product.ID) {
		return nil, access.Denied(fmt.Sprintf("read disclosed findings in product %d", product.ID))
	}
	builds, err := g.builds(ctx, subject, product, statuses)
	if err != nil {
		return nil, err
	}
	descriptions, err := g.described(ctx, subject, builds)
	if err != nil {
		return nil, err
	}
	out := g.vexDocuments(product, builds, descriptions)
	return append(out, g.openVEXDocuments(product, builds)...), nil
}

// builds reads every build of the product that is in use and has been
// scanned, with what is stated about each under the statuses given.
func (g *Generator) builds(ctx context.Context, subject access.Subject, product *catalog.Product,
	statuses string) ([]*built, error) {

	var rows []struct {
		TargetID     int64  `bun:"target_id"`
		StreamID     int64  `bun:"stream_id"`
		VariantID    int64  `bun:"variant_id"`
		Stream       string `bun:"stream"`
		StreamShown  string `bun:"stream_shown"`
		Variant      string `bun:"variant"`
		VariantShown string `bun:"variant_shown"`
	}
	if err := g.db.NewSelect().
		TableExpr(`"target" AS "tg"`).
		Join(`JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "tg"."variant_id"`).
		ColumnExpr(`"tg"."id" AS "target_id"`).
		ColumnExpr(`"st"."id" AS "stream_id"`).
		ColumnExpr(`"va"."id" AS "variant_id"`).
		ColumnExpr(`"st"."name" AS "stream"`).
		ColumnExpr(`"st"."display_name" AS "stream_shown"`).
		ColumnExpr(`"va"."name" AS "variant"`).
		ColumnExpr(`"va"."display_name" AS "variant_shown"`).
		Where(`"st"."product_id" = ?`, product.ID).
		Where(`"st"."retired_at" IS NULL`).
		Where(`"va"."retired_at" IS NULL`).
		Where(`"tg"."last_scan_id" IS NOT NULL`).
		OrderExpr(`"st"."name", "va"."name"`).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read the builds of product %s: %w", product.Name, err)
	}
	out := make([]*built, 0, len(rows))
	for _, row := range rows {
		named := &catalog.Named{
			ProductID: product.ID, StreamID: row.StreamID, VariantID: row.VariantID,
			Product: product.Name, Stream: row.Stream, Variant: row.Variant,
		}
		stated, err := g.vex.Public(ctx, subject, named, row.TargetID)
		if err != nil {
			return nil, err
		}
		one := &built{
			stream: row.Stream, streamShown: row.StreamShown,
			variant: row.Variant, variantShown: row.VariantShown, root: stated.Root,
		}
		for _, fact := range stated.Facts {
			if limited(fact.Status, statuses) {
				continue
			}
			one.facts = append(one.facts, fact)
		}
		out = append(out, one)
	}
	return out, nil
}

// limited reports whether the statuses the deployment publishes leave a
// status out.
func limited(status, statuses string) bool {
	return statuses == setting.SettledStatuses && status != vex.NotAffected && status != vex.Fixed
}

// described is what each issue stated about is, in the words of whoever
// reported it, keyed by issue.
//
// Left out where a flaw of ours recorded out of the subject's reach wrote
// onto the issue: its summary is the description every product shares, and
// it is the flaw's own words.
func (g *Generator) described(ctx context.Context, subject access.Subject,
	builds []*built) (map[int64]string, error) {
	seen := map[int64]bool{}
	var issues []int64
	for _, one := range builds {
		for _, fact := range one.facts {
			if !seen[fact.VulnerabilityID] {
				seen[fact.VulnerabilityID] = true
				issues = append(issues, fact.VulnerabilityID)
			}
		}
	}
	out := map[int64]string{}
	if len(issues) == 0 {
		return out, nil
	}
	var rows []struct {
		ID          int64  `bun:"id"`
		Description string `bun:"description"`
	}
	where, args := database.InAnyOf(`"v"."id"`, issues)
	if err := g.db.NewSelect().
		TableExpr(`"vulnerability" AS "v"`).
		ColumnExpr(`"v"."id" AS "id"`).
		ColumnExpr(`COALESCE("v"."description", '') AS "description"`).
		Where(where, args...).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what these issues are: %w", err)
	}
	withheld, err := finding.RecordedOutOfReach(ctx, g.db, subject, issues)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if !withheld[row.ID] {
			out[row.ID] = row.Description
		}
	}
	return out, nil
}

// placed is one fact as one build states it.
type placed struct {
	build *built
	fact  vex.Fact
}

// portableForm says, for each component a set of facts is about, whether
// they are stated about the component alone.
//
// A component is stated alone where every fact about it as a whole holds for
// anybody shipping it and every one says the same thing. Where one build says
// something else about the same component at the same version — an issue open
// and undecided there, or a reason that is that build's own — a statement
// about the component alone would contradict it, so every one of them is
// stated about the component as part of its build.
func portableForm(facts []placed) map[string]bool {
	type said struct {
		status, justification, impact string
	}
	first := map[string]said{}
	out := map[string]bool{}
	for _, one := range facts {
		if one.fact.Within != "" {
			continue
		}
		key := one.fact.Subject()
		now := said{one.fact.Status, one.fact.Justification, one.fact.Impact}
		was, ok := first[key]
		switch {
		case !ok:
			first[key] = now
			out[key] = one.fact.Scope == triage.Portable && one.fact.Purl != ""
		case was != now || one.fact.Scope != triage.Portable:
			out[key] = false
		}
	}
	return out
}

// byIssue is every fact of every build, grouped by the issue it is about, in
// order of the issue's name.
func byIssue(builds []*built) [][]placed {
	groups := map[string][]placed{}
	for _, one := range builds {
		for _, fact := range one.facts {
			groups[fact.Issue] = append(groups[fact.Issue], placed{build: one, fact: fact})
		}
	}
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([][]placed, 0, len(names))
	for _, name := range names {
		out = append(out, groups[name])
	}
	return out
}
