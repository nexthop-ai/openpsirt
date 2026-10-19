// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package publish

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/background"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// Lease names the work of writing the published documents, so that one
// replica writes them at a time.
const Lease = "publish.documents"

// betweenPasses is how often the published documents are worked out again.
//
// What moves them is a claim agreed to, a scan landing or a product turned
// on, and a reader learns of it from the next pass. Five minutes is the rescan
// schedule's own pace, and a pass that finds nothing moved writes nothing.
const betweenPasses = 5 * time.Minute

// Pass writes the published documents on a timer.
type Pass struct {
	db        *bun.DB
	generate  *Generator
	documents *Store
	leases    *queue.Leases
	replica   string
	logger    *slog.Logger
	interval  time.Duration
}

// NewPass returns the pass over db, writing as whichever replica this is.
func NewPass(db *bun.DB, generate *Generator, replica string, logger *slog.Logger) *Pass {
	return &Pass{
		db: db, generate: generate, documents: NewStore(db), leases: queue.NewLeases(db),
		replica: replica, logger: logger,
	}
}

// Wrote is what one pass did.
type Wrote struct {
	// Products is how many products publish, and Documents how many
	// documents they publish now.
	Products  int
	Documents int
	// Revised is how many documents took a new revision, Withdrawn how many
	// stopped being published, and Skipped how many products could not be
	// worked out, each logged as the pass met it.
	Revised   int
	Withdrawn int
	Skipped   int
}

// Run writes the documents until the context ends.
func (p *Pass) Run(ctx context.Context, interval time.Duration) {
	defer p.leases.Handback(ctx, Lease, p.replica, p.logger)
	background.Every(ctx, interval, betweenPasses, func(ctx context.Context) {
		p.interval = interval
		wrote, err := p.Once(ctx)
		switch {
		case err != nil:
			if ctx.Err() == nil {
				p.logger.Error("writing the published documents", "error", err)
			}
		case wrote.Revised > 0 || wrote.Withdrawn > 0 || wrote.Skipped > 0:
			p.logger.Info("wrote the published documents", "products", wrote.Products,
				"documents", wrote.Documents, "revised", wrote.Revised, "withdrawn", wrote.Withdrawn,
				"products not worked out", wrote.Skipped)
		}
	})
}

// Once works out every published product's documents and writes what moved.
func (p *Pass) Once(ctx context.Context) (Wrote, error) {
	var wrote Wrote
	held := p.interval
	if held <= 0 {
		held = betweenPasses
	}
	mine, err := p.leases.Take(ctx, Lease, p.replica, 5*held)
	if err != nil || !mine {
		return wrote, err
	}
	names := catalog.NewStore(p.db)
	products, err := names.Publishing(ctx)
	if err != nil {
		return wrote, err
	}
	statuses, err := Statuses(ctx, p.db)
	if err != nil {
		return wrote, err
	}
	// Anybody at all, which is who the documents are for. What it reads is
	// disclosed work in a product whose documents are published, and the
	// generation asks the same narrowing every read here asks.
	subject := access.Published(products)
	wrote.Products = len(products)
	for _, id := range products {
		if ctx.Err() != nil {
			return wrote, nil
		}
		product, err := names.ProductByID(ctx, id)
		if err != nil {
			return wrote, err
		}
		one, err := p.Product(ctx, subject, product, statuses)
		wrote.Documents += one.Documents
		wrote.Revised += one.Revised
		wrote.Withdrawn += one.Withdrawn
		if err != nil {
			// One product that cannot be worked out says nothing about the
			// next, and its documents stay as they last were.
			wrote.Skipped++
			p.logger.Error("a product's published documents could not be worked out",
				"product", product.Name, "error", err)
		}
	}
	return wrote, nil
}

// Product works out one product's documents and writes what moved.
func (p *Pass) Product(ctx context.Context, subject access.Subject, product *catalog.Product,
	statuses string) (Wrote, error) {

	var wrote Wrote
	generated, err := p.generate.Product(ctx, subject, product, statuses)
	if err != nil {
		return wrote, err
	}
	wrote.Documents = len(generated)
	held, err := p.documents.heldFor(ctx, product.ID)
	if err != nil {
		return wrote, err
	}
	kept := map[key]bool{}
	var failed []error
	for _, one := range generated {
		at := key{one.Kind, one.Subject}
		kept[at] = true
		// Read before the write to step over what has not moved, which is
		// nearly everything on nearly every pass. The write reads again
		// inside its own transaction and decides there.
		if was, ok := held[at]; ok && was.Settled == one.Settled && was.Statuses == statuses &&
			was.WithdrawnAt == nil {
			continue
		}
		revised, err := p.documents.revise(ctx, product.ID, one, statuses)
		if err != nil {
			// One document that cannot be written says nothing about the
			// rest, and the withdrawals below still run.
			failed = append(failed, err)
			continue
		}
		if revised {
			wrote.Revised++
		}
	}
	for at, was := range held {
		if kept[at] || was.WithdrawnAt != nil {
			continue
		}
		withdrawn, err := p.documents.withdraw(ctx, was.ID, was.Version)
		if err != nil {
			failed = append(failed, err)
			continue
		}
		if withdrawn {
			wrote.Withdrawn++
		}
	}
	return wrote, errors.Join(failed...)
}

// ErrPathTaken is a document whose path another product's document already
// holds: two product names the standard's filename rule folds alike. Retrying
// never clears it, and neither does withdrawing the other product's, which
// keeps its path; it is refused in words, naming the other product. Turning
// publishing on for a product is refused where this would happen, so it is
// reached only by two products turned on at once.
var ErrPathTaken = refusal.New("another product's document is published at the same path")

// Statuses is which statuses the deployment publishes now.
func Statuses(ctx context.Context, db bun.IDB) (string, error) {
	value, set, err := setting.NewStore(db).Get(ctx, setting.PublishedStatuses)
	if err != nil {
		return "", err
	}
	if !set || value != setting.SettledStatuses {
		return setting.EveryStatus, nil
	}
	return setting.SettledStatuses, nil
}

// key is what one document is about within its product.
type key struct{ kind, subject string }

// heldFor is every document held for one product, without its bytes.
func (s *Store) heldFor(ctx context.Context, productID int64) (map[key]Document, error) {
	var rows []Document
	if err := s.db.NewSelect().Model(&rows).
		ExcludeColumn("document").
		Where(`"pub"."product_id" = ?`, productID).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the documents product %d publishes: %w", productID, err)
	}
	out := make(map[key]Document, len(rows))
	for _, row := range rows {
		out[key{row.Kind, row.Subject}] = row
	}
	return out, nil
}

// revise writes a new revision of a document where what it states has moved,
// and answers whether it did.
//
// Everything it turns on is read inside the transaction that writes: the
// revision held, and the moment. A second replica writing the same document
// between the read and the write matches nothing on the version it read, and
// the attempt goes again against what that replica wrote.
//
// A document withdrawn and stating again what it stated when it was withdrawn
// is served again as the revision it was, because a reader holding that
// revision holds the right answer.
func (s *Store) revise(ctx context.Context, productID int64, one Generated,
	statuses string) (bool, error) {

	var revised bool
	err := database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		revised = false
		now := s.now().UTC().Truncate(time.Microsecond)
		was := new(Document)
		err := tx.NewSelect().Model(was).
			Where(`"pub"."product_id" = ?`, productID).
			Where(`"pub"."kind" = ?`, one.Kind).
			Where(`"pub"."subject" = ?`, one.Subject).
			Scan(ctx)
		switch {
		case database.IsNoRows(err):
			was = nil
		case err != nil:
			return fmt.Errorf("read the published %s about %s: %w", one.Kind, one.Subject, err)
		}

		if was != nil && was.Settled == one.Settled {
			if was.Statuses == statuses && was.WithdrawnAt == nil {
				return nil
			}
			// Nothing it states moved: the setting it was written under did,
			// or it is stating again what it stated when it was withdrawn.
			return s.unchanged(ctx, tx, was, statuses)
		}

		at := revision{Version: 1, First: now, Current: now}
		summary := "Initial version."
		if was != nil {
			at.Version, at.First = was.Version+1, was.FirstAt.UTC()
			history, err := historyOf(one.Kind, was)
			if err != nil {
				return err
			}
			at.History = history
			summary = "The statements changed."
		}
		at.History = append(at.History, advisory.Revision{
			Number: fmt.Sprint(at.Version), Date: now, Summary: summary,
		})
		body, err := one.render(at)
		if err != nil {
			return err
		}
		path := one.path(at)
		var other string
		switch err := tx.NewSelect().Model((*Document)(nil)).
			Join(`JOIN "product" AS "p" ON "p"."id" = "pub"."product_id"`).
			ColumnExpr(`"p"."display_name"`).
			Where(`"pub"."path_digest" = ?`, digestOf(path)).
			Where(`NOT ("pub"."product_id" = ? AND "pub"."kind" = ? AND "pub"."subject" = ?)`,
				productID, one.Kind, one.Subject).
			Scan(ctx, &other); {
		case err == nil:
			return fmt.Errorf("%w: %s is held by a document of %s, whose name folds to the same "+
				"filename; turn publishing off for this product", ErrPathTaken, path, other)
		case !database.IsNoRows(err):
			return fmt.Errorf("read who publishes at %s: %w", path, err)
		}
		row := &Document{
			ProductID: productID, Kind: one.Kind, Subject: one.Subject,
			Path: path, PathDigest: digestOf(path), TrackingID: one.TrackingID, Title: one.Title,
			Version: at.Version, FirstAt: at.First, CurrentAt: now, Statuses: statuses,
			Settled: one.Settled, Body: string(body),
		}
		if was == nil {
			if _, err := tx.NewInsert().Model(row).Exec(ctx); err != nil {
				if database.IsDuplicate(err) {
					return fmt.Errorf("publish the %s about %s: %w", one.Kind, one.Subject,
						database.ErrGoAgain)
				}
				return fmt.Errorf("publish the %s about %s: %w", one.Kind, one.Subject, err)
			}
			revised = true
			return nil
		}
		res, err := tx.NewUpdate().Model((*Document)(nil)).
			Set(`"path" = ?`, row.Path).Set(`"path_digest" = ?`, row.PathDigest).
			Set(`"tracking_id" = ?`, row.TrackingID).Set(`"title" = ?`, row.Title).
			Set(`"version" = ?`, row.Version).Set(`"current_at" = ?`, row.CurrentAt).
			Set(`"statuses" = ?`, row.Statuses).Set(`"settled" = ?`, row.Settled).
			Set(`"withdrawn_at" = NULL`).Set(`"document" = ?`, row.Body).
			Where(`"id" = ?`, was.ID).Where(`"version" = ?`, was.Version).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("publish the %s about %s: %w", one.Kind, one.Subject, err)
		}
		n, err := database.Affected(res)
		if err != nil {
			return fmt.Errorf("publish the %s about %s: %w", one.Kind, one.Subject, err)
		}
		if n == 0 {
			return fmt.Errorf("publish the %s about %s: %w", one.Kind, one.Subject, database.ErrGoAgain)
		}
		revised = true
		return nil
	})
	return revised, err
}

// unchanged records that a document stating what it stated stands again, or
// stands under the statuses the deployment publishes now.
func (s *Store) unchanged(ctx context.Context, tx bun.IDB, was *Document, statuses string) error {
	res, err := tx.NewUpdate().Model((*Document)(nil)).
		Set(`"statuses" = ?`, statuses).Set(`"withdrawn_at" = NULL`).
		Where(`"id" = ?`, was.ID).Where(`"version" = ?`, was.Version).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("publish the %s about %s again: %w", was.Kind, was.Subject, err)
	}
	n, err := database.Affected(res)
	if err != nil {
		return fmt.Errorf("publish the %s about %s again: %w", was.Kind, was.Subject, err)
	}
	if n == 0 {
		return fmt.Errorf("publish the %s about %s again: %w", was.Kind, was.Subject, database.ErrGoAgain)
	}
	return nil
}

// withdraw stops a document being served, where the product has nothing to say
// about its subject any more, and answers whether it did.
//
// Kept rather than deleted. Its revisions went to readers, and a document that
// comes back continues them.
func (s *Store) withdraw(ctx context.Context, id int64, version int) (bool, error) {
	var withdrawn bool
	err := database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		withdrawn = false
		res, err := tx.NewUpdate().Model((*Document)(nil)).
			Set(`"withdrawn_at" = ?`, s.now().UTC().Truncate(time.Microsecond)).
			Where(`"id" = ?`, id).Where(`"version" = ?`, version).
			Where(`"withdrawn_at" IS NULL`).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("withdraw a published document: %w", err)
		}
		n, err := database.Affected(res)
		if err != nil {
			return fmt.Errorf("withdraw a published document: %w", err)
		}
		// Matching nothing is another replica having revised or withdrawn it
		// first, and its write is the newer answer.
		withdrawn = n > 0
		return nil
	})
	return withdrawn, err
}

// historyOf is the revision history a held document states, read from the
// bytes it was written as.
//
// The bytes are this deployment's own, so one that does not read back is a
// fault rather than something to step over.
func historyOf(kind string, was *Document) ([]advisory.Revision, error) {
	switch kind {
	case CSAFVEX:
		var doc advisory.Document
		if err := json.Unmarshal([]byte(was.Body), &doc); err != nil {
			return nil, fmt.Errorf("read the history of the published %s about %s: %w",
				kind, was.Subject, err)
		}
		return doc.Document.Tracking.RevisionHistory, nil
	case OpenVEX:
		// OpenVEX carries no history beyond its version and its two dates.
		return nil, nil
	}
	return nil, errors.New("a published document of a kind nothing writes: " + kind)
}
