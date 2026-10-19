// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// What an upstream this product trusts says, as this product takes it
// (REQ-84). A statement holding for anybody shipping the component is applied
// by the run; one that depends on the upstream's own build is offered for
// review. Either may be declined here, which stops both.

// ErrNotUpstream says a statement is not one an upstream published, so there
// is nothing here to decline.
var ErrNotUpstream = refusal.New("only a statement an upstream published can be declined here")

// ErrStatementNotFound says no statement has that identifier in a product the
// subject may triage.
var ErrStatementNotFound = errors.New("no such statement")

// Declining is one statement declined or restored, as the act that did it
// reports it back.
type Declining struct {
	ProductID int64
	Publisher string
	Issue     string
	Component string
	About     string
}

// Decline stops an upstream's statement closing anything or being offered,
// and Restore starts it again. Both answer what the statement is about, for
// the record the caller writes beside the act.
//
// Asked of somebody who may triage the product. Declining a statement opens
// what it closed at the next run, which is work coming back rather than going
// away, so it needs nobody else.
func (s *Store) Decline(ctx context.Context, subject access.Subject, statementID int64) (*Declining, error) {
	return s.setDeclined(ctx, subject, statementID, true)
}

// Restore undoes Decline.
func (s *Store) Restore(ctx context.Context, subject access.Subject, statementID int64) (*Declining, error) {
	return s.setDeclined(ctx, subject, statementID, false)
}

func (s *Store) setDeclined(ctx context.Context, subject access.Subject, statementID int64,
	declined bool) (*Declining, error) {

	var out *Declining
	err := database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		out = nil
		one := new(Statement)
		err := tx.NewSelect().Model(one).
			Column("id", "product_id", "publisher", "vulnerability", "component", "about", "source").
			Where(`"ss"."id" = ?`, statementID).Scan(ctx)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return ErrStatementNotFound
		case err != nil:
			return fmt.Errorf("read the statement: %w", err)
		}
		// Authorized before anything about the statement is told: a
		// statement in a product the subject cannot triage reads as one that
		// does not exist.
		if !subject.Triages(access.Public, one.ProductID) {
			return ErrStatementNotFound
		}
		if one.Source != FromUpstream {
			return ErrNotUpstream
		}
		q := tx.NewUpdate().Model((*Statement)(nil)).Where(`"id" = ?`, statementID)
		if declined {
			now := s.now().UTC().Truncate(time.Microsecond)
			q = q.Set(`"declined_at" = ?`, now).Set(`"declined_by" = ?`, subject.ID)
		} else {
			q = q.Set(`"declined_at" = NULL`).Set(`"declined_by" = NULL`)
		}
		if _, err := q.Exec(ctx); err != nil {
			return fmt.Errorf("record the statement declined: %w", err)
		}
		out = &Declining{ProductID: one.ProductID, Publisher: one.Publisher,
			Issue: one.Vulnerability, Component: one.Component, About: one.About}
		return nil
	})
	return out, err
}

// Offer is an upstream's statement that depends on its own build, beside an
// open finding here it speaks about: the same issue, at a component of the
// same name and version. It is offered for review and never applied by itself.
type Offer struct {
	Statement  int64  `bun:"statement_id"`
	Product    int64  `bun:"product_id"`
	Stream     string `bun:"stream"`
	Variant    string `bun:"variant"`
	Finding    int64  `bun:"finding_id"`
	Publisher  string `bun:"publisher"`
	Issue      string `bun:"issue"`
	Component  string `bun:"component"`
	Version    string `bun:"version"`
	Status     string `bun:"status"`
	Document   string `bun:"document"`
	Within     string `bun:"within"`
	Target     int64  `bun:"target_id"`
	Justified  string `bun:"justification"`
	Reasoning  string `bun:"reasoning"`
	Identifier string `bun:"document_id"`
	Issued     int64  `bun:"vulnerability_id"`
}

// MostOffers bounds one page of offers. The queue is read by a person, and a
// page past this is not read.
const MostOffers = 200

// Offers is what the upstreams of the products here say about their open
// findings that depends on their own build, and nobody here has decided or
// declined, oldest statement first. One product where productID names one,
// and every product the subject reads disclosed work in where it is zero.
//
// Matched on the issue's own name or any name it goes by, the component's
// name and its version: the upstream named a build of its own, and a fork
// shipping the same component at the same version is where a reviewer asks
// whether the same reasoning holds. Disclosed findings only: a scanner's
// finding is disclosed, and an upstream speaks about nothing else.
func (s *Store) Offers(ctx context.Context, subject access.Subject, productID int64) ([]Offer, error) {
	var products []int64
	all := false
	if productID != 0 {
		if !subject.Reads(access.Public, productID) {
			return nil, access.Denied("read what an upstream offers")
		}
		products = []int64{productID}
	} else {
		var known []int64
		known, all = subject.Products()
		for _, id := range known {
			if subject.Reads(access.Public, id) {
				products = append(products, id)
			}
		}
		if !all && len(products) == 0 {
			return nil, nil
		}
	}
	issued := `SELECT "vv"."id" FROM "vulnerability" AS "vv" WHERE "vv"."identifier_folded" = "ss"."vulnerability"
		UNION SELECT "vl"."vulnerability_id" FROM "vulnerability_alias" AS "vl"
		WHERE "vl"."identifier_folded" = "ss"."vulnerability"`
	var out []Offer
	q := s.db.NewSelect().
		TableExpr(`"vex_statement" AS "ss"`).
		Join(`JOIN "component" AS "c" ON "c"."name_folded" = "ss"."component" AND "c"."version" = "ss"."about"`).
		Join(`JOIN "finding" AS "f" ON "f"."component_id" = "c"."id"`).
		Join(`JOIN "target" AS "tg" ON "tg"."id" = "f"."target_id"`).
		Join(`JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id" AND "st"."product_id" = "ss"."product_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "tg"."variant_id"`).
		Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "f"."vulnerability_id"`).
		Join(WordsJoin("ss")).
		ColumnExpr(`"ss"."id" AS "statement_id"`).
		ColumnExpr(`"st"."name" AS "stream"`).
		ColumnExpr(`"va"."name" AS "variant"`).
		ColumnExpr(`"st"."product_id" AS "product_id"`).
		ColumnExpr(`"f"."id" AS "finding_id"`).
		ColumnExpr(`"f"."target_id" AS "target_id"`).
		ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
		ColumnExpr(`"ss"."publisher" AS "publisher"`).
		ColumnExpr(`"v"."identifier" AS "issue"`).
		ColumnExpr(`"c"."name" AS "component"`).
		ColumnExpr(`"c"."version" AS "version"`).
		ColumnExpr(`"ss"."status" AS "status"`).
		ColumnExpr(`"ss"."document" AS "document"`).
		ColumnExpr(`"ss"."document_id" AS "document_id"`).
		ColumnExpr(`COALESCE("ss"."within", '') AS "within"`).
		ColumnExpr(`COALESCE("ss"."justification", '') AS "justification"`).
		ColumnExpr(WordsColumn+` AS "reasoning"`).
		Where(`"ss"."source" = ?`, FromUpstream).
		Where(`"ss"."placement" IS NULL`).
		Where(`"ss"."superseded_at" IS NULL`).
		Where(`"ss"."declined_at" IS NULL`).
		Where(`"f"."closed_at" IS NULL`).
		Where(`"f"."visibility" = ?`, access.Public).
		Where(`"f"."vulnerability_id" IN (`+issued+`)`).
		Where(`NOT EXISTS (SELECT 1 FROM `+Decisions+` WHERE `+DecisionAt(`"st"."product_id"`)+`
			AND "de"."live_key" IS NOT NULL AND "de"."state" IN (?))`,
			bun.List([]string{"approved", "proposed"})).
		OrderExpr(`"ss"."id", "f"."id"`).
		Limit(MostOffers)
	if !all {
		q = q.Where(`"ss"."product_id" IN (?)`, bun.List(products))
	}
	err := q.Scan(ctx, &out)
	if err != nil {
		return nil, fmt.Errorf("read what an upstream offers for review: %w", err)
	}
	return out, nil
}

// UpstreamSaid is what an upstream this product trusts says about a component
// of one name, standing statements only, declined ones included, newest
// first.
func (s *Store) UpstreamSaid(ctx context.Context, subject access.Subject, productID int64,
	component string) ([]Statement, error) {

	if !subject.Reads(access.Public, productID) {
		return nil, access.Denied("read what an upstream says")
	}
	var said []Statement
	err := withWords(s.db.NewSelect().Model(&said)).
		Where(`"ss"."product_id" = ?`, productID).
		Where(`"ss"."source" = ?`, FromUpstream).
		Where(`"ss"."component" = ?`, folded(component)).
		Where(`"ss"."superseded_at" IS NULL`).
		OrderExpr(`"ss"."id" DESC`).
		Limit(MostOffers).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read what an upstream says about a component: %w", err)
	}
	return said, nil
}
