// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"regexp"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/uptrace/bun"
)

// ErrNameTaken says another issue already goes by that name.
//
// A sentinel because the caller has to answer it: recording the name anyway
// would merge two records that were opened separately, and nothing here can
// know whether that is what somebody meant.
var ErrNameTaken = refusal.New("another issue already goes by that name")

// ErrNotAHandName refuses a name typed in a shape no scheme issues. Only the
// two schemes an internal flaw is given a public name in are taken by hand.
var ErrNotAHandName = refusal.New("a name recorded by hand is a CVE, such as CVE-2027-0001, " +
	"or a GitHub advisory, such as GHSA-2c4j-5f6m-7q8r")

// ErrScannerIssue refuses a hand-typed name on an issue a scan reported. Its
// names are the ones the scans that report it carry.
var ErrScannerIssue = refusal.New("a name may be recorded by hand only on a flaw recorded here; " +
	"an issue a scan reported takes its names from the scans")

// ErrNoSuchName is a name this issue does not answer to.
var ErrNoSuchName = refusal.New("this issue goes by no such name")

// ErrFiledUnder refuses removing the name an issue is filed under where a scan
// reported it, or where it is the only name the issue has.
var ErrFiledUnder = refusal.New("that is the name this issue is filed under, and a scan reported it")

// ErrNotByHand refuses removing a name a scan reported.
var ErrNotByHand = refusal.New("that name arrived with a scan; only a name recorded by hand is removed")

// handNamed is the shape of a name a person may record: a CVE, or a GitHub
// advisory in its own alphabet. Asked of the name as it is stored, in capitals.
var handNamed = regexp.MustCompile(
	`^(CVE-[0-9]{4}-[0-9]{4,}|GHSA(-[23456789CFGHJMPQRVWX]{4}){3})$`)

// AlsoKnownAs records another name for an issue.
//
// A CVE assigned after we minted our own identifier is the case this exists
// for. The code anticipated it and nothing implemented it, so a published
// advisory shipped an internal identifier and no CVE — and nobody searching by
// the CVE found the advisory, which is the one lookup a published advisory
// exists to serve. It is also how the identifier a reporter and a coordinator
// are already using reaches a record opened before either existed.
//
// Nothing about the finding, the decisions or the approvals moves, because
// they are keyed on the issue rather than on what it is called. What
// changes is that a report arriving under the new name resolves here rather
// than opening a second issue.
//
// The issue is refiled under the better-known name, by the same rule a
// scanner's later report already follows: what somebody sees should be the
// name they will find in an advisory. The name it was filed under
// stays an alias, so nothing that used it stops resolving.
//
// Recording a name it already goes by is not a failure — the state asked for
// is the state that holds — and recording one another issue holds is refused
// rather than silently merging two records.
func (v *Vulnerabilities) AlsoKnownAs(ctx context.Context, subject access.Subject,
	id int64, alias string) error {

	name := normalize(alias)
	if name == "" {
		return refusal.Errorf("a name has to say something")
	}
	if !handNamed.MatchString(name) {
		return ErrNotAHandName
	}

	// One act, one transaction, through the one helper. Recording the name
	// and refiling the issue under it are two statements and half of them
	// is a wrong state that nothing reports: the alias recorded and the
	// issue still filed under the name it is meant to have left.
	// Everything it decides from is read inside, because a retry runs
	// against a database that has moved and one of those reads is whether
	// the name is free .
	return database.Within(ctx, v.db, func(ctx context.Context, tx bun.IDB) error {
		var issue Vulnerability
		if err := tx.NewSelect().Model(&issue).Where(`"id" = ?`, id).Scan(ctx); err != nil {
			return fmt.Errorf("read what this issue is: %w", err)
		}

		// Every product this issue is open in, not the one in the path.
		// A name is identity, and identity is deployment-wide: from here on
		// a scan of any product reporting that name resolves to this issue
		// and inherits its decisions and its approvals. Held at a role on
		// one product, this let somebody who holds nothing in another change
		// what a finding there means. So the act asks for triage everywhere
		// it reaches, and refuses rather than doing part of it.
		//
		// Read inside the transaction with everything else it decides from.
		if err := triagesEverywhere(ctx, tx, subject, id); err != nil {
			return err
		}
		// Only an issue a person recorded. A scanner's issue is named by the
		// scans that report it; a name typed onto one would redirect every
		// scan reporting it, in every product, on one person's word.
		recorded, err := recordedByHand(ctx, tx, id)
		if err != nil {
			return err
		}
		if !recorded {
			return ErrScannerIssue
		}

		// held is whether anything already answers to it. Asked before
		// the write rather than left to the unique constraint, because
		// the answer decides between "already recorded" and "that
		// would merge two issues", and a constraint violation cannot
		// tell those apart.
		var held Alias
		switch err := tx.NewSelect().Model(&held).
			Where(`"identifier" = ?`, name).Scan(ctx); {
		case database.IsNoRows(err):
			if _, err := tx.NewInsert().Model(&Alias{
				VulnerabilityID: id, Identifier: name,
				IdentifierFolded: FoldIdentifier(name), ByHand: true,
			}).Exec(ctx); err != nil {
				return fmt.Errorf("record the name %q goes by: %w", name, err)
			}
		case err != nil:
			return fmt.Errorf("read what goes by that name: %w", err)
		case held.VulnerabilityID != id:
			return ErrNameTaken
		}

		if preferred(Named{Identifier: issue.Identifier, Aliases: []string{name}}) != name {
			return nil
		}
		if _, err := tx.NewUpdate().Model((*Vulnerability)(nil)).
			Set(`"identifier" = ?`, name).
			Set(`"identifier_folded" = ?`, FoldIdentifier(name)).
			Where(`"id" = ?`, id).Exec(ctx); err != nil {
			if database.IsDuplicate(err) {
				return ErrNameTaken
			}
			return fmt.Errorf("file it under %q: %w", name, err)
		}
		return nil
	})
}

// NoLongerKnownAs removes a name somebody recorded by hand for an issue.
//
// The same right recording it asks: triage in every product the issue is open
// in, because taking a name away changes what a later scan reporting it
// resolves to in all of them. Findings that resolved here through the name
// split back out on the next scan that reports it, which opens them under an
// issue of their own.
//
// A name a scan reported is refused, because the next scan reporting it would
// only record it again; that includes the name the issue is filed under when a
// scan reported it. A typed name the issue is filed under is removed, and the
// issue refiled under the next best name it has. It answers the name the issue
// is filed under afterwards.
func (v *Vulnerabilities) NoLongerKnownAs(ctx context.Context, subject access.Subject,
	id int64, alias string) (string, error) {

	name := normalize(alias)
	filedUnder := ""
	err := database.Within(ctx, v.db, func(ctx context.Context, tx bun.IDB) error {
		filedUnder = ""
		var issue Vulnerability
		if err := tx.NewSelect().Model(&issue).Where(`"id" = ?`, id).Scan(ctx); err != nil {
			return fmt.Errorf("read what this issue is: %w", err)
		}
		if err := triagesEverywhere(ctx, tx, subject, id); err != nil {
			return err
		}
		var held Alias
		err := tx.NewSelect().Model(&held).
			Where(`"va"."identifier" = ?`, name).
			Where(`"va"."vulnerability_id" = ?`, id).Scan(ctx)
		if err != nil {
			return database.FromRead(err, ErrNoSuchName, "read the name")
		}
		if !held.ByHand {
			if held.Identifier == issue.Identifier {
				return ErrFiledUnder
			}
			return ErrNotByHand
		}
		if _, err := tx.NewDelete().Model((*Alias)(nil)).
			Where(`"id" = ?`, held.ID).Exec(ctx); err != nil {
			return fmt.Errorf("remove the name %q: %w", name, err)
		}
		filedUnder = issue.Identifier
		if held.Identifier != issue.Identifier {
			return nil
		}
		// The name it was filed under is gone, so it is filed under the next
		// best of what remains: a CVE where one is left, and otherwise the
		// oldest name, which for a flaw recorded here is the reference it
		// was minted under.
		var left []string
		if err := tx.NewSelect().Model((*Alias)(nil)).
			ColumnExpr(`"va"."identifier"`).
			Where(`"va"."vulnerability_id" = ?`, id).
			OrderExpr(`"va"."id" ASC`).
			Scan(ctx, &left); err != nil {
			return fmt.Errorf("read what else it is called: %w", err)
		}
		if len(left) == 0 {
			return ErrFiledUnder
		}
		filedUnder = preferred(Named{Identifier: left[0], Aliases: left[1:]})
		if _, err := tx.NewUpdate().Model((*Vulnerability)(nil)).
			Set(`"identifier" = ?`, filedUnder).
			Set(`"identifier_folded" = ?`, FoldIdentifier(filedUnder)).
			Where(`"id" = ?`, id).Exec(ctx); err != nil {
			return fmt.Errorf("file it under %q: %w", filedUnder, err)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return filedUnder, nil
}

// recordedByHand reports whether a person recorded this issue: whether any
// finding of it, open or closed, is one somebody entered.
func recordedByHand(ctx context.Context, db bun.IDB, id int64) (bool, error) {
	recorded, err := db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Where(HeldAs(`"f"."vulnerability_id"`), id).
		Where(`"f"."kind" = ?`, Entered).
		Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("read whether this issue was recorded here: %w", err)
	}
	return recorded, nil
}

// triagesEverywhere refuses unless the subject may argue about this issue in
// every product it is open in.
//
// At the visibility each finding carries, because an issue open undisclosed
// somewhere is one only a private triager there may act on.
func triagesEverywhere(ctx context.Context, db bun.IDB, subject access.Subject,
	vulnerabilityID int64) error {

	if subject.Kind != access.Person {
		return access.Denied("record another name for an issue")
	}
	var reaches []struct {
		ProductID  int64  `bun:"product_id"`
		Visibility string `bun:"visibility"`
	}
	if err := db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON "tg"."id" = "f"."target_id"`).
		Join(`JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"`).
		ColumnExpr(`"st"."product_id" AS "product_id"`).
		ColumnExpr(`"f"."visibility" AS "visibility"`).
		Where(`"f"."vulnerability_id" = ?`, vulnerabilityID).
		Where(`"f"."closed_at" IS NULL`).
		GroupExpr(`"st"."product_id", "f"."visibility"`).
		Scan(ctx, &reaches); err != nil {
		return fmt.Errorf("read where this issue is open: %w", err)
	}
	for _, at := range reaches {
		if !subject.Triages(access.AsVisibility(at.Visibility), at.ProductID) {
			return access.Denied(
				"record another name for an issue open in a product you do not triage")
		}
	}
	return nil
}
