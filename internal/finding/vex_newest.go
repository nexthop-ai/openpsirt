// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// heldByItsDocument chooses the statements a document still makes: those in
// force, and those a newer statement from the same publisher overtook, which
// a revision repeating them keeps. A statement its own document's revision
// set aside is in neither.
const heldByItsDocument = `("superseded_at" IS NULL OR "overtaken_by" IS NOT NULL)`

// subjectOf is what a statement is about: the issue, the component at the
// version named, and the product it ships inside. Two statements from one
// publisher with one subject say two things about one thing, and only the
// newer stands.
func subjectOf(one Statement) string {
	return strings.Join([]string{one.Vulnerability, one.Purl, one.Component, one.About,
		one.WithinPurl, one.Within, one.WithinAbout}, "\x00")
}

// newer reports whether a was made after b: by when the publisher says each
// was made, else by when each arrived, then by which was recorded last.
func newer(a, b Statement) bool {
	moment := func(one Statement) time.Time {
		if one.SaidAt != nil {
			return *one.SaidAt
		}
		return one.UploadedAt
	}
	if c := moment(a).Compare(moment(b)); c != 0 {
		return c > 0
	}
	return a.ID > b.ID
}

// statementsPerSubjectRead bounds how many issues one read of a publisher's
// statements names.
const statementsPerSubjectRead = 500

// newestStands leaves in force only the publisher's newest statement about
// each subject the touched statements are about, in documents of one kind
// (REQ-31): every older one is set aside as overtaken by it, and one overtaken
// before that is now the newest is restored. A revision withdrawing the newest
// therefore restores the one it overtook. It answers how many statements it
// set aside that were in force.
func newestStands(ctx context.Context, tx bun.IDB, productID int64, publisher, source string,
	touched []Statement, now time.Time) (int, error) {

	subjects := map[string]bool{}
	var issues []string
	for _, one := range touched {
		subjects[subjectOf(one)] = true
		issues = append(issues, one.Vulnerability)
	}
	if len(subjects) == 0 {
		return 0, nil
	}
	slices.Sort(issues)
	issues = slices.Compact(issues)

	var standing []Statement
	for from := 0; from < len(issues); from += statementsPerSubjectRead {
		to := min(from+statementsPerSubjectRead, len(issues))
		var batch []Statement
		if err := tx.NewSelect().Model(&batch).
			Column("id", "vulnerability", "purl", "component", "about", "within_purl", "within",
				"within_about", "said_at", "uploaded_at", "superseded_at", "overtaken_by").
			Where(`"product_id" = ?`, productID).
			Where(`"publisher" = ?`, publisher).
			Where(`"source" = ?`, source).
			Where(`"vulnerability" IN (?)`, bun.List(issues[from:to])).
			Where(heldByItsDocument).
			Scan(ctx); err != nil {
			return 0, fmt.Errorf("read what the publisher has said about these issues: %w", err)
		}
		standing = append(standing, batch...)
	}

	bySubject := map[string][]Statement{}
	for _, one := range standing {
		if key := subjectOf(one); subjects[key] {
			bySubject[key] = append(bySubject[key], one)
		}
	}
	var restored []int64
	overtaken := map[int64][]int64{}
	setAside := 0
	for _, said := range bySubject {
		newest := said[0]
		for _, one := range said[1:] {
			if newer(one, newest) {
				newest = one
			}
		}
		if newest.Superseded != nil {
			restored = append(restored, newest.ID)
		}
		for _, one := range said {
			if one.ID == newest.ID {
				continue
			}
			if one.Superseded == nil {
				setAside++
			} else if one.OvertakenBy != nil && *one.OvertakenBy == newest.ID {
				continue
			}
			overtaken[newest.ID] = append(overtaken[newest.ID], one.ID)
		}
	}

	slices.Sort(restored)
	if err := database.IDsInBatches(ctx, restored, func(ctx context.Context, batch []int64) error {
		_, err := tx.NewUpdate().Model((*Statement)(nil)).
			Set(`"superseded_at" = NULL`).
			Set(`"overtaken_by" = NULL`).
			Where(`"id" IN (?)`, bun.List(batch)).Exec(ctx)
		return err
	}); err != nil {
		return 0, fmt.Errorf("restore what the publisher said last: %w", err)
	}
	newests := make([]int64, 0, len(overtaken))
	for id := range overtaken {
		newests = append(newests, id)
	}
	slices.SortFunc(newests, cmp.Compare)
	for _, by := range newests {
		ids := overtaken[by]
		slices.Sort(ids)
		if err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
			_, err := tx.NewUpdate().Model((*Statement)(nil)).
				Set(`"superseded_at" = COALESCE("superseded_at", ?)`, now).
				Set(`"overtaken_by" = ?`, by).
				Where(`"id" IN (?)`, bun.List(batch)).Exec(ctx)
			return err
		}); err != nil {
			return 0, fmt.Errorf("set aside what the publisher said before: %w", err)
		}
	}
	return setAside, nil
}
