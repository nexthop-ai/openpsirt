// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"log/slog"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// Changing runs one administrative act and the record of it in one
// transaction.
//
// A failure to record fails the act. Both are one change: a setting moved with
// nobody recorded as having moved it is exactly the state REQ-22 says the
// record exists to prevent, and it is reachable by a write that succeeds
// beside a record that does not. Answering with an error invites a retry,
// which is what the retry is for — nothing was committed.
//
// The act is written against the transaction rather than against the handle,
// so everything it decides from is read inside it (REQ-71).
func Changing(ctx context.Context, db *database.DB, logger *slog.Logger,
	do func(ctx context.Context, tx bun.Tx) error) error {

	if db == nil {
		return NoDatabase(logger)
	}
	return database.InTransaction(ctx, db.DB, do)
}

// Noted records an administrative act against whoever made it, in the
// transaction that made it.
//
// Called from the request rather than from the store underneath. The stores
// take no subject — a setting write knows the name and the value and nothing
// about who is asking — and threading one through every one of them to reach
// this would make those signatures about auditing rather than about the thing
// being written. The cost is that a new administrative route can forget, so a
// test walks the routes and asserts each leaves a row.
func Noted(ctx context.Context, tx bun.IDB, kind trail.Kind, name string, was, became *string) error {
	by, err := Reading(ctx)
	if err != nil {
		return err
	}
	return trail.NewStore(tx).Record(ctx, by, kind, name, was, became)
}

// NotRecorded refuses an act whose record could not be written.
//
// The act is rolled back with it, so the sentence says that: a caller told
// only that recording failed would be left wondering which of the two stood.
func NotRecorded(logger *slog.Logger, err error) error {
	return WentWrong(logger, "that change could not be recorded, so it was not made", err)
}

// DayOf is a moment as the day it falls on, or nothing where there is none.
func DayOf(at *time.Time) string {
	if at == nil || at.IsZero() {
		return ""
	}
	return at.UTC().Format(time.DateOnly)
}

// LabelBeside is a display name for the field beside an identity: empty where
// it would repeat the identity, so that an absent label keeps meaning "no
// display name" rather than "the same again".
func LabelBeside(name, handle string) string {
	if name == handle {
		return ""
	}
	return name
}
