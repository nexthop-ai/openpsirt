// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// signedAs is a set of people by the identity they sign in under, with the
// display name each is shown under.
//
// Every field naming a person carries the identity, and the label goes beside
// it in a field of its own. The identity is what a route resolves and what a
// screen compares against the viewer's own, so a label in its place is a
// value a caller can show and cannot act on.
type signedAs struct {
	handles, names map[int64]string
}

// WhoSigned reads the identities and display names of these people.
func WhoSigned(ctx context.Context, db bun.IDB, ids []int64) (signedAs, error) {
	rights := access.NewStore(db)
	handles, err := rights.Handles(ctx, ids)
	if err != nil {
		return signedAs{}, err
	}
	names, err := rights.Names(ctx, ids)
	if err != nil {
		return signedAs{}, err
	}
	return signedAs{handles: handles, names: names}, nil
}

// Identity is the name this person signs in under.
func (s signedAs) Identity(id int64) string {
	return s.handles[id]
}

// Label is this person's display name, or empty where they have none.
func (s signedAs) Label(id int64) string {
	return LabelBeside(s.names[id], s.handles[id])
}

// Writing is one piece of text somebody wrote here and may have edited since:
// a note on an issue, a comment on a claim.
type Writing struct {
	ID        int64
	Body      string
	WrittenBy int64
	WrittenAt time.Time
	EditedAt  *time.Time
}

// WrittenBody is one piece of text as the API states it, with its author named.
type WrittenBody struct {
	ID            int64  `json:"id"`
	Body          string `json:"body" doc:"The text, in markdown"`
	WrittenBy     string `json:"written_by" doc:"The author, by sign-in identity"`
	WrittenByName string `json:"written_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	WrittenAt     string `json:"written_at"`
	EditedAt      string `json:"edited_at,omitempty" doc:"The moment the author last changed it, where they have"`
}

// Written renders writings in the order given, naming their authors in one
// lookup. unreadable is the fault the answer gives where the names cannot be
// read.
func Written(ctx context.Context, in Deps, rows []Writing, unreadable string) (*ListOutput[WrittenBody], error) {
	authors := make([]int64, 0, len(rows))
	for _, row := range rows {
		authors = append(authors, row.WrittenBy)
	}
	who, err := WhoSigned(ctx, in.DB.DB, authors)
	if err != nil {
		return nil, WentWrong(in.Logger, unreadable, err)
	}
	out := &ListOutput[WrittenBody]{}
	out.Body.Items = make([]WrittenBody, 0, len(rows))
	for _, row := range rows {
		out.Body.Items = append(out.Body.Items, WrittenBody{
			ID: row.ID, Body: row.Body,
			WrittenBy:     who.Identity(row.WrittenBy),
			WrittenByName: who.Label(row.WrittenBy),
			WrittenAt:     Stamp(row.WrittenAt),
			EditedAt:      StampAt(row.EditedAt),
		})
	}
	return out, nil
}
