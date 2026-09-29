// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"

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
