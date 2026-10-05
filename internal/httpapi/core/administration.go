// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"log/slog"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// Administering carries what the endpoints for people and credentials run on.
type Administering struct {
	// DB is the database an administrative act and the record of it are
	// written on, in one transaction. Nil where this process has no database,
	// and then every route here refuses rather than changing anything.
	DB *database.DB
	// Access and Catalog are built over whatever handle the caller is
	// writing on: the transaction, where the act is being made, and the
	// pooled handle where it is only being read.
	Access  func(bun.IDB) *access.Store
	Catalog func(bun.IDB) *catalog.Store
	Logger  *slog.Logger
	// Findings is the store the withdrawal of somebody's last role on a
	// product runs against: their work goes back to the unassigned list
	// rather than staying where nobody can reach it. Nil where this process
	// has no database, and then nothing is released.
	//
	// Over the pooled handle rather than the act's transaction: handing work
	// back is a consequence of the withdrawal rather than part of it, and it
	// is bounded by how much that person was holding rather than by the
	// request.
	Findings func() *finding.Store
	// Settings is where the window an unredeemed authorization stays
	// redeemable for is read. Nil where this process has no database, and
	// then the built-in window applies.
	Settings func(bun.IDB) *setting.Store
}

// Handle is the database a read-only route builds its stores over.
//
// Named rather than written as a.DB at each site: a nil *database.DB handed to
// an interface parameter is an interface that is not nil, so every check below
// it reads as a database that is there and every store built over it panics on
// first use.
func (a Administering) Handle() bun.IDB {
	if a.DB == nil {
		return nil
	}
	return a.DB.DB
}

// Administerable refuses anybody who is not an administrator, and hands back
// what the endpoint needs.
//
// Managing who may do what is the one thing that must never be reachable by a
// role granted on a product: somebody who may triage a product must not be
// able to grant themselves more of it.
//
// db is the handle it builds those over: the transaction an act is being made
// in, or handle() where the route only reads.
func Administerable(ctx context.Context, a Administering, db bun.IDB) (*access.Store, *catalog.Store, error) {
	if err := Administrating(ctx); err != nil {
		return nil, nil, err
	}
	return Stores(a, db)
}

// Stores builds the pair over db, or says this process has no database.
func Stores(a Administering, db bun.IDB) (*access.Store, *catalog.Store, error) {
	if a.Access == nil || a.Catalog == nil || db == nil {
		return nil, nil, NoDatabase(a.Logger)
	}
	store, names := a.Access(db), a.Catalog(db)
	if store == nil || names == nil {
		return nil, nil, NoDatabase(a.Logger)
	}
	return store, names, nil
}
