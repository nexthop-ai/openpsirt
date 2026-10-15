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
	// written on, in one transaction.
	DB *database.DB
	// Access and Catalog are built over whatever handle the caller is
	// writing on: the transaction, where the act is being made, and the
	// pooled handle where it is only being read.
	Access  func(bun.IDB) *access.Store
	Catalog func(bun.IDB) *catalog.Store
	Logger  *slog.Logger
	// Findings says whether work is handed back to the unassigned list when
	// somebody can no longer reach it, rather than staying where nobody can.
	// Nil where the routes built over it release nothing.
	//
	// The withdrawal of somebody's last role on a product hands back inside
	// its own transaction, over a store built on it, and reads this only as
	// whether to. A deactivation hands back over this store, on the pooled
	// handle, once the deactivation has committed.
	Findings func() *finding.Store
	// Settings is where the window an unredeemed authorization stays
	// redeemable for is read.
	Settings func(bun.IDB) *setting.Store
}

// Handle is the database a read-only route builds its stores over.
func (a Administering) Handle() bun.IDB {
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
	return a.Access(db), a.Catalog(db), nil
}
