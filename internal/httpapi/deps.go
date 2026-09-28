// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"log/slog"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/currency"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/outward"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/signin"
)

// Ingest is what every route runs on: the database, the queue, the caller
// resolver and the rest of what a handler reads.
type Ingest struct {
	// Chats is the chat platforms this deployment holds a credential for,
	// which a destination and a person's own chat settings are checked
	// against.
	Chats  []string
	DB     *database.DB
	Queue  *queue.Queue
	Limits sbom.Limits
	// Access resolves the caller. A nil resolver authorizes nothing, the only
	// safe answer from a process with no way to identify a caller.
	Access *access.Resolver
	// Logger records a fault where an operator can read it, rather than
	// describing it to whoever asked.
	Logger *slog.Logger
	// Replica names this process where several run the same binary, so work
	// that must happen once can be held by one of them. Empty is a deployment
	// of one: a test, and a development run.
	Replica string
	// PlainHTTP serves this deployment without TLS, the ordinary shape of a
	// local run. It only ever loosens a cookie, so it is
	// named for what it is rather than for what it switches off.
	PlainHTTP bool
	// Interface is the built web interface, where this binary was built with
	// one. Zero serves the API alone: a development build, or a deployment
	// that offers the API and nothing else.
	Interface Interface
	// Providers are the ways somebody may sign in, by the name a URL uses.
	// Empty means none is configured, and the sign-in paths are not mounted at
	// all rather than mounted and answering that nothing is available.
	Providers map[string]signin.Provider
	// BaseURL is the address people arrive on, which behind a proxy differs
	// from this process's own name for itself. A provider compares the callback
	// against what it was registered with, so this has to be the outside one.
	BaseURL string
	// SessionLifetime bounds a sign-in. Zero takes the default.
	SessionLifetime time.Duration
	// Publisher is who an advisory says issued it. Unstated means no advisory
	// is generated, and the refusal says which part is missing — a document
	// naming no publisher is not a CSAF document, and handing one over would
	// fail wherever somebody took it next.
	Publisher publisher.Named
	// Ours is the set this deployment calls its own, and so never sends to a
	// public package index. The same value the asking pass holds, derived
	// once where the configuration is read: two derivations of one boundary
	// are two boundaries the first time either moves.
	Ours currency.Ours
	// Excluded is where no repository a patch link names is fetched from. The
	// same value the fetching pass holds, so the report of what is fetched
	// from where says what the pass does.
	Excluded outward.Excluded
	// PatchBranches is whether the deployment turned the patch branch
	// lookups on. The same value the fetching pass holds.
	PatchBranches bool
	// Mode says where roles come from. Read per request rather than held, so
	// an administrator turning group binding off takes effect at once.
	Mode func(context.Context) access.Mode
	// Files is where attachments are kept. Nil is a deployment that holds
	// none, which is ordinary: attachments are off and everything else
	// works.
	Files attach.Storage
}

// attachments returns a store over the files this deployment holds, or nothing
// where there is no database. A nil Storage inside it is the deployment that
// configured none, and every path through it refuses in the same words.
func (in Ingest) attachments() *attach.Store {
	if in.DB == nil {
		return nil
	}
	return attach.NewStore(in.DB.DB, in.Files)
}

// catalog returns a store over the handle it is given, or nothing when there
// is none — which is the process that only renders the API document.
//
// The handle is the transaction an administrative act is being made in, or
// this deployment's pooled one where the route only reads.
func (in Ingest) catalog(db bun.IDB) *catalog.Store {
	if in.DB == nil || db == nil {
		return nil
	}
	return catalog.NewStore(db)
}

// settings returns a store over what an operator has set, or nothing where
// there is no database.
func (in Ingest) settings(db bun.IDB) *setting.Store {
	if in.DB == nil || db == nil {
		return nil
	}
	return setting.NewStore(db)
}

// logger is where this process writes, and never nil.
//
// A handler that logs must not have to remember. A process built without a
// logger — the one that renders the API document — panics into the recovery
// middleware and answers 500 where the route has words for a refusal, wherever
// a site forgets the `if in.Logger != nil` guard. A no-op logger makes the
// omission impossible rather than rare.
func (in Ingest) logger() *slog.Logger {
	if in.Logger != nil {
		return in.Logger
	}
	return slog.New(slog.DiscardHandler)
}

// groupsReachable reports a source of group membership: a provider carrying
// one, or a trusted proxy that states it.
//
// Asked before roles are switched to group-bound. Without a source every
// arrival belongs to nothing, so nobody derives any role and the deployment
// locks itself out — including whoever made the change.
func (in Ingest) groupsReachable() bool {
	for _, provider := range in.Providers {
		if provider.GroupsSource() {
			return true
		}
	}
	return in.Access != nil && in.Access.ReportsGroups()
}

// rights returns a store over who may do what, built over the handle it is
// given, or nothing where there is none.
func (in Ingest) rights(db bun.IDB) *access.Store {
	if in.DB == nil || db == nil {
		return nil
	}
	return access.NewStore(db)
}

// handle is the database a read-only route builds its stores over.
//
// Named rather than written as in.DB at each site: a nil *database.DB handed
// to an interface parameter is an interface that is not nil, so every check
// below it reads as a database that is there.
func (in Ingest) handle() bun.IDB {
	if in.DB == nil {
		return nil
	}
	return in.DB.DB
}
