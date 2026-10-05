// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package core holds what every area of the API shares: the dependencies a
// handler runs on, resolving a caller and the rights an operation declares,
// the sentences a refusal is answered in, and the bodies and helpers more than
// one area uses. It imports no other package of the API.
package core

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

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
	"github.com/uptrace/bun"
)

// Deps is what every route runs on: the database, the queue, the caller
// resolver and the rest of what a handler reads.
type Deps struct {
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
	// Mode says where roles come from. Read per request rather than held,
	// because replicas restart one at a time and the one that applied
	// configuration last is what every replica answers by.
	Mode func(context.Context) access.Mode
	// Files is where attachments are kept. Nil is a deployment that holds
	// none, which is ordinary: attachments are off and everything else
	// works.
	Files attach.Storage
}

// Attachments returns a store over the files this deployment holds, or nothing
// where there is no database. A nil Storage inside it is the deployment that
// configured none, and every path through it refuses in the same words.
func (in Deps) Attachments() *attach.Store {
	if in.DB == nil {
		return nil
	}
	return attach.NewStore(in.DB.DB, in.Files)
}

// Catalog returns a store over the handle it is given, or nothing when there
// is none — which is the process that only renders the API document.
//
// The handle is the transaction an administrative act is being made in, or
// this deployment's pooled one where the route only reads.
func (in Deps) Catalog(db bun.IDB) *catalog.Store {
	if in.DB == nil || db == nil {
		return nil
	}
	return catalog.NewStore(db)
}

// Settings returns a store over what an operator has set, or nothing where
// there is no database.
func (in Deps) Settings(db bun.IDB) *setting.Store {
	if in.DB == nil || db == nil {
		return nil
	}
	return setting.NewStore(db)
}

// Log is where this process writes, and never nil.
//
// A handler that logs must not have to remember. A process built without a
// logger — the one that renders the API document — panics into the recovery
// middleware and answers 500 where the route has words for a refusal, wherever
// a site forgets the `if in.Logger != nil` guard. A no-op logger makes the
// omission impossible rather than rare.
func (in Deps) Log() *slog.Logger {
	if in.Logger != nil {
		return in.Logger
	}
	return slog.New(slog.DiscardHandler)
}

// Rights returns a store over who may do what, built over the handle it is
// given, or nothing where there is none.
func (in Deps) Rights(db bun.IDB) *access.Store {
	if in.DB == nil || db == nil {
		return nil
	}
	return access.NewStore(db)
}

// Handle is the database a read-only route builds its stores over.
//
// Named rather than written as in.DB at each site: a nil *database.DB handed
// to an interface parameter is an interface that is not nil, so every check
// below it reads as a database that is there.
func (in Deps) Handle() bun.IDB {
	if in.DB == nil {
		return nil
	}
	return in.DB.DB
}

// RedirectURI is where the provider sends the browser back to.
//
// Built from the configured base address where there is one. A provider
// compares this against what it was registered with, so it has to be the
// address people actually arrive on rather than whatever this process thinks
// it is called — behind a proxy those differ.
func (in Deps) RedirectURI(r *http.Request, provider string) (string, error) {
	base := strings.TrimSuffix(in.BaseURL, "/")
	if base == "" {
		// The Host header is whatever the caller sent. Building the address a
		// provider will send somebody back to out of it means a request
		// claiming another host produces an authorization URL pointing there,
		// and whether that is exploitable depends entirely on how strictly the
		// provider matches its registered addresses — which is not ours to
		// assume.
		//
		// So a deployment that configured a provider has to say where it is
		// served. It is one setting, it is already needed for the provider's
		// own registration to match, and failing here is visible where the
		// alternative is not.
		return "", errors.New("this deployment has not been told the address it is served on")
	}
	return base + "/v1/sign-in/" + provider + "/callback", nil
}

// Interface serves the built web interface.
//
// Embedded into the binary by whoever builds it and handed in here, rather
// than embedded in this package: a build that has not run the frontend still
// has to compile and serve the API, and //go:embed of a missing directory is a
// compile error rather than an empty filesystem.
type Interface struct {
	// Files is the built output — index.html at its root. Nil serves nothing,
	// which is what a development build or an API-only deployment gets.
	Files fs.FS
}
