// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/config"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// An address somebody else holds, and the configuration that asks for it.
func taken(t *testing.T) config.Config {
	t.Helper()
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Close() })
	return config.Config{Addr: held.Addr().String(), ShutdownGrace: 2 * time.Second}
}

// A server that cannot listen stops what it started beside it and waits for it
// before returning, so the caller's deferred close does not take the database
// from under a worker mid-query.
func TestAFailedListenStopsTheWorkersBeforeReturning(t *testing.T) {
	var stopped atomic.Bool
	err := serveBeside(taken(t), discard(), http.NotFoundHandler(),
		func(ctx context.Context) *sync.WaitGroup {
			var workers sync.WaitGroup
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-ctx.Done()
				time.Sleep(50 * time.Millisecond) // a query finishing
				stopped.Store(true)
			}()
			return &workers
		})
	if err == nil {
		t.Fatal("a server whose address was taken reported no error")
	}
	if !stopped.Load() {
		t.Error("serve returned while a worker it started was still running")
	}
}

// A worker that does not stop within the grace fails the exit, as an overrun
// request does, rather than being waited on for ever.
func TestAWorkerThatOverrunsTheGraceFailsTheExit(t *testing.T) {
	cfg := taken(t)
	cfg.ShutdownGrace = 50 * time.Millisecond
	release := make(chan struct{})
	defer close(release)
	err := serveBeside(cfg, discard(), http.NotFoundHandler(),
		func(context.Context) *sync.WaitGroup {
			var workers sync.WaitGroup
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-release
			}()
			return &workers
		})
	if err == nil || !strings.Contains(err.Error(), "did not stop within") {
		t.Errorf("an overrunning worker answered %v", err)
	}
}

// The role mode is read at each use, and a read that fails answers with the
// mode that derives nothing: a store that cannot answer must not keep deriving
// roles from groups somebody turned off.
func TestARoleModeThatCannotBeReadDerivesNothing(t *testing.T) {
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		store := setting.NewStore(db.DB)
		if err := store.Set(t.Context(), setting.RoleMode, string(access.GroupBound)); err != nil {
			t.Fatal(err)
		}
		mode := roleMode(store)
		if got := mode(t.Context()); got != access.GroupBound {
			t.Fatalf("a stored mode read as %q", got)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if got := mode(t.Context()); got != access.Direct {
			t.Errorf("a mode that could not be read answered %q, want %q", got, access.Direct)
		}
	})
}

// No mail configured is no channel: an interface holding nothing, not one
// holding a nil pointer, which reads as a channel to whatever asks.
func TestNoMailConfiguredIsNoChannel(t *testing.T) {
	if ch := mailChannel(config.Config{}, discard()); ch != nil {
		t.Errorf("no mail configured answered a channel: %#v", ch)
	}
	ch := mailChannel(config.Config{MailServer: "smtp.example.test:587", MailFrom: "psirt@example.test"}, discard())
	if ch == nil {
		t.Error("mail configured answered no channel")
	}
}

// A deployment that names a bucket and a directory for attachments means the
// bucket: the directory is the development backend.
func TestTheBucketWinsWhereBothAreSet(t *testing.T) {
	store := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer store.Close()
	got, err := attachmentStore(t.Context(), config.Config{Attachments: config.Store{
		Dir:       t.TempDir(),
		Endpoint:  store.URL,
		Bucket:    "attachments",
		Region:    "us-east-1",
		Key:       "key",
		Secret:    "secret",
		PathStyle: true,
	}}, discard())
	if err != nil {
		t.Fatal(err)
	}
	if _, bucket := got.(*attach.Bucket); !bucket {
		t.Errorf("with both set, attachments are held in %T", got)
	}
	only, err := attachmentStore(t.Context(), config.Config{Attachments: config.Store{Dir: t.TempDir()}}, discard())
	if err != nil {
		t.Fatal(err)
	}
	if _, bucket := only.(*attach.Bucket); bucket || only == nil {
		t.Errorf("with a directory alone, attachments are held in %T", only)
	}
}

// The published directory is written nowhere where nothing is configured, and
// to the directory named where one is.
func TestTheDirectoryIsWrittenWhereItIsConfigured(t *testing.T) {
	none, err := directoryStore(t.Context(), config.Config{}, discard())
	if err != nil || none != nil {
		t.Errorf("nothing configured answered %T (%v)", none, err)
	}
	local, err := directoryStore(t.Context(), config.Config{Directory: config.Store{Dir: t.TempDir()}}, discard())
	if err != nil {
		t.Fatal(err)
	}
	if local == nil {
		t.Error("a configured directory answered no store")
	}
}
