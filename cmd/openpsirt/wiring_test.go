// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
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

// A server that fails to serve after its port opened stops what it started
// beside it and waits for it before returning, so the caller's deferred close
// does not take the database from under a worker mid-query.
func TestAFailureToServeStopsTheWorkersBeforeReturning(t *testing.T) {
	server := opened(t, config.Config{Addr: "127.0.0.1:0", ShutdownGrace: 2 * time.Second})
	var stopped atomic.Bool
	err := serveBeside(t.Context(), server.cfg, discard(), server.l,
		func(ctx context.Context) *sync.WaitGroup {
			var workers sync.WaitGroup
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-ctx.Done()
				time.Sleep(50 * time.Millisecond) // a query finishing
				stopped.Store(true)
			}()
			server.l.failed <- errors.New("accept: the listener failed")
			return &workers
		})
	if err == nil {
		t.Fatal("a server that failed to serve reported no error")
	}
	if !stopped.Load() {
		t.Error("serve returned while a worker it started was still running")
	}
}

// A worker that does not stop within the grace after a failure to serve fails
// the exit, rather than being waited on for ever.
func TestAWorkerThatOverrunsTheGraceAfterAFailureToServeFailsTheExit(t *testing.T) {
	server := opened(t, config.Config{Addr: "127.0.0.1:0", ShutdownGrace: 50 * time.Millisecond})
	release := make(chan struct{})
	defer close(release)
	err := serveBeside(t.Context(), server.cfg, discard(), server.l,
		func(context.Context) *sync.WaitGroup {
			var workers sync.WaitGroup
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-release
			}()
			server.l.failed <- errors.New("accept: the listener failed")
			return &workers
		})
	if err == nil || !strings.Contains(err.Error(), "did not stop within") {
		t.Errorf("an overrunning worker answered %v", err)
	}
}

// An address somebody else holds is refused as the port is opened, before
// anything is started beside it.
func TestAnAddressSomebodyHoldsIsRefusedAsThePortOpens(t *testing.T) {
	if l, err := listen(taken(t), discard(), http.NotFoundHandler()); err == nil {
		_ = l.srv.Close()
		t.Fatal("an address somebody else holds was listened on")
	}
}

// openPort is a server whose port is open, and the configuration it was opened
// under, closed when the test ends.
type openPort struct {
	cfg config.Config
	l   *listening
}

func opened(t *testing.T, cfg config.Config) openPort {
	t.Helper()
	l, err := listen(cfg, discard(), http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.srv.Close() })
	return openPort{cfg: cfg, l: l}
}

// A signal ends serving. The parent ending stands in for it here, because it
// takes the same path.
func signalled(t *testing.T, worker func(ctx context.Context)) error {
	t.Helper()
	parent, cancel := context.WithCancel(t.Context())
	defer cancel()
	server := opened(t, config.Config{Addr: "127.0.0.1:0", ShutdownGrace: 50 * time.Millisecond})
	return serveBeside(parent, server.cfg, discard(), server.l,
		func(ctx context.Context) *sync.WaitGroup {
			var workers sync.WaitGroup
			workers.Add(1)
			go func() {
				defer workers.Done()
				worker(ctx)
			}()
			cancel()
			return &workers
		})
}

// A worker still running past the grace after a signal fails the exit, as an
// overrun request does, so a supervisor reading the exit code sees it.
func TestAWorkerThatOverrunsTheGraceAfterASignalFailsTheExit(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	err := signalled(t, func(context.Context) { <-release })
	if err == nil || !strings.Contains(err.Error(), "did not stop within") {
		t.Errorf("an overrunning worker answered %v", err)
	}
}

// A worker that stops when asked lets a signalled server exit cleanly.
func TestAWorkerThatStopsWhenSignalledLeavesACleanExit(t *testing.T) {
	if err := signalled(t, func(ctx context.Context) { <-ctx.Done() }); err != nil {
		t.Errorf("a server whose worker stopped answered %v", err)
	}
}

// The role mode is read at each use, and a read that fails answers with the
// mode that derives nothing: a store that cannot answer must not keep deriving
// roles from groups somebody turned off.
func TestARoleModeThatCannotBeReadDerivesNothing(t *testing.T) {
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		store := setting.NewStore(db.DB)
		if _, _, err := store.Change(t.Context(), setting.RoleMode, string(access.GroupBound)); err != nil {
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
