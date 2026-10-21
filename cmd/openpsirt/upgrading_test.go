// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// starting is a start of the server against a SQLite file of its own, with
// the migration held where a test can see it and a stop it can send.
type starting struct {
	addr string
	// entered closes when the migration begins, and release lets it go on.
	entered chan struct{}
	release chan struct{}
	// stop stands in for a stop signal, which takes the same path.
	stop context.CancelFunc
	done chan error
}

// freeAddress is a loopback address nothing listens on.
func freeAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// startHeld starts the server with auto-migration on and its migration held
// until release closes. It is set up for the environment the test names and
// nothing else: one administrator, and no CVE records fetched.
func startHeld(t *testing.T, addr string, migrate func(context.Context, *database.DB, *slog.Logger) error) *starting {
	t.Helper()
	t.Setenv("OPENPSIRT_DATABASE_URL", "sqlite://"+filepath.Join(t.TempDir(), "held.db"))
	t.Setenv("OPENPSIRT_ADDR", addr)
	t.Setenv("OPENPSIRT_AUTO_MIGRATE", "true")
	t.Setenv("OPENPSIRT_RECORDS_UPDATE", "false")
	t.Setenv("OPENPSIRT_RECORDS_DIR", t.TempDir())
	t.Setenv("OPENPSIRT_SHUTDOWN_GRACE", "2s")
	if _, set := os.LookupEnv("OPENPSIRT_BOOTSTRAP_ADMINS"); !set {
		t.Setenv("OPENPSIRT_BOOTSTRAP_ADMINS", "root")
	}

	s := &starting{addr: addr, entered: make(chan struct{}), release: make(chan struct{}),
		done: make(chan error, 1)}
	parent, stop := context.WithCancel(context.Background())
	s.stop = stop
	restoreApply, restoreFrom := applySchema, startedFrom
	applySchema = func(ctx context.Context, db *database.DB, logger *slog.Logger) error {
		close(s.entered)
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
		return migrate(ctx, db, logger)
	}
	startedFrom = func() context.Context { return parent }
	t.Cleanup(func() {
		stop()
		select {
		case <-s.done:
		case <-time.After(30 * time.Second):
			t.Error("the server did not stop within 30s of being told to")
		}
		applySchema, startedFrom = restoreApply, restoreFrom
	})

	quiet, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = quiet.Close() })
	go func() { s.done <- run(nil, quiet, quiet) }()
	return s
}

// entering waits for the held migration to begin.
func (s *starting) entering(t *testing.T) {
	t.Helper()
	select {
	case <-s.entered:
	case err := <-s.done:
		s.done <- err
		t.Fatalf("the start ended before it migrated: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the migration had not begun after 30s")
	}
}

// get asks the server for a path, with an Accept header where one is given.
func (s *starting) get(t *testing.T, path, accept string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+s.addr+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// A start whose migration takes a long time answers its health check while
// the migration runs, says it is not ready, and asks every other caller to
// come back. Once the migration is done, the real routes answer.
func TestAStartAnswersItsHealthCheckWhileItMigrates(t *testing.T) {
	s := startHeld(t, freeAddress(t), schema.Up)
	s.entering(t)

	if resp := s.get(t, "/healthz", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz answered %s while migrating", resp.Status)
	}
	if resp := s.get(t, "/readyz", ""); resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("/readyz answered %s while migrating", resp.Status)
	}
	api := s.get(t, "/v1/version", "")
	if api.StatusCode != http.StatusServiceUnavailable || api.Header.Get("Retry-After") == "" ||
		api.Header.Get("Content-Type") != "application/problem+json" {
		t.Errorf("/v1/version answered %s, Retry-After %q, %q while migrating",
			api.Status, api.Header.Get("Retry-After"), api.Header.Get("Content-Type"))
	}
	page := s.get(t, "/", "text/html")
	if page.StatusCode != http.StatusServiceUnavailable || page.Header.Get("Retry-After") == "" ||
		!strings.HasPrefix(page.Header.Get("Content-Type"), "text/html") {
		t.Errorf("the interface answered %s, Retry-After %q, %q while migrating",
			page.Status, page.Header.Get("Retry-After"), page.Header.Get("Content-Type"))
	}

	close(s.release)
	deadline := time.Now().Add(30 * time.Second)
	for s.get(t, "/readyz", "").StatusCode != http.StatusOK {
		if time.Now().After(deadline) {
			t.Fatal("/readyz was not ready 30s after the migration was let go")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// The router answers: an unsigned request is refused by it, where the
	// upgrading answer would have asked it to come back.
	if resp := s.get(t, "/v1/version", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/v1/version answered %s once the start was complete", resp.Status)
	}
	if resp := s.get(t, "/healthz", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz answered %s once the start was complete", resp.Status)
	}

	s.stop()
	select {
	case err := <-s.done:
		s.done <- err
		if err != nil {
			t.Errorf("a server told to stop answered %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the server did not stop within 30s of being told to")
	}
}

// A stop signal during the migration ends the migration through its context,
// which rolls its transaction back, closes the port, and exits cleanly.
func TestAStopDuringTheMigrationExitsCleanly(t *testing.T) {
	var interrupted atomic.Bool
	s := startHeld(t, freeAddress(t), func(ctx context.Context, _ *database.DB, _ *slog.Logger) error {
		<-ctx.Done()
		interrupted.Store(true)
		return ctx.Err()
	})
	s.entering(t)
	close(s.release)
	if resp := s.get(t, "/healthz", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz answered %s while migrating", resp.Status)
	}

	s.stop()
	select {
	case err := <-s.done:
		s.done <- err
		if err != nil {
			t.Errorf("a stop during the migration answered %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the server did not stop within 30s of being told to")
	}
	if !interrupted.Load() {
		t.Error("the migration was not told to stop")
	}
	if conn, err := net.DialTimeout("tcp", s.addr, time.Second); err == nil {
		_ = conn.Close()
		t.Error("the port was still open after the start stopped")
	}
}

// A refusal the start makes once the schema is in place fails the start, as a
// refusal before the port opened does: the process exits with it, and the
// port closes.
func TestARefusalAfterTheMigrationFailsTheStartAndClosesThePort(t *testing.T) {
	// Nobody named to administer a database nobody administers: refused
	// once the schema is there to read.
	t.Setenv("OPENPSIRT_BOOTSTRAP_ADMINS", "")
	s := startHeld(t, freeAddress(t), schema.Up)
	s.entering(t)
	close(s.release)

	select {
	case err := <-s.done:
		s.done <- err
		if err == nil || !strings.Contains(err.Error(), "nobody can administer") {
			t.Errorf("a start nobody could administer answered %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("a start that should have been refused was still running after 30s")
	}
	if conn, err := net.DialTimeout("tcp", s.addr, time.Second); err == nil {
		_ = conn.Close()
		t.Error("the port was still open after the start was refused")
	}
}

// An address somebody else holds is refused before the migration begins, so a
// start that cannot serve does not spend a migration finding out.
func TestAnAddressSomebodyHoldsIsRefusedBeforeMigrating(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	var migrated atomic.Bool
	s := startHeld(t, held.Addr().String(), func(context.Context, *database.DB, *slog.Logger) error {
		migrated.Store(true)
		return nil
	})
	select {
	case err := <-s.done:
		s.done <- err
		var refused *net.OpError
		if !errors.As(err, &refused) {
			t.Errorf("a start on an address somebody holds answered %v", err)
		}
	case <-s.entered:
		t.Fatal("the migration began on an address somebody else holds")
	case <-time.After(30 * time.Second):
		t.Fatal("a start on an address somebody holds was still running after 30s")
	}
	if migrated.Load() {
		t.Error("the schema was applied on an address somebody else holds")
	}
}

// A refusal that reads no database comes before the migration, so a bad value
// is refused in seconds rather than after a migration that may run for many
// minutes. A scanner allowed to outlast the queue's hold is one.
func TestARefusalOfTheConfigurationAloneComesBeforeTheMigration(t *testing.T) {
	t.Setenv("OPENPSIRT_QUEUE_MAX_HOLD", "1h")
	t.Setenv("OPENPSIRT_SCANNER_TIMEOUT", "1h")
	addr := freeAddress(t)
	var migrated atomic.Bool
	s := startHeld(t, addr, func(context.Context, *database.DB, *slog.Logger) error {
		migrated.Store(true)
		return nil
	})
	select {
	case err := <-s.done:
		s.done <- err
		if err == nil || !strings.Contains(err.Error(), "OPENPSIRT_SCANNER_TIMEOUT") {
			t.Errorf("a scanner timeout at the hold's ceiling answered %v", err)
		}
	case <-s.entered:
		t.Fatal("the migration began before a refusal of the configuration alone")
	case <-time.After(30 * time.Second):
		t.Fatal("a start that should have been refused was still running after 30s")
	}
	if migrated.Load() {
		t.Error("the schema was applied before a refusal of the configuration alone")
	}
	if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		_ = conn.Close()
		t.Error("the port opened before a refusal of the configuration alone")
	}
}

// A stop signal before the port opens ends the start cleanly, as one after it
// does: a supervisor stopping a starting process reads no failure.
func TestAStopBeforeThePortOpensExitsCleanly(t *testing.T) {
	t.Setenv("OPENPSIRT_DATABASE_URL", "sqlite://"+filepath.Join(t.TempDir(), "stopped.db"))
	t.Setenv("OPENPSIRT_ADDR", freeAddress(t))
	t.Setenv("OPENPSIRT_AUTO_MIGRATE", "false")
	t.Setenv("OPENPSIRT_RECORDS_UPDATE", "false")
	t.Setenv("OPENPSIRT_BOOTSTRAP_ADMINS", "root")
	stopped, stop := context.WithCancel(context.Background())
	stop()
	restore := startedFrom
	startedFrom = func() context.Context { return stopped }
	t.Cleanup(func() { startedFrom = restore })
	quiet, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = quiet.Close() }()

	if err := run(nil, quiet, quiet); err != nil {
		t.Errorf("a start stopped before its port opened answered %v", err)
	}
}
