// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/config"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// heldName is the setting a request held open across a pause writes.
const heldName = "held.across.a.pause"

// switched is a server answering through a router whose one held route writes
// in a transaction and waits for its request to end, with what it started
// beside it counted.
type switched struct {
	addr      string
	standings chan sighting
	done      chan error
	// inside closes once the held route has written; silent, finished and
	// refused once the routes answering nothing, a success and a refusal have
	// begun.
	inside, silent, finished, refused chan struct{}
	// starts counts the times the passes were started, and stopped the times
	// a start's context ended.
	starts, stopped atomic.Int32
	// paused counts the stops whose cause was a pause for a schema change.
	paused atomic.Int32
	// stuck keeps a pass from ending once stopped until release closes.
	stuck   atomic.Bool
	release chan struct{}
}

func serveSwitched(t *testing.T, db *database.DB) *switched {
	t.Helper()
	s := &switched{standings: make(chan sighting), done: make(chan error, 1), inside: make(chan struct{}),
		silent: make(chan struct{}), finished: make(chan struct{}), release: make(chan struct{}), refused: make(chan struct{})}
	t.Cleanup(func() { close(s.release) })
	router := http.NewServeMux()
	router.HandleFunc("/held", func(w http.ResponseWriter, r *http.Request) {
		err := database.InTransaction(r.Context(), db.DB, func(ctx context.Context, tx bun.Tx) error {
			if _, err := tx.ExecContext(ctx, `INSERT INTO "application_setting" ("name", "value", "updated_at")
				VALUES (?, ?, ?)`, heldName, "x", time.Now().UTC()); err != nil {
				return err
			}
			close(s.inside)
			<-ctx.Done()
			return nil
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, "committed")
	})
	router.HandleFunc("/silent", func(_ http.ResponseWriter, r *http.Request) {
		close(s.silent)
		<-r.Context().Done()
	})
	router.HandleFunc("/refused", func(w http.ResponseWriter, r *http.Request) {
		close(s.refused)
		<-r.Context().Done()
		http.NotFound(w, r)
	})
	router.HandleFunc("/finished", func(w http.ResponseWriter, r *http.Request) {
		close(s.finished)
		<-r.Context().Done()
		_, _ = io.WriteString(w, "finished")
	})
	router.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "router")
	})
	s.addr = freeAddress(t)
	server := opened(t, config.Config{Addr: s.addr, ShutdownGrace: 2 * time.Second})
	server.l.answer(router)
	parent, stop := context.WithCancel(t.Context())
	t.Cleanup(func() {
		stop()
		select {
		case <-s.done: //nolint:errcheck // a wait: each test judges the error and puts it back
		case <-time.After(30 * time.Second):
			t.Error("the server did not stop within 30s")
		}
	})
	go func() {
		s.done <- serveBeside(parent, server.cfg, discard(), server.l, func(ctx context.Context) *sync.WaitGroup {
			s.starts.Add(1)
			var workers sync.WaitGroup
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-ctx.Done()
				if errors.Is(context.Cause(ctx), queue.ErrPaused) {
					s.paused.Add(1)
				}
				s.stopped.Add(1)
				if s.stuck.Load() {
					<-s.release
				}
			}()
			return &workers
		}, func(context.Context) <-chan sighting { return s.standings })
	}()
	return s
}

// ask sends a GET and answers the status, the Retry-After header and the body.
func (s *switched) ask(t *testing.T, path string) (int, string, string) {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 30 * time.Second}
	resp, err := client.Get("http://" + s.addr + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Retry-After"), string(body)
}

// see hands the server a standing.
func (s *switched) see(t *testing.T, standing schema.Standing) {
	t.Helper()
	select {
	case s.standings <- sighting{standing: standing, applied: 48, carried: 47}:
	case <-time.After(30 * time.Second):
		t.Fatal("the server did not take a standing within 30s")
	}
}

// eventually waits for cond, failing the test with what it was waiting for.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("after 30s: %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// While another instance changes the schema, a serving instance answers every
// request as upgrading and its readiness fails, a request it was answering
// ends with its transaction rolled back and is answered as upgrading, and its
// passes stop. Once the schema is this build's it serves again and starts its
// passes again.
func TestAnInstanceStopsServingWhileAnotherChangesTheSchema(t *testing.T) {
	dbtest.Two(t, func(t *testing.T, db *database.DB) {
		s := serveSwitched(t, db)
		eventually(t, "the passes started", func() bool { return s.starts.Load() == 1 })

		type answer struct {
			status int
			retry  string
		}
		inFlight := func(path string, begun <-chan struct{}) <-chan answer {
			got := make(chan answer, 1)
			go func() {
				client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 30 * time.Second}
				resp, err := client.Get("http://" + s.addr + path)
				if err != nil {
					got <- answer{status: 0, retry: err.Error()}
					return
				}
				_ = resp.Body.Close()
				got <- answer{resp.StatusCode, resp.Header.Get("Retry-After")}
			}()
			select {
			case <-begun:
			case <-time.After(30 * time.Second):
				t.Fatalf("%s had not begun within 30s", path)
			}
			return got
		}
		held := inFlight("/held", s.inside)
		silent := inFlight("/silent", s.silent)
		finished := inFlight("/finished", s.finished)
		refused := inFlight("/refused", s.refused)

		s.see(t, schema.Changes)
		select {
		case got := <-held:
			if got.status != http.StatusServiceUnavailable || got.retry == "" {
				t.Errorf("the request held across the pause answered %d, Retry-After %q", got.status, got.retry)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("the request held across the pause did not end within 30s")
		}
		// A handler that answers nothing, or answers its ended lookup as a
		// refusal, is answered as upgrading; one that answers a success keeps
		// it, since what it did took effect.
		for path, want := range map[string]struct {
			got    <-chan answer
			status int
		}{"/silent": {silent, http.StatusServiceUnavailable}, "/finished": {finished, http.StatusOK},
			"/refused": {refused, http.StatusServiceUnavailable}} {
			select {
			case got := <-want.got:
				if got.status != want.status {
					t.Errorf("%s, in flight across the pause, answered %d, not %d", path, got.status, want.status)
				}
			case <-time.After(30 * time.Second):
				t.Fatalf("%s did not end within 30s of the pause", path)
			}
		}
		var written int
		if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM "application_setting" WHERE "name" = ?`,
			heldName).Scan(&written); err != nil {
			t.Fatal(err)
		}
		if written != 0 {
			t.Error("the transaction of a request held across the pause committed")
		}
		if status, _, _ := s.ask(t, "/readyz"); status != http.StatusServiceUnavailable {
			t.Errorf("/readyz answered %d while the schema changed", status)
		}
		if status, retry, _ := s.ask(t, "/v1/version"); status != http.StatusServiceUnavailable || retry == "" {
			t.Errorf("/v1/version answered %d, Retry-After %q while the schema changed", status, retry)
		}
		if status, _, _ := s.ask(t, "/healthz"); status != http.StatusOK {
			t.Errorf("/healthz answered %d while the schema changed", status)
		}
		eventually(t, "the passes stopped", func() bool { return s.stopped.Load() == 1 })

		s.see(t, schema.Serves)
		eventually(t, "the passes started again", func() bool { return s.starts.Load() == 2 })
		if status, _, body := s.ask(t, "/v1/version"); status != http.StatusOK || body != "router" {
			t.Errorf("/v1/version answered %d %q once the schema was this build's", status, body)
		}
	})
}

// An instance whose build is older than the schema another instance applied
// stops: it answers as upgrading until it has, stops its passes, and returns
// an error naming both versions, so the platform replaces it.
func TestAnInstanceOlderThanTheSchemaStops(t *testing.T) {
	dbtest.Two(t, func(t *testing.T, db *database.DB) {
		s := serveSwitched(t, db)
		eventually(t, "the passes started", func() bool { return s.starts.Load() == 1 })
		s.see(t, schema.Superseded)
		select {
		case err := <-s.done:
			s.done <- err
			if err == nil || !strings.Contains(err.Error(), "schema version 48") ||
				!strings.Contains(err.Error(), "carries 47") {
				t.Errorf("an instance older than the schema answered %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("an instance older than the schema had not stopped within 30s")
		}
		if s.stopped.Load() != 1 {
			t.Error("an instance older than the schema stopped without stopping its passes")
		}
		if s.paused.Load() != 1 {
			t.Error("an instance older than the schema stopped its passes as a shutdown, so their jobs count as failed")
		}
	})
}

// An instance whose schema falls behind its build with nothing changing it,
// as a restored backup does, stops, so its next start migrates or refuses it.
func TestAnInstanceWhoseSchemaFallsBehindStops(t *testing.T) {
	dbtest.Two(t, func(t *testing.T, db *database.DB) {
		s := serveSwitched(t, db)
		eventually(t, "the passes started", func() bool { return s.starts.Load() == 1 })
		select {
		case s.standings <- sighting{standing: schema.Behind, applied: 46, carried: 47}:
		case <-time.After(30 * time.Second):
			t.Fatal("the server did not take a standing within 30s")
		}
		select {
		case err := <-s.done:
			s.done <- err
			if err == nil || !strings.Contains(err.Error(), "behind the 47") {
				t.Errorf("an instance whose schema fell behind answered %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("an instance whose schema fell behind had not stopped within 30s")
		}
	})
}

// A look at the schema that fails pauses the instance, which serves again
// once a look succeeds and finds the schema its own.
func TestALookThatFailsPauses(t *testing.T) {
	var failing atomic.Bool
	failing.Store(true)
	look := func(context.Context) (schema.Standing, int64, int64, error) {
		if failing.Load() {
			return schema.Serves, 0, 47, errors.New("the database did not answer")
		}
		return schema.Serves, 47, 47, nil
	}
	seen := watchSchema(discard(), look, time.Millisecond)(t.Context())
	next := func() schema.Standing {
		select {
		case got := <-seen:
			return got.standing
		case <-time.After(30 * time.Second):
			t.Fatal("the watch sent nothing within 30s")
		}
		return schema.Serves
	}
	if got := next(); got != schema.Changes {
		t.Fatalf("a failed look was read as %v", got)
	}
	failing.Store(false)
	if got := next(); got != schema.Serves {
		t.Errorf("a look that succeeded after a failure was read as %v", got)
	}
}

// A running server watches the schema it serves: a later release recording a
// version past this build's stops it with an error naming both.
func TestARunningServerStopsWhenALaterReleaseUpgradesItsSchema(t *testing.T) {
	addr := freeAddress(t)
	s := startHeld(t, addr, schema.Up)
	s.entering(t)
	close(s.release)
	deadline := time.Now().Add(30 * time.Second)
	for s.get(t, "/readyz", "").StatusCode != http.StatusOK {
		if time.Now().After(deadline) {
			t.Fatal("/readyz was not ready 30s after the start")
		}
		time.Sleep(50 * time.Millisecond)
	}

	expected, err := schema.Expected()
	if err != nil {
		t.Fatal(err)
	}
	later := dbtest.Open(t, s.url)
	if _, err := later.ExecContext(t.Context(),
		`INSERT INTO "goose_db_version" ("version_id", "is_applied") VALUES (?, ?)`, expected+1, true); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-s.done:
		s.done <- err
		if err == nil || !strings.Contains(err.Error(), "a later release") {
			t.Errorf("a server whose schema a later release upgraded answered %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("a server whose schema a later release upgraded was still serving after 30s")
	}
}

// A start opens its router only on a schema at its build's version that
// nothing is changing, as a look just before opening finds it.
func TestAStartServesOnlyASchemaItsLookFindsItsOwn(t *testing.T) {
	for _, c := range []struct {
		standing schema.Standing
		err      error
		serves   bool
	}{
		{schema.Serves, nil, true},
		{schema.Changes, nil, false},
		{schema.Stranded, nil, false},
		{schema.Superseded, nil, false},
		{schema.Behind, nil, false},
		{schema.Serves, errors.New("the look failed"), false},
	} {
		look := func(context.Context) (schema.Standing, int64, int64, error) { return c.standing, 47, 47, c.err }
		if err := lookBeforeServing(t.Context(), look); (err == nil) != c.serves {
			t.Errorf("standing %v, look failing %v: refused %v, want serving %v", c.standing, c.err, err, c.serves)
		}
	}
}

// A pass that does not end when a pause stops it holds back the passes and
// not the router: the instance serves again once the schema is its own, and
// stops once the pass has not ended within the shutdown grace.
func TestAStuckPassHoldsBackOnlyThePasses(t *testing.T) {
	dbtest.Two(t, func(t *testing.T, db *database.DB) {
		s := serveSwitched(t, db)
		eventually(t, "the passes started", func() bool { return s.starts.Load() == 1 })
		s.stuck.Store(true)
		s.see(t, schema.Changes)
		eventually(t, "the passes were stopped", func() bool { return s.stopped.Load() == 1 })
		if s.paused.Load() != 1 {
			t.Error("a pause stopped the passes without saying it was a pause, so their jobs count as failed")
		}
		s.see(t, schema.Serves)
		eventually(t, "the router answered again", func() bool {
			code, _, body := s.ask(t, "/")
			return code == http.StatusOK && body == "router"
		})
		if s.starts.Load() != 1 {
			t.Error("the passes started again while a stopped one was still running")
		}
		// A standing moving back and forth faster than the grace never
		// restarts the count toward it.
		flapping := time.NewTicker(300 * time.Millisecond)
		defer flapping.Stop()
		var err error
		deadline := time.After(30 * time.Second)
		for stopped, standing := false, schema.Changes; !stopped; {
			select {
			case err = <-s.done:
				stopped = true
			case <-flapping.C:
				select {
				case s.standings <- sighting{standing: standing, applied: 47, carried: 47}:
				case err = <-s.done:
					stopped = true
				case <-deadline:
					t.Fatal("an instance whose stopped pass never ended had not stopped within 30s of flapping")
				}
				if standing == schema.Changes {
					standing = schema.Serves
				} else {
					standing = schema.Changes
				}
			case <-deadline:
				t.Fatal("an instance whose stopped pass never ended had not stopped within 30s of flapping")
			}
		}
		s.done <- err
		select {
		case err := <-s.done:
			s.done <- err
			if err == nil || !strings.Contains(err.Error(), "did not end within") {
				t.Errorf("an instance whose stopped pass never ended answered %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("an instance whose stopped pass never ended had not stopped within 30s")
		}
	})
}

// A start into a schema another instance is changing refuses before it
// prepares to serve, so it writes nothing there: not the administrators
// configuration names, not the group mappings. Both ways the schema comes to
// be in place, migrated by the start itself or by somebody else.
func TestAStartIntoASchemaBeingChangedWritesNothing(t *testing.T) {
	holdToChange := func(t *testing.T, db *database.DB) {
		t.Helper()
		if _, err := db.ExecContext(t.Context(), `INSERT INTO "schema_lease"
			("name", "token", "holding", "holder", "expires_at") VALUES (?, ?, ?, ?, ?)`,
			"schema", "another", "change", "another instance", time.Now().Add(time.Hour).UnixMicro()); err != nil {
			t.Fatal(err)
		}
	}
	nobodyNamed := func(t *testing.T, url string) {
		t.Helper()
		var named int
		if err := dbtest.Open(t, url).QueryRowContext(t.Context(),
			`SELECT COUNT(*) FROM "person" WHERE "is_bootstrap"`).Scan(&named); err != nil {
			t.Fatal(err)
		}
		if named != 0 {
			t.Errorf("a start into a schema being changed named %d administrators before refusing", named)
		}
	}
	refusedForTheChange := func(t *testing.T, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "changing the schema") {
			t.Errorf("a start into a schema being changed answered %v", err)
		}
	}

	t.Run("migrated by the start", func(t *testing.T) {
		s := startHeld(t, freeAddress(t), func(ctx context.Context, db *database.DB, logger *slog.Logger) error {
			if err := schema.Up(ctx, db, logger); err != nil {
				return err
			}
			holdToChange(t, db)
			return nil
		})
		close(s.release)
		select {
		case err := <-s.done:
			s.done <- err
			refusedForTheChange(t, err)
		case <-time.After(30 * time.Second):
			t.Fatal("the start had not ended 30s after its migration")
		}
		nobodyNamed(t, s.url)
	})

	t.Run("migrated by somebody else", func(t *testing.T) {
		url := "sqlite://" + filepath.Join(t.TempDir(), "changing.db")
		db := dbtest.Open(t, url)
		if err := schema.Up(t.Context(), db, discard()); err != nil {
			t.Fatal(err)
		}
		holdToChange(t, db)
		t.Setenv("OPENPSIRT_DATABASE_URL", url)
		t.Setenv("OPENPSIRT_ADDR", freeAddress(t))
		t.Setenv("OPENPSIRT_AUTO_MIGRATE", "false")
		t.Setenv("OPENPSIRT_RECORDS_UPDATE", "false")
		t.Setenv("OPENPSIRT_RECORDS_DIR", t.TempDir())
		t.Setenv("OPENPSIRT_BOOTSTRAP_ADMINS", "root")
		quiet, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = quiet.Close() }()
		refusedForTheChange(t, run(nil, os.Environ(), quiet, quiet))
		nobodyNamed(t, url)
	})
}
