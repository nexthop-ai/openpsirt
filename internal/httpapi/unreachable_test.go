package httpapi_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// TestADatabaseNobodyCanReachIsNotAnAnswerAboutWhatExists pins the split every
// shared resolver makes.
//
// A read that could not be made was answered as an authoritative negative at
// forty sites: 404 "no product is declared by that name", "nothing has been
// scanned there", "no open finding is recorded there". So an outage told every
// authenticated caller that their products, builds and findings were gone —
// and seven of those bodies carried the driver's own message, which is the
// database host, port and driver handed to whoever asked.
//
// Whoever is asking is resolved against a database that works, so what fails
// is the handler's own read and not sign-in. The rest of the server is given
// one that was opened and then closed, which is how a pool that cannot reach
// its server behaves: every statement returns a driver error, and none of them
// is "no rows".
func TestADatabaseNobodyCanReachIsNotAnAnswerAboutWhatExists(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		logged := &counting{}
		handler := overAClosedDatabase(t, r, logged)

		// One per shared resolver, named for the resolver the request reaches
		// it through.
		for _, c := range []struct {
			through string
			path    string
		}{
			{"productNamedVisibly", "/v1/products/mine/findings"},
			{"locatedVisibly", "/v1/products/mine/streams/master/variants/broadcom/components"},
			{"targetRow", "/v1/products/mine/streams/master/variants/broadcom/scans"},
			{"issueHere", "/v1/products/mine/streams/master/variants/broadcom/findings/" +
				"CVE-2026-9999/components/libnl-3-200"},
			{"the findings list", "/v1/products/mine/findings?stream=master&variant=broadcom"},
			// The arms that were still answering per route rather than through
			// the helper, so an unreachable database told an authenticated
			// caller their run, person, token or notification did not exist.
			{"a run on a build", "/v1/products/mine/streams/master/variants/broadcom/runs/1"},
			{"a token of your own", "/v1/tokens"},
			{"a branch named in a selection",
				"/v1/products/mine/findings?stream=master"},
			{"a document a build sent",
				"/v1/products/mine/streams/master/variants/broadcom/scans/1/documents/1"},
			{"productNamed", "/v1/products/mine/findings/components"},
			{"the catalog's own reader", "/v1/products/mine/streams"},
			{"the build lookup a document is generated from",
				"/v1/products/mine/streams/master/variants/broadcom/vex"},
		} {
			req := httptest.NewRequest(http.MethodGet, c.path, nil)
			req.Header.Set(testHeader, "reader")
			fromOurOwnPage(req)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			// The answer must not be "that does not exist", because
			// nothing here established that.
			if rec.Code == http.StatusNotFound {
				t.Errorf("%s: a database nobody can reach answered 404 for %s: %s",
					c.through, c.path, rec.Body.String())
			}
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("%s: %s answered %d, want a fault", c.through, c.path, rec.Code)
			}
			// And the driver's message is not in the body whatever the status
			// is. Here it names the schema; against a real server it names the
			// host, the port and the driver.
			for _, leak := range []string{"sql:", "no such table", "database is closed"} {
				if strings.Contains(strings.ToLower(rec.Body.String()), leak) {
					t.Errorf("%s: the driver's message reached the body for %s: %s",
						c.through, c.path, rec.Body.String())
				}
			}
		}

		// And it is reported rather than swallowed: a fault nobody logged is
		// an outage nobody can find.
		if logged.lines == 0 {
			t.Error("a database nobody can reach produced no log line at all")
		}
	})
}

// overAClosedDatabase is the server again, answering as somebody the working
// database recognizes, over a database that answers nothing.
//
// Closed rather than never opened: the handlers refuse a nil database with an
// answer of their own, which is a different arm and not this one.
func overAClosedDatabase(t *testing.T, r *reach, logged slog.Handler) http.Handler {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gone.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	target, err := database.ParseURL("sqlite://" + path)
	if err != nil {
		t.Fatal(err)
	}
	gone, err := database.Open(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if err := gone.Close(); err != nil {
		t.Fatal(err)
	}

	files, err := attach.NewFiles(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sources, err := access.ParseSources("192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := httpapi.New(slog.New(logged), nil, httpapi.Ingest{
		DB: gone, Queue: queue.New(gone, queue.DefaultOptions()), Files: files,
		Access:    access.NewResolver(r.rights, access.Trust{Header: testHeader, From: sources}),
		Publisher: publisher.Named{Name: "Example Networks", Namespace: "https://example.test"},
	})
	return handler
}

// counting is a log handler that keeps how many lines were written and none of
// what was in them.
type counting struct {
	slog.Handler
	lines int
}

func (c *counting) Enabled(context.Context, slog.Level) bool { return true }
func (c *counting) Handle(context.Context, slog.Record) error {
	c.lines++
	return nil
}
func (c *counting) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *counting) WithGroup(string) slog.Handler      { return c }
