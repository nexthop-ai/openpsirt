// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/humatest"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// An export writes every row even where its reader's own page is smaller than
// the export's.
//
// Stepping by the page size and stopping on a short page reads that constant
// as the truth about a store's page. It is a guess: a reader whose ceiling is
// lower answers with a short page every time, so the export stops after the
// first one — a file holding a fraction of the answer and saying nothing,
// which is the failure the whole export path is written to avoid. Watched
// failing against the stepping loop.
func TestAnExportWritesEveryRowWhateverTheReadersPageIs(t *testing.T) {
	for _, readerPage := range []int{1, 3, core.ExportPage - 1, core.ExportPage, core.ExportPage + 7} {
		t.Run(fmt.Sprint(readerPage), func(t *testing.T) {
			const rows = 250
			out := core.Exporting{
				Header: []string{"n"},
				Rows: func(_ context.Context, limit, offset int) ([][]string, error) {
					// A store's own ceiling, applied the way every store here
					// applies one: silently.
					if limit > readerPage {
						limit = readerPage
					}
					page := [][]string{}
					for i := offset; i < offset+limit && i < rows; i++ {
						page = append(page, []string{fmt.Sprint(i)})
					}
					return page, nil
				},
			}
			var written [][]string
			if err := core.EachPage(t.Context(), out, func(page [][]string) {
				written = append(written, page...)
			}, func() {}); err != nil {
				t.Fatal(err)
			}
			if len(written) != rows {
				t.Fatalf("a reader paging %d at a time wrote %d of %d rows",
					readerPage, len(written), rows)
			}
			for i, row := range written {
				if row[0] != fmt.Sprint(i) {
					t.Fatalf("row %d is %q, so the walk skipped or repeated", i, row[0])
				}
			}
		})
	}
}

// A streamed export writes every row too, and the walk's refusal reaches the
// caller.
//
// The register streams rather than pages, because paging costs it 52 minutes.
// Two things a file has to do either way: hold every row, and say so when it
// does not.
func TestAStreamedExportWritesEveryRowAndSaysWhenItCannot(t *testing.T) {
	const rows = 250
	out := core.Exporting{
		Header: []string{"n"},
		Stream: func(_ context.Context, each func([]string) error) error {
			for i := 0; i < rows; i++ {
				if err := each([]string{fmt.Sprint(i)}); err != nil {
					return err
				}
			}
			return nil
		},
	}
	var written [][]string
	flushes := 0
	if err := core.EachPage(t.Context(), out, func(page [][]string) {
		written = append(written, page...)
	}, func() { flushes++ }); err != nil {
		t.Fatal(err)
	}
	if len(written) != rows {
		t.Fatalf("a streamed export wrote %d of %d rows", len(written), rows)
	}
	for i, row := range written {
		if row[0] != fmt.Sprint(i) {
			t.Fatalf("row %d is %q, so the walk skipped or repeated", i, row[0])
		}
	}
	// Flushed as it goes rather than at the end, or a slow reader sees
	// nothing for the length of the export — and not per row, which is a
	// write to the socket for each of a quarter of a million.
	if flushes == 0 || flushes >= rows {
		t.Errorf("%d flushes for %d rows, wanted some but not one each", flushes, rows)
	}

	// A walk that fails partway is a file that stops, and the caller has to
	// hear about it: that is what puts the "incomplete" marker in.
	broken := core.Exporting{
		Header: []string{"n"},
		Stream: func(_ context.Context, each func([]string) error) error {
			if err := each([]string{"0"}); err != nil {
				return err
			}
			return fmt.Errorf("the database went away")
		},
	}
	if err := core.EachPage(t.Context(), broken, func([][]string) {}, func() {}); err == nil {
		t.Error("a walk that failed was reported as a clean end")
	}
}

// And it stops rather than writing a file that trails off, where the reader
// fails partway.
func TestAnExportThatFailsPartwayStopsAndSaysSo(t *testing.T) {
	out := core.Exporting{
		Header: []string{"n"},
		Rows: func(_ context.Context, limit, offset int) ([][]string, error) {
			if offset > 0 {
				return nil, fmt.Errorf("the database went away")
			}
			page := [][]string{}
			for i := 0; i < limit; i++ {
				page = append(page, []string{fmt.Sprint(i)})
			}
			return page, nil
		},
	}
	written := 0
	err := core.EachPage(t.Context(), out, func(page [][]string) { written += len(page) }, func() {})
	if err == nil {
		t.Fatal("a reader that failed was walked to a clean end")
	}
	if written != core.ExportPage {
		t.Errorf("%d rows were written before it failed, want the one page", written)
	}
}

// TestAnExportThatStopsEarlySaysSoInTheFile pins the one thing the export path
// exists to guarantee.
//
// A file that simply stops is a file somebody reads as complete. The status is
// long gone by the time a page can fail — the headers went out with the first
// byte — so saying it in the body is the only honest thing left, and nothing
// else exercises that half in either format.
func TestAnExportThatStopsEarlySaysSoInTheFile(t *testing.T) {
	for _, c := range []struct {
		format string
		marker string
	}{
		{"csv", "# this export stopped early and is incomplete"},
		{"json", `],"incomplete":true}`},
	} {
		t.Run(c.format, func(t *testing.T) {
			// A reader that answers one page and then fails, which is what a
			// connection lost part way through a large export looks like.
			pages := 0
			out := core.Exporting{
				Header: []string{"n"},
				Rows: func(_ context.Context, limit, offset int) ([][]string, error) {
					pages++
					if pages > 1 {
						return nil, errors.New("the connection went away")
					}
					page := make([][]string, 0, limit)
					for i := offset; i < offset+limit; i++ {
						page = append(page, []string{fmt.Sprint(i)})
					}
					return page, nil
				},
			}

			rec := httptest.NewRecorder()
			ctx := humatest.NewContext(nil,
				httptest.NewRequest(http.MethodGet, "/export", nil).WithContext(t.Context()), rec)
			core.WriteExport(ctx, c.format, "mine", out)

			body := rec.Body.String()
			if !strings.Contains(body, c.marker) {
				t.Errorf("an export that stopped early does not say so: %q", tail(body))
			}
			// And the rows it did write are still there, because a truncated
			// file that says it is truncated is worth more than none.
			if !strings.Contains(body, "\n0") && !strings.Contains(body, `"n":"0"`) {
				t.Errorf("an export that stopped early threw away what it had: %q", tail(body))
			}
		})
	}
}

// tail is the end of a body, for a failure message about how one finishes.
func tail(body string) string {
	if len(body) <= 200 {
		return body
	}
	return "…" + body[len(body)-200:]
}

// A streamed export gives its connection back at the ceiling, however slowly
// its reader drains it.
//
// The write deadline only fires for a reader that stops. One that takes a row
// every so often keeps it moving, and the cursor holds a connection for as
// long as that takes. On SQLite that connection is the whole pool. The reader
// here blocks on the second row, as a socket to a slow client does, and the
// connection has to be free again while it is still blocked.
func TestAStreamedExportGivesItsConnectionBackAtTheCeiling(t *testing.T) {
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		blocked := make(chan struct{})
		unblock := make(chan struct{})
		out := core.Exporting{
			Header: []string{"n"},
			Stream: func(ctx context.Context, each func([]string) error) error {
				rows, err := db.DB.DB.QueryContext(ctx, "WITH RECURSIVE n(i) AS "+
					"(SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 1000) SELECT i FROM n")
				if err != nil {
					return err
				}
				defer func() { _ = rows.Close() }()
				for rows.Next() {
					var i int
					if err := rows.Scan(&i); err != nil {
						return err
					}
					if err := each([]string{fmt.Sprint(i)}); err != nil {
						return err
					}
				}
				return rows.Err()
			},
		}
		written := 0
		done := make(chan error, 1)
		go func() {
			done <- core.Streamed(t.Context(), out, func([][]string) {
				written++
				if written == 2 {
					close(blocked)
					<-unblock
				}
			}, func() {}, 50*time.Millisecond)
		}()
		<-blocked
		deadline := time.Now().Add(5 * time.Second)
		for db.DB.DB.Stats().InUse != 0 {
			if time.Now().After(deadline) {
				close(unblock)
				t.Fatal("the cursor still holds its connection well past the ceiling")
			}
			time.Sleep(10 * time.Millisecond)
		}
		close(unblock)
		if err := <-done; err == nil {
			t.Error("an export cut at the ceiling was reported as complete")
		}
	})
}

// Streamed exports past the slots are refused rather than queued for a
// connection.
func TestStreamedExportsPastTheSlotsAreRefused(t *testing.T) {
	slots := make(streamSlots, 1)
	release, err := slots.take()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := slots.take(); err == nil {
		t.Error("a second stream was let through a single slot")
	}
	release()
	again, err := slots.take()
	if err != nil {
		t.Errorf("a released slot was not given back: %v", err)
	} else {
		again()
	}
}

// SQLite's pool is one connection, so a streamed export is given one slot
// there: a second would wait for the connection the first holds.
func TestSQLiteGivesStreamedExportsOneSlot(t *testing.T) {
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		if got := cap(newStreamSlots(db)); got != 1 {
			t.Errorf("SQLite's one connection is shared by %d streamed exports", got)
		}
	})
}
