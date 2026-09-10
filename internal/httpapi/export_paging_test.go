package httpapi

import (
	"context"
	"fmt"
	"testing"
)

// An export writes every row even where its reader's own page is smaller than
// the export's.
//
// The loop used to step by the page size and stop on a short page, which reads
// that constant as the truth about a store's page. It is a guess: a reader
// whose ceiling is lower answers with a short page every time, so the export
// would stop after the first one — a file holding a fraction of the answer and
// saying nothing, which is the failure the whole export path is written to
// avoid. Watched failing before the loop was changed.
func TestAnExportWritesEveryRowWhateverTheReadersPageIs(t *testing.T) {
	for _, readerPage := range []int{1, 3, exportPage - 1, exportPage, exportPage + 7} {
		t.Run(fmt.Sprint(readerPage), func(t *testing.T) {
			const rows = 250
			out := Exporting{
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
			if err := eachPage(t.Context(), out, func(page [][]string) {
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
// The register streams rather than pages, because paging is what made it cost
// 52 minutes. What must not change is the two things a file has to do: hold
// every row, and say so when it does not.
func TestAStreamedExportWritesEveryRowAndSaysWhenItCannot(t *testing.T) {
	const rows = 250
	out := Exporting{
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
	if err := eachPage(t.Context(), out, func(page [][]string) {
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
	broken := Exporting{
		Header: []string{"n"},
		Stream: func(_ context.Context, each func([]string) error) error {
			if err := each([]string{"0"}); err != nil {
				return err
			}
			return fmt.Errorf("the database went away")
		},
	}
	if err := eachPage(t.Context(), broken, func([][]string) {}, func() {}); err == nil {
		t.Error("a walk that failed was reported as a clean end")
	}
}

// And it stops rather than writing a file that trails off, where the reader
// fails partway.
func TestAnExportThatFailsPartwayStopsAndSaysSo(t *testing.T) {
	out := Exporting{
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
	err := eachPage(t.Context(), out, func(page [][]string) { written += len(page) }, func() {})
	if err == nil {
		t.Fatal("a reader that failed was walked to a clean end")
	}
	if written != exportPage {
		t.Errorf("%d rows were written before it failed, want the one page", written)
	}
}
