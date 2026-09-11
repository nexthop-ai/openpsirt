package httpapi

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// Exporting writes a list out as it is read.
//
// **The subject travels through the stream**. An export is the
// easiest place in this codebase to build a list first and narrow it
// afterwards, which is exactly the failure the narrowing helper's own comment
// warns about — so this is the same query with the same subject, paged and
// written as it goes, and there is no point at which a whole unnarrowed list
// exists.
//
// **Paged rather than unbounded.** A year of a real deployment is more rows
// than a process should hold, and the page is the same page the screen reads:
// one query shape, so a spreadsheet and a screen cannot disagree about what
// the filter means.
type Exporting struct {
	// About is what the file says about itself above the rows: a label and
	// the value, stated because a spreadsheet opened six months later has
	// nowhere else to carry it. The deployment's severity line is the case
	// this exists for — a file that omits a third of the estate lies by
	// omission — and the threshold a true/false column was computed against
	// is the same shape of fact.
	//
	// Empty on a file with nothing to state, which writes no statement at
	// all rather than an empty one: a key reading "triaged at or above"
	// with nothing after it, on a file about scans, is worse than silence.
	About  [2]string
	Header []string
	// Rows reads a page at a time, for a list assembled by grouping: the page
	// is the unit its statement answers in.
	//
	// Exactly one of Rows and Stream is set.
	Rows func(ctx context.Context, limit, offset int) ([][]string, error)
	// Stream hands over every row as it arrives, for a reader that can open a
	// cursor over the whole answer.
	//
	// **Paging is what made a large export cost what it did.** Each page
	// re-ran the statement, which re-sorted everything and then skipped past
	// what had already been written, so the deeper the file got the more each
	// page cost: a build's disposition register took 52 minutes and the last
	// page cost five times the first. Streamed, the same file is 1.9 seconds.
	//
	// It does not cost what paging was avoiding. "No complete list ever exists
	// in memory" is what a cursor gives — this holds one row — and what paging
	// added on top of that was the re-sorting.
	//
	// What it does cost is a database connection held for as long as the
	// response takes, where a paged reader gave one back between pages. That
	// is bounded by the write deadline below, which moves with the writing
	// rather than with the request: a reader that has stopped reading loses
	// the connection after exportStall, and one that is keeping up holds it
	// for the seconds the file takes.
	Stream func(ctx context.Context, each func([]string) error) error
}

// exportPage is how much is read at a time. The list's own maximum, so the
// export and the screen ask the same question.
const exportPage = 200

// exportStall is how long an export may go without writing anything before
// the connection is closed under it.
//
// The server bounds a response by how long the whole of it takes, which is
// right for a request that answers and wrong for one that streams: a real
// build's disposition register is a quarter of a million places, and it was
// arriving cut off in the middle of a row at exactly five minutes, with no
// marker, because the connection is closed under the handler rather than a
// write failing. A file that simply stops is a file somebody reads as
// complete — the very thing the comment on the error path above says.
//
// So the deadline moves with the writing instead of with the request. A
// client that has stopped reading still reaches it; an export that is making
// progress is no longer punished for being large.
const exportStall = 2 * time.Minute

// writing extends the response's deadline for as long as an export keeps
// producing.
//
// Returns a no-op where the writer underneath cannot take a deadline, which
// is what a test harness looks like: an export that cannot move the deadline
// behaves exactly as it did before this existed.
func writing(ctx huma.Context) func() {
	_, w := humachi.Unwrap(ctx)
	if w == nil {
		return func() {}
	}
	control := http.NewResponseController(w)
	if control.SetWriteDeadline(time.Now().Add(exportStall)) != nil {
		return func() {}
	}
	return func() { _ = control.SetWriteDeadline(time.Now().Add(exportStall)) }
}

// downloadName is a product's name made safe to put in a header.
//
// Two of these names come from the catalog, where a name is checked for being
// usable as an identifier and not for being usable in a quoted header field: a
// quote ends the field early and a carriage return ends the header. Done here
// rather than only at the catalog because this is the place that must be
// right — every export goes through it, including any added later, and a name
// declared before the catalog was tightened is still in the database.
//
// Anything outside letters, digits, dot, underscore and dash becomes a dash,
// because what this is for is a file somebody saves and finds again.
func downloadName(name string) string {
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

// writeExport streams a list as CSV or JSON.
//
// The two formats differ in five places — the content type, the extension,
// what goes before the rows, how a row is written, and what is said where the
// file stops early — and in nothing else. Written as two functions they were
// the same page loop twice, so the incomplete marker had two homes and the
// stall deadline two ways of being renewed.
func writeExport(ctx huma.Context, format, name string, out Exporting) {
	kind := asCSV
	if format == "json" {
		kind = asJSON
	}
	ctx.SetHeader("Content-Type", kind.contentType)
	ctx.SetHeader("Content-Disposition",
		`attachment; filename="`+downloadName(name)+"."+kind.extension+`"`)
	going := writing(ctx)
	write := kind.open(ctx, out)
	if eachPage(ctx.Context(), out, func(rows [][]string) {
		for _, row := range rows {
			write.row(row)
		}
	}, func() {
		write.flush()
		going()
	}) != nil {
		// The status is long gone by the time this can fail. Saying so in the
		// file is the only honest thing left: a file that simply stops is a
		// file somebody reads as complete.
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
		// What the file says about itself, above the column names, because a
		// spreadsheet has nowhere else to carry it.
		if out.About[0] != "" {
			_ = w.Write([]string{"# " + out.About[0], out.About[1]})
		}
		_ = w.Write(out.Header)
		return sink{
			row:   func(row []string) { _ = w.Write(inert(row)) },
			flush: w.Flush,
			cutShort: func() {
				_ = w.Write([]string{"# this export stopped early and is incomplete"})
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
		if out.About[0] != "" {
			_, _ = fmt.Fprintf(body, `{%s:%s,"items":[`,
				quoted(asKey(out.About[0])), quoted(out.About[1]))
		} else {
			_, _ = fmt.Fprint(body, `{"items":[`)
		}
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
					_, _ = fmt.Fprintf(body, "%s:%s", quoted(column), quoted(value))
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
// **Stepping by what came back, and stopping when nothing does.** Stepping by
// the page size and stopping on a short page reads exportPage as the truth
// about a store's own page, and it is a guess: a reader whose ceiling is
// lower returns a short page every time, so the export would end after one of
// them having written a fraction of the file and said nothing — which is the
// silent truncation these files exist not to do. Every reader here allows 200
// or more today. This costs one query at the end and stops that being
// something anybody has to keep true.
func eachPage(ctx context.Context, out Exporting,
	page func(rows [][]string), between func()) error {

	if out.Stream != nil {
		// Written one at a time, and flushed every so often rather than every
		// row: a flush is a write to the socket, and a quarter of a million of
		// them costs more than the query did.
		written := 0
		return out.Stream(ctx, func(row []string) error {
			page([][]string{row})
			written++
			if written%exportPage == 0 {
				between()
			}
			return nil
		})
	}
	for offset := 0; ; {
		rows, err := out.Rows(ctx, exportPage, offset)
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

// asKey is what a stated fact is called in JSON: the words it is written in on
// paper, joined the way every other field here is named.
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

func registerExport(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "export-findings", Method: http.MethodGet,
		Path:    "/v1/products/{product}/findings.{format}",
		Summary: "Export the findings list",
		Description: "The findings list as a file: every row the same filters would show, not " +
			"one page of them.\n\n" +
			"**Read with your own visibility, as it streams.** It is the same query the screen " +
			"reads, paged and written out as it goes — there is no point at which a whole " +
			"unnarrowed list exists to be filtered afterwards, which is the failure an export " +
			"is the easiest place in a codebase to make.\n\n" +
			"The line this deployment triages at is stated in the file, because a spreadsheet " +
			"opened six months later has nothing else to say that everything below it was " +
			"never in there.\n\n" +
			"Takes every filter the findings list takes.",
		Tags: []string{"Findings"},
	}, anySubject, "Exports only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Format  string `path:"format" enum:"csv,json"`
		Stream  string `query:"stream"`
		Variant string `query:"variant"`
		AtOneBuild
		Narrowing
	}) (*huma.StreamResponse, error) {
		at, err := narrowing(ctx, in, ScopeQuery{
			Product: input.Product, Stream: input.Stream, Variant: input.Variant,
		}, input.AtOneBuild, input.Narrowing, "the triage line could not be read")
		if err != nil {
			return nil, err
		}
		subject, scope, floor, narrowed, store := at.Subject, at.Scope, at.Floor, at.Filter, at.Store

		line := "everything"
		if floor.Hides() {
			line = floor.Word
		}
		out := Exporting{
			About: [2]string{"triaged at or above", line},
			Header: []string{
				"issue", "severity", "score", "exploited", "component", "version",
				"ecosystem", "upstream fix", "packages", "consumers", "state", "opened", "due",
				"stream", "variant",
			},
			Rows: func(ctx context.Context, limit, offset int) ([][]string, error) {
				groups, _, err := store.Groups(ctx, subject, scope, limit, offset, narrowed)
				if err != nil {
					return nil, err
				}
				rows := make([][]string, 0, len(groups))
				for _, g := range groups {
					due, opened := "", ""
					if g.DueAt != nil {
						due = g.DueAt.Format("2006-01-02")
					} else if g.NoDeadline != "" {
						due = string(g.NoDeadline)
					}
					if !g.OpenedAt.IsZero() {
						opened = g.OpenedAt.Format("2006-01-02")
					}
					rows = append(rows, []string{
						g.Vulnerability, g.Severity,
						strconv.FormatFloat(float64(g.ScoreCenti)/100, 'f', -1, 64),
						strconv.FormatBool(g.Exploited),
						g.Component, g.Version, g.Ecosystem, g.FixedIn,
						strconv.Itoa(g.Packages), strconv.Itoa(g.Consumers),
						g.State, opened, due,
						g.Stream, g.Variant,
					})
				}
				return rows, nil
			},
		}
		name := "findings-" + strings.ToLower(input.Product)
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			writeExport(writer, input.Format, name, out)
		}}, nil
	})
}

// registerAnywhereExport is the cross-product findings list as a file.
//
// The per-product export existed and this did not, so the one screen that
// answers "what is open anywhere" was the one screen whose answer could not
// leave the application — which is the screen somebody reporting to a manager
// is on. It is the same query the cross-product list reads, paged and written
// as it goes, with the product as a column because it is the thing that varies.
//
// **The triage line is per product here**, so the file cannot name one. It
// says so rather than naming a number that would be wrong for every product
// but one.
func registerAnywhereExport(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "export-findings-anywhere", Method: http.MethodGet,
		Path:    "/v1/findings.{format}",
		Summary: "Export findings across every product",
		Description: "The cross-product findings list as a file: every row the same filters " +
			"would show, not one page of them.\n\n" +
			"**Read with your own visibility, as it streams.** It is the same query the " +
			"screen reads, paged and written out as it goes.\n\n" +
			"Each product applies its own triage line, so the file states that rather than " +
			"naming one line, and `product` is a column.\n\n" +
			"Takes every filter the cross-product list takes. `beneath` and `differs` are " +
			"not offered here, for the reason that list gives.",
		Tags: []string{"Findings"},
	}, anySubject, "Exports only what you may see."), func(ctx context.Context, input *struct {
		Format string `path:"format" enum:"csv,json"`
		Narrowing
	}) (*huma.StreamResponse, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		// The same handling the cross-product list gives severity: the line is
		// applied per row inside the store, and asking for it as a filter as
		// well would narrow twice and answer neither question.
		narrowed, err := input.filter(finding.Floor{Word: input.Severity})
		if err != nil {
			return nil, err
		}
		narrowed.MinSeverity = ""
		store := finding.NewStore(in.DB.DB)
		out := Exporting{
			About: [2]string{"triaged at or above", "each product's own line"},
			Header: []string{
				"product", "issue", "severity", "score", "exploited", "component", "version",
				"ecosystem", "upstream fix", "packages", "consumers", "state", "opened", "due",
				"stream", "variant",
			},
			Rows: func(ctx context.Context, limit, offset int) ([][]string, error) {
				groups, _, err := store.Anywhere(ctx, subject, limit, offset, narrowed)
				if err != nil {
					return nil, err
				}
				rows := make([][]string, 0, len(groups))
				for _, g := range groups {
					due, opened := "", ""
					if g.DueAt != nil {
						due = g.DueAt.Format("2006-01-02")
					} else if g.NoDeadline != "" {
						due = string(g.NoDeadline)
					}
					if !g.OpenedAt.IsZero() {
						opened = g.OpenedAt.Format("2006-01-02")
					}
					rows = append(rows, []string{
						g.Product, g.Vulnerability, g.Severity,
						strconv.FormatFloat(float64(g.ScoreCenti)/100, 'f', -1, 64),
						strconv.FormatBool(g.Exploited),
						g.Component, g.Version, g.Ecosystem, g.FixedIn,
						strconv.Itoa(g.Packages), strconv.Itoa(g.Consumers),
						g.State, opened, due,
						g.Stream, g.Variant,
					})
				}
				return rows, nil
			},
		}
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			writeExport(writer, input.Format, "findings", out)
		}}, nil
	})
}
