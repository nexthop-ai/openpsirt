package httpapi

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// RetiredBody is one release that has gone out of support, and what is still
// open against it.
type RetiredBody struct {
	Product string `json:"product"`
	Stream  string `json:"stream"`
	Kind    string `json:"kind" enum:"branch,tag" doc:"Whether this line moves"`
	// EndedOn is the date support ended: the release's own where it stated
	// one, its product's otherwise.
	EndedOn string `json:"ended_on" doc:"The date support ended, as YYYY-MM-DD"`
	// Inherited says the date came from the product. A release following a
	// date and one that stated the same date are different: only the first
	// moves when the product changes its mind.
	Inherited bool `json:"inherited,omitempty" doc:"The date came from the product rather than from this release"`
	// EndedDays is how long ago that was, which is what orders a pile nobody
	// has looked at in two years below one that ended last month.
	//
	// Negative on a release whose date has not arrived: the same figure read
	// the other way, which is how long there is left.
	EndedDays int `json:"ended_days" doc:"How many days ago support ended. Negative where the date has not arrived, which is how many days are left"`
	Open      int `json:"open" doc:"Issues open against it, counted at components rather than at every place they sit"`
	// Ended says the date has passed. The two populations are drawn apart
	// rather than sorted together, because one is exposure nobody can work on
	// and the other is a date somebody can still act before.
	Ended bool `json:"ended" doc:"The date has passed. False is a release that is about to go out of support"`
}

// registerOutOfSupport answers which releases have gone out of support and
// what is still open on them.
//
// **This is the pile that dropped out of every deadline figure by design.**
// Past end-of-life the deadline is stripped from every open finding, so none
// of this is overdue, none of it is due soon, and none of it appears in any
// count built on either. That is the right behavior — nothing will be fixed
// there — and it means the only way to see the exposure is to ask for it.
//
// It is not a coverage question and not a compliance one. A release out of
// support going quiet is expected, and work on it is not late; what somebody
// is asking is what is still shipped and no longer maintained.
func registerOutOfSupport(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-out-of-support", Method: http.MethodGet,
		Path:    "/v1/releases/out-of-support",
		Summary: "List releases that are out of support",
		Description: "Every release you can see whose end-of-life date has passed, with how " +
			"long ago that was and how many issues are still open against it.\n\n" +
			"Past end-of-life the deadline is removed from every open finding on a release, so " +
			"nothing here is overdue or due soon and none of it reaches a figure built on " +
			"either. Nothing is deleted or hidden: the findings and the history stay, and stay " +
			"reportable.\n\n" +
			"`inherited` means the date came from the product rather than from the release " +
			"itself. `open` counts issues at components, not one per place — the same unit " +
			"every release-level count here uses.\n\n" +
			"`within` asks what is about to go, in days ahead. Those come back under " +
			"`ending`, soonest first and never mixed into what has already gone: the day a " +
			"release crosses, the deadline comes off every open finding on it and that work " +
			"leaves every overdue count at once, so a warning and an exposure are two lists " +
			"rather than one. `ended_days` is negative on those, which is how many days are " +
			"left.\n\n" +
			"Narrowed by what you may see, and ordered by what is open.",
		Tags: []string{"Reports"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		ScopeQuery
		Within int `query:"within" minimum:"0" maximum:"3650" doc:"Also list releases whose date falls inside this many days ahead. They come back under ending, never mixed into what has already gone"`
	}) (*retiredOutput, error) {
		rows, err := outOfSupport(ctx, in, input.ScopeQuery, input.Within)
		if err != nil {
			return nil, err
		}
		out := &retiredOutput{}
		out.Body.Items = []RetiredBody{}
		out.Body.Ending = []RetiredBody{}
		for _, row := range rows {
			if !row.Ended {
				out.Body.Ending = append(out.Body.Ending, row)
				out.Body.EndingOpen += row.Open
				continue
			}
			out.Body.Items = append(out.Body.Items, row)
			out.Body.Open += row.Open
		}
		out.Body.Total = len(out.Body.Items)
		out.Body.Within = input.Within
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "export-out-of-support", Method: http.MethodGet,
		Path:    "/v1/releases/out-of-support.{format}",
		Summary: "Export releases that are out of support",
		Description: "The same answer as a file: every release you can see whose end-of-life " +
			"date has passed, how long ago that was, and how many issues are still open " +
			"against it.\n\n" +
			"`open` counts issues at components rather than one per place, the same unit " +
			"every release-level count here uses. `inherited` means the date came from the " +
			"product rather than from the release itself.\n\n" +
			"`within` writes out what is about to go as well, marked `ending` in the state " +
			"column, with `ended_days` negative for how many days are left.\n\n" +
			"The day the file was taken is stated in it, because how long ago a release ended " +
			"is only readable against a date.",
		Tags: []string{"Reports"},
	}, anyPerson, "Exports only what you may see."), func(ctx context.Context, input *struct {
		Format string `path:"format" enum:"csv,json"`
		ScopeQuery
		Within int `query:"within" minimum:"0" maximum:"3650" doc:"Also write out releases whose date falls inside this many days ahead, marked as not yet ended"`
	}) (*huma.StreamResponse, error) {
		rows, err := outOfSupport(ctx, in, input.ScopeQuery, input.Within)
		if err != nil {
			return nil, err
		}
		out := Exporting{
			What: "releases out of support",
			Header: []string{
				"product", "stream", "kind", "state", "ended_on", "inherited",
				"ended_days", "open",
			},
			// Read whole above, so a page is a slice of what is already in
			// hand rather than the same query run again per two hundred.
			Rows: func(_ context.Context, limit, offset int) ([][]string, error) {
				if offset >= len(rows) {
					return nil, nil
				}
				page := rows[offset:]
				if len(page) > limit {
					page = page[:limit]
				}
				written := make([][]string, 0, len(page))
				for _, row := range page {
					// Said in a word as well as in the sign of a number: a
					// spreadsheet sorted on the days column puts the two
					// populations either side of zero, and a reader scanning
					// rows has to notice the minus to tell them apart.
					state := "ending"
					if row.Ended {
						state = "ended"
					}
					written = append(written, []string{
						row.Product, row.Stream, row.Kind, state, row.EndedOn,
						strconv.FormatBool(row.Inherited),
						strconv.Itoa(row.EndedDays), strconv.Itoa(row.Open),
					})
				}
				return written, nil
			},
		}
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			writeExport(writer, input.Format, "out-of-support", out)
		}}, nil
	})
}

type retiredOutput struct {
	Body struct {
		Items []RetiredBody `json:"items"`
		Total int           `json:"total" doc:"How many releases are out of support"`
		Open  int           `json:"open" doc:"Issues open across all of them"`
		// Ending is what has not gone yet, kept apart rather than mixed in.
		// The day a release crosses, the deadline comes off every open
		// finding on it and the work leaves every overdue count at once —
		// so the two are a warning and an exposure, and reading them as one
		// list is how the warning is missed.
		Ending     []RetiredBody `json:"ending" doc:"Releases whose date has not arrived yet, soonest first. Empty unless within was asked for"`
		EndingOpen int           `json:"ending_open" doc:"Issues open across those, which is what leaves every overdue count on the day they cross"`
		Within     int           `json:"within" doc:"How many days ahead this looked"`
	}
}

// outOfSupport is the answer both the screen and the file read, so a file
// cannot come to describe a different set of releases from the screen it was
// taken from.
func outOfSupport(ctx context.Context, in Ingest, asked ScopeQuery,
	within int) ([]RetiredBody, error) {
	subject, err := reading(ctx)
	if err != nil {
		return nil, err
	}
	if in.DB == nil {
		return nil, noDatabase(in.Logger)
	}
	scope, err := scoped(ctx, in, subject, asked)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	// How far ahead to look. Nothing by default, which is the past-only
	// report this has always been: a second population appearing in it
	// unasked would change what every figure on the screen counts.
	ended, err := catalog.NewStore(in.DB.DB).OutOfSupport(ctx, subject, now,
		now.AddDate(0, 0, within))
	if err != nil {
		return nil, wentWrong(in.Logger, "which releases are out of support could not be read", err)
	}
	// What is open on each: an issue at a component, not one per place it sits
	// at. The same count every other release-level figure here uses, so a
	// release reads the same on this report and on its product's own list.
	// The findings list can show slightly fewer rows than this, because it
	// folds sibling packages cut from one source together, and that is a
	// property of the list rather than a disagreement about the unit.
	open, err := finding.NewStore(in.DB.DB).OpenBy(ctx, subject, scope, finding.ByStream)
	if err != nil {
		return nil, wentWrong(in.Logger, "what is open could not be counted", err)
	}

	rows := make([]RetiredBody, 0, len(ended))
	for _, release := range ended {
		if scope.ProductID != nil && *scope.ProductID != release.ProductID {
			continue
		}
		if scope.StreamID != nil && *scope.StreamID != release.StreamID {
			continue
		}
		// Whole days from today, which is the day the store's own predicate
		// is truncated to. Counted from the instant, a release ending
		// tomorrow read as zero days left on the screen that exists to warn
		// about it: the difference is a few hours, and truncation toward zero
		// swallowed it.
		today := now.Truncate(24 * time.Hour)
		since := int(today.Sub(release.EndedOn).Hours() / 24)
		rows = append(rows, RetiredBody{
			Product: release.Product, Stream: release.Stream,
			Kind: string(release.Kind), EndedOn: release.EndedOn.Format(time.DateOnly),
			Inherited: release.Inherited,
			EndedDays: since,
			Ended:     !release.EndedOn.After(now),
			Open:      open[release.StreamID],
		})
	}
	// Most exposed first, then longest out of support, then by name so the
	// order does not move between two reads of the same estate.
	sort.SliceStable(rows, func(i, j int) bool {
		switch {
		case rows[i].Ended != rows[j].Ended:
			// What has ended is exposure now; what is about to is a date
			// somebody can still act before.
			return rows[i].Ended
		case !rows[i].Ended && rows[i].EndedDays != rows[j].EndedDays:
			// Soonest first among those, which is what the warning is for and
			// what it says it is: ordered by what is open, the release with
			// the most work outranked the one about to cross, and the one
			// about to cross is the only one anybody can still act before.
			return rows[i].EndedDays > rows[j].EndedDays
		case rows[i].Open != rows[j].Open:
			return rows[i].Open > rows[j].Open
		case rows[i].EndedDays != rows[j].EndedDays:
			return rows[i].EndedDays > rows[j].EndedDays
		case rows[i].Product != rows[j].Product:
			return rows[i].Product < rows[j].Product
		}
		return rows[i].Stream < rows[j].Stream
	})
	return rows, nil
}
