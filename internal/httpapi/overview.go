package httpapi

import (
	"context"
	"net/http"
	"sort"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// BuildStandingBody is one build of a product and how far its work has got.
type BuildStandingBody struct {
	Stream     string `json:"stream"`
	StreamKind string `json:"stream_kind,omitempty" enum:"branch,tag" doc:"Whether the line moves or is fixed"`
	Variant    string `json:"variant"`
	Open       int    `json:"open" doc:"Issues at components, the unit every count here uses"`
	Overdue    int    `json:"overdue,omitempty" doc:"How many of those are past a deadline"`
	Exploited  int    `json:"exploited,omitempty" doc:"How many somebody is known to be exploiting"`
	Undecided  int    `json:"undecided,omitempty" doc:"How many nobody has claimed anything about"`
	Agreed     int    `json:"agreed,omitempty" doc:"How many are answered at every place by a standing decision"`
	// LastScanAt is when a scan last arrived here, and Retired says the
	// release is out of support — so a build that stopped being scanned
	// because it stopped being supported reads as expected rather than as
	// a fault.
	LastScanAt string `json:"last_scan_at,omitempty" doc:"When a scan last arrived here. Absent where none ever has"`
	Retired    bool   `json:"retired,omitempty" doc:"This build's release is out of support"`
}

// OverviewOutput is one product, as a page about that product.
type OverviewOutput struct {
	Body struct {
		Name        string `json:"name"`
		DisplayName string `json:"display_name,omitempty"`
		// TriageFloor is what this product considers worth triaging, or empty
		// where it inherits the deployment's line. Said rather than left out:
		// a number somebody chose and a number nobody noticed are different
		// facts about the same screen.
		TriageFloor string              `json:"triage_floor,omitempty" doc:"The least severity this product triages, where the product states one of its own"`
		EndOfLife   string              `json:"end_of_life,omitempty" doc:"When the product goes out of support, where a date is set"`
		Builds      []BuildStandingBody `json:"builds"`
		// Open, Overdue and Undecided are the product's own totals, counted
		// across its builds rather than summed over them. The findings list
		// answers for a whole product as one row per issue and component, so
		// a library carrying one issue in two builds is one thing to decide
		// about and two build rows — and a sum would put a number here that
		// the list this page links to contradicts.
		Open      int `json:"open"`
		Overdue   int `json:"overdue"`
		Undecided int `json:"undecided"`
		// Waiting is how many claims about this product are waiting for a
		// second person. Somebody asking how a product is doing is asking
		// partly whether the work is stuck on somebody else.
		Waiting int `json:"waiting" doc:"Claims about this product waiting for a second person"`
	}
}

// registerOverview is one product's own page.
//
// **There was no page for one product**, only a table of all of them with
// administration controls in the cells. "How is SONiC doing" was five requests
// and a spreadsheet — what is open per build, how much is overdue, how much
// has been decided, when each build was last scanned — every piece of which
// existed and none of which sat together.
func registerOverview(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-product-overview", Method: http.MethodGet,
		Path:    "/v1/products/{product}/overview",
		Summary: "Show how one product is doing",
		Description: "One product, with each of its builds: what is open, how much is overdue, " +
			"how much is exploited, how much nobody has claimed anything about, how much is " +
			"answered at every place, and when a scan last arrived.\n\n" +
			"Counted as issues at components, the unit every other count here uses. A " +
			"component reached twenty ways carries the same issue twenty times, so counting " +
			"rows would make a build look twenty times worse than the list somebody opens " +
			"next.\n\n" +
			"\"Undecided\" and \"agreed\" are the findings list's own words, by the same " +
			"definition and read from the same expression: undecided means no place has a " +
			"decision, agreed means every place is answered by one that stands. Two screens " +
			"with two definitions of \"decided\" is how they come to disagree in front of " +
			"somebody.\n\n" +
			"A build whose release is out of support says so rather than reading as one that " +
			"stopped being scanned: those are different facts and only one of them is a fault.",
		Tags: []string{"Catalog"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
	}) (*OverviewOutput, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		named, err := productNamedVisibly(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		standing, whole, err := finding.NewStore(in.DB.DB).HowItStands(ctx, subject, named.ID)
		if err != nil {
			return nil, refused(in.Logger, err, "cannot read how this product is doing")
		}
		// When each build was last scanned, from the same answer the coverage
		// screen reads rather than a second query that could disagree with it
		// about which build counts.
		seen, err := ingest.NewStore(in.DB.DB).Scanning(ctx, subject,
			finding.Scope{ProductID: &named.ID}, 0)
		if err != nil {
			return nil, refused(in.Logger, err, "cannot read when these were last scanned")
		}
		type where struct{ stream, variant string }
		covered := make(map[where]ingest.Coverage, len(seen))
		for _, row := range seen {
			covered[where{row.Stream, row.Variant}] = row
		}
		held := make(map[where]finding.BuildStanding, len(standing))
		for _, row := range standing {
			held[where{row.Stream, row.Variant}] = row
		}

		out := &OverviewOutput{}
		out.Body.Name = named.Name
		out.Body.DisplayName = named.DisplayName
		out.Body.TriageFloor = stated(named.TriageFloor)
		out.Body.EndOfLife = onDate(named.EOLOn)
		out.Body.Builds = make([]BuildStandingBody, 0, len(covered)+len(held))

		// Every declared build, not only the ones carrying findings: a build
		// that has never been scanned is the row this page exists to show, and
		// leaving it out would report a product as clean because nobody has
		// looked at part of it.
		at := map[where]bool{}
		for key := range covered {
			at[key] = true
		}
		for key := range held {
			at[key] = true
		}
		keys := make([]where, 0, len(at))
		for key := range at {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].stream != keys[j].stream {
				return keys[i].stream < keys[j].stream
			}
			return keys[i].variant < keys[j].variant
		})
		for _, key := range keys {
			row := held[key]
			body := BuildStandingBody{
				Stream: key.stream, Variant: key.variant,
				Open: row.Open, Overdue: row.Overdue, Exploited: row.Exploited,
				Undecided: row.Undecided, Agreed: row.Agreed,
			}
			if cover, has := covered[key]; has {
				body.StreamKind = cover.StreamKind
				body.Retired = cover.Retired
				if cover.LastReceivedAt != nil {
					body.LastScanAt = stamp(*cover.LastReceivedAt)
				}
			}
			out.Body.Builds = append(out.Body.Builds, body)
		}

		// The product's own totals, counted across its builds rather than
		// summed over the rows above: the findings list answers for a whole
		// product as one row per issue and component, so a library carrying
		// one issue in two builds is one thing to decide about and two build
		// rows. A sum here would contradict the list this page links to.
		out.Body.Open = whole.Open
		out.Body.Overdue = whole.Overdue
		out.Body.Undecided = whole.Undecided

		// What is waiting for a second person here. Read through the same
		// queue the review screen reads, narrowed to this product, so the
		// number and the screen it links to are the same answer.
		waiting, err := triage.NewStore(in.DB.DB).WaitingIn(ctx, subject, named.ID)
		if err != nil {
			return nil, wentWrong(in.Logger, "cannot read what is waiting here", err)
		}
		out.Body.Waiting = waiting
		return out, nil
	})
}
