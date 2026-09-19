package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// BuildCountsBody is what one build holds now, by severity band.
type BuildCountsBody struct {
	Stream  string `json:"stream"`
	Variant string `json:"variant"`
	// Kind says whether this is a branch or a tag. The comparison only means
	// something for a branch, and a screen asks before drawing the panel at
	// all rather than drawing one that explains why it is empty.
	Kind     string `json:"kind,omitempty" enum:"branch,tag"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Total    int    `json:"total"`
	// LastScannedAt says how old this statement is. A count from a build
	// nothing has scanned in a year is a statement about last year.
	LastScannedAt string `json:"last_scanned_at,omitempty"`
}

// ReadinessBody is a branch beside the last release cut from it.
type ReadinessBody struct {
	Now BuildCountsBody `json:"now"`
	// Shipped is absent where there is nothing to compare against, and Why
	// says what is missing. "We shipped with none" and "we do not know what we
	// shipped with" are answers a person acts on differently, so the second is
	// never dressed up as the first.
	Shipped *BuildCountsBody `json:"shipped,omitempty"`
	Why     string           `json:"why,omitempty" doc:"The missing half, where there is nothing to compare against"`
	// Floor is the line both counts are at or above, named so a shared number
	// says whose it is.
	Floor string `json:"floor,omitempty" doc:"The least severity counted, or empty where everything is"`
	// Blocking is what the count is made of, worst first: the work nobody has
	// agreed to ship with. A number with no list behind it is a number
	// somebody has to go and assemble by hand before they can do anything
	// about it, and this is read at exactly the moment there is no time for
	// that.
	Blocking []BlockingBody `json:"blocking" doc:"The work nobody has agreed to ship with, worst first. Bounded; total says how many there are"`
	// Blockers is how many there are altogether, which is what the list is a
	// page of.
	Blockers int `json:"blockers" doc:"The number of pieces of work nobody has agreed to ship with"`
}

// BlockingBody is one thing standing between a branch and a release.
type BlockingBody struct {
	Vulnerability string `json:"vulnerability"`
	Component     string `json:"component"`
	// Version is what tells one of these from another. A group is keyed on the
	// issue and the fold — the source package at the version it was built at —
	// so one issue at three versions of one component is three rows here.
	// Without it they arrived identical: four rows reading "CVE-2026-46595
	// golang.org/x/crypto", differing only in a count the panel does not draw.
	Version   string `json:"version,omitempty" doc:"The version this sits at, which is what tells two rows of one component apart"`
	Severity  string `json:"severity,omitempty"`
	Exploited bool   `json:"exploited,omitempty"`
	Places    int    `json:"places" doc:"The number of places of the build it sits at"`
	State     string `json:"state,omitempty" enum:"undecided,waiting,lapsed" doc:"The decision state. Anything agreed is not in this list"`
	Due       string `json:"due,omitempty"`
}

// blocking is how many of the worst are listed.
//
// A release conversation reads the top of this and the number beside it; the
// findings list is where the whole of it is worked, and the panel links to it.
// The worst few: against a blocker count in the thousands, a longer list is an
// arbitrary page of the findings list rather than what the count is made of,
// and it costs the panel the comparison it is named after — which is what the
// rest of the panel draws. What is asked for here is a number somebody can act
// on without going and assembling it, and the worst few are that.
const blocking = 5

func registerReadiness(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-readiness", Method: http.MethodGet,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/readiness",
		Summary: "Compare a branch against the last release cut from it",
		Description: "Answers the question asked before shipping: is what we are about to " +
			"ship better or worse than what we last shipped. \"8 criticals now, v2.4.1 " +
			"shipped with 4.\"\n\n" +
			"The release is the newest one cut from this branch, built the same way, that " +
			"has been scanned here — a branch built for one chip beside a release built for " +
			"another compares two different pieces of software and reads as a regression " +
			"somebody then goes looking for.\n\n" +
			"Both sides come from scans already collected, so this asks nothing new of a " +
			"build pipeline. Where there is nothing to compare against, `shipped` is absent " +
			"and `why` says what is missing rather than reporting zeroes, because a release " +
			"that shipped clean and a release nobody scanned are not the same answer.\n\n" +
			"Counted as issues at components at or above the deployment's line, which `floor` " +
			"names.\n\n" +
			"`blocking` is the worst few of what the count is made of: the work nobody has agreed to ship " +
			"with, worst first, read through the findings list's own reader with the same " +
			"line — so the list it opens is the list it counts. Anything agreed is absent, " +
			"because agreeing is the decision to ship with it. `blockers` says how many " +
			"there are altogether.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
	}) (*struct{ Body ReadinessBody }, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		named, err := catalog.NewStore(in.DB.DB).
			LocateVisible(ctx, subject, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, noSuchProduct()
		}

		ready, err := finding.NewStore(in.DB.DB).
			ReadyFor(ctx, subject, named.ProductID, named.StreamID, named.VariantID)
		if err != nil {
			return nil, refusedFinding(in, err)
		}

		out := &struct{ Body ReadinessBody }{}
		out.Body.Now = buildCounts(ready.Now)
		out.Body.Why = ready.Why
		if ready.Floor.Hides() {
			out.Body.Floor = ready.Floor.Word
		}
		if ready.Shipped != nil {
			shipped := buildCounts(*ready.Shipped)
			out.Body.Shipped = &shipped
		}

		// What the count is made of. The same reader the findings list uses,
		// with the same line and the same narrowing, so the list this opens
		// is the list this counts.
		scope := finding.Scope{
			ProductID: &named.ProductID, StreamID: &named.StreamID, VariantID: &named.VariantID,
		}
		groups, blockers, err := finding.NewStore(in.DB.DB).Groups(ctx, subject, scope,
			blocking, 0, finding.Filter{
				Floor: ready.Floor,
				// Everything nobody has agreed to. An agreed row is a
				// decision somebody made to ship with it, which is the
				// opposite of a blocker.
				States: []string{"undecided", "waiting", "lapsed"},
			})
		if err != nil {
			return nil, refusedFinding(in, err)
		}
		out.Body.Blockers = blockers
		out.Body.Blocking = make([]BlockingBody, 0, len(groups))
		for _, group := range groups {
			one := BlockingBody{
				Vulnerability: group.Vulnerability, Component: group.Component,
				Version:  group.Version,
				Severity: group.Severity, Exploited: group.Exploited,
				Places: group.Places, State: group.State,
			}
			if group.DueAt != nil {
				one.Due = group.DueAt.Format(time.DateOnly)
			}
			out.Body.Blocking = append(out.Body.Blocking, one)
		}
		return out, nil
	})
}

func buildCounts(s finding.Standing) BuildCountsBody {
	body := BuildCountsBody{
		Stream: s.Stream, Variant: s.Variant, Kind: s.Kind, Total: s.Total,
		Critical: s.ByBand["critical"], High: s.ByBand["high"],
		Medium: s.ByBand["medium"], Low: s.ByBand["low"],
	}
	if s.LastScanned != nil {
		body.LastScannedAt = s.LastScanned.Format(time.RFC3339)
	}
	return body
}
