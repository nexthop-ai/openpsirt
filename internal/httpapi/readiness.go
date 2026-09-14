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
	Why     string           `json:"why,omitempty" doc:"What is missing, where there is nothing to compare against"`
	// Floor is the line both counts are at or above, named so a shared number
	// says whose it is.
	Floor string `json:"floor,omitempty" doc:"The least severity counted, or empty where everything is"`
}

func registerReadiness(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-readiness", Method: http.MethodGet,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/readiness",
		Summary: "Compare a branch against the last release cut from it",
		Description: "Answers the question asked before shipping: is what we are about to " +
			"ship better or worse than what we last shipped. \"8 criticals now, v2.4.1 " +
			"shipped with 4.\"\n\n" +
			"The release is the newest one cut from this branch, **built the same way**, that " +
			"has been scanned here — a branch built for one chip beside a release built for " +
			"another compares two different pieces of software and reads as a regression " +
			"somebody then goes looking for.\n\n" +
			"Both sides come from scans already collected, so this asks nothing new of a " +
			"build pipeline. Where there is nothing to compare against, `shipped` is absent " +
			"and `why` says what is missing rather than reporting zeroes, because a release " +
			"that shipped clean and a release nobody scanned are not the same answer.\n\n" +
			"Counted as issues at components at or above the deployment's line, which `floor` " +
			"names.",
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
