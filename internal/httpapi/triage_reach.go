package httpapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// The reach of a judgment made here, beyond this build.
//
// Two operations and the shape they answer with. A judgment is keyed on
// content rather than on a location, so what it covers beyond the build
// somebody is looking at is a question with an answer — and the answer has to
// be shown before the judgment is made, not discovered afterwards.

// ReachBody is how far a judgment made here would travel.
type ReachBody struct {
	Here      int         `json:"here" doc:"Places in this build the judgment covers"`
	Automatic []MatchBody `json:"automatic" doc:"Other builds it reaches by matching. Nothing to agree to"`
	Differing []MatchBody `json:"differing" doc:"The same issue at the same place held at another version — in this build or in another. Each is a separate judgment, because the code differs"`
}

func reachBody(r finding.Reach) ReachBody {
	body := ReachBody{
		Here:      r.Here,
		Automatic: make([]MatchBody, 0, len(r.Automatic)),
		Differing: make([]MatchBody, 0, len(r.Differing)),
	}
	for _, m := range r.Automatic {
		body.Automatic = append(body.Automatic, MatchBody{
			Stream: m.Stream, Variant: m.Variant, Version: m.Version, Places: m.Places, Here: m.Here,
		})
	}
	for _, m := range r.Differing {
		body.Differing = append(body.Differing, MatchBody{
			Stream: m.Stream, Variant: m.Variant, Version: m.Version, Places: m.Places, Here: m.Here,
		})
	}
	return body
}

// MatchBody is the same issue at the same place in another build.
type MatchBody struct {
	Stream  string `json:"stream"`
	Variant string `json:"variant"`
	// Version is what that build ships, and the reason this is a separate
	// question. With a match, the decision already reaches there and nobody is
	// asked. It is the version the decision route resolves a name by, so a
	// caller applying the decision there passes it back as ?version=.
	Version string `json:"version,omitempty" doc:"The version that build ships under this name — pass it as ?version= when applying a decision there"`
	Places  int    `json:"places" doc:"The number of places it sits at there"`
	// Here says this is another version in the build being decided in, rather
	// than in another release or variant. A build commonly ships one name at
	// several versions, and those sit beside the one in hand.
	Here bool `json:"here,omitempty" doc:"This is another version in the same build, not another build"`
}

func registerElsewhere(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-decision-reach", Method: http.MethodGet,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/findings/{vulnerability}/places/{place}/reach",
		Summary: "Show how far a decision here would reach",
		Description: "Returns the three parts of what a judgment made here covers.\n\n" +
			"`here` is how many places in this build. `automatic` are other builds it reaches " +
			"without anybody doing anything, because their upstream versions and chains already " +
			"match — a decision is a claim about a combination of code, not about a release. " +
			"`differing` hold the same issue at the same place at another version, so each is a " +
			"separate judgment.\n\n" +
			"Only `differing` is a choice. The first two follow from the matching rules and are " +
			"there to be told, not agreed to — and showing them as one number is how a decision " +
			"comes to reach builds the person making it never knew about.",
		Tags: []string{"Triage"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Stream        string `path:"stream"`
		Variant       string `path:"variant"`
		Vulnerability string `path:"vulnerability"`
		Place         string `path:"place"`
	}) (*struct{ Body ReachBody }, error) {
		subject, _, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		// The build this decision was authorized against, not the one a
		// second resolution would find. Resolved twice, the two can disagree
		// under a concurrent write — a grant withdrawn between them refuses
		// the second differently — so the request would authorize against one
		// answer and report against another.
		at, here, err := decidingAbout(ctx, in, subject, input.Product, input.Stream,
			input.Variant, input.Vulnerability, input.Place)
		if err != nil {
			return nil, err
		}

		reach, err := finding.NewStore(in.DB.DB).Reaching(ctx, subject, *at, here)
		if err != nil {
			return nil, wentWrong(in.Logger, "cannot look for the same issue elsewhere", err)
		}
		return &struct{ Body ReachBody }{Body: reachBody(reach)}, nil
	})
}

func registerReachAcross(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-finding-reach", Method: http.MethodGet,
		Path: "/v1/products/{product}/streams/{stream}/variants/{variant}" +
			"/findings/{vulnerability}/components/{component}/reach",
		Summary: "Show how far a decision about this finding would reach",
		Description: "The same three parts the per-place answer gives, for every place " +
			"the finding sits at, merged.\n\n" +
			"A judgment is made about an issue in a component, which is a group of places " +
			"rather than one — a kernel flaw sits at sixty. Asking per place is a request " +
			"each, so a screen doing that samples, and a sample decides which other builds " +
			"it can offer to include: one reachable only from a place the sample missed is " +
			"never offered and the judgment does not travel there.\n\n" +
			"A build reached from two places of the finding is one thing to agree to, and " +
			"carries the places of both.",
		Tags: []string{"Triage"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Stream        string `path:"stream"`
		Variant       string `path:"variant"`
		Vulnerability string `path:"vulnerability"`
		Component     string `path:"component"`
		Version       string `query:"version" doc:"The version, where the build holds that name at more than one"`
	}) (*struct{ Body ReachBody }, error) {
		subject, _, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		target, issue, at, err := findingAbout(ctx, in, subject, input.Product, input.Stream,
			input.Variant, input.Vulnerability, input.Component, input.Version)
		if err != nil {
			return nil, err
		}
		places, err := finding.NewStore(in.DB.DB).PlacesFor(ctx, subject, target, issue, at)
		if err != nil || len(places) == 0 {
			return nil, noSuchFinding()
		}
		reach, err := finding.NewStore(in.DB.DB).ReachingAcross(ctx, subject, places, target)
		if err != nil {
			return nil, wentWrong(in.Logger, "cannot look for the same issue elsewhere", err)
		}
		return &struct{ Body ReachBody }{Body: reachBody(reach)}, nil
	})
}
