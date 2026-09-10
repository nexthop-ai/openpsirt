package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// FixTargetBody is one build's part in fixing an issue.
//
// Every build of the product holding the issue is here, chosen or not, and so
// is every build that was chosen and no longer holds it. "Nobody has said" and
// "chosen and not delivered" are different answers, and a list that reported
// them alike would lose the second among the first.
type FixTargetBody struct {
	Stream  string `json:"stream"`
	Variant string `json:"variant"`
	// Places is how many findings of this issue the build still holds.
	Places int `json:"places" doc:"How many places the issue still sits at in this build"`
	// State is what to say about this build, in one word.
	//
	//   missed    — chosen, scanned since, and the issue is still there
	//   fixing    — chosen, and no scan has looked since
	//   undecided — nobody has said whether it will be fixed here
	//   clear     — chosen, and the issue is gone
	//   gone      — nobody chose it, and the issue has left anyway
	//   retired   — out of support, so it carries no target at all
	State      string `json:"state" enum:"missed,fixing,undecided,clear,gone,retired" doc:"Where this build stands"`
	DeclaredBy string `json:"declared_by,omitempty" doc:"Who said it would be fixed here"`
	DeclaredAt string `json:"declared_at,omitempty" doc:"When they said so"`
	// Elsewhere is where the work is happening: a ticket, a pull request,
	// a branch. Stored and never fetched.
	Elsewhere string `json:"elsewhere,omitempty" doc:"Where the work is happening — a ticket or a change. Stored and never fetched"`
}

// FixInBody is one build a fix is declared for, and where that work is.
type FixInBody struct {
	Stream  string `json:"stream" minLength:"1"`
	Variant string `json:"variant" minLength:"1"`
	// A pointer, so that "said nothing" and "said it is nowhere" are different
	// requests: re-sending a plan without links must not erase them, and
	// clearing one has to be possible.
	Elsewhere *string `json:"elsewhere,omitempty" maxLength:"1000" doc:"Where the work is happening. Left out, whatever is recorded stays; sent empty, it is cleared"`
}

// FixBody is the whole picture for one piece of work.
type FixBody struct {
	Items []FixTargetBody `json:"items"`
	// Declared, Clear and Missed count the builds somebody chose. Resolved
	// is every one of them being clear, which is what "fixed" means here:
	// it is worked out from what the scans say rather than declared by
	// anybody .
	Declared int  `json:"declared" doc:"Builds somebody said this would be fixed in"`
	Clear    int  `json:"clear" doc:"How many of those no longer hold the issue"`
	Missed   int  `json:"missed" doc:"How many were scanned since and still hold it"`
	Resolved bool `json:"resolved" doc:"Every chosen build is clear, and at least one was chosen"`
}

func registerFixTargets(api huma.API, in Ingest) {
	const path = "/v1/products/{product}/streams/{stream}/variants/{variant}" +
		"/findings/{vulnerability}/components/{component}/fix-targets"

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-fix-targets", Method: http.MethodGet, Path: path,
		Summary: "List which builds this is to be fixed in",
		Description: "Returns every build of the product that holds this issue, plus every " +
			"build that once held it and no longer does — \"gone from main, still present in " +
			"2.4 and 2.3\". A build that was fixed and left out of the list would read " +
			"identically to one that never shipped the component, and those are opposite " +
			"answers.\n\n" +
			"**Nothing here is declared done.** A build is clear when it stops holding the " +
			"issue, which the scans already say; a chosen build that still holds it after a " +
			"scan has run is a missed target, and the scan is independent evidence against " +
			"the claim. A build nobody chose reads as `undecided` rather than as outstanding " +
			"work: nobody is made to answer the same question for six releases, but silence " +
			"has to read as silence.\n\n" +
			"A release out of support is `retired` and carries no target — nothing on it will " +
			"be fixed, so counting it as outstanding would fill this permanently.",
		Tags: []string{"Findings"},
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Stream        string `path:"stream"`
		Variant       string `path:"variant"`
		Vulnerability string `path:"vulnerability"`
		Component     string `path:"component"`
	}) (*struct{ Body FixBody }, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		product, _, issue, component, err := locateFinding(ctx, in, subject,
			input.Product, input.Stream, input.Variant, input.Vulnerability, input.Component)
		if err != nil {
			return nil, err
		}
		intents, err := finding.NewStore(in.DB.DB).FixingIn(ctx, subject, product, issue, component)
		if err != nil {
			return nil, refusedFinding(in, err)
		}

		who := make([]int64, 0, len(intents))
		for _, intent := range intents {
			if intent.Declared {
				who = append(who, intent.DeclaredBy)
			}
		}
		names, err := access.NewStore(in.DB.DB).Names(ctx, who)
		if err != nil {
			return nil, wentWrong(in.Logger, "who declared these could not be read", err)
		}

		out := &struct{ Body FixBody }{}
		out.Body.Items = make([]FixTargetBody, 0, len(intents))
		for _, intent := range intents {
			body := FixTargetBody{
				Stream: intent.Stream, Variant: intent.Variant,
				Places: intent.Places, State: fixState(intent),
			}
			if intent.Declared {
				body.DeclaredBy = names[intent.DeclaredBy]
				body.DeclaredAt = intent.DeclaredAt.Format(time.RFC3339)
				body.Elsewhere = intent.Elsewhere
			}
			// A build that has gone out of support since it was chosen is
			// listed and not counted. Counted as outstanding it would never
			// clear; counted as clear it would claim a fix nobody shipped.
			if intent.Counts() {
				out.Body.Declared++
				if intent.Clear() {
					out.Body.Clear++
				}
				if intent.Missed() {
					out.Body.Missed++
				}
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		out.Body.Resolved = out.Body.Declared > 0 && out.Body.Clear == out.Body.Declared
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "set-fix-targets", Method: http.MethodPut, Path: path,
		Summary: "Say which builds this will be fixed in",
		Description: "Replaces the set of builds this issue is to be fixed in. Declared " +
			"intent, not commits — nothing here watches a repository.\n\n" +
			"**A set, written whole.** Intent spans several releases and is decided in one " +
			"sitting, so what is sent is what the answer now is; sending an empty list " +
			"withdraws the plan. A build already chosen keeps the date it was chosen on, " +
			"because rewriting the set to add one release would otherwise move every date in " +
			"it to today.\n\n" +
			"**It covers the product, not the build in the path**, like assignment: the path " +
			"says which finding is being looked at, and the plan belongs to the work it is " +
			"part of.\n\n" +
			"A release out of support cannot be chosen, and naming one is refused rather than " +
			"quietly dropped — dropping it leaves somebody believing a release is covered.",
		Tags: []string{"Findings"},
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Stream        string `path:"stream"`
		Variant       string `path:"variant"`
		Vulnerability string `path:"vulnerability"`
		Component     string `path:"component"`
		Body          struct {
			Builds []FixInBody `json:"builds" doc:"The builds it will be fixed in. Empty withdraws the plan"`
		}
	}) (*struct {
		Body struct {
			Declared int `json:"declared" doc:"Builds newly chosen by this request"`
		}
	}, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		product, _, issue, component, err := locateFinding(ctx, in, subject,
			input.Product, input.Stream, input.Variant, input.Vulnerability, input.Component)
		if err != nil {
			return nil, err
		}
		// Authorized before any build named in the body is resolved.
		// Looking them up first and refusing after answers "does this
		// release exist" for anybody who can merely read the product.
		if !subject.Triages(access.Public, product) {
			return nil, noSuchFinding()
		}

		names := catalog.NewStore(in.DB.DB)
		builds := make([]int64, 0, len(input.Body.Builds))
		// Where the work is happening, per build, for the ones that
		// said . A build that said nothing is absent from the map
		// rather than present and empty, so re-sending a plan without
		// links does not erase the links it already had.
		elsewhere := map[int64]string{}
		for _, want := range input.Body.Builds {
			named, err := names.LocateVisible(ctx, subject, input.Product, want.Stream, want.Variant)
			if err != nil {
				return nil, noSuchProduct()
			}
			target, err := names.ExistingTarget(ctx, named.StreamID, named.VariantID)
			if err != nil {
				return nil, nothingScannedThere()
			}
			builds = append(builds, target.ID)
			if want.Elsewhere != nil {
				elsewhere[target.ID] = *want.Elsewhere
			}
		}

		declared, err := finding.NewStore(in.DB.DB).FixIn(ctx, subject, product, issue,
			component, builds, elsewhere)
		if err != nil {
			return nil, refusedFinding(in, err)
		}
		out := &struct {
			Body struct {
				Declared int `json:"declared" doc:"Builds newly chosen by this request"`
			}
		}{}
		out.Body.Declared = declared
		return out, nil
	})
}

// BuildBody names one build: a release and the way it is built.
type BuildBody struct {
	Stream  string `json:"stream" minLength:"1"`
	Variant string `json:"variant" minLength:"1"`
}

// fixState says where a build stands in one word.
func fixState(intent finding.Intent) string {
	switch {
	case intent.PastEndOfLife:
		return "retired"
	case intent.Missed():
		return "missed"
	case intent.Counts() && intent.Places > 0:
		return "fixing"
	case intent.Clear():
		return "clear"
	case intent.Gone():
		return "gone"
	default:
		return "undecided"
	}
}
