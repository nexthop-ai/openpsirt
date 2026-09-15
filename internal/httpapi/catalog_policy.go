package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// Stating policy on what exists.
//
// The four levers that change what the tool reports without anything being
// scanned: the line a product triages at, a product's end of life, a
// release's details and a stream's end of life. Each of them moves what
// carries a deadline at all, so each queues a rewrite away from the request
// — and that is why they are together rather than filed beside the
// declarations they sit on.
func registerCatalogPolicy(api huma.API, d Declaring) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "set-product-triage-floor", Method: http.MethodPut,
		Path:    "/v1/products/{product}/triage-floor",
		Summary: "Set what a product considers worth triaging",
		Description: "Sets the least severity worth triaging for one product, overriding what " +
			"the deployment says. Below the line a finding is still recorded, still counted and " +
			"still reportable, and it carries no deadline — it is out of the working list, not " +
			"out of the system.\n\n" +
			"An empty value clears the override, so the product follows the deployment again. " +
			"Clearing is not the same as stating the deployment's current line: a product that " +
			"stated it would stop following when the deployment changed.\n\n" +
			"Deadlines are rewritten afterwards, away from the request, because moving the line " +
			"moves what is on a clock at all. The response returns before that has finished.",
		Tags: []string{"Catalog"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Body    TriageFloorBody
	}) (*struct{}, error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		// The same words the deployment's line takes, checked the same way. A
		// product that could be set to something the deployment could not
		// would be a second vocabulary for one idea.
		word := strings.TrimSpace(strings.ToLower(in.Body.Floor))
		if word != "" && !slices.Contains(theFloor, word) {
			return nil, huma.Error422UnprocessableEntity(
				fmt.Sprintf("%q is not a line to triage from — write one of %s, "+
					"or nothing at all to follow the deployment",
					in.Body.Floor, strings.Join(theFloor, ", ")))
		}
		store, err := storeFor(d)
		if err != nil {
			return nil, err
		}
		product, err := store.ProductByName(ctx, in.Product)
		if err != nil {
			return nil, undeclared(d.Logger, err, "that product could not be looked up")
		}
		if err := store.SetTriageFloor(ctx, product.ID, word); err != nil {
			return nil, wentWrong(d.Logger, "that line could not be recorded", err)
		}
		if d.RewriteDeadlines != nil {
			d.RewriteDeadlines(ctx, "triage floor of product "+product.Name, word)
		}
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "set-product-end-of-life", Method: http.MethodPut,
		Path:    "/v1/products/{product}/end-of-life",
		Summary: "Set when a product goes out of support",
		Description: "Sets the date support ends for every release of a product that has not " +
			"stated its own. Past it, nothing on the product carries a remediation deadline and " +
			"a build that stops being scanned is expected rather than a fault.\n\n" +
			"Nothing is deleted or hidden: the findings and the history stay, and stay " +
			"reportable. What ends is what is expected of us.\n\n" +
			"An empty date clears it, because extended support happens. Deadlines are rewritten " +
			"afterwards, away from the request; the response returns before that has finished.",
		Tags: []string{"Catalog"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Body    EndOfLifeBody
	}) (*struct{}, error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		on, err := aDate(in.Body.On)
		if err != nil {
			return nil, err
		}
		store, err := storeFor(d)
		if err != nil {
			return nil, err
		}
		product, err := store.ProductByName(ctx, in.Product)
		if err != nil {
			return nil, undeclared(d.Logger, err, "that product could not be looked up")
		}
		before := product.EOLOn
		if err := store.SetProductEndOfLife(ctx, product.ID, on); err != nil {
			return nil, wentWrong(d.Logger, "that date could not be recorded", err)
		}
		noteDeclared(ctx, d, trail.Support, product.Name, onDay(before), onDay(on))
		if d.RewriteDeadlines != nil {
			d.RewriteDeadlines(ctx, "end of life of product "+product.Name, in.Body.On)
		}
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "set-release-details", Method: http.MethodPut,
		Path:    "/v1/products/{product}/streams/{stream}/release",
		Summary: "Set when a release went out and what it was cut from",
		Description: "Records the day a tag actually shipped, and the branch it was cut " +
			"from.\n\n" +
			"**Both are settable after the fact, because that is when they are usually " +
			"known.** A tag is declared here so scans can be filed against it, which happens " +
			"whenever somebody gets to it — before the release, months after, or while " +
			"backfilling a year. Fixed at declaration, a release recorded late ordered after " +
			"ones that came out before it, and a year entered in an afternoon plotted as a " +
			"single day.\n\n" +
			"The date orders and labels the release-over-release chart. Left unset, the day " +
			"the release was declared here stands in.\n\n" +
			"**The parent fills in, and never changes.** It is what a branch is " +
			"compared against for release notes, and a pipeline that does not know declares " +
			"the tag without it — so saying it late is the same act arriving late, because " +
			"nothing had been said for it to contradict. Naming a different branch is refused, " +
			"and so is clearing one: a tag is one frozen point and it came from wherever it " +
			"came from. It is a branch and nothing is cut from itself; both are refused rather " +
			"than stored, because a cycle here is a comparison that never returns.\n\n" +
			"An empty date clears the date. An empty parent leaves whatever stands alone.",
		Tags: []string{"Catalog"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Body    struct {
			ReleasedOn string `json:"released_on" doc:"The day it went out, as 2026-03-31. Empty clears it, and the day it was declared here stands in"`
			CutFrom    string `json:"cut_from,omitempty" doc:"The branch it was cut from, by name. Fills in where nothing has been said; naming a different one is refused, and empty leaves whatever stands alone"`
		}
	}) (*struct{}, error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		on, err := aDate(in.Body.ReleasedOn)
		if err != nil {
			return nil, err
		}
		store, err := storeFor(d)
		if err != nil {
			return nil, err
		}
		product, err := store.ProductByName(ctx, in.Product)
		if err != nil {
			return nil, undeclared(d.Logger, err, "that product could not be looked up")
		}
		stream, err := store.StreamByName(ctx, product.ID, in.Stream)
		if err != nil {
			return nil, undeclared(d.Logger, err, "that product could not be looked up")
		}
		if named := strings.TrimSpace(in.Body.CutFrom); named != "" {
			from, err := store.StreamByName(ctx, product.ID, named)
			if err != nil {
				return nil, undeclared(d.Logger, err, "that product could not be looked up")
			}
			if err := store.FillInParent(ctx, stream.ID, from.ID); err != nil {
				return nil, asked(d.Logger, err)
			}
		}
		if err := store.SetReleasedOn(ctx, stream.ID, on); err != nil {
			return nil, wentWrong(d.Logger, "that date could not be recorded", err)
		}
		noteDeclared(ctx, d, trail.Release, product.Name+" "+stream.Name,
			onDay(stream.ReleasedOn), onDay(on))
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "set-stream-end-of-life", Method: http.MethodPut,
		Path:    "/v1/products/{product}/streams/{stream}/end-of-life",
		Summary: "Set when a branch or tag goes out of support",
		Description: "Sets the date support ends for one release, overriding what its product " +
			"says. Past it, nothing on the release carries a remediation deadline and a build " +
			"that stops being scanned is expected rather than a fault.\n\n" +
			"An empty date clears the override, so the release follows its product again. " +
			"Clearing is not the same as stating the product's current date: a release that " +
			"stated it would stop following when the product changed.",
		Tags: []string{"Catalog"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Body    EndOfLifeBody
	}) (*struct{}, error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		on, err := aDate(in.Body.On)
		if err != nil {
			return nil, err
		}
		store, err := storeFor(d)
		if err != nil {
			return nil, err
		}
		product, err := store.ProductByName(ctx, in.Product)
		if err != nil {
			return nil, undeclared(d.Logger, err, "that product could not be looked up")
		}
		stream, err := store.StreamByName(ctx, product.ID, in.Stream)
		if err != nil {
			return nil, undeclared(d.Logger, err, "that product could not be looked up")
		}
		before := stream.EOLOn
		if err := store.SetStreamEndOfLife(ctx, stream.ID, on); err != nil {
			return nil, wentWrong(d.Logger, "that date could not be recorded", err)
		}
		noteDeclared(ctx, d, trail.Support, product.Name+" "+stream.Name,
			onDay(before), onDay(on))
		if d.RewriteDeadlines != nil {
			d.RewriteDeadlines(ctx, "end of life of "+product.Name+" "+stream.Name, in.Body.On)
		}
		return &struct{}{}, nil
	})
}
