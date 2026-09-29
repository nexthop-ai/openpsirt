// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// Stating policy on what exists.
//
// Per-product policy that changes what the tool reports without anything
// being scanned. Three of these move what carries a deadline at all, so each
// queues a rewrite away from the request: the line a product triages at, a
// product's end of life and a stream's end of life. A release's details and a
// product's pair thresholds move no deadline and queue nothing; they sit here
// as the same kind of policy rather than beside the declarations they amend.
func registerCatalogPolicy(api huma.API, d core.Declaring) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "set-product-pair-thresholds", Method: http.MethodPut,
		Path:    "/v1/products/{product}/pair-thresholds",
		Summary: "Set when one pair's agreements are raised for a product",
		Description: "Sets this product's own thresholds for telling administrators that one " +
			"pair of people is agreeing to most of its work: the share of its agreements, as " +
			"a percentage, and the fewest people who may approve here for that share to count. " +
			"Both are replaced by what is sent, and zero or left off follows the deployment " +
			"again. Recorded in the administrative trail.",
		Tags: []string{"Catalog"}, DefaultStatus: http.StatusNoContent,
	}, core.DeploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Body    core.PairThresholdsBody
	}) (*struct{}, error) {
		if err := core.Administrating(ctx); err != nil {
			return nil, err
		}
		var share, approvers *int
		if in.Body.Share > 0 {
			share = &in.Body.Share
		}
		if in.Body.Approvers > 0 {
			approvers = &in.Body.Approvers
		}
		return &struct{}{}, core.Changing(ctx, d.DB, d.Logger, func(ctx context.Context, tx bun.Tx) error {
			store, product, err := core.ProductIn(ctx, d, tx, in.Product)
			if err != nil {
				return err
			}
			was := thresholdsSaid(product.PairShare, product.PairApprovers)
			if err := store.SetPairThresholds(ctx, product.ID, share, approvers); err != nil {
				return core.WentWrong(d.Logger, "those thresholds could not be recorded", err)
			}
			became := thresholdsSaid(share, approvers)
			if err := core.Noted(ctx, tx, trail.Setting, "pair thresholds of "+product.Name,
				trail.Said(was, was != ""), trail.Said(became, became != "")); err != nil {
				return core.NotRecorded(d.Logger, err)
			}
			return nil
		})
	})

	huma.Register(api, core.Requiring(huma.Operation{
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
	}, core.DeploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Body    core.TriageFloorBody
	}) (*struct{}, error) {
		if err := core.Administrating(ctx); err != nil {
			return nil, err
		}
		// The same words the deployment's line takes, checked the same way. A
		// product that could be set to something the deployment could not
		// would be a second vocabulary for one idea.
		word := strings.TrimSpace(strings.ToLower(string(in.Body.Floor)))
		if word != "" && !slices.Contains(theFloor, word) {
			return nil, huma.Error422UnprocessableEntity(
				fmt.Sprintf("%q is not a line to triage from — write one of %s, "+
					"or nothing at all to follow the deployment",
					in.Body.Floor, strings.Join(theFloor, ", ")))
		}
		var product *catalog.Product
		if err := core.Changing(ctx, d.DB, d.Logger, func(ctx context.Context, tx bun.Tx) error {
			var store *catalog.Store
			var err error
			if store, product, err = core.ProductIn(ctx, d, tx, in.Product); err != nil {
				return err
			}
			// Absent means the product follows the deployment, which is a
			// different act from stating the deployment's current line: a
			// blank and an unset value have to stay distinguishable in the
			// record.
			before := product.TriageFloor
			if err := store.SetTriageFloor(ctx, product.ID, word); err != nil {
				return core.WentWrong(d.Logger, "that line could not be recorded", err)
			}
			// The line one product triages at, recorded like the deployment's
			// own: it is one of the three levers that rewrite what this tool
			// reports without anything being scanned.
			if err := core.Noted(ctx, tx, trail.Setting, "triage floor of "+product.Name,
				trail.Said(core.WordStated(before), before != nil),
				trail.Said(word, word != "")); err != nil {
				return core.NotRecorded(d.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		if d.RewriteDeadlines != nil {
			d.RewriteDeadlines(ctx, "triage floor of product "+product.Name, word)
		}
		return &struct{}{}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
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
	}, core.DeploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Body    core.EndOfLifeBody
	}) (*struct{}, error) {
		if err := core.Administrating(ctx); err != nil {
			return nil, err
		}
		on, err := core.CalendarDate(in.Body.On)
		if err != nil {
			return nil, err
		}
		var product *catalog.Product
		if err := core.Changing(ctx, d.DB, d.Logger, func(ctx context.Context, tx bun.Tx) error {
			var store *catalog.Store
			var err error
			if store, product, err = core.ProductIn(ctx, d, tx, in.Product); err != nil {
				return err
			}
			before := product.EOLOn
			if err := store.SetProductEndOfLife(ctx, product.ID, on); err != nil {
				return core.WentWrong(d.Logger, "that date could not be recorded", err)
			}
			if err := core.Noted(ctx, tx, trail.Support, product.Name,
				onDay(before), onDay(on)); err != nil {
				return core.NotRecorded(d.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		if d.RewriteDeadlines != nil {
			d.RewriteDeadlines(ctx, "end of life of product "+product.Name, in.Body.On)
		}
		return &struct{}{}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "set-release-details", Method: http.MethodPut,
		Path:    "/v1/products/{product}/streams/{stream}/release",
		Summary: "Set when a release went out and what it was cut from",
		Description: "Records the day a tag actually shipped, and the branch it was cut " +
			"from.\n\n" +
			"Both are settable after the fact, because that is when they are usually " +
			"known. A tag is declared here so scans can be filed against it, which happens " +
			"whenever somebody gets to it — before the release, months after, or while " +
			"backfilling a year. Fixed at declaration, a release recorded late ordered after " +
			"ones that came out before it, and a year entered in an afternoon plotted as a " +
			"single day.\n\n" +
			"The date orders and labels the release-over-release chart. Left unset, the day " +
			"the release was declared here stands in.\n\n" +
			"The parent fills in, and never changes. It is what a branch is " +
			"compared against for release notes, and a pipeline that does not know declares " +
			"the tag without it — so saying it late is the same act arriving late, because " +
			"nothing had been said for it to contradict. Naming a different branch is refused, " +
			"and so is clearing one: a tag is one frozen point and it came from wherever it " +
			"came from. It is a branch and nothing is cut from itself; both are refused rather " +
			"than stored, because a cycle here is a comparison that never returns.\n\n" +
			"An empty date clears the date. An empty parent leaves whatever stands alone.",
		Tags: []string{"Catalog"}, DefaultStatus: http.StatusNoContent,
	}, core.DeploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Body    struct {
			ReleasedOn string `json:"released_on" doc:"The day it went out, as 2026-03-31. Empty clears it, and the day it was declared here stands in"`
			CutFrom    string `json:"cut_from,omitempty" doc:"The branch it was cut from, by name. Fills in where nothing has been said; naming a different one is refused, and empty leaves whatever stands alone"`
		}
	}) (*struct{}, error) {
		if err := core.Administrating(ctx); err != nil {
			return nil, err
		}
		on, err := core.CalendarDate(in.Body.ReleasedOn)
		if err != nil {
			return nil, err
		}
		// Both writes or neither, and every name they turn on resolved inside
		// the transaction that acts on it. Written apart, a date that cannot
		// be recorded leaves the parent filled in permanently — and the parent
		// is what a comparison walks, so the caller's refusal describes a
		// state the database no longer has.
		if err := core.Changing(ctx, d.DB, d.Logger, func(ctx context.Context, tx bun.Tx) error {
			store, product, stream, err := core.StreamIn(ctx, d, tx, in.Product, in.Stream)
			if err != nil {
				return err
			}
			if named := strings.TrimSpace(in.Body.CutFrom); named != "" {
				from, err := store.StreamByName(ctx, product.ID, named)
				if err != nil {
					return core.Undeclared(d.Logger, err, "the release it was cut from could not be looked up")
				}
				filled, err := store.FillInParent(ctx, stream.ID, from.ID)
				if err != nil {
					return core.Asked(d.Logger, err)
				}
				if filled {
					if err := core.Noted(ctx, tx, trail.Release, product.Name+" "+stream.Name+" cut from",
						nil, trail.Said(from.Name, true)); err != nil {
						return core.NotRecorded(d.Logger, err)
					}
				}
			}
			if err := store.SetReleasedOn(ctx, stream.ID, on); err != nil {
				return core.WentWrong(d.Logger, "that date could not be recorded", err)
			}
			if err := core.Noted(ctx, tx, trail.Release, product.Name+" "+stream.Name,
				onDay(stream.ReleasedOn), onDay(on)); err != nil {
				return core.NotRecorded(d.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
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
	}, core.DeploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Body    core.EndOfLifeBody
	}) (*struct{}, error) {
		if err := core.Administrating(ctx); err != nil {
			return nil, err
		}
		on, err := core.CalendarDate(in.Body.On)
		if err != nil {
			return nil, err
		}
		var product *catalog.Product
		var stream *catalog.Stream
		if err := core.Changing(ctx, d.DB, d.Logger, func(ctx context.Context, tx bun.Tx) error {
			var store *catalog.Store
			var err error
			if store, product, stream, err = core.StreamIn(ctx, d, tx, in.Product, in.Stream); err != nil {
				return err
			}
			before := stream.EOLOn
			if err := store.SetStreamEndOfLife(ctx, stream.ID, on); err != nil {
				return core.WentWrong(d.Logger, "that date could not be recorded", err)
			}
			if err := core.Noted(ctx, tx, trail.Support, product.Name+" "+stream.Name,
				onDay(before), onDay(on)); err != nil {
				return core.NotRecorded(d.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		if d.RewriteDeadlines != nil {
			d.RewriteDeadlines(ctx, "end of life of "+product.Name+" "+stream.Name, in.Body.On)
		}
		return &struct{}{}, nil
	})
}

// thresholdsSaid is a product's own pair thresholds as the trail records them,
// or empty where it follows the deployment on both.
func thresholdsSaid(share, approvers *int) string {
	var parts []string
	if share != nil {
		parts = append(parts, fmt.Sprintf("%d%%", *share))
	}
	if approvers != nil {
		parts = append(parts, fmt.Sprintf("%d approvers", *approvers))
	}
	return strings.Join(parts, ", ")
}
