// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// RuleBody is a standing rule that hands work nobody holds to a team.
type RuleBody struct {
	ID   int64  `json:"id"`
	Name string `json:"name" doc:"The name, so a placement can be explained in words"`
	Team string `json:"team" doc:"The team work lands on, by the name that addresses it"`
	// TeamDisplayName is the label shown beside it. The field above is the one
	// add-routing-rule resolves through TeamByName, which matches the folded
	// name column — so a team declared "platform-security" and displayed
	// "Platform Security" lists as the label, and sending that back finds no
	// team at all.
	TeamDisplayName string `json:"team_display_name,omitempty" doc:"That team's display name, where it was declared with one"`
	// Order is the whole of the precedence: first match wins.
	Order int `json:"order" doc:"Its position among the others. The first rule that matches places the work"`
	// Upstream is the key that matters: one rule naming a source package
	// catches every binary package built from it, wherever they sit.
	Upstream string `json:"upstream,omitempty" doc:"A source package name. Catches every binary package built from it"`
	Beneath  string `json:"beneath,omitempty" doc:"A component name. Catches it and everything sitting under it, in every build"`
}

// CatchesOutput is what a rule would match, before anybody saves it.
type CatchesOutput struct {
	Body struct {
		Components []string `json:"components" doc:"The components it names, at most twenty"`
		Total      int      `json:"total" doc:"The number of distinct components it matches. More than the list where the list was cut"`
		Work       int      `json:"work" doc:"Pieces of work at those components — one issue in one component, whatever it sits at"`
		Unheld     int      `json:"unheld" doc:"The number of those nobody holds, which is what a rule may place"`
	}
}

func registerRouting(api huma.API, in Ingest) {
	const path = "/v1/products/{product}/routing-rules"

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-routing-rules", Method: http.MethodGet, Path: path,
		Summary: "List the rules that route work to teams",
		Description: "The standing rules for this product, in the order they are tried.\n\n" +
			"First match wins, and which rule placed a finding is recorded on the finding: " +
			"an unwritten precedence is forgettable, and the question it answers — where did " +
			"this come from — is asked months later by somebody who was not there.",
		Tags: []string{"Administration"},
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		Product string `path:"product"`
	}) (*listOutput[RuleBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		product, err := productNamedVisibly(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		// A rule is configuration rather than a finding, so there is nothing
		// in it for the data layer to narrow: a reader either gets the whole
		// precedence order or none of it. The declaration says triage and its
		// three siblings enforce it, so this one does too — read against each
		// other they say different things, which is the whole failure mode
		// this pair is kept in step to avoid.
		if !subject.TriagesIn(product.ID) {
			return nil, noSuchProduct()
		}
		rules, err := finding.NewStore(in.DB.DB).Rules(ctx, product.ID)
		if err != nil {
			return nil, wentWrong(in.Logger, "the rules could not be read", err)
		}
		teams, err := teamsByID(ctx, in)
		if err != nil {
			return nil, wentWrong(in.Logger, "the teams could not be read", err)
		}
		out := &listOutput[RuleBody]{}
		out.Body.Items = make([]RuleBody, 0, len(rules))
		for _, rule := range rules {
			out.Body.Items = append(out.Body.Items, RuleBody{
				ID: rule.ID, Name: rule.Name, Team: teams[rule.TeamID].Address,
				TeamDisplayName: teams[rule.TeamID].Display,
				Order:           rule.Ordinal, Upstream: rule.Upstream, Beneath: rule.Beneath,
			})
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "preview-routing-rule", Method: http.MethodGet, Path: path + "/preview",
		Summary: "Preview what a routing rule would catch",
		Description: "Answers what a rule with these keys matches, without recording " +
			"anything: the components it names, how many pieces of work sit at them, and how " +
			"many of those nobody holds.\n\n" +
			"A rule whose reach nobody can see before saving is a rule that sweeps the " +
			"estate on a guess, and one naming something nothing is called places nothing, " +
			"silently — which is the worst way for a rule to be wrong, because it still looks " +
			"like a rule. `*` matches any run of characters in either key.\n\n" +
			"It does not account for the rules already there. First match wins, so what " +
			"this catches is what it would place only where no earlier rule claimed it first.",
		Tags: []string{"Administration"},
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		Product  string `path:"product"`
		Upstream string `query:"upstream" maxLength:"191" doc:"A source package name, with * for any run of characters"`
		Beneath  string `query:"beneath" maxLength:"191" doc:"A component name, with * for any run of characters"`
	}) (*CatchesOutput, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		product, err := productNamedVisibly(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		// Declared triage, like the rule it previews. What comes back is
		// narrowed to what the asker may read, but a preview is part of
		// writing a rule and nobody who may not write one has a reason to run
		// it.
		if !subject.TriagesIn(product.ID) {
			return nil, noSuchProduct()
		}
		if input.Upstream == "" && input.Beneath == "" {
			return nil, huma.Error422UnprocessableEntity(
				"a rule that matches nothing places nothing: name a source package, " +
					"a place in the tree, or both")
		}
		caught, err := finding.NewStore(in.DB.DB).
			WouldMatch(ctx, subject, product.ID, input.Upstream, input.Beneath, 20)
		switch {
		case errors.Is(err, finding.ErrTooBroad):
			// The same refusal writing the rule gives, in the same words: a
			// preview that answered where the rule could not be saved would
			// be a preview of something nobody can have.
			return nil, huma.Error422UnprocessableEntity(err.Error())
		case err != nil:
			return nil, wentWrong(in.Logger, "what that rule would catch could not be read", err)
		}
		out := &CatchesOutput{}
		out.Body.Components = caught.Components
		if out.Body.Components == nil {
			out.Body.Components = []string{}
		}
		out.Body.Total = caught.Total
		out.Body.Work = caught.Work
		out.Body.Unheld = caught.Unheld
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "add-routing-rule", Method: http.MethodPost, Path: path,
		Summary: "Add a rule that routes work to a team",
		Description: "Records a standing rule and queues it against what is already open.\n\n" +
			"It matches on component identity as well as on a place in the tree. The " +
			"source package is the key that matters: one rule naming it catches every binary " +
			"package built from it, wherever they sit — a kernel is one source package " +
			"appearing at many places under many consumers, and a subtree rule would need a " +
			"line per place and would still miss tomorrow's.\n\n" +
			"It places only work nobody holds. A human assignment always wins, and " +
			"adding a rule never takes something out of somebody's hands.\n\n" +
			"Turning one on is a bulk write, so it is queued rather than done here: one " +
			"rule naming a source package sweeps thousands of existing findings, and saving " +
			"a form must not hold a transaction open across the estate. The reply says the " +
			"rule was recorded, not that the sweep has finished.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusCreated,
	}, perProduct, "A rule hands work to somebody, continuously, on behalf of whoever wrote it.",
		[]access.Role{access.Assigner}...), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Body    struct {
			Name     string `json:"name" minLength:"1" maxLength:"120"`
			Team     string `json:"team" minLength:"1" doc:"The team work lands on, by name"`
			Upstream string `json:"upstream,omitempty" doc:"A source package name"`
			Beneath  string `json:"beneath,omitempty" doc:"A component name, matching it and everything under it"`
		}
	}) (*struct{ Body RuleBody }, error) {
		subject, product, _, err := routable(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		var rule *finding.Routing
		var team *access.Team
		if err := changing(ctx, in.DB, in.Logger, func(ctx context.Context, tx bun.Tx) error {
			var err error
			if team, err = access.NewStore(tx).TeamByName(ctx, input.Body.Team); err != nil {
				return noSuchTeamNamed(input.Body.Team)
			}
			if rule, err = finding.NewStore(tx).AddRule(ctx, subject, product, team.ID,
				input.Body.Name, input.Body.Upstream, input.Body.Beneath); err != nil {
				return asked(in.Logger, err)
			}
			if err := noted(ctx, tx, trail.Routing, input.Product+" · "+rule.Name,
				nil, trail.Said("to "+team.Called(), true)); err != nil {
				return notRecorded(in.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		queueSweep(ctx, in, product)

		shown := ""
		if team.DisplayName != "" && team.DisplayName != team.Name {
			shown = team.DisplayName
		}
		return &struct{ Body RuleBody }{Body: RuleBody{
			ID: rule.ID, Name: rule.Name, Team: team.Name, TeamDisplayName: shown,
			Order:    rule.Ordinal,
			Upstream: rule.Upstream, Beneath: rule.Beneath,
		}}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "retire-routing-rule", Method: http.MethodDelete,
		Path:    path + "/{id}",
		Summary: "Retire a routing rule",
		Description: "Takes a rule out of use. What it already placed stays placed: " +
			"changing a rule never takes something out of somebody's hands, and that holds " +
			"for a team's queue as much as for a person.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusNoContent,
	}, perProduct, "", []access.Role{access.Assigner}...),
		func(ctx context.Context, input *struct {
			Product string `path:"product"`
			ID      int64  `path:"id"`
		}) (*struct{}, error) {
			subject, product, _, err := routable(ctx, in, input.Product)
			if err != nil {
				return nil, err
			}
			if err := changing(ctx, in.DB, in.Logger, func(ctx context.Context, tx bun.Tx) error {
				if err := finding.NewStore(tx).RetireRule(ctx, subject, product, input.ID); err != nil {
					return absent(in.Logger, err, "that rule could not be retired", noSuchRule)
				}
				if err := noted(ctx, tx, trail.Routing,
					input.Product+" · "+strconv.FormatInt(input.ID, 10),
					trail.Said("in use", true), nil); err != nil {
					return notRecorded(in.Logger, err)
				}
				return nil
			}); err != nil {
				return nil, err
			}
			return &struct{}{}, nil
		})
}

// routable resolves who is asking and the product they are asking about, and
// refuses somebody who may not hand work to anybody.
//
// The conjunction is checked here rather than by the route's own role list,
// which is satisfied by any one of what it names. Writing a rule performs the
// act the assigner right is named for — continuously, on behalf of whoever
// wrote it — so it asks for that right and not merely for triage.
func routable(ctx context.Context, in Ingest, name string) (access.Subject, int64,
	*access.Store, error) {

	subject, err := reading(ctx)
	if err != nil {
		return access.Subject{}, 0, nil, err
	}
	if in.DB == nil {
		return access.Subject{}, 0, nil, noDatabase(in.Logger)
	}
	product, err := productNamedVisibly(ctx, in, subject, name)
	if err != nil {
		return access.Subject{}, 0, nil, err
	}
	if !subject.Holds(access.Assigner, product.ID) {
		// Answered as a product that is not there, the way every other
		// refusal about a finding is: guessing a name says nothing.
		return access.Subject{}, 0, nil, noSuchProduct()
	}
	return subject, product.ID, access.NewStore(in.DB.DB), nil
}

// queueSweep asks for the rules to be applied to what is already open.
//
// Queued rather than run here. A failure to queue is logged rather than
// returned: the rule is recorded either way, and answering with an error would
// invite a retry that records it twice.
func queueSweep(ctx context.Context, in Ingest, productID int64) {
	if in.Queue == nil {
		return
	}
	if _, err := in.Queue.Add(ctx, queue.Route,
		strconv.FormatInt(productID, 10)); err != nil {
		in.logger().Error("could not queue a routing sweep", "error", err, "product", productID)
	}
}

// teamsByID is every team's two names, by identifier: the one a write resolves
// and the one a screen shows.
func teamsByID(ctx context.Context, in Ingest) (map[int64]named, error) {
	teams, err := access.NewStore(in.DB.DB).Teams(ctx, "", database.InBulk.Most)
	if err != nil {
		return nil, err
	}
	by := make(map[int64]named, len(teams))
	for _, team := range teams {
		one := named{Address: team.Name}
		if team.DisplayName != "" && team.DisplayName != team.Name {
			one.Display = team.DisplayName
		}
		by[team.ID] = one
	}
	return by, nil
}
