// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// RuleBody is a standing rule that hands work nobody holds to a team.
type RuleBody struct {
	ID   int64  `json:"id"`
	Name string `json:"name" doc:"The name, so a placement can be explained in words"`
	Team string `json:"team" doc:"The team work lands on, by the name that addresses it"`
	// TeamDisplayName is the label shown beside it. The field above is the one
	// add-assignment-rule resolves through TeamByName, which matches the folded
	// name column — so a team declared "platform-security" and displayed
	// "Platform Security" lists as the label, and sending that back finds no
	// team at all.
	TeamDisplayName string `json:"team_name,omitempty" doc:"The team's display name, where it differs from its name"`
	// TeamRetired marks a rule that places nothing, because its team is out
	// of use.
	TeamRetired bool `json:"team_retired,omitempty" doc:"Whether the team is retired. A rule whose team is retired places nothing"`
	// Order is the whole of the precedence: first match wins.
	Order int `json:"order" doc:"Its position among the others. The first rule that matches places the work"`
	// Upstream is the key that matters: one rule naming a source package
	// catches every binary package built from it, wherever they sit.
	Upstream string `json:"upstream,omitempty" doc:"A source package name. Catches every binary package built from it"`
	Beneath  string `json:"beneath,omitempty" doc:"A component name. Catches it and everything sitting under it, in every build"`
	Reports  bool   `json:"reports,omitempty" doc:"Whether it places the product's vulnerability reports rather than findings. A rule placing reports names no package and no place"`
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

func registerAssignmentRules(api huma.API, in core.Deps) {
	const path = "/v1/products/{product}/assignment-rules"

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-assignment-rules", Method: http.MethodGet, Path: path,
		Summary: "List assignment rules",
		Description: "The standing rules for this product, in the order they are tried.\n\n" +
			"First match wins, and which rule placed a finding is recorded on the finding.",
		Tags: []string{"Administration"},
	}, core.PerProduct, "", core.TriageRights()...), func(ctx context.Context, input *struct {
		Product string `path:"product"`
	}) (*core.ListOutput[RuleBody], error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		product, err := core.ProductNamedVisibly(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		// The store asks for triage on the product, which is what the
		// declaration says and what its sibling routes enforce. Somebody who
		// can see the product already knows it exists, so they are refused
		// for the role, as an issue act refuses them.
		rules, err := finding.NewStore(in.DB.DB).Rules(ctx, subject, product.ID)
		if errors.Is(err, access.ErrDenied) {
			return nil, huma.Error403Forbidden("not authorized")
		}
		if err != nil {
			return nil, core.WentWrong(in.Logger, "the rules could not be read", err)
		}
		owners := make([]int64, 0, len(rules))
		for _, rule := range rules {
			owners = append(owners, rule.TeamID)
		}
		teams, err := teamsByID(ctx, in, owners)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "the teams could not be read", err)
		}
		out := &core.ListOutput[RuleBody]{}
		out.Body.Items = make([]RuleBody, 0, len(rules))
		for _, rule := range rules {
			out.Body.Items = append(out.Body.Items, RuleBody{
				ID: rule.ID, Name: rule.Name, Team: teams[rule.TeamID].Address,
				TeamDisplayName: teams[rule.TeamID].Display,
				TeamRetired:     teams[rule.TeamID].Retired,
				Order:           rule.Ordinal, Upstream: rule.Upstream, Beneath: rule.Beneath,
				Reports: rule.Reports,
			})
		}
		return out, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "preview-assignment-rule", Method: http.MethodGet, Path: path + "/preview",
		Summary: "Preview what an assignment rule would catch",
		Description: "Answers what a rule with these keys matches, without recording " +
			"anything: the components it names, how many pieces of work sit at them, and how " +
			"many of those nobody holds.\n\n" +
			"`*` matches any run of characters in either key.\n\n" +
			"It does not account for the rules already there. First match wins, so what " +
			"this catches is what it would place only where no earlier rule claimed it first.\n\n" +
			"Send `reports` instead of either key for a rule placing vulnerability reports: " +
			"`work` is then the product's open reports and `unheld` those nobody holds, " +
			"counted where you read the product's reports and zero elsewhere.",
		Tags: []string{"Administration"},
	}, core.PerProduct, "", core.TriageRights()...), func(ctx context.Context, input *struct {
		Product  string `path:"product"`
		Upstream string `query:"upstream" maxLength:"191" doc:"A source package name, with * for any run of characters"`
		Beneath  string `query:"beneath" maxLength:"191" doc:"A component name, with * for any run of characters"`
		Reports  bool   `query:"reports" doc:"Preview a rule placing vulnerability reports"`
	}) (*CatchesOutput, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		// Triage at any visibility, as reading the rules asks. What comes
		// back is narrowed to what the asker may read, so somebody who
		// triages code findings alone counts the code findings a rule would place.
		product, err := core.ProductNamedVisibly(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		if !subject.TriagesAnyIn(product.ID) {
			return nil, huma.Error403Forbidden("not authorized")
		}
		if input.Reports {
			if input.Upstream != "" || input.Beneath != "" {
				return nil, huma.Error422UnprocessableEntity(reportRuleKeyed)
			}
			caught, err := finding.NewStore(in.DB.DB).ReportsWouldMatch(ctx, subject, product.ID)
			if err != nil {
				return nil, core.WentWrong(in.Logger, "what that rule would catch could not be read", err)
			}
			out := &CatchesOutput{}
			out.Body.Components = []string{}
			out.Body.Work, out.Body.Unheld = caught.Open, caught.Unheld
			return out, nil
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
			return nil, core.WentWrong(in.Logger, "what that rule would catch could not be read", err)
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

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "add-assignment-rule", Method: http.MethodPost, Path: path,
		Summary: "Add an assignment rule",
		Description: "Records a standing rule and queues it against what is already open.\n\n" +
			"It matches on component identity as well as on a place in the tree. A rule " +
			"naming a source package catches every binary package built from it, wherever " +
			"they sit.\n\n" +
			"It places only work nobody holds. A human assignment always wins, and " +
			"adding a rule never takes something out of somebody's hands.\n\n" +
			"It places work only at a visibility one member of the team reads. Undisclosed " +
			"or internal work nobody on the team reads stays unassigned.\n\n" +
			"Send `reports` and neither key for a rule placing the product's vulnerability " +
			"reports nobody holds. A report is placed only where one member of the team reads " +
			"undisclosed work here, and a report recorded later is placed as it is recorded.\n\n" +
			"Applying it to what is open is queued rather than done here. The reply says " +
			"the rule was recorded, not that the sweep has finished. Where the queue is " +
			"full the rule is not recorded and the answer is 503: send it again later.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusCreated,
	}, core.PerProduct, "A rule hands work to somebody, continuously, on behalf of whoever wrote it.",
		[]access.Role{access.Assigner}...), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Body    struct {
			Name     string `json:"name" minLength:"1" maxLength:"120"`
			Team     string `json:"team" minLength:"1" doc:"The team work lands on, by name"`
			Upstream string `json:"upstream,omitempty" maxLength:"191" doc:"A source package name"`
			Beneath  string `json:"beneath,omitempty" maxLength:"191" doc:"A component name, matching it and everything under it"`
			Reports  bool   `json:"reports,omitempty" doc:"Whether it places vulnerability reports rather than findings. Refused with either key"`
		}
	}) (*struct{ Body RuleBody }, error) {
		subject, product, err := ruleWriter(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		if input.Body.Reports && (input.Body.Upstream != "" || input.Body.Beneath != "") {
			return nil, huma.Error422UnprocessableEntity(reportRuleKeyed)
		}
		var rule *finding.AssignmentRule
		var team *access.Team
		if err := core.Changing(ctx, in.DB, in.Logger, func(ctx context.Context, tx bun.Tx) error {
			var err error
			if team, err = core.TeamNamed(ctx, in.Logger, access.NewStore(tx), input.Body.Team); err != nil {
				return err
			}
			store := finding.NewStore(tx)
			if input.Body.Reports {
				rule, err = store.AddReportRule(ctx, subject, product, team.ID, input.Body.Name)
			} else {
				rule, err = store.AddRule(ctx, subject, product, team.ID,
					input.Body.Name, input.Body.Upstream, input.Body.Beneath)
			}
			if err != nil {
				return core.Asked(in.Logger, err)
			}
			if err := core.Noted(ctx, tx, trail.AssignmentRule, input.Product+" · "+rule.Name,
				nil, trail.Said("to "+team.Called(), true)); err != nil {
				return core.NotRecorded(in.Logger, err)
			}
			return queueSweep(ctx, in, tx, product)
		}); err != nil {
			return nil, err
		}

		shown := ""
		if team.DisplayName != "" && team.DisplayName != team.Name {
			shown = team.DisplayName
		}
		return &struct{ Body RuleBody }{Body: RuleBody{
			ID: rule.ID, Name: rule.Name, Team: team.Name, TeamDisplayName: shown,
			Order:    rule.Ordinal,
			Upstream: rule.Upstream, Beneath: rule.Beneath, Reports: rule.Reports,
		}}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "retire-assignment-rule", Method: http.MethodDelete,
		Path:    path + "/{id}",
		Summary: "Retire an assignment rule",
		Description: "Takes a rule out of use. What it already placed stays placed: " +
			"changing a rule never takes something out of somebody's hands, and that holds " +
			"for a team's queue as much as for a person.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusNoContent,
	}, core.PerProduct, "", []access.Role{access.Assigner}...),
		func(ctx context.Context, input *struct {
			Product string `path:"product"`
			ID      int64  `path:"id"`
		}) (*struct{}, error) {
			subject, product, err := ruleWriter(ctx, in, input.Product)
			if err != nil {
				return nil, err
			}
			if err := core.Changing(ctx, in.DB, in.Logger, func(ctx context.Context, tx bun.Tx) error {
				if err := finding.NewStore(tx).RetireRule(ctx, subject, product, input.ID); err != nil {
					return core.Absent(in.Logger, err, "that rule could not be retired", core.NoSuchRule)
				}
				if err := core.Noted(ctx, tx, trail.AssignmentRule,
					input.Product+" · "+strconv.FormatInt(input.ID, 10),
					trail.Said("in use", true), nil); err != nil {
					return core.NotRecorded(in.Logger, err)
				}
				return nil
			}); err != nil {
				return nil, err
			}
			return &struct{}{}, nil
		})
}

// reportRuleKeyed refuses a rule placing reports that names a key.
const reportRuleKeyed = "a rule placing reports names no package and no place: a report sits at neither"

// ruleWriter resolves who is asking and the product they are asking about, and
// refuses somebody who may not hand work to anybody.
//
// The conjunction is checked here rather than by the route's own role list,
// which is satisfied by any one of what it names. Writing a rule performs the
// act the assigner right is named for — continuously, on behalf of whoever
// wrote it — so it asks for that right and not merely for triage.
func ruleWriter(ctx context.Context, in core.Deps, name string) (access.Subject, int64, error) {
	subject, err := core.Reading(ctx)
	if err != nil {
		return access.Subject{}, 0, err
	}
	product, err := core.ProductNamedVisibly(ctx, in, subject, name)
	if err != nil {
		return access.Subject{}, 0, err
	}
	if !subject.Holds(access.Assigner, product.ID) {
		// The product resolved, so the caller can see it: refused for the
		// role. A product they cannot see was answered as not there above.
		return access.Subject{}, 0, huma.Error403Forbidden("not authorized")
	}
	return subject, product.ID, nil
}

// queueSweep asks for the rules to be applied to what is already open, in the
// transaction that records the rule.
//
// The rule and its sweep commit together. A rule recorded without its sweep
// leaves every open finding it covers unrouted until another rule is saved, so
// a full queue refuses the rule and the caller sends it again.
func queueSweep(ctx context.Context, in core.Deps, tx bun.Tx, productID int64) error {
	_, err := in.Queue.AddTx(ctx, tx, queue.AssignmentSweep, strconv.FormatInt(productID, 10))
	switch {
	case errors.Is(err, queue.ErrBacklogFull):
		return huma.NewError(http.StatusServiceUnavailable,
			"too much work is waiting to be done, so the rule was not recorded: send it again later")
	case err != nil:
		return core.WentWrong(in.Logger, "applying the rule could not be queued, so it was not recorded", err)
	}
	return nil
}

// ruleTeam is a rule's team as the listing names it: the name a write
// resolves, the one a screen shows, and whether it is still in use.
type ruleTeam struct {
	core.Named
	Retired bool
}

// teamsByID is the named teams' names, by identifier, retired ones included,
// so a rule whose team was retired still names it.
func teamsByID(ctx context.Context, in core.Deps, ids []int64) (map[int64]ruleTeam, error) {
	teams, err := access.NewStore(in.DB.DB).TeamsByID(ctx, ids)
	if err != nil {
		return nil, err
	}
	by := make(map[int64]ruleTeam, len(teams))
	for id, team := range teams {
		one := ruleTeam{Named: core.Named{Address: team.Name}, Retired: team.RetiredAt != nil}
		if team.DisplayName != "" && team.DisplayName != team.Name {
			one.Display = team.DisplayName
		}
		by[id] = one
	}
	return by, nil
}
