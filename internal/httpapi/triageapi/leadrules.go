// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/trail"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// LeadRuleState is where a standing rule stands.
type LeadRuleState string

// Schema offers the states a standing rule is in.
func (LeadRuleState) Schema(huma.Registry) *huma.Schema {
	offered := make([]any, 0, len(analysis.RuleStates()))
	for _, each := range analysis.RuleStates() {
		offered = append(offered, string(each))
	}
	return &huma.Schema{Type: huma.TypeString, Enum: offered}
}

// LeadRuleBody is a standing rule that dismisses the leads it names.
type LeadRuleBody struct {
	ID         int64           `json:"id"`
	Rule       string          `json:"rule,omitempty" doc:"The analyzer rule it names, as <tool>/<rule>. Left out, every rule"`
	Prefix     string          `json:"prefix,omitempty" doc:"The path it names, from the top of the checkout. A lead at or under it is covered. Left out, every path"`
	Reason     core.LeadReason `json:"reason" doc:"Why the leads it covers are dismissed"`
	Reasoning  string          `json:"reasoning" doc:"The reasoning, in markdown"`
	ProposedBy int64           `json:"proposed_by" doc:"The person who proposed it"`
	Yours      bool            `json:"yours,omitempty" doc:"Whether you proposed it. The proposer may not approve it"`
	ProposedAt string          `json:"proposed_at" format:"date-time"`
	ApprovedBy *int64          `json:"approved_by,omitempty" doc:"The person who last approved it"`
	ApprovedAt string          `json:"approved_at,omitempty" format:"date-time"`
	Approved   *int            `json:"approved_covering,omitempty" doc:"The open leads it covered when last approved"`
	RetiredAt  string          `json:"retired_at,omitempty" format:"date-time"`
	Covering   int             `json:"covering" doc:"The open leads it names now that you may read, approved or not"`
	State      LeadRuleState   `json:"state" doc:"proposed covers nothing yet. in-force and outgrown dismiss what they name; outgrown names an analyzer rule, covers more than its approver saw by the deployment's factor, and asks to be approved again. A rule naming a path alone is never outgrown. needs-path names an analyzer rule and no path, and covers nothing since the rule was found to find memory safety or injection flaws: retire it and propose it again with a path. retired covers nothing"`
}

// leadRuleBody is a standing rule as the subject reads it.
func leadRuleBody(subject access.Subject, r analysis.StandingRule) LeadRuleBody {
	return LeadRuleBody{
		ID: r.ID, Rule: r.Rule, Prefix: r.Prefix, Reason: core.LeadReason(r.Reason), Reasoning: r.Reasoning,
		ProposedBy: r.ProposedBy, Yours: r.ProposedBy == subject.ID, ProposedAt: core.Stamp(r.ProposedAt),
		ApprovedBy: r.ApprovedBy, ApprovedAt: core.StampAt(r.ApprovedAt), Approved: r.ApprovedCovering,
		RetiredAt: core.StampAt(r.RetiredAt), Covering: r.Covering, State: LeadRuleState(r.State),
	}
}

// leadRuleSaid is a standing rule as the trail records it.
func leadRuleSaid(r analysis.StandingRule) string {
	var named []string
	if r.Rule != "" {
		named = append(named, r.Rule)
	}
	if r.Prefix != "" {
		named = append(named, "under "+r.Prefix)
	}
	return strings.Join(named, " ") + ", " + string(r.Reason)
}

func registerLeadRules(api huma.API, in core.Deps) {
	const path = "/v1/products/{product}/lead-rules"

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-lead-rules", Method: http.MethodGet, Path: path,
		Summary: "List standing rules for leads",
		Description: "Returns the product's standing rules for static analysis leads, retired ones " +
			"included, oldest first, each with how many open leads it names now.",
		Tags: []string{"Triage"},
	}, core.PerProduct, "", access.InternalRead, access.InternalTriage), func(ctx context.Context, input *struct {
		Product string `path:"product"`
	}) (*struct {
		Body struct {
			Items []LeadRuleBody `json:"items"`
		}
	}, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		product, err := core.ProductNamedVisibly(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		rules, err := analysis.StandingRules(ctx, in.DB.DB, subject, product.ID)
		if err != nil {
			return nil, core.Refused(in.Logger, err, "the standing rules could not be read")
		}
		out := &struct {
			Body struct {
				Items []LeadRuleBody `json:"items"`
			}
		}{}
		out.Body.Items = make([]LeadRuleBody, 0, len(rules))
		for _, r := range rules {
			out.Body.Items = append(out.Body.Items, leadRuleBody(subject, r))
		}
		return out, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "propose-lead-rule", Method: http.MethodPost, Path: path,
		Summary: "Propose a standing rule for leads",
		Description: "Records a rule dismissing every open lead of an analyzer rule, every one at or " +
			"under a path, or every one of a rule under a path. At least one of `rule` and `prefix` " +
			"is required, and so are `reason` and `reasoning`. A `rule` with no `prefix` is refused where the rule " +
			"finds memory safety or injection flaws, or where no analyzer has reported it here.\n\n" +
			"It dismisses nothing until somebody other than its author holding `approver` and " +
			"`internal-read` on the product approves it. Its words do not change: retire it and " +
			"propose another. Recorded in the administrative trail.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, core.PerProduct, "", access.InternalTriage), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Body    struct {
			Rule      string          `json:"rule,omitempty" maxLength:"191" doc:"An analyzer rule, as <tool>/<rule>"`
			Prefix    string          `json:"prefix,omitempty" doc:"A path from the top of the checkout"`
			Reason    core.LeadReason `json:"reason" doc:"Why the leads it covers are dismissed"`
			Reasoning string          `json:"reasoning" minLength:"1" doc:"The reasoning, in markdown"`
		}
	}) (*struct{ Body LeadRuleBody }, error) {
		subject, err := leadRulesProduct(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		var rule *analysis.StandingRule
		if err := core.Changing(ctx, in.DB, in.Logger, func(ctx context.Context, tx bun.Tx) error {
			product, err := catalog.NewStore(tx).ProductByName(ctx, input.Product)
			if err != nil {
				return core.Absent(in.Logger, err, "that product could not be looked up", core.NoSuchProduct)
			}
			if rule, err = analysis.ProposeRule(ctx, tx, subject, product.ID, analysis.Proposal{
				Rule: input.Body.Rule, Prefix: input.Body.Prefix,
				Reason: triage.LeadReason(input.Body.Reason), Reasoning: input.Body.Reasoning,
			}, time.Now()); err != nil {
				return core.Asked(in.Logger, err)
			}
			return noteLeadRule(ctx, in, tx, product.Name, *rule, nil, trail.Said("proposed: "+leadRuleSaid(*rule), true))
		}); err != nil {
			return nil, err
		}
		return &struct{ Body LeadRuleBody }{Body: leadRuleBody(subject, *rule)}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "approve-lead-rule", Method: http.MethodPost, Path: path + "/{id}/approval",
		Summary: "Approve a standing rule for leads",
		Description: "Puts a proposed rule in force, recording how many open leads it covers as what " +
			"was approved. An outgrown rule is approved again at its new size; a rule in force is " +
			"refused with 409.\n\n" +
			"Requires `approver` and `internal-read` on the product, and somebody other than the " +
			"rule's author, which is refused with 409. A rule with no path is refused with 422 where its " +
			"analyzer rule has since been found to find memory safety or injection flaws. " +
			"Recorded in the administrative trail.",
		Tags: []string{"Triage"},
	}, core.PerProduct, "", access.Approver), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		ID      int64  `path:"id"`
	}) (*struct{ Body LeadRuleBody }, error) {
		subject, err := leadRulesProduct(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		var rule *analysis.StandingRule
		if err := core.Changing(ctx, in.DB, in.Logger, func(ctx context.Context, tx bun.Tx) error {
			product, err := catalog.NewStore(tx).ProductByName(ctx, input.Product)
			if err != nil {
				return core.Absent(in.Logger, err, "that product could not be looked up", core.NoSuchProduct)
			}
			rule, err = analysis.ApproveRule(ctx, tx, subject, product.ID, input.ID, time.Now())
			switch {
			case errors.Is(err, analysis.ErrNoSuchRule):
				return core.NoSuchLeadRule()
			case errors.Is(err, analysis.ErrRuleInForce), errors.Is(err, analysis.ErrOwnRule):
				return huma.Error409Conflict(err.Error())
			case err != nil:
				return core.Asked(in.Logger, err)
			}
			return noteLeadRule(ctx, in, tx, product.Name, *rule, nil,
				trail.Said("approved covering "+strconv.Itoa(rule.Covering), true))
		}); err != nil {
			return nil, err
		}
		return &struct{ Body LeadRuleBody }{Body: leadRuleBody(subject, *rule)}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "retire-lead-rule", Method: http.MethodDelete, Path: path + "/{id}",
		Summary: "Retire a standing rule for leads",
		Description: "Takes a rule out of use. The leads it covered are open again where nothing " +
			"else answers them. Recorded in the administrative trail.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusNoContent,
	}, core.PerProduct, "", access.InternalTriage), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		ID      int64  `path:"id"`
	}) (*struct{}, error) {
		subject, err := leadRulesProduct(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		return &struct{}{}, core.Changing(ctx, in.DB, in.Logger, func(ctx context.Context, tx bun.Tx) error {
			product, err := catalog.NewStore(tx).ProductByName(ctx, input.Product)
			if err != nil {
				return core.Absent(in.Logger, err, "that product could not be looked up", core.NoSuchProduct)
			}
			rule, err := analysis.RetireRule(ctx, tx, subject, product.ID, input.ID, time.Now())
			switch {
			case errors.Is(err, analysis.ErrNoSuchRule):
				return core.NoSuchLeadRule()
			case err != nil:
				return core.Asked(in.Logger, err)
			}
			return noteLeadRule(ctx, in, tx, product.Name, *rule, trail.Said("in use", true), nil)
		})
	})
}

// leadRulesProduct is who is asking, with a product they cannot see answered
// as not there. The rights each act takes are asked by the act.
func leadRulesProduct(ctx context.Context, in core.Deps, name string) (access.Subject, error) {
	subject, err := core.Reading(ctx)
	if err != nil {
		return access.Subject{}, err
	}
	if _, err := core.ProductNamedVisibly(ctx, in, subject, name); err != nil {
		return access.Subject{}, err
	}
	return subject, nil
}

func noteLeadRule(ctx context.Context, in core.Deps, tx bun.Tx, product string, rule analysis.StandingRule,
	was, became *string) error {

	if err := core.Noted(ctx, tx, trail.LeadRule, product+" · "+strconv.FormatInt(rule.ID, 10),
		was, became); err != nil {
		return core.NotRecorded(in.Logger, err)
	}
	return nil
}
