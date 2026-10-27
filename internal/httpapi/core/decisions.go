// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// StandingDecisionBody is a live decision covering some of a finding's
// occurrences.
type StandingDecisionBody struct {
	DecisionID           int64        `json:"decision_id"`
	Kind                 DecisionKind `json:"kind"`
	DecisionOccurrenceID int64        `json:"decision_occurrence_id" doc:"One representative occurrence of the decision at this finding"`
	// State is the decision's as a whole, not a representative row's: approved
	// only where every live row here is.
	State DecisionStateLive `json:"state" doc:"The decision's state as a whole: approved only when it is approved at every live occurrence here, otherwise proposed"`
	Rows  RowsStandingBody  `json:"rows" doc:"How many of the decision's live occurrences here stand in each state"`
	// SentBackAt is the last time an approver asked for more, where rows were
	// sent back.
	SentBackAt      string        `json:"sent_back_at,omitempty" doc:"The last time rows were sent back to the author"`
	SentBackBecause string        `json:"sent_back_because,omitempty" doc:"The reason given when they were, in markdown"`
	Outcome         Outcome       `json:"outcome"`
	Justification   Justification `json:"justification,omitempty"`
	// FixedVersion is the evidence for a decision that the fix is already
	// here, on the screen the decision is read from. Carried by the audit trail
	// alone, the checkable part of the decision is everywhere except where
	// somebody reads the decision.
	FixedVersion   string   `json:"fixed_version,omitempty" doc:"The package version the decision says the fix arrived in, where it names one"`
	NeedsApproval  bool     `json:"needs_approval,omitempty"`
	ProposedBy     string   `json:"proposed_by" doc:"The person who proposed it, by sign-in identity"`
	ProposedByName string   `json:"proposed_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	ProposedAt     string   `json:"proposed_at"`
	Occurrences    int      `json:"occurrences" doc:"The number of this finding's occurrences the decision covers"`
	Builds         []string `json:"builds" doc:"Every build the decision currently covers, as stream and variant"`
	ApprovedBy     string   `json:"approved_by,omitempty" doc:"The person who agreed, by sign-in identity"`
	ApprovedByName string   `json:"approved_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	ApprovedAt     string   `json:"approved_at,omitempty"`
	// Elsewhere is where this is being worked on outside here.
	Elsewhere string `json:"elsewhere,omitempty" doc:"A ticket, a thread or a change. Stored and never fetched"`
}

// RowsStandingBody counts a decision's live occurrences by where they stand.
type RowsStandingBody struct {
	Proposed int `json:"proposed" doc:"Waiting for a second person"`
	SentBack int `json:"sent_back" doc:"Returned to the author for more"`
	Approved int `json:"approved" doc:"Agreed to and in force"`
}

// EarlierBody is a decision once made here that no longer applies.
type EarlierBody struct {
	DecisionOccurrenceID int64         `json:"decision_occurrence_id"`
	DecisionID           int64         `json:"decision_id"`
	Outcome              Outcome       `json:"outcome"`
	Justification        Justification `json:"justification,omitempty"`
	DeferredUntil        string        `json:"deferred_until,omitempty"`
	// FixedVersion is the evidence an approver checks the already-fixed
	// decision against. Agreeing to a claim of fact without being shown the fact is
	// the failure this outcome is most exposed to.
	FixedVersion   string             `json:"fixed_version,omitempty" doc:"The package version the decision says the fix arrived in, where it names one"`
	ProposedBy     string             `json:"proposed_by" doc:"The person who proposed it, by sign-in identity"`
	ProposedByName string             `json:"proposed_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	ProposedAt     string             `json:"proposed_at"`
	Ended          DecisionStateEnded `json:"ended" doc:"The reason it stopped applying"`
	EndedAt        string             `json:"ended_at,omitempty"`
	About          string             `json:"about,omitempty" doc:"The component upstream version it was a decision about"`
	Reasoning      string             `json:"reasoning" doc:"The reasoning as it last stood, in markdown, offered back rather than thrown away. Empty where you may read only some of the occurrences the decision covers"`
	ApprovedBy     string             `json:"approved_by,omitempty" doc:"The person who last agreed to it, where anybody did, by sign-in identity"`
	ApprovedByName string             `json:"approved_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
}

// SimilarBody is an approved decision at the same occurrences about another
// issue, which may reach this one.
type SimilarBody struct {
	DecisionID           int64         `json:"decision_id" doc:"Pass as extends when deciding to carry it to this issue"`
	DecisionOccurrenceID int64         `json:"decision_occurrence_id"`
	Justification        Justification `json:"justification,omitempty"`
	Reasoning            string        `json:"reasoning" doc:"The reasoning, in markdown. Empty where you may read only some of the occurrences the decision covers"`
	ApprovedBy           string        `json:"approved_by,omitempty" doc:"The person who agreed, by sign-in identity"`
	ApprovedByName       string        `json:"approved_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	ApprovedAt           string        `json:"approved_at,omitempty"`
	Issues               int           `json:"issues" doc:"The number of distinct issues the decision covers"`
}

// ElsewhereBody is an approved decision about this same issue at this same
// occurrence,
// in another product.
//
// Evidence, never an outcome. Offered the way a supplier's VEX statement is:
// something to read and to quote, prefilling a reasoning where somebody asks
// for it and deciding nothing. Another team's decision about their product is
// not a decision about this one — the software shipped around the component
// differs, which is why an occurrence is a component at a position rather than
// a component.
type ElsewhereBody struct {
	Product              string        `json:"product" doc:"The product it was decided in"`
	DecisionID           int64         `json:"decision_id"`
	DecisionOccurrenceID int64         `json:"decision_occurrence_id"`
	Outcome              Outcome       `json:"outcome"`
	Justification        Justification `json:"justification,omitempty"`
	Reasoning            string        `json:"reasoning" doc:"The reasoning, in markdown. Empty where you may read only some of the occurrences the decision covers"`
	ApprovedBy           string        `json:"approved_by,omitempty" doc:"The person who agreed, by sign-in identity"`
	ApprovedByName       string        `json:"approved_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	ApprovedAt           string        `json:"approved_at,omitempty"`
}

// ProductsDecidedIn is the names of the products a set of decisions were made
// in, by identifier.
//
// Resolved here rather than carried on the decision: a name is a fact about the
// catalog, and the read that found the decisions is narrowed by what the
// subject may see — so a name only ever reaches a reader who could already read
// the decision it belongs to.
func ProductsDecidedIn(ctx context.Context, in Deps, rows []triage.Elsewhere) (map[int64]string, error) {
	ids := make([]int64, 0, len(rows))
	for _, one := range rows {
		ids = append(ids, one.ProductID)
	}
	return catalog.NewStore(in.DB.DB).ProductsCalled(ctx, ids)
}

// OrBlank reads a string that may be absent as the string, or as nothing where
// it is absent: an override the product has no opinion of its own on, a
// justification nobody gave.
func OrBlank(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
