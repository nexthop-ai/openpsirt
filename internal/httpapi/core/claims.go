// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// StandingClaimBody is a live claim covering some of a finding's places.
type StandingClaimBody struct {
	ClaimID    int64     `json:"claim_id"`
	Kind       ClaimKind `json:"kind"`
	DecisionID int64     `json:"decision_id" doc:"A representative row of the claim at this finding"`
	// State is the claim's as a whole, not a representative row's: approved
	// only where every live row here is.
	State ClaimStateLive   `json:"state" doc:"The claim's state as a whole: approved only when every live row here is approved, otherwise proposed"`
	Rows  RowsStandingBody `json:"rows" doc:"The state of the claim's rows here"`
	// SentBackAt is the last time an approver asked for more, where rows were
	// sent back.
	SentBackAt      string        `json:"sent_back_at,omitempty" doc:"The last time rows were sent back to the author"`
	SentBackBecause string        `json:"sent_back_because,omitempty" doc:"The reason given when they were, in markdown"`
	Outcome         Outcome       `json:"outcome"`
	Justification   Justification `json:"justification,omitempty"`
	// FixedVersion is the evidence for a claim that the fix is already here,
	// on the screen the claim is read from. Carried by the audit trail alone,
	// the checkable part of the claim is everywhere except where somebody
	// reads the claim.
	FixedVersion   string   `json:"fixed_version,omitempty" doc:"The package version the claim says the fix arrived in, where it claims one has"`
	NeedsApproval  bool     `json:"needs_approval,omitempty"`
	ProposedBy     string   `json:"proposed_by" doc:"The person who proposed it, by sign-in identity"`
	ProposedByName string   `json:"proposed_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	ProposedAt     string   `json:"proposed_at"`
	Places         int      `json:"places" doc:"The number of this finding's places the claim covers"`
	Builds         []string `json:"builds" doc:"Every build the claim currently covers, as stream and variant"`
	ApprovedBy     string   `json:"approved_by,omitempty" doc:"The person who agreed, by sign-in identity"`
	ApprovedByName string   `json:"approved_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	ApprovedAt     string   `json:"approved_at,omitempty"`
	// Elsewhere is where this is being worked on outside here.
	Elsewhere string `json:"elsewhere,omitempty" doc:"A ticket, a thread or a change. Stored and never fetched"`
}

// RowsStandingBody counts a claim's live rows by where they stand.
type RowsStandingBody struct {
	Proposed int `json:"proposed" doc:"Waiting for a second person"`
	SentBack int `json:"sent_back" doc:"Returned to the author for more"`
	Approved int `json:"approved" doc:"Agreed to and in force"`
}

// EarlierBody is a decision once made here that no longer applies.
type EarlierBody struct {
	DecisionID    int64         `json:"decision_id"`
	ClaimID       int64         `json:"claim_id"`
	Outcome       Outcome       `json:"outcome"`
	Justification Justification `json:"justification,omitempty"`
	DeferredUntil string        `json:"deferred_until,omitempty"`
	// FixedVersion is the evidence an approver checks the already-fixed claim
	// against. Agreeing to a claim of fact without being shown the fact is
	// the failure this outcome is most exposed to.
	FixedVersion   string          `json:"fixed_version,omitempty" doc:"The package version the claim says the fix arrived in, where it claims one has"`
	ProposedBy     string          `json:"proposed_by" doc:"The person who proposed it, by sign-in identity"`
	ProposedByName string          `json:"proposed_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	ProposedAt     string          `json:"proposed_at"`
	Ended          ClaimStateEnded `json:"ended" doc:"The reason it stopped applying"`
	EndedAt        string          `json:"ended_at,omitempty"`
	About          string          `json:"about,omitempty" doc:"The component upstream version it was a claim about"`
	Reasoning      string          `json:"reasoning" doc:"The reasoning as it last stood, in markdown, offered back rather than thrown away"`
	ApprovedBy     string          `json:"approved_by,omitempty" doc:"The person who last agreed to it, where anybody did, by sign-in identity"`
	ApprovedByName string          `json:"approved_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
}

// SimilarBody is an approved claim at the same places about another issue,
// which may reach this one.
type SimilarBody struct {
	ClaimID        int64         `json:"claim_id" doc:"Pass as extends when deciding to carry it to this issue"`
	DecisionID     int64         `json:"decision_id"`
	Justification  Justification `json:"justification,omitempty"`
	Reasoning      string        `json:"reasoning"`
	ApprovedBy     string        `json:"approved_by,omitempty" doc:"The person who agreed, by sign-in identity"`
	ApprovedByName string        `json:"approved_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	ApprovedAt     string        `json:"approved_at,omitempty"`
	Issues         int           `json:"issues" doc:"The number of distinct issues the claim covers"`
}

// ElsewhereBody is an approved claim about this same issue at this same place,
// in another product.
//
// Evidence, never an outcome. Offered the way a supplier's VEX statement is:
// something to read and to quote, prefilling a reasoning where somebody asks
// for it and deciding nothing. Another team's judgment about their product is
// not a judgment about this one — the software shipped around the component
// differs, which is why a place is a component at a position rather than a
// component.
type ElsewhereBody struct {
	Product        string        `json:"product" doc:"The product it was decided in"`
	ClaimID        int64         `json:"claim_id"`
	DecisionID     int64         `json:"decision_id"`
	Outcome        Outcome       `json:"outcome"`
	Justification  Justification `json:"justification,omitempty"`
	Reasoning      string        `json:"reasoning"`
	ApprovedBy     string        `json:"approved_by,omitempty" doc:"The person who agreed, by sign-in identity"`
	ApprovedByName string        `json:"approved_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	ApprovedAt     string        `json:"approved_at,omitempty"`
}

// ProductsDecidedIn is the names of the products a set of judgments were made
// in, by identifier.
//
// Resolved here rather than carried on the judgment: a name is a fact about the
// catalog, and the read that found the judgments is narrowed by what the
// subject may see — so a name only ever reaches a reader who could already read
// the judgment it belongs to.
func ProductsDecidedIn(ctx context.Context, in Deps, rows []triage.Elsewhere) (map[int64]string, error) {
	ids := make([]int64, 0, len(rows))
	for _, one := range rows {
		ids = append(ids, one.ProductID)
	}
	return catalog.NewStore(in.DB.DB).ProductsCalled(ctx, ids)
}

func OrBlank(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
