// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// UnagreedBody is risk standing with nobody's agreement behind it.
type UnagreedBody struct {
	Outcome outcomeHidingRisk `json:"outcome"`
	Claims  int               `json:"claims" doc:"The number of acts"`
	Rows    int               `json:"rows" doc:"The number of decisions those acts wrote"`
}

// BulkApprovalBody is one act of agreement covering many claims.
type BulkApprovalBody struct {
	Batch      string `json:"batch"`
	ApprovedBy string `json:"approved_by"`
	ApprovedAt string `json:"approved_at"`
	Claims     int    `json:"claims"`
	Rows       int    `json:"rows"`
}

// PairingBody is one proposer and one approver.
type PairingBody struct {
	Proposer string `json:"proposer"`
	Approver string `json:"approver"`
	Claims   int    `json:"claims"`
	Rows     int    `json:"rows"`
	// Share is how much of everything agreed to in this period ran between
	// these two, as a percentage. Concentration is the signal, and a count
	// alone does not carry it: fifty out of fifty-two and fifty out of nine
	// hundred are the same number.
	Share int `json:"share" doc:"The share of everything agreed to here that ran between these two, as a percentage of rows"`
}

// LapsedApprovalBody is an agreement standing from somebody who has since lost
// the right to give one.
type LapsedApprovalBody struct {
	ClaimID    int64   `json:"claim_id"`
	ApprovedBy string  `json:"approved_by"`
	ApprovedAt string  `json:"approved_at"`
	Product    string  `json:"product"`
	Outcome    outcome `json:"outcome"`
	Rows       int     `json:"rows"`
}

// GrownBody is a claim covering more now than when it was agreed to.
type GrownBody struct {
	ClaimID    int64   `json:"claim_id"`
	ApprovedBy string  `json:"approved_by"`
	ApprovedAt string  `json:"approved_at"`
	Outcome    outcome `json:"outcome"`
	Covered    int     `json:"covered" doc:"The claim's reach when it was agreed to"`
	CoversNow  int     `json:"covers_now" doc:"Its reach now, arrived at by matching rather than by anybody acting"`
}

type scrutinyOutput struct {
	Body struct {
		Alone  []UnagreedBody       `json:"alone"`
		Bulk   []BulkApprovalBody   `json:"bulk"`
		Pairs  []PairingBody        `json:"pairs"`
		Lapsed []LapsedApprovalBody `json:"lapsed"`
		Grew   []GrownBody          `json:"grew"`
		// Agreed is every row a standing agreement covers in this period, so
		// each figure above can be read against the whole rather than on its
		// own.
		Agreed int `json:"agreed" doc:"Decisions a standing agreement covers in this period"`
		// The period these cover, said back, so a figure is never read apart
		// from the window it was worked out over.
		From string `json:"from,omitempty" doc:"The first day of the period, by when a claim was proposed. Absent where it runs from the beginning"`
		To   string `json:"to" doc:"The day it ends, which is not itself in it"`
		// Capped says a section reached the ceiling, so what is here is the
		// worst of it rather than all of it. Said rather than implied: a
		// report about a control that reads as complete while it is clipped
		// misleads exactly the reader it is for.
		Capped bool `json:"capped,omitempty" doc:"A section reached the limit, so this is the worst of it rather than all of it"`
	}
}

// registerScrutiny answers how much a second pair of eyes actually did.
//
// The control cannot be bypassed, so this is not a list of people who broke
// it. Approving refuses the proposer and refuses the author of the revision
// being agreed to, and the write is conditional on that revision still being
// current. What is worth reporting is where the rule did not apply, and where
// it applied in form only.
func registerScrutiny(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-approval-scrutiny", Method: http.MethodGet,
		Path:    "/v1/approvals/scrutiny",
		Summary: "Get approval coverage",
		Description: "Five answers about approvals over a period, for somebody auditing whether " +
			"they mean anything here.\n\n" +
			"`alone` is risk standing with nobody's agreement behind it, by outcome. That is " +
			"not a failure by itself: a short deferral and an upgrade promised inside the " +
			"deadline the work already had are both deliberately exempt. A dismissal in this " +
			"list is a different matter.\n\n" +
			"`bulk` is agreements given as one act over many claims, `pairs` is who agrees " +
			"with whom and what share of everything ran between them, `lapsed` is agreements " +
			"standing from somebody who no longer holds the right to give one, and `grew` is " +
			"what somebody agreed to against what the same claim reaches now — a claim reaches " +
			"by matching, so a build appearing afterwards is covered with nobody acting.\n\n" +
			"Everything is dated by when the claim was proposed, not by when it was agreed to, " +
			"and narrowed by what you may see.\n\n" +
			"Asked for neither a period nor a window, this is the last 90 days.",
		Tags: []string{"Reports"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `query:"product" doc:"Limit to one product, by name"`
		Period
		Limit int `query:"limit" default:"100" minimum:"1" maximum:"500" doc:"The number of rows each section carries at most. capped says a section reached it"`
	}) (*scrutinyOutput, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		var products []int64
		if input.Product != "" {
			// Resolved against what the caller may see, and a product they may
			// not read answers as one nobody declared. Anything else turns
			// this into a way to ask which products exist.
			named, err := productNamedVisibly(ctx, in, subject, input.Product)
			if err != nil {
				return nil, err
			}
			products = []int64{named.ID}
		}
		since, until, err := input.window(90, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		got, err := triage.NewStore(in.DB.DB).Scrutinize(ctx, subject, products,
			since, until, input.Limit)
		if err != nil {
			return nil, wentWrong(in.Logger, "how approvals are going could not be read", err)
		}

		out := &scrutinyOutput{}
		out.Body.From, out.Body.To = stating(since, until)
		out.Body.Capped = got.Capped
		out.Body.Alone = make([]UnagreedBody, 0, len(got.Alone))
		for _, row := range got.Alone {
			out.Body.Alone = append(out.Body.Alone, UnagreedBody{
				Outcome: outcomeHidingRisk(row.Outcome), Claims: row.Claims, Rows: row.Rows,
			})
		}
		out.Body.Bulk = make([]BulkApprovalBody, 0, len(got.Bulk))
		for _, row := range got.Bulk {
			out.Body.Bulk = append(out.Body.Bulk, BulkApprovalBody{
				Batch: row.Batch, ApprovedBy: row.ApprovedBy,
				ApprovedAt: stamp(row.ApprovedAt), Claims: row.Claims, Rows: row.Rows,
			})
		}
		// The whole a share is taken of. Every row a standing agreement covers,
		// which is exactly what the pairs add up to.
		for _, row := range got.Pairs {
			out.Body.Agreed += row.Rows
		}
		out.Body.Pairs = make([]PairingBody, 0, len(got.Pairs))
		for _, row := range got.Pairs {
			share := 0
			if out.Body.Agreed > 0 {
				share = row.Rows * 100 / out.Body.Agreed
			}
			out.Body.Pairs = append(out.Body.Pairs, PairingBody{
				Proposer: row.Proposer, Approver: row.Approver,
				Claims: row.Claims, Rows: row.Rows, Share: share,
			})
		}
		out.Body.Lapsed = make([]LapsedApprovalBody, 0, len(got.Lapsed))
		for _, row := range got.Lapsed {
			out.Body.Lapsed = append(out.Body.Lapsed, LapsedApprovalBody{
				ClaimID: row.ClaimID, ApprovedBy: row.ApprovedBy,
				ApprovedAt: stamp(row.ApprovedAt), Product: row.Product,
				Outcome: outcome(row.Outcome), Rows: row.Rows,
			})
		}
		out.Body.Grew = make([]GrownBody, 0, len(got.Grew))
		for _, row := range got.Grew {
			out.Body.Grew = append(out.Body.Grew, GrownBody{
				ClaimID: row.ClaimID, ApprovedBy: row.ApprovedBy,
				ApprovedAt: stamp(row.ApprovedAt), Outcome: outcome(row.Outcome),
				Covered: row.Covered, CoversNow: row.CoversNow,
			})
		}
		return out, nil
	})
}
