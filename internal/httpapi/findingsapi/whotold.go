// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// ReportBody is what somebody told us, and what became of it.
type ReportBody struct {
	Reference  string `json:"reference" doc:"The name this report is reached by"`
	Product    string `json:"product" doc:"The product it was reported against, by name. The notes and correspondence of a report are read under it"`
	Title      string `json:"title,omitempty" doc:"A line naming the claim"`
	Summary    string `json:"summary,omitempty" doc:"What was claimed, as markdown, as it stands now"`
	ReportedBy string `json:"reported_by,omitempty"`
	Contact    string `json:"contact,omitempty"`
	Credit     string `json:"credit,omitempty" doc:"The credit they asked for in an advisory"`
	Received   string `json:"received,omitempty" doc:"The day it arrived, which the embargo is counted from"`
	FoundHere  bool   `json:"found_here" doc:"Whether somebody here found it rather than somebody outside sending it. A flaw found here carries no disclosure date, nobody is owed an answer, and it has no correspondence"`
	// Edits and Editable are how often what it says was changed, and whether
	// it may still be.
	Edits    int  `json:"edits,omitempty" doc:"How many times what it says was edited. The earlier versions, the original first, are read from its revisions"`
	Editable bool `json:"editable" doc:"Whether its title, claim and reporter may still be edited: nobody has judged it and no ruling holds it"`
	// Acknowledged is the day of the first message sent to the reporter,
	// which is the acknowledgement. Absent is a report nothing has been sent
	// on.
	Acknowledged       string `json:"acknowledged,omitempty" doc:"The day of the first message sent to the reporter, which is the acknowledgement"`
	AcknowledgedBy     string `json:"acknowledged_by,omitempty" doc:"The person who recorded that message, by sign-in identity"`
	AcknowledgedByName string `json:"acknowledged_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	core.HolderBody
	AssignedAt string `json:"assigned_at,omitempty" doc:"When it went to whoever holds it"`
	// Issue is what the claim turned out to be, where somebody has said, with
	// when they said it and who they were. Absent is a claim nobody has
	// judged, which is the state every report arrives in.
	Issue           string `json:"issue,omitempty" doc:"The issue the claim turned out to be"`
	Evaluated       string `json:"evaluated,omitempty" doc:"When somebody said what it turned out to be"`
	EvaluatedBy     string `json:"evaluated_by,omitempty" doc:"The person who said so, by sign-in identity"`
	EvaluatedByName string `json:"evaluated_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	// Disposition is what the claim was judged to be, where that has taken
	// effect. Absent is a claim nobody has answered, or one whose ruling is
	// waiting for a second person.
	Disposition    core.Disposition        `json:"disposition,omitempty" doc:"What the claim was judged to be, once that has taken effect"`
	DuplicateOf    string                  `json:"duplicate_of,omitempty" doc:"The issue a duplicate points at"`
	Ruling         int64                   `json:"ruling,omitempty" doc:"The ruling that answers it, waiting or in force"`
	Waiting        core.DispositionWaiting `json:"waiting,omitempty" doc:"A disposition proposed and waiting for a second person"`
	RecordedBy     string                  `json:"recorded_by" doc:"The person who wrote it down, by sign-in identity"`
	RecordedByName string                  `json:"recorded_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	RecordedAt     string                  `json:"recorded_at" doc:"When it was written down, which is not when it arrived"`
}

// registerWhoTold is the record of who told us, and the other names an issue
// goes by.
func registerWhoTold(api huma.API, in core.Deps) {
	const path = "/v1/products/{product}/issues/{vulnerability}/report"

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "get-report", Method: http.MethodGet, Path: path,
		Summary: "Show who reported a flaw",
		Description: "Who reported it, how to reach them, when it arrived, when somebody " +
			"answered them, and how they wish to be credited.\n\n" +
			"Its notes and correspondence are read from the report itself, under the product " +
			"`product` names, by whoever may read that product's reports.\n\n" +
			"The received date is what the embargo runs from: a report arriving " +
			"on 1 June and typed in on 15 June otherwise puts our clock two weeks behind the " +
			"one the reporter has a publication scheduled against, and they are the party who " +
			"will publish regardless.\n\n" +
			"Answers 404 where no report is the record of this issue — every issue a scan " +
			"reported that nobody wrote in about — and to somebody who may not read the " +
			"product's vulnerability reports.",
		Tags: []string{"Findings"},
	}, core.PerProduct, "", core.PrivateRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability"`
	}) (*struct{ Body ReportBody }, error) {
		// Read with the right every read of a report asks, which the store
		// checks against the product it was reported in.
		subject, _, issue, err := caseAt(ctx, in, input.Product, input.Vulnerability)
		if err != nil {
			return nil, err
		}
		told, err := finding.NewStore(in.DB.DB).ReportFor(ctx, subject, issue)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "who told us could not be read", err)
		}
		if told == nil {
			return nil, huma.Error404NotFound("nobody is recorded as having reported this")
		}
		body, err := reportBody(ctx, in, *told)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "who told us could not be read", err)
		}
		return &struct{ Body ReportBody }{Body: body}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "add-alias", Method: http.MethodPut,
		Path:    "/v1/products/{product}/issues/{vulnerability}/aliases/{alias}",
		Summary: "Record another name for an issue",
		Description: "Records that this issue is also known by another identifier — a CVE or " +
			"a GHSA assigned after we minted our own.\n\n" +
			"Nothing about the finding, the decisions or the approvals moves, because " +
			"they are keyed on the issue rather than on what it is called. What changes is " +
			"that the name travels with it: a report arriving under the new name resolves " +
			"here rather than opening a second issue, the finding shows it, and the advisory " +
			"carries it in the field a reader looks in — which is the one lookup a published " +
			"advisory exists to serve.\n\n" +
			"A name is identity, and identity is deployment-wide. From here on a scan of " +
			"any product reporting that name resolves to this issue and inherits its " +
			"decisions. So this asks for the right to triage the issue in every product it " +
			"is currently open in, at the visibility each one carries, and is refused rather " +
			"than partly done.\n\n" +
			"Only on a flaw recorded here: an issue a scan reported answers 422, because " +
			"its names are the ones the scans carry. The name is a CVE (CVE-2027-0001) or " +
			"a GitHub advisory (GHSA-2c4j-5f6m-7q8r); anything else answers 422.\n\n" +
			"Recording a name it already goes by succeeds and changes nothing.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, core.PerProduct, "Also asks for triage in every other product the issue is open in.",
		core.DisclosureTriageRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability"`
		Alias         string `path:"alias" maxLength:"191" doc:"The other identifier, as it is written"`
	}) (*struct{}, error) {
		subject, _, issue, err := caseAtTriaging(ctx, in, input.Product, input.Vulnerability)
		if err != nil {
			return nil, err
		}
		if err := core.Changing(ctx, in.DB, in.Log(), func(ctx context.Context, tx bun.Tx) error {
			// The name the issue is filed under, read before the new one is
			// added.
			//
			// By the stored name rather than the one typed: a path segment
			// carries no length, and the lookup keeps only the first NameWidth
			// runes of it, so what resolved and what was typed are not the
			// same string. Before, because recording an alias refiles the
			// issue under the more widely recognized of its names — read
			// afterwards, a row would say an issue gained the name it had
			// just been renamed to.
			named, err := finding.NewVulnerabilities(tx).NamesByID(ctx, []int64{issue})
			if err != nil {
				return core.WentWrong(in.Logger, "that issue could not be looked up", err)
			}
			switch err := finding.NewVulnerabilities(tx).
				AlsoKnownAs(ctx, subject, issue, input.Alias); {
			case errors.Is(err, finding.ErrNameTaken):
				return huma.Error409Conflict(
					"another issue already goes by that name, so this would merge two records")
			case err != nil:
				return core.Asked(in.Logger, err)
			}
			// Recorded deployment-wide, because that is what it is: from here
			// on a scan of any product reporting that name resolves to this
			// issue. The issue it was recorded against is named too, since
			// that is where the right to record it was held.
			if err := core.Noted(ctx, tx, trail.Alias, named[issue],
				nil, trail.Said(finding.Normalize(input.Alias), true)); err != nil {
				return core.NotRecorded(in.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "remove-alias", Method: http.MethodDelete,
		Path:    "/v1/products/{product}/issues/{vulnerability}/aliases/{alias}",
		Summary: "Remove another name for an issue",
		Description: "Removes a name somebody recorded by hand for this issue.\n\n" +
			"From here on a scan reporting that name no longer resolves here. Findings " +
			"that did resolve here through it split back out on the next scan that " +
			"reports it, under an issue of their own.\n\n" +
			"Where the issue is filed under the name removed, it is refiled under the " +
			"next best name it has: a CVE where one is left, and otherwise the reference " +
			"it was minted under. The answer says which, and the issue is read by that " +
			"name afterwards.\n\n" +
			"Asks for the same right recording it does: triage in every product the " +
			"issue is open in. A name a scan reported answers 422, including the name " +
			"the issue is filed under when a scan reported it. A name the issue does not " +
			"answer to answers 404.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusOK,
	}, core.PerProduct, "Also asks for triage in every other product the issue is open in.",
		core.DisclosureTriageRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability"`
		Alias         string `path:"alias" maxLength:"191" doc:"The name to remove, as it is written"`
	}) (*struct{ Body AliasRemovedBody }, error) {
		subject, _, issue, err := caseAtTriaging(ctx, in, input.Product, input.Vulnerability)
		if err != nil {
			return nil, err
		}
		out := &struct{ Body AliasRemovedBody }{}
		if err := core.Changing(ctx, in.DB, in.Log(), func(ctx context.Context, tx bun.Tx) error {
			named, err := finding.NewVulnerabilities(tx).NamesByID(ctx, []int64{issue})
			if err != nil {
				return core.WentWrong(in.Logger, "that issue could not be looked up", err)
			}
			filedUnder, err := finding.NewVulnerabilities(tx).
				NoLongerKnownAs(ctx, subject, issue, input.Alias)
			out.Body.FiledUnder = filedUnder
			switch {
			case errors.Is(err, finding.ErrNoSuchName):
				return huma.Error404NotFound(finding.ErrNoSuchName.Error())
			case err != nil:
				return core.Asked(in.Logger, err)
			}
			// Every removal is a row, for the reason recording one is: it
			// changes what a later scan of any product means.
			if err := core.Noted(ctx, tx, trail.Alias, named[issue],
				trail.Said(finding.Normalize(input.Alias), true), nil); err != nil {
				return core.NotRecorded(in.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return out, nil
	})
}

// AliasRemovedBody is an issue after one of its names was removed.
type AliasRemovedBody struct {
	FiledUnder string `json:"filed_under" doc:"The name the issue is filed under now, which is the name to read it by"`
}

// reportBody names the people and the issue one report refers to.
func reportBody(ctx context.Context, in core.Deps, told finding.FlawReport) (ReportBody, error) {
	bodies, err := reportBodies(ctx, in, []finding.FlawReport{told})
	if err != nil {
		return ReportBody{}, err
	}
	return bodies[0], nil
}

// reportBodies renders a page of reports, naming the people, the products and
// the issues they refer to in one read each.
//
// One read each for the page rather than per row: a page of fifty reports is
// a hundred round trips asked one at a time, and the names are the same
// handful of people over and over.
func reportBodies(ctx context.Context, in core.Deps, rows []finding.FlawReport) (
	[]ReportBody, error) {

	ids := make([]int64, 0, len(rows))
	people := make([]int64, 0, len(rows))
	issues := make([]int64, 0, len(rows))
	products := make([]int64, 0, len(rows))
	parties := make([]int64, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
		people = append(people, row.RecordedBy)
		products = append(products, row.ProductID)
		if row.EvaluatedBy != nil {
			people = append(people, *row.EvaluatedBy)
		}
		if row.VulnerabilityID != nil {
			issues = append(issues, *row.VulnerabilityID)
		}
		if row.AssignedTo != nil {
			parties = append(parties, *row.AssignedTo)
		}
	}
	acknowledged, err := finding.Acknowledgements(ctx, in.DB.DB, ids)
	if err != nil {
		return nil, err
	}
	for _, sent := range acknowledged {
		people = append(people, sent.LoggedBy)
	}
	edits, err := finding.RevisionCounts(ctx, in.DB.DB, ids)
	if err != nil {
		return nil, err
	}
	rulings, err := finding.NewStore(in.DB.DB).RulingsOf(ctx, rows)
	if err != nil {
		return nil, err
	}
	for _, ruling := range rulings {
		if ruling.DuplicateOf != nil {
			issues = append(issues, *ruling.DuplicateOf)
		}
	}
	who, err := core.WhoSigned(ctx, in.DB.DB, people)
	if err != nil {
		return nil, err
	}
	identifiers, err := finding.NewVulnerabilities(in.DB.DB).NamesByID(ctx, issues)
	if err != nil {
		return nil, err
	}
	called, err := in.Catalog(in.DB.DB).ProductsCalled(ctx, products)
	if err != nil {
		return nil, err
	}
	holders, err := access.NewStore(in.DB.DB).WhoHolds(ctx, parties)
	if err != nil {
		return nil, err
	}

	out := make([]ReportBody, 0, len(rows))
	for _, row := range rows {
		body := ReportBody{
			Reference: row.Reference, Product: called[row.ProductID],
			Title: row.Title, Summary: row.Summary,
			ReportedBy: row.ReportedBy, Contact: row.Contact, Credit: row.Credit,
			FoundHere: row.FoundHere, Edits: edits[row.ID], Editable: row.Editable(),
			RecordedBy: who.Identity(row.RecordedBy), RecordedByName: who.Label(row.RecordedBy),
			RecordedAt: core.Stamp(row.RecordedAt),
		}
		if row.ReceivedOn != nil {
			body.Received = row.ReceivedOn.UTC().Format(time.DateOnly)
		}
		if sent, ok := acknowledged[row.ID]; ok {
			body.Acknowledged = sent.Dated.UTC().Format(time.DateOnly)
			body.AcknowledgedBy = who.Identity(sent.LoggedBy)
			body.AcknowledgedByName = who.Label(sent.LoggedBy)
		}
		if row.AssignedTo != nil {
			if held, ok := holders[*row.AssignedTo]; ok {
				body.HolderBody = core.HolderOf(held)
				body.AssignedAt = core.StampAt(row.AssignedAt)
			}
		}
		if row.VulnerabilityID != nil {
			body.Issue = identifiers[*row.VulnerabilityID]
			body.Disposition = core.Disposition(finding.Accepted)
		}
		if row.RulingID != nil {
			ruling := rulings[*row.RulingID]
			body.Ruling = ruling.ID
			if ruling.InForce() {
				body.Disposition = core.Disposition(ruling.Disposition)
			} else {
				body.Waiting = core.DispositionWaiting(ruling.Disposition)
			}
			if ruling.DuplicateOf != nil {
				body.DuplicateOf = identifiers[*ruling.DuplicateOf]
			}
		}
		body.Evaluated = core.StampAt(row.EvaluatedAt)
		if row.EvaluatedBy != nil {
			body.EvaluatedBy = who.Identity(*row.EvaluatedBy)
			body.EvaluatedByName = who.Label(*row.EvaluatedBy)
		}
		out = append(out, body)
	}
	return out, nil
}
