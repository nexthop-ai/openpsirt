// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// ReportBody is what somebody told us, and what became of it.
type ReportBody struct {
	Reference  string `json:"reference" doc:"The name this report is reached by"`
	Summary    string `json:"summary,omitempty" doc:"What was claimed, as markdown. Absent on a flaw recorded by hand, where the issue's own description carries it"`
	ReportedBy string `json:"reported_by,omitempty"`
	Contact    string `json:"contact,omitempty"`
	Credit     string `json:"credit,omitempty" doc:"The credit they asked for in an advisory"`
	Received   string `json:"received,omitempty" doc:"The day it arrived, which the embargo is counted from"`
	FoundHere  bool   `json:"found_here" doc:"Whether somebody here found it rather than somebody outside sending it. A flaw found here carries no disclosure date and nobody is owed an answer"`
	// Acknowledged is when somebody answered them, and by whom. Absent is the
	// state an unacknowledged report is in: prompt acknowledgment is the part
	// of coordinated disclosure a reporter actually judges.
	Acknowledged       string `json:"acknowledged,omitempty"`
	AcknowledgedBy     string `json:"acknowledged_by,omitempty" doc:"The person who answered them, by sign-in identity"`
	AcknowledgedByName string `json:"acknowledged_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
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
	Disposition    disposition        `json:"disposition,omitempty" doc:"What the claim was judged to be, once that has taken effect"`
	DuplicateOf    string             `json:"duplicate_of,omitempty" doc:"The issue a duplicate points at"`
	Ruling         int64              `json:"ruling,omitempty" doc:"The ruling that answers it, waiting or in force"`
	Waiting        dispositionWaiting `json:"waiting,omitempty" doc:"A disposition proposed and waiting for a second person"`
	RecordedBy     string             `json:"recorded_by" doc:"The person who wrote it down, by sign-in identity"`
	RecordedByName string             `json:"recorded_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	RecordedAt     string             `json:"recorded_at" doc:"When it was written down, which is not when it arrived"`
}

// registerWhoTold is the record of who told us, and the act of saying we
// answered them.
func registerWhoTold(api huma.API, in Deps) {
	const path = "/v1/products/{product}/issues/{vulnerability}/report"

	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-report", Method: http.MethodGet, Path: path,
		Summary: "Show who reported a flaw",
		Description: "Who reported it, how to reach them, when it arrived, when somebody " +
			"answered them, and how they wish to be credited.\n\n" +
			"The received date is what the embargo runs from: a report arriving " +
			"on 1 June and typed in on 15 June otherwise puts our clock two weeks behind the " +
			"one the reporter has a publication scheduled against, and they are the party who " +
			"will publish regardless.\n\n" +
			"Answers 404 where no report is the record of this issue — every issue a scan " +
			"reported that nobody wrote in about — and to somebody who may not read the " +
			"product's vulnerability reports.",
		Tags: []string{"Findings"},
	}, perProduct, "", privateRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability"`
	}) (*struct{ Body ReportBody }, error) {
		// Read with the right every read of a report asks, which the store
		// checks against the product it was reported in.
		subject, _, _, issue, err := caseAt(ctx, in, input.Product, input.Vulnerability)
		if err != nil {
			return nil, err
		}
		told, err := finding.NewStore(in.DB.DB).ReportFor(ctx, subject, issue)
		if err != nil {
			return nil, wentWrong(in.Logger, "who told us could not be read", err)
		}
		if told == nil {
			return nil, huma.Error404NotFound("nobody is recorded as having reported this")
		}
		body, err := reportBody(ctx, in, *told)
		if err != nil {
			return nil, wentWrong(in.Logger, "who told us could not be read", err)
		}
		return &struct{ Body ReportBody }{Body: body}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "acknowledge-report", Method: http.MethodPost,
		Path:    path + "/acknowledgement",
		Summary: "Record that the reporter was answered",
		Description: "Records that somebody replied to whoever reported this, and when.\n\n" +
			"It records that it happened rather than doing it. What reaches a researcher " +
			"is a mail somebody sends from an address they already have; recording it is what " +
			"turns \"somebody probably replied\" into a date the timeline can be evidenced " +
			"from, and what clears the condition an unanswered report opens.\n\n" +
			"Acknowledging twice keeps the first date: when somebody was answered is a fact " +
			"about the past, and the second person to press it did not change it.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability"`
	}) (*struct{}, error) {
		subject, _, _, issue, err := caseAtTriaging(ctx, in, input.Product, input.Vulnerability)
		if err != nil {
			return nil, err
		}
		store := finding.NewStore(in.DB.DB)
		told, err := store.ReportFor(ctx, subject, issue)
		if err != nil {
			return nil, wentWrong(in.Logger, "who told us could not be read", err)
		}
		if told == nil {
			return nil, huma.Error404NotFound("nobody is recorded as having reported this")
		}
		if err := store.Acknowledge(ctx, subject, issue); err != nil {
			return nil, refused(in.Logger, err, "that could not be recorded")
		}
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
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
	}, perProduct, "Also asks for triage in every other product the issue is open in.",
		triageRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability"`
		Alias         string `path:"alias" maxLength:"191" doc:"The other identifier, as it is written"`
	}) (*struct{}, error) {
		subject, _, _, issue, err := caseAtTriaging(ctx, in, input.Product, input.Vulnerability)
		if err != nil {
			return nil, err
		}
		if err := changing(ctx, in.DB, in.logger(), func(ctx context.Context, tx bun.Tx) error {
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
				return wentWrong(in.Logger, "that issue could not be looked up", err)
			}
			switch err := finding.NewVulnerabilities(tx).
				AlsoKnownAs(ctx, subject, issue, input.Alias); {
			case errors.Is(err, finding.ErrNameTaken):
				return huma.Error409Conflict(
					"another issue already goes by that name, so this would merge two records")
			case err != nil:
				return asked(in.Logger, err)
			}
			// Recorded deployment-wide, because that is what it is: from here
			// on a scan of any product reporting that name resolves to this
			// issue. The issue it was recorded against is named too, since
			// that is where the right to record it was held.
			if err := noted(ctx, tx, trail.Alias, named[issue],
				nil, trail.Said(input.Alias, true)); err != nil {
				return notRecorded(in.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
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
	}, perProduct, "Also asks for triage in every other product the issue is open in.",
		triageRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability"`
		Alias         string `path:"alias" maxLength:"191" doc:"The name to remove, as it is written"`
	}) (*struct{ Body AliasRemovedBody }, error) {
		subject, _, _, issue, err := caseAtTriaging(ctx, in, input.Product, input.Vulnerability)
		if err != nil {
			return nil, err
		}
		out := &struct{ Body AliasRemovedBody }{}
		if err := changing(ctx, in.DB, in.logger(), func(ctx context.Context, tx bun.Tx) error {
			named, err := finding.NewVulnerabilities(tx).NamesByID(ctx, []int64{issue})
			if err != nil {
				return wentWrong(in.Logger, "that issue could not be looked up", err)
			}
			filedUnder, err := finding.NewVulnerabilities(tx).
				NoLongerKnownAs(ctx, subject, issue, input.Alias)
			out.Body.FiledUnder = filedUnder
			switch {
			case errors.Is(err, finding.ErrNoSuchName):
				return huma.Error404NotFound(finding.ErrNoSuchName.Error())
			case err != nil:
				return asked(in.Logger, err)
			}
			// Every removal is a row, for the reason recording one is: it
			// changes what a later scan of any product means.
			if err := noted(ctx, tx, trail.Alias, named[issue],
				trail.Said(strings.ToUpper(strings.TrimSpace(input.Alias)), true), nil); err != nil {
				return notRecorded(in.Logger, err)
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
func reportBody(ctx context.Context, in Deps, told finding.FlawReport) (ReportBody, error) {
	bodies, err := reportBodies(ctx, in, []finding.FlawReport{told})
	if err != nil {
		return ReportBody{}, err
	}
	return bodies[0], nil
}

// reportBodies renders a page of reports, naming the people and the issues
// they refer to in one read each.
//
// Two reads for the page rather than two per row: a page of fifty reports is
// a hundred round trips asked one at a time, and the names are the same
// handful of people over and over.
func reportBodies(ctx context.Context, in Deps, rows []finding.FlawReport) (
	[]ReportBody, error) {

	people := make([]int64, 0, len(rows))
	issues := make([]int64, 0, len(rows))
	for _, row := range rows {
		people = append(people, row.RecordedBy)
		if row.AcknowledgedBy != nil {
			people = append(people, *row.AcknowledgedBy)
		}
		if row.EvaluatedBy != nil {
			people = append(people, *row.EvaluatedBy)
		}
		if row.VulnerabilityID != nil {
			issues = append(issues, *row.VulnerabilityID)
		}
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
	who, err := whoSigned(ctx, in.DB.DB, people)
	if err != nil {
		return nil, err
	}
	identifiers, err := finding.NewVulnerabilities(in.DB.DB).NamesByID(ctx, issues)
	if err != nil {
		return nil, err
	}

	out := make([]ReportBody, 0, len(rows))
	for _, row := range rows {
		body := ReportBody{
			Reference: row.Reference, Summary: row.Summary,
			ReportedBy: row.ReportedBy, Contact: row.Contact, Credit: row.Credit,
			FoundHere:  row.FoundHere,
			RecordedBy: who.identity(row.RecordedBy), RecordedByName: who.label(row.RecordedBy),
			RecordedAt: row.RecordedAt.UTC().Format(time.RFC3339),
		}
		if row.ReceivedOn != nil {
			body.Received = row.ReceivedOn.Format(time.DateOnly)
		}
		if row.AcknowledgedAt != nil {
			body.Acknowledged = row.AcknowledgedAt.UTC().Format(time.RFC3339)
		}
		if row.AcknowledgedBy != nil {
			body.AcknowledgedBy = who.identity(*row.AcknowledgedBy)
			body.AcknowledgedByName = who.label(*row.AcknowledgedBy)
		}
		if row.VulnerabilityID != nil {
			body.Issue = identifiers[*row.VulnerabilityID]
			body.Disposition = disposition(finding.Accepted)
		}
		if row.RulingID != nil {
			ruling := rulings[*row.RulingID]
			body.Ruling = ruling.ID
			if ruling.InForce() {
				body.Disposition = disposition(ruling.Disposition)
			} else {
				body.Waiting = dispositionWaiting(ruling.Disposition)
			}
			if ruling.DuplicateOf != nil {
				body.DuplicateOf = identifiers[*ruling.DuplicateOf]
			}
		}
		if row.EvaluatedAt != nil {
			body.Evaluated = row.EvaluatedAt.UTC().Format(time.RFC3339)
		}
		if row.EvaluatedBy != nil {
			body.EvaluatedBy = who.identity(*row.EvaluatedBy)
			body.EvaluatedByName = who.label(*row.EvaluatedBy)
		}
		out = append(out, body)
	}
	return out, nil
}
