// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// LeadPlace is one place an analyzer named for a lead.
type LeadPlace struct {
	Path        string `json:"path,omitempty" doc:"The file, from the top of the checkout. Absent for a step outside it"`
	StartLine   int    `json:"start_line,omitempty"`
	StartColumn int    `json:"start_column,omitempty"`
	EndLine     int    `json:"end_line,omitempty"`
	EndColumn   int    `json:"end_column,omitempty"`
	Function    string `json:"function,omitempty" doc:"The function the place is in, where the analyzer names one"`
	Message     string `json:"message,omitempty" doc:"What the analyzer says at the place"`
	Depth       *int   `json:"depth,omitempty" doc:"How deep in calls a step is, where the analyzer says"`
	Snippet     string `json:"snippet,omitempty" doc:"The source at the place, where the product keeps source under its path. Uploaded text, to be shown as text"`
	SnippetLine int    `json:"snippet_line,omitempty" doc:"The line the snippet starts at"`
	Link        string `json:"link,omitempty" doc:"The address of the place in the repository's web view. Absent where unlinked says why"`
	Repository  string `json:"repository,omitempty" doc:"The repository the place is in: its web address on a host the product names, or the remote as the upload stated it"`
	Within      string `json:"within,omitempty" doc:"The place's path inside that repository"`
	Revision    string `json:"revision,omitempty" doc:"The commit the link opens at, or the branch of an approximate link"`
	Approximate bool   `json:"approximate,omitempty" doc:"Whether the link opens on a branch the product names rather than on the analyzed commit"`
	Patched     bool   `json:"patched,omitempty" doc:"Whether the repository differed from its commit when it was analyzed, so the link shows the source before the patch"`
	Unlinked    string `json:"unlinked,omitempty" doc:"Why the place has no link"`
}

// LeadEvidenceBody is what the newest run that saw a lead said about it.
type LeadEvidenceBody struct {
	Rule          string             `json:"rule" doc:"The analyzer's rule, as <tool>/<rule>"`
	At            LeadPlace          `json:"at" doc:"Where the lead is"`
	Steps         []LeadPlace        `json:"steps" doc:"The path the analyzer took to it, in order"`
	Related       []LeadPlace        `json:"related" doc:"The other places the analyzer names"`
	Open          bool               `json:"open" doc:"Whether the lead is open on the build"`
	LastSeen      string             `json:"last_seen" format:"date-time" doc:"When the build of the newest run that saw the lead was made"`
	NotSeen       string             `json:"not_seen,omitempty" format:"date-time" doc:"When the build of the first run after it that did not see the lead was made. Absent while every run since has seen it"`
	LastCommit    string             `json:"last_commit,omitempty" doc:"The commit the lead's own repository was at in the build of the newest run that saw the lead. Absent where the run named none"`
	NotSeenCommit string             `json:"not_seen_commit,omitempty" doc:"The commit the lead's own repository was at in the build of the first run that did not see the lead. Absent where that run named none, or while every run since has seen it"`
	NotSeenRun    int64              `json:"not_seen_run,omitempty" doc:"The run that did not see the lead, which a statement that it was fixed may name"`
	FixedIn       *LeadRunBody       `json:"fixed_in,omitempty" doc:"The build a person stated fixed the lead, once they closed it as fixed"`
	Compare       string             `json:"compare,omitempty" doc:"The address comparing the lead's repository between those two builds"`
	Unchanged     bool               `json:"unchanged,omitempty" doc:"Whether those two builds name the same commit for the lead's repository and neither patched it at build time, so its disappearance is not a change to that code"`
	State         LeadState          `json:"state" doc:"Where the lead stands: open, not reproduced, fixed, answered by a claim somebody agreed to, or handed off as a flaw"`
	Kin           []LeadKin          `json:"kin" doc:"Other analyzers' leads on the build that are the same flaw, and those that possibly are"`
	Decision      *core.DecisionBody `json:"decision,omitempty" doc:"The live claim at the lead, agreed to or waiting for a second person. Absent where there is none"`
	Withheld      bool               `json:"withheld,omitempty" doc:"Whether the lead is part of a case you are not on, so only its state, rule, location and sightings are answered"`
	ThirdParty    bool               `json:"third_party,omitempty" doc:"Whether the lead is in code the newest run that saw it declared third-party"`
	Ended         bool               `json:"past_end_of_life,omitempty" doc:"Whether every release the lead was seen in is past its end of life, so it is kept as it stands and takes no decision, fixed closure, assignment or hand-off"`
	Handoff       *LeadHandoffBody   `json:"handoff,omitempty" doc:"The flaw the lead was handed off as. Answered where you read the product's undisclosed work, are on the flaw's case, or were granted the lead"`
	// Who is dealing with the lead on this build, while it is open there.
	core.HolderBody
}

// LeadRunBody is one run of a lead's series, by the build it analyzed.
type LeadRunBody struct {
	Run    int64  `json:"run" doc:"The run"`
	Built  string `json:"built" format:"date-time" doc:"When the build it analyzed was made"`
	Commit string `json:"commit,omitempty" doc:"The commit at the top of the checkout it analyzed, where the run stated one"`
}

// leadRunBody is a run as an answer states it, nil for none.
func leadRunBody(run *analysis.RunAt) *LeadRunBody {
	if run == nil {
		return nil
	}
	return &LeadRunBody{Run: run.ID, Built: core.Stamp(run.BuiltAt), Commit: run.Commit}
}

// LeadHandoffBody is the flaw a lead was handed off as.
type LeadHandoffBody struct {
	Flaw         string `json:"flaw" doc:"The identifier the flaw was filed under"`
	Moved        bool   `json:"moved" doc:"Whether the lead is part of the flaw's case. Otherwise it is kept internal and linked"`
	Disclosed    bool   `json:"disclosed" doc:"Whether the flaw is disclosed, which ends moving the lead in or out"`
	HandedBy     string `json:"handed_by" doc:"The person who handed it off, by sign-in identity"`
	HandedByName string `json:"handed_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	HandedAt     string `json:"handed_at" format:"date-time"`
}

// LeadKin is another lead on a build that is the same flaw as a lead, or
// possibly is.
type LeadKin struct {
	Place string `json:"place" doc:"The other lead's place identity"`
	Rule  string `json:"rule" doc:"Its analyzer's rule, as <tool>/<rule>"`
	Path  string `json:"path" doc:"The file of the last place it names"`
	Line  int    `json:"line,omitempty" doc:"The line of the last place it names"`
	Same  bool   `json:"same" doc:"Whether it is the same flaw: a weakness of the same family, its last place within two lines. Otherwise within ten, and offered as possibly the same"`
}

// LeadState is where a lead stands.
type LeadState string

// Schema answers with the states a lead is in.
func (LeadState) Schema(huma.Registry) *huma.Schema {
	offered := make([]any, 0, len(analysis.States()))
	for _, each := range analysis.States() {
		offered = append(offered, string(each))
	}
	return &huma.Schema{Type: huma.TypeString, Enum: offered}
}

// LeadAssignee is who the lead queue is narrowed to as holding a lead.
type LeadAssignee string

// Schema offers every word the lead queue asks who holds a lead in.
func (LeadAssignee) Schema(huma.Registry) *huma.Schema {
	offered := make([]any, 0, len(analysis.LeadAssignees()))
	for _, each := range analysis.LeadAssignees() {
		offered = append(offered, each)
	}
	return &huma.Schema{Type: huma.TypeString, Enum: offered}
}

func registerLeads(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "get-lead-evidence", Method: http.MethodGet,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/leads/{place}",
		Summary: "Get a lead's evidence",
		Description: "Returns what the newest run that saw a lead on a build said about it: where it " +
			"is, the path the analyzer took to it, and the other places it names. Each place links " +
			"into the repository's web view at the analyzed commit, where the product names the " +
			"repository's host, and carries the source kept beside it, where the product keeps " +
			"source under its path.\n\n" +
			"A lead the build no longer holds open answers the newest it held, with when it was " +
			"last seen, when it was first not seen, and whether its repository changed between " +
			"the two.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
		Place   string `path:"place" doc:"The lead's place identity"`
	}) (*struct{ Body LeadEvidenceBody }, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		// Resolved for somebody granted the lead alone as well: the names
		// it sits at, and nothing past them.
		named, err := core.LocatedForLead(ctx, in, subject, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		target, err := core.TargetRow(ctx, in, named.StreamID, named.VariantID)
		if err != nil {
			return nil, err
		}
		lead, _, err := finding.NewStore(in.DB.DB).LeadOrStubAt(ctx, subject, target.ID, input.Place)
		if err != nil {
			return nil, core.Absent(in.Logger, err, "that lead could not be looked up", core.NoSuchFinding)
		}
		evidence, err := analysis.EvidenceOf(ctx, in.DB.DB, subject, lead, named.ProductID)
		if err != nil {
			return nil, core.Absent(in.Logger, err, "that lead's evidence could not be read", core.NoSuchFinding)
		}
		body := LeadEvidenceBody{
			Rule: evidence.Rule,
			At:   leadPlace(evidence.At), Steps: []LeadPlace{}, Related: []LeadPlace{},
			Open: lead.ClosedAt == nil, LastSeen: core.Stamp(evidence.LastSeen), NotSeen: core.StampAt(evidence.NotSeen),
			NotSeenRun: evidence.NotSeenRun, FixedIn: leadRunBody(evidence.FixedIn),
			LastCommit: evidence.LastCommit, NotSeenCommit: evidence.NotSeenCommit,
			Compare: evidence.Compare, Unchanged: evidence.Unchanged, State: LeadState(evidence.State),
			Kin: make([]LeadKin, 0, len(evidence.Kin)), Withheld: evidence.Stub, ThirdParty: evidence.ThirdParty,
		}
		switch err := finding.LeadEnded(ctx, in.DB.DB, named.ProductID, lead.PlaceIdentity, time.Now().UTC()); {
		case errors.Is(err, finding.ErrLeadPastEndOfLife):
			body.Ended = true
		case err != nil:
			return nil, core.WentWrong(in.Logger, "whether that lead's releases are in support could not be read", err)
		}
		if !evidence.Stub {
			if body.Handoff, err = leadHandoff(ctx, in, subject, named.ProductID, lead.PlaceIdentity); err != nil {
				return nil, core.WentWrong(in.Logger, "the flaw that lead was handed off as could not be read", err)
			}
		}
		for _, k := range evidence.Kin {
			one := LeadKin{Place: k.Place, Rule: k.Rule, Path: k.Path, Same: k.Same}
			if k.Line != nil {
				one.Line = *k.Line
			}
			body.Kin = append(body.Kin, one)
		}
		if evidence.Stub {
			// The claims about a moved lead, and who works it, are private
			// with it.
			return &struct{ Body LeadEvidenceBody }{Body: body}, nil
		}
		if lead.ClosedAt == nil && lead.AssignedTo != nil {
			who, err := access.NewStore(in.DB.DB).WhoHolds(ctx, []int64{*lead.AssignedTo})
			if err != nil {
				return nil, core.WentWrong(in.Logger, "who is dealing with that lead could not be read", err)
			}
			body.HolderBody = core.HolderOf(who[*lead.AssignedTo])
		}
		held, err := triage.NewStore(in.DB.DB).PreviouslyAt(ctx, subject, triage.Place{
			ProductID: named.ProductID, VulnerabilityID: lead.VulnerabilityID, PlaceIdentity: lead.PlaceIdentity,
		})
		if err != nil {
			return nil, core.Absent(in.Logger, err, "the claim at that lead could not be read", core.NoSuchFinding)
		}
		for _, d := range held {
			if d.LiveKey != nil {
				decided := core.DecisionBodyOf(d)
				body.Decision = &decided
				break
			}
		}
		for _, p := range evidence.Steps {
			body.Steps = append(body.Steps, leadPlace(p))
		}
		for _, p := range evidence.Related {
			body.Related = append(body.Related, leadPlace(p))
		}
		return &struct{ Body LeadEvidenceBody }{Body: body}, nil
	})
}

// leadPlace is one place as an answer states it.
func leadPlace(p analysis.Located) LeadPlace {
	return LeadPlace{
		Path: p.Path, StartLine: p.StartLine, StartColumn: p.StartColumn,
		EndLine: p.EndLine, EndColumn: p.EndColumn, Function: p.Function, Message: p.Message,
		Depth: p.Depth, Snippet: p.Snippet, SnippetLine: p.SnippetLine,
		Link: p.Link.URL, Repository: p.Link.Repository, Within: p.Link.Within, Revision: p.Link.Revision,
		Approximate: p.Link.Approximate, Patched: p.Link.Patched, Unlinked: p.Link.Unlinked,
	}
}

// leadHandoff is the flaw a lead was handed off as, where the reader is on the
// case: they read the product's undisclosed work, are on the flaw's case, or
// were granted the lead. Nil for anybody else, and for a lead not handed off.
func leadHandoff(ctx context.Context, in core.Deps, subject access.Subject, productID int64,
	place string) (*LeadHandoffBody, error) {

	h, err := finding.HandoffAt(ctx, in.DB.DB, productID, place)
	if err != nil || h == nil {
		return nil, err
	}
	if !subject.Reads(access.Private, productID) && !subject.OnCase(productID, h.VulnerabilityID) &&
		!subject.OnLead(productID, place) {
		return nil, nil
	}
	names, err := finding.NewVulnerabilities(in.DB.DB).NamesByID(ctx, []int64{h.VulnerabilityID})
	if err != nil {
		return nil, err
	}
	who, err := core.WhoSigned(ctx, in.DB.DB, []int64{h.HandedBy})
	if err != nil {
		return nil, err
	}
	return &LeadHandoffBody{
		Flaw: names[h.VulnerabilityID], Moved: h.Moved(), Disclosed: h.Disclosed(),
		HandedBy: who.Identity(h.HandedBy), HandedByName: who.Label(h.HandedBy),
		HandedAt: core.Stamp(h.HandedAt),
	}, nil
}
