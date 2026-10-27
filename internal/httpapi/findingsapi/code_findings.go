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

// CodeFindingOccurrence is one place an analyzer named for a code finding.
type CodeFindingOccurrence struct {
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

// CodeFindingEvidenceBody is what the newest run that saw a code finding said about it.
type CodeFindingEvidenceBody struct {
	Rule               string                       `json:"rule" doc:"The analyzer's rule, as <tool>/<rule>"`
	At                 CodeFindingOccurrence        `json:"at" doc:"Where the code finding is"`
	Steps              []CodeFindingOccurrence      `json:"steps" doc:"The path the analyzer took to it, in order"`
	Related            []CodeFindingOccurrence      `json:"related" doc:"The other places the analyzer names"`
	Open               bool                         `json:"open" doc:"Whether the code finding is open on the build"`
	LastSeen           string                       `json:"last_seen" format:"date-time" doc:"When the build of the newest run that saw the code finding was made"`
	NotSeen            string                       `json:"not_seen,omitempty" format:"date-time" doc:"When the build of the first run after it that did not see the code finding was made. Absent while every run since has seen it"`
	LastCommit         string                       `json:"last_commit,omitempty" doc:"The commit the code finding's own repository was at in the build of the newest run that saw the code finding. Absent where the run named none"`
	NotSeenCommit      string                       `json:"not_seen_commit,omitempty" doc:"The commit the code finding's own repository was at in the build of the first run that did not see the code finding. Absent where that run named none, or while every run since has seen it"`
	NotSeenRun         int64                        `json:"not_seen_run,omitempty" doc:"The run that did not see the code finding, which a statement that it was fixed may name"`
	FixedIn            *CodeFindingRunBody          `json:"fixed_in,omitempty" doc:"The build a person stated fixed the code finding, once they closed it as fixed"`
	Compare            string                       `json:"compare,omitempty" doc:"The address comparing the code finding's repository between those two builds"`
	Unchanged          bool                         `json:"unchanged,omitempty" doc:"Whether those two builds name the same commit for the code finding's repository and neither patched it at build time, so its disappearance is not a change to that code"`
	State              CodeFindingState             `json:"state" doc:"Where the code finding stands: open, no longer detected, fixed, answered by a decision somebody agreed to, or recorded as a flaw"`
	Kin                []CodeFindingKin             `json:"kin" doc:"Other analyzers' code findings on the build that are the same flaw, and those that possibly are"`
	DecisionOccurrence *core.DecisionOccurrenceBody `json:"decision_occurrence,omitempty" doc:"The live decision at the code finding, agreed to or waiting for a second person. Absent where there is none"`
	ThirdParty         bool                         `json:"third_party,omitempty" doc:"Whether the code finding is in code the newest run that saw it declared third-party"`
	Ended              bool                         `json:"past_end_of_life,omitempty" doc:"Whether every release the code finding was seen in is past its end of life, so it is kept as it stands and takes no decision, fixed closure, assignment or flaw record"`
	RecordedAsFlaw     *CodeFindingFlawBody         `json:"recorded_as_flaw,omitempty" doc:"The flaw the code finding was recorded as. Answered where you read the product's undisclosed work, are on the flaw's case, or were granted the code finding"`
	// Who is dealing with the code finding on this build, while it is open there.
	core.HolderBody
}

// CodeFindingRunBody is one run of a code finding's series, by the build it analyzed.
type CodeFindingRunBody struct {
	Run    int64  `json:"run" doc:"The run"`
	Built  string `json:"built" format:"date-time" doc:"When the build it analyzed was made"`
	Commit string `json:"commit,omitempty" doc:"The commit at the top of the checkout it analyzed, where the run stated one"`
}

// codeFindingRunBody is a run as an answer states it, nil for none.
func codeFindingRunBody(run *analysis.RunAt) *CodeFindingRunBody {
	if run == nil {
		return nil
	}
	return &CodeFindingRunBody{Run: run.ID, Built: core.Stamp(run.BuiltAt), Commit: run.Commit}
}

// CodeFindingFlawBody is the flaw a code finding was recorded as.
type CodeFindingFlawBody struct {
	Flaw                 string `json:"flaw" doc:"The identifier the flaw was filed under"`
	IncludedInDisclosure bool   `json:"included_in_disclosure" doc:"Whether the code finding is included in its flaw's disclosure. Otherwise it is internal only, and linked"`
	Disclosed            bool   `json:"disclosed" doc:"Whether the flaw is disclosed, which ends moving the code finding in or out"`
	RecordedBy           string `json:"recorded_by" doc:"The person who recorded it as a flaw, by sign-in identity"`
	RecordedByName       string `json:"recorded_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	RecordedAt           string `json:"recorded_at" format:"date-time"`
}

// CodeFindingKin is another code finding on a build that is the same flaw as a code finding, or
// possibly is.
type CodeFindingKin struct {
	Occurrence string `json:"occurrence" doc:"The other code finding's occurrence identity"`
	Rule       string `json:"rule" doc:"Its analyzer's rule, as <tool>/<rule>"`
	Path       string `json:"path" doc:"The file of the last place it names"`
	Line       int    `json:"line,omitempty" doc:"The line of the last place it names"`
	Same       bool   `json:"same" doc:"Whether it is the same flaw: a weakness of the same family, its last place within two lines. Otherwise within ten, and offered as possibly the same"`
}

// CodeFindingState is where a code finding stands.
type CodeFindingState string

// Schema answers with the states a code finding is in.
func (CodeFindingState) Schema(huma.Registry) *huma.Schema {
	offered := make([]any, 0, len(analysis.States()))
	for _, each := range analysis.States() {
		offered = append(offered, string(each))
	}
	return &huma.Schema{Type: huma.TypeString, Enum: offered}
}

// CodeFindingAssignee is who the code finding queue is narrowed to as holding a code finding.
type CodeFindingAssignee string

// Schema offers every word the code finding queue asks who holds a code finding in.
func (CodeFindingAssignee) Schema(huma.Registry) *huma.Schema {
	offered := make([]any, 0, len(analysis.CodeFindingAssignees()))
	for _, each := range analysis.CodeFindingAssignees() {
		offered = append(offered, each)
	}
	return &huma.Schema{Type: huma.TypeString, Enum: offered}
}

// CodeFindingMethod is a testing method the code finding queue narrows by.
type CodeFindingMethod string

// Schema offers every method the code finding queue narrows by.
func (CodeFindingMethod) Schema(huma.Registry) *huma.Schema {
	offered := make([]any, 0, len(analysis.Methods()))
	for _, each := range analysis.Methods() {
		offered = append(offered, each)
	}
	return &huma.Schema{Type: huma.TypeString, Enum: offered}
}

func registerCodeFindings(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "get-code-finding-evidence", Method: http.MethodGet,
		Path:    "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}",
		Summary: "Get a code finding's evidence",
		Description: "Returns what the newest run that saw a code finding on a build said about it: where it " +
			"is, the path the analyzer took to it, and the other places it names. Each place links " +
			"into the repository's web view at the analyzed commit, where the product names the " +
			"repository's host, and carries the source kept beside it, where the product keeps " +
			"source under its path.\n\n" +
			"A code finding the build no longer holds open answers the newest it held, with when it was " +
			"last seen, when it was first not seen, and whether its repository changed between " +
			"the two.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product     string `path:"product"`
		BranchOrTag string `path:"branch_or_tag"`
		Variant     string `path:"variant"`
		Occurrence  string `path:"occurrence" doc:"The code finding's occurrence identity"`
	}) (*struct{ Body CodeFindingEvidenceBody }, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		// Resolved for somebody granted the code finding alone as well: the names
		// it sits at, and nothing past them.
		named, err := core.LocatedForCodeFinding(ctx, in, subject, input.Product, input.BranchOrTag, input.Variant)
		if err != nil {
			return nil, err
		}
		build, err := core.BuildRow(ctx, in, named.BranchOrTagID, named.VariantID)
		if err != nil {
			return nil, err
		}
		codeFinding, err := finding.NewStore(in.DB.DB).CodeFindingAt(ctx, subject, build.ID, input.Occurrence)
		if err != nil {
			return nil, core.Absent(in.Logger, err, "that code finding could not be looked up", core.NoSuchFinding)
		}
		evidence, err := analysis.EvidenceOf(ctx, in.DB.DB, subject, codeFinding, named.ProductID)
		if err != nil {
			return nil, core.Absent(in.Logger, err, "that code finding's evidence could not be read", core.NoSuchFinding)
		}
		body := CodeFindingEvidenceBody{
			Rule: evidence.Rule,
			At:   codeFindingOccurrence(evidence.At), Steps: []CodeFindingOccurrence{}, Related: []CodeFindingOccurrence{},
			Open: codeFinding.ClosedAt == nil, LastSeen: core.Stamp(evidence.LastSeen), NotSeen: core.StampAt(evidence.NotSeen),
			NotSeenRun: evidence.NotSeenRun, FixedIn: codeFindingRunBody(evidence.FixedIn),
			LastCommit: evidence.LastCommit, NotSeenCommit: evidence.NotSeenCommit,
			Compare: evidence.Compare, Unchanged: evidence.Unchanged, State: CodeFindingState(evidence.State),
			Kin: make([]CodeFindingKin, 0, len(evidence.Kin)), ThirdParty: evidence.ThirdParty,
		}
		switch err := finding.CodeFindingEnded(ctx, in.DB.DB, named.ProductID, codeFinding.OccurrenceIdentity, time.Now().UTC()); {
		case errors.Is(err, finding.ErrCodeFindingPastEndOfLife):
			body.Ended = true
		case err != nil:
			return nil, core.WentWrong(in.Logger, "whether that code finding's releases are in support could not be read", err)
		}
		if body.RecordedAsFlaw, err = codeFindingFlaw(ctx, in, subject, named.ProductID, codeFinding.OccurrenceIdentity); err != nil {
			return nil, core.WentWrong(in.Logger, "the flaw that code finding was recorded as could not be read", err)
		}
		for _, k := range evidence.Kin {
			one := CodeFindingKin{Occurrence: k.Occurrence, Rule: k.Rule, Path: k.Path, Same: k.Same}
			if k.Line != nil {
				one.Line = *k.Line
			}
			body.Kin = append(body.Kin, one)
		}
		if codeFinding.ClosedAt == nil && codeFinding.AssignedTo != nil {
			who, err := access.NewStore(in.DB.DB).WhoHolds(ctx, []int64{*codeFinding.AssignedTo})
			if err != nil {
				return nil, core.WentWrong(in.Logger, "who is dealing with that code finding could not be read", err)
			}
			body.HolderBody = core.HolderOf(who[*codeFinding.AssignedTo])
		}
		held, err := triage.NewStore(in.DB.DB).PreviouslyAt(ctx, subject, triage.Occurrence{
			ProductID: named.ProductID, VulnerabilityID: codeFinding.VulnerabilityID, OccurrenceIdentity: codeFinding.OccurrenceIdentity,
		})
		if err != nil {
			return nil, core.Absent(in.Logger, err, "the decision at that code finding could not be read", core.NoSuchFinding)
		}
		for _, d := range held {
			if d.LiveKey != nil {
				decided := core.DecisionOccurrenceBodyOf(d)
				body.DecisionOccurrence = &decided
				break
			}
		}
		for _, p := range evidence.Steps {
			body.Steps = append(body.Steps, codeFindingOccurrence(p))
		}
		for _, p := range evidence.Related {
			body.Related = append(body.Related, codeFindingOccurrence(p))
		}
		return &struct{ Body CodeFindingEvidenceBody }{Body: body}, nil
	})
}

// codeFindingOccurrence is one place as an answer states it.
func codeFindingOccurrence(p analysis.Located) CodeFindingOccurrence {
	return CodeFindingOccurrence{
		Path: p.Path, StartLine: p.StartLine, StartColumn: p.StartColumn,
		EndLine: p.EndLine, EndColumn: p.EndColumn, Function: p.Function, Message: p.Message,
		Depth: p.Depth, Snippet: p.Snippet, SnippetLine: p.SnippetLine,
		Link: p.Link.URL, Repository: p.Link.Repository, Within: p.Link.Within, Revision: p.Link.Revision,
		Approximate: p.Link.Approximate, Patched: p.Link.Patched, Unlinked: p.Link.Unlinked,
	}
}

// codeFindingFlaw is the flaw a code finding was recorded as, where the reader is on the
// case: they read the product's undisclosed work, are on the flaw's case, or
// were granted the code finding. Nil for anybody else, and for a code finding not recorded as a flaw.
func codeFindingFlaw(ctx context.Context, in core.Deps, subject access.Subject, productID int64,
	occurrence string) (*CodeFindingFlawBody, error) {

	h, err := finding.CodeFindingFlawAt(ctx, in.DB.DB, productID, occurrence)
	if err != nil || h == nil {
		return nil, err
	}
	if !subject.Reads(access.Private, productID) && !subject.OnCase(productID, h.VulnerabilityID) &&
		!subject.OnCodeFinding(productID, occurrence) {
		return nil, nil
	}
	names, err := finding.NewVulnerabilities(in.DB.DB).NamesByID(ctx, []int64{h.VulnerabilityID})
	if err != nil {
		return nil, err
	}
	who, err := core.WhoSigned(ctx, in.DB.DB, []int64{h.RecordedBy})
	if err != nil {
		return nil, err
	}
	return &CodeFindingFlawBody{
		Flaw: names[h.VulnerabilityID], IncludedInDisclosure: h.Included(), Disclosed: h.Disclosed(),
		RecordedBy: who.Identity(h.RecordedBy), RecordedByName: who.Label(h.RecordedBy),
		RecordedAt: core.Stamp(h.RecordedAt),
	}, nil
}
