package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// PointBody is what was true at one moment.
type PointBody struct {
	At         string         `json:"at" doc:"The end of this step, as a date"`
	Open       int            `json:"open"`
	Opened     int            `json:"opened" doc:"Findings that appeared during this step"`
	Resolved   int            `json:"resolved" doc:"Findings that went away during this step"`
	BySeverity map[string]int `json:"by_severity"`
	// The two flows, split the same way. What arrived and what was answered
	// is the question a backlog is read for: ten in and ten out is a team
	// keeping pace where both are low, and a team losing ground where what
	// arrives is critical and what leaves is not.
	OpenedBySeverity   map[string]int `json:"opened_by_severity" doc:"What appeared, split by severity"`
	ResolvedBySeverity map[string]int `json:"resolved_by_severity" doc:"What went away, split by the severity it held while it was open"`
}

// ComparisonBody is what changed between two builds.
//
// **What left the affected list is two lists, not one.** A bump that carried
// the issue with it, a record taken back and a closure nothing explains are
// not fixes, and a caller reading one list quotes scanner faults as work done.
type ComparisonBody struct {
	Fixed  []ChangedBody `json:"fixed"`
	Closed []ChangedBody `json:"closed_not_fixed" doc:"Left the affected list without being fixed"`
	Newly  []ChangedBody `json:"newly_present"`
	Still  []ChangedBody `json:"still_present"`
}

// ChangedBody is one issue that differs between two builds.
type ChangedBody struct {
	Vulnerability string `json:"vulnerability"`
	Component     string `json:"component"`
	Severity      string `json:"severity,omitempty"`
	Because       string `json:"because,omitempty" enum:"removed,upgraded,revised,superseded,unexplained" doc:"Why it went. Only on fixed entries"`
	ArrivedFrom   string `json:"arrived_from,omitempty" doc:"The version this was upgraded from since the earlier build. Only on still-present entries, where it means the upgrade did not reach the fix"`
	FromVersion   string `json:"from_version,omitempty" doc:"The version the place held before the fix. Only on a fixed entry the version moved for"`
	MovedTo       string `json:"moved_to,omitempty" doc:"The version the place moved to. Only on a fixed entry the version moved for, so a removed component carries neither"`
	ClosedRun     int64  `json:"closed_by_run,omitempty" doc:"The run that stopped reporting it. Only on an entry that left the affected list, and absent where a person closed it"`
	// State is what stands about it, on a still-present entry and nowhere
	// else. This is what turns a list of what is still there into
	// something somebody can sign a release off against: an approved
	// not-applicable and a row nobody has looked at are opposite answers
	// and read alike without it.
	State         string        `json:"state,omitempty" enum:"undecided,waiting,agreed,lapsed" doc:"How far this build has decided it. Only on a still-present entry. Absent where some places are agreed and the rest were never decided, which is none of the four"`
	Outcome       outcome       `json:"outcome,omitempty" doc:"What was decided, where every standing decision over its places says the same thing"`
	Justification justification `json:"justification,omitempty" doc:"The recognized reason it does not apply, on a dismissal"`
	Due           string        `json:"due,omitempty" doc:"The soonest deadline among the places still open, as a date"`
}

func registerReports(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-trend", Method: http.MethodGet, Path: "/v1/trend",
		Summary: "Show new, resolved and open over time",
		Description: "Returns the three counts per step, with open split by severity, across " +
			"every product you can see.\n\n" +
			"**Narrowable to part of a tree.** `component` keeps one package at any version; " +
			"`beneath` keeps a component and everything under it, which needs a branch and a " +
			"variant naming exactly one build. A team that owns one area asks for its own " +
			"three lines this way.\n\n" +
			"Three series rather than one, because separately they are three numbers and " +
			"together they say whether the team is keeping pace: new consistently outrunning " +
			"resolved is a growing backlog.\n\n" +
			"Split by severity because a total that barely moves while its critical share rises " +
			"is getting worse, and a single line hides exactly that.\n\n" +
			"Worked out when it is asked for. Nothing is precomputed or refreshed on a schedule " +
			"until a measurement says it has to be.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		ScopeQuery
		Weeks     int    `query:"weeks" default:"12" minimum:"1" maximum:"104"`
		Component string `query:"component" doc:"Keep only what is open against components of this name, whatever version"`
		Beneath   string `query:"beneath" doc:"Keep only what sits at this component or anywhere under it. A subtree is a walk over one build's edges, so this needs a branch and a variant naming exactly one build"`
		Version   string `query:"beneath_version" doc:"Which one, where the build holds that name at several versions"`
		Ecosystem string `query:"beneath_ecosystem" doc:"Which one, for the few names a build holds at one version as two components"`
	}) (*listOutput[PointBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		const week = 7 * 24 * time.Hour
		since := time.Now().UTC().Add(-time.Duration(input.Weeks) * week)

		scope, err := scoped(ctx, in, subject, input.ScopeQuery)
		if err != nil {
			return nil, err
		}
		points, err := finding.NewStore(in.DB.DB).Trend(ctx, subject, scope, since, week, input.Weeks,
			finding.Within{
				Component: input.Component, Beneath: input.Beneath,
				BeneathVersion: input.Version, BeneathEcosystem: input.Ecosystem,
			})
		if err != nil {
			// A name meaning two components is the caller's question and not a
			// fault here: every other endpoint that resolves one answers with
			// the choices, and this one was answering 500 — so the panel that
			// draws a subtree's history said the trend could not be worked
			// out, about a component the reader could have picked.
			var several *graph.Ambiguous
			if errors.As(err, &several) {
				return nil, severalComponents(several,
					"?beneath_version= and, where two share a version, &beneath_ecosystem=")
			}
			return nil, wentWrong(in.Logger, "the trend could not be worked out", err)
		}
		out := &listOutput[PointBody]{}
		out.Body.Items = make([]PointBody, 0, len(points))
		for _, p := range points {
			out.Body.Items = append(out.Body.Items, PointBody{
				At: p.At.Format(time.DateOnly), Open: p.Open,
				Opened: p.Opened, Resolved: p.Resolved, BySeverity: p.BySeverity,
				OpenedBySeverity: p.OpenedBySeverity, ResolvedBySeverity: p.ResolvedBySeverity,
			})
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-releases", Method: http.MethodGet,
		Path:    "/v1/products/{product}/releases",
		Summary: "Report what is open in each build of a product",
		Description: "One number per build, which is what a release-over-release chart is " +
			"drawn from. The comparison endpoint says what changed between **two** builds; " +
			"this says whether the estate is getting better or worse across all of them.\n\n" +
			"Counted before any triage line is applied, so it agrees with the findings list " +
			"rather than with whatever a product has decided is worth working on — a line is " +
			"about what to spend an afternoon on, not about what exists.\n\n" +
			"Severities are folded the same four ways everything else here ranks by, through " +
			"the one expression the working list and the deadline also read, so a chart cannot " +
			"disagree with a list about what counts as high.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
	}) (*listOutput[ReleaseBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		// The visible lookup, so a product somebody may not see answers the
		// same way as one that was never declared. Resolving the name first
		// and authorizing afterwards is how the difference gets out: this
		// answered 200 with an empty list for a product held by somebody else
		// and 404 for a name nobody has, which hands anyone holding one
		// product the name of every other by guessing.
		named, err := productNamedVisibly(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		releases, err := finding.NewStore(in.DB.DB).Releases(ctx, subject, named.ID)
		if err != nil {
			return nil, wentWrong(in.Logger, "what is open per build could not be read", err)
		}
		out := &listOutput[ReleaseBody]{}
		out.Body.Items = make([]ReleaseBody, 0, len(releases))
		for _, r := range releases {
			out.Body.Items = append(out.Body.Items, ReleaseBody{
				Stream: r.Stream, Kind: r.Kind, Variant: r.Variant,
				Open: r.Open, BySeverity: r.BySeverity,
			})
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "compare-releases", Method: http.MethodGet,
		Path:    "/v1/products/{product}/comparison",
		Summary: "Compare two builds",
		Description: "Returns what was fixed, what is newly present, and what is still there " +
			"between two builds of one product.\n\n" +
			"Between **any** two, not only adjacent ones: what a release note has to answer is " +
			"usually about the last release a customer has, which is rarely the previous one.\n\n" +
			"Each fixed entry says why it went, because \"fixed by upgrading\" and \"fixed by a " +
			"carried patch\" are different sentences to a reader. `superseded` is the one to " +
			"read carefully — it means the version moved and the issue came with it, so it was " +
			"not fixed at all.\n\n" +
			"A still-present entry carrying `arrived_from` is the same failure seen from the " +
			"other side: somebody moved that version since the earlier build and the issue came " +
			"with it, so the upgrade did not reach the fix.\n\n" +
			"**Public findings only unless you ask otherwise.** Its destination is usually a " +
			"public document, so including something undisclosed should be deliberate rather " +
			"than something pasted in without noticing.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product        string `path:"product"`
		From           string `query:"from" required:"true" doc:"The earlier build's stream — a branch or a tag"`
		FromVariant    string `query:"from_variant" required:"true" doc:"The earlier build's variant"`
		To             string `query:"to" required:"true" doc:"The later build's stream"`
		ToVariant      string `query:"to_variant" required:"true" doc:"The later build's variant"`
		IncludePrivate bool   `query:"include_undisclosed" doc:"Include findings nobody has disclosed"`
	}) (*struct{ Body ComparisonBody }, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		locate := func(stream, variant string) (int64, error) {
			return targetIDOf(ctx, in, subject, input.Product, stream, variant)
		}
		from, err := locate(input.From, input.FromVariant)
		if err != nil {
			return nil, err
		}
		to, err := locate(input.To, input.ToVariant)
		if err != nil {
			return nil, err
		}

		comparison, err := finding.NewStore(in.DB.DB).Compare(ctx, subject, from, to,
			input.IncludePrivate)
		if err != nil {
			return nil, refusedFinding(in, err)
		}

		out := &struct{ Body ComparisonBody }{}
		out.Body.Fixed = changed(comparison.Fixed, true, false)
		// The other half of what left, kept apart from it. A bump that carried
		// the issue along and a closure nothing explains are not fixes, and a
		// release coordinator quoting one number for both quotes scanner
		// faults as work done.
		out.Body.Closed = changed(comparison.Closed, true, false)
		out.Body.Newly = changed(comparison.Newly, false, false)
		// Only the still-present column says what a place was bumped from. On
		// a fixed entry the closure already says what happened, and on a new
		// one there was nothing to bump.
		out.Body.Still = changed(comparison.Still, false, true)
		return out, nil
	})
}

// ReleasePointBody is what one release shipped with.
type ReleasePointBody struct {
	Stream     string         `json:"stream"`
	Cut        string         `json:"cut" doc:"When the release was declared. It orders them and labels them; the axis is the sequence"`
	Open       int            `json:"open" doc:"Distinct issues open against it now, against today's vulnerability data rather than the day it was cut"`
	BySeverity map[string]int `json:"by_severity,omitempty"`
}

// registerReleaseTrend offers the trend on the other axis.
func registerReleaseTrend(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-release-trend", Method: http.MethodGet, Path: "/v1/trend/releases",
		Summary: "Show what each release shipped with",
		Description: "One point per tagged release of one product, oldest first, with what is " +
			"open against it now.\n\n" +
			"**The axis follows what is being viewed.** A branch is scanned nightly and has " +
			"continuous data, so a calendar reads correctly on it. A tag never moves again, and " +
			"releases months apart make a calendar count read as slow drift rather than the " +
			"step change it was — the gaps are the chart's whole shape and they are gaps in " +
			"nothing.\n\n" +
			"**Answered against today's vulnerability data**, not as of the day each was cut. " +
			"That is what re-scanning a shipped release is for.\n\n" +
			"**No rates here.** How many appeared and were resolved between two releases is an " +
			"artifact of how far apart somebody cut them; rates always plot on calendar. And a " +
			"product must be named: two products' tags interleave by date and mean nothing side " +
			"by side.",
		Tags: []string{"Reports"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		ScopeQuery
		Limit int `query:"limit" default:"12" minimum:"1" maximum:"50" doc:"How many releases, most recent kept"`
	}) (*struct {
		Body struct {
			Items []ReleasePointBody `json:"items"`
		}
	}, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		scope, err := scoped(ctx, in, subject, input.ScopeQuery)
		if err != nil {
			return nil, err
		}
		points, err := finding.NewStore(in.DB.DB).ReleaseTrend(ctx, subject, scope, input.Limit)
		switch {
		case errors.Is(err, finding.ErrNoProductNamed):
			// The description says a product must be named and the route
			// answered 200 with an empty list — which is what a product with
			// no releases looks like, so a dashboard polling it without one
			// read as a product that had never cut a release.
			return nil, huma.Error422UnprocessableEntity(
				"a product must be named: two products' tags interleave by date and mean " +
					"nothing side by side")
		case err != nil:
			return nil, refused(in.Logger, err, "cannot read what each release shipped with")
		}
		out := &struct {
			Body struct {
				Items []ReleasePointBody `json:"items"`
			}
		}{}
		out.Body.Items = make([]ReleasePointBody, 0, len(points))
		for _, point := range points {
			out.Body.Items = append(out.Body.Items, ReleasePointBody{
				Stream: point.Stream, Cut: point.Cut.Format(time.RFC3339),
				Open: point.Open, BySeverity: point.BySeverity,
			})
		}
		return out, nil
	})
}

// registerNotes offers the comparison as prose.
func registerNotes(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-release-notes", Method: http.MethodGet,
		Path:    "/v1/products/{product}/comparison/notes",
		Summary: "Render a comparison as release notes",
		Description: "The same comparison as markdown, in the form somebody pastes into a " +
			"release note. Returned as `text/markdown` rather than as a string in a JSON " +
			"field, because the point of it is that it goes straight in.\n\n" +
			"**It carries what was fixed and nothing else.** Not what is still present, not " +
			"what newly appeared, and not an upgrade that carried the issue with it — those are " +
			"statements about what a build contains, and the document for them is a VEX, " +
			"which a customer's own scanner reads. The comparison itself still answers all " +
			"three.\n\n" +
			"Worst first and stably ordered, so two runs over the same pair of builds produce " +
			"the same document. A lead line names both builds, the day, and the scanner and " +
			"vulnerability-database versions the later build was last measured with.\n\n" +
			"**Public findings only unless you ask otherwise**, as the comparison itself is. " +
			"Where fixes are left out for not having been disclosed, the note says how many " +
			"and never which.\n\n" +
			"A release that fixed nothing answers with a sentence saying so, not with an " +
			"empty body: zero bytes is also what a truncated response and the wrong pair of " +
			"builds look like.",
		Tags: []string{"Reports"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product        string `path:"product"`
		From           string `query:"from" required:"true" doc:"The earlier build's stream"`
		FromVariant    string `query:"from_variant" required:"true" doc:"The earlier build's variant"`
		To             string `query:"to" required:"true" doc:"The later build's stream"`
		ToVariant      string `query:"to_variant" required:"true" doc:"The later build's variant"`
		IncludePrivate bool   `query:"include_undisclosed" doc:"Include findings nobody has disclosed"`
	}) (*huma.StreamResponse, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		names := catalog.NewStore(in.DB.DB)
		locate := func(stream, variant string) (int64, error) {
			return targetIDOf(ctx, in, subject, input.Product, stream, variant)
		}
		from, err := locate(input.From, input.FromVariant)
		if err != nil {
			return nil, err
		}
		to, err := locate(input.To, input.ToVariant)
		if err != nil {
			return nil, err
		}
		findings := finding.NewStore(in.DB.DB)
		comparison, err := findings.Compare(ctx, subject, from, to, input.IncludePrivate)
		if err != nil {
			return nil, refusedFinding(in, err)
		}
		about := finding.Note{
			From: describing(ctx, names, from, input.From, input.FromVariant),
			To:   describing(ctx, names, to, input.To, input.ToVariant),
		}
		// What the later build was last measured with, and when. A note
		// somebody kept for a year is re-checkable only if it says what
		// produced it — a vulnerability database ships bad data and is
		// corrected, and "which data said so" is then the question. A run that
		// has not finished is not an answer.
		if last, err := findings.LatestRun(ctx, subject, to); err == nil && last != nil {
			about.Scanner = strings.TrimSpace(last.Scanner + " " + last.ScannerVersion)
			about.Database = last.DatabaseVersion
			if last.FinishedAt != nil {
				about.At = *last.FinishedAt
			}
		}
		if !input.IncludePrivate {
			if left, err := findings.OmittedFixes(ctx, subject, from, to); err == nil {
				about.Omitted = left
			}
		}
		notes := finding.Notes(about, comparison)
		return &huma.StreamResponse{Body: func(hc huma.Context) {
			hc.SetHeader("Content-Type", "text/markdown; charset=utf-8")
			hc.SetStatus(http.StatusOK)
			_, _ = hc.BodyWriter().Write([]byte(notes))
		}}, nil
	})
}

// describing names a build the way whoever reads a release note knows it,
// falling back to what the request called it.
//
// A heading naming the stream and variant this deployment files a build under
// is our internals on the first line of a document going to a customer.
func describing(ctx context.Context, names *catalog.Store, targetID int64, stream, variant string) string {
	placed, err := names.Describe(ctx, targetID)
	if err != nil || placed == nil {
		return strings.TrimSpace(stream + " " + variant)
	}
	return strings.TrimSpace(placed.Stream + " " + placed.Variant)
}

func changed(rows []finding.Changed, why, bumped bool) []ChangedBody {
	out := make([]ChangedBody, 0, len(rows))
	for _, row := range rows {
		body := ChangedBody{
			Vulnerability: row.Vulnerability, Component: row.Component, Severity: row.Severity,
		}
		if why {
			body.Because = string(row.Because)
			body.FromVersion, body.MovedTo = row.FromVersion, row.MovedTo
			body.ClosedRun = row.ClosedRun
		}
		// The sign-off half travels with the bump flag: both are about what
		// is still there, which is the only list either means anything on.
		if bumped {
			body.ArrivedFrom = row.ArrivedFrom
			body.State = row.State
			body.Outcome, body.Justification = outcome(row.Outcome), justification(row.Justification)
			if row.Due != nil {
				body.Due = row.Due.Format(time.DateOnly)
			}
		}
		out = append(out, body)
	}
	return out
}

// InheritedBody is one claim a new line could take on.
type InheritedBody struct {
	Decision      int64   `json:"decision"`
	Vulnerability string  `json:"vulnerability"`
	Component     string  `json:"component"`
	Outcome       outcome `json:"outcome"`
	Was           string  `json:"was" doc:"The version the claim was made against"`
	Now           string  `json:"now" doc:"What the new line has"`
	Reasoning     string  `json:"reasoning" doc:"The old words, to start from rather than start without"`
	DeferredDays  int     `json:"deferred_days,omitempty" doc:"How long this has already been put off, across every line it has been carried through"`
}

// CarriedBody is what a new line would inherit.
type CarriedBody struct {
	Applying  int             `json:"applying" doc:"Reach it by matching. Nothing to choose"`
	Moved     []InheritedBody `json:"moved" doc:"The version differs, so each needs a fresh answer"`
	Postponed []InheritedBody `json:"postponed" doc:"Deferrals, offered separately and never carried by default"`
	Absent    int             `json:"absent" doc:"Cover nothing in the new line"`
}

func registerCarry(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "preview-carried-decisions", Method: http.MethodGet,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/carried",
		Summary: "Show what triage a new line would inherit",
		Description: "Returns what an existing line's decisions would mean for this one, " +
			"without changing anything. Ask before creating a line: the answer is what " +
			"somebody is agreeing to.\n\n" +
			"Four groups, because they need four different things:\n\n" +
			"`applying` reach this line by matching, and there is nothing to choose.\n\n" +
			"`moved` held a claim at a version this line does not have. Each would come " +
			"across as a **proposal carrying the old reasoning**, never as a decision.\n\n" +
			"`postponed` were deferrals. Each says how long it has already been put off " +
			"across every line it has come through, which is the total that carrying it " +
			"again agrees to.\n\n" +
			"`absent` cover nothing here and are left behind.",
		Tags: []string{"Triage"},
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		Product     string `path:"product"`
		Stream      string `path:"stream"`
		Variant     string `path:"variant"`
		From        string `query:"from" required:"true" doc:"The stream to inherit from"`
		FromVariant string `query:"from_variant" required:"true" doc:"That stream's variant"`
	}) (*struct{ Body CarriedBody }, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		_, to, err := browsing(ctx, in, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		_, from, err := browsing(ctx, in, input.Product, input.From, input.FromVariant)
		if err != nil {
			return nil, err
		}

		carried, err := store.WouldCarry(ctx, subject, from, to)
		if err != nil {
			return nil, refusedDecision(in.Logger, err)
		}
		body := CarriedBody{
			Applying: carried.Applying, Absent: carried.Absent,
			Moved:     inherited(carried.Moved),
			Postponed: inherited(carried.Postponed),
		}
		return &struct{ Body CarriedBody }{Body: body}, nil
	})
}

// registerCarrying takes the chosen judgments onto the new line.
func registerCarrying(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "carry-decisions", Method: http.MethodPost,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/carried",
		Summary: "Carry chosen triage onto a new line",
		Description: "Takes the judgments named onto this build as claims waiting for " +
			"agreement, each carrying the words from the line it came from.\n\n" +
			"**Reasoning travels and conclusions do not.** Every one arrives needing approval, " +
			"however confident whoever carried it was: a version moved, which is exactly what " +
			"made the old judgment stop applying, so somebody has to look at the new code. " +
			"What is inherited is the thinking rather than the answer.\n\n" +
			"**Only what the preview offered.** A judgment that already applies here has " +
			"nothing to agree to, and one covering nothing here has nothing to apply to; " +
			"naming either is refused rather than skipped, because a caller that got the set " +
			"wrong should hear so.\n\n" +
			"A deferral is carried with the date it had, not with a fresh one. Bounded by the " +
			"same setting that bounds every other action writing many rows.",
		Tags:          []string{"Triage"},
		DefaultStatus: http.StatusCreated,
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
		From    string `query:"from" required:"true" doc:"The line to carry from — a branch or a tag"`
		// The same pair the preview takes, so the two cannot come to disagree
		// about which build is being carried from.
		FromVariant string `query:"from_variant" required:"true" doc:"That line's variant"`
		Body        struct {
			Decisions []int64 `json:"decisions" minItems:"1" doc:"Which of the offered judgments to carry"`
		}
	}) (*struct {
		Body struct {
			Carried int `json:"carried" doc:"How many claims were written, each waiting for a second person"`
		}
	}, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		to, err := locatedVisibly(ctx, in, subject, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		toTarget, err := targetRow(ctx, in, to.StreamID, to.VariantID)
		if err != nil {
			return nil, err
		}
		from, err := locatedVisibly(ctx, in, subject, input.Product, input.From, input.FromVariant)
		if err != nil {
			return nil, err
		}
		fromTarget, err := targetRow(ctx, in, from.StreamID, from.VariantID)
		if err != nil {
			return nil, err
		}

		cap, err := setting.NewStore(in.DB.DB).Count(ctx, setting.TogetherCap,
			triage.DefaultTogetherCap)
		if err != nil {
			return nil, wentWrong(in.Logger, "cannot tell how much may be carried at once", err)
		}
		carried, err := triage.NewStore(in.DB.DB).Carry(ctx, subject,
			fromTarget.ID, toTarget.ID, input.Body.Decisions, cap)
		if err != nil {
			return nil, refusedDecision(in.Logger, err)
		}
		out := &struct {
			Body struct {
				Carried int `json:"carried" doc:"How many claims were written, each waiting for a second person"`
			}
		}{}
		out.Body.Carried = carried
		return out, nil
	})
}

func inherited(rows []triage.Inherited) []InheritedBody {
	out := make([]InheritedBody, 0, len(rows))
	for _, row := range rows {
		out = append(out, InheritedBody{
			Decision: row.DecisionID, Vulnerability: row.Vulnerability,
			Component: row.Component, Outcome: outcome(row.Outcome),
			Was: row.Was, Now: row.Now, Reasoning: row.Reasoning,
			DeferredDays: row.DeferredDays,
		})
	}
	return out
}

// ReleaseBody is one build and how much stands open against it.
type ReleaseBody struct {
	Stream     string         `json:"stream" doc:"The branch or tag"`
	Kind       string         `json:"kind" doc:"Whether that is a branch or a tag"`
	Variant    string         `json:"variant"`
	Open       int            `json:"open" doc:"Every open finding at this build"`
	BySeverity map[string]int `json:"by_severity,omitempty" doc:"That total split by the rating in force"`
}
