// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// Recording one decision about one finding, across the builds it reaches.
//
// Its own subject: a decision's lifecycle is about the decision, and this is
// about the finding a person is standing on — which occurrences of it a
// decision covers, which other builds the same decision is written against in
// the same transaction, and what a refusal says about a build that could not
// be resolved.

// namedTwice refuses a decision naming one build twice.
const namedTwice = "a build is named twice, and one decision is recorded against it once"

// promisedDates reads the date a deferral returns on and the date promised
// work lands on, either of which may be absent.
func promisedDates(deferred, committed string) (until, lands *time.Time, err error) {
	if deferred != "" {
		when, err := time.Parse(time.DateOnly, deferred)
		if err != nil {
			return nil, nil, huma.Error422UnprocessableEntity(
				"a deferral returns on a date, written as YYYY-MM-DD")
		}
		until = &when
	}
	if committed != "" {
		when, err := time.Parse(time.DateOnly, committed)
		if err != nil {
			return nil, nil, huma.Error422UnprocessableEntity(
				"the date promised work lands on is written as YYYY-MM-DD")
		}
		lands = &when
	}
	return until, lands, nil
}

// FindingDecisionBody is one decision about a finding, and which of its
// occurrences it covers.
type FindingDecisionBody struct {
	Outcome       core.OutcomeOneAtATime `json:"outcome"`
	Justification core.Justification     `json:"justification,omitempty" doc:"The reason it does not apply. Required when it does not"`
	Mitigation    string                 `json:"mitigation,omitempty" maxLength:"65536" doc:"The mitigation that stops it — the rule, the setting, the service that is not exposed. Required when the reason is that mitigations already exist, optional when the outcome is that this will not be fixed, and refused otherwise"`
	Scope         core.StatementScope    `json:"scope,omitempty" doc:"Whom a published statement made from this decision holds for: portable for anybody shipping the component at that version, build for this product's own build only. Omit to let the outcome and the reason decide. Refused on a deferral. An extension keeps the scope of the decision it carries"`
	DeferredUntil string                 `json:"deferred_until,omitempty" doc:"Required when it is deferred. A date, as 2026-03-31"`
	// CommittedTo is when a promised backport lands. An upgrade is not
	// recorded here at all: it answers a component rather than one
	// finding, so it is recorded from the component.
	CommittedTo string `json:"committed_to,omitempty" doc:"The date a promised backport lands. Required for patch-needed and refused with any other"`
	// FixedVersion is what makes the already-fixed decision checkable against
	// whoever packages the component. Offered here because the outcome is
	// offered here: an enum listing an outcome whose evidence the body
	// cannot carry refuses every request that picks it.
	FixedVersion string `json:"fixed_version,omitempty" doc:"The package version whoever packages this states the fix arrived in. Required when the outcome is already-fixed, and refused with any other"`
	Reasoning    string `json:"reasoning" minLength:"1" doc:"The reasoning"`
	// Occurrences is the deliberate narrowing. Absent means every occurrence,
	// which is the default naming the occurrences covered asks for.
	// Bounded like every other array a write path takes. Each entry costs a
	// map insert and a scan of the finding's occurrences before anything is
	// refused, so an unbounded one is work a caller chooses the size of.
	Occurrences []string `json:"occurrences,omitempty" maxItems:"2000" maxLength:"191" doc:"The occurrences this covers, as the finding names them. Omit for all of them"`
	// Extends names an approved decision this one carries to a new issue. The
	// outcome and justification have to be the source's, and the occurrences
	// have to be ones the source sits at.
	Extends int64 `json:"extends,omitempty" doc:"An approved decision at the same component and consumer to carry to this issue. The outcome and justification must match it; the new decision is recorded as an extension of it and still needs a second person"`
	// Remaining decides only the occurrences nothing stands at yet. For
	// applying a decision to another build, where the occurrences at matching
	// versions are already reached by lookup and a second decision about them
	// would be refused.
	Remaining bool `json:"remaining,omitempty" doc:"Decide only the occurrences nothing currently stands at, and leave the rest as they are. For applying a decision to another build, where some of its occurrences are already reached by lookup"`
	// FromStatement cites a VEX statement this was started from. A citation
	// and never an application: their statement is not this decision, and the
	// citation is what lets a later revision be noticed.
	FromStatement int64 `json:"from_statement,omitempty" doc:"A VEX statement this was started from, by its identifier. Recorded as a citation so a later revision to it raises an alert. It is never what the decision rests on"`
	// Also carries the same decision to other builds of this product, in
	// the same transaction as the build in the path.
	// Bounded: each entry costs a build resolution and an occurrence lookup before
	// any cap is consulted, so a body naming every build of a product is one
	// resolution pass per build before the transaction opens.
	Also []AlsoBuild `json:"also,omitempty" maxItems:"2000" doc:"Other builds of this product the same decision covers. All of it is written together or none of it is"`
}

// AlsoBuild is another build one decision reaches, as the reach names it.
type AlsoBuild struct {
	Stream  string `json:"stream"`
	Variant string `json:"variant"`
	// Version is what that build ships under this component's name, and is
	// required wherever it ships more than one — the same reason the route
	// takes it as a query for the build in the path.
	Version string `json:"version,omitempty" doc:"The version that build ships under this name, where it ships more than one"`
}

// DecidedBody is what one decision about a finding recorded.
type DecidedBody struct {
	DecisionID int64 `json:"decision_id" doc:"The decision this action made, which is what the review queue lists and what is approved"`
	Recorded   int   `json:"recorded" doc:"The number of occurrences it covers"`
	Covered    int   `json:"covered" doc:"The number of findings those occurrences hold"`
	// Every occurrence this decision did not reach, whatever kept it from
	// reaching. Not being named describes one of the two: with `remaining`
	// it also counts occurrences a decision reached through lookup already
	// suppressed, which is deliberate — a caller deciding
	// what is left to do wants the number that is left to do, not the
	// number they could have named.
	Left          int     `json:"left" doc:"Occurrences of this finding this decision did not reach: ones it did not name, and ones a decision already standing there covers"`
	NeedsApproval bool    `json:"needs_approval" doc:"Whether a second person has to agree"`
	IDs           []int64 `json:"ids"`
	// Also is the same decision's record in each other build named, in the
	// order they were named. Absent where none were.
	Also []CoveredBuild `json:"also,omitempty" doc:"What this decision covers in each other build it reached"`
}

// CoveredBuild is one decision's record in one other build.
//
// There is no per-build outcome to report, because there is no per-build
// outcome to have: the whole decision is written or none of it is.
type CoveredBuild struct {
	Stream   string `json:"stream"`
	Variant  string `json:"variant"`
	Version  string `json:"version,omitempty"`
	Recorded int    `json:"recorded" doc:"The number of occurrences it covers there"`
	Covered  int    `json:"covered" doc:"The number of findings those occurrences hold"`
}

func registerFindingDecision(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "decide-finding", Method: http.MethodPost,
		Path: "/v1/products/{product}/branches-and-tags/{stream}/variants/{variant}" +
			"/findings/{issue}/components/{component}/decision",
		Summary: "Record one decision about a finding, covering its occurrences",
		Description: "Records the same decision against every occurrence this issue has in this " +
			"component. Naming `occurrences` narrows it; leaving it out covers all of them.\n\n" +
			"An occurrence left out stays open. Nothing is recorded against it and nothing is " +
			"asked about it.\n\n" +
			"The decision is keyed and expires at each occurrence on its own, so it reads " +
			"later occurrence by occurrence rather than as one.\n\n" +
			"The ordinary approval rules apply however many occurrences this reaches: covering " +
			"many occurrences does not on its own require a second person.\n\n" +
			"Pass `also` to apply the same decision to other builds of this product, naming " +
			"each as the reach gives it. All of it is written in one transaction: the " +
			"response is what every build recorded, or a refusal and nothing written " +
			"anywhere. In those builds only the occurrences nothing already stands at are " +
			"written, because the ones at matching versions are reached by lookup " +
			"already. The decision records the build in the path and each build named in " +
			"`also` as the builds it was made on, and no build it reaches by lookup.\n\n" +
			"Pass `extends` to carry an approved decision to this issue: the source must be " +
			"approved, sit at the same component under the same consumer, and the outcome and " +
			"justification must match it. The new decision is recorded as an extension of it and " +
			"still waits for a second person. `similar` on `GET .../findings/{issue}/" +
			"components/{component}` lists the decisions that qualify.\n\n" +
			"`patch-needed` is the backport case: a fix is being carried into this build " +
			"and the version does not move, so it requires `committed_to`, the date the work " +
			"lands. `upgrade-needed` is not recorded here — an upgrade answers a component and " +
			"everything open on it, so it is recorded from the component.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, core.PerProduct, "", core.TriageRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Stream        string `path:"stream"`
		Variant       string `path:"variant"`
		Vulnerability string `path:"issue" doc:"The issue, by any name it is known under"`
		Component     string `path:"component" doc:"The component, as the findings list gives it"`
		core.ComponentQuery
		Body FindingDecisionBody
	}) (*struct{ Body DecidedBody }, error) {
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}

		// Every build this decision covers, named before anything is
		// written: the one in the path, and any the caller put beside
		// it.
		asked := append([]AlsoBuild{{
			Stream: input.Stream, Variant: input.Variant, Version: input.Version,
		}}, input.Body.Also...)
		until, lands, err := promisedDates(input.Body.DeferredUntil, input.Body.CommittedTo)
		if err != nil {
			return nil, err
		}

		limit, err := setting.NewStore(in.DB.DB).Count(ctx, setting.BulkDecisionCap,
			triage.DefaultBulkDecisionCap)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "the limit on one action could not be read", err)
		}

		out := &struct{ Body DecidedBody }{}
		var proposals []triage.Proposal
		// Each build's contribution, so the decision can report per build
		// once the whole of it has been written.
		writes := make([]int, len(asked))
		holds := make([]int, len(asked))
		sits := 0
		// The occurrences the act has reached so far, charged as each build
		// resolves.
		seen := 0
		reached := make([][]finding.Deciding, len(asked))
		// The builds a promise made here is gated across. The gate itself —
		// the earliest deadline among them — is a stored value that
		// a re-rating or an arriving scan moves, so it is resolved inside the
		// transaction rather than here: read now, a promise would be gated
		// against a deadline that may be gone by the time it is written, and a
		// retry of the closure re-reads everything else.
		covering := make([]int64, 0, len(asked))
		for i, build := range asked {
			// Only the build in the path takes the caller's narrowing. In the
			// others the occurrences at matching versions are already reached by
			// lookup, and a second decision about them would be refused, so what
			// is written there is whatever nothing stands at yet.
			wanted, remaining := input.Body.Occurrences, input.Body.Remaining
			if i > 0 {
				wanted, remaining = nil, true
			}
			// The path's ecosystem and namespace travel to the others with each
			// one's own version. Another build can describe the package under a
			// namespace of its own — one image written by a generator that
			// named its own packages, another by one that names them as the
			// distribution's — so where the namespace finds nothing there it is
			// dropped, and the version and what carries the issue decide.
			which := graph.Choice{Version: build.Version, Ecosystem: input.Ecosystem,
				Namespace: input.Namespace}
			occurrences, all, target, err := occurrencesToDecide(ctx, in, subject, store, input.Product,
				build.Stream, build.Variant, input.Vulnerability, input.Component,
				which, wanted, remaining)
			if i > 0 && which.Namespace != "" && core.Answered(err) == http.StatusNotFound {
				which.Namespace = ""
				occurrences, all, target, err = occurrencesToDecide(ctx, in, subject, store, input.Product,
					build.Stream, build.Variant, input.Vulnerability, input.Component,
					which, wanted, remaining)
			}
			if err != nil {
				if i == 0 {
					return nil, err
				}
				return nil, aboutBuild(build.Stream, build.Variant, err)
			}
			// Compared as the names resolve, because a name people type is
			// matched without regard to capitals.
			if slices.Contains(covering, target) {
				return nil, huma.Error422UnprocessableEntity(namedTwice)
			}
			if i == 0 {
				sits = all
			}
			reached[i] = occurrences
			covering = append(covering, target)

			// Charged as each build is resolved rather than after all of
			// them. REQ-27 bounds what is written, not what was asked for —
			// and a request naming two thousand builds of a kernel-shaped
			// component accumulates seven figures of occurrences before the cap is
			// consulted, which is a small request doing a large amount of
			// work. The refusal names the same limit the store's own check
			// names, because it is the same limit.
			seen += len(occurrences)
			if seen > limit {
				return nil, huma.Error422UnprocessableEntity(fmt.Sprintf(
					"that reaches more than the %d findings one action may write: "+
						"name fewer builds, or raise the limit deliberately", limit))
			}
		}

		for i, occurrences := range reached {
			for _, occurrence := range occurrences {
				proposal := triage.Proposal{
					Occurrence:    occurrenceOf(occurrence),
					Outcome:       triage.Outcome(input.Body.Outcome),
					Justification: triage.Justification(input.Body.Justification),
					Mitigation:    input.Body.Mitigation,
					Scope:         triage.Scope(input.Body.Scope),
					FixedVersion:  input.Body.FixedVersion,
					Reasoning:     input.Body.Reasoning,
					By:            subject.ID,
					SeverityCenti: occurrence.SeverityCenti,
					DeferredUntil: until,
					CommittedTo:   lands,
					BindingAcross: covering,
					// Made on the build in the path and every build the
					// caller named beside it. The builds the decision reaches by
					// lookup are not among them.
					MadeOn: covering,
				}
				writes[i]++
				holds[i] += occurrence.Occurrences
				proposals = append(proposals, proposal)
			}
		}

		// One action, one transaction, however many builds it reached. Half of
		// them written and the rest abandoned leaves a decision recorded in
		// some releases and not others — an act nobody performed, and one
		// nobody can point at afterwards.
		var recorded []*triage.DecisionOccurrence
		if input.Body.Extends != 0 {
			recorded, err = store.Extend(ctx, subject, input.Body.Extends, proposals)
		} else {
			recorded, err = store.ProposeMany(ctx, subject, proposals)
		}
		if err != nil {
			return nil, core.RefusedDecision(in.Logger, err)
		}
		for _, occurrence := range recorded {
			out.Body.IDs = append(out.Body.IDs, occurrence.ID)
			out.Body.DecisionID = occurrence.DecisionID
			// Read off what was written rather than off what was asked for.
			out.Body.NeedsApproval = out.Body.NeedsApproval || occurrence.NeedsApproval
		}
		if out.Body.IDs == nil {
			out.Body.IDs = []int64{}
		}
		// The counts on the body itself are about the build in the path; the
		// others report themselves.
		out.Body.Recorded = writes[0]
		out.Body.Covered = holds[0]
		out.Body.Left = sits - out.Body.Recorded
		for i, build := range asked[1:] {
			out.Body.Also = append(out.Body.Also, CoveredBuild{
				Stream: build.Stream, Variant: build.Variant, Version: build.Version,
				Recorded: writes[i+1], Covered: holds[i+1],
			})
		}
		return out, nil
	})
}

// occurrencesToDecide resolves one build's occurrences for a finding, narrowed
// the way the caller asked for.
//
// Returns the occurrences to write against and the number the finding sits at
// there. The two differ whenever something was left out, and the difference
// states how much of the finding is still open.
func occurrencesToDecide(ctx context.Context, in core.Deps, subject access.Subject, store *triage.Store,
	product, stream, variant, vulnerability, component string, which graph.Choice,
	wanted []string, remaining bool) ([]finding.Deciding, int, int64, error) {

	target, issue, at, err := findingAbout(ctx, in, subject,
		product, stream, variant, vulnerability, component, which)
	if err != nil {
		return nil, 0, 0, err
	}
	all, err := finding.NewStore(in.DB.DB).OccurrencesFor(ctx, subject, target, issue, at)
	if err != nil {
		return nil, 0, 0, core.Absent(in.Logger, err, "those occurrences could not be looked up", core.NoSuchFinding)
	}
	if len(all) == 0 {
		return nil, 0, 0, core.NoSuchFinding()
	}

	// Narrowed to what was named, and a name nothing matches is refused
	// rather than ignored: somebody who meant to cover six occurrences and
	// mistyped one should not quietly cover five.
	occurrences := all
	if len(wanted) > 0 {
		asked := map[string]bool{}
		for _, name := range wanted {
			asked[name] = true
		}
		occurrences = make([]finding.Deciding, 0, len(asked))
		for _, occurrence := range all {
			if asked[occurrence.OccurrenceIdentity] {
				occurrences = append(occurrences, occurrence)
				delete(asked, occurrence.OccurrenceIdentity)
			}
		}
		if len(asked) > 0 {
			return nil, 0, 0, huma.Error422UnprocessableEntity(
				"this finding does not sit at every occurrence you named")
		}
	}

	if !remaining {
		return occurrences, len(all), target, nil
	}
	ask := make([]triage.Occurrence, 0, len(occurrences))
	for _, occurrence := range occurrences {
		ask = append(ask, occurrenceOf(occurrence))
	}
	left, err := store.Undecided(ctx, ask)
	if err != nil {
		return nil, 0, 0, core.WentWrong(in.Logger, "cannot tell what already stands here", err)
	}
	standing := make(map[string]bool, len(left))
	for _, one := range left {
		standing[one.OccurrenceIdentity+"\x00"+one.ComponentUpstream+"\x00"+one.ConsumerUpstream] = true
	}
	// Everything else is already reached by lookup: nothing to record there,
	// and nothing wrong either. An empty answer is what says so.
	open := make([]finding.Deciding, 0, len(left))
	for _, occurrence := range occurrences {
		if standing[occurrence.OccurrenceIdentity+"\x00"+occurrence.ComponentUpstream+"\x00"+occurrence.ConsumerUpstream] {
			open = append(open, occurrence)
		}
	}
	return open, len(all), target, nil
}

// aboutBuild says which of the builds a refusal is about.
//
// Only for the ones named beside the path, and it says nothing a caller did
// not already know: it named the build itself, and the refusal is the same one
// the build in the path would have got.
func aboutBuild(stream, variant string, err error) error {
	var status huma.StatusError
	if errors.As(err, &status) {
		return huma.NewError(status.GetStatus(), stream+"/"+variant+": "+status.Error())
	}
	return err
}

// findingAbout resolves the names in a path to one finding: the build, the
// issue and the component it is open against, authorized on the way.
//
// Name and version together, because a name alone is not unique — a real image
// ships three vendored versions of one library, and resolving the name on its
// own answers about whichever was interned first.
func findingAbout(ctx context.Context, in core.Deps, subject access.Subject,
	product, stream, variant, vulnerability, component string,
	which graph.Choice) (int64, int64, int64, error) {

	named, err := core.LocatedVisibly(ctx, in, subject, product, stream, variant)
	if err != nil {
		return 0, 0, 0, err
	}
	target, err := core.TargetRow(ctx, in, named.StreamID, named.VariantID)
	if err != nil {
		return 0, 0, 0, err
	}
	issue, err := core.IssueHere(ctx, in, subject, named.ProductID, vulnerability)
	if err != nil {
		return 0, 0, 0, err
	}
	at, err := core.ComponentCarrying(ctx, in, subject, target.ID, issue, component, which,
		func(err error) error { return core.AmbiguousOrMissing(in.Logger, err) })
	if err != nil {
		return 0, 0, 0, err
	}
	return target.ID, issue, at, nil
}

// decidingAbout resolves the names in a path to the occurrence a decision is made
// about, authorized on the way.
//
// A build the caller cannot reach answers with the sentence every other
// finding route gives. Naming which part of the address failed is for a
// pipeline filing a scan; here it would tell a reader which products exist.
func decidingAbout(ctx context.Context, in core.Deps, subject access.Subject,
	product, stream, variant, vulnerability, occurrence string) (*finding.Deciding, int64, error) {
	named, err := core.LocatedVisibly(ctx, in, subject, product, stream, variant)
	if err != nil {
		return nil, 0, err
	}
	target, err := core.TargetRow(ctx, in, named.StreamID, named.VariantID)
	if err != nil {
		return nil, 0, err
	}

	issue, err := core.IssueHere(ctx, in, subject, named.ProductID, vulnerability)
	if err != nil {
		return nil, 0, err
	}

	at, err := finding.NewStore(in.DB.DB).OccurrenceFor(ctx, subject, target.ID, issue, occurrence)
	if err != nil {
		return nil, 0, core.Absent(in.Logger, err, "that occurrence could not be looked up", core.NoSuchFinding)
	}
	return at, target.ID, nil
}

// occurrenceOf is the occurrence a decision is about, as the finding there
// states it.
//
// One spelling for every route. Whether the occurrence sits in a tag build is read
// from the finding rather than supplied, and a route that leaves it out makes
// a dated outcome on a release built once, which the store refuses on every
// other route.
func occurrenceOf(d finding.Deciding) triage.Occurrence {
	return triage.Occurrence{
		ProductID: d.ProductID, VulnerabilityID: d.VulnerabilityID,
		OccurrenceIdentity: d.OccurrenceIdentity, Visibility: d.Visibility,
		ComponentUpstream: d.ComponentUpstream, ConsumerUpstream: d.ConsumerUpstream,
		OnTag: d.OnTag,
	}
}
