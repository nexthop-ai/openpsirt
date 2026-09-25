// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// Recording one judgment about one finding, across the builds it reaches.
//
// Its own subject: a claim's lifecycle is about the claim, and this is about
// the finding a person is standing on — which places of it a judgment covers,
// which other builds the same judgment is written against in the same
// transaction, and what a refusal says about a build that could not be
// resolved.

// FindingDecisionBody is one judgment about a finding, and which of its places
// it covers.
type FindingDecisionBody struct {
	Outcome       outcomeOneAtATime `json:"outcome"`
	Justification justification     `json:"justification,omitempty" doc:"The reason it does not apply. Required when it does not"`
	Mitigation    string            `json:"mitigation,omitempty" maxLength:"65536" doc:"The mitigation that stops it — the rule, the setting, the service that is not exposed. Required when the reason is that mitigations already exist, optional when the outcome is that this will not be fixed, and refused otherwise"`
	DeferredUntil string            `json:"deferred_until,omitempty" doc:"Required when it is deferred. A date, as 2026-03-31"`
	// CommittedTo is when a promised backport lands. An upgrade is not
	// recorded here at all: it answers a component rather than one
	// finding, so it is recorded from the component.
	CommittedTo string `json:"committed_to,omitempty" doc:"The date a promised backport lands. Required for patch-needed and refused with any other"`
	// FixedVersion is what makes the already-fixed claim checkable against
	// whoever packages the component. Offered here because the outcome is
	// offered here: an enum listing an outcome whose evidence the body
	// cannot carry refuses every request that picks it.
	FixedVersion string `json:"fixed_version,omitempty" doc:"The package version whoever packages this states the fix arrived in. Required when the outcome is already-fixed, and refused with any other"`
	Reasoning    string `json:"reasoning" minLength:"1" doc:"The reasoning"`
	// Places is the deliberate narrowing. Absent means every place, which
	// is the default naming the places covered asks for.
	// Bounded like every other array a write path takes. Each entry costs a
	// map insert and a scan of the finding's places before anything is
	// refused, so an unbounded one is work a caller chooses the size of.
	Places []string `json:"places,omitempty" maxItems:"2000" maxLength:"191" doc:"The places this covers, as the finding names them. Omit for all of them"`
	// Extends names an approved claim this one carries to a new issue. The
	// outcome and justification have to be the source's, and the places have
	// to be ones the source sits at.
	Extends int64 `json:"extends,omitempty" doc:"An approved claim at the same component and consumer to carry to this issue. The outcome and justification must match it; the new claim is recorded as an extension of it and still needs a second person"`
	// Remaining decides only the places nothing stands at yet. For applying
	// a decision to another build, where the places at matching versions
	// are already reached by lookup and a second claim about them would be
	// refused.
	Remaining bool `json:"remaining,omitempty" doc:"Decide only the places nothing currently stands at, and leave the rest as they are. For applying a decision to another build, where some of its places are already reached by lookup"`
	// FromStatement cites a VEX statement this was started from. A citation
	// and never an application: their statement is not this claim, and the
	// citation is what lets a later revision be noticed.
	FromStatement int64 `json:"from_statement,omitempty" doc:"A VEX statement this was started from, by its identifier. Recorded as a citation so a later revision to it raises an alert. It is never what the claim rests on"`
	// Also carries the same judgment to other builds of this product, in
	// the same transaction as the build in the path.
	// Bounded: each entry costs a build resolution and a place lookup before
	// any cap is consulted, so a body naming every build of a product is one
	// resolution pass per build before the transaction opens.
	Also []AlsoBuild `json:"also,omitempty" maxItems:"2000" doc:"Other builds of this product the same judgment covers. All of it is written together or none of it is"`
}

// AlsoBuild is another build one judgment reaches, as the reach names it.
type AlsoBuild struct {
	Stream  string `json:"stream"`
	Variant string `json:"variant"`
	// Version is what that build ships under this component's name, and is
	// required wherever it ships more than one — the same reason the route
	// takes it as a query for the build in the path.
	Version string `json:"version,omitempty" doc:"The version that build ships under this name, where it ships more than one"`
}

// DecidedBody is what one judgment about a finding recorded.
type DecidedBody struct {
	ClaimID  int64 `json:"claim_id" doc:"The claim this action made, which is what the review queue lists and what is approved"`
	Recorded int   `json:"recorded" doc:"The number of places it was written against"`
	Covered  int   `json:"covered" doc:"The number of findings those places hold"`
	// Every place this judgment did not reach, whatever kept it from
	// reaching. Not being named describes one of the two: with `remaining`
	// it also counts places a decision reached through lookup already
	// suppressed, which is deliberate — a caller deciding
	// what is left to do wants the number that is left to do, not the
	// number they could have named.
	Left          int     `json:"left" doc:"Places of this finding this judgment did not reach: ones it did not name, and ones a decision already standing there covers"`
	NeedsApproval bool    `json:"needs_approval" doc:"Whether a second person has to agree"`
	IDs           []int64 `json:"ids"`
	// Also is the same judgment's record in each other build named, in the
	// order they were named. Absent where none were.
	Also []CoveredBuild `json:"also,omitempty" doc:"The rows this judgment wrote in each other build it reached"`
}

// CoveredBuild is one judgment's record in one other build.
//
// There is no per-build outcome to report, because there is no per-build
// outcome to have: the whole judgment is written or none of it is.
type CoveredBuild struct {
	Stream   string `json:"stream"`
	Variant  string `json:"variant"`
	Version  string `json:"version,omitempty"`
	Recorded int    `json:"recorded" doc:"The number of places it was written against there"`
	Covered  int    `json:"covered" doc:"The number of findings those places hold"`
}

func registerFindingDecision(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "decide-finding", Method: http.MethodPost,
		Path: "/v1/products/{product}/streams/{stream}/variants/{variant}" +
			"/findings/{vulnerability}/components/{component}/decision",
		Summary: "Record one judgment about a finding, covering its places",
		Description: "Records the same claim against every place this issue occupies in this " +
			"component. Naming `places` narrows it; leaving it out covers all of them.\n\n" +
			"A place left out stays open. Nothing is recorded against it and nothing is " +
			"asked about it.\n\n" +
			"One record is written per place, each keyed and expiring on its own, so this " +
			"reads later as the several decisions it is rather than as one.\n\n" +
			"The ordinary approval rules apply however many places this reaches: covering " +
			"many places does not on its own require a second person.\n\n" +
			"Pass `also` to apply the same judgment to other builds of this product, naming " +
			"each as the reach gives it. All of it is written in one transaction: the " +
			"response is what every build recorded, or a refusal and nothing written " +
			"anywhere. In those builds only the places nothing already stands at are " +
			"written, because the ones at matching versions are reached by lookup " +
			"already.\n\n" +
			"Pass `extends` to carry an approved claim to this issue: the source must be " +
			"approved, sit at the same component under the same consumer, and the outcome and " +
			"justification must match it. The new claim is recorded as an extension of it and " +
			"still waits for a second person. `similar` on `GET .../findings/{vulnerability}/" +
			"components/{component}` lists the claims that qualify.\n\n" +
			"`patch-needed` is the backport case: a fix is being carried into this build " +
			"and the version does not move, so it requires `committed_to`, the date the work " +
			"lands. `upgrade-needed` is not recorded here — an upgrade answers a component and " +
			"everything open on it, so it is recorded from the component.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Stream        string `path:"stream"`
		Variant       string `path:"variant"`
		Vulnerability string `path:"vulnerability" doc:"The issue, by any name it is known under"`
		Component     string `path:"component" doc:"The component, as the findings list gives it"`
		ComponentQuery
		Body FindingDecisionBody
	}) (*struct{ Body DecidedBody }, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}

		// Every build this judgment covers, named before anything is
		// written: the one in the path, and any the caller put beside
		// it.
		asked := append([]AlsoBuild{{
			Stream: input.Stream, Variant: input.Variant, Version: input.Version,
		}}, input.Body.Also...)
		named := make(map[string]bool, len(asked))
		for _, build := range asked {
			if named[build.Stream+"\x00"+build.Variant] {
				return nil, huma.Error422UnprocessableEntity(
					"a build is named twice, and one judgment is recorded against it once")
			}
			named[build.Stream+"\x00"+build.Variant] = true
		}

		var until *time.Time
		if input.Body.DeferredUntil != "" {
			when, err := time.Parse(time.DateOnly, input.Body.DeferredUntil)
			if err != nil {
				return nil, huma.Error422UnprocessableEntity(
					"a deferral returns on a date, written as YYYY-MM-DD")
			}
			until = &when
		}
		var lands *time.Time
		if input.Body.CommittedTo != "" {
			when, err := time.Parse(time.DateOnly, input.Body.CommittedTo)
			if err != nil {
				return nil, huma.Error422UnprocessableEntity(
					"the date promised work lands on is written as YYYY-MM-DD")
			}
			lands = &when
		}

		limit, err := setting.NewStore(in.DB.DB).Count(ctx, setting.TogetherCap,
			triage.DefaultTogetherCap)
		if err != nil {
			return nil, wentWrong(in.Logger, "the limit on one action could not be read", err)
		}

		out := &struct{ Body DecidedBody }{}
		var proposals []triage.Proposal
		// Each build's contribution, so the judgment can report per build
		// once the whole of it has been written.
		writes := make([]int, len(asked))
		holds := make([]int, len(asked))
		sits := 0
		// The places the act has reached so far, charged as each build
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
			// others the places at matching versions are already reached by
			// lookup, and a second claim about them would be refused, so what
			// is written there is whatever nothing stands at yet.
			wanted, remaining := input.Body.Places, input.Body.Remaining
			if i > 0 {
				wanted, remaining = nil, true
			}
			// A package's ecosystem and namespace are the same in every build
			// of a product, so the path's travel to the others with each one's
			// own version.
			places, all, target, err := placesToDecide(ctx, in, subject, store, input.Product,
				build.Stream, build.Variant, input.Vulnerability, input.Component,
				graph.Choice{Version: build.Version, Ecosystem: input.Ecosystem,
					Namespace: input.Namespace},
				wanted, remaining)
			if err != nil {
				if i == 0 {
					return nil, err
				}
				return nil, aboutBuild(build.Stream, build.Variant, err)
			}
			if i == 0 {
				sits = all
			}
			reached[i] = places
			covering = append(covering, target)

			// Charged as each build is resolved rather than after all of
			// them. REQ-27 bounds what is written, not what was asked for —
			// and a request naming two thousand builds of a kernel-shaped
			// component accumulates seven figures of places before the cap is
			// consulted, which is a small request doing a large amount of
			// work. The refusal names the same limit the store's own check
			// names, because it is the same limit.
			seen += len(places)
			if seen > limit {
				return nil, huma.Error422UnprocessableEntity(fmt.Sprintf(
					"that reaches more than the %d findings one action may write: "+
						"name fewer builds, or raise the limit deliberately", limit))
			}
		}

		for i, places := range reached {
			for _, place := range places {
				proposal := triage.Proposal{
					Place: triage.Place{
						ProductID: place.ProductID, VulnerabilityID: place.VulnerabilityID,
						PlaceIdentity: place.PlaceIdentity, Visibility: place.Visibility,
						ComponentUpstream: place.ComponentUpstream,
						ConsumerUpstream:  place.ConsumerUpstream,
						OnTag:             place.OnTag,
					},
					Outcome:       triage.Outcome(input.Body.Outcome),
					Justification: triage.Justification(input.Body.Justification),
					Mitigation:    input.Body.Mitigation,
					FixedVersion:  input.Body.FixedVersion,
					Reasoning:     input.Body.Reasoning,
					By:            subject.ID,
					SeverityCenti: place.SeverityCenti,
					DeferredUntil: until,
					CommittedTo:   lands,
					BindingAcross: covering,
				}
				writes[i]++
				holds[i] += place.Places
				proposals = append(proposals, proposal)
			}
		}

		// One action, one transaction, however many builds it reached. Half of
		// them written and the rest abandoned leaves a judgment recorded in
		// some releases and not others — an act nobody performed, and one
		// nobody can point at afterwards.
		var recorded []*triage.Decision
		if input.Body.Extends != 0 {
			recorded, err = store.Extend(ctx, subject, input.Body.Extends, proposals, limit)
		} else {
			recorded, err = store.ProposeMany(ctx, subject, proposals, limit)
		}
		if err != nil {
			return nil, refusedDecision(in.Logger, err)
		}
		for _, decision := range recorded {
			out.Body.IDs = append(out.Body.IDs, decision.ID)
			out.Body.ClaimID = decision.ClaimID
			// Read off what was written rather than off what was asked for.
			out.Body.NeedsApproval = out.Body.NeedsApproval || decision.NeedsApproval
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

// placesToDecide resolves one build's places for a finding, narrowed the way
// the caller asked for.
//
// Returns the places to write against and the number the finding sits at
// there. The two differ whenever something was left out, and the difference
// states how much of the finding is still open.
func placesToDecide(ctx context.Context, in Ingest, subject access.Subject, store *triage.Store,
	product, stream, variant, vulnerability, component string, which graph.Choice,
	wanted []string, remaining bool) ([]finding.Deciding, int, int64, error) {

	target, issue, at, err := findingAbout(ctx, in, subject,
		product, stream, variant, vulnerability, component, which)
	if err != nil {
		return nil, 0, 0, err
	}
	all, err := finding.NewStore(in.DB.DB).PlacesFor(ctx, subject, target, issue, at)
	if err != nil || len(all) == 0 {
		return nil, 0, 0, noSuchFinding()
	}

	// Narrowed to what was named, and a name nothing matches is refused
	// rather than ignored: somebody who meant to cover six places and
	// mistyped one should not quietly cover five.
	places := all
	if len(wanted) > 0 {
		asked := map[string]bool{}
		for _, name := range wanted {
			asked[name] = true
		}
		places = make([]finding.Deciding, 0, len(asked))
		for _, place := range all {
			if asked[place.PlaceIdentity] {
				places = append(places, place)
				delete(asked, place.PlaceIdentity)
			}
		}
		if len(asked) > 0 {
			return nil, 0, 0, huma.Error422UnprocessableEntity(
				"this finding does not sit at every place you named")
		}
	}

	if !remaining {
		return places, len(all), target, nil
	}
	ask := make([]triage.Place, 0, len(places))
	for _, place := range places {
		ask = append(ask, triage.Place{
			ProductID: place.ProductID, VulnerabilityID: place.VulnerabilityID,
			PlaceIdentity: place.PlaceIdentity, Visibility: place.Visibility,
			ComponentUpstream: place.ComponentUpstream,
			ConsumerUpstream:  place.ConsumerUpstream,
		})
	}
	left, err := store.Undecided(ctx, ask)
	if err != nil {
		return nil, 0, 0, wentWrong(in.Logger, "cannot tell what already stands here", err)
	}
	standing := make(map[string]bool, len(left))
	for _, one := range left {
		standing[one.PlaceIdentity+"\x00"+one.ComponentUpstream+"\x00"+one.ConsumerUpstream] = true
	}
	// Everything else is already reached by lookup: nothing to record there,
	// and nothing wrong either. An empty answer is what says so.
	open := make([]finding.Deciding, 0, len(left))
	for _, place := range places {
		if standing[place.PlaceIdentity+"\x00"+place.ComponentUpstream+"\x00"+place.ConsumerUpstream] {
			open = append(open, place)
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
func findingAbout(ctx context.Context, in Ingest, subject access.Subject,
	product, stream, variant, vulnerability, component string,
	which graph.Choice) (int64, int64, int64, error) {

	named, err := locatedVisibly(ctx, in, subject, product, stream, variant)
	if err != nil {
		return 0, 0, 0, err
	}
	target, err := targetRow(ctx, in, named.StreamID, named.VariantID)
	if err != nil {
		return 0, 0, 0, err
	}
	issue, err := issueHere(ctx, in, subject, named.ProductID, vulnerability)
	if err != nil {
		return 0, 0, 0, err
	}
	at, err := componentCarrying(ctx, in, subject, target.ID, issue, component, which,
		ambiguousOrMissing)
	if err != nil {
		return 0, 0, 0, err
	}
	return target.ID, issue, at, nil
}

// decidingAbout resolves the names in a path to the place a decision is made
// about, authorized on the way.
func decidingAbout(ctx context.Context, in Ingest, subject access.Subject,
	product, stream, variant, vulnerability, place string) (*finding.Deciding, int64, error) {
	names := catalog.NewStore(in.DB.DB)
	named, err := names.LocateVisible(ctx, subject, product, stream, variant)
	if err != nil {
		return nil, 0, undeclared(in.Logger, err, "that build could not be looked up")
	}
	target, err := targetRow(ctx, in, named.StreamID, named.VariantID)
	if err != nil {
		return nil, 0, err
	}

	issue, err := issueHere(ctx, in, subject, named.ProductID, vulnerability)
	if err != nil {
		return nil, 0, err
	}

	at, err := finding.NewStore(in.DB.DB).PlaceFor(ctx, subject, target.ID, issue, place)
	if err != nil {
		return nil, 0, noSuchFinding()
	}
	return at, target.ID, nil
}
