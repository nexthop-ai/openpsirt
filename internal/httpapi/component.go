// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// PerBuildBody is one build's answer about a component.
type PerBuildBody struct {
	Stream  string `json:"stream"`
	Variant string `json:"variant"`
	Version string `json:"version" doc:"The version this build ships"`
	// Purl is the identifier an ecosystem and an upstream address are read out
	// of.
	Purl      string `json:"purl,omitempty" doc:"The package identifier this build ships it under"`
	Ecosystem string `json:"ecosystem,omitempty" doc:"The ecosystem the identifier names, read out of it rather than stored"`
	// PackagePageURL is where the package is published, worked out from
	// the identifier by the one table that does that. A second table in the
	// interface, with a different membership, answers differently for the same
	// identifier — sending an Ubuntu package to Debian's tracker, which is a
	// record for different code.
	//
	// Named for what it is rather than "upstream", which already means
	// something else in this vocabulary: on a finding it is what a fork was
	// made from, and on a component it is the source package a binary was
	// built from. One word for two unrelated senses is what this name
	// avoids.
	PackagePageURL  string `json:"package_page_url,omitempty" doc:"The address this package is published at, worked out from its identifier. Absent for a kind of package this has no address for, which is what a private registry, a vendored fork and a distribution with no package browser all look like"`
	PackagePageName string `json:"package_page_name,omitempty" doc:"The name for that address on screen — which distribution's or which index's record it is, since a reader choosing between two needs to know which kind of source each is"`
	// Summary is the ecosystem index's own description of the package, where
	// one was asked and answered. Absent is the ordinary case rather than a
	// gap.
	Summary    string `json:"summary,omitempty" doc:"One line saying what the package is, as its ecosystem's index states it. Absent where no index serves one — the Go module protocol has no such field — and where no index is asked, which is every distribution package"`
	ProjectURL string `json:"project_url,omitempty" doc:"The address the index gives for where the package is developed. Absent where it does not say, in which case an address can still be built from the identifier"`
	// A count has a shape. Forty issues and three criticals are different
	// work, and a number with nothing beside it says which is which.
	BySeverity map[string]int `json:"by_severity,omitempty" doc:"Everything open here by how it was rated. 'unrated' is what nobody scored, and the bands sum to the issue count"`
	Exploited  bool           `json:"exploited" doc:"Whether any of what is open here is known to be exploited, which outranks everything else about it"`
	// ExploitedHere is the other exploitation signal, and the one that
	// outranks it. Separate, because a feed's word about the world and a
	// person's word about this product are different facts.
	ExploitedHere bool   `json:"exploited_here,omitempty" doc:"Whether this product is recorded as having been exploited through any of what is open here"`
	Fixable       int    `json:"fixable" doc:"The number of open findings any version fixes, counted once per issue. What is left needs a judgment rather than an upgrade, and a record naming several fixed versions is still one issue"`
	Supplier      string `json:"supplier,omitempty" doc:"The supplier the scan named — a distribution, a vendor, a project. From the inventory rather than from an index, and absent for plenty of it"`
	// Newest is the current version according to the ecosystem's index, where
	// one was asked.
	Newest    string     `json:"newest_version,omitempty" doc:"The newest version the ecosystem's index knows of. Absent where no index is asked, which is every distribution package"`
	NewestAt  *time.Time `json:"newest_released_at,omitempty" doc:"The date that version shipped, where the index said"`
	FirstSeen time.Time  `json:"first_seen" doc:"The moment a scan of this deployment first reported the component"`
	Issues    int        `json:"issues" doc:"Distinct vulnerabilities open against it here"`
	// Consumers is the unit somebody acts in: one judgment covers the whole
	// fold, and what varies underneath it is the set of consumers pulling the
	// package in.
	Consumers int `json:"consumers" doc:"The number of things pulling it in here"`
	Places    int `json:"places" doc:"The number of times those sit somewhere in this build. What the bulk cap is measured against"`
	// Upgrades are the versions this build could move to.
	Upgrades []UpgradeBody `json:"upgrades,omitempty" doc:"Versions upstream released that would close some of what is open here, most-closing first. Per build, because the answer differs by build: a stream on a maintained older line and a stream that has moved on have different targets"`
	DueAt    *time.Time    `json:"due_at,omitempty" doc:"The earliest deadline among what is open here. A commitment at or before it needs no approval; past it a second person agrees, because that defers the worst thing it covers"`
	// CommittedTo is the promise already made for this build, read off the
	// decisions.
	CommittedTo *time.Time `json:"committed_to,omitempty" doc:"The date the work promised here is due"`
	UpgradeTo   string     `json:"upgrade_to,omitempty" doc:"The version somebody has committed to moving this build to"`
}

// registerComponent answers a component across the builds that carry it.
//
// The by-component view answers where the weight is. Clicking a component into
// a filtered list of its findings leaves it read and never acted on, and the
// act of upgrading one on a screen of its own, keyed on version pairs, puts
// the thing somebody does on a different page from the thing it is done to.
func registerComponent(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-component", Method: http.MethodGet,
		Path:    "/v1/products/{product}/components/{component}",
		Summary: "Show a component across the builds that carry it",
		Description: "What each build ships, what is open against it there, where it could " +
			"go, and what has already been promised.\n\n" +
			"Answered per build, because the answer differs by build. A stream staying " +
			"on a maintained older line and a stream that has moved on are different work " +
			"with different testing, and one target across both would be wrong for one of " +
			"them.\n\n" +
			"Where it could go carries two counts. `fixed_here` is how many of what is " +
			"open name that exact version as their fix, which is the release's own security " +
			"content; `reached` is how many the upgrade closes altogether, counting " +
			"everything fixed at or before it. The second is the one somebody choosing a " +
			"version is asking about, and it needs the ecosystem's ordering: where that is " +
			"not defined the two counts are equal, `ordered` is false, and the list is not " +
			"ranked. Ranked on `fixed_here` a quiet release late on a maintained line sorts " +
			"near the bottom while carrying every fix before it.\n\n" +
			"A build is listed because it ships the component, not because something is " +
			"open against it. A package carrying nothing of its own still answers with the " +
			"version it ships and how many things pull it in, which is the ordinary case for " +
			"anything vendored in pre-built.\n\n" +
			"One entry per version rather than per build. A build shipping a name at two " +
			"versions holds two components, and they are two different pieces of code to " +
			"decide about.\n\n" +
			"`due_at` is what a commitment about that build is gated against, and is absent " +
			"where nothing is open.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Component string `path:"component"`
		ScopeQuery
	}) (*listOutput[PerBuildBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		asked := input.ScopeQuery
		asked.Product = input.Product
		scope, err := scoped(ctx, in, subject, asked)
		if err != nil {
			return nil, err
		}
		builds, err := finding.NewStore(in.DB.DB).AcrossBuilds(ctx, subject, scope, input.Component)
		if err != nil {
			return nil, refusedFinding(in, err)
		}
		out := &listOutput[PerBuildBody]{}
		out.Body.Items = make([]PerBuildBody, 0, len(builds))
		for _, build := range builds {
			upgrades := make([]UpgradeBody, 0, len(build.Upgrades))
			for _, each := range build.Upgrades {
				upgrades = append(upgrades, UpgradeBody{To: each.To, FixedHere: each.FixedHere,
					Reached: each.Reached, Ordered: each.Ordered})
			}
			page, called := finding.PackagePage(build.Purl)
			out.Body.Items = append(out.Body.Items, PerBuildBody{
				Stream: build.Stream, Variant: build.Variant, Version: build.Version,
				Purl: build.Purl, Ecosystem: graph.EcosystemOf(build.Purl),
				PackagePageURL: page, PackagePageName: called,
				Summary: build.Summary, ProjectURL: build.ProjectURL,
				BySeverity: build.BySeverity, Exploited: build.Exploited,
				ExploitedHere: build.ExploitedHere,
				Fixable:       build.Fixable,
				Supplier:      build.Supplier,
				Newest:        build.Newest, NewestAt: build.NewestAt, FirstSeen: build.FirstSeen,
				Issues: build.Issues, Consumers: build.Consumers, Places: build.Places,
				Upgrades: upgrades,
				DueAt:    build.DueAt, CommittedTo: build.CommittedTo, UpgradeTo: build.UpgradeTo,
			})
		}
		return out, nil
	})
}

// PlanUpgradeBody is a promise to move a component in the builds named.
type PlanUpgradeBody struct {
	To string `json:"to" minLength:"1" maxLength:"191" doc:"The version this moves to, as whoever packages it writes it"`
	By string `json:"by" doc:"The date the work lands, as 2026-03-31. A missed target is measured against it"`
	// Builds is which releases this is promised for. The same component
	// can be promised a different version in another release, which is the
	// ordinary case.
	Builds    []BuildName `json:"builds" minItems:"1" doc:"The releases this is promised for. A stream staying on a maintained older line takes its own promise with its own version"`
	Reasoning string      `json:"reasoning" minLength:"1" doc:"The reason this is the answer here. Required like every other judgment: what an auditor reads is the reasoning, not the outcome"`
	// Person is who carries it. A team as readily as a person: moving a
	// package is work a queue tracks rather than a judgment one person
	// makes.
	Person string `json:"person,omitempty" doc:"The party carrying it, by sign-in identity. Leave both out and it is held by nobody"`
	Team   string `json:"team,omitempty" doc:"A team carrying it, by name. A queue rather than a holding: it stays unheld until somebody takes it"`
}

// PlannedUpgradeBody is the record of one act.
type PlannedUpgradeBody struct {
	ClaimID    int64 `json:"claim_id" doc:"The one claim the whole upgrade was recorded under"`
	Decisions  int   `json:"decisions" doc:"Places answered"`
	Issues     int   `json:"issues" doc:"Distinct vulnerabilities it covers"`
	Targets    int   `json:"targets" doc:"Build-level intents recorded, which is what the pending upgrades screen reads"`
	Components int   `json:"components" doc:"The number of packages of the source it reached. Naming any binary of a source package reaches all of them, because they move together"`
	// Waiting says a second person has to agree, which happens when the date
	// is past the earliest deadline among what this covers.
	Waiting bool `json:"waiting" doc:"Whether this needs a second person. True when the date is past the earliest deadline among what it covers, because that defers the worst thing in it"`
	// Held is how many findings were handed to whoever is carrying it. A
	// different number from the decisions: assignment is product-wide and a
	// decision is per place.
	Held int `json:"held,omitempty" doc:"Findings handed to whoever is carrying this. Product-wide, like every assignment, because who moves the package on one release is who moves it on the next"`
}

// registerPlanUpgrade records moving a component as the answer to what is
// open.
//
// The act the component screen exists for. It replaces declaring a fix bundle:
// the same thing, recorded as a decision with the version and the date as its
// payload rather than as a record beside one, so what somebody decided and
// what a release is waiting on cannot come to disagree.
func registerPlanUpgrade(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "plan-upgrade", Method: http.MethodPost,
		Path:    "/v1/products/{product}/components/{component}/upgrade",
		Summary: "Record moving a component as the answer to what is open against it",
		Description: "Answers everything open against a component in the releases named, in one " +
			"act: each is recorded as `upgrade-needed`, carrying the version it moves to and " +
			"the date the work will be done.\n\n" +
			"Coverage is the component, not a version pair. Moving to 3.5.2 is a claim " +
			"that it answers what is open on the package — including findings recorded as " +
			"fixed in 3.5.0 — and the next scan says which of that was true. Deciding it " +
			"from the versions would need an ordering per ecosystem this does not have.\n\n" +
			"Whether a second person agrees depends on the date. At or before the " +
			"earliest deadline among what this covers, it stands on its own: nothing is " +
			"hidden for longer than the policy already allowed. Past it, the promise defers " +
			"the worst thing it covers and it waits for approval. The response says which.\n\n" +
			"Not bounded, unlike a bulk judgment: this one writes as many rows as the " +
			"component has open findings in the releases named.\n\n" +
			"Saying who carries it is part of the act, not a second one: name a `person` " +
			"or a `team`, and every finding the promise covers is handed to them in the same " +
			"transaction, so a promise nobody is carrying and a holder with no promise are " +
			"both impossible. A team is a perfectly good holder — moving a package is work a " +
			"queue tracks rather than a judgment one person makes — and it stays unheld until " +
			"somebody on it takes it. The handover is product-wide like every other, because " +
			"the promise is per build and who is carrying the work is not.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Component string `path:"component"`
		Body      PlanUpgradeBody
	}) (*struct{ Body PlannedUpgradeBody }, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		by, err := time.Parse("2006-01-02", strings.TrimSpace(input.Body.By))
		if err != nil {
			return nil, huma.Error422UnprocessableEntity(
				"say when this will be done, as a date like 2026-03-31")
		}
		product, err := productNamedVisibly(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		builds := make([]int64, 0, len(input.Body.Builds))
		for _, at := range input.Body.Builds {
			located, err := locatedVisibly(ctx, in, subject, input.Product, at.Stream, at.Variant)
			if err != nil {
				return nil, err
			}
			target, err := targetRow(ctx, in, located.StreamID, located.VariantID)
			if err != nil {
				return nil, err
			}
			builds = append(builds, target.ID)
		}

		holder, err := carrying(ctx, in, subject, product.ID, builds, input.Component,
			input.Body.Person, input.Body.Team)
		if err != nil {
			return nil, err
		}

		// No limit read, because this one is not bounded. The setting bounds
		// a bulk judgment, which nothing re-checks; the next scan re-checks
		// every row a promise names.
		done, err := store.PlanUpgrade(ctx, subject, triage.Upgrade{
			ProductID: product.ID, Component: input.Component,
			To: input.Body.To, By: by, Builds: builds, Reasoning: input.Body.Reasoning,
			HoldBy: holder,
		})
		if err != nil {
			return nil, refusedDecision(in.Logger, err)
		}
		return &struct{ Body PlannedUpgradeBody }{Body: PlannedUpgradeBody{
			ClaimID: done.ClaimID, Decisions: done.Decisions,
			Issues: done.Issues, Targets: done.Targets, Components: done.Components,
			Waiting: done.Waiting, Held: done.Held,
		}}, nil
	})
}

// carrying is the party an upgrade is handed to, or none where nobody was
// named.
//
// The same checks the per-finding assignment makes, asked once about the whole
// set: a handover carries visibility of what was handed over, so the check is
// against the strictest thing the promise covers rather than whichever row
// somebody was looking at — one embargoed finding among fifty is enough to
// make the handover the disclosure. And somebody has to be able to read a
// team's queue, or it sits where none of them can see it.
func carrying(ctx context.Context, in Ingest, subject access.Subject, productID int64,
	targets []int64, component, person, team string) (*int64, error) {

	if person == "" && team == "" {
		return nil, nil
	}
	if err := mayHandOver(subject, productID, person, team); err != nil {
		return nil, err
	}
	strictest, err := finding.NewStore(in.DB.DB).StrictestOnComponent(ctx, subject,
		productID, targets, component)
	if err != nil {
		return nil, refusedFinding(in, err)
	}
	rights := access.NewStore(in.DB.DB)
	if person != "" {
		who, err := rights.ByIdentity(ctx, person)
		if err != nil {
			return nil, noSuchPerson()
		}
		if strictest == access.Private {
			reads, err := rights.PersonReads(ctx, who.ID, productID, strictest)
			if err != nil {
				return nil, wentWrong(in.Logger, "cannot tell whether they may see this", err)
			}
			if !reads {
				return nil, huma.Error422UnprocessableEntity(
					"some of what this covers has not been disclosed and they may not read " +
						"undisclosed work here, so handing it to them would be the disclosure")
			}
		}
		party := who.PartyID
		return &party, nil
	}
	found, err := rights.TeamByName(ctx, team)
	if err != nil {
		return nil, noSuchTeamNamed(team)
	}
	reads, err := teamMayHold(ctx, rights, found.ID, productID, strictest)
	if err != nil {
		return nil, wentWrong(in.Logger, "cannot tell whether that team may see this", err)
	}
	if !reads {
		return nil, huma.Error422UnprocessableEntity(
			"nobody on " + found.Called() + " may read this, so it would sit in a queue " +
				"none of them can see")
	}
	party := found.PartyID
	return &party, nil
}

// mayHandOver refuses a party nobody may be given work as, and a hand-off the
// subject may not make.
//
// One helper because the rule is one rule. Two routes stating it answer the
// same request differently: they drift over which status a refused hand-off
// is, so the two paths to the same act contradict each other about what
// happened.
//
// Putting work into a team's queue is dispatching; taking it out again is not,
// and that asymmetry is the whole of a team queue rather than a holding.
// Matched without regard to capitals, because an identity is stored folded:
// somebody typing their own name with the capitals they use is told they need
// the right to give work away, to themselves.
//
// A 422 rather than a 404, which is this package's rule: a 404 answers a
// *name*, and this answers an act on a finding already shown to them.
func mayHandOver(subject access.Subject, productID int64, person, team string) error {
	if person != "" && team != "" {
		return huma.Error422UnprocessableEntity(
			"work is held by one party: name a person or a team, not both")
	}
	// Assigning to yourself, or to nobody, is not giving work away and needs
	// no more than the triage right the route has already asked for.
	givingAway := team != "" ||
		(person != "" && !strings.EqualFold(strings.TrimSpace(person), subject.Identity))
	if givingAway && !subject.Holds(access.Assigner, productID) {
		return huma.Error422UnprocessableEntity(
			"you may take what nobody owns and hand back your own; giving this to " +
				"somebody else needs the right that names it")
	}
	return nil
}
