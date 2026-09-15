package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// UnassignedBody is one finding nobody is dealing with.
type UnassignedBody struct {
	Vulnerability string `json:"vulnerability"`
	Severity      string `json:"severity,omitempty"`
	Exploited     bool   `json:"exploited,omitempty"`
	Component     string `json:"component"`
	Version       string `json:"version"`
	Product       string `json:"product"`
	// Stream and Variant name a build holding this, not the only one: a screen
	// needs somewhere to link to and an action needs a finding to name. What
	// says there are several is `builds`.
	Stream  string `json:"stream" doc:"A branch or tag holding it. Where builds is more than one, any of them"`
	Variant string `json:"variant" doc:"A build variant holding it. Where builds is more than one, any of them"`
	Places  int    `json:"places" doc:"How many findings a judgment here would be recorded against, across every build it is in"`
	Builds  int    `json:"builds" doc:"How many builds hold it. More than one means the same code built more than one way, which one judgment answers"`
}

// HoldingBody is how much work one person has.
type HoldingBody struct {
	Person string `json:"person" doc:"Whoever holds it, by the name they are shown under. A person or a team"`
	// Team says this is a queue rather than a holding: work routed to a
	// team is unheld until somebody takes it.
	Team bool `json:"team,omitempty" doc:"This is a team's queue rather than one person's work"`
	// Open counts pieces of work — an issue in a component in a product — and
	// not the findings they cover, so this agrees with the list behind it.
	Open    int `json:"open" doc:"Pieces of work assigned to them: an issue in a component in a product"`
	Places  int `json:"places" doc:"How many findings those cover, across every build"`
	Overdue int `json:"overdue" doc:"How many of those pieces are past their deadline"`
}

// registerAssignment registers the two halves of deciding who deals with
// something.
//
// Writing an assignment and reading who holds what share this file's helpers
// and nothing else: one is the act the assigner right names, guarded at every
// step, and the three lists are the ordinary question "what is mine" asked
// three ways.
func registerAssignment(api huma.API, in Ingest) {
	registerAssigning(api, in)
	registerAssignmentReading(api, in)
}

// Giving work out and handing it back.
//
// The two writes. Taking work nobody owns and handing back your own is
// triage; giving it to somebody else, or taking what they are holding, is the
// assigner right — and doing either to yourself is still doing it.
func registerAssigning(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "assign-finding", Method: http.MethodPut,
		Path: "/v1/products/{product}/streams/{stream}/variants/{variant}" +
			"/findings/{vulnerability}/components/{component}/assignment",
		Summary: "Assign a finding to somebody",
		Description: "Records who is dealing with this issue in this component.\n\n" +
			"**It covers the product, not the build named in the path.** The path says which " +
			"finding is being looked at; what is assigned is every build of the product " +
			"holding the same component, and every place that component sits at.\n\n" +
			"Send `person` as an empty string to hand it back to nobody, which is this same " +
			"operation rather than one of its own.\n\n" +
			"Send `team` instead to route it to a team. That is a queue rather than a " +
			"holding: it stays unheld until somebody takes it, and anybody on the team may " +
			"take it with the triage right alone. Routing to a team asks that at least one " +
			"member may read what is being routed there — not that every member may.\n\n" +
			"Findings arriving later under the same component start unassigned.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, perProduct, "Giving work to somebody else also needs assigner. Taking unowned work, "+
		"or handing back your own, does not.", triageRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Stream        string `path:"stream"`
		Variant       string `path:"variant"`
		Vulnerability string `path:"vulnerability"`
		Component     string `path:"component"`
		Body          struct {
			Person string `json:"person,omitempty" doc:"Their sign-in identity, or empty for nobody"`
			Team   string `json:"team,omitempty" doc:"A team to route it to instead, by name. A queue rather than a holding: it stays unheld until somebody takes it"`
		}
	}) (*struct{}, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		product, target, issue, component, err := locateFinding(ctx, in, subject,
			input.Product, input.Stream, input.Variant, input.Vulnerability, input.Component)
		if err != nil {
			return nil, err
		}

		// Authorized to hand work around before any name is looked up.
		// Resolving first and refusing after answers "does this person have an
		// account here" for anybody who can merely read the product, which is
		// a directory of the organization for the price of one request.
		if !subject.Triages(access.Public, product) {
			return nil, noSuchFinding()
		}

		// Every right this needs is checked before any name is looked
		// up . The triage check above is not enough on its own: giving
		// work to somebody else asks for more, and resolving the name
		// first answers "does this person have an account here"
		// differently depending on whether they do — which is a staff
		// directory for the price of one request, to anybody who may
		// triage.
		//
		// Assigning to yourself, or to nobody, is not giving work away
		// and needs no more than the triage right already checked.
		if input.Body.Person != "" && input.Body.Team != "" {
			return nil, huma.Error422UnprocessableEntity(
				"work is held by one party: name a person or a team, not both")
		}
		// Putting work into a team's queue is dispatching. Taking it
		// out again is not, and that asymmetry is the whole of a team
		// queue rather than a holding.
		// Without regard to capitals, for the reason the component path is:
		// an identity is stored folded, so the exact comparison refused
		// somebody handing work back to themselves under their own spelling.
		givingAway := input.Body.Team != "" ||
			(input.Body.Person != "" &&
				!strings.EqualFold(strings.TrimSpace(input.Body.Person), subject.Identity))
		if givingAway && !subject.Holds(access.Assigner, product) {
			return nil, noSuchFinding()
		}

		var to *int64
		// Who to tell, which is a person. The column holds the party
		// they are assignable as, and a notification goes to somebody.
		// A team tells nobody: a queue filling up is digest content
		// rather than an interruption.
		var whoToTell int64
		rights := access.NewStore(in.DB.DB)
		switch {
		case input.Body.Person != "":
			person, err := rights.ByIdentity(ctx, input.Body.Person)
			if err != nil {
				return nil, noSuchPerson()
			}
			// An assignment carries visibility of what was
			// assigned, so what is checked is the level rather
			// than whether they can already see the row — which,
			// before the assignment, they cannot by construction.
			// Handing an embargoed finding to somebody cleared for
			// nothing embargoed would make the assignment the
			// disclosure.
			strictest, err := finding.NewStore(in.DB.DB).StrictestOf(ctx, subject,
				target, issue, component)
			if err != nil {
				return nil, refusedFinding(in, err)
			}
			if strictest == access.Private {
				reads, err := rights.PersonReads(ctx, person.ID, product, strictest)
				if err != nil {
					return nil, wentWrong(in.Logger,
						"cannot tell whether they may see this", err)
				}
				if !reads {
					return nil, huma.Error422UnprocessableEntity(
						"this has not been disclosed and they may not read undisclosed " +
							"work here, so handing it to them would be the disclosure")
				}
			}
			party := person.PartyID
			to, whoToTell = &party, person.ID
		case input.Body.Team != "":
			team, err := rights.TeamByName(ctx, input.Body.Team)
			if err != nil {
				return nil, noSuchTeamNamed(input.Body.Team)
			}
			// At least one member has to be able to read what is
			// being routed there. Asked at the strictest
			// visibility present, since reading what is
			// undisclosed implies reading what is not — so a team
			// with one member who may read an embargoed finding
			// can hold a queue of both kinds.
			strictest, err := finding.NewStore(in.DB.DB).StrictestOf(ctx, subject,
				target, issue, component)
			if err != nil {
				return nil, refusedFinding(in, err)
			}
			reads, err := rights.AnyMemberReads(ctx, team.ID, product, strictest)
			if err != nil {
				return nil, wentWrong(in.Logger, "cannot tell whether that team may see this", err)
			}
			if !reads {
				return nil, huma.Error422UnprocessableEntity(
					"nobody on " + team.Called() + " may read this, so it would sit in a " +
						"queue none of them can see")
			}
			party := team.PartyID
			to = &party
		}

		_, undisclosed, err := finding.NewStore(in.DB.DB).Assign(ctx, subject, target, issue, component, to)
		if err != nil {
			return nil, refusedFinding(in, err)
		}

		// Tell them. Work arriving is the thing a triager most wants
		// to notice , and it is the one category that deserves
		// interrupting somebody for.
		//
		// **Only if they can see what they are being told about.** A
		// notification carries the product, the branch, the variant and the
		// issue, and it is stored as written rather than derived on read — so
		// there is no visibility filter downstream that could repair it, and
		// the check belongs here. Without it, assigning an undisclosed finding
		// to somebody who holds nothing on that product hands them its name,
		// its releases and a live vulnerability against it: a product they
		// hold nothing on is meant to read as one that does not exist.
		//
		// The assignment itself is left alone. Whether work may be
		// handed to somebody who cannot yet see it is a question about
		// assignment, not about this channel, and quietly refusing it
		// here would be deciding it in the wrong place.
		//
		// Nobody is told they were unassigned: a name being removed is
		// not an action directed at the person who held it, and a
		// queue that gets shorter says so already. Telling somebody
		// something was taken away invites them to go and look at what
		// is no longer theirs.
		//
		// A failure here is logged and not returned. The assignment
		// happened; answering with an error would invite a retry that
		// assigns it again, and the notification is the lesser half of
		// the two.
		if to != nil && *to != subject.Party() &&
			seenBy(ctx, in, input.Body.Person, product, undisclosed) {
			tell(ctx, in, "could not say that work was assigned", notify.Telling{
				PersonID: whoToTell, Kind: notify.Assigned,
				Body: input.Vulnerability + " in " + input.Component +
					", in " + input.Product + " " + input.Stream + " " + input.Variant,
				Link: findingPath(input.Product, input.Stream, input.Variant,
					input.Vulnerability, input.Component),
				// What it is about, so a digest can tell later that this
				// person was told about this work and leave it out.
				Concerns: notify.Concerning(product, issue, component),
				// The body above names the product, the build
				// and the issue. Inside the application that
				// is right — reaching it is already the
				// visibility check — and outside it is the
				// announcement an embargo exists to prevent,
				// so a channel that leaves here carries the
				// link alone.
				Private: undisclosed,
				// The same two as columns. Concerns above is a
				// string a digest matches on; these are what a
				// read narrows by.
				ProductID:       &product,
				VulnerabilityID: &issue,
			}, "person", whoToTell)
		}
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "hand-back-assignments", Method: http.MethodPost,
		Path:    "/v1/people/{identity}/assignments/hand-back",
		Summary: "Hand back everything one person is dealing with",
		Description: "Returns all their open findings to the unassigned list. For when somebody " +
			"has left, or their last role is removed.\n\n" +
			"Nothing tells this software that somebody has gone — membership is read at sign-in, " +
			"and a person who has left never signs in again. So this is an action an " +
			"administrator takes rather than something that happens on its own, and until it is " +
			"taken their work is in no list at all: not in the shared one because it is assigned, " +
			"and not in anybody's own because they are not here.\n\n" +
			"Send `to` instead to hand it to a named person rather than to nobody.",
		Tags: []string{"Administration"},
	}, deploymentWide, ""), func(ctx context.Context, input *struct {
		Identity string `path:"identity"`
		Body     struct {
			To string `json:"to,omitempty" doc:"Who takes it on. Omit to return it to nobody"`
		}
	}) (*struct {
		Body struct {
			Moved int64 `json:"moved"`
		}
	}, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		// Authorized before the name is looked up. Resolving first and
		// refusing after answers "does this person have an account here" for
		// anybody signed in: a name nobody holds and a name somebody holds
		// come back differently, which is a directory of the organization
		// readable by every account.
		if !subject.Admin {
			return nil, huma.Error403Forbidden("not authorized")
		}
		rights := access.NewStore(in.DB.DB)
		from, err := rights.ByIdentity(ctx, input.Identity)
		if err != nil {
			return nil, noSuchPerson()
		}

		findings := finding.NewStore(in.DB.DB)
		var moved int64
		if input.Body.To == "" {
			moved, err = findings.Release(ctx, subject, from.PartyID)
		} else {
			var to *access.Account
			if to, err = rights.ByIdentity(ctx, input.Body.To); err != nil {
				return nil, noSuchPerson()
			} else {
				moved, err = findings.HandOver(ctx, subject, from.PartyID, to.PartyID)
			}
		}
		if err != nil {
			return nil, refusedFinding(in, err)
		}
		out := &struct {
			Body struct {
				Moved int64 `json:"moved"`
			}
		}{}
		out.Body.Moved = moved
		return out, nil
	})
}

// Reading who holds what.
//
// Three lists, each narrowed by what the reader may see: work nobody owns
// across every product they can see, one person's or team's holdings, and the
// per-holder totals the assignments screen is built on.
func registerAssignmentReading(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-unassigned", Method: http.MethodGet, Path: "/v1/unassigned",
		Summary: "List findings nobody is dealing with",
		Description: "Returns open findings with no assignee, across every product you can see, " +
			"most urgent first.\n\n" +
			"Deliberately not scoped to one product: work falling between people is exactly what " +
			"hides when every screen shows one product and nobody looks at the others.\n\n" +
			"**One item per issue in a component in a product, not one per build.** The same code " +
			"built as several variants is one piece of work — a judgment is keyed on the product " +
			"and the code rather than on the build, so answering it once answers every build " +
			"holding the same versions. `builds` says how many that is. Where two builds ship " +
			"different versions of the component they are different work and appear separately.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		ScopeQuery
		Limit  int `query:"limit" default:"50" minimum:"1" maximum:"200"`
		Offset int `query:"offset" minimum:"0"`
	}) (*struct {
		Body struct {
			Items []UnassignedBody `json:"items"`
			Total int              `json:"total"`
		}
	}, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		scope, err := scoped(ctx, in, subject, input.ScopeQuery)
		if err != nil {
			return nil, err
		}
		rows, total, err := finding.NewStore(in.DB.DB).Unassigned(ctx, subject, scope,
			input.Limit, input.Offset)
		if err != nil {
			return nil, wentWrong(in.Logger, "what nobody is dealing with could not be read", err)
		}
		out := &struct {
			Body struct {
				Items []UnassignedBody `json:"items"`
				Total int              `json:"total"`
			}
		}{}
		out.Body.Items = make([]UnassignedBody, 0, len(rows))
		for _, row := range rows {
			out.Body.Items = append(out.Body.Items, UnassignedBody{
				Vulnerability: row.Vulnerability, Severity: row.Severity, Exploited: row.Exploited,
				Component: row.Component, Version: row.Version,
				Product: row.Product, Stream: row.Stream, Variant: row.Variant,
				Places: row.Places, Builds: row.Builds,
			})
		}
		out.Body.Total = total
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-assigned", Method: http.MethodGet,
		Path:    "/v1/people/{identity}/assignments",
		Summary: "List what one person is dealing with",
		Description: "The open findings assigned to somebody, most urgent first, in the same " +
			"units as what nobody is dealing with: **one item per issue in a component in a " +
			"product**, not one per build. The same code built several ways is one piece of " +
			"work, and it was taken on as one.\n\n" +
			"Send `me` as the identity for your own.\n\n" +
			"An identity nobody holds answers with an empty list rather than a 404, which is " +
			"also what an identity somebody holds answers when none of their work is yours to " +
			"see. The two are deliberately the same.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see. An identity nobody holds answers as one whose "+
		"work you cannot see."), func(ctx context.Context, input *struct {
		Identity string `path:"identity" doc:"Their sign-in identity, or 'me' for your own"`
		ScopeQuery
		Limit  int `query:"limit" default:"50" minimum:"1" maximum:"200"`
		Offset int `query:"offset" minimum:"0"`
	}) (*struct {
		Body struct {
			Items []UnassignedBody `json:"items"`
			Total int              `json:"total"`
		}
	}, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		// Narrowed by what they hold rather than by what they read. A
		// capability held without a read role reaches no product and
		// is given content by what has been assigned, and the store
		// already answers for that — but the scope check refused
		// first, so somebody looking at the build they hold work in
		// was told the product does not exist. What keeps that check's
		// property is below: an empty answer for a product they cannot
		// see is still "no such product".
		scope, sees, err := scopedByHolding(ctx, in, subject, input.ScopeQuery)
		if err != nil {
			return nil, err
		}
		// "me" rather than making a screen know its own identity and
		// spell it into a path. It is also the only form that cannot
		// name somebody else by accident. Theirs and their teams'
		// queues, because "assigned to me" means mine or my team's
		// everywhere the phrase appears. Asked of somebody else it is
		// the same question about a different holder.
		holders := subject.Mine()
		if input.Identity != "me" {
			rights := access.NewStore(in.DB.DB)
			person, err := rights.ByIdentity(ctx, input.Identity)
			if err != nil {
				// A name nobody holds answers exactly as a
				// name somebody holds whose work this caller
				// cannot see: an empty list . Refusing instead
				// would answer "does this person have an
				// account here" for any credential at all,
				// including one holding no product — a
				// directory of the organization for the price
				// of one request. This read is narrowed by
				// what the caller may see anyway, so nothing
				// is lost by answering it for a name that
				// reaches nobody.
				holders = []int64{nobody}
			} else {
				teams, err := rights.TeamsOf(ctx, person.ID)
				if err != nil {
					return nil, wentWrong(in.Logger,
						"what they are dealing with could not be read", err)
				}
				holders = []int64{person.PartyID}
				for _, team := range teams {
					holders = append(holders, team.PartyID)
				}
			}
		}
		rows, total, err := finding.NewStore(in.DB.DB).AssignedTo(ctx, subject, holders,
			scope, input.Limit, input.Offset)
		if err != nil {
			return nil, wentWrong(in.Logger, "what they are dealing with could not be read", err)
		}
		// Nothing here, in a product they cannot read, is the answer a product
		// that was never declared gives — so it gives that answer, and asking
		// this cannot be used to find out which products exist.
		if len(rows) == 0 && input.Product != "" && !sees {
			return nil, noSuchProduct()
		}
		out := &struct {
			Body struct {
				Items []UnassignedBody `json:"items"`
				Total int              `json:"total"`
			}
		}{}
		out.Body.Items = make([]UnassignedBody, 0, len(rows))
		for _, row := range rows {
			out.Body.Items = append(out.Body.Items, UnassignedBody{
				Vulnerability: row.Vulnerability, Severity: row.Severity, Exploited: row.Exploited,
				Component: row.Component, Version: row.Version,
				Product: row.Product, Stream: row.Stream, Variant: row.Variant,
				Places: row.Places, Builds: row.Builds,
			})
		}
		out.Body.Total = total
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-holdings", Method: http.MethodGet, Path: "/v1/assignments",
		Summary: "List assignment totals",
		Description: "Returns everyone holding open work you can see, with how much.\n\n" +
			"Counted in pieces of work — an issue in a component in a product — which is the " +
			"unit the list behind each person is in. `places` says how many findings those " +
			"cover: one flaw in a kernel is one thing to answer and can be dozens of rows to " +
			"write.\n\n" +
			"The number worth watching is not how many findings exist but how many are waiting " +
			"behind somebody: an idle account holding nothing is harmless, and work stuck behind " +
			"a person who has gone is the problem — nothing tells this software that somebody " +
			"has left.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `query:"product" doc:"Limit to work held in one product, by name. Empty means every product you can see; a name you cannot see is refused rather than answered empty"`
	}) (*listOutput[HoldingBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		within, err := narrowedTo(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		held, err := finding.NewStore(in.DB.DB).HeldBy(ctx, subject, within)
		if err != nil {
			return nil, wentWrong(in.Logger, "who is holding what could not be read", err)
		}
		ids := make([]int64, 0, len(held))
		for _, h := range held {
			ids = append(ids, h.PartyID)
		}
		// Whoever holds it, which the screen does not have to know the kind of.
		who, err := access.NewStore(in.DB.DB).WhoHolds(ctx, ids)
		if err != nil {
			return nil, wentWrong(in.Logger, "who is holding what could not be read", err)
		}
		out := &listOutput[HoldingBody]{}
		out.Body.Items = make([]HoldingBody, 0, len(held))
		for _, h := range held {
			out.Body.Items = append(out.Body.Items, HoldingBody{
				Person: who[h.PartyID].Name, Team: who[h.PartyID].Team,
				Open: h.Open, Places: h.Places, Overdue: h.Overdue,
			})
		}
		return out, nil
	})
}

// locateFinding resolves the names in a path to the finding they address.
func locateFinding(ctx context.Context, in Ingest, subject access.Subject,
	product, stream, variant, vulnerability, component string) (int64, int64, int64, int64, error) {

	named, err := locatedVisibly(ctx, in, subject, product, stream, variant)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	target, err := targetRow(ctx, in, named.StreamID, named.VariantID)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	issue, err := issueHere(ctx, in, subject, named.ProductID, vulnerability)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	held, err := graph.NewStore(in.DB.DB).ComponentAt(ctx, target.ID, component)
	if errors.Is(err, graph.ErrAmbiguous) {
		// The build ships that name at more than one version, and these routes
		// carry no version to choose with. Answering "no open finding is
		// recorded there" was wrong twice over: the finding is there, and the
		// caller had just read it on a screen that resolved the same name.
		//
		// Narrowed to the versions carrying this issue first, the way the
		// finding's own route does it, because the lookup raises the ambiguity
		// before it knows which issue is being asked about — so left alone it
		// would offer every version of the name, most of which lead nowhere.
		carrying, second := finding.NewStore(in.DB.DB).VersionsWithIssue(
			ctx, subject, target.ID, issue, component)
		if second != nil {
			in.Logger.Error("which versions carry this issue could not be read",
				"component", component, "error", second)
		}
		switch {
		case len(carrying) == 1:
			// One choice is not a choice, so it is taken rather than offered.
			held, err = graph.NewStore(in.DB.DB).ComponentAs(ctx, target.ID,
				component, carrying[0].Version, carrying[0].Ecosystem)
		case len(carrying) > 1:
			return 0, 0, 0, 0, ambiguousAmong(component, carrying)
		default:
			return 0, 0, 0, 0, noSuchFinding()
		}
	}
	if err != nil {
		return 0, 0, 0, 0, noSuchFinding()
	}
	return named.ProductID, target.ID, issue, held, nil
}

// refusedFinding turns a store's refusal about a finding into an answer.
//
// Somebody who may not reach a finding is told it is not there, the same
// answer a name nobody ever used gets — otherwise the two differ and guessing
// becomes informative.
//
// Only the refusals it recognizes are reported to the caller. Anything else is
// a database that could not answer, and returning those as 422 told somebody
// their request was wrong and put a driver's error text — table names,
// statement fragments — in the response body. What is not a recognized refusal
// is logged and answered as ours.
func refusedFinding(in Ingest, err error) error {
	switch {
	case errors.Is(err, access.ErrDenied):
		return noSuchFinding()
	case errors.Is(err, finding.ErrSamePerson):
		return asked(in.Logger, err)
	}
	return wentWrong(in.Logger, "that could not be recorded", err)
}

// seenBy reports whether the person being told may read what it is about.
//
// Read as that person rather than as the caller: what the caller can see says
// nothing about what the recipient can, and it is the recipient who receives
// the text.
//
// **At the visibility of the finding, not merely of the product.** The body
// names the issue, the component and the build, and is stored as written — so
// somebody who may read what has been disclosed and no more would be handed
// the name of a finding nobody has announced, in a product they hold nothing
// undisclosed on. Seeing that a product exists is not reading its embargoed
// work.
func seenBy(ctx context.Context, in Ingest, identity string, productID int64, undisclosed bool) bool {
	them, err := access.NewStore(in.DB.DB).Resolve(ctx, identity)
	if err != nil {
		return false
	}
	if undisclosed {
		return them.Reads(access.Private, productID)
	}
	return them.Reads(access.Public, productID)
}
