// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// EmbargoedBody is one finding nobody has announced, and when that ends.
type EmbargoedBody struct {
	Vulnerability string `json:"vulnerability"`
	Summary       string `json:"summary,omitempty"`
	Component     string `json:"component"`
	Product       string `json:"product"`
	Stream        string `json:"stream"`
	Variant       string `json:"variant"`
	Severity      string `json:"severity,omitempty"`
	DiscloseAt    string `json:"disclose_at" doc:"The date the embargo ends. Reaching it discloses nothing"`
	// Passed says the date has arrived. It is a date to answer rather than a
	// trigger, so this is a row somebody has to act on rather than a record of
	// something that happened.
	Passed bool `json:"passed" doc:"Whether the date has already arrived"`
	Places int  `json:"places" doc:"The number of findings this covers"`
}

// EnteredBody is the record of a flaw entered.
type EnteredBody struct {
	// Identifier is the name it is filed under here, minted because a flaw
	// nobody has announced has no CVE to file it under.
	Identifier string `json:"identifier" doc:"The identifier this deployment filed it under, such as SONIC-2026-0001"`
	Component  string `json:"component" doc:"The component in the build that carries it"`
	Visibility string `json:"visibility" enum:"public,private" doc:"Whether it has been disclosed"`
	DueAt      string `json:"due_at,omitempty" doc:"The date it has to be answered by"`
	Builds     int    `json:"builds" doc:"The number of builds it was recorded against"`
	// Places is how many findings that made. A component can sit in more than
	// one place in a build, and a finding is a component at a place, so a
	// flaw recorded against one build can open several — which is what a
	// scanned finding of the same flaw at the same component would open.
	Places int `json:"places" doc:"The number of findings that opened. One per place the component sits in, in each build"`
}

func registerEntry(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "record-finding", Method: http.MethodPost,
		Path:    "/v1/products/{product}/findings",
		Summary: "Record a flaw in what this product ships",
		Description: "Records a vulnerability in your own product — one no scanner reported, " +
			"usually because nobody outside knows about it yet.\n\n" +
			"It starts undisclosed, which needs the private triage role on the product. " +
			"Send `disclosed` for one that is already public, which needs the ordinary " +
			"one.\n\n" +
			"It is filed under an identifier this deployment mints — the product's name, " +
			"the year and a number. A CVE assigned later becomes another name for the same " +
			"issue; nothing about the finding, the decisions or the approvals moves.\n\n" +
			"`component` names what in the build carries it, as the build calls it. Leave it " +
			"out for the build itself, which is where a flaw in how the pieces fit together " +
			"goes. A name the build holds at more than one version is refused with the " +
			"choices rather than resolved to one; send `version`, and `ecosystem` where two " +
			"share a version.\n\n" +
			"`from_report` records the flaw from a vulnerability report already in this " +
			"product and accepts the report as it in the same act; it needs private-triage. " +
			"A report already judged, or under a ruling, is refused with 409.\n\n" +
			"From here it behaves like any other finding: triaged, assigned, decided, on the " +
			"same clock and in the same reports. No scan will close it, so it is closed " +
			"by a person through the resolve endpoint or it stays open.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusCreated,
	}, perProduct, "public-triage where the finding is disclosed, private-triage where it is not.", triageRights()...), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Body    struct {
			// Builds is which builds ship it, rather than one in
			// the path. The same code goes out on several lines
			// and as several variants at once, and the identifier
			// is minted per product — so the product is the level
			// this is recorded at and the builds are what it
			// names.
			Builds []struct {
				Stream  string `json:"stream" minLength:"1" doc:"A branch or a tag"`
				Variant string `json:"variant" minLength:"1" doc:"The way that line is built"`
			} `json:"builds" minItems:"1" maxItems:"200" doc:"Every build that ships it. One issue, and one finding for each place the component sits at in each build — which is the shape a scanner's findings already take"`
			Summary  string `json:"summary" minLength:"1" doc:"The flaw, in your own words"`
			Severity string `json:"severity,omitempty" enum:"critical,high,medium,low,negligible,none" doc:"The severity. May be left out during early triage, before anybody has worked that out — an unrated finding is carried and listed, and what it does not get is a deadline. Worked out from the vector where one is given"`
			// The vector rather than a score. The number is derived from it
			// here, so the two cannot say different things.
			Vector     string   `json:"vector,omitempty" doc:"A CVSS 3.0 or 3.1 base vector. The score and the severity are worked out from it, so a score is never taken alongside it. Anything else is refused rather than scored with the wrong formula"`
			Weaknesses []string `json:"weaknesses,omitempty" doc:"The kind of flaw, by the classification the world uses, such as CWE-125. Recorded as given, and the first is the root cause — a published advisory states one weakness, and this is what says which"`
			Component  string   `json:"component,omitempty" doc:"The component that carries it. Omit for the build itself"`
			Version    string   `json:"version,omitempty" doc:"The version, where the build holds that name at several"`
			Ecosystem  string   `json:"ecosystem,omitempty" doc:"The ecosystem, where two share a name and a version"`
			Disclosed  bool     `json:"disclosed,omitempty" doc:"Whether this is already public. Undisclosed by default"`
			// ReportedBy is who told us, where somebody did. Every
			// field is optional: a flaw found by whoever is typing
			// has no reporter, and a form demanding one asks them
			// to invent an answer.
			ReportedBy string `json:"reported_by,omitempty" maxLength:"191" doc:"The finder, as they gave their name"`
			Contact    string `json:"contact,omitempty" maxLength:"191" doc:"The address to reach them at. A researcher has no account here, which is the shape of the thing"`
			Credit     string `json:"credit,omitempty" maxLength:"191" doc:"The credit they asked for in an advisory, where that is not the name they reported under. \"anonymous\" is a real answer"`
			Received   string `json:"received,omitempty" format:"date" doc:"The day it arrived. The embargo is counted from this rather than from when it was typed in — the reporter is counting from the day they sent it, and they are the party who will publish regardless"`
			FromReport string `json:"from_report,omitempty" maxLength:"593" doc:"A vulnerability report in this product that this flaw is the record of, by its reference. It is accepted as this flaw in the same act, and who reported it and when come from the report, so the four fields above are refused beside it"`
		}
	}) (*struct {
		Status int
		Body   EnteredBody
	}, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		names := catalog.NewStore(in.DB.DB)
		targets := make([]int64, 0, len(input.Body.Builds))
		for _, build := range input.Body.Builds {
			at, err := names.LocateVisible(ctx, subject, input.Product, build.Stream, build.Variant)
			if err != nil {
				return nil, undeclared(in.Logger, err, "that build could not be looked up")
			}
			target, err := targetRow(ctx, in, at.StreamID, at.VariantID)
			if err != nil {
				return nil, err
			}
			targets = append(targets, target.ID)
		}

		rows, identifier, err := finding.NewStore(in.DB.DB).Enter(ctx, subject, finding.Entering{
			TargetIDs: targets, Component: input.Body.Component,
			Version: input.Body.Version, Ecosystem: input.Body.Ecosystem,
			Summary: input.Body.Summary, Severity: input.Body.Severity,
			Vector: input.Body.Vector, Weaknesses: input.Body.Weaknesses,
			Disclosed: input.Body.Disclosed,
			Told: finding.Told{
				ReportedBy: input.Body.ReportedBy, Contact: input.Body.Contact,
				Credit: input.Body.Credit, Received: input.Body.Received,
			},
			FromReport: input.Body.FromReport,
		})
		if err != nil {
			// Each of these is the caller's to fix, and says which. Falling
			// through to the generic refusal would answer a name the build
			// holds twice, and a summary of nothing but spaces, with a 500
			// that says the request went wrong at our end.
			var several *graph.Ambiguous
			switch {
			case errors.As(err, &several):
				return nil, severalComponents(several, "version, and ecosystem where two share one")
			case errors.Is(err, finding.ErrNoSuchComponent):
				return nil, huma.Error404NotFound(finding.ErrNoSuchComponent.Error())
			case errors.Is(err, finding.ErrNothingSaid):
				return nil, asked(in.Logger, err)
			case errors.Is(err, finding.ErrNotAVector):
				return nil, asked(in.Logger, err)
			case errors.Is(err, finding.ErrNothingScanned):
				return nil, huma.Error404NotFound(finding.ErrNothingScanned.Error())
			case errors.Is(err, finding.ErrNoBuild), errors.Is(err, finding.ErrSeveralProducts):
				return nil, asked(in.Logger, err)
			case errors.Is(err, finding.ErrTooManyPlaces):
				// The caller's to narrow, and the sentence says by how much.
				return nil, asked(in.Logger, err)
			case errors.Is(err, finding.ErrToldTwice):
				return nil, asked(in.Logger, err)
			case errors.Is(err, finding.ErrNoSuchReport):
				return nil, huma.Error404NotFound(finding.ErrNoSuchReport.Error())
			case errors.Is(err, finding.ErrAlreadyJudged):
				return nil, huma.Error409Conflict(finding.ErrAlreadyJudged.Error())
			}
			return nil, refusedFinding(in, err)
		}

		component, err := finding.NewStore(in.DB.DB).ComponentName(ctx, rows[0].ComponentID)
		if err != nil {
			return nil, wentWrong(in.Logger, "what carries it could not be read", err)
		}
		out := &struct {
			Status int
			Body   EnteredBody
		}{Status: http.StatusCreated}
		// Builds and places are different numbers: one flaw at a component
		// that two things pull in is two findings in one build.
		builds := map[int64]bool{}
		for _, row := range rows {
			builds[row.TargetID] = true
		}
		out.Body = EnteredBody{
			Identifier: identifier, Component: component,
			Visibility: string(rows[0].Visibility),
			Builds:     len(builds), Places: len(rows),
		}
		// Every row got the same one, because they are the same flaw.
		if rows[0].DueAt != nil {
			out.Body.DueAt = stamp(*rows[0].DueAt)
		}
		return out, nil
	})
}

// ResolvedBody is the record of a flaw marked fixed.
type ResolvedBody struct {
	Closed int    `json:"closed" doc:"The number of locations of the issue in this build that closed"`
	At     string `json:"at" doc:"The moment it closed"`
}

func registerResolution(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "resolve-finding", Method: http.MethodPost,
		Path: "/v1/products/{product}/streams/{stream}/variants/{variant}" +
			"/findings/{vulnerability}/resolve",
		Summary: "Close a recorded flaw as fixed in this build",
		Description: "Closes a flaw somebody recorded here, in one build, because it has been " +
			"fixed there. Every location of the issue in that build is closed together.\n\n" +
			"Only a flaw somebody recorded. Everywhere else, resolution is computed from " +
			"scans rather than declared, which is what stops a fix being reported that shipped " +
			"in nobody's release. A flaw recorded by hand is the one case with no such " +
			"evidence and no prospect of any — no scan reports it — so a person closes it or " +
			"nothing does. An issue a scanner found is refused.\n\n" +
			"A reason is required. A closure with no reason is a record saying somebody " +
			"closed it and nothing else.\n\n" +
			"Nothing reopens one. Closing is a considered act, and this is the way it is " +
			"undone: it is not.",
		Tags: []string{"Findings"},
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Stream        string `path:"stream"`
		Variant       string `path:"variant"`
		Vulnerability string `path:"vulnerability"`
		Body          struct {
			Because string `json:"because" minLength:"1" doc:"The fix"`
		}
	}) (*struct{ Body ResolvedBody }, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		named, err := locatedVisibly(ctx, in, subject, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		target, err := targetRow(ctx, in, named.StreamID, named.VariantID)
		if err != nil {
			return nil, err
		}
		issueID, err := issueHere(ctx, in, subject, named.ProductID, input.Vulnerability)
		if err != nil {
			return nil, err
		}

		done, err := finding.NewStore(in.DB.DB).Resolve(ctx, subject,
			target.ID, issueID, input.Body.Because)
		if err != nil {
			switch {
			case errors.Is(err, finding.ErrNotOursToClose):
				return nil, asked(in.Logger, err)
			case errors.Is(err, finding.ErrNoReason):
				return nil, asked(in.Logger, err)
			case errors.Is(err, finding.ErrNothingOpenThere):
				return nil, noSuchFinding()
			case errors.Is(err, access.ErrDenied):
				return nil, noSuchFinding()
			}
			return nil, wentWrong(in.Logger, "that could not be closed", err)
		}
		return &struct{ Body ResolvedBody }{Body: ResolvedBody{
			Closed: done.Closed, At: stamp(done.At),
		}}, nil
	})
}

func registerDisclosure(api huma.API, in Ingest) {
	huma.Register(api, answering(huma.Operation{
		OperationID: "list-approaching-disclosure", Method: http.MethodGet,
		Path:    "/v1/disclosing",
		Summary: "List what is approaching disclosure",
		Description: "Returns findings nobody has announced whose embargo is running out, " +
			"soonest first, and the ones whose date has already arrived.\n\n" +
			"Before the date, not on it. The date arriving is the last moment to act on " +
			"something rather than the first useful warning, and a list that only ever showed " +
			"what was already past would be a list of decisions somebody has already failed to " +
			"make.\n\n" +
			"Nothing here discloses anything. Reaching the date escalates: the row appears " +
			"and the people who can act on it are told. Publishing embargoed detail because a " +
			"timer expired is the wrong default — if the fix is not ready, disclosing anyway is " +
			"a decision a person makes.\n\n" +
			"Every row is undisclosed by definition, so this list is a disclosure in its own " +
			"right: a product you may not read undisclosed work in contributes nothing to it, " +
			"not even a count.\n\n" +
			"`within` is how many days ahead to look. Left off, it is this deployment's own " +
			"embargo length — the screen opened on thirty days against a ninety-day policy " +
			"and drew nothing while five embargoes were running.",
		Tags: []string{"Findings"},
	}, perProduct, "A product you may not read undisclosed work in contributes "+
		"nothing, not even a count.", privateRights()...), func(ctx context.Context, input *struct {
		ScopeQuery
		Within int `query:"within" minimum:"1" maximum:"365" doc:"The number of days ahead to look. Left off, this deployment's own embargo length"`
		Limit  int `query:"limit" default:"100" minimum:"1" maximum:"500"`
		Offset int `query:"offset" minimum:"0" doc:"The offset into the list"`
	}) (*listOutput[EmbargoedBody], error) {
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

		// The distance ahead to look, where the caller has not said: the length
		// this deployment gives an embargo. A fixed thirty days against the
		// ninety-day policy that ships draws an empty screen while embargoes
		// are running, which reads as "nothing is coming".
		within := time.Duration(input.Within) * 24 * time.Hour
		if input.Within == 0 {
			within, err = setting.NewStore(in.DB.DB).Duration(ctx, setting.DiscloseAfter,
				setting.DefaultDiscloseAfter)
			if err != nil {
				return nil, wentWrong(in.Logger, "the embargo length could not be read", err)
			}
		}

		store := finding.NewStore(in.DB.DB)
		rows, total, err := store.DisclosingPage(ctx, subject, scope,
			within, input.Limit, input.Offset)
		if err != nil {
			return nil, wentWrong(in.Logger, "what is approaching disclosure could not be read", err)
		}

		now := time.Now().UTC()
		out := &listOutput[EmbargoedBody]{}
		// The total, so a caller holding a full page can tell
		// a clipped page from the whole list.
		out.Body.Total = total
		out.Body.Items = make([]EmbargoedBody, 0, len(rows))
		for _, row := range rows {
			out.Body.Items = append(out.Body.Items, EmbargoedBody{
				Vulnerability: row.Vulnerability, Summary: row.Summary,
				Component: row.Component, Product: row.Product,
				Stream: row.Stream, Variant: row.Variant, Severity: row.Severity,
				DiscloseAt: stamp(row.DiscloseAt), Passed: row.Passed(now),
				Places: row.Places,
			})
		}
		return out, nil
	})
}

// MovementBody is one time somebody moved the end of an embargo.
type MovementBody struct {
	ID            int64  `json:"id"`
	Act           string `json:"act" enum:"extension,shortening" doc:"Which act this was. An extension ends the embargo later, a shortening ends it sooner"`
	Was           string `json:"was" doc:"The embargo's previous end"`
	Until         string `json:"until" doc:"The end that was asked for"`
	Reason        string `json:"reason"`
	AskedBy       string `json:"asked_by"`
	AskedAt       string `json:"asked_at"`
	NeedsApproval bool   `json:"needs_approval" doc:"Whether a second person had to agree"`
	ApprovedBy    string `json:"approved_by,omitempty"`
	ApprovedAt    string `json:"approved_at,omitempty"`
	// InForce says the date follows this one. A movement waiting for
	// agreement has moved nothing.
	InForce bool `json:"in_force"`
}

// PendingMovementBody is one request to move a date that is waiting for a
// second person, with the issue it is about.
type PendingMovementBody struct {
	ID            int64  `json:"id"`
	Product       string `json:"product"`
	Vulnerability string `json:"vulnerability"`
	Act           string `json:"act" enum:"extension,shortening" doc:"Which act is being asked for"`
	Was           string `json:"was" doc:"The embargo's end now"`
	Until         string `json:"until" doc:"The end being asked for"`
	Days          int    `json:"days" doc:"How far the date moves, in days, whichever way it moves"`
	By            string `json:"by" doc:"The person who asked"`
	AskedAt       string `json:"asked_at"`
	Reason        string `json:"reason"`
	// Mine says you asked for this one, so you may not agree to it.
	Mine bool `json:"mine,omitempty" doc:"You asked for this, so you may not be the second person"`
}

func registerMovements(api huma.API, in Ingest) {
	const path = "/v1/products/{product}/issues/{vulnerability}/disclosure"

	// One handler for both acts. What differs between them is the act
	// recorded, the direction the date has to move and the words on the
	// operation; the authorization, the reason and the threshold are one rule
	// and a second copy of them is a second rule that drifts. Each act is
	// registered on its own line all the same, because the check that no two
	// operations claim one method and path counts registrations in this
	// source.
	type movingInput = struct {
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability"`
		Body          struct {
			Until  string `json:"until" doc:"The date the embargo should end"`
			Reason string `json:"reason" minLength:"1" maxLength:"65536" doc:"The reason the date is moving"`
		}
	}
	type movingOutput = struct {
		Status int
		Body   MovementBody
	}
	moving := func(act finding.Act) func(context.Context, *movingInput) (*movingOutput, error) {
		return func(ctx context.Context, input *movingInput) (*movingOutput, error) {
			subject, store, product, issue, err := embargoAt(ctx, in, input.Product, input.Vulnerability)
			if err != nil {
				return nil, err
			}
			until, err := time.Parse(time.DateOnly, input.Body.Until)
			if err != nil {
				return nil, huma.Error422UnprocessableEntity(
					"until has to be a date, as 2026-12-31")
			}

			move := store.Extend
			if act == finding.Shortening {
				move = store.BringForward
			}
			asked, err := move(ctx, subject, product, issue, until, input.Body.Reason)
			if err != nil {
				if errors.Is(err, finding.ErrNotEmbargoed) {
					return nil, noSuchFinding()
				}
				return nil, refusedFinding(in, err)
			}
			body, err := movementBody(ctx, in, []finding.Movement{*asked})
			if err != nil {
				return nil, wentWrong(in.Logger, "the movement could not be read back", err)
			}
			return &movingOutput{Status: http.StatusCreated, Body: body[0]}, nil
		}
	}
	gated := func(operation huma.Operation) huma.Operation {
		return requiring(operation, perProduct, "A second person agrees past the threshold.",
			[]access.Role{access.PrivateTriage}...)
	}

	huma.Register(api, gated(huma.Operation{
		OperationID: "extend-disclosure", Method: http.MethodPost, Path: path + "/extension",
		Summary: "Extend a disclosure date",
		Description: "Moves the end of an embargo later, across every undisclosed finding of " +
			"this issue in this product.\n\n" +
			"A reason is required, always, however short the extension. One with no reason " +
			"is a record saying somebody moved it and nothing else.\n\n" +
			"Past a threshold it needs a second person, and the threshold is measured " +
			"against how far this embargo's end has already been carried rather than against " +
			"this request alone — measured per request, the exception swallows the rule three " +
			"weeks at a time. It is the same act a deferral is, and the same shape.\n\n" +
			"An extension that needs agreement moves nothing until it has it. The request " +
			"is on record either way; `in_force` says whether the date follows it.\n\n" +
			"A date sent earlier is refused here. Ending an embargo sooner is a different " +
			"act, recorded as one: `POST .../disclosure/shortening`.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusCreated,
	}), moving(finding.Extension))

	huma.Register(api, gated(huma.Operation{
		OperationID: "shorten-disclosure", Method: http.MethodPost, Path: path + "/shortening",
		Summary: "Bring a disclosure date forward",
		Description: "Moves the end of an embargo sooner, across every undisclosed finding of " +
			"this issue in this product. What a coordinator or a peer vendor publishing on a " +
			"date of their own asks for, and what a leak leaves.\n\n" +
			"Its own act rather than an extension sent a smaller date. Shortening an embargo " +
			"because it leaked and extending one because a fix slipped are different events, " +
			"and which of them happened is read off the record rather than inferred from the " +
			"direction a date moved.\n\n" +
			"A reason is required, and the same threshold applies: how far this embargo's end " +
			"has already been carried, counting a date brought forward the same distance as " +
			"one pushed back. Past it a second person agrees, and until they do the date " +
			"does not move.\n\n" +
			"A date sent later is refused here. Extend with `POST .../disclosure/extension`.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusCreated,
	}), moving(finding.Shortening))

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-disclosure-movements", Method: http.MethodGet, Path: path,
		Summary: "List how an embargo has been moved",
		Description: "Every time this embargo was moved, oldest first, with which act it " +
			"was, why, and by whom.\n\n" +
			"Kept in full and never overwritten. One movement is a judgment and six is a " +
			"policy nobody wrote down, and the difference is invisible if each replaces the " +
			"last. A request still waiting for agreement is here too: what was asked for is " +
			"part of how long this stayed hidden, whether or not it was granted.",
		Tags: []string{"Findings"},
	}, perProduct, "Only where you may read undisclosed work.", privateRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability"`
	}) (*listOutput[MovementBody], error) {
		subject, store, product, issue, err := embargoAt(ctx, in, input.Product, input.Vulnerability)
		if err != nil {
			return nil, err
		}
		rows, err := store.Movements(ctx, subject, product, issue)
		if err != nil {
			return nil, refusedFinding(in, err)
		}
		items, err := movementBody(ctx, in, rows)
		if err != nil {
			return nil, wentWrong(in.Logger, "the movements could not be read", err)
		}
		out := &listOutput[MovementBody]{}
		out.Body.Items = items
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-pending-disclosure-movements", Method: http.MethodGet,
		Path:    "/v1/disclosure-movements",
		Summary: "List disclosure-date movements waiting for a second person",
		Description: "Every request to move a disclosure date that nobody has agreed to yet, " +
			"across the products you may read undisclosed work in, newest first. Both acts " +
			"are here, and `act` says which each one is.\n\n" +
			"Without this there is nowhere to be that second person. A request could be " +
			"read on the finding it belongs to and nowhere else, so the only way to find one " +
			"was to already know it existed — which is the failure the review queue exists to " +
			"prevent, in the one place where what is being agreed to is how long something " +
			"stays hidden.\n\n" +
			"Your own requests are here too, marked as yours. You cannot agree to one — " +
			"the endpoint refuses it — but a proposer looking for what is holding a case up " +
			"should not have their own request hidden from them.\n\n" +
			"Agree with `POST /v1/disclosure-movements/{id}/approval`.",
		Tags: []string{"Findings"},
	}, anyPerson, "Only where you may read undisclosed work."), func(ctx context.Context, input *struct {
		Limit  int `query:"limit" default:"50" minimum:"1" maximum:"200"`
		Offset int `query:"offset" minimum:"0" doc:"The offset into the list"`
	}) (*listOutput[PendingMovementBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		rows, total, err := finding.NewStore(in.DB.DB).PendingPage(ctx, subject,
			input.Limit, input.Offset)
		if err != nil {
			return nil, wentWrong(in.Logger, "what is waiting could not be read", err)
		}
		out := &listOutput[PendingMovementBody]{}
		// The number waiting in all: without it a screen prints the length of
		// its own page as the number.
		out.Body.Total = total
		out.Body.Items = make([]PendingMovementBody, 0, len(rows))
		for _, row := range rows {
			out.Body.Items = append(out.Body.Items, PendingMovementBody{
				ID:      row.ID,
				Product: row.Product, Vulnerability: row.Vulnerability,
				Act: string(row.Act),
				Was: row.Was.Format(time.DateOnly), Until: row.Until.Format(time.DateOnly),
				By:      row.AskedByName,
				AskedAt: row.AskedAt.Format(time.RFC3339),
				Reason:  row.Reason,
				// Said rather than left to be worked out: the person who asked
				// may not be the one who agrees, and a row somebody cannot act
				// on has to say why before they press it.
				Mine: row.AskedBy == subject.ID,
				// How far, whichever way. The act says which way.
				Days: int(row.Distance().Hours() / 24),
			})
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "agree-to-disclosure-movement", Method: http.MethodPost,
		Path:    "/v1/disclosure-movements/{id}/approval",
		Summary: "Approve a disclosure-date movement",
		Description: "Records a second person agreeing, and moves the date. Either act.\n\n" +
			"The person who asked may not be the one who agrees. That is the control the " +
			"threshold exists to reach, and a movement somebody approved for themselves is " +
			"the same as one nobody approved.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, perProduct, "Not the person who asked for it.", []access.Role{access.PrivateTriage}...), func(ctx context.Context, input *struct {
		ID int64 `path:"id"`
	}) (*struct{}, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		err = finding.NewStore(in.DB.DB).AgreeToMovement(ctx, subject, input.ID)
		switch {
		case errors.Is(err, finding.ErrNotEmbargoed):
			return nil, noSuchFinding()
		case errors.Is(err, finding.ErrSamePerson):
			return nil, huma.Error409Conflict(
				"the person who asked to move a date may not be the one who agrees to it")
		case errors.Is(err, finding.ErrAlreadyAgreed):
			// The same shape as the self-approval case beside it: somebody
			// else got there first, which is a conflict rather than a fault.
			return nil, huma.Error409Conflict(err.Error())
		case err != nil:
			return nil, refusedFinding(in, err)
		}
		return &struct{}{}, nil
	})
}

// embargoAt resolves a product and an issue for the disclosure endpoints.
func embargoAt(ctx context.Context, in Ingest, productName, issueName string) (
	access.Subject, *finding.Store, int64, int64, error) {

	subject, err := reading(ctx)
	if err != nil {
		return subject, nil, 0, 0, err
	}
	if in.DB == nil {
		return subject, nil, 0, 0,
			noDatabase(in.Logger)
	}
	product, err := productNamedVisibly(ctx, in, subject, productName)
	if err != nil {
		return subject, nil, 0, 0, err
	}
	issue, err := issueHere(ctx, in, subject, product.ID, issueName)
	if err != nil {
		return subject, nil, 0, 0, err
	}
	return subject, finding.NewStore(in.DB.DB), product.ID, issue, nil
}

// movementBody names the people a movement record refers to by identifier.
func movementBody(ctx context.Context, in Ingest, rows []finding.Movement) ([]MovementBody, error) {
	people := make([]int64, 0, len(rows)*2)
	for _, row := range rows {
		people = append(people, row.AskedBy)
		if row.ApprovedBy != nil {
			people = append(people, *row.ApprovedBy)
		}
	}
	names, err := access.NewStore(in.DB.DB).Names(ctx, people)
	if err != nil {
		return nil, err
	}
	out := make([]MovementBody, 0, len(rows))
	for _, row := range rows {
		body := MovementBody{
			ID: row.ID, Act: string(row.Act), Was: stamp(row.Was), Until: stamp(row.Until),
			Reason: row.Reason, AskedBy: names[row.AskedBy],
			AskedAt: stamp(row.AskedAt), NeedsApproval: row.NeedsApproval,
			InForce: row.InForce(),
		}
		if row.ApprovedBy != nil {
			body.ApprovedBy = names[*row.ApprovedBy]
		}
		if row.ApprovedAt != nil {
			body.ApprovedAt = stamp(*row.ApprovedAt)
		}
		out = append(out, body)
	}
	return out, nil
}

// AffectsBody is the record of setting the builds.
type AffectsBody struct {
	Added  int `json:"added" doc:"Builds it is now filed against that it was not"`
	Closed int `json:"closed" doc:"Builds taken back out, closed as invalid because they were never affected"`
}

func registerAffects(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "set-affected-builds", Method: http.MethodPut,
		Path:    "/v1/products/{product}/issues/{vulnerability}/builds",
		Summary: "Set which builds a recorded flaw affects",
		Description: "Makes the builds this flaw is filed against exactly the ones " +
			"named.\n\n" +
			"Widening opens findings; narrowing closes them as `invalid` — never " +
			"affected rather than no longer affected, so they count as no fix and appear in " +
			"no release note. The record stays, with the reason.\n\n" +
			"A reason is required whenever anything is taken out.\n\n" +
			"Only a flaw recorded here. Which builds hold an issue a scanner reported is " +
			"what the scans found, and this would overwrite it.\n\n" +
			"`invalid` never means the finding exists but does not apply. That is a triage " +
			"decision of `not-applicable` with the justification that fits.",
		Tags: []string{"Findings"},
	}, perProduct, "public-triage where the finding is disclosed, private-triage where it is not.",
		triageRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability" doc:"The identifier it was filed under"`
		Body          struct {
			Builds []struct {
				Stream  string `json:"stream" minLength:"1"`
				Variant string `json:"variant" minLength:"1"`
			} `json:"builds" minItems:"1" maxItems:"200" doc:"Every build it affects, as the whole answer rather than a change to it. Bounded, because this is a complete list and every build absent from it is closed as never affected — so a caller that sent what it happened to have in hand would close the rest. Where an issue is open at more builds than this, the builds are answered one at a time from each build's own finding"`
			Reason string `json:"reason,omitempty" doc:"The reason any build is being taken out. Required whenever one is"`
		}
	}) (*struct{ Body AffectsBody }, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		// The rule for a route about one named issue, which is what this is —
		// and it is the rule the build lookup below applies. Gated on the
		// narrower one, a single request gives both answers about the same
		// subject and the same product: refused here as though the product did
		// not exist, and admitted four lines later.
		product, err := productForIssue(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		// The resolver everything else uses, so an issue found by a CVE it was
		// later given answers the same as one found by what we filed it under.
		issue, err := issueHere(ctx, in, subject, product.ID, input.Vulnerability)
		if err != nil {
			return nil, err
		}

		targets := make([]int64, 0, len(input.Body.Builds))
		for _, build := range input.Body.Builds {
			at, err := locatedVisibly(ctx, in, subject, input.Product, build.Stream, build.Variant)
			if err != nil {
				return nil, err
			}
			target, err := targetRow(ctx, in, at.StreamID, at.VariantID)
			if err != nil {
				return nil, err
			}
			targets = append(targets, target.ID)
		}

		changed, err := finding.NewStore(in.DB.DB).Affects(ctx, subject,
			product.ID, issue, targets, input.Body.Reason)
		if err != nil {
			var several *graph.Ambiguous
			switch {
			case errors.As(err, &several):
				return nil, severalComponents(several, "version, and ecosystem where two share one")
			case errors.Is(err, finding.ErrNotOursToSay),
				errors.Is(err, finding.ErrNoReason),
				errors.Is(err, finding.ErrTooManyPlaces),
				errors.Is(err, finding.ErrNoBuild),
				errors.Is(err, finding.ErrSeveralProducts):
				return nil, asked(in.Logger, err)
			case errors.Is(err, finding.ErrNoSuchComponent):
				return nil, huma.Error404NotFound(finding.ErrNoSuchComponent.Error())
			case errors.Is(err, finding.ErrNothingOpenThere):
				return nil, huma.Error404NotFound(finding.ErrNothingOpenThere.Error())
			}
			return nil, refusedFinding(in, err)
		}
		return &struct{ Body AffectsBody }{
			Body: AffectsBody{Added: changed.Added, Closed: changed.Closed},
		}, nil
	})
}
