package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/trail"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// AboutPersonBody is one person, whole: what they hold, what they used to
// hold, what they did to the record, and what they were told.
//
// Four questions that were answerable only by reading four screens against
// each other, and two of them could not be asked at all: what somebody was
// told while holding a role that has since been withdrawn is what an
// investigation after a leak is for, and how much of the record rests on one
// person is what the rubber-stamp report counts across a program and nothing
// answered for one person.
type AboutPersonBody struct {
	Identity    string `json:"identity"`
	DisplayName string `json:"display_name,omitempty"`
	Admin       bool   `json:"admin,omitempty" doc:"Whether they administer this deployment"`
	// Audits is the read-only half of what is held over the deployment: its
	// own records, and no product's findings or decisions.
	Audits bool `json:"audits,omitempty" doc:"Whether they may read this deployment's own records. It grants no product's findings or decisions"`
	// DeactivatedAt is when they stopped being somebody who may sign in.
	// Absent is the ordinary state. Never a deletion: they are still named
	// by every judgment they proposed and every one they agreed to.
	DeactivatedAt string `json:"deactivated_at,omitempty" doc:"When they left. Absent means they are active"`
	// Holds is what is in force now.
	Holds []HeldBody `json:"holds,omitempty"`
	// SeesNothing says every role they hold is a capability, so none of them
	// reaches a product — which reads very differently from holding none at
	// all, and differently again from holding roles that are out of force.
	SeesNothing bool `json:"sees_nothing,omitempty" doc:"Every role they hold is a capability, so they reach no product. A capability is bounded by what its holder may read, so on its own it grants nothing"`
	// Held is every grant and withdrawal against them, newest first.
	Held      []HeldChangeBody `json:"held,omitempty"`
	HeldTotal int              `json:"held_total" doc:"How many role changes there are, of which the list above is a page"`
	// Record is their part in the triage record.
	Record PersonRecordBody `json:"record"`
	// Told is what was sent to them, newest first, read and cleared
	// included: what somebody was told is a fact about what was sent.
	Told      []ToldBody `json:"told,omitempty"`
	ToldTotal int        `json:"told_total" doc:"How many things they were told that you may read, of which the list above is a page. Narrowed like the list: administering decides who may ask, not what the answer contains"`
}

// HeldChangeBody is one role granted or withdrawn.
type HeldChangeBody struct {
	At    string `json:"at"`
	By    string `json:"by" doc:"Who made the change"`
	About string `json:"about" doc:"What it was against, as the trail records it"`
	Was   string `json:"was,omitempty" doc:"What they held before. Absent means they held nothing"`
	Now   string `json:"now,omitempty" doc:"What they hold after. Absent means it was withdrawn"`
}

// PersonRecordBody is how much of the triage record rests on one person.
type PersonRecordBody struct {
	Proposed int `json:"proposed" doc:"Claims they argued"`
	Approved int `json:"approved" doc:"Claims they agreed to that still stand"`
	// Withdrawn is counted apart, because an agreement taken back is not
	// somebody who agrees.
	Withdrawn      int    `json:"withdrawn" doc:"Claims they agreed to and later took back"`
	LastProposedAt string `json:"last_proposed_at,omitempty" doc:"Absent where they never have"`
	LastApprovedAt string `json:"last_approved_at,omitempty" doc:"Absent where they never have"`
}

// ToldBody is one thing somebody was told.
type ToldBody struct {
	At      string `json:"at"`
	Kind    string `json:"kind"`
	Body    string `json:"body"`
	Link    string `json:"link,omitempty"`
	Private bool   `json:"private,omitempty" doc:"It is about a finding nobody has announced"`
	Read    bool   `json:"read,omitempty" doc:"They have acknowledged it"`
	Cleared bool   `json:"cleared,omitempty" doc:"The condition it was about stopped being true"`
}

func registerPerson(api huma.API, in Ingest, a Administering) {
	registerDeactivation(api, a)

	huma.Register(api, requiring(huma.Operation{
		OperationID: "read-person", Method: http.MethodGet, Path: "/v1/people/{identity}",
		Summary: "Read one user",
		Description: "Returns one person: the roles in force for them, every grant and " +
			"withdrawal against them, how much of the triage record they proposed and " +
			"agreed to, and what this deployment has told them.\n\n" +
			"`told` includes what they have already acknowledged and what has since " +
			"cleared, because the question it answers is what was sent rather than what " +
			"is waiting. It is not narrowed by what they may read now: a line about an " +
			"undisclosed finding, sent while they held the role that reached it, is " +
			"exactly what an investigation is looking for.\n\n" +
			"`held` and `told` are the first page of each; `held_total` and `told_total` " +
			"say how many there are.",
		Tags: []string{"Administration"},
	}, deploymentRecords, ""), func(ctx context.Context, input *struct {
		Identity string `path:"identity" maxLength:"191"`
		Limit    int    `query:"limit" default:"50" minimum:"1" maximum:"200" doc:"How many of each list to return"`
	}) (*struct{ Body AboutPersonBody }, error) {
		store, _, err := readable(ctx, a, a.handle())
		if err != nil {
			return nil, err
		}
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		person, err := store.ByIdentity(ctx, input.Identity)
		if err != nil {
			return nil, absent(a.Logger, err, "that person could not be looked up",
				noSuchPerson)
		}

		body := AboutPersonBody{
			Identity: person.Identity, DisplayName: person.DisplayName, Admin: person.IsAdmin,
			Audits:        person.Audits,
			DeactivatedAt: orAbsent(person.DeactivatedAt),
		}

		named, err := productNames(ctx, a)
		if err != nil {
			return nil, err
		}
		held, err := store.Grants(ctx, person.ID)
		if err != nil {
			return nil, wentWrong(a.Logger, "cannot read what they hold", err)
		}
		for _, grant := range held {
			body.Holds = append(body.Holds, HeldBody{
				Product: named[grant.ProductID].Address, Role: string(grant.Role),
				ProductDisplayName: named[grant.ProductID].Display,
				Effective:          grant.Active, Source: string(grant.Source),
			})
		}
		body.SeesNothing = seesNothing(body.Holds)

		changes, total, err := trail.NewStore(in.DB.DB).About(ctx, subject, trail.Role,
			person.Identity, input.Limit, 0)
		if err != nil {
			return nil, refused(a.Logger, err, "cannot read what they used to hold")
		}
		body.HeldTotal = total
		who, err := whoChanged(ctx, in, a, changes)
		if err != nil {
			return nil, err
		}
		for _, change := range changes {
			body.Held = append(body.Held, HeldChangeBody{
				At: change.At.Format(time.RFC3339), By: who[change.By],
				About: change.Name, Was: orBlank(change.Was), Now: orBlank(change.Became),
			})
		}

		// What they did to the triage record, which is counted over every
		// product without narrowing — a concentration signal computed over
		// the products the reader happens to hold is not the signal. So it is
		// an administrator's, and the page leaves the block out for an auditor
		// rather than refusing: the grant that reads this deployment's records
		// is declared to reach no product's decisions, and this is a count
		// over all of them.
		if subject.Admin {
			record, err := triage.NewStore(in.DB.DB).RecordOf(ctx, subject, person.ID)
			if err != nil {
				return nil, refused(a.Logger, err, "cannot read their part in the record")
			}
			body.Record = PersonRecordBody{
				Proposed: record.Proposed, Approved: record.Approved, Withdrawn: record.Withdrawn,
				LastProposedAt: orAbsent(record.LastProposedAt),
				LastApprovedAt: orAbsent(record.LastApprovedAt),
			}
		}

		told, toldTotal, err := notify.NewStore(in.DB.DB).ToldTo(ctx, subject, person.ID, input.Limit, 0)
		if err != nil {
			return nil, refused(a.Logger, err, "cannot read what they were told")
		}
		body.ToldTotal = toldTotal
		for _, row := range told {
			body.Told = append(body.Told, ToldBody{
				At: row.CreatedAt.Format(time.RFC3339), Kind: string(row.Kind),
				Body: row.Body, Link: row.Link, Private: row.Private,
				Read: row.ReadAt != nil, Cleared: row.ClearedAt != nil,
			})
		}
		return &struct{ Body AboutPersonBody }{Body: body}, nil
	})
}

// whoChanged names the people who made a set of changes, once each.
//
// The trail holds who by number, and a page naming numbers is a page nobody
// can read. Looked up together rather than per row, because a screen showing
// fifty changes made by two people would otherwise ask fifty times.
func whoChanged(ctx context.Context, in Ingest, a Administering, changes []trail.Change) (map[int64]string, error) {
	who := map[int64]string{}
	for _, change := range changes {
		who[change.By] = ""
	}
	if len(who) == 0 {
		return who, nil
	}
	people, _, err := access.NewStore(in.DB.DB).People(ctx)
	if err != nil {
		return nil, wentWrong(a.Logger, "cannot read who made those changes", err)
	}
	for _, person := range people {
		if _, wanted := who[person.ID]; wanted {
			who[person.ID] = person.Identity
		}
	}
	return who, nil
}

func orAbsent(at *time.Time) string {
	if at == nil {
		return ""
	}
	return at.Format(time.RFC3339)
}

// registerDeactivation is somebody leaving, and somebody coming back.
//
// REQ-45 says we cannot detect that somebody has left: a provider never tells
// us an account was disabled, and somebody who left never signs in again. So it
// is recorded here, by an administrator, and the two acts are the two verbs on
// one thing rather than two verbs on the person — a person is not created or
// destroyed by this, and naming it after the state makes that plain.
func registerDeactivation(api huma.API, a Administering) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "deactivate-person", Method: http.MethodPut,
		Path:    "/v1/people/{identity}/deactivation",
		Summary: "Deactivate a user",
		Description: "Records that somebody has left. They are refused at every way in — a " +
			"session, a personal token, a group-bound sign-in — from the next request " +
			"onward, their sessions are ended, and what they were dealing with is handed " +
			"back so it is not held by somebody who is gone.\n\n" +
			"Nobody is deleted. The record names them as the proposer of judgments and the " +
			"approver of others, and their roles are left where they are: what somebody " +
			"held is part of why the record reads as it does, and bringing them back should " +
			"not mean reconstructing it. What stops them is the date.\n\n" +
			"Deactivating somebody already deactivated succeeds and moves nothing, because " +
			"the date is when they left.\n\n" +
			"`released` says how much work was handed back.",
		Tags: []string{"Administration"},
	}, deploymentWide, ""), func(ctx context.Context, input *struct {
		Identity string `path:"identity" maxLength:"191"`
	}) (*struct {
		Body struct {
			Released int64  `json:"released" doc:"Findings handed back because they are gone"`
			Already  bool   `json:"already,omitempty" doc:"They had already left, and the date did not move"`
			Since    string `json:"since" doc:"When they left"`
		}
	}, error) {
		out := &struct {
			Body struct {
				Released int64  `json:"released" doc:"Findings handed back because they are gone"`
				Already  bool   `json:"already,omitempty" doc:"They had already left, and the date did not move"`
				Since    string `json:"since" doc:"When they left"`
			}
		}{}
		var subject access.Subject
		var person *access.Account
		if err := changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
			rights, asking, who, err := aboutPerson(ctx, a, tx, input.Identity)
			if err != nil {
				return err
			}
			subject, person = asking, who
			// Refused before anything is written. An administrator locking
			// themselves out is a deployment nobody can administer, and the
			// documented way back in is the bootstrap account — which is this
			// one often enough that the mistake is worth refusing rather than
			// recording.
			if person.ID == subject.ID {
				return huma.Error409Conflict(
					"deactivating yourself would leave nobody able to undo it")
			}

			moved, err := rights.Deactivate(ctx, person.ID)
			if err != nil {
				return wentWrong(a.Logger, "cannot record that they left", err)
			}
			out.Body.Already = !moved
			out.Body.Since, out.Body.Released = "", 0
			if !moved {
				// Read back rather than echoed: the date is when they left,
				// and a second call must report that moment rather than this
				// one. A second call finds nothing to move and writes no
				// second row.
				again, err := rights.ByIdentity(ctx, input.Identity)
				if err == nil && again.DeactivatedAt != nil {
					out.Body.Since = again.DeactivatedAt.Format(time.RFC3339)
				}
				return nil
			}
			out.Body.Since = time.Now().UTC().Format(time.RFC3339)

			if err := noted(ctx, tx, trail.Account, person.Identity,
				trail.Said("active", true), trail.Said("deactivated", true)); err != nil {
				return notRecorded(a.Logger, err)
			}

			// Ended rather than left to expire. Roles are re-read at sign-in,
			// so withdrawing one takes effect then; this is what makes leaving
			// immediate instead.
			if err := rights.EndSessionsFor(ctx, person.ID); err != nil {
				return wentWrong(a.Logger, "cannot end their sessions", err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		if out.Body.Already {
			return out, nil
		}
		// Handed back for the reason losing a last role hands work back: work
		// held by somebody who is gone is work nobody is doing, and it does
		// not look like it. Outside the act, like the release a withdrawal
		// does, because it is bounded by how much they were holding.
		if a.Findings != nil {
			if findings := a.Findings(); findings != nil {
				released, err := findings.Release(ctx, subject, person.PartyID)
				if err != nil {
					return nil, wentWrong(a.Logger, "cannot hand back what they were dealing with", err)
				}
				out.Body.Released = released
			}
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "reactivate-person", Method: http.MethodDelete,
		Path:    "/v1/people/{identity}/deactivation",
		Summary: "Reactivate a user",
		Description: "Lets somebody who was deactivated sign in again, with whatever they still " +
			"hold. Their roles were never withdrawn, so nothing has to be granted back.\n\n" +
			"What they were dealing with was handed back when they left and is not returned " +
			"to them: somebody else may have picked it up, and reassigning it here would " +
			"take it off them silently.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, input *struct {
		Identity string `path:"identity" maxLength:"191"`
	}) (*struct{}, error) {
		if err := changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
			rights, _, person, err := aboutPerson(ctx, a, tx, input.Identity)
			if err != nil {
				return err
			}
			moved, err := rights.Reactivate(ctx, person.ID)
			if err != nil {
				return wentWrong(a.Logger, "cannot record that they are back", err)
			}
			if !moved {
				return nil
			}
			if err := noted(ctx, tx, trail.Account, person.Identity,
				trail.Said("deactivated", true), trail.Said("active", true)); err != nil {
				return notRecorded(a.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	})
}

// aboutPerson resolves who an administrative act is about, after checking that
// the caller may make it.
//
// The order matters: authorized first, resolved second. Resolving first and
// refusing after makes the refusal informative — a name nobody holds and a name
// somebody holds come back differently, which turns a lookup into a directory
// (REQ-42).
// db is the handle it builds the store over: the transaction the act is being
// made in, or handle() where the route only reads.
func aboutPerson(ctx context.Context, a Administering, db bun.IDB, identity string) (
	*access.Store, access.Subject, *access.Account, error) {

	rights, _, err := administerable(ctx, a, db)
	if err != nil {
		return nil, access.Subject{}, nil, err
	}
	subject, err := reading(ctx)
	if err != nil {
		return nil, access.Subject{}, nil, err
	}
	person, err := rights.ByIdentity(ctx, identity)
	if err != nil {
		return nil, access.Subject{}, nil,
			absent(a.Logger, err, "that person could not be looked up", noSuchPerson)
	}
	return rights, subject, person, nil
}
