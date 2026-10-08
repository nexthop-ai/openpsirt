// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// described reads a person into their identity, their sign-in routes and their
// grants. named maps a product to its label, because a grant stores an
// identifier and a reader wants a name.
func described(ctx context.Context, a core.Administering, store *access.Store,
	person *access.Account,
) (*PersonBody, error) {
	named, err := productNames(ctx, a)
	if err != nil {
		return nil, err
	}
	doors, err := store.Identities(ctx, person.ID)
	if err != nil {
		return nil, err
	}
	held, err := store.Grants(ctx, person.ID)
	if err != nil {
		return nil, err
	}
	estate, err := store.EstateGrants(ctx, person.ID)
	if err != nil {
		return nil, err
	}
	body := personBody(person, doors, estate, held, named)
	return &body, nil
}

// personBody is one person as the people list and the one-person read both
// answer: who they are, their address and which source said so, how they sign
// in, and what they hold.
//
// The estate grants come first, because they are the wider statement and a
// reader scanning the list should meet "everywhere" before the exceptions to
// it.
func personBody(person *access.Account, doors []access.Identity, estate []access.EstateGrant,
	held []access.Grant, named map[int64]core.Named,
) PersonBody {
	body := PersonBody{
		Identity: person.Identity, DisplayName: person.DisplayName,
		Admin: person.IsAdmin, AdminByConfiguration: person.IsBootstrap,
		Audits: person.Audits, DeactivatedAt: orAbsent(person.DeactivatedAt),
		Email: person.Email, EmailSource: string(person.EmailSource),
	}
	for _, door := range doors {
		body.SignsInBy = append(body.SignsInBy, SignInBody{
			Username: door.Username, Pinned: door.Subject != nil,
		})
	}
	for _, grant := range estate {
		body.Holds = append(body.Holds, HeldBody{
			Everywhere: true, Role: core.Role(grant.Role),
			Effective: grant.Active, Source: string(grant.Source),
		})
	}
	for _, grant := range held {
		body.Holds = append(body.Holds, HeldBody{
			Product: named[grant.ProductID].Address, Role: core.Role(grant.Role),
			ProductDisplayName: named[grant.ProductID].Display,
			Effective:          grant.Active, Source: string(grant.Source),
		})
	}
	body.SeesNothing = seesNothing(body.Holds)
	return body
}

// PersonBody is somebody who has been granted access.
type PersonBody struct {
	Identity    string `json:"identity" minLength:"1" maxLength:"191" doc:"The name for them here"`
	DisplayName string `json:"display_name,omitempty" doc:"The label shown instead of the identity"`
	// Admin and AdminByConfiguration are the two sources of administration,
	// reported apart: removing a name from configuration revokes only what
	// the name gave, and a reader deciding whether somebody stays an
	// administrator after that needs to see which of the two they hold.
	Admin                bool `json:"admin,omitempty" doc:"Whether administration is granted to them in the application, by an administrator or through a group"`
	AdminByConfiguration bool `json:"admin_by_configuration,omitempty" doc:"Whether OPENPSIRT_BOOTSTRAP_ADMINS names them. They administer this deployment while it does, whatever admin says. Removing the name and restarting revokes it"`
	// Audits is the read-only half: this deployment's own records, and no
	// product's findings or decisions.
	Audits bool `json:"audits,omitempty" doc:"Whether they may read this deployment's own records. It grants no product's findings or decisions"`
	// DeactivatedAt is when they stopped being somebody who may sign in.
	// Absent is the ordinary state, and it is never a deletion: they are
	// still named by every judgment they proposed.
	//
	// On the list as well as on the person, because "who still has access"
	// is a question about the list — and a list that answers it only one row
	// at a time is one nobody asks it of.
	DeactivatedAt string `json:"deactivated_at,omitempty" doc:"The date they left. Absent means they may still sign in"`
	// Email is the address, and the field beside it names the source that
	// last decided the address. The sign-in route is SignsInBy below.
	//
	// The source is worth reporting: an address a provider supplied is one a
	// later sign-in may change, and one recorded here is not.
	Email       string `json:"email,omitempty" doc:"The address they are reached at outside the application"`
	EmailSource string `json:"email_source,omitempty" enum:"provider,recorded" doc:"The source that last decided it. A provider's may be refreshed by a later sign-in; one recorded here is never overwritten"`
	// Holds is the grants in force, listed as product and role.
	Holds []HeldBody `json:"holds,omitempty"`
	// SeesNothing says every role they hold is a capability, so they reach
	// no product at all.
	//
	// A capability is bounded by what its holder may read, so `approver`
	// or `assigner` on its own grants nothing: the person is recorded, the
	// grant is in force, and every screen is empty. Accepted in silence, the
	// grant reads as working until somebody signs in. Answered
	// here rather than left for a reader to work out from the list,
	// because working it out means knowing which roles grant visibility.
	SeesNothing bool `json:"sees_nothing,omitempty" doc:"Every role they hold is a capability, so they reach no product. A capability is bounded by what its holder may read, so on its own it grants nothing"`
	// SignsInBy lists the ways they can arrive.
	SignsInBy []SignInBody `json:"signs_in_by,omitempty"`
}

// seesNothing reports that every grant in force is a capability.
//
// False for somebody holding nothing at all: that is an account waiting to be
// granted something rather than one granted the wrong thing, and saying it of
// everybody newly recorded would make the warning worthless.
func seesNothing(held []HeldBody) bool {
	var inForce int
	for _, grant := range held {
		if !grant.Effective {
			continue
		}
		inForce++
		switch access.Role(grant.Role) {
		case access.PublicRead, access.PrivateRead, access.PublicTriage, access.PrivateTriage:
			return false
		}
	}
	return inForce > 0
}

// RecordBody is somebody being recorded, and what they are to hold.
//
// Separate from PersonBody because a request states less than an answer
// reports. Reading a person also states the sign-in routes and the force of
// each role; neither is anything a caller decides. One type for both
// directions puts them in the request, where "effective" is required — so
// granting a role means stating that the role being granted works, every
// caller sends "effective": true to be allowed to, and the reply echoes that
// back as though it were the answer.
type RecordBody struct {
	Identity string `json:"identity" minLength:"1" maxLength:"191" doc:"The name for them here"`
	// DisplayName is a pointer for the reason Email is: a name, an empty one,
	// and no mention at all are three different requests.
	DisplayName *string `json:"display_name,omitempty" doc:"The label shown instead of the identity. Send it empty to clear it; omit it to leave it alone"`
	// Admin is a pointer so that three things stay distinguishable: making
	// somebody an administrator, taking it away, and saying nothing about it.
	// A plain bool decodes an absent field as false, so granting a role — a
	// request that says nothing about administration — withdraws it.
	Admin *bool `json:"admin,omitempty" doc:"Whether administration is granted to them in the application. Omit it to leave it as it is. Administration named in OPENPSIRT_BOOTSTRAP_ADMINS is not changed by this, and a grant made here outlasts the name"`
	// Audits is the same shape for the other thing held over the deployment:
	// reading its own records and writing none of them.
	Audits *bool `json:"audits,omitempty" doc:"Whether they may read this deployment's own records: the settings, who holds what, and the administrative change log. It grants no product's findings or decisions. Omit it to leave it as it is"`
	// Email is where to reach them outside the application. Optional:
	// without one somebody is told nothing outside it and keeps the area
	// inside it. A provider that verifies an address fills in one nobody
	// stated here, and never replaces one that was. A pointer so that
	// three things are distinguishable: an address, an empty one, and no
	// mention at all. Stating it empty clears it, which is how somebody
	// comes off mail without coming off the tool; omitting it leaves
	// whatever is stored.
	Email *string `json:"email,omitempty" doc:"The address to reach them at outside the application. Optional. Send it empty to clear it; omit it to leave it alone. A sign-in provider that verifies an address fills it in where nobody here has recorded one, and never replaces one that was"`
	// Holds is what to grant them, listed as product and role.
	Holds []GrantBody `json:"holds,omitempty"`
}

// GrantBody is one role, as a request states it.
type GrantBody struct {
	// Product is the one it is held against, or empty with Everywhere set.
	Product string    `json:"product,omitempty" doc:"The product the role is held against. Omit it and set everywhere instead to hold it across the estate"`
	Role    core.Role `json:"role" doc:"The rights it carries"`
	// Everywhere holds the role across every product, including products
	// declared afterwards. Stated rather than implied by an absent product,
	// so that a caller that forgot the product is refused instead of quietly
	// granting the widest thing there is.
	Everywhere bool `json:"everywhere,omitempty" doc:"Hold it across every product, including products declared later. The product is then omitted"`
}

// SignInBody is how somebody may arrive.
type SignInBody struct {
	Username string `json:"username"`
	// Pinned says the provider's own identifier has been bound, which happens
	// at the first successful sign-in. Until then the authorization is still
	// waiting to be redeemed by whoever arrives under that name.
	Pinned bool `json:"pinned"`
}

// HeldBody is one role against one product.
type HeldBody struct {
	// Product is the one it is held against, absent where it is held across
	// every product.
	Product string `json:"product,omitempty" doc:"The product the role is held against, by the name that addresses it. Absent where it is held across every product"`
	// ProductDisplayName is the label shown beside it. The field above is the
	// one the withdraw route resolves, so it carries the address and this
	// carries the label — a screen rendering the label and sending it back
	// grants a role it cannot withdraw.
	ProductDisplayName string `json:"product_name,omitempty" doc:"The product's display name, or its name where it has none"`
	// Everywhere says it is held across the estate, covering products
	// declared afterwards. Reported rather than left to be inferred from an
	// absent product: an access review asks what somebody holds, and "on
	// nothing" and "on everything" must not read alike.
	Everywhere bool      `json:"everywhere,omitempty" doc:"Held across every product, including products declared later"`
	Role       core.Role `json:"role" doc:"The rights it carries"`
	// Effective says whether this grants anything right now. An assignment set
	// aside by a change of role-assignment mode is kept so the change can be
	// undone, and it grants nothing while it sits there — so it is shown, and
	// shown as what it is. An access review that counted it would be recording
	// access that does not exist.
	Effective bool `json:"effective" doc:"Whether this grants anything right now"`
	// Source is the origin: assigned by an administrator, or derived from a
	// group. The origin of a grant is the first thing an access review asks
	// for.
	Source string `json:"source,omitempty" enum:"assigned,derived" doc:"Whether an administrator assigned this or a group derived it"`
}

// KeyBody is a pipeline credential, without its secret.
type KeyBody struct {
	Name    string `json:"name" minLength:"1" maxLength:"191" doc:"The credential's purpose, stored in lower case and matched without regard to capitals"`
	Product string `json:"product" minLength:"1" doc:"The product it may send scans for, by the name that addresses it. Always required"`
	// ProductDisplayName is the human spelling, beside the address rather than
	// in place of it: this field is what create-key resolves, and a display
	// name resolves to nothing.
	ProductDisplayName string `json:"product_name,omitempty" doc:"The product's display name, where it differs from its name"`
	// Stream and Variant narrow it further. Either, both or neither may be
	// given: a key covering a whole product cannot imply which release an
	// upload is for, which is why an upload always states its own target.
	Stream  string `json:"stream,omitempty" doc:"Optionally, the one release it may send for"`
	Variant string `json:"variant,omitempty" doc:"Optionally, the one variant it may send for"`
	// Secret is returned when the credential is created, and never again.
	Secret string `json:"secret,omitempty" doc:"Shown once, at creation. It is stored hashed and cannot be shown again"`
	// CreatedAt is when it was issued. A credential's age is half of what
	// somebody reviewing them is looking at — the other half is when it was
	// last used, and "never used and two years old" reads very differently
	// from "never used and made this morning".
	//
	// A pipeline key does not expire, which is why the date it was made is
	// the only thing that bounds it.
	CreatedAt  string `json:"created_at,omitempty" doc:"The date it was issued. A pipeline key does not expire, so this is the only thing that dates it"`
	LastUsedAt string `json:"last_used_at,omitempty" doc:"The last time it sent something"`
	Withdrawn  bool   `json:"withdrawn,omitempty" doc:"Whether it has been withdrawn"`
}

// People and the roles they hold.
//
// Pipeline keys live in a file of their own. They share the administration
// gate and nothing else: a person is recorded once and holds roles that change
// under them, and a key is minted, used by a build server and revoked.
func registerAdministration(api huma.API, a core.Administering) {
	registerKeys(api, a)

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-people", Method: http.MethodGet, Path: "/v1/people",
		Summary: "List users",
		Description: "Lists everybody who may sign in, with the roles each of them holds and " +
			"the products those apply to.\n\n" +
			"Nobody appears here by having authenticated. Access is granted in advance, so this " +
			"list is what an administrator has decided rather than who has turned up.\n\n" +
			"`product` and `role` narrow it to the grants in force. The approvers on " +
			"one product are what an access review asks for, and reading that off a list " +
			"of everybody is reading the grid sideways. A grant that is not in force does " +
			"not match: holding is a statement about now.",
		Tags: []string{"Administration"},
	}, core.DeploymentRecords, ""), func(ctx context.Context, input *struct {
		Product string    `query:"product" doc:"Keep only people holding something on this product, by the name that addresses it"`
		Role    core.Role `query:"role" doc:"Keep only people holding this role"`
	}) (*core.ListOutput[PersonBody], error) {
		store, names, err := readable(ctx, a, a.Handle())
		if err != nil {
			return nil, err
		}
		// Resolved before the list is read, so a product nobody declared is
		// said rather than answered with an empty list — which reads as
		// "nobody holds anything there" and is a different fact.
		var onProduct int64
		if input.Product != "" {
			product, err := names.ProductByName(ctx, input.Product)
			if err != nil {
				return nil, core.Undeclared(a.Logger, err, "that product could not be looked up")
			}
			onProduct = product.ID
		}
		if input.Role != "" && !access.Role(input.Role).Valid() {
			return nil, huma.Error422UnprocessableEntity("that is not a role")
		}
		people, held, err := store.People(ctx)
		if err != nil {
			return nil, core.WentWrong(a.Logger, "cannot list people", err)
		}

		named, err := productNames(ctx, a)
		if err != nil {
			return nil, err
		}
		// Read once for everybody, like the per-product grants beside it. A
		// query per person makes a long list slow.
		everywhere, err := store.EveryEstateGrant(ctx)
		if err != nil {
			return nil, core.WentWrong(a.Logger, "cannot list what people hold everywhere", err)
		}

		out := &core.ListOutput[PersonBody]{}
		out.Body.Items = make([]PersonBody, 0, len(people))
		for _, person := range people {
			doors, err := store.Identities(ctx, person.ID)
			if err != nil {
				return nil, core.WentWrong(a.Logger, "cannot read how they sign in", err)
			}
			body := personBody(&person, doors, everywhere[person.ID], held[person.ID], named)
			if !holding(body.Holds, onProduct, named, string(input.Role)) {
				continue
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		return out, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "record-person", Method: http.MethodPost, Path: "/v1/people",
		Summary: "Create a user and grant roles",
		Description: "Records somebody so that they may sign in, and optionally what they hold. " +
			"Recording the same person again confirms them and adds any roles named.\n\n" +
			"Requires a session. A personal token cannot record a person, because the " +
			"account it would create outlives the token and is not bounded by it.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusCreated,
	}, core.DeploymentWide, ""), func(ctx context.Context, in *struct {
		Body RecordBody
	}) (*core.DeclaredOutput[PersonBody], error) {
		store, _, err := mintable(ctx, a, a.Handle())
		if err != nil {
			return nil, err
		}

		// Recording somebody records the way they sign in, because access
		// without a way to arrive is access nobody can use. The identity is
		// that way: one provider is configured at a time and a username a
		// trusted proxy asserts is the same person, so there is nothing left
		// to ask for and nothing left to get wrong.
		//
		// Administration is passed through rather than decided here. A request
		// that says nothing about it leaves it alone, and the store is what
		// knows that — computed here from a read taken before the write, two
		// requests at once would have the second write back the value it saw
		// before the first. Recording somebody, the way to reach them and what
		// they hold is one act. Written as a statement each, a product name
		// nobody has declared answers 422 with the person recorded and the
		// roles named before it granted — so an administrator correcting a
		// typo and sending the request again grants the earlier ones twice,
		// and a request they give up on leaves access nobody asked for.
		var person *access.Account
		var recorded bool
		if err := store.Within(ctx, func(ctx context.Context, store *access.Store,
			db bun.IDB) error {

			names := catalog.NewStore(db)

			// The source of roles, and how long an authorization stays
			// redeemable, read inside the act that decides from them (REQ-71).
			//
			// Read before it opens, a mode switch landing between the two lets
			// an assignment be written into a deployment where nothing derives
			// one — and nothing re-derives an assignment, so the grant
			// outlives every group change without a group ever having been
			// behind it.
			//
			// Through the transaction's own handle. A read through the root
			// handle is outside the transaction, and on a pool of one
			// connection it waits for ever on the connection the closure
			// holds.
			deriving, err := roleModeIn(a.Settings)(ctx, db)
			if err != nil {
				return core.WentWrong(a.Logger, "cannot read where roles come from", err)
			}
			window := access.DefaultClaimWindow
			if a.Settings != nil {
				if settings := a.Settings(db); settings != nil {
					window, err = settings.Duration(ctx, setting.ClaimWindow, access.DefaultClaimWindow)
					if err != nil {
						return core.WentWrong(a.Logger,
							"cannot read how long an authorization stays redeemable", err)
					}
				}
			}

			// What was stored before is the value the write was made against,
			// so the record at the foot of this says what this write moved.
			// A read of its own, taken first, can see a value another
			// administrator replaces before the write reads it, and the
			// record would then claim a move this request did not make.
			//
			// Nobody recorded under that name, and a read that failed, are
			// different answers: read as "this person is new", a dropped
			// connection takes administration away from somebody who has it,
			// records nothing saying so, and answers 201.
			var before *access.Account
			named := ""
			if in.Body.DisplayName != nil {
				named = strings.TrimSpace(*in.Body.DisplayName)
			}
			before, person, err = store.Restate(ctx, in.Body.Identity, named,
				in.Body.Admin, in.Body.Audits)
			switch {
			case errors.Is(err, database.ErrGoAgain):
				// A lost race is taken again whole, and the retry reads the
				// value the other writer left.
				return err
			case errors.Is(err, access.ErrNoIdentity):
				return huma.Error400BadRequest(err.Error())
			case err != nil:
				return core.WentWrong(a.Logger, "that person could not be recorded", err)
			}
			recorded = before == nil

			if err := store.ClaimingWithin(window).Claim(ctx, person.ID, in.Body.Identity); err != nil {
				return core.Asked(a.Logger, err)
			}
			// Recorded here, so it outranks whatever a provider states
			// later. A request that says nothing about an address leaves
			// the stored one alone rather than clearing it: this endpoint
			// records somebody, and an omission is silence rather than an
			// instruction. An address stated is recorded; an address
			// stated as empty is cleared, which is how somebody comes off
			// mail without coming off the tool.
			if in.Body.Email != nil {
				if err := store.SetEmail(ctx, person.ID, *in.Body.Email, access.Recorded); err != nil {
					return core.WentWrong(a.Logger, "where to reach them could not be recorded", err)
				}
			}
			// The name, for somebody already recorded: recording a new
			// person wrote it above. Stated empty clears it, which leaves the
			// identity showing; omitted leaves it alone.
			if before != nil && in.Body.DisplayName != nil && named != before.DisplayName {
				err := store.SetDisplayName(ctx, person.ID, before.DisplayName, named)
				switch {
				case errors.Is(err, database.ErrGoAgain):
					// Renamed by somebody else since it was read: the retry
					// reads the name they left.
					return err
				case err != nil:
					return core.WentWrong(a.Logger, "that name could not be recorded", err)
				}
				person.DisplayName = named
				if err := core.Noted(ctx, db, trail.Account, person.Identity,
					trail.Said("named "+before.DisplayName, before.DisplayName != ""),
					trail.Said("named "+named, named != "")); err != nil {
					return core.NotRecorded(a.Logger, err)
				}
			}
			if len(in.Body.Holds) > 0 && deriving == access.GroupBound {
				// Roles come from one place at a time. Assigning one while
				// groups decide produces exactly the hybrid that can name no
				// origin for its access — and worse than the drift that rule
				// anticipates, since nothing re-derives an assignment, so it
				// outlives every group change without ever having had a group
				// behind it.
				return huma.Error409Conflict(
					"roles are derived from groups here, so they are granted by binding a group rather than a person")
			}
			for _, hold := range in.Body.Holds {
				if hold.Everywhere {
					if hold.Product != "" {
						return huma.Error422UnprocessableEntity(
							"a role is held against one product or across every product, not both")
					}
					if err := store.GrantEstateRole(ctx, person.ID, access.Role(hold.Role)); err != nil {
						return core.Asked(a.Logger, err)
					}
					if err := core.Noted(ctx, db, trail.Role, person.Identity+" on every product",
						nil, trail.Said(string(hold.Role), true)); err != nil {
						return core.NotRecorded(a.Logger, err)
					}
					continue
				}
				if hold.Product == "" {
					return huma.Error422UnprocessableEntity(
						"say which product the role is held against, or set everywhere")
				}
				product, err := names.ProductByName(ctx, hold.Product)
				if err != nil {
					return core.Undeclared(a.Logger, err, "that product could not be looked up")
				}
				if err := store.GrantRole(ctx, person.ID, product.ID, access.Role(hold.Role)); err != nil {
					return core.Asked(a.Logger, err)
				}
				if err := core.Noted(ctx, db, trail.Role, person.Identity+" on "+product.Name,
					nil, trail.Said(string(hold.Role), true)); err != nil {
					return core.NotRecorded(a.Logger, err)
				}
			}

			if before == nil {
				if err := core.Noted(ctx, db, trail.Account, person.Identity, nil,
					trail.Said("recorded", true)); err != nil {
					return core.NotRecorded(a.Logger, err)
				}
			}
			// The two things held over the deployment, each recorded where it
			// moved and with what it moved from (REQ-22).
			for _, held := range moved(before, in.Body) {
				if held.asked == nil || held.was == *held.asked {
					continue
				}
				if err := core.Noted(ctx, db, trail.Account, person.Identity,
					trail.Said(held.what, held.was),
					trail.Said(held.what, *held.asked)); err != nil {
					return core.NotRecorded(a.Logger, err)
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}

		// Read back rather than echoed. The force of a grant and the origin of
		// a role are answers, and a reply repeating the request reports the
		// caller's own words as the state of the deployment — including for a
		// grant set aside by group-bound mode, which the request has just been
		// told grants nothing.
		body, err := described(ctx, a, store, person)
		if err != nil {
			return nil, core.WentWrong(a.Logger, "cannot read back the person just recorded", err)
		}
		return core.Answer(recorded, *body), nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "withdraw-role", Method: http.MethodDelete,
		Path:    "/v1/people/{identity}/roles/{product}/{role}",
		Summary: "Withdraw a user's role on a product",
		Description: "Withdraws one role from one person. Takes effect at their next request; " +
			"end their sessions to cut them off now.\n\n" +
			"If it was their last role on that product, everything they were dealing with there " +
			"goes back to the unassigned list. Otherwise that work is in no list at all: not in " +
			"the shared one because it is assigned, and not in theirs because they can no " +
			"longer open it. `released` says how much moved.\n\n" +
			"The grant is removed rather than marked as ended. What somebody used to hold is " +
			"answered by the record of what they did, so this list only ever says what is true " +
			"today.",
		Tags: []string{"Administration"},
	}, core.DeploymentWide, ""), func(ctx context.Context, in *struct {
		Identity string `path:"identity"`
		Product  string `path:"product"`
		Role     string `path:"role"`
	}) (*struct {
		Body struct {
			Released int64 `json:"released" doc:"Findings handed back because that was their last role here"`
		}
	}, error) {
		subject, err := core.Requester(ctx)
		if err != nil {
			return nil, err
		}
		var person *access.Account
		var productID int64
		var remaining bool
		if err := core.Changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
			store, names, err := core.Administerable(ctx, a, tx)
			if err != nil {
				return err
			}
			if person, err = store.ByIdentity(ctx, in.Identity); err != nil {
				return core.Absent(a.Logger, err, "that person could not be looked up", core.NoSuchPerson)
			}
			product, err := names.ProductByName(ctx, in.Product)
			if err != nil {
				return core.Undeclared(a.Logger, err, "that product could not be looked up")
			}
			productID = product.ID
			// The role is checked before anything is written, because a word
			// that is not a role withdraws nothing and would otherwise be
			// recorded as a withdrawal of it.
			role := access.Role(in.Role)
			if !role.Valid() {
				return huma.Error422UnprocessableEntity("that is not a role")
			}
			// Mapped before the trail row and before the work is handed back.
			// A withdrawal that matches nothing does neither, and doing them
			// anyway writes a record of an act that never happened and
			// unassigns everything the person is dealing with there.
			switch err := store.Withdraw(ctx, person.ID, product.ID, role); {
			case errors.Is(err, access.ErrNothingMatched):
				return core.NoSuchGrant()
			case err != nil:
				return core.WentWrong(a.Logger, "cannot withdraw the role", err)
			}
			if err := core.Noted(ctx, tx, trail.Role, person.Identity+" on "+product.Name,
				trail.Said(in.Role, true), nil); err != nil {
				return core.NotRecorded(a.Logger, err)
			}
			// Asked inside, so what it sees is what the withdrawal left rather
			// than what another administrator leaves behind afterwards. Their
			// last role here going is what turns their assigned work into work
			// nobody can reach.
			if remaining, err = store.HoldsAnythingIn(ctx, person.ID, product.ID); err != nil {
				return core.WentWrong(a.Logger, "cannot read what they still hold", err)
			}
			return nil
		}); err != nil {
			return nil, err
		}

		out := &struct {
			Body struct {
				Released int64 `json:"released" doc:"Findings handed back because that was their last role here"`
			}
		}{}
		if remaining || a.Findings == nil {
			return out, nil
		}
		findings := a.Findings()
		if findings == nil {
			return out, nil
		}
		released, err := findings.ReleaseIn(ctx, subject, person.PartyID, productID)
		if err != nil {
			return nil, core.WentWrong(a.Logger, "cannot hand back what they were dealing with", err)
		}
		out.Body.Released = released
		return out, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "unbind-identifier", Method: http.MethodDelete,
		Path:    "/v1/people/{identity}/identifier",
		Summary: "Unbind a user's provider identifier",
		Description: "Clears the identifier a sign-in provider pinned to somebody, so that the " +
			"next person to arrive under their username binds it again. Their authorization and " +
			"their roles are untouched.\n\n" +
			"Use it after changing sign-in provider. An identifier belongs to the provider " +
			"that issued it, so every account pinned to the old one is refused once a new one is " +
			"configured: the name matches and the identifier does not.\n\n" +
			"It re-opens the window a pinned identifier closes, in which whoever arrives under " +
			"that username is taken to be its holder. Do it when you expect them to sign in.\n\n" +
			"Somebody with no identifier pinned answers 404 and records nothing.",
		Tags: []string{"Administration"},
	}, core.DeploymentWide, ""), func(ctx context.Context, in *struct {
		Identity string `path:"identity"`
	}) (*struct{}, error) {
		if err := core.Changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
			store, _, err := core.Administerable(ctx, a, tx)
			if err != nil {
				return err
			}
			person, err := store.ByIdentity(ctx, in.Identity)
			if err != nil {
				return core.Absent(a.Logger, err, "that person could not be looked up", core.NoSuchPerson)
			}
			switch err := store.UnbindIdentifier(ctx, person.ID); {
			case errors.Is(err, access.ErrNothingMatched):
				return huma.Error404NotFound("they have no identifier bound")
			case err != nil:
				return core.WentWrong(a.Logger, "cannot unbind how they sign in", err)
			}
			if err := core.Noted(ctx, tx, trail.Account, person.Identity,
				trail.Said("identifier bound", true),
				trail.Said("identifier bound", false)); err != nil {
				return core.NotRecorded(a.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "withdraw-estate-role", Method: http.MethodDelete,
		Path:    "/v1/people/{identity}/roles/{role}",
		Summary: "Withdraw a user's role on every product",
		Description: "Withdraws a role held across the estate. Takes effect at their next " +
			"request; end their sessions to cut them off now.\n\n" +
			"It leaves no per-product grants in its place: anything still wanted on one " +
			"product is granted there deliberately. Roles held against a named product are " +
			"untouched, and are withdrawn one at a time through the path that names the " +
			"product.\n\n" +
			"Where this was their last role in a product, what they were dealing with there " +
			"goes back to the unassigned list. `released` says how much moved in total.",
		Tags: []string{"Administration"},
	}, core.DeploymentWide, ""), func(ctx context.Context, in *struct {
		Identity string `path:"identity"`
		Role     string `path:"role"`
	}) (*struct {
		Body struct {
			Released int64 `json:"released" doc:"Findings handed back because that was their last role there"`
		}
	}, error) {
		subject, err := core.Requester(ctx)
		if err != nil {
			return nil, err
		}
		var person *access.Account
		var unreachable []int64
		if err := core.Changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
			store, _, err := core.Administerable(ctx, a, tx)
			if err != nil {
				return err
			}
			if person, err = store.ByIdentity(ctx, in.Identity); err != nil {
				return core.Absent(a.Logger, err, "that person could not be looked up", core.NoSuchPerson)
			}
			role := access.Role(in.Role)
			if !role.Valid() {
				return huma.Error422UnprocessableEntity("that is not a role")
			}
			switch err := store.WithdrawEstateRole(ctx, person.ID, role); {
			case errors.Is(err, access.ErrNothingMatched):
				return core.NoSuchGrant()
			case err != nil:
				return core.WentWrong(a.Logger, "cannot withdraw the role", err)
			}
			if err := core.Noted(ctx, tx, trail.Role, person.Identity+" on every product",
				trail.Said(in.Role, true), nil); err != nil {
				return core.NotRecorded(a.Logger, err)
			}

			// The same reason the per-product withdrawal releases work: their
			// last role in a product going is what turns their assigned
			// findings into work nobody can reach — assigned, so out of the
			// shared queue, and assigned to somebody who can no longer open
			// it. An estate role is the last role in every product at once, so
			// this asks for each.
			//
			// The products themselves are read here, in the view the
			// withdrawal left. Handing the work back is done afterwards: it is
			// bounded by how much they were holding rather than by the
			// request, and it is a consequence of the withdrawal rather than
			// part of it.
			covered, err := store.ProductsCovered(ctx)
			if err != nil {
				return core.WentWrong(a.Logger, "cannot read what the grant covered", err)
			}
			unreachable = unreachable[:0]
			for _, productID := range covered {
				remaining, err := store.HoldsAnythingIn(ctx, person.ID, productID)
				if err != nil {
					return core.WentWrong(a.Logger, "cannot read what they still hold", err)
				}
				if !remaining {
					unreachable = append(unreachable, productID)
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}

		out := &struct {
			Body struct {
				Released int64 `json:"released" doc:"Findings handed back because that was their last role there"`
			}
		}{}
		if a.Findings == nil {
			return out, nil
		}
		findings := a.Findings()
		if findings == nil {
			return out, nil
		}
		for _, productID := range unreachable {
			released, err := findings.ReleaseIn(ctx, subject, person.PartyID, productID)
			if err != nil {
				return nil, core.WentWrong(a.Logger, "cannot hand back what they were dealing with", err)
			}
			out.Body.Released += released
		}
		return out, nil
	})
}

// timeFormat is how a moment is reported.
const timeFormat = "2006-01-02T15:04:05Z"

// mintable is administerable for the two acts that create a credential: a
// credential cannot create another.
func mintable(ctx context.Context, a core.Administering, db bun.IDB) (*access.Store, *catalog.Store, error) {
	if err := core.MintingCredentials(ctx); err != nil {
		return nil, nil, err
	}
	return core.Administerable(ctx, a, db)
}

// readable is administerable for the routes that only read the deployment's
// own records: who holds what, what it is set to, and what has been changed.
//
// The audit permission reaches those and nothing else. Every write below stays
// with administerable above, which is the whole difference between the two.
func readable(ctx context.Context, a core.Administering, db bun.IDB) (*access.Store, *catalog.Store, error) {
	if err := core.ReadingTheDeployment(ctx); err != nil {
		return nil, nil, err
	}
	return core.Stores(a, db)
}

// held is one thing somebody holds over the deployment: what it is called in
// the record, what it was, and what the request asks it to become.
type held struct {
	what  string
	was   bool
	asked *bool
}

// moved is the two of those, for a person who was already recorded.
//
// Both, rather than whichever matches first. Written as arms of one switch
// beside "this person is new", a request granting both records one of them —
// and the audit permission, the one grant that opens the change log, is the
// arm that never runs, so the permission to read the record is the change the
// record does not hold.
//
// Nothing for somebody who has just been recorded: their creation is the row,
// and a second line saying a brand-new account went from holding nothing is a
// line about no change.
func moved(before *access.Account, asked RecordBody) []held {
	if before == nil {
		return nil
	}
	return []held{
		{"administrator", before.IsAdmin, asked.Admin},
		{"auditor", before.Audits, asked.Audits},
	}
}

// holding reports whether what somebody holds matches the narrowing asked for.
//
// Applied to the bodies rather than in the query, because the narrowing runs
// over what the list already states: a role held across every product
// matches a named one, and a grant out of force matches nothing. Both of those
// are decided above, and asking the database again would be a second rule that
// can disagree with the first.
func holding(holds []HeldBody, productID int64, named map[int64]core.Named, role string) bool {
	if productID == 0 && role == "" {
		return true
	}
	address := named[productID].Address
	for _, held := range holds {
		// A grant out of force is not held. Holding is a statement about now,
		// and a review of who approves here must not be handed
		// somebody whose grant a change of mode set aside.
		if !held.Effective {
			continue
		}
		if role != "" && string(held.Role) != role {
			continue
		}
		// A role held across every product is held on this one, including
		// products declared after the grant was made.
		if productID != 0 && !held.Everywhere && held.Product != address {
			continue
		}
		return true
	}
	return false
}
