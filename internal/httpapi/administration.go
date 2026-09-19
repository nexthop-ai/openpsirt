package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// described says who somebody is, how they can arrive and what they hold, by
// reading it. named maps a product to what it is called, because a grant
// stores an identifier and a reader wants a name.
func described(ctx context.Context, a Administering, store *access.Store,
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
	body := &PersonBody{
		Identity: person.Identity, DisplayName: person.DisplayName, Admin: person.IsAdmin,
		Audits: person.Audits, DeactivatedAt: orAbsent(person.DeactivatedAt),
		Email: person.Email, EmailSource: string(person.EmailSource),
	}
	for _, door := range doors {
		body.SignsInBy = append(body.SignsInBy, SignInBody{
			Username: door.Username, Pinned: door.Subject != nil,
		})
	}
	// The estate grants first, because they are the wider statement and a
	// reader scanning the list should meet "everywhere" before the exceptions
	// to it.
	for _, grant := range estate {
		body.Holds = append(body.Holds, HeldBody{
			Everywhere: true, Role: string(grant.Role),
			Effective: grant.Active, Source: string(grant.Source),
		})
	}
	for _, grant := range held {
		body.Holds = append(body.Holds, HeldBody{
			Product: named[grant.ProductID].Address, Role: string(grant.Role),
			ProductDisplayName: named[grant.ProductID].Display,
			Effective:          grant.Active, Source: string(grant.Source),
		})
	}
	body.SeesNothing = seesNothing(body.Holds)
	return body, nil
}

// Administering is what the endpoints for people and credentials need.
type Administering struct {
	// DB is what an administrative act and the record of it are written in
	// one transaction on. Nil where this process has no database, and then
	// every route here refuses rather than changing anything.
	DB *database.DB
	// Access and Catalog are built over whatever handle the caller is
	// writing on: the transaction, where the act is being made, and the
	// pooled handle where it is only being read.
	Access  func(bun.IDB) *access.Store
	Catalog func(bun.IDB) *catalog.Store
	Logger  *slog.Logger
	// Findings is what withdrawing somebody's last role on a product
	// needs: their work there goes back to the unassigned list rather than
	// staying where nobody can reach it. Nil where this process has no
	// database, and then nothing is released.
	//
	// Over the pooled handle rather than the act's transaction: handing work
	// back is a consequence of the withdrawal rather than part of it, and it
	// is bounded by how much that person was holding rather than by the
	// request.
	Findings func() *finding.Store
	// Settings is where the window an unredeemed authorization stays
	// redeemable for is read. Nil where this process has no database, and
	// then the built-in window applies.
	Settings func(bun.IDB) *setting.Store
	// Groups says whether anything configured here can hand over group
	// membership: a provider with a source of groups, or a trusted proxy that
	// reports them.
	//
	// Asked before roles are switched to group-bound. Without a source every
	// arrival reports belonging to nothing, so nobody derives any role and the
	// deployment locks itself out — including whoever made the change.
	Groups func() bool
}

// handle is what a route that only reads builds its stores over.
//
// Named rather than written as a.DB at each site: a nil *database.DB handed to
// an interface parameter is an interface that is not nil, so every check below
// it reads as a database that is there and every store built over it panics on
// first use.
func (a Administering) handle() bun.IDB {
	if a.DB == nil {
		return nil
	}
	return a.DB.DB
}

// PersonBody is somebody who has been granted access.
type PersonBody struct {
	Identity    string `json:"identity" minLength:"1" maxLength:"191" doc:"What to call them here"`
	DisplayName string `json:"display_name,omitempty" doc:"What to show instead of the identity"`
	Admin       bool   `json:"admin,omitempty" doc:"Whether they administer this deployment"`
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
	DeactivatedAt string `json:"deactivated_at,omitempty" doc:"When they left. Absent means they may still sign in"`
	// Email is how somebody signs in is SignsInBy below, which carries the
	// username and whether the provider's own identifier has been pinned
	// to it. Two fields here said the same thing, were documented as
	// though a request set them, and were assigned on no path at all — so
	// every client written against the published document read them as
	// absent for everybody.
	//
	// Email, and whether a provider gave it. The second is worth answering:
	// an address a provider supplied is one a later sign-in may change, and
	// one recorded here is not.
	Email       string `json:"email,omitempty" doc:"Where they are reached outside the application"`
	EmailSource string `json:"email_source,omitempty" enum:"provider,recorded" doc:"Who last decided it. A provider's may be refreshed by a later sign-in; one recorded here is never overwritten"`
	// Holds is what they may do, listed as product and role.
	Holds []HeldBody `json:"holds,omitempty"`
	// SeesNothing says every role they hold is a capability, so they reach
	// no product at all.
	//
	// A capability is bounded by what its holder may read, so `approver`
	// or `assigner` on its own grants nothing: the person is recorded, the
	// grant is in force, and every screen is empty. It was accepted in
	// silence, which reads as working until somebody signs in. Answered
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
// reports. Reading a person also says how they sign in and whether each role
// is in force; neither is anything a caller can decide, and one type for both
// directions put them in the request — where "effective" was required, so
// granting a role meant stating whether the role you are granting works.
// Everything that granted one sent "effective": true to be allowed to, and
// the reply then echoed that back as though it were the answer.
type RecordBody struct {
	Identity    string `json:"identity" minLength:"1" maxLength:"191" doc:"What to call them here"`
	DisplayName string `json:"display_name,omitempty" doc:"What to show instead of the identity"`
	// Admin is a pointer so that three things stay distinguishable: making
	// somebody an administrator, taking it away, and saying nothing about it.
	// A plain bool decodes an absent field as false, so granting a role — a
	// request that says nothing about administration — withdrew it.
	Admin *bool `json:"admin,omitempty" doc:"Whether they administer this deployment. Omit it to leave it as it is"`
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
	Email *string `json:"email,omitempty" doc:"Where to reach them outside the application. Optional. Send it empty to clear it; omit it to leave it alone. A sign-in provider that verifies an address fills it in where nobody here has recorded one, and never replaces one that was"`
	// Holds is what to grant them, listed as product and role.
	Holds []GrantBody `json:"holds,omitempty"`
}

// GrantBody is one role, as a request states it.
type GrantBody struct {
	// Product is the one it is held against, or empty with Everywhere set.
	Product string `json:"product,omitempty" doc:"The product the role is held against. Omit it and set everywhere instead to hold it across the estate"`
	Role    string `json:"role" enum:"approver,assigner,public-read,private-read,public-triage,private-triage" doc:"What they may do with it"`
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
	// ProductDisplayName is what to show beside it. The field above is what
	// the withdraw route resolves, so it carries the address and this carries
	// the label — a screen rendering the label and sending it back is how a
	// role could be granted and not withdrawn.
	ProductDisplayName string `json:"product_display_name,omitempty" doc:"What to call that product, where it was declared with a display name"`
	// Everywhere says it is held across the estate, covering products
	// declared afterwards. Reported rather than left to be inferred from an
	// absent product: an access review asks what somebody holds, and "on
	// nothing" and "on everything" must not read alike.
	Everywhere bool   `json:"everywhere,omitempty" doc:"Held across every product, including products declared later"`
	Role       string `json:"role" enum:"approver,assigner,public-read,private-read,public-triage,private-triage" doc:"What they may do with it"`
	// Effective says whether this grants anything right now. An assignment set
	// aside by a change of role-assignment mode is kept so the change can be
	// undone, and it grants nothing while it sits there — so it is shown, and
	// shown as what it is. An access review that counted it would be recording
	// access that does not exist.
	Effective bool `json:"effective" doc:"Whether this grants anything right now"`
	// Source says where it came from: assigned by an administrator, or derived
	// from a group. "Where did this access come from" is the question an audit
	// asks first.
	Source string `json:"source,omitempty" enum:"assigned,derived" doc:"Whether an administrator assigned this or a group derived it"`
}

// KeyBody is a pipeline credential, without its secret.
type KeyBody struct {
	Name    string `json:"name" minLength:"1" maxLength:"191" doc:"What this credential is for"`
	Product string `json:"product" minLength:"1" doc:"The product it may send scans for, by the name that addresses it. Always required"`
	// ProductDisplayName is the human spelling, beside the address rather than
	// in place of it: this field is what create-key resolves, and a display
	// name resolves to nothing.
	ProductDisplayName string `json:"product_display_name,omitempty" doc:"What to call that product, where it was declared with a display name"`
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
	CreatedAt  string `json:"created_at,omitempty" doc:"When it was issued. A pipeline key does not expire, so this is the only thing that dates it"`
	LastUsedAt string `json:"last_used_at,omitempty" doc:"When it last sent something"`
	Withdrawn  bool   `json:"withdrawn,omitempty" doc:"Whether it has been withdrawn"`
}

// People and the roles they hold.
//
// Pipeline keys were here too. They share the administration gate and nothing
// else: a person is recorded once and holds roles that change under them, and
// a key is minted, used by a build server and revoked.
func registerAdministration(api huma.API, a Administering) {
	registerKeys(api, a)

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-people", Method: http.MethodGet, Path: "/v1/people",
		Summary: "List users",
		Description: "Lists everybody who may sign in, with the roles each of them holds and " +
			"the products those apply to.\n\n" +
			"Nobody appears here by having authenticated. Access is granted in advance, so this " +
			"list is what an administrator has decided rather than who has turned up.\n\n" +
			"**`product` and `role` narrow it to who holds what.** \"Who approves on this " +
			"product\" is the question an access review asks, and reading it off a list of " +
			"everybody is reading the grid sideways. A grant that is not in force does not " +
			"match: what somebody holds is a statement about now.",
		Tags: []string{"Administration"},
	}, deploymentRecords, ""), func(ctx context.Context, input *struct {
		Product string `query:"product" doc:"Keep only people holding something on this product, by the name that addresses it"`
		Role    string `query:"role" enum:"approver,assigner,public-read,private-read,public-triage,private-triage" doc:"Keep only people holding this role"`
	}) (*listOutput[PersonBody], error) {
		store, names, err := readable(ctx, a, a.handle())
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
				return nil, undeclared(a.Logger, err, "that product could not be looked up")
			}
			onProduct = product.ID
		}
		if input.Role != "" && !access.Role(input.Role).Valid() {
			return nil, huma.Error422UnprocessableEntity("that is not a role")
		}
		people, held, err := store.People(ctx)
		if err != nil {
			return nil, wentWrong(a.Logger, "cannot list people", err)
		}

		named, err := productNames(ctx, a)
		if err != nil {
			return nil, err
		}
		// Read once for everybody, like the per-product grants beside it. A
		// query per person is what makes a long list slow.
		everywhere, err := store.EveryEstateGrant(ctx)
		if err != nil {
			return nil, wentWrong(a.Logger, "cannot list what people hold everywhere", err)
		}

		out := &listOutput[PersonBody]{}
		out.Body.Items = make([]PersonBody, 0, len(people))
		for _, person := range people {
			body := PersonBody{
				Identity: person.Identity, DisplayName: person.DisplayName, Admin: person.IsAdmin,
				Audits: person.Audits, DeactivatedAt: orAbsent(person.DeactivatedAt),
				// Where they are reached, and which of the two sources said
				// so. On the list as well as on the one-person read: the
				// screen that records an address is the list, and a column
				// that drew "none" over an address somebody had just typed
				// reads as the write having been refused.
				Email: person.Email, EmailSource: string(person.EmailSource),
			}
			doors, err := store.Identities(ctx, person.ID)
			if err != nil {
				return nil, wentWrong(a.Logger, "cannot read how they sign in", err)
			}
			for _, door := range doors {
				body.SignsInBy = append(body.SignsInBy, SignInBody{
					Username: door.Username, Pinned: door.Subject != nil,
				})
			}
			for _, grant := range everywhere[person.ID] {
				body.Holds = append(body.Holds, HeldBody{
					Everywhere: true, Role: string(grant.Role),
					Effective: grant.Active, Source: string(grant.Source),
				})
			}
			for _, grant := range held[person.ID] {
				body.Holds = append(body.Holds, HeldBody{
					Product: named[grant.ProductID].Address, Role: string(grant.Role),
					ProductDisplayName: named[grant.ProductID].Display,
					Effective:          grant.Active, Source: string(grant.Source),
				})
			}
			body.SeesNothing = seesNothing(body.Holds)
			if !holding(body.Holds, onProduct, named, input.Role) {
				continue
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "record-person", Method: http.MethodPost, Path: "/v1/people",
		Summary: "Create a user and grant roles",
		Description: "Records somebody so that they may sign in, and optionally what they hold. " +
			"Recording the same person again confirms them and adds any roles named.\n\n" +
			"**Requires a session.** A personal token cannot record a person, because the " +
			"account it would create outlives the token and is not bounded by it.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusCreated,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Body RecordBody
	}) (*declaredOutput[PersonBody], error) {
		store, _, err := mintable(ctx, a, a.handle())
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
		// before the first.
		// Recording somebody, how they may be reached and what they hold is
		// one act. Written as a statement each, a product name nobody has
		// declared answered 422 with the person recorded and the roles named
		// before it granted — so an administrator correcting a typo and
		// sending the request again granted the earlier ones twice, and a
		// request they gave up on left access nobody asked for.
		var person *access.Account
		var recorded bool
		if err := store.Within(ctx, func(ctx context.Context, store *access.Store,
			db bun.IDB) error {

			names := catalog.NewStore(db)

			// Where roles come from, and how long an authorization stays
			// redeemable, read inside the act that decides from them (REQ-71).
			//
			// Read before it opened, a mode switch landing between the two let
			// an assignment be written into a deployment where nothing derives
			// one — and nothing re-derives an assignment, so the grant would
			// outlive every group change without a group ever having been
			// behind it.
			//
			// Through the transaction's own handle, which is what the comment
			// that stood here had wrong: the stall it described came from
			// reading through the *root* handle while the closure held
			// SQLite's one connection, not from reading inside the
			// transaction at all. Unbinding a group already reads the mode
			// exactly this way.
			deriving, err := roleModeIn(a.Settings)(ctx, db)
			if err != nil {
				return wentWrong(a.Logger, "cannot read where roles come from", err)
			}
			window := access.DefaultClaimWindow
			if a.Settings != nil {
				if settings := a.Settings(db); settings != nil {
					window, err = settings.Duration(ctx, setting.ClaimWindow, access.DefaultClaimWindow)
					if err != nil {
						return wentWrong(a.Logger,
							"cannot read how long an authorization stays redeemable", err)
					}
				}
			}

			// Nobody recorded under that name, and a read that failed, are
			// different answers. Told apart by the sentinel rather than by
			// "any error at all": read as "this person is new", a dropped
			// connection took administration away from somebody who had it,
			// recorded nothing saying so, and answered 201.
			//
			// Read here rather than before the transaction, because what the
			// record at the foot of it says depends on the answer and a retry
			// re-runs against a database that has moved (REQ-71).
			before, lookupErr := store.ByIdentity(ctx, in.Body.Identity)
			switch {
			case lookupErr == nil:
			case errors.Is(lookupErr, access.ErrNoSuchPerson):
				before = nil
			default:
				return wentWrong(a.Logger, "that person could not be looked up", lookupErr)
			}
			recorded = before == nil

			if person, err = store.Ensure(ctx, in.Body.Identity, in.Body.DisplayName,
				in.Body.Admin, in.Body.Audits); err != nil {
				return huma.Error400BadRequest(err.Error())
			}
			if err := store.ClaimingWithin(window).Claim(ctx, person.ID, in.Body.Identity); err != nil {
				return asked(a.Logger, err)
			}
			// Recorded here, so it outranks whatever a provider states
			// later . A request that says nothing about an address leaves
			// the stored one alone rather than clearing it: this endpoint
			// records somebody, and an omission is silence rather than an
			// instruction. An address stated is recorded; an address
			// stated as empty is cleared, which is how somebody comes off
			// mail without coming off the tool.
			if in.Body.Email != nil {
				if err := store.SetEmail(ctx, person.ID, *in.Body.Email, access.Recorded); err != nil {
					return wentWrong(a.Logger, "where to reach them could not be recorded", err)
				}
			}
			if len(in.Body.Holds) > 0 && deriving == access.GroupBound {
				// Roles come from one place at a time. Assigning one while
				// groups decide would produce exactly the hybrid that has no
				// answer to "where did this access come from" — and worse than
				// the drift that rule anticipates, since nothing re-derives an
				// assignment, so it would outlive every group change without
				// ever having had a group behind it.
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
						return huma.Error400BadRequest(err.Error())
					}
					if err := noted(ctx, db, trail.Role, in.Body.Identity+" on every product",
						nil, trail.Said(hold.Role, true)); err != nil {
						return notRecorded(a.Logger, err)
					}
					continue
				}
				if hold.Product == "" {
					return huma.Error422UnprocessableEntity(
						"say which product the role is held against, or set everywhere")
				}
				product, err := names.ProductByName(ctx, hold.Product)
				if err != nil {
					return undeclared(a.Logger, err, "that product could not be looked up")
				}
				if err := store.GrantRole(ctx, person.ID, product.ID, access.Role(hold.Role)); err != nil {
					return huma.Error400BadRequest(err.Error())
				}
				if err := noted(ctx, db, trail.Role, in.Body.Identity+" on "+hold.Product,
					nil, trail.Said(hold.Role, true)); err != nil {
					return notRecorded(a.Logger, err)
				}
			}

			if before == nil {
				if err := noted(ctx, db, trail.Account, in.Body.Identity, nil,
					trail.Said("recorded", true)); err != nil {
					return notRecorded(a.Logger, err)
				}
			}
			// The two things held over the deployment, each recorded where it
			// moved and with what it moved from (REQ-22).
			for _, held := range moved(before, in.Body) {
				if held.asked == nil || held.was == *held.asked {
					continue
				}
				if err := noted(ctx, db, trail.Account, in.Body.Identity,
					trail.Said(held.what, held.was),
					trail.Said(held.what, *held.asked)); err != nil {
					return notRecorded(a.Logger, err)
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}

		// Read back rather than echoed. What is in force and where a role came
		// from are answers, and a reply that repeated the request reported the
		// caller's own words as the state of the deployment — including for a
		// grant set aside by group-bound mode, which the request had just been
		// told grants nothing.
		body, err := described(ctx, a, store, person)
		if err != nil {
			return nil, wentWrong(a.Logger, "cannot read back the person just recorded", err)
		}
		return answer(recorded, *body), nil
	})

	huma.Register(api, requiring(huma.Operation{
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
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Identity string `path:"identity"`
		Product  string `path:"product"`
		Role     string `path:"role"`
	}) (*struct {
		Body struct {
			Released int64 `json:"released" doc:"Findings handed back because that was their last role here"`
		}
	}, error) {
		subject, err := requester(ctx)
		if err != nil {
			return nil, err
		}
		var person *access.Account
		var productID int64
		var remaining bool
		if err := changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
			store, names, err := administerable(ctx, a, tx)
			if err != nil {
				return err
			}
			if person, err = store.ByIdentity(ctx, in.Identity); err != nil {
				return noSuchPerson()
			}
			product, err := names.ProductByName(ctx, in.Product)
			if err != nil {
				return undeclared(a.Logger, err, "that product could not be looked up")
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
			// A withdrawal that matched nothing did neither of those things,
			// and doing them anyway wrote a record of an act that never
			// happened and unassigned everything the person was dealing with
			// there.
			switch err := store.Withdraw(ctx, person.ID, product.ID, role); {
			case errors.Is(err, access.ErrNothingMatched):
				return noSuchGrant()
			case err != nil:
				return wentWrong(a.Logger, "cannot withdraw the role", err)
			}
			if err := noted(ctx, tx, trail.Role, in.Identity+" on "+in.Product,
				trail.Said(in.Role, true), nil); err != nil {
				return notRecorded(a.Logger, err)
			}
			// Asked inside, so what it sees is what the withdrawal left rather
			// than what another administrator leaves behind afterwards. Their
			// last role here going is what turns their assigned work into work
			// nobody can reach.
			if remaining, err = store.HoldsAnythingIn(ctx, person.ID, product.ID); err != nil {
				return wentWrong(a.Logger, "cannot read what they still hold", err)
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
			return nil, wentWrong(a.Logger, "cannot hand back what they were dealing with", err)
		}
		out.Body.Released = released
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "unbind-identifier", Method: http.MethodDelete,
		Path:    "/v1/people/{identity}/identifier",
		Summary: "Unbind a user's provider identifier",
		Description: "Clears the identifier a sign-in provider pinned to somebody, so that the " +
			"next person to arrive under their username binds it again. Their authorization and " +
			"their roles are untouched.\n\n" +
			"**Use it after changing sign-in provider.** An identifier belongs to the provider " +
			"that issued it, so every account pinned to the old one is refused once a new one is " +
			"configured: the name matches and the identifier does not.\n\n" +
			"It re-opens the window a pinned identifier closes, in which whoever arrives under " +
			"that username is taken to be its holder. Do it when you expect them to sign in.",
		Tags: []string{"Administration"},
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Identity string `path:"identity"`
	}) (*struct{}, error) {
		if err := changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
			store, _, err := administerable(ctx, a, tx)
			if err != nil {
				return err
			}
			person, err := store.ByIdentity(ctx, in.Identity)
			if err != nil {
				return noSuchPerson()
			}
			if err := store.UnbindIdentifier(ctx, person.ID); err != nil {
				return wentWrong(a.Logger, "cannot unbind how they sign in", err)
			}
			if err := noted(ctx, tx, trail.Account, in.Identity,
				trail.Said("identifier bound", true),
				trail.Said("identifier bound", false)); err != nil {
				return notRecorded(a.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
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
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Identity string `path:"identity"`
		Role     string `path:"role"`
	}) (*struct {
		Body struct {
			Released int64 `json:"released" doc:"Findings handed back because that was their last role there"`
		}
	}, error) {
		subject, err := requester(ctx)
		if err != nil {
			return nil, err
		}
		var person *access.Account
		var unreachable []int64
		if err := changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
			store, _, err := administerable(ctx, a, tx)
			if err != nil {
				return err
			}
			if person, err = store.ByIdentity(ctx, in.Identity); err != nil {
				return noSuchPerson()
			}
			role := access.Role(in.Role)
			if !role.Valid() {
				return huma.Error422UnprocessableEntity("that is not a role")
			}
			switch err := store.WithdrawEstateRole(ctx, person.ID, role); {
			case errors.Is(err, access.ErrNothingMatched):
				return noSuchGrant()
			case err != nil:
				return wentWrong(a.Logger, "cannot withdraw the role", err)
			}
			if err := noted(ctx, tx, trail.Role, in.Identity+" on every product",
				trail.Said(in.Role, true), nil); err != nil {
				return notRecorded(a.Logger, err)
			}

			// The same reason the per-product withdrawal releases work: their
			// last role in a product going is what turns their assigned
			// findings into work nobody can reach — assigned, so out of the
			// shared queue, and assigned to somebody who can no longer open
			// it. An estate role is the last role in every product at once, so
			// this asks for each.
			//
			// Which products those are is read here, in the view the
			// withdrawal left. Handing the work back is done afterwards: it is
			// bounded by how much they were holding rather than by the
			// request, and it is a consequence of the withdrawal rather than
			// part of it.
			covered, err := store.ProductsCovered(ctx)
			if err != nil {
				return wentWrong(a.Logger, "cannot read what the grant covered", err)
			}
			unreachable = unreachable[:0]
			for _, productID := range covered {
				remaining, err := store.HoldsAnythingIn(ctx, person.ID, productID)
				if err != nil {
					return wentWrong(a.Logger, "cannot read what they still hold", err)
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
				return nil, wentWrong(a.Logger, "cannot hand back what they were dealing with", err)
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
func mintable(ctx context.Context, a Administering, db bun.IDB) (*access.Store, *catalog.Store, error) {
	if err := mintingCredentials(ctx); err != nil {
		return nil, nil, err
	}
	return administerable(ctx, a, db)
}

// administerable refuses anybody who is not an administrator, and hands back
// what the endpoint needs.
//
// Managing who may do what is the one thing that must never be reachable by a
// role granted on a product: somebody who may triage a product must not be
// able to grant themselves more of it.
// db is the handle it builds those over: the transaction an act is being made
// in, or handle() where the route only reads.
func administerable(ctx context.Context, a Administering, db bun.IDB) (*access.Store, *catalog.Store, error) {
	if err := administrating(ctx); err != nil {
		return nil, nil, err
	}
	return stores(a, db)
}

// readable is administerable for the routes that only read the deployment's
// own records: who holds what, what it is set to, and what has been changed.
//
// The audit permission reaches those and nothing else. Every write below stays
// with administerable above, which is the whole difference between the two.
func readable(ctx context.Context, a Administering, db bun.IDB) (*access.Store, *catalog.Store, error) {
	if err := readingTheDeployment(ctx); err != nil {
		return nil, nil, err
	}
	return stores(a, db)
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
// **Both, rather than whichever matched first.** Written as arms of one switch
// beside "this person is new", a request granting both recorded one of them —
// and the audit permission, which is the one grant that opens the change log,
// was the arm that never ran at all, so the permission to read the record was
// the change the record did not hold.
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
// Applied to the bodies rather than in the query, because what is being
// narrowed is what the list already says: a role held across every product
// matches a named one, and a grant out of force matches nothing. Both of those
// are decided above, and asking the database again would be a second rule that
// can disagree with the first.
func holding(holds []HeldBody, productID int64, named map[int64]named, role string) bool {
	if productID == 0 && role == "" {
		return true
	}
	address := named[productID].Address
	for _, held := range holds {
		// Not in force is not held. What somebody holds is a statement about
		// now, and a review asking who approves here must not be handed
		// somebody whose grant a change of mode set aside.
		if !held.Effective {
			continue
		}
		if role != "" && held.Role != role {
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

// stores builds the pair over db, or says this process has no database.
func stores(a Administering, db bun.IDB) (*access.Store, *catalog.Store, error) {
	if a.Access == nil || a.Catalog == nil || db == nil {
		return nil, nil, noDatabase(a.Logger)
	}
	store, names := a.Access(db), a.Catalog(db)
	if store == nil || names == nil {
		return nil, nil, noDatabase(a.Logger)
	}
	return store, names, nil
}
