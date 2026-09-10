package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
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
	body := &PersonBody{
		Identity: person.Identity, DisplayName: person.DisplayName, Admin: person.IsAdmin,
		Email: person.Email, EmailSource: string(person.EmailSource),
	}
	for _, door := range doors {
		body.SignsInBy = append(body.SignsInBy, SignInBody{
			Provider: door.Provider, Username: door.Username, Pinned: door.Subject != nil,
		})
	}
	for _, grant := range held {
		body.Holds = append(body.Holds, HeldBody{
			Product: named[grant.ProductID], Role: string(grant.Role),
			Effective: grant.Active, Source: string(grant.Source),
		})
	}
	body.SeesNothing = seesNothing(body.Holds)
	return body, nil
}

// Administering is what the endpoints for people and credentials need.
type Administering struct {
	Access  func() *access.Store
	Catalog func() *catalog.Store
	Logger  *slog.Logger
	// Mode says where roles come from, read per request because an
	// administrator can change it without a restart.
	Mode func(context.Context) access.Mode
	// Findings is what withdrawing somebody's last role on a product
	// needs: their work there goes back to the unassigned list rather than
	// staying where nobody can reach it. Nil where this process has no
	// database, and then nothing is released.
	Findings func() *finding.Store
	// Trail is where an administrative change is recorded. Nil where this
	// process has no database, and then nothing is recorded — which is the
	// same state as having no database to change anything in.
	Trail func() *trail.Store
}

// PersonBody is somebody who has been granted access.
type PersonBody struct {
	Identity    string `json:"identity" minLength:"1" maxLength:"191" doc:"What to call them here"`
	DisplayName string `json:"display_name,omitempty" doc:"What to show instead of the identity"`
	Admin       bool   `json:"admin,omitempty" doc:"Whether they administer this deployment"`
	// Provider and Username are how they will sign in. Recording somebody
	// without them records a person with access and no door to come through,
	// so they are required when somebody is first recorded.
	//
	// The username is what an administrator can type: a provider's own
	// identifier for somebody is not knowable until they have arrived, so the
	// authorization is written in the name and pinned to the identifier the
	// first time it is redeemed.
	Provider string `json:"provider,omitempty" doc:"Which sign-in path they will arrive by, such as proxy for a trusted header"`
	Username string `json:"username,omitempty" doc:"What that provider calls them. Defaults to the identity"`
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
	Admin       bool   `json:"admin,omitempty" doc:"Whether they administer this deployment"`
	Provider    string `json:"provider,omitempty" doc:"Which sign-in path they will arrive by, such as proxy for a trusted header"`
	Username    string `json:"username,omitempty" doc:"What that provider calls them. Defaults to the identity"`
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

// GrantBody is one role against one product, as a request states it.
type GrantBody struct {
	Product string `json:"product" minLength:"1" doc:"The product the role is held against"`
	Role    string `json:"role" enum:"approver,assigner,public-read,private-read,public-triage,private-triage" doc:"What they may do with it"`
}

// SignInBody is one way somebody may arrive.
type SignInBody struct {
	Provider string `json:"provider"`
	Username string `json:"username"`
	// Pinned says the provider's own identifier has been bound, which happens
	// at the first successful sign-in. Until then the authorization is still
	// waiting to be redeemed by whoever arrives under that name.
	Pinned bool `json:"pinned"`
}

// HeldBody is one role against one product.
type HeldBody struct {
	Product string `json:"product" minLength:"1" doc:"The product the role is held against"`
	Role    string `json:"role" enum:"approver,assigner,public-read,private-read,public-triage,private-triage" doc:"What they may do with it"`
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
	Product string `json:"product" minLength:"1" doc:"The product it may send scans for. Always required"`
	// Stream and Variant narrow it further. Either, both or neither may be
	// given: a key covering a whole product cannot imply which release an
	// upload is for, which is why an upload always states its own target.
	Stream  string `json:"stream,omitempty" doc:"Optionally, the one release it may send for"`
	Variant string `json:"variant,omitempty" doc:"Optionally, the one variant it may send for"`
	// Secret is returned when the credential is created, and never again.
	Secret     string `json:"secret,omitempty" doc:"Shown once, at creation. It is stored hashed and cannot be shown again"`
	LastUsedAt string `json:"last_used_at,omitempty" doc:"When it last sent something"`
	Withdrawn  bool   `json:"withdrawn,omitempty" doc:"Whether it has been withdrawn"`
}

func registerAdministration(api huma.API, a Administering) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-people", Method: http.MethodGet, Path: "/v1/people",
		Summary: "List users",
		Description: "Lists everybody who may sign in, with the roles each of them holds and " +
			"the products those apply to.\n\n" +
			"Nobody appears here by having authenticated. Access is granted in advance, so this " +
			"list is what an administrator has decided rather than who has turned up.",
		Tags: []string{"Administration"},
	}, deploymentWide, ""), func(ctx context.Context, _ *struct{}) (*listOutput[PersonBody], error) {
		store, _, err := administerable(ctx, a)
		if err != nil {
			return nil, err
		}
		people, held, err := store.People(ctx)
		if err != nil {
			return nil, wentWrong(a.Logger, "cannot list people", err)
		}

		named, err := productNames(ctx, a)
		if err != nil {
			return nil, err
		}

		out := &listOutput[PersonBody]{}
		out.Body.Items = make([]PersonBody, 0, len(people))
		for _, person := range people {
			body := PersonBody{
				Identity: person.Identity, DisplayName: person.DisplayName, Admin: person.IsAdmin,
			}
			doors, err := store.Identities(ctx, person.ID)
			if err != nil {
				return nil, wentWrong(a.Logger, "cannot read how they sign in", err)
			}
			for _, door := range doors {
				body.SignsInBy = append(body.SignsInBy, SignInBody{
					Provider: door.Provider, Username: door.Username, Pinned: door.Subject != nil,
				})
			}
			for _, grant := range held[person.ID] {
				body.Holds = append(body.Holds, HeldBody{
					Product: named[grant.ProductID], Role: string(grant.Role),
					Effective: grant.Active, Source: string(grant.Source),
				})
			}
			body.SeesNothing = seesNothing(body.Holds)
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
		store, names, err := mintable(ctx, a)
		if err != nil {
			return nil, err
		}

		_, lookupErr := store.ByIdentity(ctx, in.Body.Identity)
		created := lookupErr != nil

		// Recording somebody is not the same as recording how they sign in,
		// and access without a way to arrive is access nobody can use. So the
		// door is recorded with them, and a first recording that names none is
		// refused rather than half-done.
		provider := strings.TrimSpace(in.Body.Provider)
		username := strings.TrimSpace(in.Body.Username)
		if username == "" {
			username = strings.TrimSpace(in.Body.Identity)
		}
		if created && provider == "" {
			return nil, huma.Error422UnprocessableEntity(
				"say which provider they will sign in by, or they are somebody with access and no way to use it")
		}

		person, err := store.Ensure(ctx, in.Body.Identity, in.Body.DisplayName, in.Body.Admin)
		if err != nil {
			return nil, huma.Error400BadRequest(err.Error())
		}
		if created {
			noteAdminChange(ctx, a, trail.Account, in.Body.Identity, nil,
				trail.Said("recorded", true))
		}
		if provider != "" {
			if err := store.Claim(ctx, person.ID, provider, username); err != nil {
				return nil, asked(a.Logger, err)
			}
		}
		// Recorded here, so it outranks whatever a provider states
		// later . A request that says nothing about an address leaves
		// the stored one alone rather than clearing it: this endpoint
		// records somebody, and an omission is silence rather than an
		// instruction. An address stated is recorded; an address
		// stated as empty is cleared, which is how somebody comes off
		// mail without coming off the tool. A request that does not
		// mention one at all leaves the stored address alone: this
		// endpoint records somebody, and an omission is silence rather
		// than an instruction.
		if in.Body.Email != nil {
			if err := store.SetEmail(ctx, person.ID, *in.Body.Email, access.Recorded); err != nil {
				return nil, wentWrong(a.Logger, "where to reach them could not be recorded", err)
			}
		}

		if len(in.Body.Holds) > 0 {
			// Roles come from one place at a time. Assigning one while groups
			// decide would produce exactly the hybrid that has no answer to
			// "where did this access come from" — and worse than the drift
			// that rule anticipates, since nothing re-derives an assignment,
			// so it would outlive every group change without ever having had
			// a group behind it.
			if a.Mode != nil && a.Mode(ctx) == access.GroupBound {
				return nil, huma.Error409Conflict(
					"roles are derived from groups here, so they are granted by binding a group rather than a person")
			}
		}
		for _, hold := range in.Body.Holds {
			product, err := names.ProductByName(ctx, hold.Product)
			if err != nil {
				return nil, huma.Error404NotFound(err.Error())
			}
			if err := store.GrantRole(ctx, person.ID, product.ID, access.Role(hold.Role)); err != nil {
				return nil, huma.Error400BadRequest(err.Error())
			}
			noteAdminChange(ctx, a, trail.Role, in.Body.Identity+" on "+hold.Product,
				nil, trail.Said(hold.Role, true))
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
		return answer(created, *body), nil
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
		store, names, err := administerable(ctx, a)
		if err != nil {
			return nil, err
		}
		person, err := store.ByIdentity(ctx, in.Identity)
		if err != nil {
			return nil, noSuchPerson()
		}
		product, err := names.ProductByName(ctx, in.Product)
		if err != nil {
			return nil, huma.Error404NotFound(err.Error())
		}
		if err := store.Withdraw(ctx, person.ID, product.ID, access.Role(in.Role)); err != nil {
			return nil, wentWrong(a.Logger, "cannot withdraw the role", err)
		}
		noteAdminChange(ctx, a, trail.Role, in.Identity+" on "+in.Product,
			trail.Said(in.Role, true), nil)

		out := &struct {
			Body struct {
				Released int64 `json:"released" doc:"Findings handed back because that was their last role here"`
			}
		}{}
		// Asked after the withdrawal, so what it sees is what the withdrawal
		// left. Their last role here going is what turns their assigned work
		// into work nobody can reach.
		remaining, err := store.HoldsAnythingIn(ctx, person.ID, product.ID)
		if err != nil {
			return nil, wentWrong(a.Logger, "cannot read what they still hold", err)
		}
		if remaining || a.Findings == nil {
			return out, nil
		}
		findings := a.Findings()
		if findings == nil {
			return out, nil
		}
		released, err := findings.ReleaseIn(ctx, subject, person.PartyID, product.ID)
		if err != nil {
			return nil, wentWrong(a.Logger, "cannot hand back what they were dealing with", err)
		}
		out.Body.Released = released
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-keys", Method: http.MethodGet, Path: "/v1/keys",
		Summary: "List API keys",
		Description: "Which credentials exist, what each may send, when it was last used and " +
			"whether it still works. The secrets are not here and cannot be: what is stored is a digest.",
		Tags: []string{"Administration"},
	}, deploymentWide, ""), func(ctx context.Context, _ *struct{}) (*listOutput[KeyBody], error) {
		store, names, err := administerable(ctx, a)
		if err != nil {
			return nil, err
		}
		keys, err := store.Keys(ctx)
		if err != nil {
			return nil, wentWrong(a.Logger, "cannot list credentials", err)
		}

		out := &listOutput[KeyBody]{}
		out.Body.Items = make([]KeyBody, 0, len(keys))
		for _, key := range keys {
			body := KeyBody{Name: key.Name, Withdrawn: key.RevokedAt != nil}
			if product, err := names.ProductByID(ctx, key.ProductID); err == nil {
				body.Product = product.DisplayName
			}
			// What the key is narrowed to, not only which product it names.
			// "any branch, any variant" and "one release only" are different
			// credentials, and a list that renders both the same way cannot be
			// used to decide which one to withdraw.
			if key.StreamID != nil {
				if stream, err := names.StreamByID(ctx, *key.StreamID); err == nil {
					body.Stream = stream.Name
				}
			}
			if key.VariantID != nil {
				if variant, err := names.VariantByID(ctx, *key.VariantID); err == nil {
					body.Variant = variant.Name
				}
			}
			if key.LastUsedAt != nil {
				body.LastUsedAt = key.LastUsedAt.UTC().Format(timeFormat)
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "create-key", Method: http.MethodPost, Path: "/v1/keys",
		Summary: "Create an API key",
		Description: "Creates a credential a build may send scans with, and returns its secret. " +
			"The secret is shown once and stored hashed: a credential store that can hand back " +
			"what it holds gives up every pipeline's key with a copy of the database.\n\n" +
			"**Requires a session.** A credential cannot create another, and a key created by " +
			"one would outlive it.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusCreated,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Body KeyBody
	}) (*declaredOutput[KeyBody], error) {
		store, names, err := mintable(ctx, a)
		if err != nil {
			return nil, err
		}

		product, err := names.ProductByName(ctx, in.Body.Product)
		if err != nil {
			return nil, huma.Error404NotFound(err.Error())
		}
		scope := access.Scope{ProductID: product.ID}

		if in.Body.Stream != "" {
			stream, err := names.StreamByName(ctx, product.ID, in.Body.Stream)
			if err != nil {
				return nil, huma.Error404NotFound(err.Error())
			}
			scope.StreamID = &stream.ID
		}
		if in.Body.Variant != "" {
			variant, err := names.VariantByName(ctx, product.ID, in.Body.Variant)
			if err != nil {
				return nil, huma.Error404NotFound(err.Error())
			}
			scope.VariantID = &variant.ID
		}

		key, secret, err := store.NewKey(ctx, in.Body.Name, scope)
		if err != nil {
			return nil, wentWrong(a.Logger, "cannot issue a credential", err)
		}
		return answer(true, KeyBody{
			Name: key.Name, Product: in.Body.Product, Stream: in.Body.Stream,
			Variant: in.Body.Variant, Secret: secret,
		}), nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "revoke-key", Method: http.MethodDelete, Path: "/v1/keys/{name}",
		Summary: "Withdraw an API key",
		Description: "Stops it working, without removing the record of what it sent. Revoking one " +
			"credential leaves every other pipeline running.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Name string `path:"name"`
	}) (*struct{}, error) {
		store, _, err := administerable(ctx, a)
		if err != nil {
			return nil, err
		}
		keys, err := store.Keys(ctx)
		if err != nil {
			return nil, wentWrong(a.Logger, "cannot read the credentials", err)
		}
		for _, key := range keys {
			if key.Name != in.Name || key.RevokedAt != nil {
				continue
			}
			if err := store.Revoke(ctx, key.ID); err != nil {
				return nil, wentWrong(a.Logger, "cannot withdraw the credential", err)
			}
			noteAdminChange(ctx, a, trail.Credential, in.Name,
				trail.Said("in force", true), nil)
			return nil, nil
		}
		return nil, noSuchKey()
	})
}

// timeFormat is how a moment is reported.
const timeFormat = "2006-01-02T15:04:05Z"

// administerable refuses anybody who is not an administrator, and hands back
// what the endpoint needs.
//
// Managing who may do what is the one thing that must never be reachable by a
// role granted on a product: somebody who may triage a product must not be
// able to grant themselves more of it. mintable is administerable for the two
// acts that create a credential: a credential cannot create another.
func mintable(ctx context.Context, a Administering) (*access.Store, *catalog.Store, error) {
	if err := mintingCredentials(ctx); err != nil {
		return nil, nil, err
	}
	return administerable(ctx, a)
}

func administerable(ctx context.Context, a Administering) (*access.Store, *catalog.Store, error) {
	if err := administrating(ctx); err != nil {
		return nil, nil, err
	}
	if a.Access == nil || a.Catalog == nil {
		return nil, nil, noDatabase(a.Logger)
	}
	store, names := a.Access(), a.Catalog()
	if store == nil || names == nil {
		return nil, nil, noDatabase(a.Logger)
	}
	return store, names, nil
}
