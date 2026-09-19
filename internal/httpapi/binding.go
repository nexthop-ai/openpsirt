package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// ModeBody is where this deployment's roles come from.
type ModeBody struct {
	Mode string `json:"mode" enum:"direct,group-bound" doc:"Whether an administrator assigns roles or provider groups derive them"`
}

// BindingBody is a provider group bound to a role.
type BindingBody struct {
	Group string `json:"group" minLength:"1" maxLength:"191" doc:"The group exactly as the provider names it — a team slug, or a claim value. Matched with its capitals, because it is the provider's identity rather than a name typed here"`
	// Product is absent where the binding carries administration, which is
	// global rather than held against a product.
	Product string `json:"product,omitempty" doc:"The product the role is held against, by the name that addresses it"`
	// ProductDisplayName is what to show beside it, for the reason HeldBody
	// carries one: unbind resolves the field above.
	ProductDisplayName string `json:"product_display_name,omitempty" doc:"That product's display name, where it was declared with one"`
	Role               string `json:"role" enum:"approver,assigner,public-read,private-read,public-triage,private-triage,admin,audit" doc:"The roles membership of this group grants"`
}

func registerBindings(api huma.API, a Administering, settings func(bun.IDB) *setting.Store) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-role-mode", Method: http.MethodGet, Path: "/v1/roles/mode",
		Summary: "Get the role assignment mode",
		Description: "Says where roles come from here: assigned by an administrator, or derived " +
			"from the groups an identity provider reports.\n\n" +
			"One mode for the whole deployment, never both. A hybrid would need a precedence " +
			"rule for somebody holding one role from a team and another directly, which is how a " +
			"stale assignment outlives somebody's removal from the team it was shadowing.",
		Tags: []string{"Administration"},
	}, deploymentRecords, ""), func(ctx context.Context, _ *struct{}) (*struct{ Body ModeBody }, error) {
		if _, _, err := readable(ctx, a, a.handle()); err != nil {
			return nil, err
		}
		store := settings(a.handle())
		if store == nil {
			return nil, noDatabase(a.Logger)
		}
		stored, _, err := store.Get(ctx, setting.RoleMode)
		if err != nil {
			return nil, wentWrong(a.Logger, "cannot read where roles come from", err)
		}
		return &struct{ Body ModeBody }{Body: ModeBody{Mode: string(access.AsMode(stored))}}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "set-role-mode", Method: http.MethodPut, Path: "/v1/roles/mode",
		Summary: "Set the role assignment mode",
		Description: "Turning group binding on sets assignments aside rather than deleting them, " +
			"and turning it off restores them — so trying it is not a one-way door. Refused if it " +
			"would leave nobody able to administer this deployment.",
		Tags: []string{"Administration"},
	}, deploymentWide, ""), func(ctx context.Context, in *struct{ Body ModeBody }) (*struct{ Body ModeBody }, error) {
		wanted := access.AsMode(in.Body.Mode)
		if string(wanted) != in.Body.Mode {
			return nil, huma.Error422UnprocessableEntity("that is not a way for roles to be assigned")
		}

		if err := changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
			rights, _, err := administerable(ctx, a, tx)
			if err != nil {
				return err
			}
			store := settings(tx)
			if store == nil {
				return noDatabase(a.Logger)
			}

			// Asked before the switch rather than after. A deployment that has
			// locked itself out of its own administration has one route back —
			// editing the database by hand — and refusing the change is
			// cheaper than discovering that afterwards.
			can, err := rights.CanAdminister(ctx, wanted)
			if err != nil {
				return wentWrong(a.Logger, "cannot tell who would administer", err)
			}
			if !can {
				return huma.Error409Conflict(
					"nothing would administer this deployment in that mode: bind a group to admin, " +
						"or name somebody in configuration, before switching")
			}
			// And something has to be able to say what groups somebody is in.
			// A provider configured without a source of groups reports every
			// arrival as belonging to nothing, so in this mode nobody derives
			// any role — which is the same lockout the check above prevents,
			// arriving by the other door and looking like a working deployment
			// that admits nobody.
			if wanted == access.GroupBound && a.Groups != nil && !a.Groups() {
				return huma.Error409Conflict(
					"nothing here can say which groups somebody is in, so in that mode " +
						"nobody would hold any role: configure a groups claim on the provider, " +
						"an organization for GitHub sign-in, or a trusted proxy that reports " +
						"groups, before switching")
			}

			if err := rights.SwitchTo(ctx, wanted); err != nil {
				return wentWrong(a.Logger, "cannot change where roles come from", err)
			}
			// Changed rather than set, because what it held is not derivable
			// afterwards and is half of what the trail is asked: read in a
			// statement of its own it would be the value at some earlier
			// moment.
			before, had, err := store.Change(ctx, setting.RoleMode, string(wanted))
			if err != nil {
				return recording(a.Logger, "cannot record where roles come from", err)
			}
			if err := noted(ctx, tx, trail.Setting, setting.RoleMode,
				trail.Said(before, had), trail.Said(string(wanted), true)); err != nil {
				return notRecorded(a.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct{ Body ModeBody }{Body: ModeBody{Mode: string(wanted)}}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-bindings", Method: http.MethodGet, Path: "/v1/roles/bindings",
		Summary: "List group-to-role bindings",
		Description: "Lists every group-to-role mapping, and the groups that administer or " +
			"audit.\n\n" +
			"In group-bound mode a mapping is the advance authorization: somebody arriving for " +
			"the first time in a mapped group is admitted, and somebody in none is refused.",
		Tags: []string{"Administration"},
	}, deploymentRecords, ""), func(ctx context.Context, _ *struct{}) (*listOutput[BindingBody], error) {
		rights, _, err := readable(ctx, a, a.handle())
		if err != nil {
			return nil, err
		}

		bindings, err := rights.Bindings(ctx)
		if err != nil {
			return nil, wentWrong(a.Logger, "cannot list the group bindings", err)
		}
		products, err := productNames(ctx, a)
		if err != nil {
			return nil, err
		}

		out := &listOutput[BindingBody]{}
		out.Body.Items = make([]BindingBody, 0, len(bindings))
		for _, binding := range bindings {
			held := products[binding.ProductID]
			out.Body.Items = append(out.Body.Items, BindingBody{
				Group: binding.GroupName, Product: held.Address,
				ProductDisplayName: held.Display, Role: string(binding.Role),
			})
		}

		// Listed after the per-product bindings, each under the word a
		// request names it by.
		for _, over := range access.OverTheDeployment() {
			groups, err := rights.GroupsOver(ctx, over)
			if err != nil {
				return nil, wentWrong(a.Logger,
					"cannot list what groups hold over this deployment", err)
			}
			for _, group := range groups {
				out.Body.Items = append(out.Body.Items,
					BindingBody{Group: group, Role: string(over)})
			}
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "bind-group", Method: http.MethodPost, Path: "/v1/roles/bindings",
		Summary: "Bind an identity-provider group to a role",
		Description: "Maps one identity-provider group to one role, so that everybody in that " +
			"group holds it from their next sign-in.\n\n" +
			"Every role names the product it applies to. Administration and the audit " +
			"permission are bound without one, because they are held over the deployment " +
			"rather than against a product.\n\n" +
			"The group is matched exactly, including its capitals. It is an identity the " +
			"provider hands over rather than a name anybody here types, so it is stored as " +
			"given and compared as given — `Security` and `security` are two bindings, and a " +
			"binding whose capitals do not match what the provider sends grants nothing. The " +
			"refusal somebody then meets says only that they are not authorized, so check the " +
			"spelling against the provider rather than against what looks right.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusCreated,
	}, deploymentWide, ""), func(ctx context.Context, in *struct{ Body BindingBody }) (*struct{ Body BindingBody }, error) {
		if err := changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
			rights, names, err := administerable(ctx, a, tx)
			if err != nil {
				return err
			}

			if over, deployment := overTheDeployment(in.Body.Role); deployment {
				if in.Body.Product != "" {
					return huma.Error422UnprocessableEntity(
						"that is held over the deployment rather than against a product, " +
							"so a group bound to it names none")
				}
				if err := rights.BindOver(ctx, in.Body.Group, over); err != nil {
					return wentWrong(a.Logger,
						"cannot bind a group to something held over this deployment", err)
				}
				if err := noted(ctx, tx, trail.Role, in.Body.Group+" over this deployment",
					nil, trail.Said(string(over), true)); err != nil {
					return notRecorded(a.Logger, err)
				}
				return nil
			}

			role := access.Role(in.Body.Role)
			if !role.Valid() {
				return huma.Error422UnprocessableEntity("that is not a role")
			}
			product, err := names.ProductByName(ctx, in.Body.Product)
			if err != nil {
				return absent(a.Logger, err, "that product could not be looked up", noSuchProduct)
			}
			if err := rights.Bind(ctx, in.Body.Group, product.ID, role); err != nil {
				return wentWrong(a.Logger, "cannot bind a group", err)
			}
			// Named by the product's address rather than its display name,
			// because that is what a binding states and what the withdrawal
			// resolves.
			if err := noted(ctx, tx, trail.Role, in.Body.Group+" on "+product.Name,
				nil, trail.Said(in.Body.Role, true)); err != nil {
				return notRecorded(a.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct{ Body BindingBody }{Body: in.Body}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "unbind-group", Method: http.MethodDelete, Path: "/v1/roles/bindings",
		Summary: "Remove a group-to-role binding",
		Description: "Removes one group-to-role mapping.\n\n" +
			"It takes effect at each member's next sign-in, because group membership is read at " +
			"sign-in and never again. To cut somebody off now, end their sessions.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Group   string `query:"group" required:"true"`
		Product string `query:"product"`
		Role    string `query:"role" required:"true"`
	}) (*struct{}, error) {
		if err := changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
			rights, names, err := administerable(ctx, a, tx)
			if err != nil {
				return err
			}

			if over, deployment := overTheDeployment(in.Role); deployment {
				// Administration is refused where it would leave nobody able
				// to administer, for the same reason the mode change is — and
				// decided inside the write, so a refusal rolls the delete back
				// rather than being undone by a second statement that could
				// itself fail. Nothing else held over the deployment can lock
				// anybody out, so nothing else is counted.
				unbind := func() error { return rights.UnbindOver(ctx, in.Group, over) }
				if over == access.Administers {
					unbind = func() error {
						return rights.UnbindAdminIfOthersRemain(ctx, in.Group, roleModeIn(settings))
					}
				}
				switch err := unbind(); {
				case errors.Is(err, access.ErrLastAdministrator):
					return huma.Error409Conflict(
						"that was the last thing granting administration: bind another group " +
							"to admin, or name somebody in configuration, first")
				case errors.Is(err, access.ErrNothingMatched):
					// Nothing was bound, so nothing was withdrawn — and the
					// check that would have refused this passed *because* the
					// delete did nothing.
					return noSuchGrant()
				case err != nil:
					return wentWrong(a.Logger,
						"cannot unbind a group from what it holds over this deployment", err)
				}
				if err := noted(ctx, tx, trail.Role, in.Group+" over this deployment",
					trail.Said(string(over), true), nil); err != nil {
					return notRecorded(a.Logger, err)
				}
				return nil
			}

			product, err := names.ProductByName(ctx, in.Product)
			if err != nil {
				return absent(a.Logger, err, "that product could not be looked up", noSuchProduct)
			}
			role := access.Role(in.Role)
			if !role.Valid() {
				return huma.Error422UnprocessableEntity("that is not a role")
			}
			switch err := rights.Unbind(ctx, in.Group, product.ID, role); {
			case errors.Is(err, access.ErrNothingMatched):
				return noSuchGrant()
			case err != nil:
				return wentWrong(a.Logger, "cannot unbind a group", err)
			}
			if err := noted(ctx, tx, trail.Role, in.Group+" on "+product.Name,
				trail.Said(in.Role, true), nil); err != nil {
				return notRecorded(a.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	})
}

// overTheDeployment reads a binding's role as something held over the
// deployment, or says it is not one.
//
// Two words in the role field name nothing held against a product:
// administering this deployment, and auditing what it is set to. They are in
// that field because a binding maps a group to one thing somebody holds, and
// splitting them out would make a caller decide which of two shapes to send.
func overTheDeployment(role string) (access.Over, bool) {
	over := access.Over(role)
	return over, over.Valid()
}

// roleModeIn reads where roles actually come from, against whichever handle it
// is given — which is the transaction deciding, rather than this.
//
// Asked because unbinding the last administrators' group matters while roles
// are derived from groups and does not while they are assigned: refusing in
// both would leave a deployment that has never turned group binding on unable
// to tidy up a mapping it is not using.
func roleModeIn(settings func(bun.IDB) *setting.Store) func(context.Context, bun.IDB) (access.Mode, error) {
	return func(ctx context.Context, db bun.IDB) (access.Mode, error) {
		if settings(db) == nil {
			return access.Direct, nil
		}
		stored, _, err := setting.NewStore(db).Get(ctx, setting.RoleMode)
		if err != nil {
			return "", fmt.Errorf("read where roles come from: %w", err)
		}
		return access.AsMode(stored), nil
	}
}

// named is the two names a product answers to, which are different strings
// wherever an operator declared a display name.
//
// Both, because a body carrying a role or a binding needs each for a different
// purpose: the address is what the withdraw beside the row resolves, and the
// display name is what the row says. Published as one pair rather than fetched
// twice, so the two cannot come back from different reads.
type named struct {
	// Address is what ProductByName matches: lowercased and trimmed.
	Address string
	// Display is what the operator declared, empty where it is the address
	// again.
	Display string
}

// productNames maps product rows to the names bindings state them by.
//
// The address is the one a binding states and the one every matching write
// resolves. Publishing the display name there made the interface's Withdraw
// send back a word that matched no row, so a role on a product whose display
// name is not merely a recapitalization could be granted and not withdrawn.
func productNames(ctx context.Context, a Administering) (map[int64]named, error) {
	names := a.Catalog(a.handle())
	// Every product, because this is naming the ones bindings already refer
	// to rather than answering anybody about them. The caller is administering
	// group bindings and was authorized for that before reaching here.
	products, err := names.Products(ctx, access.Everything("naming products for bindings"))
	if err != nil {
		return nil, wentWrong(a.Logger, "cannot read the products roles are held against", err)
	}
	by := map[int64]named{}
	for _, product := range products {
		one := named{Address: product.Name}
		if product.DisplayName != product.Name {
			one.Display = product.DisplayName
		}
		by[product.ID] = one
	}
	return by, nil
}

// registerRevocation mounts what an administrator needs to cut access off now
// rather than at the next sign-in.
//
// Group membership is only ever re-read when somebody signs in, so withdrawing
// a role or a mapping takes effect at their next one. That is the right
// mechanism for drift and the wrong one for somebody leaving. Ending their
// sessions is what makes the deliberate case immediate.
func registerRevocation(api huma.API, a Administering) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-all-tokens", Method: http.MethodGet, Path: "/v1/people/tokens",
		Summary: "List all users' API tokens",
		Description: "Lists every personal token in the deployment, whose it is, what it may " +
			"send and when it was last used.\n\n" +
			"Without it a stale token is found only when somebody leaves and nobody knows what " +
			"breaks if it is turned off.",
		Tags: []string{"Administration"},
	}, deploymentWide, ""), func(ctx context.Context, _ *struct{}) (*listOutput[TokenBody], error) {
		rights, names, err := administerable(ctx, a, a.handle())
		if err != nil {
			return nil, err
		}
		tokens, err := rights.AllTokens(ctx)
		if err != nil {
			return nil, wentWrong(a.Logger, "cannot list the tokens", err)
		}
		people, _, err := rights.People(ctx)
		if err != nil {
			return nil, wentWrong(a.Logger, "cannot read whose tokens these are", err)
		}
		owners := map[int64]string{}
		for _, person := range people {
			owners[person.ID] = person.Identity
		}
		return tokenList(ctx, names, tokens, owners)
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "revoke-anyones-token", Method: http.MethodDelete,
		Path:    "/v1/people/{identity}/tokens/{name}",
		Summary: "Withdraw another user's API token",
		Description: "Revokes one person's token on their behalf. It stops working immediately; " +
			"the record of what it sent stays.\n\n" +
			"An owner withdraws their own through their own token paths. This is for the ones " +
			"whose owner is no longer here to do it.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Identity string `path:"identity"`
		Name     string `path:"name"`
	}) (*struct{}, error) {
		if err := changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
			rights, _, err := administerable(ctx, a, tx)
			if err != nil {
				return err
			}
			person, err := rights.ByIdentity(ctx, in.Identity)
			if err != nil {
				return absent(a.Logger, err, "that person could not be looked up",
					noSuchPerson)
			}
			token, err := rights.TokenByName(ctx, person.ID, in.Name)
			if err != nil {
				return absent(a.Logger, err, "that token could not be looked up",
					func() error {
						return huma.Error404NotFound("they hold no token called that")
					})
			}
			if err := rights.RevokeToken(ctx, token.ID); err != nil {
				return wentWrong(a.Logger, "cannot revoke a token", err)
			}
			if err := noted(ctx, tx, trail.Credential, in.Identity+" · "+in.Name,
				trail.Said("in force", true), nil); err != nil {
				return notRecorded(a.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "end-sessions", Method: http.MethodDelete, Path: "/v1/people/{identity}/sessions",
		Summary: "End all of a user's sessions",
		Description: "Takes effect at once, whichever copy of the application answers next. Roles " +
			"and group mappings are re-read at sign-in, so withdrawing one takes effect then; this " +
			"is what makes somebody leaving immediate instead.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Identity string `path:"identity"`
	}) (*struct{}, error) {
		if err := changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
			rights, _, err := administerable(ctx, a, tx)
			if err != nil {
				return err
			}
			person, err := rights.ByIdentity(ctx, in.Identity)
			if err != nil {
				return noSuchPerson()
			}
			if err := rights.EndSessionsFor(ctx, person.ID); err != nil {
				return wentWrong(a.Logger, "cannot end the sessions", err)
			}
			if err := noted(ctx, tx, trail.Account, in.Identity,
				nil, trail.Said("sessions ended", true)); err != nil {
				return notRecorded(a.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	})
}
