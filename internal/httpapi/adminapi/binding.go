// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// ModeBody is where this deployment's roles come from.
type ModeBody struct {
	Mode string `json:"mode" enum:"direct,group-bound" doc:"Whether an administrator assigns roles or provider groups derive them"`
}

// BindingBody is a provider group bound to a role.
type BindingBody struct {
	Group string `json:"group" minLength:"1" maxLength:"191" doc:"The group exactly as the provider names it: a team slug, or a claim value. Matched with its capitals"`
	// Product is absent where the binding is held on every product, and where
	// it carries something held over the deployment rather than on a product.
	Product string `json:"product,omitempty" doc:"The product the role is held on, by the name that addresses it. Absent for a role held on every product, and for admin and audit"`
	// ProductDisplayName is the label shown beside it, for the reason HeldBody
	// carries one.
	ProductDisplayName string          `json:"product_name,omitempty" doc:"The product's display name, or its name where it has none. Absent where no product of that name is declared yet"`
	Role               core.RoleOrOver `json:"role" doc:"The role membership of this group grants"`
}

func registerBindings(api huma.API, a core.Administering, settings func(bun.IDB) *setting.Store) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "get-role-mode", Method: http.MethodGet, Path: "/v1/roles/mode",
		Summary: "Get the role assignment mode",
		Description: "Says where roles come from here: assigned by an administrator, or derived " +
			"from the groups an identity provider reports.\n\n" +
			"One mode for the whole deployment, never both. It is group-bound exactly when " +
			"`OPENPSIRT_GROUP_ROLES` maps a group, and changes only when that setting does.",
		Tags: []string{"Administration"},
	}, core.DeploymentRecords, ""), func(ctx context.Context, _ *struct{}) (*struct{ Body ModeBody }, error) {
		if _, _, err := readable(ctx, a, a.Handle()); err != nil {
			return nil, err
		}
		store := settings(a.Handle())
		if store == nil {
			return nil, core.NoDatabase(a.Logger)
		}
		stored, _, err := store.Get(ctx, setting.RoleMode)
		if err != nil {
			return nil, core.WentWrong(a.Logger, "cannot read where roles come from", err)
		}
		return &struct{ Body ModeBody }{Body: ModeBody{Mode: string(access.AsMode(stored))}}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-bindings", Method: http.MethodGet, Path: "/v1/roles/bindings",
		Summary: "List group-to-role bindings",
		Description: "Lists every group-to-role mapping, and the groups that administer or " +
			"audit.\n\n" +
			"The mappings are the ones `OPENPSIRT_GROUP_ROLES` states, applied when the " +
			"deployment starts. Nothing here changes them. In group-bound mode a mapping is the " +
			"advance authorization: somebody arriving for the first time in a mapped group is " +
			"admitted, and somebody in none is refused.",
		Tags: []string{"Administration"},
	}, core.DeploymentRecords, ""), func(ctx context.Context, _ *struct{}) (*core.ListOutput[BindingBody], error) {
		rights, _, err := readable(ctx, a, a.Handle())
		if err != nil {
			return nil, err
		}

		mappings, err := rights.Mappings(ctx)
		if err != nil {
			return nil, core.WentWrong(a.Logger, "cannot list the group bindings", err)
		}
		products, err := productLabels(ctx, a)
		if err != nil {
			return nil, err
		}

		out := &core.ListOutput[BindingBody]{}
		out.Body.Items = make([]BindingBody, 0, len(mappings))
		for _, mapping := range mappings {
			out.Body.Items = append(out.Body.Items, BindingBody{
				Group: mapping.Group, Product: mapping.Product,
				ProductDisplayName: products[mapping.Product],
				Role:               core.RoleOrOver(mapping.Grants),
			})
		}
		return out, nil
	})
}

// productLabels maps each product's name to the label shown beside it.
func productLabels(ctx context.Context, a core.Administering) (map[string]string, error) {
	products, err := productNames(ctx, a)
	if err != nil {
		return nil, err
	}
	by := make(map[string]string, len(products))
	for _, product := range products {
		by[product.Address] = product.Display
	}
	return by, nil
}

// roleModeIn reads where roles actually come from, against whichever handle it
// is given — which is the transaction deciding, rather than this.
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

// productNames maps product rows to the names bindings state them by.
//
// The address is the one a grant states and the one every matching write
// resolves. Publishing the display name there has the interface's Withdraw
// send back a word that matches no row, so a role on a product whose display
// name is more than a recapitalization is granted and not withdrawn.
func productNames(ctx context.Context, a core.Administering) (map[int64]core.Named, error) {
	names := a.Catalog(a.Handle())
	// Every product, because this is naming the ones grants already refer to
	// rather than answering anybody about them. The caller was authorized for
	// that before reaching here.
	//
	// Retired ones included: a role held against one is still held, and the
	// offered list leaves them out.
	products, err := names.EveryProduct(ctx)
	if err != nil {
		return nil, core.WentWrong(a.Logger, "cannot read the products roles are held against", err)
	}
	by := map[int64]core.Named{}
	for _, product := range products {
		by[product.ID] = core.Named{
			Address: product.Name, Display: catalog.Shown(product.DisplayName, product.Name),
		}
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
func registerRevocation(api huma.API, a core.Administering) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-all-tokens", Method: http.MethodGet, Path: "/v1/people/tokens",
		Summary: "List all users' API tokens",
		Description: "Lists every personal token in the deployment, whose it is, what it may " +
			"send and when it was last used.\n\n" +
			"Without it a stale token is found only when somebody leaves and nobody knows what " +
			"breaks if it is turned off.",
		Tags: []string{"Administration"},
	}, core.DeploymentWide, ""), func(ctx context.Context, _ *struct{}) (*core.ListOutput[TokenBody], error) {
		rights, names, err := core.Administerable(ctx, a, a.Handle())
		if err != nil {
			return nil, err
		}
		tokens, err := rights.AllTokens(ctx)
		if err != nil {
			return nil, core.WentWrong(a.Logger, "cannot list the tokens", err)
		}
		people, _, err := rights.People(ctx)
		if err != nil {
			return nil, core.WentWrong(a.Logger, "cannot read whose tokens these are", err)
		}
		owners := map[int64]string{}
		for _, person := range people {
			owners[person.ID] = person.Identity
		}
		return tokenList(ctx, a.Logger, names, tokens, owners)
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "revoke-anyones-token", Method: http.MethodDelete,
		Path:    "/v1/people/{identity}/tokens/{name}",
		Summary: "Withdraw another user's API token",
		Description: "Revokes one person's token on their behalf. It stops working immediately; " +
			"the record of what it sent stays.\n\n" +
			"An owner withdraws their own through their own token paths. This is for the ones " +
			"whose owner is no longer here to do it.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusNoContent,
	}, core.DeploymentWide, ""), func(ctx context.Context, in *struct {
		Identity string `path:"identity"`
		Name     string `path:"name"`
	}) (*struct{}, error) {
		if err := core.Changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
			rights, _, err := core.Administerable(ctx, a, tx)
			if err != nil {
				return err
			}
			person, err := rights.ByIdentity(ctx, in.Identity)
			if err != nil {
				return core.Absent(a.Logger, err, "that person could not be looked up",
					core.NoSuchPerson)
			}
			token, err := rights.TokenByName(ctx, person.ID, in.Name)
			if err != nil {
				return core.Absent(a.Logger, err, "that token could not be looked up",
					func() error {
						return huma.Error404NotFound("they hold no token called that")
					})
			}
			switch err := rights.RevokeToken(ctx, token.ID); {
			case errors.Is(err, access.ErrNothingMatched):
				return huma.Error404NotFound("they hold no token in force called that")
			case err != nil:
				return core.WentWrong(a.Logger, "cannot revoke a token", err)
			}
			if err := core.Noted(ctx, tx, trail.Credential, person.Identity+" · "+token.Name,
				trail.Said("in force", true), nil); err != nil {
				return core.NotRecorded(a.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "end-sessions", Method: http.MethodDelete, Path: "/v1/people/{identity}/sessions",
		Summary: "End all of a user's sessions",
		Description: "Takes effect at once, whichever copy of the application answers next. Roles " +
			"and group mappings are re-read at sign-in, so withdrawing one takes effect then; this " +
			"is what makes somebody leaving immediate instead.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusNoContent,
	}, core.DeploymentWide, ""), func(ctx context.Context, in *struct {
		Identity string `path:"identity"`
	}) (*struct{}, error) {
		if err := core.Changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
			rights, _, err := core.Administerable(ctx, a, tx)
			if err != nil {
				return err
			}
			person, err := rights.ByIdentity(ctx, in.Identity)
			if err != nil {
				return core.Absent(a.Logger, err, "that person could not be looked up", core.NoSuchPerson)
			}
			if err := rights.EndSessionsFor(ctx, person.ID); err != nil {
				return core.WentWrong(a.Logger, "cannot end the sessions", err)
			}
			if err := core.Noted(ctx, tx, trail.Account, person.Identity,
				nil, trail.Said("sessions ended", true)); err != nil {
				return core.NotRecorded(a.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	})
}
