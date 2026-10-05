// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// Pipeline keys.
//
// A different noun from a person and a different lifetime, and the one act
// here that hands out a new way into the deployment — which is worth being
// able to find on its own rather than in the middle of the people endpoints.
func registerKeys(api huma.API, a core.Administering) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-keys", Method: http.MethodGet, Path: "/v1/keys",
		Summary: "List API keys",
		Description: "Which credentials exist, what each may send, when it was last used and " +
			"whether it still works. The secrets are not here and cannot be: what is stored is a digest.",
		Tags: []string{"Administration"},
	}, core.DeploymentWide, ""), func(ctx context.Context, _ *struct{}) (*core.ListOutput[KeyBody], error) {
		store, names, err := core.Administerable(ctx, a, a.Handle())
		if err != nil {
			return nil, err
		}
		keys, err := store.Keys(ctx)
		if err != nil {
			return nil, core.WentWrong(a.Logger, "cannot list credentials", err)
		}

		out := &core.ListOutput[KeyBody]{}
		out.Body.Items = make([]KeyBody, 0, len(keys))
		for _, key := range keys {
			body := KeyBody{
				Name: key.Name, Withdrawn: key.RevokedAt != nil,
				CreatedAt: key.CreatedAt.UTC().Format(timeFormat),
			}
			// The address, because create-key resolves this field through
			// ProductByName — and the Stream and Variant fields beside it
			// already answer the address. A listing that cannot be used to
			// remake what it lists is a listing of something else.
			product, err := names.ProductByID(ctx, key.ProductID)
			if err != nil {
				return nil, core.WentWrong(a.Logger, "cannot list credentials", err)
			}
			body.Product = product.Name
			if product.DisplayName != product.Name {
				body.ProductDisplayName = product.DisplayName
			}
			// The whole narrowing, not only the product it names. "any
			// branch, any variant" and "one release only" are different
			// credentials, and a list that renders both the same way cannot be
			// used to decide which one to withdraw. A read that fails answers
			// the whole listing with an error for the same reason: a pinned key
			// listed unscoped is the wrong credential to withdraw.
			if key.StreamID != nil {
				stream, err := names.StreamByID(ctx, *key.StreamID)
				if err != nil {
					return nil, core.WentWrong(a.Logger, "cannot list credentials", err)
				}
				body.Stream = stream.Name
			}
			if key.VariantID != nil {
				variant, err := names.VariantByID(ctx, *key.VariantID)
				if err != nil {
					return nil, core.WentWrong(a.Logger, "cannot list credentials", err)
				}
				body.Variant = variant.Name
			}
			if key.LastUsedAt != nil {
				body.LastUsedAt = key.LastUsedAt.UTC().Format(timeFormat)
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		return out, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "create-key", Method: http.MethodPost, Path: "/v1/keys",
		Summary: "Create an API key",
		Description: "Creates a credential a build may send scans with, and returns its secret. " +
			"The secret is shown once and stored hashed: a credential store that can hand back " +
			"what it holds gives up every pipeline's key with a copy of the database.\n\n" +
			"Requires a session. A credential cannot create another, and a key created by " +
			"one would outlive it.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusCreated,
	}, core.DeploymentWide, ""), func(ctx context.Context, in *struct {
		Body KeyBody
	}) (*core.DeclaredOutput[KeyBody], error) {
		var name, secret string
		if err := core.Changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
			store, names, err := mintable(ctx, a, tx)
			if err != nil {
				return err
			}

			product, err := names.ProductByName(ctx, in.Body.Product)
			if err != nil {
				return core.Undeclared(a.Logger, err, "that product could not be looked up")
			}
			scope := access.Scope{ProductID: product.ID}

			// Each lookup names the field whose read failed, so a fault
			// reading the branch is not reported as a fault reading the
			// product. A name that is simply not declared never reaches this
			// string: undeclared answers those from the error, which already
			// carries the name and what it was.
			if in.Body.Stream != "" {
				stream, err := names.StreamByName(ctx, product.ID, in.Body.Stream)
				if err != nil {
					return core.Undeclared(a.Logger, err, "that branch or tag could not be looked up")
				}
				scope.StreamID = &stream.ID
			}
			if in.Body.Variant != "" {
				variant, err := names.VariantByName(ctx, product.ID, in.Body.Variant)
				if err != nil {
					return core.Undeclared(a.Logger, err, "that variant could not be looked up")
				}
				scope.VariantID = &variant.ID
			}

			key, minted, err := store.NewKey(ctx, in.Body.Name, scope)
			switch {
			case database.IsDuplicate(err):
				return huma.Error409Conflict("a key in force already has that name")
			case errors.Is(err, access.ErrNoKeyName):
				return huma.Error422UnprocessableEntity(err.Error())
			case err != nil:
				return core.WentWrong(a.Logger, "cannot issue a credential", err)
			}
			name, secret = key.Name, minted
			// Its reach, never the secret or its digest: the trail is
			// read by whoever may administer, and a credential store that
			// hands back what it holds is what storing a digest exists to
			// avoid.
			if err := core.Noted(ctx, tx, trail.Credential, key.Name,
				nil, trail.Said(keyScope(in.Body), true)); err != nil {
				return core.NotRecorded(a.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return core.Answer(true, KeyBody{
			Name: name, Product: in.Body.Product, Stream: in.Body.Stream,
			Variant: in.Body.Variant, Secret: secret,
		}), nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "revoke-key", Method: http.MethodDelete, Path: "/v1/keys/{name}",
		Summary: "Withdraw an API key",
		Description: "Stops it working, without removing the record of what it sent. Revoking one " +
			"credential leaves every other pipeline running.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusNoContent,
	}, core.DeploymentWide, ""), func(ctx context.Context, in *struct {
		Name string `path:"name"`
	}) (*struct{}, error) {
		if err := core.Changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
			store, _, err := core.Administerable(ctx, a, tx)
			if err != nil {
				return err
			}
			keys, err := store.Keys(ctx)
			if err != nil {
				return core.WentWrong(a.Logger, "cannot read the credentials", err)
			}
			named := access.KeyName(in.Name)
			for _, key := range keys {
				if key.Name != named || key.RevokedAt != nil {
					continue
				}
				switch err := store.Revoke(ctx, key.ID); {
				case errors.Is(err, access.ErrNothingMatched):
					return core.NoSuchKey()
				case err != nil:
					return core.WentWrong(a.Logger, "cannot withdraw the credential", err)
				}
				if err := core.Noted(ctx, tx, trail.Credential, key.Name,
					trail.Said("in force", true), nil); err != nil {
					return core.NotRecorded(a.Logger, err)
				}
				return nil
			}
			return core.NoSuchKey()
		}); err != nil {
			return nil, err
		}
		return nil, nil
	})
}

// keyScope spells what a credential may send, for the trail.
//
// The whole scope rather than the product alone: "any branch, any variant" and
// "one release only" are different credentials, and a record that spells both
// the same way cannot be used to decide whether the one that was minted was
// the one that was meant.
func keyScope(key KeyBody) string {
	scope := key.Product
	if key.Stream != "" {
		scope += " · " + key.Stream
	}
	if key.Variant != "" {
		scope += " · " + key.Variant
	}
	return scope
}
