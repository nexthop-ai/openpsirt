package httpapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// Pipeline keys.
//
// A different noun from a person and a different lifetime, and the one act
// here that hands out a new way into the deployment — which is worth being
// able to find on its own rather than in the middle of the people endpoints.
func registerKeys(api huma.API, a Administering) {
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
			// The address, because create-key resolves this field through
			// ProductByName — and the Stream and Variant fields beside it
			// already answer the address. A listing that cannot be used to
			// remake what it lists is a listing of something else.
			if product, err := names.ProductByID(ctx, key.ProductID); err == nil {
				body.Product = product.Name
				if product.DisplayName != product.Name {
					body.ProductDisplayName = product.DisplayName
				}
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
			return nil, undeclared(a.Logger, err, "that product could not be looked up")
		}
		scope := access.Scope{ProductID: product.ID}

		if in.Body.Stream != "" {
			stream, err := names.StreamByName(ctx, product.ID, in.Body.Stream)
			if err != nil {
				return nil, undeclared(a.Logger, err, "that product could not be looked up")
			}
			scope.StreamID = &stream.ID
		}
		if in.Body.Variant != "" {
			variant, err := names.VariantByName(ctx, product.ID, in.Body.Variant)
			if err != nil {
				return nil, undeclared(a.Logger, err, "that product could not be looked up")
			}
			scope.VariantID = &variant.ID
		}

		key, secret, err := store.NewKey(ctx, in.Body.Name, scope)
		if err != nil {
			return nil, wentWrong(a.Logger, "cannot issue a credential", err)
		}
		// What it may send, never the secret or its digest: the trail is read
		// by whoever may administer, and a credential store that hands back
		// what it holds is what storing a digest exists to avoid.
		noteAdminChange(ctx, a, trail.Credential, key.Name,
			nil, trail.Said(keyScope(in.Body), true))
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
