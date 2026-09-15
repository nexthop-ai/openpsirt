package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// TokenBody is somebody's own credential for scripting.
type TokenBody struct {
	Name string `json:"name" minLength:"1" maxLength:"191" doc:"What its owner calls it"`
	// Product narrows it below its owner. What it reaches is the intersection,
	// so naming something they cannot read reaches nothing.
	Product string `json:"product,omitempty" doc:"Optionally, the one product it may reach, by the name that addresses it"`
	// ProductDisplayName is the human spelling, beside the address rather than
	// in place of it: minting a token resolves the field above.
	ProductDisplayName string `json:"product_display_name,omitempty" doc:"What to call that product, where it was declared with a display name"`
	// Lifetime is how long it lasts, as a duration. There is a maximum, and
	// there is no way to ask for one that never expires.
	Lifetime string `json:"lifetime,omitempty" doc:"How long it lasts, such as \"720h\". There is a configured maximum"`
	// Secret is returned at creation and never again.
	Secret     string `json:"secret,omitempty" doc:"Shown once, at creation. It is stored hashed and cannot be shown again"`
	Owner      string `json:"owner,omitempty" doc:"Whose it is. Shown to an administrator listing everybody's"`
	ExpiresAt  string `json:"expires_at,omitempty" doc:"When it stops working"`
	LastUsedAt string `json:"last_used_at,omitempty" doc:"When it was last used"`
	Withdrawn  bool   `json:"withdrawn,omitempty" doc:"Whether it has been withdrawn"`
}

func registerTokens(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-my-tokens", Method: http.MethodGet, Path: "/v1/tokens",
		Summary: "List your API tokens",
		Description: "Lists your own personal tokens: what each is called, when it expires and " +
			"when it was last used. Never anybody else's, and never the secrets.\n\n" +
			"A token is a live reference to you rather than a copy of what you could do when it " +
			"was made, so what one reaches shrinks the moment your roles do.",
		Tags: []string{"Access"},
	}, ownSubject, ""), func(ctx context.Context, _ *struct{}) (*listOutput[TokenBody], error) {
		subject, rights, names, err := mine(ctx, in)
		if err != nil {
			return nil, err
		}
		tokens, err := rights.Tokens(ctx, subject.ID)
		if err != nil {
			return nil, wentWrong(in.Logger, "cannot list your tokens", err)
		}
		return tokenList(ctx, names, tokens, nil)
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "mint-token", Method: http.MethodPost, Path: "/v1/tokens",
		Summary: "Create an API token",
		Description: "Creates a personal token and returns its secret. The secret is shown once " +
			"and never again — what is stored is a digest.\n\n" +
			"Expiry is not optional, and `lifetime` may not exceed the ceiling an administrator " +
			"has set. A credential that never runs out is one nobody ever revokes, and those are " +
			"found when somebody leaves and nobody knows what breaks if it is turned off.",
		Tags: []string{"Access"}, DefaultStatus: http.StatusCreated,
	}, ownSubject, "Signed in, not through a token: a token cannot mint another."), func(ctx context.Context, input *struct{ Body TokenBody }) (*struct{ Body TokenBody }, error) {
		subject, rights, _, err := mine(ctx, in)
		if err != nil {
			return nil, err
		}
		// A token cannot mint a token. Minting resolves through the owner, so
		// a narrowed one could otherwise ask for a wide one and be given it —
		// which makes every limit on a token exactly one request deep,
		// including the lifetime ceiling and, for an administrator's token,
		// administration itself.
		if subject.Delegated() {
			return nil, huma.Error403Forbidden(
				"a token cannot mint another; sign in to mint one")
		}

		var productID *int64
		if input.Body.Product != "" {
			// Resolved through what this person may see, so naming a product
			// they cannot read answers as one that was never declared rather
			// than telling them it exists.
			product, err := productNamedVisibly(ctx, in, subject, input.Body.Product)
			if err != nil {
				return nil, err
			}
			productID = &product.ID
		}

		lifetime := time.Duration(0)
		if input.Body.Lifetime != "" {
			parsed, err := time.ParseDuration(input.Body.Lifetime)
			if err != nil || parsed <= 0 {
				return nil, huma.Error422UnprocessableEntity("that is not a length of time a token can last")
			}
			lifetime = parsed
		}

		ceiling := access.MaxTokenLifetime
		if in.DB != nil {
			ceiling, err = setting.NewStore(in.DB.DB).
				Duration(ctx, setting.MaxTokenLifetime, access.MaxTokenLifetime)
			if err != nil {
				return nil, wentWrong(in.Logger, "cannot read how long a token may last", err)
			}
		}

		token, secret, err := rights.NewToken(ctx, subject.ID, input.Body.Name, productID, lifetime, ceiling)
		if err != nil {
			// The refusals here are about what was asked for — a name that is
			// missing, a lifetime past the ceiling — so they are reported.
			return nil, asked(in.Logger, err)
		}
		return &struct{ Body TokenBody }{Body: TokenBody{
			Name: token.Name, Product: input.Body.Product, Secret: secret,
			ExpiresAt: stamp(token.ExpiresAt),
		}}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "revoke-my-token", Method: http.MethodDelete, Path: "/v1/tokens/{name}",
		Summary: "Withdraw one of your API tokens",
		Description: "Revokes one of your own tokens by name. It stops working immediately.\n\n" +
			"Yours alone. An administrator withdraws anybody else's through the administration " +
			"paths.",
		Tags:          []string{"Access"},
		DefaultStatus: http.StatusNoContent,
	}, ownSubject, "Signed in, not through a token: a token cannot withdraw another."), func(ctx context.Context, input *struct {
		Name string `path:"name"`
	}) (*struct{}, error) {
		subject, rights, _, err := mine(ctx, in)
		if err != nil {
			return nil, err
		}
		// Withdrawing is minting's mirror: a leaked token that could revoke
		// its owner's others would be a way to lock them out of their own
		// scripting while keeping the one that leaked.
		if subject.Delegated() {
			return nil, huma.Error403Forbidden(
				"a token cannot withdraw another; sign in to withdraw one")
		}
		token, err := rights.TokenByName(ctx, subject.ID, input.Name)
		if err != nil {
			return nil, absent(in.Logger, err, "that token could not be looked up",
				func() error {
					return huma.Error404NotFound("no token of yours is called that")
				})
		}
		if err := rights.RevokeToken(ctx, token.ID); err != nil {
			return nil, wentWrong(in.Logger, "cannot revoke a token", err)
		}
		return &struct{}{}, nil
	})
}

// mine resolves whose tokens are being asked about.
//
// A person, and only a person. A pipeline's key has no owner to be a live
// reference to, and a token minted by one would be a credential nobody's
// departure ever invalidates.
func mine(ctx context.Context, in Ingest) (access.Subject, *access.Store, *catalog.Store, error) {
	subject, err := reading(ctx)
	if err != nil {
		return access.Subject{}, nil, nil, err
	}
	if in.DB == nil {
		return access.Subject{}, nil, nil, noDatabase(in.Logger)
	}
	return subject, access.NewStore(in.DB.DB), catalog.NewStore(in.DB.DB), nil
}

// tokenList renders tokens, naming the products they are narrowed to.
func tokenList(ctx context.Context, names *catalog.Store, tokens []access.Token, owners map[int64]string) (*listOutput[TokenBody], error) {
	out := &listOutput[TokenBody]{}
	out.Body.Items = make([]TokenBody, 0, len(tokens))
	for _, token := range tokens {
		body := TokenBody{
			Name: token.Name, ExpiresAt: stamp(token.ExpiresAt),
			Withdrawn: token.RevokedAt != nil, Owner: owners[token.PersonID],
		}
		if token.LastUsedAt != nil {
			body.LastUsedAt = stamp(*token.LastUsedAt)
		}
		if token.ProductID != nil {
			// The address, for the reason KeyBody carries it: minting
			// resolves this field, and a display name resolves to nothing.
			if product, err := names.ProductByID(ctx, *token.ProductID); err == nil {
				body.Product = product.Name
				if product.DisplayName != product.Name {
					body.ProductDisplayName = product.DisplayName
				}
			}
		}
		out.Body.Items = append(out.Body.Items, body)
	}
	return out, nil
}
