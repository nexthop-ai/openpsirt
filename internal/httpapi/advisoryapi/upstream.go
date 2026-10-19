// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/trail"
	"github.com/nexthop-ai/openpsirt/internal/upstream"
)

// UpstreamBody is the upstream a product trusts, and how reading it is going.
type UpstreamBody struct {
	URL         string `json:"url" doc:"The address of the upstream's CSAF provider description"`
	Publisher   string `json:"publisher" doc:"Whose statements they are, as the provider description names its publisher"`
	Fingerprint string `json:"fingerprint,omitempty" doc:"The fingerprint of the key the upstream's documents are signed with, where it signs them"`
	KeyOffered  string `json:"key_offered,omitempty" doc:"A key the upstream now names in place of the trusted one. Nothing is read while the upstream names a key other than the trusted one, and the reason says so"`
	TrustedAt   string `json:"trusted_at" doc:"When the upstream, or its key, was last trusted"`
	Tried       string `json:"tried,omitempty" doc:"When the upstream was last tried"`
	Read        string `json:"read,omitempty" doc:"When a read of the upstream last succeeded"`
	Because     string `json:"because,omitempty" doc:"The reason the last attempt stopped, or what it could not take"`
}

// InspectedBody is what an upstream's provider description says about itself.
type InspectedBody struct {
	Publisher   string `json:"publisher" doc:"Whose statements they are, as the provider description names its publisher"`
	Fingerprint string `json:"fingerprint,omitempty" doc:"The fingerprint of the key its documents are signed with. Empty where it names none"`
}

// OfferBody is one statement an upstream offers for review.
type OfferBody struct {
	Statement     int64  `json:"statement" doc:"The statement, by its identifier. Pass as from_statement when proposing a claim from it"`
	Finding       int64  `json:"finding" doc:"The open finding it speaks about"`
	Product       string `json:"product" doc:"The product the finding is in, by name"`
	Stream        string `json:"stream" doc:"The branch or tag of the build the finding is in"`
	Variant       string `json:"variant" doc:"The variant of the build the finding is in"`
	Publisher     string `json:"publisher" doc:"The upstream that published it"`
	Issue         string `json:"issue" doc:"The issue"`
	Component     string `json:"component" doc:"The component"`
	Version       string `json:"version" doc:"The version the upstream and this product both ship"`
	Status        string `json:"status" doc:"What the upstream says, in the VEX format's own words"`
	Justification string `json:"justification,omitempty" doc:"The reason the upstream gives for a status of not affected"`
	Reasoning     string `json:"reasoning,omitempty" doc:"The upstream's own words"`
	Within        string `json:"within,omitempty" doc:"What of the upstream's the statement depends on: its build, or what pulls the component in there"`
	Document      string `json:"document" doc:"The address of the document it is in"`
	DocumentID    string `json:"document_id" doc:"The tracking identifier of that document"`
}

// UpstreamSaidBody is one statement an upstream publishes about a component.
type UpstreamSaidBody struct {
	Statement     int64  `json:"statement" doc:"The statement, by its identifier"`
	Publisher     string `json:"publisher" doc:"The upstream that published it"`
	Issue         string `json:"issue" doc:"The issue, as the upstream named it"`
	Version       string `json:"version,omitempty" doc:"The version of the component it is about"`
	Status        string `json:"status" doc:"What the upstream says, in the VEX format's own words"`
	Justification string `json:"justification,omitempty" doc:"The reason the upstream gives for a status of not affected"`
	Reasoning     string `json:"reasoning,omitempty" doc:"The upstream's own words"`
	ForAnybody    bool   `json:"for_anybody" doc:"Whether it holds for anybody shipping the component, rather than depending on the upstream's own build"`
	Declined      bool   `json:"declined" doc:"Whether somebody here declined it, so it closes nothing and is offered to nobody"`
	Document      string `json:"document" doc:"The address of the document it is in"`
	DocumentID    string `json:"document_id" doc:"The tracking identifier of that document"`
}

// registerUpstream configures the upstream a product trusts, lists what it
// offers for review, and declines or restores one of its statements.
func registerUpstream(api huma.API, in core.Deps) {
	const path = "/v1/products/{product}/upstream"

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "get-upstream", Method: http.MethodGet, Path: path,
		Summary: "Get a product's upstream",
		Description: "The upstream this product trusts the published statements of, the key " +
			"its documents are checked against, and how reading it is going. Answered 404 " +
			"where the product trusts none.",
		Tags: []string{"Administration"},
	}, core.DeploymentWide, ""), func(ctx context.Context, input *struct {
		Product string `path:"product"`
	}) (*struct{ Body UpstreamBody }, error) {
		by, product, err := core.AdministeredProduct(ctx, in, in.Handle(), input.Product)
		if err != nil {
			return nil, err
		}
		up, err := upstream.NewStore(in.DB.DB).For(ctx, by, product.ID)
		switch {
		case err != nil:
			return nil, core.Asked(in.Logger, err)
		case up == nil:
			return nil, huma.Error404NotFound("this product trusts no upstream")
		}
		return &struct{ Body UpstreamBody }{Body: upstreamBody(up)}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "inspect-upstream", Method: http.MethodPost, Path: path + "/inspection",
		Summary: "Inspect an upstream",
		Description: "Reads an upstream's CSAF provider description and the key it names, and " +
			"answers whose statements they are and the key's fingerprint, for an " +
			"administrator to confirm before trusting it. Nothing is recorded.\n\n" +
			"The address must be https with a host and no user. Every request goes to that " +
			"host and follows no redirect. An upstream that cannot be read, or whose key does " +
			"not carry the fingerprint its description names, is answered 422 saying why.",
		Tags: []string{"Administration"},
	}, core.DeploymentWide, ""), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Body    struct {
			URL string `json:"url" minLength:"1" maxLength:"1000" doc:"The address of the upstream's CSAF provider description"`
		}
	}) (*struct{ Body InspectedBody }, error) {
		if _, _, err := core.AdministeredProduct(ctx, in, in.Handle(), input.Product); err != nil {
			return nil, err
		}
		described, err := inspect(ctx, in, input.Body.URL)
		if err != nil {
			return nil, err
		}
		return &struct{ Body InspectedBody }{Body: InspectedBody{
			Publisher: described.Publisher, Fingerprint: described.Fingerprint,
		}}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "trust-upstream", Method: http.MethodPut, Path: path,
		Summary: "Trust an upstream",
		Description: "Records that this product trusts an upstream's published VEX statements, " +
			"or trusts the upstream's key again after it changed.\n\n" +
			"The upstream is read again on the interval upstream.every names. A statement it " +
			"publishes as holding for anybody shipping a component closes the findings of that " +
			"issue on that component, at the version it names, the next time a build is " +
			"scanned, unless somebody here decided about the place. It closes only where it says " +
			"not affected or fixed. A statement that depends on the upstream's own build is " +
			"offered for review and closes nothing.\n\n" +
			"The fingerprint must be the one the upstream names now, which inspecting it " +
			"answers; another is refused with 409 naming the one served. Leave it empty for an " +
			"upstream that signs nothing. Every document is checked against the digest served " +
			"beside it, and against its signature where a key is trusted. A key the upstream " +
			"changes stops it being read until it is trusted again.\n\n" +
			"Another address is the same upstream moved: the fingerprint is not asked for, the " +
			"key already trusted still checks every document, and a different key the new " +
			"address names stops reading until it is trusted. What the upstream said stands " +
			"until the first complete read of the new address, which keeps what it repeats, " +
			"replaces what it revises and withdraws what it no longer lists. A read that fails " +
			"withdraws nothing. Recorded in the administrative trail.",
		Tags: []string{"Administration"},
	}, core.DeploymentWide, ""), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Body    struct {
			URL         string `json:"url" minLength:"1" maxLength:"1000" doc:"The address of the upstream's CSAF provider description"`
			Fingerprint string `json:"fingerprint,omitempty" maxLength:"191" doc:"The fingerprint of the key its documents are signed with, as inspecting it answered. Empty for an upstream that signs nothing"`
		}
	}) (*struct{ Body UpstreamBody }, error) {
		if _, _, err := core.AdministeredProduct(ctx, in, in.Handle(), input.Product); err != nil {
			return nil, err
		}
		described, err := inspect(ctx, in, input.Body.URL)
		if err != nil {
			return nil, err
		}
		address, _ := upstream.Address(input.Body.URL)
		var out *upstream.Upstream
		if err := core.Changing(ctx, in.DB, in.Log(), func(ctx context.Context, tx bun.Tx) error {
			by, product, err := core.AdministeredProduct(ctx, in, tx, input.Product)
			if err != nil {
				return err
			}
			was, err := upstream.NewStore(tx).For(ctx, by, product.ID)
			if err != nil {
				return core.Asked(in.Logger, err)
			}
			// Moving to another address keeps the keys trusted, so what the
			// new address names is recorded rather than confirmed here. Asked
			// of what the transaction read: an upstream stopped being trusted
			// meanwhile is a first trust, and its keys are confirmed.
			moving := was != nil && was.URL != address.String()
			if !moving && upstream.FingerprintOf(input.Body.Fingerprint) != described.Fingerprint {
				if described.Fingerprint == "" {
					return huma.Error409Conflict("that upstream names no signing key; send no fingerprint")
				}
				return huma.Error409Conflict("that upstream signs with " +
					described.Fingerprint + "; send that fingerprint to trust it")
			}
			out, err = upstream.NewStore(tx).Trust(ctx, by, product.ID, upstream.Trusting{
				URL: address.String(), Publisher: described.Publisher,
				Fingerprint: described.Fingerprint, PublicKey: described.PublicKey,
			})
			if err != nil {
				return core.Asked(in.Logger, err)
			}
			var before *string
			if was != nil {
				before = trail.Said(trusted(was), true)
			}
			if err := core.Noted(ctx, tx, trail.Upstream, "upstream · "+product.Name,
				before, trail.Said(trusted(out), true)); err != nil {
				return core.NotRecorded(in.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct{ Body UpstreamBody }{Body: upstreamBody(out)}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "withdraw-upstream", Method: http.MethodDelete, Path: path,
		Summary: "Stop trusting an upstream",
		Description: "Stops this product trusting its upstream. Nothing more is read from it, " +
			"and everything it said stops closing findings and stops being offered: the " +
			"product's builds are queued to be scanned again, which opens what its statements " +
			"closed. The statements stay readable where a decision cites one.\n\n" +
			"Answered 404 where the product trusts none. Recorded in the administrative trail.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusNoContent,
	}, core.DeploymentWide, ""), func(ctx context.Context, input *struct {
		Product string `path:"product"`
	}) (*struct{}, error) {
		if err := core.Changing(ctx, in.DB, in.Log(), func(ctx context.Context, tx bun.Tx) error {
			by, product, err := core.AdministeredProduct(ctx, in, tx, input.Product)
			if err != nil {
				return err
			}
			was, err := upstream.NewStore(tx).Withdraw(ctx, by, product.ID)
			switch {
			case err != nil:
				return core.Asked(in.Logger, err)
			case was == nil:
				return huma.Error404NotFound("this product trusts no upstream")
			}
			if err := core.Noted(ctx, tx, trail.Upstream, "upstream · "+product.Name,
				trail.Said(trusted(was), true), nil); err != nil {
				return core.NotRecorded(in.Logger, err)
			}
			return again(ctx, in, tx, product.ID)
		}); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-upstream-offers", Method: http.MethodGet, Path: "/v1/upstream-offers",
		Summary: "List what upstreams offer for review",
		Description: "The statements the upstreams of the products here publish that depend on " +
			"their own build, beside each open finding they speak about: the same issue, at a " +
			"component of the same name and version. None of these closes anything by itself. " +
			"Propose a claim from one, passing it as from_statement, or decline it.\n\n" +
			"A finding somebody here has decided about, or a statement somebody declined, is " +
			"not listed. At most 200, oldest statement first.",
		Tags: []string{"Triage"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `query:"product" doc:"Limit to one product, by name. Empty means every product you can see; a name you cannot see is refused rather than answered empty"`
	}) (*core.ListOutput[OfferBody], error) {
		subject, err := core.Requester(ctx)
		if err != nil {
			return nil, err
		}
		var productID int64
		if input.Product != "" {
			product, err := core.ProductNamedVisibly(ctx, in, subject, input.Product)
			if err != nil {
				return nil, err
			}
			productID = product.ID
		}
		offers, err := finding.NewStore(in.DB.DB).Offers(ctx, subject, productID)
		if err != nil {
			return nil, core.Asked(in.Logger, err)
		}
		named, err := productNames(ctx, in, offers)
		if err != nil {
			return nil, err
		}
		out := &core.ListOutput[OfferBody]{}
		out.Body.Items = make([]OfferBody, 0, len(offers))
		for _, one := range offers {
			out.Body.Items = append(out.Body.Items, OfferBody{
				Statement: one.Statement, Finding: one.Finding, Product: named[one.Product],
				Stream: one.Stream, Variant: one.Variant,
				Publisher: one.Publisher, Issue: one.Issue, Component: one.Component,
				Version: one.Version, Status: one.Status, Justification: one.Justified,
				Reasoning: one.Reasoning, Within: one.Within, Document: one.Document,
				DocumentID: one.Identifier,
			})
		}
		return out, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-upstream-statements", Method: http.MethodGet,
		Path:    "/v1/products/{product}/components/{component}/upstream-statements",
		Summary: "List what an upstream says about a component",
		Description: "The statements the upstream this product trusts publishes about a " +
			"component of this name, at any version, newest first, declined ones included. A " +
			"statement holding for anybody that says not affected or fixed closes the findings " +
			"of its issue on the component at its version at the next scan, unless it is " +
			"declined. At most 200.",
		Tags: []string{"Triage"},
	}, core.PerProduct, "", core.ReadRights()...), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Component string `path:"component"`
	}) (*core.ListOutput[UpstreamSaidBody], error) {
		subject, err := core.Requester(ctx)
		if err != nil {
			return nil, err
		}
		product, err := core.ProductNamedVisibly(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		said, err := finding.NewStore(in.DB.DB).UpstreamSaid(ctx, subject, product.ID, input.Component)
		if err != nil {
			return nil, core.Asked(in.Logger, err)
		}
		out := &core.ListOutput[UpstreamSaidBody]{}
		out.Body.Items = make([]UpstreamSaidBody, 0, len(said))
		for _, one := range said {
			out.Body.Items = append(out.Body.Items, UpstreamSaidBody{
				Statement: one.ID, Publisher: one.Publisher, Issue: one.Vulnerability,
				Version: one.About, Status: one.Status, Justification: one.Justification,
				Reasoning: one.Statement, ForAnybody: one.Placement == finding.PlacedAnybody,
				Declined: one.DeclinedAt != nil, Document: one.Document, DocumentID: one.Identifier,
			})
		}
		return out, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "decline-statement", Method: http.MethodPut,
		Path:    "/v1/statements/{statement}/declined",
		Summary: "Decline an upstream's statement",
		Description: "Stops one statement an upstream published closing anything here, or being " +
			"offered for review. The product's builds are queued to be scanned again, which " +
			"opens what it closed. Recorded in the administrative trail.\n\n" +
			"Only a statement an upstream published may be declined; another is refused with " +
			"422; answer a supplier's statement by proposing a claim about the place. A " +
			"statement in a product the caller does not triage is answered 404.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusNoContent,
	}, core.AnyPerson, "", core.TriageRights()...), declineHandler(in, true))

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "restore-statement", Method: http.MethodDelete,
		Path:    "/v1/statements/{statement}/declined",
		Summary: "Restore a declined statement",
		Description: "Takes back declining one statement an upstream published, so it closes " +
			"and is offered again. The product's builds are queued to be scanned again. " +
			"Recorded in the administrative trail.\n\n" +
			"A statement in a product the caller does not triage is answered 404.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusNoContent,
	}, core.AnyPerson, "", core.TriageRights()...), declineHandler(in, false))
}

// declineHandler declines one statement an upstream published, or restores it.
func declineHandler(in core.Deps, decline bool) func(context.Context, *struct {
	Statement int64 `path:"statement"`
}) (*struct{}, error) {
	return func(ctx context.Context, input *struct {
		Statement int64 `path:"statement"`
	}) (*struct{}, error) {
		if err := core.Changing(ctx, in.DB, in.Log(), func(ctx context.Context, tx bun.Tx) error {
			subject, err := core.Requester(ctx)
			if err != nil {
				return err
			}
			store := finding.NewStore(tx)
			act := store.Restore
			if decline {
				act = store.Decline
			}
			done, err := act(ctx, subject, input.Statement)
			switch {
			case errors.Is(err, finding.ErrStatementNotFound):
				return huma.Error404NotFound("no such statement")
			case err != nil:
				return core.Asked(in.Logger, err)
			}
			said := done.Publisher + " · " + done.Issue + " · " + done.Component
			if done.About != "" {
				said += " " + done.About
			}
			was, became := trail.Said("declined", true), (*string)(nil)
			if decline {
				was, became = nil, trail.Said("declined", true)
			}
			if err := core.Noted(ctx, tx, trail.Upstream, "statement · "+said, was, became); err != nil {
				return core.NotRecorded(in.Logger, err)
			}
			return again(ctx, in, tx, done.ProductID)
		}); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	}
}

// productNames is the name of each product the offers are in.
func productNames(ctx context.Context, in core.Deps, offers []finding.Offer) (map[int64]string, error) {
	named := map[int64]string{}
	for _, one := range offers {
		if _, ok := named[one.Product]; ok {
			continue
		}
		product, err := in.Catalog(in.DB.DB).ProductByID(ctx, one.Product)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "the products could not be named", err)
		}
		named[one.Product] = product.Name
	}
	return named, nil
}

// inspect reads an upstream's description, answering a refusal a caller can
// act on where it cannot be read.
func inspect(ctx context.Context, in core.Deps, raw string) (upstream.Described, error) {
	address, err := upstream.Address(raw)
	if err != nil {
		return upstream.Described{}, huma.Error422UnprocessableEntity(err.Error())
	}
	described, err := upstream.Inspect(ctx, upstream.Client(address, in.UpstreamRoots), address.String())
	if err != nil {
		return upstream.Described{}, huma.Error422UnprocessableEntity(
			"that upstream could not be read: " + err.Error())
	}
	return described, nil
}

// again queues the product's builds to be scanned again, inside the act that
// changed what closes their findings.
func again(ctx context.Context, in core.Deps, tx bun.IDB, productID int64) error {
	if in.Queue == nil {
		return nil
	}
	if err := upstream.Again(ctx, tx, in.Queue, productID); err != nil {
		return core.WentWrong(in.Logger, "the product's builds could not be queued to be scanned again", err)
	}
	return nil
}

// trusted is how the trail names what was trusted: the address, and the key.
func trusted(up *upstream.Upstream) string {
	if up.Fingerprint == "" {
		return up.URL + " (unsigned)"
	}
	return up.URL + " (key " + up.Fingerprint + ")"
}

// upstreamBody is an upstream as the API returns it.
func upstreamBody(up *upstream.Upstream) UpstreamBody {
	return UpstreamBody{
		URL: up.URL, Publisher: up.Publisher, Fingerprint: up.Fingerprint, KeyOffered: up.KeyOffered,
		TrustedAt: core.StampAt(&up.TrustedAt), Tried: core.StampAt(up.FetchedAt),
		Read: core.StampAt(up.ReachedAt), Because: up.Failed,
	}
}
