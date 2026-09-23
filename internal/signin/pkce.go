// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package signin

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

// The two halves of an authorization-code exchange with a proof key, which
// both adapters do the same way.
//
// Written out once per provider, and the OIDC copy's own comment is the record
// of that going wrong: the guarded client reached the key fetches and not the
// token exchange — the one call carrying the secret — and the fix had to be
// found and applied to one adapter. Every literal involved appeared in one copy
// and its twin, which is what made a change to either invisible from the
// other.
//
// A third provider, or any hardening here — a shorter timeout, a check that
// the provider echoed the challenge method, a refusal of a downgraded redirect
// — would land in two places today and in more later, and nothing observed
// either.

// beginPKCE returns where to send the browser, and what to remember until it
// comes back.
//
// extra is what one provider asks for and the other does not: OpenID Connect
// carries a nonce, which is what ties the identity token that comes back to
// this sign-in, and GitHub issues no identity token to tie.
func beginPKCE(config oauth2.Config, redirectURI string,
	extra func(Pending) []oauth2.AuthCodeOption) (string, Pending, error) {

	pending, err := newPending()
	if err != nil {
		return "", Pending{}, err
	}
	config.RedirectURL = redirectURI

	// The proof key is sent as a digest and kept as the secret it hashes, so
	// an authorization code intercepted on its way back cannot be exchanged by
	// whoever intercepted it.
	options := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", pending.challenge()),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	if extra != nil {
		options = append(options, extra(pending)...)
	}
	return config.AuthCodeURL(pending.State, options...), pending, nil
}

// exchangePKCE redeems the code for a token, through the client this adapter
// carries.
//
// Without that client the exchange falls back to the default one, which has no
// timeout at all, follows up to ten redirects — re-sending the authorization
// code, and downgrading to plain HTTP if told to — and resolves the issuer's
// name afresh on every sign-in with nothing checking what it resolves to. That
// is the defect this file exists to stop having twice: a key fetch is guarded
// because the verifier keeps the client, and the token exchange is the call
// with nothing keeping one for it.
func exchangePKCE(ctx context.Context, config oauth2.Config, client *http.Client,
	code, redirectURI string, pending Pending) (*oauth2.Token, error) {

	config.RedirectURL = redirectURI
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	return config.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", pending.Verifier))
}
