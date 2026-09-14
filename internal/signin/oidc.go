// Package signin turns a provider's answer into somebody we already know.
//
// Nothing here creates an account. A provider establishes who somebody is;
// whether they should be here was settled in advance by an administrator, so
// the end of every path in this package is a lookup that can fail.
package signin

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/nexthop-ai/openpsirt/internal/outward"
)

// OIDC signs somebody in through an OpenID Connect provider.
//
// The exchange happens here rather than in the browser, and what the browser
// gets back is a session of ours. A provider's token is never handed to a
// page: it would mean a second thing able to authenticate, verified by a
// second path, and it would be readable by anything that got into the page.
type OIDC struct {
	name string
	// issuer is who mints the identifiers this provider hands over, which is
	// what an identity is recorded against. Kept apart from name, which is a
	// label an operator picks and may change without anything moving.
	issuer   string
	config   oauth2.Config
	verifier *oidc.IDTokenVerifier
	// groupsClaim names where this provider puts group membership. There is no
	// standard claim for it, so it is configured rather than guessed.
	groupsClaim string
	// usernameClaim names what to call somebody. Providers disagree —
	// preferred_username, email, sub — so the deployment says.
	usernameClaim string
	// client is the guarded one every outbound fetch here goes through: pinned
	// to the issuer's host, refusing redirects, refusing to connect inside
	// this network, and bounded in time. Kept rather than rebuilt, because the
	// token exchange happens on every sign-in and the pin is what makes the
	// host it resolves to at that moment the one that was configured.
	client *http.Client
}

// OIDCConfig is what an operator supplies for an OpenID Connect provider.
type OIDCConfig struct {
	Name          string
	Issuer        string
	ClientID      string
	ClientSecret  string
	Scopes        []string
	GroupsClaim   string
	UsernameClaim string
}

// NewOIDC discovers a provider and returns an adapter for it.
//
// Discovery happens once, at startup, through a client that will talk to the
// issuer's host and nowhere else. A provider that cannot be reached stops the
// process rather than producing a deployment whose sign-in fails later for
// reasons nobody can see.
func NewOIDC(ctx context.Context, cfg OIDCConfig) (*OIDC, error) {
	issuer, err := url.Parse(cfg.Issuer)
	if err != nil || issuer.Hostname() == "" {
		return nil, fmt.Errorf("the issuer %q is not a URL naming a host", cfg.Issuer)
	}
	if issuer.Scheme != "https" {
		return nil, fmt.Errorf("the issuer %q is not https, and an identity provider reached over plain http can be answered by anybody on the path", cfg.Issuer)
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("the %q provider needs a client identifier and secret", cfg.Name)
	}

	// Discovery and the key fetches that follow it are pinned to the issuer's
	// host, refuse redirects, and refuse to connect inside this network.
	guarded := outward.Guarded(issuer.Hostname())
	ctx = oidc.ClientContext(ctx, guarded)
	provider, err := oidc.NewProvider(ctx, strings.TrimSuffix(cfg.Issuer, "/"))
	if err != nil {
		return nil, fmt.Errorf("discover the %q provider: %w", cfg.Name, err)
	}

	// A discovery document names the endpoints this deployment will send
	// people to, and it arrives over the network. Pinning the fetch to the
	// issuer's host stops it being fetched from anywhere else; it does not
	// stop the document naming somewhere else inside itself. An issuer that
	// named an authorization endpoint on another host would turn every
	// sign-in into a redirect somewhere of its choosing, carrying whatever a
	// browser sends to it.
	//
	// Checked at startup rather than at each redirect, so a provider that
	// would do this stops the process instead of producing a deployment that
	// misdirects the first person to sign in.
	endpoint := provider.Endpoint()
	for what, raw := range map[string]string{
		"authorization": endpoint.AuthURL,
		"token":         endpoint.TokenURL,
	} {
		named, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("the %q provider named an unreadable %s endpoint", cfg.Name, what)
		}
		if !strings.EqualFold(named.Hostname(), issuer.Hostname()) {
			return nil, fmt.Errorf(
				"the %q provider names its %s endpoint on %s rather than on its own host %s",
				cfg.Name, what, named.Hostname(), issuer.Hostname())
		}
		if named.Scheme != "https" {
			return nil, fmt.Errorf("the %q provider names a %s endpoint that is not https", cfg.Name, what)
		}
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	// Stated by the operator, never defaulted.
	//
	// This is not the identity. The subject is, and it is what a first
	// sign-in pins and what decides from then on. This claim does one job:
	// match an authorization an administrator wrote for somebody who has not
	// arrived yet, which has to be a name a person can type.
	//
	// So the property it needs is that an end user cannot set it to a name an
	// administrator might have authorized. OpenID Connect permits a provider
	// to let people choose their own preferred_username and says a relying
	// party may not rely on it being unique, and whether a given deployment's
	// provider does that is a question only its operator can answer — which
	// is why there is no default rather than a different default.
	username := strings.TrimSpace(cfg.UsernameClaim)
	if username == "" {
		return nil, fmt.Errorf(
			"the %q provider needs a username claim: set %sOIDC_USERNAME_CLAIM to a claim "+
				"whose value an end user cannot choose, because it is what redeems an "+
				"authorization written for somebody who has not signed in yet. Which claim "+
				"that is depends on the provider, so there is no default; the configuration "+
				"reference names the usual answer for each",
			cfg.Name, "OPENPSIRT_")
	}

	return &OIDC{
		name:   cfg.Name,
		issuer: strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/"),
		config: oauth2.Config{
			ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
			Endpoint: endpoint, Scopes: scopes,
		},
		verifier:      provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		groupsClaim:   cfg.GroupsClaim,
		usernameClaim: username,
		client:        guarded,
	}, nil
}

// Issuer is who mints the identifiers this provider hands over.
func (o *OIDC) Issuer() string { return o.issuer }

// Name is how a sign-in path names this provider.
func (o *OIDC) Name() string { return o.name }

// Begin returns where to send the browser.
func (o *OIDC) Begin(_ context.Context, redirectURI string) (string, Pending, error) {
	pending, err := newPending()
	if err != nil {
		return "", Pending{}, err
	}
	config := o.config
	config.RedirectURL = redirectURI

	// The proof key is sent as a digest and kept as the secret it hashes, so
	// an authorization code intercepted on its way back cannot be exchanged by
	// whoever intercepted it.
	return config.AuthCodeURL(pending.State,
		oidc.Nonce(pending.Nonce),
		oauth2.SetAuthURLParam("code_challenge", pending.challenge()),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	), pending, nil
}

// Complete exchanges the code for who the provider says this is.
func (o *OIDC) Complete(ctx context.Context, code string, pending Pending, redirectURI string) (*Identity, error) {
	config := o.config
	config.RedirectURL = redirectURI

	// Through the guarded client, like every other fetch here. Without this
	// the exchange falls back to the default client, which has no timeout at
	// all, follows up to ten redirects — re-sending the authorization code,
	// and downgrading to plain HTTP if told to — and resolves the issuer's
	// name afresh on every sign-in with nothing checking what it resolves to.
	// The key fetches were guarded because the verifier kept this client; the
	// token exchange was the one call that did not, so the paragraph above
	// describing all of them was true of all but the one carrying the secret.
	ctx = context.WithValue(ctx, oauth2.HTTPClient, o.client)
	token, err := config.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", pending.Verifier))
	if err != nil {
		return nil, fmt.Errorf("exchange what %q sent back: %w", o.name, err)
	}

	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return nil, fmt.Errorf("%q returned no identity token, so there is nothing here that says who this is", o.name)
	}
	verified, err := o.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("verify the identity token from %q: %w", o.name, err)
	}
	// The nonce ties this token to the sign-in that started here. Without the
	// comparison a token issued for some other sign-in would verify perfectly
	// well and be accepted.
	if verified.Nonce != pending.Nonce {
		return nil, fmt.Errorf("the identity token from %q belongs to a different sign-in", o.name)
	}

	// The specification requires a subject and the verifier does not check for
	// one, so an identity token naming nobody would otherwise be accepted and
	// leave this sign-in with nothing stable to be matched on.
	if strings.TrimSpace(verified.Subject) == "" {
		return nil, fmt.Errorf("the identity token from %q names no subject", o.name)
	}

	claims := map[string]any{}
	if err := verified.Claims(&claims); err != nil {
		return nil, fmt.Errorf("read the claims from %q: %w", o.name, err)
	}

	// The email is a fallback only where the provider says it verified it. An
	// unverified one is whatever the account holder typed, and an
	// authorization waiting under somebody's work address would be redeemable
	// by anybody willing to claim that address at the provider.
	fallback := ""
	if verifiedEmail(claims) {
		fallback = text(claims["email"])
	}
	username, err := usernameFrom(text(claims[o.usernameClaim]), fallback, verified.Subject)
	if err != nil {
		return nil, err
	}
	return &Identity{
		Subject:       verified.Subject,
		Provider:      o.issuer,
		Username:      username,
		DisplayName:   text(claims["name"]),
		Email:         text(claims["email"]),
		EmailVerified: verifiedEmail(claims),
		Groups:        groups(claims[o.groupsClaim]),
	}, nil
}

// text reads a claim that should be a string, treating anything else as
// absent. A provider is free to send what it likes and a claim of the wrong
// shape is not something to fail a sign-in over.
func text(claim any) string {
	s, _ := claim.(string)
	return strings.TrimSpace(s)
}

// groups reads a claim carrying group membership.
//
// Providers send it as a list, and some send a single group as a bare string.
// Anything else yields nothing, which is the safe direction: missing or
// unreadable membership means no roles, never unrestricted.
func groups(claim any) []string {
	switch value := claim.(type) {
	case []string:
		return trimmed(value)
	case string:
		return trimmed([]string{value})
	case []any:
		names := make([]string, 0, len(value))
		for _, item := range value {
			if name, ok := item.(string); ok {
				names = append(names, name)
			}
		}
		return trimmed(names)
	}
	return nil
}

func trimmed(values []string) []string {
	kept := make([]string, 0, len(values))
	for _, value := range values {
		if name := strings.TrimSpace(value); name != "" {
			kept = append(kept, name)
		}
	}
	return kept
}

// verifiedEmail reports whether the provider says it checked that this person
// controls the address it stated.
//
// Providers spell the claim two ways — a boolean, and the same word as a
// string — and one that says nothing has not verified anything. Read in one
// place because two readers of the same claim eventually disagree, and the
// half that matters here is the strict one: an address nobody checked is
// whatever the account holder typed.
func verifiedEmail(claims map[string]any) bool {
	switch stated := claims["email_verified"].(type) {
	case bool:
		return stated
	case string:
		return strings.EqualFold(strings.TrimSpace(stated), "true")
	}
	return false
}
