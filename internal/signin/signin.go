// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package signin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// Identity is who a provider says somebody is.
//
// Subject is the provider's own stable identifier and Username is what this
// deployment calls them. They are kept apart because a username moves — people
// change their name at work, and a GitHub login can be renamed and then taken
// by somebody else — while the subject does not. Matching on the moving one is
// how an account ends up belonging to the wrong person.
type Identity struct {
	Subject string
	// Provider is which provider this came from, as that provider names
	// itself here. It travels with the subject because a subject means
	// nothing on its own: two providers issue their own identifiers, and one
	// read as the other names a different person.
	Provider    string
	Username    string
	DisplayName string
	// Email is where the provider says this person is reached, and
	// EmailVerified says the provider claims to have checked that they
	// control it.
	//
	// The two are separate because an unverified address is whatever the
	// account holder typed. Nothing here is authorized by it — the
	// username fallback already refuses one for that reason — and mail
	// sent to it is mail sent wherever they said, which for an alert about
	// an undisclosed finding is the disclosure the alert exists to avoid.
	Email         string
	EmailVerified bool
	// Groups is what the provider says they belong to, read at sign-in and
	// never again. Empty means no groups, never unrestricted.
	Groups []string
}

// Pending is what has to survive the round trip to the provider.
//
// It is held by the browser rather than here, in a cookie the browser cannot
// read, because the alternative is a table of half-finished sign-ins that has
// to be swept and that anybody can fill by starting sign-ins they never
// complete.
type Pending struct {
	// State is echoed by the provider and compared to what we sent. It is what
	// stops somebody handing a signed-in user a callback of their own making
	// and having the session come back as theirs.
	State string
	// Nonce is carried inside the identity token and compared to what we sent,
	// which ties the token to this sign-in rather than to a replayed one.
	Nonce string
	// Verifier is the proof-key secret. The provider only ever saw its digest,
	// so a stolen authorization code cannot be exchanged by whoever stole it.
	Verifier string
}

// Provider is one way to sign in.
//
// Two implement it: an OpenID Connect adapter and an OAuth 2.0 adapter for
// GitHub, which is not an OpenID Connect provider — it issues no identity
// token and publishes no discovery document, so there is nothing for the first
// adapter to verify.
type Provider interface {
	// Name is how a sign-in path names this provider in a URL. Cosmetic and
	// operator-chosen: it is what the button says.
	Name() string
	// Issuer is who mints the identifiers this provider hands over.
	//
	// Not the name. The name is a label an operator picks and may change
	// without anything about the identities moving, and repointing the issuer
	// at a different provider while leaving the label alone is the ordinary
	// shape of a provider change. What decides whether an identifier is still
	// interpretable is who minted it, so that is what is recorded beside it.
	Issuer() string
	// Begin returns where to send the browser, and what to remember until it
	// comes back.
	Begin(ctx context.Context, redirectURI string) (string, Pending, error)
	// Complete exchanges what the provider sent back for who it says they are.
	Complete(ctx context.Context, code string, pending Pending, redirectURI string) (*Identity, error)
	// GroupsSource reports whether this provider is configured to hand over
	// group membership at all.
	//
	// Asked because a deployment can be switched to group-bound roles at any
	// time, and a provider configured without a source of groups then reports
	// every arrival as belonging to nothing — so nobody derives any role and
	// the deployment locks itself out, including whoever made the change.
	// Empty is a legitimate configuration for a deployment assigning roles
	// directly; it is only the pair that is the failure.
	GroupsSource() bool
}

// newPending generates what one sign-in needs to survive its round trip.
func newPending() (Pending, error) {
	values := make([]string, 3)
	for i := range values {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return Pending{}, fmt.Errorf("begin a sign-in: %w", err)
		}
		values[i] = base64.RawURLEncoding.EncodeToString(raw)
	}
	return Pending{State: values[0], Nonce: values[1], Verifier: values[2]}, nil
}

// challenge is what the provider is shown in place of the verifier.
func (p Pending) challenge() string {
	sum := sha256.Sum256([]byte(p.Verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// usernameFrom picks what to call somebody from what a provider supplied.
//
// A provider that supplies nothing usable is a configuration mistake rather
// than an anonymous user, so this fails instead of inventing a name: an
// invented one would not match anything an administrator granted access to,
// and the sign-in would be refused for a reason nobody could work out.
func usernameFrom(candidates ...string) (string, error) {
	for _, candidate := range candidates {
		if trimmed := strings.TrimSpace(candidate); trimmed != "" {
			return trimmed, nil
		}
	}
	return "", fmt.Errorf("the provider supplied no username, so there is nothing to match against what was granted")
}
