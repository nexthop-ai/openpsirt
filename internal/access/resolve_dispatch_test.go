// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// digest is the stored form of a secret.
func digest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// bearing is a request presenting a secret as a bearer credential.
func bearing(secret string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return req
}

// A presented secret is looked up only in the store its prefix names.
//
// Each secret here is recorded in both stores, so only the dispatch decides
// which subject it resolves to: a resolver trying the stores in turn answers
// one of the two with the other kind of credential. Verified by swapping the
// two prefix arms in Resolver.Resolve: the token resolves as the pipeline and
// the key as the person.
func TestASecretIsLookedUpOnlyInTheStoreItsPrefixNames(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, tokenSecret := holder(t, f)
		scope := access.Scope{ProductID: f.products["sonic"]}

		// A pipeline key whose stored digest is the personal token's.
		shadow, _, err := f.store.NewKey(ctx, "shadow", scope)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.NewUpdate().Model((*access.Key)(nil)).
			Set("secret_hash = ?", digest(tokenSecret)).Where("id = ?", shadow.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		// A personal token whose stored digest is a pipeline key's.
		_, keySecret, err := f.store.NewKey(ctx, "nightly", scope)
		if err != nil {
			t.Fatal(err)
		}
		mirror, _, err := f.store.NewToken(ctx, person.ID, "mirror", nil, nil, time.Hour, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.NewUpdate().Model((*access.Token)(nil)).
			Set("secret_hash = ?", digest(keySecret)).Where("id = ?", mirror.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		resolver := access.NewResolver(f.store, access.Trust{})
		subject, _, err := resolver.Resolve(ctx, bearing(tokenSecret))
		if err != nil {
			t.Fatalf("a personal token was refused: %v", err)
		}
		if subject.Kind != access.Person || subject.ID != person.ID {
			t.Errorf("a personal token resolved as %q", subject.Kind)
		}
		subject, _, err = resolver.Resolve(ctx, bearing(keySecret))
		if err != nil {
			t.Fatalf("a pipeline key was refused: %v", err)
		}
		if subject.Kind != access.Pipeline {
			t.Errorf("a pipeline key resolved as %q", subject.Kind)
		}
	})
}

// A bearer credential of no shape this deployment issues is refused, and
// nothing else on the request is consulted in its place.
//
// The request also carries a trusted proxy's assertion naming somebody
// authorized, so a resolver that fell through to the next way of arriving
// would admit them. Verified by deleting the refusal after the prefix switch.
func TestABearerOfNoKnownShapeIsRefusedRatherThanPassedOver(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		authorized(t, f, "someone", "someone")
		sources, err := access.ParseSources("10.9.9.9")
		if err != nil {
			t.Fatal(err)
		}
		resolver := access.NewResolver(f.store, access.Trust{Header: "X-User", From: sources})

		req := bearing("not-a-credential-we-issue")
		req.Header.Set("X-User", "someone")
		req.RemoteAddr = "10.9.9.9:5555"
		if _, _, err := resolver.Resolve(ctx, req); !errors.Is(err, access.ErrDenied) {
			t.Errorf("a bearer of no known shape was not refused: %v", err)
		}
	})
}
