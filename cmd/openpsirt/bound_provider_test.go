// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/signin"
)

// labelled is a provider known only by its label and its issuer, which is all
// the startup check reads.
type labelled struct{ name, issuer string }

func (p labelled) Name() string       { return p.name }
func (p labelled) Issuer() string     { return p.issuer }
func (p labelled) GroupsSource() bool { return false }

func (labelled) Begin(context.Context, string) (string, signin.Pending, error) {
	return "", signin.Pending{}, nil
}

func (labelled) Complete(context.Context, string, signin.Pending, string) (*signin.Identity, error) {
	return nil, nil
}

// An identifier belongs to the issuer that minted it, so a deployment whose
// people are bound under one issuer does not start configured for another:
// the same identifier would name somebody else. The refusal names the issuer
// the bindings are under and the route that withdraws one. Keeping the label
// and changing the issuer is the ordinary shape of that change, and is
// refused; changing the label and keeping the issuer moves nothing, and
// starts.
//
// Verified by discarding the error onlyTheBoundProvider's loop returns: the
// changed issuer then starts.
func TestAStartupWithADifferentIssuerIsRefused(t *testing.T) {
	dbtest.Two(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		rights := access.NewStore(db.DB)
		const was = "https://old.example"
		person, err := rights.Ensure(ctx, "alice", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.Claim(ctx, person.ID, "alice"); err != nil {
			t.Fatal(err)
		}
		if _, err := rights.MatchProvider(ctx, was, "alice-1", "alice"); err != nil {
			t.Fatalf("binding the first sign-in: %v", err)
		}

		err = onlyTheBoundProvider(ctx, rights, map[string]signin.Provider{
			"sso": labelled{name: "sso", issuer: "https://new.example"},
		})
		if err == nil {
			t.Fatal("a deployment bound under one issuer started configured for another")
		}
		for _, want := range []string{was, "https://new.example", "DELETE /v1/people/{identity}/identifier"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not name %s: %v", want, err)
			}
		}

		if err := onlyTheBoundProvider(ctx, rights, map[string]signin.Provider{
			"renamed": labelled{name: "renamed", issuer: was},
		}); err != nil {
			t.Errorf("a new label for the same issuer was refused: %v", err)
		}
		if err := onlyTheBoundProvider(ctx, rights, nil); err != nil {
			t.Errorf("no provider at all was refused: %v", err)
		}
	})
}
