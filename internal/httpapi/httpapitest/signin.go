// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapitest

import (
	"context"

	"github.com/nexthop-ai/openpsirt/internal/signin"
)

// StubProvider stands in for a real one, so the paths that decide who gets in
// can be tested without an identity provider to sign in to.
type StubProvider struct {
	Says   *signin.Identity
	Fail   error
	issuer string
}

func (s *StubProvider) Name() string { return "stub" }

// Issuer is who mints the identifiers, which is what an identity is recorded
// against. Distinct from the name here on purpose: the two being the same
// string is what hid a provider change from the startup check.
func (s *StubProvider) Issuer() string {
	if s.issuer != "" {
		return s.issuer
	}
	return "https://stub.example"
}

func (s *StubProvider) Begin(_ context.Context, _ string) (string, signin.Pending, error) {
	return "https://provider.example/authorize", signin.Pending{
		State: "the-state", Nonce: "the-nonce", Verifier: "the-verifier",
	}, nil
}

func (s *StubProvider) Complete(_ context.Context, _ string, _ signin.Pending, _ string) (*signin.Identity, error) {
	if s.Fail != nil {
		return nil, s.Fail
	}
	// Stamped here the way both real adapters stamp it, so a test standing on
	// this double stands on something that behaves like the boundary. An
	// identifier travels with the provider that issued it, because one
	// provider's identifier names somebody else at another.
	said := *s.Says
	if said.Provider == "" {
		said.Provider = s.Issuer()
	}
	return &said, nil
}
