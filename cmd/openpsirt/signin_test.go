package main

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/config"
)

// quiet is a logger for a test that is not about what was logged.
func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// An identity here is a username, so two providers issuing usernames
// independently cannot be told apart: the same name from each is either one
// person or two, and nothing in the record says which. The process stops
// rather than resolving that by accident (REQ-41).
//
// Refused before either provider is built, which is also why this test needs
// no network: the pair is rejected on the configuration alone.
func TestTwoSignInProvidersAreRefused(t *testing.T) {
	_, err := signInProviders(context.Background(), config.Config{
		OIDCIssuer:         "https://example.invalid",
		OIDCClientID:       "a",
		OIDCClientSecret:   "b",
		GitHubClientID:     "c",
		GitHubClientSecret: "d",
	}, quiet())
	if err == nil {
		t.Fatal("two providers were accepted; one is configured at a time")
	}

	// The refusal names both settings. Whichever one is the mistake, an
	// operator has to be able to see which two are fighting — a message
	// saying only that something is wrong sends them to the source.
	for _, want := range []string{"OPENPSIRT_OIDC_ISSUER", "OPENPSIRT_GITHUB_CLIENT_ID"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %s: %v", want, err)
		}
	}
}

// One provider is the ordinary arrangement. GitHub is the one that can be
// built without reaching anything: it publishes no discovery document, so
// there is nothing to fetch.
func TestOneSignInProviderIsAccepted(t *testing.T) {
	providers, err := signInProviders(context.Background(), config.Config{
		GitHubClientID: "c", GitHubClientSecret: "d",
	}, quiet())
	if err != nil {
		t.Fatalf("one provider was refused: %v", err)
	}
	if len(providers) != 1 {
		t.Fatalf("got %d providers, want 1", len(providers))
	}
}

// None is not a fault. It is the arrangement where a reverse proxy
// authenticates instead, and a deployment running that way configures no
// provider at all.
func TestNoSignInProviderIsNotAFault(t *testing.T) {
	providers, err := signInProviders(context.Background(), config.Config{}, quiet())
	if err != nil {
		t.Fatalf("configuring no provider was refused: %v", err)
	}
	if len(providers) != 0 {
		t.Fatalf("got %d providers, want none", len(providers))
	}
}
