// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/signing/signingtest"
)

// expiring is a key valid now and for the lifetime given, in seconds, from its
// creation an hour ago.
func expiring(t *testing.T, lifetime uint32) *Signer {
	t.Helper()
	created := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	signer, err := Read(signingtest.Key(t, created, lifetime), "")
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// A document dated after the key expired is refused in words naming the key,
// its expiry and the document's date, which is what an operator reading the
// log needs to act on.
func TestSigningPastTheKeysExpiryNamesTheExpiry(t *testing.T) {
	signer := expiring(t, 2*3600)
	until, expires := signer.until, signer.expires
	if !expires || until.Sub(signer.From()) != 2*time.Hour {
		t.Fatalf("the key reads as expiring %v at %s, want two hours after %s", expires, until, signer.From())
	}
	if _, err := signer.Sign([]byte(`{}`), until.Add(-time.Minute)); err != nil {
		t.Fatalf("a document dated before the expiry was refused: %v", err)
	}
	_, err := signer.Sign([]byte(`{}`), until.Add(time.Hour))
	if err == nil {
		t.Fatal("a document dated after the key expired was signed")
	}
	for _, want := range []string{signer.Fingerprint(), "expired at " + until.Format(time.RFC3339)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not name %q", err, want)
		}
	}
}

// The watch says nothing while the key is far from expiring, warns within the
// warning window, and reports an error once it has expired. A key that never
// expires is not watched.
func TestTheKeysExpiryIsSaidAheadOfTime(t *testing.T) {
	signer := expiring(t, 365*24*3600)
	until := signer.until
	for _, tc := range []struct {
		name  string
		at    time.Time
		level string
	}{
		{"far off", until.Add(-2 * Warning), ""},
		{"within the window", until.Add(-Warning / 2), "level=WARN"},
		{"expired", until.Add(time.Minute), "level=ERROR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logged bytes.Buffer
			w := NewWatch(signer, slog.New(slog.NewTextHandler(&logged, nil)))
			w.now = func() time.Time { return tc.at }
			said := w.Check(t.Context())
			if said != (tc.level != "") || (tc.level != "" && !strings.Contains(logged.String(), tc.level)) {
				t.Errorf("at %s the watch said %v: %q, want %q", tc.at, said, logged.String(), tc.level)
			}
		})
	}
	if NewWatch(expiring(t, 0), slog.Default()) != nil {
		t.Error("a key that never expires is watched")
	}
	if NewWatch(nil, slog.Default()) != nil {
		t.Error("a deployment with no key watches one")
	}
}
