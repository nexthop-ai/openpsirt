package signin

import (
	"testing"
)

func TestWhatOneSignInIsGivenIsUnguessableAndItsOwn(t *testing.T) {
	// What this file can say about a sign-in's three values: that they are
	// distinct, unguessable, and not shared with the next sign-in.
	//
	// It was named for the proof key being sent as a digest and kept as the
	// secret, and it asserted that a sha256 digest differs from its own
	// preimage — false for every implementation of challenge(), including a
	// broken one — while sending nothing anywhere. That control is the address
	// Begin produces, and it is asserted there, against both adapters.
	first, err := newPending()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newPending()
	if err != nil {
		t.Fatal(err)
	}

	if first.State == second.State || first.Nonce == second.Nonce || first.Verifier == second.Verifier {
		t.Error("two sign-ins were given the same values")
	}
	if first.State == first.Nonce || first.State == first.Verifier {
		t.Error("one value is doing the work of two")
	}
	for what, value := range map[string]string{
		"state": first.State, "nonce": first.Nonce, "verifier": first.Verifier,
	} {
		if len(value) < 40 {
			t.Errorf("the %s is %d characters, which is not enough to be unguessable", what, len(value))
		}
	}
}

func TestGroupMembershipThatCannotBeReadYieldsNoRolesRatherThanEveryRole(t *testing.T) {
	// The failure that would otherwise be silent and total.
	for _, claim := range []any{nil, 42, map[string]any{"a": 1}, []any{1, 2}, "", "   "} {
		if got := groups(claim); len(got) != 0 {
			t.Errorf("%#v read as %v, want nothing", claim, got)
		}
	}
	for _, claim := range []any{
		[]any{"platform", "security"},
		[]string{"platform", "security"},
	} {
		if got := groups(claim); len(got) != 2 || got[0] != "platform" || got[1] != "security" {
			t.Errorf("%#v read as %v", claim, got)
		}
	}
	if got := groups("platform"); len(got) != 1 || got[0] != "platform" {
		t.Errorf("a single group as a bare string read as %v", got)
	}
}

func TestAProviderThatNamesNobodyIsAMisconfigurationRatherThanAnAnonymousUser(t *testing.T) {
	// An invented username would match nothing an administrator granted, and
	// the sign-in would be refused for a reason nobody could work out.
	if _, err := usernameFrom("", "  ", ""); err == nil {
		t.Error("a provider that supplied no username produced one anyway")
	}
	got, err := usernameFrom("", " someone ", "fallback")
	if err != nil {
		t.Fatal(err)
	}
	if got != "someone" {
		t.Errorf("picked %q", got)
	}
}

func TestAnAddressIsOfferedOnlyWhereTheProviderCheckedIt(t *testing.T) {
	// An unverified address is whatever the account holder typed. Nothing here
	// is authorized by one — the username fallback already refuses it — and
	// mail sent to it goes wherever they said, which for an alert about an
	// undisclosed finding is the disclosure the alert exists to avoid.
	//
	// Providers spell the claim two ways and some do not send it at all, so
	// what is pinned is that only the true forms count.
	for _, c := range []struct {
		name   string
		claims map[string]any
		want   bool
	}{
		{name: "boolean true", claims: map[string]any{"email_verified": true}, want: true},
		{name: "string true", claims: map[string]any{"email_verified": "true"}, want: true},
		{name: "string True", claims: map[string]any{"email_verified": "True"}, want: true},
		{name: "boolean false", claims: map[string]any{"email_verified": false}},
		{name: "string false", claims: map[string]any{"email_verified": "false"}},
		{name: "absent", claims: map[string]any{}},
		{name: "a number", claims: map[string]any{"email_verified": 1}},
		{name: "null", claims: map[string]any{"email_verified": nil}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := verifiedEmail(c.claims); got != c.want {
				t.Errorf("verifiedEmail(%v) = %v, want %v", c.claims, got, c.want)
			}
		})
	}
}
