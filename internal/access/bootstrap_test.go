package access_test

import (
	"strings"
	"testing"
)

// The recovery path, so it fails loudly rather than at the moment somebody
// needs it. A name was written "provider:username" before an identity became a
// plain username; accepted silently it makes an administrator account nobody
// can sign in as, while the real person is refused — and the startup check for
// a deployment nobody can administer is satisfied by the phantom.
func TestABootstrapNameWithAProviderPrefixIsRefused(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		err := f.store.NameBootstrapAdmins(t.Context(), []string{"okta:alice"})
		if err == nil {
			t.Fatal("a name in the old provider:username form was accepted")
		}
		// It says what to write instead, because an operator reading this is
		// locked out and guessing.
		if !strings.Contains(err.Error(), `"alice"`) {
			t.Errorf("the refusal does not say what to write instead: %v", err)
		}
		if _, err := f.store.ByIdentity(t.Context(), "okta:alice"); err == nil {
			t.Error("the phantom account was recorded anyway")
		}
	})
}

// And a plain name still works, which is what makes the refusal above mean
// something.
func TestABootstrapNameIsAPlainUsername(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		if err := f.store.NameBootstrapAdmins(t.Context(), []string{"alice"}); err != nil {
			t.Fatalf("a plain name was refused: %v", err)
		}
		person, err := f.store.ByIdentity(t.Context(), "alice")
		if err != nil {
			t.Fatalf("the named administrator was not recorded: %v", err)
		}
		if !person.IsAdmin {
			t.Error("the named administrator does not administer")
		}
	})
}
