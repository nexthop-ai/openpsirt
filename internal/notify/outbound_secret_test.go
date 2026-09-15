package notify

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestAFailureDoesNotCarryTheAddressBack(t *testing.T) {
	// For Slack and for Teams the address is the credential: the path carries
	// the token and there is no other authentication. The standard library
	// wraps a failed request in an error whose text embeds the whole URL,
	// redacting only a password in the userinfo — so the path survives. That
	// text is stored on the delivery and answered back by the endpoint listing
	// destinations, which is the one field that is careful never to return the
	// address, so the first failure republished what the design refuses to.
	const address = "https://hooks.slack.example/services/T000/B000/SUPERSECRETTOKEN"
	wrapped := &url.Error{
		Op:  "Post",
		URL: address,
		Err: fmt.Errorf("connection refused"),
	}

	said := withoutTheAddress(wrapped, address)
	for _, secret := range []string{"SUPERSECRETTOKEN", "/services/T000/B000"} {
		if strings.Contains(said, secret) {
			t.Errorf("the stored failure carries %q: %q", secret, said)
		}
	}
	// The host stays, because an operator reading "why is this failing" needs
	// to know which destination it is about.
	if !strings.Contains(said, "hooks.slack.example") {
		t.Errorf("the stored failure does not say which destination it is about: %q", said)
	}
	if !strings.Contains(said, "connection refused") {
		t.Errorf("the stored failure no longer says what went wrong: %q", said)
	}
}

func TestAFailureOutsideASCIIIsStillStorableOnceItIsBounded(t *testing.T) {
	// The stored failure is the standard library's own error text, which
	// quotes an address somebody else chose, so it can carry characters
	// outside ASCII at the 400-byte cut. What is left goes into a column on
	// four engines: PostgreSQL refuses invalid UTF-8 outright and MySQL and
	// MariaDB refuse it in strict mode, and the update is only logged when it
	// fails — leaving the operator's one view of why a destination refuses
	// permanently empty.
	//
	// Swept over a leading offset, because where the cut falls depends on the
	// length of the whole message: one fixed string is as likely as not to
	// land on a boundary and pass whatever the code does.
	for offset := range 4 {
		text := strings.Repeat("x", offset) + strings.Repeat("é", 400)
		stored := trimTo(text, 400)
		if !utf8.ValidString(stored) {
			t.Fatalf("at offset %d the stored failure is not valid UTF-8: %q", offset, stored)
		}
		if len(stored) > 400 {
			t.Fatalf("at offset %d the stored failure is %d bytes", offset, len(stored))
		}
	}
}
