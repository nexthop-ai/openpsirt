package notify

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
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
