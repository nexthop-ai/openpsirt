// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package redact_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/redact"
)

func TestNoCredentialSurvivesRedaction(t *testing.T) {
	for _, each := range []struct {
		raw, secret, keeps string
	}{
		{"https://user:hunter2@s3.example.com/bucket", "hunter2", "s3.example.com"},
		{"https://user:p%zz@s3.example.com", "p%zz", ""},
		{"https://cdn.example.com/csaf/?X-Amz-Signature=abc123&X-Amz-Date=1", "abc123", "X-Amz-Date=1"},
		{"https://cdn.example.com/csaf/?x-amz-security-token=tok987", "tok987", "cdn.example.com"},
		{"https://chat.example.com/?token=t0ken", "t0ken", "chat.example.com"},
		{"postgres://u@db.example.com/x?password=pw%zz", "pw%zz", "db.example.com"},
		{"https://psirt.example.com/#access_token=frag", "frag", "psirt.example.com"},
		{"admin:hunter2@psirt.example.com", "hunter2", "psirt.example.com"},
		{"psirt.example.com:hunter2@x", "hunter2", "@x"},
		{"https://ghp_abc123@cdn.example.com/csaf", "ghp_abc123", "cdn.example.com/csaf"},
		// A password whose first part is digits and holds an unescaped "/",
		// "?" or "#" parses as a host and port, with the rest of it elsewhere.
		{"https://bot:1234/abcd@chat.example.com", "1234", "https://xxxxx@chat.example.com"},
		{"https://bot:1234/abcd@chat.example.com", "abcd", "chat.example.com"},
		{"https://bot:/s3cret@chat.example.com", "s3cret", "chat.example.com"},
		{"postgres://u:12?x@db.example.com/x", "12?x", "db.example.com/x"},
		{"https://bot:1234#word@chat.example.com", "1234", "chat.example.com"},
		{"https://bot:1234/abcd@chat.example.com/?token=t0ken", "t0ken", "chat.example.com"},
		{"https://bot:1234?x=y@chat.example.com", "1234?x=y", "chat.example.com"},
		{"postgres://u:12?a=b@db.example.com/x", "12?a=b", "db.example.com/x"},
		{"postgres://u:12?a=b@db.example.com?sslmode=require", "12?a=b", "db.example.com"},
		{"https://bot:1234?x=y@chat.example.com?token=t0ken", "1234?x=y", "chat.example.com"},
		{"postgres://u:12?a=b@db_host/x", "12?a=b", "db_host/x"},
		{"https://bot:?a=b@chat.example.com", "?a=b", "chat.example.com"},
		{"postgres://db.internal?user=app@corp&password=hunter2", "hunter2", "db.internal"},
		{"postgres://db.internal?application_name=a@b&password=hunter2", "hunter2", "db.internal"},
		{"postgres://db.internal?application_name=a@b&password=hunter2#f", "hunter2", "xxxxx"},
		// An "@" in a credential or an ordinary fragment ends no spill, so
		// what follows it is no host, and nothing is shown.
		{"https://chat.example.com/?token=ab@cdsecret#f", "cdsecret", "xxxxx"},
		{"https://chat.example.com/#token=abc@secretpart", "secretpart", "xxxxx"},
		{"https://chat.example.com/?a@b=1&token=ab@cdsecret", "cdsecret", "xxxxx"},
	} {
		got := redact.URL(each.raw)
		if strings.Contains(got, each.secret) {
			t.Errorf("%q shows as %q, which carries %q", each.raw, got, each.secret)
		}
		if !strings.Contains(got, each.keeps) {
			t.Errorf("%q shows as %q, want it to keep %q", each.raw, got, each.keeps)
		}
	}
}

func TestAnAddressWithNoCredentialIsShownAsWritten(t *testing.T) {
	for _, raw := range []string{
		"https://psirt.example.com",
		"https://cdn.example.com/csaf/?",
		"https://cdn.example.com/csaf/?page=2",
		"https://chat.example.com/?user=bot@corp",
		"postgres://db.example.com/psirt?application_name=psirt@prod",
	} {
		if got := redact.URL(raw); got != raw {
			t.Errorf("%q shows as %q, want it unchanged", raw, got)
		}
	}
}

// A fragment carrying no "@" holds no spilled password, so it is no sign of
// one; one carrying an "@" is.
func TestOnlyAFragmentWithAnAtSignIsASpill(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://hooks.example.test/notify#team-a": false,
		"https://minio.example.test:9000#x":        false,
		"https://bot:1234#word@chat.example.test":  true,
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := redact.Stray(u); got != want {
			t.Errorf("%s: spilled = %v, want %v", raw, got, want)
		}
	}
}
