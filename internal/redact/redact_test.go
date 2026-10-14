// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package redact_test

import (
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
	} {
		if got := redact.URL(raw); got != raw {
			t.Errorf("%q shows as %q, want it unchanged", raw, got)
		}
	}
}
