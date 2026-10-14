// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package redact turns an address that may carry a credential into text safe
// to log or put in a refusal.
//
// One rule for every address the deployment is configured with: a database
// server, an object store endpoint, a published directory, a chat server.
// Each of them reaches a log line or a startup refusal, and a container
// runtime keeps those in a log store.
package redact

import (
	"net/url"
	"strings"
)

// hidden is what stands in for anything taken out.
const hidden = "xxxxx"

// secretParams are query keys that carry a credential, compared without
// regard to capitals. Drivers accept a password in the query as well as in the
// user information, and a presigned object store address carries its
// signature and session token there.
var secretParams = []string{
	"password", "sslpassword", "sslkey",
	"token", "access_token", "secret", "signature", "sig",
	"x-amz-signature", "x-amz-credential", "x-amz-security-token",
	"x-goog-signature", "x-goog-credential",
}

// Parsed is the URL with every credential replaced: the password in the user
// information, every secret query value, and the fragment.
//
// The query is read pair by pair rather than through the parser. The parser
// drops a pair it cannot decode, so a password parameter with a malformed
// escape is neither found nor replaced, and is printed as it was written.
func Parsed(u *url.URL) string {
	clone := *u
	if u.User != nil {
		if _, set := u.User.Password(); set {
			clone.User = url.UserPassword(u.User.Username(), hidden)
		}
	}
	if clone.RawQuery != "" {
		pairs := strings.Split(clone.RawQuery, "&")
		for i, pair := range pairs {
			if key, _, _ := strings.Cut(pair, "="); Secret(key) {
				pairs[i] = key + "=" + hidden
			}
		}
		clone.RawQuery = strings.Join(pairs, "&")
	}
	clone.Fragment, clone.RawFragment = "", ""
	if clone.Opaque != "" {
		clone.Opaque = beforeLastAt(clone.Opaque)
	}
	return clone.String()
}

// URL is an address as text safe to show, from what an operator wrote.
//
// Text the parser cannot read is not shown at all: the parser's own error
// quotes it, and a malformed escape in a password is the commonest reason it
// fails. Text with no "//" after its scheme shows nothing up to its last "@",
// because `admin:hunter2@psirt.example.com` parses with the scheme `admin` and
// no user information. A user name with no password is hidden as well: a
// configured address carries no user, so whatever stands there may be a token.
func URL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return hidden
	}
	if u.User != nil {
		u.User = url.User(hidden)
	}
	if u.Scheme == "" || u.Opaque != "" || u.Host == "" {
		// A scheme the parser did not separate from a host leaves the
		// credential where nothing above looks for it.
		redacted := Parsed(u)
		return beforeLastAt(redacted)
	}
	return Parsed(u)
}

// Secret reports whether a query key, as written, names a credential.
func Secret(key string) bool {
	if decoded, err := url.QueryUnescape(key); err == nil {
		key = decoded
	}
	for _, name := range secretParams {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

// beforeLastAt replaces everything up to the last "@", which may be a
// password whether or not the parser read it as user information.
func beforeLastAt(text string) string {
	if at := strings.LastIndex(text, "@"); at >= 0 {
		return hidden + "@" + text[at+1:]
	}
	return text
}
