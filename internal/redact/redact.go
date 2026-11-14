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
//
// User information that spilled past its authority (see Stray) shows nothing
// between the "//" and the last "@". The parser reads `bot:1234` in
// `https://bot:1234/rest@host` as a host and port, so the first part of the
// password stands where the host should and the rest sits in the path.
func URL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return hidden
	}
	if u.Host != "" && Stray(u) {
		if !spillEnd(u) {
			return hidden
		}
		if _, rest, found := strings.Cut(raw, "//"); found {
			cut, err := url.Parse(u.Scheme + "://" + beforeLastAt(rest))
			// What follows the last "@" is shown as an address only where it
			// is one, since it may be the rest of a query.
			if err != nil || !hostShaped(cut.Host) {
				return hidden
			}
			u = cut
		}
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

// Stray reports whether a parsed address has user information that spilled
// past its authority.
//
// A password holding an unescaped "/", "?" or "#" still parses. The authority
// ends at that character, part of the credential becomes the host, and the
// rest lands in the path, the query or the fragment.
//
// | Sign | Reading |
// |---|---|
// | An "@" in the path or in a query key | The rest of a user name and password cut at "/" or "?" |
// | An "@" in the fragment | The rest of a password cut at "#" |
// | An opaque address, a scheme and a colon with no slashes | User information outside every part the parser separates |
// | An "@" in a query value | The rest of a password cut at "?", under every condition below |
//
// The conditions for a query value:
//   - The address has no user information and no path, so the authority
//     ended at that "?".
//   - The host has a port or a bare ":". The port is the start of the
//     password, and one that is not a number fails to parse.
//   - The value's key names neither a user nor a credential. Drivers read both
//     from the query.
//   - A host follows the query's last "@".
//
// `u:12?a=b@db/x` meets every one. `db?user=app@corp` names a user,
// `db?name=svc@prod` has no port, and `db:5432?name=a@b&c=d` has no host
// after its "@".
func Stray(u *url.URL) bool {
	stray := u.Opaque != "" || strings.Contains(u.EscapedFragment(), "@") || strings.Contains(u.EscapedPath(), "@")
	cut := endedAtPassword(u)
	if at := strings.LastIndex(u.RawQuery, "@"); at >= 0 {
		host := u.RawQuery[at+1:]
		if end := strings.IndexAny(host, "/?"); end >= 0 {
			host = host[:end]
		}
		cut = cut && hostShaped(host)
	}
	for pair := range strings.SplitSeq(u.RawQuery, "&") {
		key, value, _ := strings.Cut(pair, "=")
		stray = stray || strings.Contains(key, "@") || cut && valueSpills(u, key, value)
	}
	return stray
}

// endedAtPassword reports whether an authority may have ended inside a
// password: no user information, no path, and a port or a bare ":" where the
// password began.
func endedAtPassword(u *url.URL) bool {
	return u.User == nil && u.EscapedPath() == "" && (u.Port() != "" || strings.HasSuffix(u.Host, ":"))
}

// spillEnd reports whether an address's last "@" can end spilled user
// information, so that what follows it is the host. An "@" in a credential's
// value or in an ordinary fragment ends nothing.
//
// | Last "@" in | Ends a spill where |
// |---|---|
// | The fragment | The authority ended inside a password, and there is no query |
// | A query value | The authority ended inside a password, and the key names neither a user nor a credential |
// | A query key or the path | Always |
func spillEnd(u *url.URL) bool {
	if strings.Contains(u.EscapedFragment(), "@") {
		return endedAtPassword(u) && u.RawQuery == ""
	}
	at := strings.LastIndex(u.RawQuery, "@")
	if at < 0 {
		return true
	}
	pair := u.RawQuery[strings.LastIndex(u.RawQuery[:at], "&")+1:]
	key, value, _ := strings.Cut(pair, "=")
	if !strings.Contains(value, "@") {
		return true
	}
	return valueSpills(u, key, value)
}

// valueSpills reports whether an "@" in a query value can be the end of a
// password cut at "?": the authority may have ended inside a password, and
// the key names neither a user nor a credential, which drivers read from the
// query.
func valueSpills(u *url.URL, key, value string) bool {
	return strings.Contains(value, "@") && endedAtPassword(u) && !userKey(key) && !Secret(key)
}

// hostShaped reports whether text is a host and an optional port: letters,
// digits, ".", "-", "_", which a container's service name may hold, ":" and
// the brackets around an IPv6 address.
func hostShaped(text string) bool {
	if text == "" {
		return false
	}
	for _, r := range text {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_', r == ':', r == '[', r == ']':
		default:
			return false
		}
	}
	return true
}

// userKey reports whether a query key, as written, names a user.
func userKey(key string) bool {
	if decoded, err := url.QueryUnescape(key); err == nil {
		key = decoded
	}
	return strings.EqualFold(key, "user") || strings.EqualFold(key, "username")
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
