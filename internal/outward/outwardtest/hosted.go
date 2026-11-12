// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package outwardtest stands a test server in for the hosts a client reaches.
package outwardtest

import "net/http"

// Hosted sends every request to the server at the host and port given,
// whatever host it names, through inner.
func Hosted(at string, inner http.RoundTripper) http.RoundTripper {
	return hosted{at: at, inner: inner}
}

type hosted struct {
	at    string
	inner http.RoundTripper
}

func (h hosted) RoundTrip(req *http.Request) (*http.Response, error) {
	sent := req.Clone(req.Context())
	sent.URL.Host = h.at
	return h.inner.RoundTrip(sent)
}
