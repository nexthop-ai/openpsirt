// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"html"
	"net/http"
	"strings"
)

// upgradingRetry is how long a caller is asked to wait before asking again, in
// seconds, while the schema is applied.
const upgradingRetry = "30"

// upgradingSentence is the whole of what a caller is told while the schema is
// applied.
const upgradingSentence = "OpenPSIRT is upgrading its database"

// Upgrading answers every request while the process applies the schema and
// starts, before the router exists.
//
// Liveness answers, because the process is alive and working: a platform that
// ends a process failing it ends the migration part way, and the migration
// starts again from the beginning in the next one. Readiness does not, because
// nothing here can serve. Every other path is asked to come back: the API in
// the shape every refusal takes, a browser in a page, and anything else in a
// sentence.
//
// Nothing here reads the database, which is the migration's alone until it
// ends.
func Upgrading() http.Handler {
	answer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			plainOK(w, r)
			return
		case "/readyz":
			http.Error(w, "not ready\n", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Retry-After", upgradingRetry)
		switch {
		case r.URL.Path == "/v1" || strings.HasPrefix(r.URL.Path, "/v1/"):
			Problem(w, http.StatusServiceUnavailable, upgradingSentence)
		case strings.Contains(r.Header.Get("Accept"), "text/html"):
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(upgradingPage))
		default:
			http.Error(w, upgradingSentence+"\n", http.StatusServiceUnavailable)
		}
	})
	return browserHeaders(baseContentSecurityPolicy)(answer)
}

// upgradingPage is what a browser is shown while the schema is applied. It
// asks again on its own, at the interval the header names, and carries no
// script and no style for the policy to refuse.
var upgradingPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="` + upgradingRetry + `">
<title>OpenPSIRT</title>
</head>
<body>
<p>` + html.EscapeString(upgradingSentence) + `</p>
</body>
</html>
`
