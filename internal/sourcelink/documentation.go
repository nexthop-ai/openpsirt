// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sourcelink

import (
	"net/url"
	"strings"
)

// documentationHosts is the hosts analyzers document their rules on. A rule's
// documentation address comes from the upload, so a host outside this list
// is the uploader's choice of where a reader is sent.
var documentationHosts = map[string]bool{
	"clang.llvm.org":          true,
	"clang-analyzer.llvm.org": true,
	"cppcheck.sourceforge.io": true,
	"codeql.github.com":       true,
	"docs.github.com":         true,
	"rules.sonarsource.com":   true,
	"semgrep.dev":             true,
	"pmd.github.io":           true,
	"spotbugs.readthedocs.io": true,
	"find-sec-bugs.github.io": true,
	"bandit.readthedocs.io":   true,
	"pylint.readthedocs.io":   true,
	"docs.astral.sh":          true,
	"eslint.org":              true,
	"staticcheck.dev":         true,
	"golangci-lint.run":       true,
	"rust-lang.github.io":     true,
	"learn.microsoft.com":     true,
	"pvs-studio.com":          true,
}

// Documentation is a rule's documentation address where it may be followed:
// https, on a host analyzers document rules on, with no credential. Empty
// otherwise.
func Documentation(address string) string {
	u, err := url.Parse(strings.TrimSpace(address))
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" ||
		!documentationHosts[strings.ToLower(u.Hostname())] || u.Port() != "" {
		return ""
	}
	return u.String()
}
