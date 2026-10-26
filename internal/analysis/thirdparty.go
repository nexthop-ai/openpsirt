// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"encoding/json"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/series"
)

// declaredThirdParty is the innermost path a run declared as third-party code
// that holds a file, or empty where none does. A path holds itself and every
// path under it, compared exactly, as a repository holds its files.
//
// The run's list is the one the upload wrote, a JSON list of paths from the
// top of the checkout. One that does not read as that list declares nothing.
func declaredThirdParty(run *series.Run, at string) string {
	if run == nil || run.ThirdParty == "" {
		return ""
	}
	var paths []string
	if json.Unmarshal([]byte(run.ThirdParty), &paths) != nil {
		return ""
	}
	best := ""
	for _, p := range paths {
		if holds(p, at) && len(p) > len(best) {
			best = p
		}
	}
	return best
}

// holds reports whether the directory prefix, from the top of the checkout,
// is the path at or a directory above it.
func holds(prefix, at string) bool {
	return prefix != "" && (at == prefix || strings.HasPrefix(at, prefix+"/"))
}
