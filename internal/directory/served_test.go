// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package directory_test

import (
	"os/exec"
	"strings"
	"testing"
)

// Nothing in this deployment serves the directory.
//
// The whole shape of this area rests on it: the application leaves no
// unauthenticated route at all, and the directory is files anybody may fetch.
// A route that served them would be that route, and it would be added by
// somebody who meant well — an endpoint to preview the feed, a handler to
// fetch one document.
//
// Asked of everything the serving packages depend on, directly or through
// another package, rather than of the routes. A handler cannot serve what its
// program cannot reach, and a check over route paths would pass a handler that
// read the store directly and served the same bytes under any name it liked.
func TestNothingInThisDeploymentServesTheDirectory(t *testing.T) {
	const mine = "github.com/nexthop-ai/openpsirt/internal/directory"
	listed, err := exec.CommandContext(t.Context(), "go", "list", "-deps",
		"-f", "{{.ImportPath}}", "../httpapi", "../webui").Output()
	if err != nil {
		t.Fatalf("listing what the serving packages depend on: %v", err)
	}
	read := 0
	for _, dependency := range strings.Fields(string(listed)) {
		read++
		if dependency == mine {
			t.Error("a serving package reaches the published advisory directory, so " +
				"something in this deployment can serve it")
		}
	}
	// A listing that came back empty is a check that read nothing and
	// reported the same clean answer.
	if read == 0 {
		t.Fatal("no dependency of the serving packages was listed, so this checked nothing")
	}
}
