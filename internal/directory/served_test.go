package directory_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
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
// Asked of the imports rather than of the routes. A handler cannot serve what
// its package cannot reach, and a check over route paths would pass a handler
// that read the store directly and served the same bytes under any name it
// liked.
func TestNothingInThisDeploymentServesTheDirectory(t *testing.T) {
	const mine = "github.com/nexthop-ai/openpsirt/internal/directory"
	read := 0
	for _, serving := range []string{"../httpapi", "../webui"} {
		entries, err := os.ReadDir(serving)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
				continue
			}
			at := filepath.Join(serving, entry.Name())
			source, err := parser.ParseFile(token.NewFileSet(), at, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			read++
			for _, imported := range source.Imports {
				if strings.Trim(imported.Path.Value, `"`) == mine {
					t.Errorf("%s reaches the published advisory directory, so something "+
						"in this deployment can serve it", at)
				}
			}
		}
	}
	// A directory that stopped resolving is a check that read nothing and
	// reported the same clean answer.
	if read == 0 {
		t.Fatal("no serving source was read, so this checked nothing")
	}
}
