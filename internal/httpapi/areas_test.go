// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// areaImports is each import of one area package that names another area,
// as "file imports path".
func areaImports(t *testing.T, root string) (crossings []string, examined int) {
	t.Helper()
	const prefix = "github.com/nexthop-ai/openpsirt/internal/httpapi/"
	areas, err := filepath.Glob(filepath.Join(root, "*api"))
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range areas {
		area := filepath.Base(dir)
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			examined++
			for _, spec := range parsed.Imports {
				path, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				named, ok := strings.CutPrefix(path, prefix)
				if !ok || strings.Contains(named, "/") || !strings.HasSuffix(named, "api") {
					continue
				}
				if named != area {
					crossings = append(crossings, filepath.Join(area, filepath.Base(file))+" imports "+named)
				}
			}
		}
	}
	return crossings, examined
}

// Areas import nothing of each other, tests included, so each area builds and
// tests alone.
func TestNoAreaImportsAnother(t *testing.T) {
	crossings, examined := areaImports(t, ".")
	if examined == 0 {
		t.Fatal("no area source was found, so this checked nothing")
	}
	for _, one := range crossings {
		t.Errorf("%s: an area reaches another only through the shared package", one)
	}
}

func TestAnAreaImportingAnotherIsReported(t *testing.T) {
	root := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		full := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("oneapi/a_test.go", `package oneapi_test
import (
	_ "github.com/nexthop-ai/openpsirt/internal/httpapi/otherapi"
	_ "github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	_ "github.com/nexthop-ai/openpsirt/internal/httpapi/oneapi"
)`)
	write("otherapi/b.go", `package otherapi
import _ "github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"`)
	crossings, examined := areaImports(t, root)
	if examined != 2 {
		t.Fatalf("read %d files, want both", examined)
	}
	if len(crossings) != 1 || crossings[0] != "oneapi/a_test.go imports otherapi" {
		t.Errorf("reported %v, want only the one area importing another", crossings)
	}
}
