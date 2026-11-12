// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// archived zips one catalog document.
func archived(t *testing.T, document string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create("cwec_v4.18.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(document)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const document = `<Weakness_Catalog Version="4.18" Date="2025-09-09">
<Weaknesses>
<Weakness ID="1000" Name="Thousand"/>
<Weakness ID="787" Name="Out-of-bounds Write"/>
<Weakness ID="79" Name="Cross-site Scripting"/>
<Weakness ID="x" Name="Not a number"/>
<Weakness ID="20" Name=""/>
</Weaknesses>
<Categories><Category ID="2" Name="A category"/></Categories>
</Weakness_Catalog>`

func TestTheNamesAreWrittenInNumericOrder(t *testing.T) {
	read, err := catalogIn(archived(t, document), mostDocument)
	if err != nil {
		t.Fatal(err)
	}
	names := namesIn(read)
	if len(names) != 3 {
		t.Errorf("read %v; an entry missing a half, or with no number, is not a weakness", names)
	}
	source, err := render(read.Version, read.Date, names)
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	at79, at787, at1000 := strings.Index(text, `"CWE-79"`), strings.Index(text, `"CWE-787"`), strings.Index(text, `"CWE-1000"`)
	if at79 < 0 || at79 > at787 || at787 > at1000 {
		t.Errorf("CWE-79, 787 and 1000 are not in numeric order:\n%s", text)
	}
	if !strings.Contains(text, "read from catalog 4.18\n// published 2025-09-09") || !strings.Contains(text, "DO NOT EDIT") {
		t.Errorf("the generated file does not say what it was read from:\n%s", text)
	}
}

func TestAnArchiveLargerThanItsBoundIsRefused(t *testing.T) {
	body := archived(t, document)
	if _, err := catalogIn(body, int64(len(document))-1); err == nil {
		t.Error("a document past the decompression bound was read")
	}
	if _, err := catalogIn(body, int64(len(document))); err != nil {
		t.Errorf("a document within the bound was refused: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()
	if _, err := fetch(server.Client(), server.URL, int64(len(body))-1); err == nil {
		t.Error("an answer past the archive bound was read")
	}
	if got, err := fetch(server.Client(), server.URL, int64(len(body))); err != nil || !bytes.Equal(got, body) {
		t.Errorf("an answer within the bound was refused: %v", err)
	}
}

func TestARedirectIsFollowedOnlyToHTTPS(t *testing.T) {
	to := func(raw string) *http.Request { u, _ := url.Parse(raw); return &http.Request{URL: u} }
	if err := redirect(to("http://cwe.mitre.org/x.zip"), []*http.Request{{}}); err == nil {
		t.Error("a redirect to plain http was followed")
	}
	if err := redirect(to("https://cwe.mitre.org/x.zip"), []*http.Request{{}}); err != nil {
		t.Errorf("a redirect to https was refused: %v", err)
	}
	if err := redirect(to("https://cwe.mitre.org/x.zip"), make([]*http.Request, mostHops)); err == nil {
		t.Error("a redirect past the hop bound was followed")
	}
}

func TestAWeaknessTakesItsPrimaryParentInTheResearchView(t *testing.T) {
	const doc = `<Weakness_Catalog Version="4.18" Date="2025-09-09"><Weaknesses>
<Weakness ID="664" Name="Resource" Abstraction="Pillar"/>
<Weakness ID="119" Name="Bounds" Abstraction="Class"/>
<Weakness ID="787" Name="Write" Abstraction="Base"><Related_Weaknesses>
<Related_Weakness Nature="ChildOf" CWE_ID="20" View_ID="1000"/>
<Related_Weakness Nature="ChildOf" CWE_ID="119" View_ID="1000" Ordinal="Primary"/>
</Related_Weaknesses></Weakness>
<Weakness ID="121" Name="Stack" Abstraction="Variant"><Related_Weaknesses>
<Related_Weakness Nature="ChildOf" CWE_ID="1" View_ID="699" Ordinal="Primary"/>
<Related_Weakness Nature="CanPrecede" CWE_ID="2" View_ID="1000"/>
<Related_Weakness Nature="ChildOf" CWE_ID="787" View_ID="1000"/>
</Related_Weaknesses></Weakness>
</Weaknesses></Weakness_Catalog>`
	read, err := catalogIn(archived(t, doc), mostDocument)
	if err != nil {
		t.Fatal(err)
	}
	parents, classes, pillars := lineageIn(read)
	if parents["CWE-787"] != "CWE-119" || parents["CWE-121"] != "CWE-787" || len(parents) != 2 {
		t.Errorf("read parents %v; want the primary one in the research view, and the first where none is", parents)
	}
	if !classes["CWE-119"] || !classes["CWE-664"] || len(classes) != 2 {
		t.Errorf("read classes %v; want CWE-119 and CWE-664", classes)
	}
	if !pillars["CWE-664"] || len(pillars) != 1 {
		t.Errorf("read pillars %v; want CWE-664 alone", pillars)
	}
	source, err := renderLineage(read.Version, read.Date, parents, classes, pillars)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), "read from catalog 4.18\n// published 2025-09-09") {
		t.Errorf("the generated hierarchy does not say what it was read from:\n%s", source)
	}
}

// committed reads a generated file of package weakness: the catalog its
// header names, and each map it declares, by variable.
func committed(t *testing.T, name string) (version, date string, maps map[string]map[string]string) {
	t.Helper()
	path := filepath.Join("..", "..", "weakness", name)
	source, err := os.ReadFile(path) //nolint:gosec // G304: a generated file of this repository
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`read from catalog (\S+)\n// published (\S+) by`).FindSubmatch(source)
	if m == nil {
		t.Fatalf("%s names no catalog it was read from", name)
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	maps = map[string]map[string]string{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			value := spec.(*ast.ValueSpec)
			entries := map[string]string{}
			for _, element := range value.Values[0].(*ast.CompositeLit).Elts {
				pair := element.(*ast.KeyValueExpr)
				key, _ := strconv.Unquote(pair.Key.(*ast.BasicLit).Value)
				switch v := pair.Value.(type) {
				case *ast.BasicLit:
					entries[key], _ = strconv.Unquote(v.Value)
				case *ast.Ident:
					entries[key] = v.Name
				}
			}
			maps[value.Names[0].Name] = entries
		}
	}
	return string(m[1]), string(m[2]), maps
}

func TestTheCommittedFilesAreWhatTheGeneratorWrites(t *testing.T) {
	version, date, read := committed(t, "names.go")
	if len(read["names"]) == 0 {
		t.Fatal("names.go declares no names, so this checked nothing")
	}
	names, err := render(version, date, read["names"])
	if err != nil {
		t.Fatal(err)
	}
	if held, _ := os.ReadFile(filepath.Join("..", "..", "weakness", "names.go")); !bytes.Equal(held, names) {
		t.Errorf("names.go is not what the generator writes for its own catalog and names")
	}

	namesVersion, namesDate := version, date
	version, date, read = committed(t, "lineage.go")
	if version != namesVersion || date != namesDate {
		t.Errorf("lineage.go names catalog %s of %s and names.go %s of %s; one run writes both",
			version, date, namesVersion, namesDate)
	}
	set := func(m map[string]string) map[string]bool {
		out := map[string]bool{}
		for k := range m {
			out[k] = true
		}
		return out
	}
	if len(read["parents"]) == 0 || len(read["classes"]) == 0 || len(read["pillars"]) == 0 {
		t.Fatal("lineage.go declares an empty map, so this checked nothing")
	}
	lineage, err := renderLineage(version, date, read["parents"], set(read["classes"]), set(read["pillars"]))
	if err != nil {
		t.Fatal(err)
	}
	if held, _ := os.ReadFile(filepath.Join("..", "..", "weakness", "lineage.go")); !bytes.Equal(held, lineage) {
		t.Errorf("lineage.go is not what the generator writes for its own catalog and hierarchy")
	}
}
