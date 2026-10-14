// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	if !strings.Contains(text, `const Version = "4.18"`) || !strings.Contains(text, "DO NOT EDIT") {
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
