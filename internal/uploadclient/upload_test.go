// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package uploadclient

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestARunIsSentCompressedWithItsFields(t *testing.T) {
	var path, auth string
	var doc []byte
	var fields map[string][]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, auth = r.URL.EscapedPath(), r.Header.Get("Authorization")
		if err := r.ParseMultipartForm(1 << 20); err != nil { //nolint:gosec // G120: a test server reading the client's own request
			t.Error(err)
			return
		}
		fields = r.MultipartForm.Value
		f, head, err := r.FormFile("sarif")
		if err != nil {
			t.Error(err)
			return
		}
		if head.Header.Get("Content-Type") != "application/gzip" {
			t.Errorf("sent as %q", head.Header.Get("Content-Type"))
		}
		z, err := gzip.NewReader(f)
		if err != nil {
			t.Error(err)
			return
		}
		doc, _ = io.ReadAll(z)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"outcome":"queued"}`))
	}))
	defer srv.Close()

	answer, err := Send(t.Context(), srv.Client(),
		Target{URL: srv.URL + "/", Key: "opk_test", Product: "sonic", BranchOrTag: "202605.1", Variant: "broad com"},
		[]byte(`{"version":"2.1.0"}`), Fields{Rules: []string{"core.DivideZero", "unix.Malloc"}, ThirdParty: []string{"src/frr"}})
	if err != nil {
		t.Fatal(err)
	}
	if answer.Status != http.StatusAccepted || string(answer.Body) != `{"outcome":"queued"}` {
		t.Errorf("answer %d %s", answer.Status, answer.Body)
	}
	if path != "/v1/products/sonic/branches-and-tags/202605.1/variants/broad%20com/analyses" {
		t.Errorf("sent to %s", path)
	}
	if auth != "Bearer opk_test" {
		t.Errorf("authorized as %q", auth)
	}
	if string(doc) != `{"version":"2.1.0"}` {
		t.Errorf("document %q", doc)
	}
	want := map[string][]string{"rules": {"core.DivideZero", "unix.Malloc"}, "third-party": {"src/frr"}}
	if !reflect.DeepEqual(fields, want) {
		t.Errorf("fields %v; want %v", fields, want)
	}
}

func TestABusyDeploymentIsAskedAgain(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls < 3 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	answer, err := Send(t.Context(), srv.Client(), Target{URL: srv.URL, Key: "k", Product: "p", BranchOrTag: "s", Variant: "v"}, []byte("{}"), Fields{})
	if err != nil || answer.Status != http.StatusAccepted || calls != 3 {
		t.Errorf("answer %d after %d calls, %v; want 202 on the third", answer.Status, calls, err)
	}
}

func TestARefusalIsReturnedAsItCame(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"detail":"names no series"}`))
	}))
	defer srv.Close()
	answer, err := Send(t.Context(), srv.Client(), Target{URL: srv.URL, Key: "k", Product: "p", BranchOrTag: "s", Variant: "v"}, []byte("{}"), Fields{})
	if err != nil || answer.Status != http.StatusUnprocessableEntity || calls != 1 {
		t.Errorf("answer %d after %d calls, %v; want the 422 once", answer.Status, calls, err)
	}
}

func TestAnUploadNamesItsBuild(t *testing.T) {
	for _, to := range []Target{
		{URL: "not an address", Product: "p", BranchOrTag: "s", Variant: "v"},
		{URL: "ftp://example.com", Product: "p", BranchOrTag: "s", Variant: "v"},
		{URL: "https://example.com", Product: "p", BranchOrTag: "s"},
	} {
		if _, err := analysesURL(to); err == nil {
			t.Errorf("%+v was accepted", to)
		}
	}
}

// A plain http address is refused unless it is this machine or plain http is
// allowed, because the key would cross the network unencrypted.
func TestAPlainHTTPAddressIsRefusedUnlessItIsThisMachineOrAllowed(t *testing.T) {
	for _, address := range []string{"http://192.0.2.1", "http://psirt.example.com:8080/", "HTTP://psirt.example.com"} {
		_, err := analysesURL(Target{URL: address, Product: "p", BranchOrTag: "b", Variant: "v"})
		if err == nil || !strings.Contains(err.Error(), "--allow-http") {
			t.Errorf("%s answered %v, want a refusal naming --allow-http", address, err)
		}
	}
	for _, to := range []Target{
		{URL: "http://127.0.0.1:8080"},
		{URL: "http://localhost:8080"},
		{URL: "http://[::1]:8080"},
		{URL: "http://192.0.2.1", AllowHTTP: true},
		{URL: "https://psirt.example.com"},
	} {
		to.Product, to.BranchOrTag, to.Variant = "p", "b", "v"
		if _, err := analysesURL(to); err != nil {
			t.Errorf("%+v was refused: %v", to, err)
		}
	}
}

// An address that is not a deployment's is refused without its password,
// which a CI log would otherwise keep.
func TestARefusedAddressHidesItsPassword(t *testing.T) {
	for _, address := range []string{"psirt.example.com:hunter2@x", "ftp://u:hunter2@psirt.example.com",
		"https://bot:12/hunter2@psirt.example.com"} {
		_, err := analysesURL(Target{URL: address, Product: "p", BranchOrTag: "b", Variant: "v"})
		if err == nil || !strings.Contains(err.Error(), "not the address of a deployment") {
			t.Errorf("%s answered %v, want a refusal", address, err)
		} else if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: the refusal shows the password: %v", address, err)
		}
	}
}
