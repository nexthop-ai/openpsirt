// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestAProductsRepositorySettingsReadBackAsStored(t *testing.T) {
	eachCatalog(t, func(t *testing.T, d *declaring) {
		d.post(t, "/v1/products", `{"name": "sonic"}`)
		d.post(t, "/v1/products", `{"name": "onie"}`)
		code, body := d.put(t, "/v1/products/sonic/repositories", `{
			"hosts": [
				{"remote": "GitHub.com/", "web": "https://github.com/", "style": "github"},
				{"remote": "code.example.org", "web": "https://code.example.org", "style": "custom",
				 "file_template": "{repo}/view/{commit}/{path}"}
			],
			"paths": [
				{"prefix": "/src/sonic-swss/", "remote": "https://github.com/sonic-net/sonic-swss", "branch": "master"},
				{"prefix": "", "snippets": true}
			]}`)
		if code != http.StatusNoContent {
			t.Fatalf("stating repositories returned %d, want 204: %v", code, body)
		}
		code, body = d.get(t, "/v1/products/sonic/repositories")
		if code != http.StatusOK {
			t.Fatalf("reading repositories returned %d: %v", code, body)
		}
		delete(body, "$schema")
		got, _ := json.Marshal(body)
		want := `{"hosts":[{"file_template":"{repo}/view/{commit}/{path}","remote":"code.example.org","style":"custom","web":"https://code.example.org"},` +
			`{"remote":"github.com","style":"github","web":"https://github.com"}],` +
			`"paths":[{"prefix":"","snippets":true},{"branch":"master","prefix":"src/sonic-swss","remote":"https://github.com/sonic-net/sonic-swss"}]}`
		if string(got) != want {
			t.Errorf("read back\n%s\nwant\n%s", got, want)
		}
		if _, other := d.get(t, "/v1/products/onie/repositories"); len(other["hosts"].([]any))+len(other["paths"].([]any)) != 0 {
			t.Errorf("another product reads %v; want nothing it did not state", other)
		}
		if code, _ := d.put(t, "/v1/products/sonic/repositories", `{"hosts": [], "paths": []}`); code != http.StatusNoContent {
			t.Fatalf("clearing returned %d", code)
		}
		if _, cleared := d.get(t, "/v1/products/sonic/repositories"); len(cleared["hosts"].([]any)) != 0 {
			t.Errorf("a cleared product reads %v", cleared)
		}
	})
}

func TestRepositorySettingsThatCannotBeUsedAreRefused(t *testing.T) {
	twoCatalog(t, func(t *testing.T, d *declaring) {
		d.post(t, "/v1/products", `{"name": "sonic"}`)
		code, body := d.put(t, "/v1/products/sonic/repositories",
			`{"hosts": [{"remote": "github.com", "web": "http://github.com", "style": "github"}], "paths": []}`)
		if code != http.StatusUnprocessableEntity {
			t.Errorf("a host over plain http returned %d, want 422: %v", code, body)
		}
		if code, _ := d.put(t, "/v1/products/absent/repositories", `{"hosts": [], "paths": []}`); code != http.StatusNotFound {
			t.Errorf("a product nobody declared returned %d, want 404", code)
		}
	})
}
