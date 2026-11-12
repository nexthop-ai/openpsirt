// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package uploadclient

import (
	"reflect"
	"strings"
	"testing"
)

// A key with no value is refused naming it. It never ends the dictionary
// holding it or the array around that, so the keys after it in the document,
// the files every location names among them, are never dropped.
func TestAKeyWithNoValueIsRefusedRatherThanEndingTheDocument(t *testing.T) {
	_, err := parsePlist([]byte(`<?xml version="1.0"?><plist version="1.0"><dict>` +
		`<key>diagnostics</key><array><dict><key>x</key></dict></array>` +
		`<key>files</key><array><string>a.c</string></array></dict></plist>`))
	if err == nil || !strings.Contains(err.Error(), `"x" has no value`) {
		t.Errorf("answered %v, want a refusal naming the key", err)
	}
}

// The keys after an array of dictionaries are read.
func TestTheKeysAfterAnArrayOfDictionariesAreRead(t *testing.T) {
	got, err := parsePlist([]byte(`<?xml version="1.0"?><plist version="1.0"><dict>` +
		`<key>diagnostics</key><array><dict><key>x</key><integer>1</integer></dict><dict/></array>` +
		`<key>files</key><array><string>a.c</string></array></dict></plist>`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"diagnostics": []any{map[string]any{"x": 1}, map[string]any{}},
		"files":       []any{"a.c"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("read %#v, want %#v", got, want)
	}
}

// A property list holding nothing is refused.
func TestAnEmptyPropertyListIsRefused(t *testing.T) {
	_, err := parsePlist([]byte(`<?xml version="1.0"?><plist version="1.0"></plist>`))
	if err == nil || !strings.Contains(err.Error(), "holds nothing") {
		t.Errorf("answered %v, want a refusal saying it holds nothing", err)
	}
}
