// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

const list = `<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
    <cppcheck version="2.13.0"/>
    <errors>
        <error id="purgedConfiguration" severity="information" msg="m" verbose="v"/>
        <error id="memleak" severity="error" msg="m" verbose="v" cwe="401"/>
        <error id="nullPointer" severity="error" msg="m" verbose="v" cwe="476"/>
        <error id="unknownMacro" severity="error" msg="m" verbose="v" cwe="0"/>
    </errors>
</results>`

func TestEveryCheckNamingAWeaknessIsWrittenAndNoOther(t *testing.T) {
	version, table, err := checks([]byte(list))
	if err != nil {
		t.Fatal(err)
	}
	if version != "2.13.0" {
		t.Errorf("the version is %q; want 2.13.0", version)
	}
	if len(table) != 2 || table["memleak"] != "CWE-401" || table["nullPointer"] != "CWE-476" {
		t.Errorf("the table is %v; want memleak and nullPointer alone", table)
	}
	src, err := render(version, table)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `"memleak":     "CWE-401",`) || !strings.Contains(string(src), `cppcheckVersion = "2.13.0"`) {
		t.Errorf("the file written is:\n%s", src)
	}
}

func TestAListNamingNoWeaknessWritesNothing(t *testing.T) {
	if _, _, err := checks([]byte(strings.ReplaceAll(list, ` cwe="`, ` x="`))); err == nil {
		t.Error("a list naming no weakness was read as a table")
	}
}

func TestAListNamingNoVersionIsRefused(t *testing.T) {
	if _, _, err := checks([]byte(strings.Replace(list, `<cppcheck version="2.13.0"/>`, "", 1))); err == nil {
		t.Error("a list naming no cppcheck version was read")
	}
}
