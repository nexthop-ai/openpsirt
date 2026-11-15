// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package build_test

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// The chart's list of roles it accepts in auth.groupRoles, and the roles the
// demo administrator is granted.
var (
	chartRoles = regexp.MustCompile(`\$roles := list((?: "[^"]*")+)`)
	demoRoles  = regexp.MustCompile(`(?m)^DEMO_ROLES := ((?:.*\\\n)*.*)$`)
)

// rolesIn is the words a pattern's first group holds, unquoted.
func rolesIn(t *testing.T, pattern *regexp.Regexp, text string) []string {
	t.Helper()
	match := pattern.FindStringSubmatch(text)
	if match == nil {
		return nil
	}
	words := strings.Fields(strings.NewReplacer(`"`, " ", `\`, " ").Replace(match[1]))
	slices.Sort(words)
	return words
}

// differ reports the words one side holds and the other does not, both ways.
func differ(t *testing.T, where string, got, want []string) {
	t.Helper()
	if len(got) == 0 {
		t.Fatalf("%s names no roles, so this checked nothing", where)
	}
	for _, role := range got {
		if !slices.Contains(want, role) {
			t.Errorf("%s names %q, which the server does not grant", where, role)
		}
	}
	for _, role := range want {
		if !slices.Contains(got, role) {
			t.Errorf("%s leaves out %q, which the server grants", where, role)
		}
	}
}

func perProduct() []string {
	var roles []string
	for _, role := range access.Roles() {
		roles = append(roles, string(role))
	}
	return roles
}

func TestTheChartAcceptsEveryRoleTheServerGrants(t *testing.T) {
	text, err := os.ReadFile(filepath.Join("..", "..", "deploy", "helm", "openpsirt", "templates", "deployment.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	want := perProduct()
	for _, over := range access.OverTheDeployment() {
		want = append(want, string(over))
	}
	differ(t, "the chart's $roles", rolesIn(t, chartRoles, string(text)), want)
}

func TestTheDemoAdministratorHoldsEveryPerProductRole(t *testing.T) {
	text, err := os.ReadFile(filepath.Join("..", "..", "Makefile.demo"))
	if err != nil {
		t.Fatal(err)
	}
	differ(t, "Makefile.demo's DEMO_ROLES", rolesIn(t, demoRoles, string(text)), perProduct())
}

func TestTheRoleListsAreReadFromTheLinesHoldingThem(t *testing.T) {
	if got := rolesIn(t, chartRoles, `{{- $roles := list "b" "a" }}`); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("the chart line read as %q", got)
	}
	if got := rolesIn(t, demoRoles, "DEMO_ROLES := b \\\n              a\nother := c\n"); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("the makefile lines read as %q", got)
	}
	if got := rolesIn(t, chartRoles, `roles: a b`); got != nil {
		t.Errorf("a line holding no list read as %q", got)
	}
}
