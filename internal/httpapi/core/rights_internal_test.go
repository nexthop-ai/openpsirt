// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"strings"
	"testing"
)

// The requirement line says a scope the middleware enforces whatever roles are
// held, so a pipeline key is never told it may call a route only a person may.
func TestARequirementSaysAPersonOnlyScopeWhateverRolesItLists(t *testing.T) {
	for _, scope := range []string{AnyPerson, OwnSubject} {
		for _, roles := range [][]string{nil, {"public-triage", "private-triage"}} {
			said := requires{Scope: scope, AnyOf: roles}.said()
			if !strings.Contains(said, "not a pipeline key") {
				t.Errorf("scope %q with roles %v reads %q, which does not say a pipeline key is refused",
					scope, roles, said)
			}
		}
	}
	said := requires{Scope: DeploymentRecords, AnyOf: []string{"admin"}}.said()
	if !strings.Contains(said, "audit permission") {
		t.Errorf("the deployment's records with a role listed reads %q, without the audit permission", said)
	}
}
