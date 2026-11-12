// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package docs_test

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// A kubelet refuses to start an image whose user is a name in a pod that asks
// only for runAsNonRoot, because it cannot tell the name is not root. The
// image names its user by number, and the number is the one the chart runs as.
func TestTheImageNamesItsUserByTheNumberTheChartRunsAs(t *testing.T) {
	dockerfile, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	users := regexp.MustCompile(`(?m)^USER\s+(\S+)\s*$`).FindAllSubmatch(dockerfile, -1)
	if len(users) == 0 {
		t.Fatal("the Dockerfile sets no user, so this checked nothing")
	}
	// The last USER is the one the image runs as.
	user := string(users[len(users)-1][1])
	numbered := regexp.MustCompile(`^([0-9]+):([0-9]+)$`).FindStringSubmatch(user)
	if numbered == nil {
		t.Fatalf("the image runs as %q; name the user and group by number, as uid:gid", user)
	}

	values, err := os.ReadFile(filepath.Join("..", "..", "deploy", "helm", "openpsirt", "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []struct{ key, want string }{
		{"runAsUser", numbered[1]},
		{"runAsGroup", numbered[2]},
	} {
		found := regexp.MustCompile(`(?m)^\s+` + field.key + `:\s*([0-9]+)\s*$`).FindSubmatch(values)
		if found == nil {
			t.Errorf("the chart sets no %s, so the image's user was not compared with it", field.key)
			continue
		}
		if string(found[1]) != field.want {
			t.Errorf("the chart's %s is %s and the image's is %s", field.key, found[1], field.want)
		}
	}
}
