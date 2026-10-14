// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// Two processes with one host name and one process number are two workers.
// Replicas sharing the host's network share its name, and in a container
// every process is the first, so a name built from those alone lets both hold
// one job and one lease.
func TestTwoProcessesOnOneHostAreTwoWorkers(t *testing.T) {
	first, second := workerName(), workerName()
	if first == second {
		t.Errorf("two workers were both named %q", first)
	}
	host, _ := os.Hostname()
	if want := fmt.Sprintf("%s/%d/", host, os.Getpid()); !strings.HasPrefix(first, want) {
		t.Errorf("the worker %q does not begin with the host and process an operator reads, %q", first, want)
	}
}
