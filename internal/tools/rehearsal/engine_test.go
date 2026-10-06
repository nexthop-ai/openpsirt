// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestTheContainerPortIsReadForTheHostPortItIsPublishedOn(t *testing.T) {
	ports := "3306/tcp -> 127.0.0.1:3307\n5432/tcp -> 127.0.0.1:5433\n5432/tcp -> [::1]:5433\n"
	for host, want := range map[string]string{"3307": "3306", "5433": "5432", "5432": "", "": ""} {
		if got := publishedAs(ports, host); got != want {
			t.Errorf("host port %q read as container port %q, want %q", host, got, want)
		}
	}
}

func TestOnlyALoopbackHostIsLookedForAmongContainers(t *testing.T) {
	for host, want := range map[string]bool{
		"127.0.0.1": true, "127.0.0.2": true, "::1": true, "localhost": true,
		"db.example.com": false, "10.0.0.5": false, "host.docker.internal": false, "": false,
	} {
		if got := loopback(host); got != want {
			t.Errorf("%q read as loopback %v, want %v", host, got, want)
		}
	}
}
