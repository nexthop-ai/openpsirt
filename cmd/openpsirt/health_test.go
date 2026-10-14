// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// The health check asks the server at the address the configuration names.
func TestTheHealthCheckAsksWhereTheServerListens(t *testing.T) {
	quiet, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = quiet.Close() }()
	alive := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" || !alive {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENPSIRT_ADDR", "0.0.0.0:"+port)
	if err := run([]string{"health"}, quiet, quiet); err != nil {
		t.Errorf("a server listening where the configuration says was reported unhealthy: %v", err)
	}
	alive = false
	if err := run([]string{"health"}, quiet, quiet); err == nil {
		t.Error("a server answering 503 was reported healthy")
	}
	t.Setenv("OPENPSIRT_ADDR", "127.0.0.1:1")
	if err := run([]string{"health"}, quiet, quiet); err == nil {
		t.Error("a port nothing listens on was reported healthy")
	}
}

func TestAServerOnEveryInterfaceIsAskedOnLoopback(t *testing.T) {
	for addr, want := range map[string]string{
		":8080":          "127.0.0.1:8080",
		"0.0.0.0:9000":   "127.0.0.1:9000",
		"[::]:9000":      "127.0.0.1:9000",
		"10.1.2.3:8443":  "10.1.2.3:8443",
		"[fd00::5]:8080": "[fd00::5]:8080",
	} {
		got, err := probeAddress(addr)
		if err != nil || got != want {
			t.Errorf("%s is asked at %q (%v), want %q", addr, got, err, want)
		}
	}
	if _, err := probeAddress("8080"); err == nil {
		t.Error("an address with no port was accepted")
	}
}
