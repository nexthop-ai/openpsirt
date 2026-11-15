// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// Requests to the proxy share one client, so a second request reuses the
// connection the first left idle, and only a request that changes state names
// the origin.
func TestRequestsToTheProxyShareOneConnection(t *testing.T) {
	var opened atomic.Int32
	var mu sync.Mutex
	var origins []string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		origins = append(origins, req.Method+" "+req.Header.Get("Origin"))
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			opened.Add(1)
		}
	}
	server.Start()
	t.Cleanup(server.Close)

	r := &run{base: server.URL, client: proxyClient()}
	t.Cleanup(r.client.CloseIdleConnections)
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodGet} {
		status, body, err := r.do(t.Context(), method, "/")
		if err != nil || status != http.StatusOK || string(body) != "ok" {
			t.Fatalf("%s answered %d %q: %v", method, status, body, err)
		}
	}
	if got := opened.Load(); got != 1 {
		t.Errorf("three requests opened %d connections, want 1", got)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"GET ", "POST " + server.URL, "GET "}
	for i := range want {
		if i >= len(origins) || origins[i] != want[i] {
			t.Errorf("request %d carried %v, want %q", i, origins, want[i])
		}
	}
}
