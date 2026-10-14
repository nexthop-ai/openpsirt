// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/outward"
)

// healthWithin is how long the running server has to answer a liveness check.
// The image's health check gives the whole command three seconds.
const healthWithin = 2 * time.Second

// runHealth asks the running server whether it is alive, at the address the
// same configuration tells it to listen on. It is the image's health check, so
// a container configured to listen elsewhere is asked where it listens.
//
// Never through a proxy, including for an address that is not loopback. A
// deployment that sets HTTP_PROXY for the scanner sets it for everything in the
// image, and a proxy asked about this container answers for itself.
func runHealth(ctx context.Context, addr string) error {
	at, err := probeAddress(addr)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, healthWithin)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+at+"/healthz", nil)
	if err != nil {
		return fmt.Errorf("ask %s whether it is alive: %w", at, err)
	}
	req.Header.Set("User-Agent", outward.Agent)
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ask %s whether it is alive: %w", at, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s to a liveness check", at, resp.Status)
	}
	return nil
}

// probeAddress is where to reach a server listening on addr from inside its
// own container: the address it names, or loopback where it names every
// interface.
func probeAddress(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("OPENPSIRT_ADDR: %w", err)
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}
