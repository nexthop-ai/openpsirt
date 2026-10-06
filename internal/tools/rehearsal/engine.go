// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net"
	"net/url"
	"os/exec"
	"strings"
)

// reachEngine is where a container on the rehearsal's network reaches the
// engine, and the container it attached to get there, or empty.
//
// An engine `make engines-up` made is a container publishing its port on this
// machine's loopback alone, which no other container can reach. So the
// container publishing the port the URL names is attached to the rehearsal's
// network and addressed by its name and its own port. That holds on Docker
// Desktop, rootless Docker and Podman alike, where an address on the host
// differs or is not reachable from a container at all.
//
// A URL naming another host, or a port no container here publishes, is reached
// through host.docker.internal: a server listening on a real interface answers
// there on every setup that maps the name.
func reachEngine(ctx context.Context, u *url.URL) (host, attached string) {
	fallback := "host.docker.internal:" + u.Port()
	if !loopback(u.Hostname()) || u.Port() == "" {
		return fallback, ""
	}
	out, err := exec.CommandContext(ctx, "docker", "ps", "--filter", "publish="+u.Port(), //nolint:gosec // G204: a port from the engine URL this tool was given
		"--format", "{{.Names}}").Output()
	if err != nil {
		return fallback, ""
	}
	names := strings.Fields(string(out))
	if len(names) != 1 {
		return fallback, ""
	}
	ports, err := exec.CommandContext(ctx, "docker", "port", names[0]).Output() //nolint:gosec // G204: a container name docker just listed
	if err != nil {
		return fallback, ""
	}
	inside := publishedAs(string(ports), u.Port())
	if inside == "" {
		return fallback, ""
	}
	// The network is the release demo's, made here first so the engine can
	// join it before the release's container starts. Every release's demo
	// leaves a network that already exists alone.
	_ = exec.CommandContext(ctx, "docker", "network", "create", "--subnet", subnet, network).Run()
	if err := exec.CommandContext(ctx, "docker", "network", "connect", network, names[0]).Run(); err != nil && //nolint:gosec // G204: a container name docker just listed
		!connected(ctx, names[0]) {
		return fallback, ""
	}
	return net.JoinHostPort(names[0], inside), names[0]
}

// loopback reports whether a host names this machine's loopback.
func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// publishedAs reads `docker port` for the container port published on the
// host port given, as "5432" from "5432/tcp -> 127.0.0.1:15432".
func publishedAs(ports, hostPort string) string {
	for _, line := range strings.Split(ports, "\n") {
		inside, outside, found := strings.Cut(line, " -> ")
		if !found {
			continue
		}
		if _, p, err := net.SplitHostPort(strings.TrimSpace(outside)); err == nil && p == hostPort {
			number, _, _ := strings.Cut(strings.TrimSpace(inside), "/")
			return number
		}
	}
	return ""
}

// connected reports whether a container is on the rehearsal's network already,
// which is what a second connect answers as an error.
func connected(ctx context.Context, name string) bool {
	out, err := exec.CommandContext(ctx, "docker", "inspect", "--format", //nolint:gosec // G204: a container name docker just listed
		"{{range $n, $_ := .NetworkSettings.Networks}}{{$n}} {{end}}", name).Output()
	return err == nil && strings.Contains(" "+string(out), " "+network+" ")
}
