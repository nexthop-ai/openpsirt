// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"strings"
)

// docker runs one docker command and answers what it printed. A failure
// carries what docker said on standard error.
type docker func(ctx context.Context, args ...string) (string, error)

func runDocker(ctx context.Context, args ...string) (string, error) {
	var stderr bytes.Buffer
	c := exec.CommandContext(ctx, "docker", args...) //nolint:gosec // G204: arguments this tool built itself
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

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
// A URL naming another host, or a loopback port no container publishes, is
// reached through host.docker.internal: a server listening on a real interface
// answers there on every setup that maps the name. Any docker command failing
// on the way to a container that does publish the port is an error, with what
// docker said, because the fallback cannot reach a port published on loopback
// alone and would fail minutes later with nothing to say why.
func reachEngine(ctx context.Context, u *url.URL, run docker) (host, attached string, err error) {
	fallback := "host.docker.internal:" + u.Port()
	if !loopback(u.Hostname()) {
		return fallback, "", nil
	}
	if u.Port() == "" {
		return "", "", fmt.Errorf("the engine URL names %s and no port, so no container publishing it can be found", u.Hostname())
	}
	out, err := run(ctx, "ps", "--filter", "publish="+u.Port(), "--format", "{{.Names}}")
	if err != nil {
		return "", "", err
	}
	names := strings.Fields(out)
	switch len(names) {
	case 0:
		return fallback, "", nil
	case 1:
	default:
		return "", "", fmt.Errorf("%d containers publish port %s (%s), so which is the engine is unknown",
			len(names), u.Port(), strings.Join(names, ", "))
	}
	ports, err := run(ctx, "port", names[0])
	if err != nil {
		return "", "", err
	}
	inside := publishedAs(ports, u.Port())
	if inside == "" {
		return "", "", fmt.Errorf("%s does not say which of its ports is published on %s", names[0], u.Port())
	}
	// The network is the release demo's, made here first so the engine can
	// join it before the release's container starts. Every release's demo
	// leaves a network that already exists alone.
	if _, err := run(ctx, "network", "create", "--subnet", subnet, network); err != nil {
		if _, exists := run(ctx, "network", "inspect", network); exists != nil {
			return "", "", err
		}
	}
	if _, err := run(ctx, "network", "connect", network, names[0]); err != nil && !connected(ctx, run, names[0]) {
		return "", "", err
	}
	return net.JoinHostPort(names[0], inside), names[0], nil
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
func connected(ctx context.Context, run docker, name string) bool {
	out, err := run(ctx, "inspect", "--format", "{{range $n, $_ := .NetworkSettings.Networks}}{{$n}} {{end}}", name)
	return err == nil && strings.Contains(" "+out, " "+network+" ")
}
