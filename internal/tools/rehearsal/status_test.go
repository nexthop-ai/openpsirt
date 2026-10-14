// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestABuildWhoseCountDoesNotReadIsNotSettled(t *testing.T) {
	out := "builds\n" +
		"  openpsirt/streams/main/variants/binary   scan scanned · open 12 findings\n" +
		"  openpsirt/streams/v1.0/variants/binary   scan scanned · open unreadable\n"
	totals, busy, failed, unread := parseStatus(out)
	if !busy {
		t.Error("a build whose count did not read was read as settled")
	}
	if len(unread) != 1 || !strings.Contains(unread[0], "v1.0") {
		t.Errorf("unread %q, want the v1.0 line", unread)
	}
	if len(failed) != 0 || !reflect.DeepEqual(totals, Totals{"openpsirt/main/binary": 12}) {
		t.Errorf("totals %v failed %v", totals, failed)
	}
}

func TestEveryBuildScannedAndCountedIsSettled(t *testing.T) {
	out := "  a/streams/s/variants/v   scan scanned · open 3 findings\n" +
		"  b/streams/s/variants/v   scan failed · open 0 findings\n" +
		"  c/streams/s/variants/v   scan scanning · open 0 findings\n" +
		"a line that names no build\n"
	totals, busy, failed, unread := parseStatus(out)
	if !busy || len(unread) != 0 {
		t.Errorf("a scan on its way: busy %v, unread %q", busy, unread)
	}
	if !reflect.DeepEqual(failed, []string{"b/s/v"}) || len(totals) != 3 {
		t.Errorf("failed %v totals %v", failed, totals)
	}
	if _, busy, _, _ := parseStatus(out[:strings.Index(out, "  b/")]); busy {
		t.Error("a report where every build scanned and counted read as busy")
	}
}

func TestTheCastMovesOntoTheRehearsalsPorts(t *testing.T) {
	got, err := shiftCast("8081:alice:triage 8090:bob:admin", 18080)
	if err != nil || !reflect.DeepEqual(got, []string{"18081:alice:triage", "18090:bob:admin"}) {
		t.Errorf("shifted %v, %v", got, err)
	}
	if _, err := shiftCast("alice:triage", 18080); err == nil {
		t.Error("a cast entry without a port was accepted")
	}
}

func TestTheSweepAsksTheBuildThatSortsFirst(t *testing.T) {
	builds := Totals{"openpsirt/v1.0/container": 1, "openpsirt/main/container": 1,
		"openpsirt/main/binary": 1, "openpsirt/v1.0/binary": 1}
	for range 20 {
		p, s, v, ok := firstBuild(builds)
		if !ok || p+"/"+s+"/"+v != "openpsirt/main/binary" {
			t.Fatalf("swept %s/%s/%s, want openpsirt/main/binary", p, s, v)
		}
	}
	if _, _, _, ok := firstBuild(Totals{}); ok {
		t.Error("no build named a build")
	}
}

func TestAPathIsFilledOnlyWhenEveryParameterHasAName(t *testing.T) {
	names := map[string]string{"product": "open psirt", "stream": "main"}
	if got, ok := fillPath("/v1/products/{product}/streams/{stream}", names); !ok ||
		got != "/v1/products/open%20psirt/streams/main" {
		t.Errorf("filled %q, %v", got, ok)
	}
	if _, ok := fillPath("/v1/products/{product}/cases/{case}", names); ok {
		t.Error("a parameter with no name read as filled")
	}
}

func TestTheServerIsServedWithWhatTheReleaseStartedItWith(t *testing.T) {
	image := []string{"PATH=/bin", "GRYPE_DB_CACHE_DIR=/var/cache"}
	container := append(append([]string{}, image...),
		"OPENPSIRT_PATCH_BRANCHES=true", "OPENPSIRT_DATABASE_URL=postgres://u:p@h/db", "HTTPS_PROXY=http://proxy")
	got := started(container, image)
	if want := []string{"HTTPS_PROXY=http://proxy", "OPENPSIRT_PATCH_BRANCHES=true"}; !reflect.DeepEqual(got, want) {
		t.Errorf("served with %v, want %v", got, want)
	}

	r := &run{appURL: "sqlite:///data/dev.db", env: got}
	args := strings.Join(r.container("--rm", "image"), " ")
	if !strings.Contains(args, "-e OPENPSIRT_PATCH_BRANCHES ") || strings.Contains(args, "=true") {
		t.Errorf("a release setting is not named, or its value is an argument: %s", args)
	}
	if env := strings.Join(r.withDatabase(), " "); !strings.Contains(env, "OPENPSIRT_PATCH_BRANCHES=true") {
		t.Errorf("the environment does not carry the release's setting: %s", env)
	}
}

func TestAPauseEndsWhenTheRunIsInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	began := time.Now()
	if err := pause(ctx, time.Hour); !errors.Is(err, context.Canceled) || time.Since(began) > time.Second {
		t.Errorf("an interrupted pause answered %v after %s", err, time.Since(began))
	}
}

// fakeDocker answers each docker command by its first two words.
func fakeDocker(answers map[string]string, failing ...string) docker {
	return func(_ context.Context, args ...string) (string, error) {
		key := strings.Join(args[:min(2, len(args))], " ")
		for _, f := range failing {
			if f == key {
				return "", errors.New("docker " + key + ": refused")
			}
		}
		return answers[key], nil
	}
}

func TestALoopbackEngineIsReachedOrRefusedInWords(t *testing.T) {
	u, _ := url.Parse("postgres://u:p@127.0.0.1:15432/x")
	engine := map[string]string{
		"ps --filter":       "openpsirt-pg\n",
		"port openpsirt-pg": "5432/tcp -> 127.0.0.1:15432\n",
		"inspect --format":  network + " ",
	}
	host, attached, err := reachEngine(context.Background(), u, fakeDocker(engine))
	if err != nil || host != "openpsirt-pg:5432" || attached != "openpsirt-pg" {
		t.Errorf("reached %q through %q, %v", host, attached, err)
	}
	for what, d := range map[string]docker{
		"docker ps failing":            fakeDocker(engine, "ps --filter"),
		"two containers on the port":   fakeDocker(map[string]string{"ps --filter": "a\nb\n"}),
		"the network not made":         fakeDocker(engine, "network create", "network inspect"),
		"the engine never joining":     fakeDocker(map[string]string{"ps --filter": "openpsirt-pg\n", "port openpsirt-pg": engine["port openpsirt-pg"]}, "network connect"),
		"the port not published there": fakeDocker(map[string]string{"ps --filter": "openpsirt-pg\n"}),
	} {
		if host, _, err := reachEngine(context.Background(), u, d); err == nil {
			t.Errorf("%s: reached as %q", what, host)
		}
	}
	if host, _, err := reachEngine(context.Background(), u, fakeDocker(engine, "network create")); err != nil {
		t.Errorf("a network already there refused, %q: %v", host, err)
	}
	if host, _, err := reachEngine(context.Background(), u, fakeDocker(map[string]string{})); err != nil ||
		host != "host.docker.internal:15432" {
		t.Errorf("a loopback port no container publishes: %q, %v", host, err)
	}
	other, _ := url.Parse("postgres://u:p@db.example.com:5432/x")
	if host, _, err := reachEngine(context.Background(), other, fakeDocker(nil, "ps --filter")); err != nil ||
		host != "host.docker.internal:5432" {
		t.Errorf("another host: %q, %v", host, err)
	}
}
