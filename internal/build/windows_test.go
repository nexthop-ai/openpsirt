// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package build_test

import (
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// reserved is the device names Windows will not create a file under, with or
// without an extension, in any case.
var reserved = regexp.MustCompile(`(?i)^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(\..*)?$`)

// unportable is why Windows cannot check a path out, or empty where it can.
func unportable(path string) string {
	for _, segment := range strings.Split(path, "/") {
		switch {
		case reserved.MatchString(segment):
			return segment + " is a device name on Windows"
		case strings.ContainsAny(segment, `<>:"\|?*`):
			return segment + " holds a character Windows refuses in a file name"
		case strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " "):
			return segment + " ends in a dot or a space, which Windows drops"
		}
	}
	return ""
}

func TestAPathWindowsCannotCheckOutIsReported(t *testing.T) {
	for _, path := range []string{"internal/core/nul.go", "a/CON", "a/b:c.go", "a/b."} {
		if unportable(path) == "" {
			t.Errorf("%s passed", path)
		}
	}
	for _, path := range []string{"internal/core/nulchar.go", "a/console.go", "a/null.go"} {
		if why := unportable(path); why != "" {
			t.Errorf("%s reported: %s", path, why)
		}
	}
}

// The upload client is built and tested on Windows, so every tracked path
// has to be one a Windows checkout can write.
func TestEveryTrackedPathChecksOutOnWindows(t *testing.T) {
	out, err := exec.Command("git", "-C", "../..", "ls-files", "-z").Output()
	if err != nil {
		t.Fatalf("list the tracked files: %v", err)
	}
	paths := strings.Split(strings.TrimRight(string(out), "\x00"), "\x00")
	if len(paths) == 0 || paths[0] == "" {
		t.Fatal("no tracked files were found, so this checked nothing")
	}
	for _, path := range paths {
		if why := unportable(path); why != "" {
			t.Errorf("%s: %s", path, why)
		}
	}
}
