// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package background_test

import (
	"bytes"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/background"
)

// niceness reads the niceness field of a /proc stat line: the nineteenth,
// counted after the command name, which may itself hold spaces.
func niceness(t *testing.T, stat string) int {
	t.Helper()
	fields := strings.Fields(stat[strings.LastIndexByte(stat, ')')+1:])
	n, err := strconv.Atoi(fields[16])
	if err != nil {
		t.Fatalf("read the niceness from %q: %v", stat, err)
	}
	return n
}

func TestAProgramAndWhatItStartsRunBehindTheServer(t *testing.T) {
	own, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Skipf("no /proc here: %v", err)
	}
	server := niceness(t, string(own))
	if server >= background.Behind {
		t.Skipf("this process already runs at niceness %d", server)
	}

	// The shell prints its own line and then forks cat to print cat's, so one
	// run shows the program and a program it started. The trailing command
	// keeps a shell from running cat in its own place.
	var out bytes.Buffer
	cmd := exec.Command("sh", "-c", "cat /proc/$$/stat; cat /proc/self/stat; true")
	cmd.Stdout = &out
	if err := background.Run(cmd); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want the shell's line and cat's, got %q", out.String())
	}
	shell, cat := strings.Fields(lines[0])[0], lines[1][strings.LastIndexByte(lines[1], ')')+1:]
	if parent := strings.Fields(cat)[1]; parent != shell {
		t.Fatalf("cat's parent is %s, not the shell %s, so this shows nothing inherited", parent, shell)
	}
	for i, who := range []string{"the program", "what it started"} {
		if got := niceness(t, lines[i]); got != background.Behind {
			t.Errorf("%s runs at niceness %d, want %d", who, got, background.Behind)
		}
	}

	after, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	if got := niceness(t, string(after)); got != server {
		t.Errorf("the server moved from niceness %d to %d", server, got)
	}

	// Niceness belongs to a thread, and the one lowered to start the program
	// is never handed back to the scheduler, so no thread of this process is
	// left behind the server. The lowered thread exits once its goroutine
	// has, which is shortly after, so this asks until none remains.
	deadline := time.Now().Add(5 * time.Second)
	for {
		lowered := loweredThreads(t)
		if lowered == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d threads of the server still run at niceness %d", lowered, background.Behind)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// loweredThreads counts this process's threads running at the niceness a
// program is started at.
func loweredThreads(t *testing.T) int {
	t.Helper()
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) == 0 {
		t.Fatal("this process has no threads to read, so this checked nothing")
	}
	lowered := 0
	for _, task := range tasks {
		stat, err := os.ReadFile("/proc/self/task/" + task.Name() + "/stat")
		if err != nil {
			continue // a thread that exited between the listing and the read
		}
		if niceness(t, string(stat)) == background.Behind {
			lowered++
		}
	}
	return lowered
}
