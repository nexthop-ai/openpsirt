// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package background

import (
	"log/slog"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
)

var lowering sync.Once

// start lowers the niceness of one operating-system thread and starts cmd from
// it.
//
// A child takes its niceness from the thread that forks it, so it is born
// behind the server and nothing it starts runs before the priority is set.
// Setting the priority of the child after it starts leaves a window in which
// git has already started its own children at the server's priority.
//
// Niceness on Linux belongs to a thread. The thread lowered here cannot raise
// itself again without privilege, so it is never handed back: a goroutine that
// ends while locked to its thread takes the thread with it, and the server's
// other threads keep their priority.
func start(cmd *exec.Cmd) error {
	started := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		tid := syscall.Gettid()
		// The kernel's value is 20 minus the niceness. A thread already at or
		// past the target is left where it is: setting it would be raising it.
		current, err := syscall.Getpriority(syscall.PRIO_PROCESS, tid)
		if err == nil && 20-current < Behind {
			err = syscall.Setpriority(syscall.PRIO_PROCESS, tid, Behind)
		}
		if err != nil {
			lowering.Do(func() {
				slog.Warn("background programs run at the server's CPU priority", "error", err)
			})
		}
		started <- cmd.Start()
	}()
	return <-started
}
