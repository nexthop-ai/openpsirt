// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package background

import (
	"os/exec"
)

// Behind is the niceness a program run by a background pass starts at.
//
// The scanner and git share the pod's CPU with the server. At this niceness
// they take what the server leaves idle, so a request is answered while a scan
// or a fetch is running. Lowering one's own priority needs no privilege.
const Behind = 10

// Run starts cmd at the niceness above and waits for it to finish.
//
// Everything the program starts inherits the niceness, so git's own children
// run behind the server as well. Where the priority cannot be lowered the
// program runs anyway, at the server's priority, and the first such failure is
// logged.
func Run(cmd *exec.Cmd) error {
	if err := start(cmd); err != nil {
		return err
	}
	return cmd.Wait()
}
