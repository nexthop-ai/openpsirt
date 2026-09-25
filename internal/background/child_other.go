// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package background

import "os/exec"

// start starts cmd at the caller's priority. Niceness is lowered on Linux,
// which is the only platform the image is built for.
func start(cmd *exec.Cmd) error { return cmd.Start() }
