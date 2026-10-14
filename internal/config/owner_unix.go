// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package config

import (
	"os"
	"syscall"
)

// ownerOf is the user that owns a file, where the system says.
func ownerOf(info os.FileInfo) (int, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(stat.Uid), true
}
