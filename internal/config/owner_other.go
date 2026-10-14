// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package config

import "os"

// ownerOf is the user that owns a file. A system with no numeric owners says
// nothing, and the mode check stands alone.
func ownerOf(os.FileInfo) (int, bool) { return 0, false }
