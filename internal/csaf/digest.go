// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package csaf

import (
	"encoding/hex"
	"strings"
)

// DigestIn is the digest a digest file beside a document states, of the size
// given in bytes, and whether it states one.
//
// The file is what the usual checksum tools write: the digest in
// hexadecimal, then optionally the file name. Only the first field is read,
// because the name is the publisher's own and says nothing about the bytes. A
// body that is not a digest of that size — a server answering every address
// with a page of its own — states none, whatever status it came with.
func DigestIn(served []byte, size int) ([]byte, bool) {
	fields := strings.Fields(string(served))
	if len(fields) == 0 {
		return nil, false
	}
	want, err := hex.DecodeString(strings.ToLower(fields[0]))
	if err != nil || len(want) != size {
		return nil, false
	}
	return want, true
}
