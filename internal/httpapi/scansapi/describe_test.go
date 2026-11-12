// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scansapi

import (
	"errors"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// failing is a spooled part whose reads fail, as a temporary file does when
// the disk under it fails.
type failing struct{ *strings.Reader }

func (failing) Read([]byte) (int, error) {
	return 0, errors.New("read /tmp/multipart-1: input/output error")
}
func (failing) Close() error { return nil }

// A spooled part that cannot be read is this server's fault and names a path
// on it, so it is never answered as the sender's document refused. A part
// that never arrived is the sender's.
func TestAnUploadThisServerCannotReadIsAFaultNotARefusal(t *testing.T) {
	parts := &uploadParts{Inventory: huma.FormFile{File: failing{strings.NewReader("")}, IsSet: true}}
	if _, _, _, err := describe(parts, sbom.Limits{}); err == nil || refusal.In(err) {
		t.Errorf("a part that failed to read answered %v, want a fault", err)
	}
	if _, _, _, err := describe(&uploadParts{}, sbom.Limits{}); !refusal.In(err) {
		t.Errorf("an upload with no inventory answered %v, want a refusal", err)
	}
}
