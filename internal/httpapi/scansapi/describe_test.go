// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scansapi

import (
	"errors"
	"net/http"
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

// The door answers a part this server could not read as its own fault, and
// names no path on it; a document it read and refused is a 422 the receipts
// record.
func TestTheDoorAnswersAnUnreadablePartAsAFault(t *testing.T) {
	parts := &uploadParts{Inventory: huma.FormFile{File: failing{strings.NewReader("")}, IsSet: true}}
	_, _, _, err := describe(parts, sbom.Limits{})
	answer, refused := unreadable(nil, err)
	var status huma.StatusError
	if refused || !errors.As(answer, &status) || status.GetStatus() != http.StatusInternalServerError {
		t.Errorf("a part this server could not read answered %v, refused %v; want a fault", answer, refused)
	}
	if strings.Contains(answer.Error(), "/tmp/") {
		t.Errorf("the answer names a path on this server: %v", answer)
	}
	_, _, _, err = describe(&uploadParts{}, sbom.Limits{})
	answer, refused = unreadable(nil, err)
	if !refused || !errors.As(answer, &status) || status.GetStatus() != http.StatusUnprocessableEntity {
		t.Errorf("an upload with no inventory answered %v, refused %v; want a recorded 422", answer, refused)
	}
}
