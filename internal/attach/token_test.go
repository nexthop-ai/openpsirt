// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package attach_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
)

// An identifier an attachment is minted with is one text can refer to.
//
// The two are written in two packages: this one mints the identifier, and the
// text policy decides what a reference to one looks like. A minted identifier
// the policy does not recognize is a file no text ever counts as referred to,
// which the collection pass then removes.
func TestAMintedAttachmentIsOneTextCanReferTo(t *testing.T) {
	for range 20 {
		token, err := attach.MintToken()
		if err != nil {
			t.Fatal(err)
		}
		source := "The capture is [here](" + markdown.Attachment + ":" + token + ")."
		if err := markdown.Check(source); err != nil {
			t.Fatalf("text referring to %s is refused: %v", token, err)
		}
		if got := markdown.References(source); len(got) != 1 || got[0] != token {
			t.Fatalf("text referring to %s is read as referring to %v", token, got)
		}
	}
}
