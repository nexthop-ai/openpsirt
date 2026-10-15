// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom_test

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// failing hands over its bytes and then fails with err.
type failing struct {
	r   io.Reader
	err error
}

func (f *failing) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	if err == io.EOF {
		return n, f.err
	}
	return n, err
}

// A document whose reader failed partway is a fault of whatever was read
// from, and is not published to the sender as a fault in their file. One
// that ends partway through a value on its own is the sender's to fix.
func TestAReaderThatFailsPartwayIsAFaultNotARefusal(t *testing.T) {
	const partial = `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","na`
	released := errors.New("the document was let go while it was read")

	read := map[string]func(io.Reader) error{
		"an inventory": func(r io.Reader) error {
			_, err := sbom.Read(r, sbom.Limits{})
			return err
		},
		"suppressions": func(r io.Reader) error {
			_, err := sbom.ReadSuppressions(r, sbom.Limits{})
			return err
		},
		"an advisory": func(r io.Reader) error {
			_, err := sbom.ReadAdvisory(r, sbom.Limits{})
			return err
		},
	}
	for name, reading := range read {
		t.Run(name, func(t *testing.T) {
			for _, cause := range []error{released, io.ErrUnexpectedEOF} {
				err := reading(&failing{r: strings.NewReader(partial), err: cause})
				if !errors.Is(err, cause) {
					t.Errorf("a reader failing with %v answered %v", cause, err)
				}
				if refusal.In(err) {
					t.Errorf("a reader failing with %v was refused as the sender's fault: %v",
						cause, err)
				}
			}
			if err := reading(strings.NewReader(partial)); !refusal.In(err) {
				t.Errorf("a document ending partway on its own answered %v, want a refusal", err)
			}
		})
	}
}
