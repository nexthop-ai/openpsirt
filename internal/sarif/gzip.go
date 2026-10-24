// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"errors"
	"io"

	"github.com/nexthop-ai/openpsirt/internal/docread"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// gunzipped is a document as JSON: decompressed where it arrived compressed,
// and refused past most bytes once decompressed. A document is compressed
// where it opens with gzip's magic bytes, whatever it was labeled.
func gunzipped(r io.Reader, most int64) (io.Reader, error) {
	br := bufio.NewReader(r)
	head, err := br.Peek(2)
	if err != nil || head[0] != 0x1f || head[1] != 0x8b {
		// Too short to be compressed is read as it is, and refused by the
		// reader as the JSON it is not.
		return br, nil
	}
	z, err := gzip.NewReader(br)
	if err != nil {
		return nil, refusal.Errorf("the document is not readable gzip: %v", err)
	}
	return &unzipped{r: docread.Cap(z, most)}, nil
}

// unzipped states a fault in the compression in words. A fault reading the
// stored bytes beneath it passes through as it is: it is not the sender's.
type unzipped struct{ r io.Reader }

func (u *unzipped) Read(p []byte) (int, error) {
	n, err := u.r.Read(p)
	var corrupt flate.CorruptInputError
	if errors.Is(err, gzip.ErrChecksum) || errors.Is(err, gzip.ErrHeader) ||
		errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &corrupt) {
		return n, refusal.Errorf("the document is not readable gzip: %v", err)
	}
	return n, err
}
