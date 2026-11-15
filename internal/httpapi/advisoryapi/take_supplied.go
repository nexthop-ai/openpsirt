// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/docread"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// suppliedForm is the admission a supplier's uploaded document passes before
// any of its route's own checks: the form bounded to the upload limit, and a
// request turned away there recorded against its source.
//
// A published document is somebody else's output arriving over a link we do
// not control, exactly as a scan file is, and this is the first place it can
// be stopped. Without it huma's default does not apply, since it is not
// consulted for multipart at all, so the whole body is spooled to disk first.
func suppliedForm(api huma.API, in core.Deps, source string) huma.Middlewares {
	return huma.Middlewares{core.BoundedForm(api, in, core.Admission{
		Limit:   core.Fixed(core.MaxUpload(in.Limits)),
		Refused: turnedAwayBeforeReading(in, source),
	})}
}

// suppliedDocument is what a parser read out of a supplier's document.
type suppliedDocument struct {
	Publisher, Identifier string
	SaidAt                *time.Time
	Claims                []sbom.Suppression
}

// suppliedTaken is what one supplier document changed, and the record of the
// document it was taken as.
type suppliedTaken struct {
	From                 finding.Supplied
	Recorded, Superseded int
}

// takeSupplied takes one supplier document for a product: the product
// administered, the document read past its digest by read, its names settled
// by name, and its claims recorded under the trail line about writes.
//
// Every refusal after the product resolves is recorded against it, as far as
// the document had been read, through this one path. name sees the publisher
// and identifier the document states, held without the characters that
// reorder or hide text, since both are shown wherever the evidence is; it may
// replace either, and answers a refusal for a name it does not take.
func takeSupplied(ctx context.Context, in core.Deps, productName string, file huma.FormFile,
	source string,
	read func(io.Reader, sbom.Limits) (suppliedDocument, error),
	name func(*finding.Supplied) error,
	about func(finding.Supplied) string,
) (suppliedTaken, error) {

	by, product, err := core.AdministeredProduct(ctx, in, in.Handle(), productName)
	if err != nil {
		return suppliedTaken{}, err
	}
	from := finding.Supplied{
		Source: source, Document: documentName(file.Filename), Arrived: &finding.Arrival{},
	}
	refused := func(err error) (suppliedTaken, error) {
		turnedAway(ctx, in, by, product.ID, from, err)
		return suppliedTaken{}, err
	}
	var said suppliedDocument
	digest, err := uploaded(in, file, func(r io.Reader) error {
		var err error
		said, err = read(r, in.Limits.OrDefault())
		return err
	})
	if err != nil {
		return refused(err)
	}
	from.Digest = digest
	from.Publisher = strings.TrimSpace(attach.Visible(said.Publisher))
	from.Identifier = strings.TrimSpace(attach.Visible(said.Identifier))
	// What a statement stating no time of its own was made at, which orders
	// it against the publisher's other documents.
	from.SaidAt = said.SaidAt
	if err := name(&from); err != nil {
		return refused(err)
	}
	recorded, superseded, err := recordSupplied(ctx, in, by, product.Name, from, said.Claims, about(from))
	if err != nil {
		return refused(err)
	}
	return suppliedTaken{From: from, Recorded: recorded, Superseded: superseded}, nil
}

// uploaded streams one third party's document past a digest, parses it with
// read, and answers the digest of the bytes that arrived.
//
// Read as a stream, digested as it goes, and never held whole. Read into
// memory it is held twice — the growing buffer and then a copy of it to parse
// from — which is about two and a half times the limit, against a container
// that ships with less than that: an administrator importing a large vendor
// document gets the process killed rather than an answer. The scan upload
// streams a document of the same size past the same digest and holds none of
// it.
//
// Read one byte past the limit, so a document over it is refused as too large
// rather than cut off and reported as malformed — and so the digest recorded
// is over what arrived rather than over the part that fitted.
//
// The parser reads to the end of the file: whitespace after the document is
// read and anything else is refused. So a document it takes has passed
// through the digest whole.
func uploaded(in core.Deps, file huma.FormFile, read func(io.Reader) error) (string, error) {
	most := in.Limits.OrDefault().MaxBytes
	digest := sha256.New()
	counted := &docread.Counting{R: io.TeeReader(io.LimitReader(file, most+1), digest)}
	err := read(counted)
	// Asked before the parse error, because a document cut off at the limit
	// fails as malformed and the honest answer is its size.
	if counted.N > most {
		return "", huma.Error413RequestEntityTooLarge(fmt.Sprintf(
			"that document is larger than the %d bytes this deployment reads", most))
	}
	if err != nil {
		return "", core.Asked(in.Logger, err)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
