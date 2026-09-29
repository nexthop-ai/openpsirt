// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// statementParts is a VEX document arriving.
type statementParts struct {
	// The declared content type is permissive for the reason an inventory's
	// is: a part's type is decided by reading it rather than by the label a
	// client put on it.
	Statements huma.FormFile `form:"statements" contentType:"application/json,application/octet-stream" required:"true"`
}

// StatementsTakenBody is the record of what one VEX document changed.
type StatementsTakenBody struct {
	Publisher  string `json:"publisher" doc:"The publisher the document names"`
	Recorded   int    `json:"recorded" doc:"Statements taken from it"`
	Superseded int    `json:"superseded" doc:"This publisher's previous statements, set aside rather than deleted"`
	Digest     string `json:"digest" doc:"The document's digest, which is how a revision is noticed later"`
}

// counting is a reader that says how much has gone past it.
//
// The length a size refusal needs, which a stream does not otherwise carry:
// the document is never held, so its length is only knowable by counting it on
// the way through.
type counting struct {
	r io.Reader
	n int64
}

func (c *counting) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
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
func uploaded(in core.Deps, file huma.FormFile, read func(io.Reader) error) (string, error) {
	most := in.Limits.OrDefault().MaxBytes
	digest := sha256.New()
	counted := &counting{r: io.TeeReader(io.LimitReader(file, most+1), digest)}
	err := read(counted)
	// Asked before the parse error, because a document cut off at the limit
	// fails as malformed and the honest answer is its size.
	if counted.n > most {
		return "", huma.Error413RequestEntityTooLarge(fmt.Sprintf(
			"that document is larger than the %d bytes this deployment reads", most))
	}
	if err != nil {
		return "", core.Asked(in.Logger, err)
	}
	// Whatever the parser left, read past the digest exactly once. The digest
	// is the whole document by definition, and a reader that answered early
	// would otherwise record a hash of the part it read.
	//
	// Drained into nothing, because the reader above already tees into the
	// digest: copying into it here hashes every drained byte a second time, so
	// a document with anything after the closing brace — a trailing newline is
	// enough — records a digest that is not the document's, and the digest is
	// what says whether a publisher has revised what an approval was granted
	// against.
	if _, err := io.Copy(io.Discard, counted); err != nil {
		return "", huma.Error400BadRequest("that document could not be read")
	}
	if counted.n > most {
		return "", huma.Error413RequestEntityTooLarge(fmt.Sprintf(
			"that document is larger than the %d bytes this deployment reads", most))
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func registerVexImport(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "upload-vex-statements", Method: http.MethodPost,
		Path:    "/v1/products/{product}/vex-statements",
		Summary: "Upload a VEX document",
		Description: "Takes one OpenVEX document of what a distribution or an upstream " +
			"security team has published about components this product ships.\n\n" +
			"Nothing is applied. What arrives is a third layer beside the build's own " +
			"claims and our decisions: shown as evidence, offered as a prefill, and never " +
			"standing as our judgment by itself.\n\n" +
			"What a document adds over what the scanner already reports is the " +
			"reasoning. The status is in the fix state already.\n\n" +
			"Uploading again from the same publisher sets aside what they said before rather " +
			"than deleting it, so what an approval was granted on the strength of stays " +
			"readable.\n\n" +
			"OpenVEX and CSAF-VEX both read. The two say the same thing in different " +
			"shapes — one puts the status on a statement, the other in which list a product " +
			"identifier appears in — and both become the same claim here, because what a " +
			"publisher is saying does not depend on which file they wrote it in. Which of the " +
			"two a document is decides itself; anything else is refused with a sentence rather " +
			"than half-read.\n\n" +
			"A CSAF security advisory is refused here and taken by the supplier-advisory " +
			"endpoint instead. It is a document about somebody's own flaws, one per issue, " +
			"and what a later upload of it replaces is the advisory of the same name rather " +
			"than everything that publisher has said.",
		Tags: []string{"Ingest"}, DefaultStatus: http.StatusCreated,
		// A published document is somebody else's output arriving over a link
		// we do not control, exactly as a scan file is, and this is the first
		// place it can be stopped. Without it huma's default does not apply —
		// it is not consulted for multipart at all — so the whole body is
		// spooled to disk before any of this endpoint's own checks run.
		MaxBodyBytes: core.MaxUpload(in.Limits),
		Middlewares:  huma.Middlewares{core.BoundedForm(api, core.MaxUpload(in.Limits))},
	}, core.DeploymentWide, ""), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Publisher string `query:"publisher" maxLength:"191" doc:"The publisher, where the document does not name itself. At most 191 characters"`
		RawBody   huma.MultipartFormFiles[statementParts]
	}) (*struct{ Body StatementsTakenBody }, error) {
		if err := core.Administrating(ctx); err != nil {
			return nil, err
		}
		by, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, core.NoDatabase(in.Logger)
		}
		product, err := catalog.NewStore(in.DB.DB).ProductByName(ctx, input.Product)
		if err != nil {
			return nil, core.Absent(in.Logger, err, "that product could not be looked up", core.NoSuchProduct)
		}

		file := input.RawBody.Data().Statements
		var said []sbom.Suppression
		digest, err := uploaded(in, file, func(r io.Reader) error {
			var err error
			said, err = sbom.ReadSuppressions(r, in.Limits.OrDefault())
			return err
		})
		if err != nil {
			return nil, err
		}

		// The publisher is the key a later upload supersedes on, and it is
		// an indexed column of a fixed width. Refused rather than shortened:
		// two publishers agreeing for the width of the column would collapse
		// into one, and the later upload would set aside statements it has
		// nothing to do with.
		//
		// The fallback is the name the client gave the file it uploaded, so
		// the bound has to hold there too — that is the path with nothing
		// else guarding it.
		publisher := strings.TrimSpace(input.Publisher)
		if publisher == "" {
			publisher = strings.TrimSpace(file.Filename)
		}
		if utf8.RuneCountInString(publisher) > finding.MostPublisher {
			return nil, huma.Error422UnprocessableEntity(fmt.Sprintf(
				"who published it is longer than the %d characters this records; "+
					"name it with ?publisher=", finding.MostPublisher))
		}
		recorded, superseded, err := recordSupplied(ctx, in, by, product.ID, finding.Supplied{
			Source:    finding.FromVex,
			Publisher: publisher,
			Document:  file.Filename,
			Digest:    digest,
		}, said, "VEX statements from "+publisher)
		if err != nil {
			return nil, err
		}

		return &struct{ Body StatementsTakenBody }{Body: StatementsTakenBody{
			Publisher: strings.ToLower(publisher), Recorded: recorded, Superseded: superseded,
			Digest: digest,
		}}, nil
	})
}

// statementsOf is what a publisher's document says, one statement for each
// component each claim names.
func statementsOf(said []sbom.Suppression) []finding.Statement {
	statements := make([]finding.Statement, 0, len(said))
	for _, one := range said {
		for _, at := range one.Targets {
			statements = append(statements, finding.Statement{
				Vulnerability: one.Vulnerability,
				Purl:          at.Purl,
				About:         at.VersionNamed(),
				Component:     at.ComponentNamed(),
				Status:        string(one.Status),
				Justification: one.Justification,
				Statement:     one.Statement,
			})
		}
	}
	return statements
}

// recordSupplied records what an uploaded document says about a product, in
// place of what the same document said before, and notes the upload in the
// trail under about. It answers how many statements it recorded and how many
// earlier ones it set aside.
func recordSupplied(ctx context.Context, in core.Deps, by access.Subject, productID int64,
	from finding.Supplied, said []sbom.Suppression, about string) (int, int, error) {

	statements := statementsOf(said)
	var recorded, superseded int
	if err := core.Changing(ctx, in.DB, in.Log(), func(ctx context.Context, tx bun.Tx) error {
		var err error
		recorded, superseded, err = finding.NewStore(tx).RecordStatements(ctx, by,
			productID, from, statements)
		if err != nil {
			return core.Asked(in.Logger, err)
		}
		if err := core.Noted(ctx, tx, trail.Setting, about,
			nil, trail.Said(from.Document, true)); err != nil {
			return core.NotRecorded(in.Logger, err)
		}
		return nil
	}); err != nil {
		return 0, 0, err
	}
	return recorded, superseded, nil
}
