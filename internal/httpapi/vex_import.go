// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
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

// SaidBody is one standing third-party statement, as a finding shows it.
type SaidBody struct {
	// ID is the citation a decision carries when somebody starts from this, so
	// a revision to it can be noticed later.
	ID        int64  `json:"id" doc:"Pass as from_statement when starting a decision from this, so a later revision can be noticed"`
	Publisher string `json:"publisher"`
	// Source is which kind of document carried it and Identifier the name the
	// publisher gave that document. An advisory is recognized by its own name;
	// a statement set carries none, because a publisher issues one.
	Source        evidenceSource `json:"source" doc:"Which kind of document carried it"`
	Identifier    string         `json:"identifier,omitempty" doc:"The name the publisher gave the advisory"`
	Status        string         `json:"status" doc:"Their statement, in the format's own vocabulary"`
	Justification string         `json:"justification,omitempty" doc:"The term they gave for it, where the status is one that takes one"`
	// About is the version the publisher spoke about, where they named one. A
	// status read without it is a claim about a version the reader cannot see:
	// "fixed" against a component that is not at that version says the
	// opposite of what it looks like.
	About string `json:"about,omitempty" doc:"The version they made the claim about, where they named one"`
	// Statement is the reasoning, which is the part worth having: the status
	// is in the fix state already.
	Statement string `json:"statement,omitempty" doc:"Their reasoning. What a triager otherwise types from memory"`
	Document  string `json:"document" doc:"The document it came from"`
	At        string `json:"at" doc:"The moment it was uploaded here"`
	// Offers is the outcome this would prefill, where it offers one. A
	// publisher saying they will not fix something is not the same as saying
	// it does not apply, so that offers a will-not-fix and never a dismissal.
	// A statement naming a version offers nothing against a different one.
	Offers outcomeOffered `json:"offers,omitempty" doc:"The outcome this offers as a prefill, where it was made about the version shipped here. Never applied by itself"`
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
func uploaded(in Ingest, file huma.FormFile, read func(io.Reader) error) (string, error) {
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
		return "", asked(in.Logger, err)
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

func registerVexImport(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
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
		MaxBodyBytes: maxUpload(in.Limits),
		Middlewares:  huma.Middlewares{boundedForm(api, maxUpload(in.Limits))},
	}, deploymentWide, ""), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Publisher string `query:"publisher" maxLength:"191" doc:"The publisher, where the document does not name itself. At most 191 characters"`
		RawBody   huma.MultipartFormFiles[statementParts]
	}) (*struct{ Body StatementsTakenBody }, error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		by, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		product, err := catalog.NewStore(in.DB.DB).ProductByName(ctx, input.Product)
		if err != nil {
			return nil, absent(in.Logger, err, "that product could not be looked up", noSuchProduct)
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
		if len(publisher) > finding.MostPublisher {
			return nil, huma.Error422UnprocessableEntity(fmt.Sprintf(
				"who published it is longer than the %d characters this records; "+
					"name it with ?publisher=", finding.MostPublisher))
		}
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
		var recorded, superseded int
		if err := changing(ctx, in.DB, in.logger(), func(ctx context.Context, tx bun.Tx) error {
			var err error
			recorded, superseded, err = finding.NewStore(tx).RecordStatements(ctx, by,
				product.ID, finding.Supplied{
					Source:    finding.FromVex,
					Publisher: publisher,
					Document:  file.Filename,
					Digest:    digest,
				}, statements)
			if err != nil {
				return asked(in.Logger, err)
			}
			if err := noted(ctx, tx, trail.Setting, "VEX statements from "+publisher,
				nil, trail.Said(file.Filename, true)); err != nil {
				return notRecorded(in.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}

		return &struct{ Body StatementsTakenBody }{Body: StatementsTakenBody{
			Publisher: strings.ToLower(publisher), Recorded: recorded, Superseded: superseded,
			Digest: digest,
		}}, nil
	})
}

// cited is a VEX statement's identifier as a citation, or none where
// nothing was cited. Zero is "nothing", which is what a body that omits the
// field sends.
func cited(id int64) *int64 {
	if id == 0 {
		return nil
	}
	return &id
}
