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

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// statementParts is a VEX document arriving.
type statementParts struct {
	// The declared content type is permissive for the reason an inventory's
	// is: what a part is gets decided by reading it rather than by the label a
	// client put on it.
	Statements huma.FormFile `form:"statements" contentType:"application/json,application/octet-stream" required:"true"`
}

// StatementsTakenBody is what one VEX document changed.
type StatementsTakenBody struct {
	Publisher  string `json:"publisher" doc:"Who the document says it is from"`
	Recorded   int    `json:"recorded" doc:"Statements taken from it"`
	Superseded int    `json:"superseded" doc:"What this publisher had said before, set aside rather than deleted"`
	Digest     string `json:"digest" doc:"What the document hashed to, which is how a revision is noticed later"`
}

// VexSaidBody is one standing VEX statement, as a finding shows it.
type VexSaidBody struct {
	// ID is what a decision cites when somebody starts from this, so that
	// a revision to it can be noticed later.
	ID            int64  `json:"id" doc:"Pass as from_statement when starting a decision from this, so a later revision can be noticed"`
	Publisher     string `json:"publisher"`
	Status        string `json:"status" doc:"What they said, in the format's own vocabulary"`
	Justification string `json:"justification,omitempty" doc:"The term they gave for it, where the status is one that takes one"`
	// Statement is the reasoning, which is the part worth having: the status
	// is in the fix state already.
	Statement string `json:"statement,omitempty" doc:"Why they reached that answer. What a triager otherwise types from memory"`
	Document  string `json:"document" doc:"The document it came from"`
	At        string `json:"at" doc:"When it was uploaded here"`
	// Offers is the outcome this would prefill, where it offers one. A
	// publisher saying they will not fix something is not the same as saying
	// it does not apply, so that offers a will-not-fix and never a dismissal.
	Offers string `json:"offers,omitempty" enum:"not-applicable,wont-fix,already-fixed" doc:"The outcome this offers as a prefill. Never applied by itself"`
}

// counting is a reader that says how much has gone past it.
//
// What a size refusal needs and what a stream does not otherwise carry: the
// document is never held, so its length is only knowable by counting it on
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

func registerVexImport(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "upload-vex-statements", Method: http.MethodPost,
		Path:    "/v1/products/{product}/vex-statements",
		Summary: "Upload a VEX document",
		Description: "Takes one OpenVEX document of what a distribution or an upstream " +
			"security team has published about components this product ships.\n\n" +
			"**Nothing is applied.** What arrives is a third layer beside the build's own " +
			"claims and our decisions: shown as evidence, offered as a prefill, and never " +
			"standing as our judgment by itself.\n\n" +
			"What a document adds over what the scanner already reports is the " +
			"**reasoning**. The status is in the fix state already.\n\n" +
			"Uploading again from the same publisher sets aside what they said before rather " +
			"than deleting it, so what an approval was granted on the strength of stays " +
			"readable.\n\n" +
			"**OpenVEX and CSAF-VEX both read.** The two say the same thing in different " +
			"shapes — one puts the status on a statement, the other in which list a product " +
			"identifier appears in — and both become the same claim here, because what a " +
			"publisher is saying does not depend on which file they wrote it in. Which of the " +
			"two a document is decides itself; anything else is refused with a sentence rather " +
			"than half-read.\n\n" +
			"A CSAF *advisory* is refused as well, and deliberately: it is a document about " +
			"somebody's own flaws, and reading one as claims about what a build ships would " +
			"take their advisory as this build's argument and every product it names as a " +
			"suppression.",
		Tags: []string{"Ingest"}, DefaultStatus: http.StatusCreated,
		// A published document is somebody else's output arriving over a link
		// we do not control, exactly as a scan file is, and this is the first
		// place it can be stopped. Without it huma's default does not apply —
		// it is not consulted for multipart at all — so the whole body was
		// spooled to disk before any of this endpoint's own checks ran.
		MaxBodyBytes: maxUpload(in.Limits),
		Middlewares:  huma.Middlewares{boundedForm(api, maxUpload(in.Limits))},
	}, deploymentWide, ""), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Publisher string `query:"publisher" doc:"Who published it, where the document does not name itself"`
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

		// Read as a stream, digested as it goes, and never held whole. Read
		// into memory it was held twice — the growing buffer and then a copy
		// of it to parse from — which is about two and a half times the
		// limit, against a container that ships with less than that: an
		// administrator importing a large vendor document got the process
		// killed rather than an answer. The scan upload streams a document of
		// the same size past the same digest and holds none of it.
		//
		// Read one byte past the limit, so a document over it is refused as
		// too large rather than cut off and reported as malformed — and so
		// the digest recorded is over what arrived rather than over the part
		// that fitted.
		file := input.RawBody.Data().Statements
		most := in.Limits.OrDefault().MaxBytes
		digest := sha256.New()
		counted := &counting{r: io.TeeReader(io.LimitReader(file, most+1), digest)}
		said, err := sbom.ReadSuppressions(counted, in.Limits.OrDefault())
		// Asked before the parse error, because a document cut off at the
		// limit fails as malformed and the honest answer is its size.
		if counted.n > most {
			return nil, huma.Error413RequestEntityTooLarge(fmt.Sprintf(
				"that document is larger than the %d bytes this deployment reads", most))
		}
		if err != nil {
			return nil, asked(in.Logger, err)
		}
		// Whatever the parser left. It reads this format to the end today, so
		// there is nothing here to find and no test can make this line matter
		// — it is here because the digest is the whole document by definition
		// and a reader that answered early would otherwise record a hash of
		// the part it read, which is the failure the scan upload copies past
		// its own digest to avoid.
		if _, err := io.Copy(digest, counted); err != nil {
			return nil, huma.Error400BadRequest("that document could not be read")
		}
		if counted.n > most {
			return nil, huma.Error413RequestEntityTooLarge(fmt.Sprintf(
				"that document is larger than the %d bytes this deployment reads", most))
		}

		publisher := strings.TrimSpace(input.Publisher)
		if publisher == "" {
			publisher = file.Filename
		}
		statements := make([]finding.Statement, 0, len(said))
		for _, one := range said {
			for _, at := range one.Targets {
				statements = append(statements, finding.Statement{
					Vulnerability: one.Vulnerability,
					Purl:          at.Purl,
					Component:     componentNamed(at),
					Status:        string(one.Status),
					Justification: one.Justification,
					Statement:     one.Statement,
				})
			}
		}
		recorded, superseded, err := finding.NewStore(in.DB.DB).RecordStatements(ctx, by,
			product.ID, publisher, file.Filename, hex.EncodeToString(digest.Sum(nil)), statements)
		if err != nil {
			return nil, asked(in.Logger, err)
		}
		noteChange(ctx, in, trail.Setting, "VEX statements from "+publisher,
			nil, trail.Said(file.Filename, true))

		return &struct{ Body StatementsTakenBody }{Body: StatementsTakenBody{
			Publisher: strings.ToLower(publisher), Recorded: recorded, Superseded: superseded,
			Digest: hex.EncodeToString(digest.Sum(nil)),
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

// componentNamed is what a statement's target points at, as a component name.
//
// A package identifier where it carries one, and the bare name otherwise: a
// statement made against a source tree names something we cannot resolve to a
// package, and the most that can be said is that a component of that name is
// the one meant.
func componentNamed(at sbom.Target) string {
	if at.Name != "" {
		return at.Name
	}
	name := at.Purl
	if cut := strings.LastIndex(name, "@"); cut > 0 {
		name = name[:cut]
	}
	if cut := strings.LastIndex(name, "/"); cut > 0 {
		name = name[cut+1:]
	}
	return name
}
