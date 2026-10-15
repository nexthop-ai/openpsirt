// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// signedFor is how long an address handed to a browser lasts.
//
// Long enough to follow a redirect and start a download on a slow connection,
// short enough that an address copied out of a browser's history is not a way
// back in. It is not a session: the authorization happened before the redirect
// was issued.
const signedFor = 5 * time.Minute

// AttachmentBody is one file hanging off an issue.
type AttachmentBody struct {
	Token string `json:"token" doc:"Refer to this in text as attachment:<token>. It is the only identifier for a file, and never an address"`
	// Reference is the same thing written out, because the thing somebody
	// pastes is what they want back rather than a value to assemble.
	Reference   string `json:"reference" doc:"The reference to paste into a justification or a comment"`
	Filename    string `json:"filename" doc:"Its name when it arrived"`
	ContentType string `json:"content_type" doc:"The type it is served as, which is decided here and is not what the uploader called it"`
	Size        int64  `json:"size" doc:"Bytes"`
	Inline      bool   `json:"inline,omitempty" doc:"Whether it is displayed in the page rather than downloaded. Only a small allowlist of raster image types is"`
	UploadedAt  string `json:"uploaded_at"`
	// Redacted says an administrator took the file back out. The record and
	// the reference stay, so text that pointed at it says what happened
	// rather than pointing at nothing.
	Redacted       bool   `json:"redacted,omitempty" doc:"The file was removed on purpose. The record of it remains"`
	RedactedReason string `json:"redacted_reason,omitempty" doc:"The reason it was removed"`
}

// attachmentUploaded is the answer to a file stored.
type attachmentUploaded struct {
	Status int
	Body   AttachmentBody
}

// attachmentsOutput is the files attached to one thing.
type attachmentsOutput struct {
	Body struct {
		Items []AttachmentBody `json:"items"`
	}
}

// uploaded answers an upload from what storing it did, with the refusals an
// issue's file and a report's file share: too large, no room left, or
// anything the store refused.
func uploaded(in core.Deps, stored *attach.Attachment, err error, size, maxSize int64) (*attachmentUploaded, error) {
	switch {
	case errors.Is(err, attach.ErrTooLarge):
		return nil, huma.Error413RequestEntityTooLarge(fmt.Sprintf(
			"that file is %d bytes and this deployment accepts %d", size, maxSize))
	case errors.Is(err, attach.ErrNoRoom):
		return nil, huma.Error507InsufficientStorage(attach.ErrNoRoom.Error())
	case err != nil:
		return nil, core.Refused(in.Logger, err, "cannot store that file")
	}
	return &attachmentUploaded{Status: http.StatusCreated, Body: attachmentBody(stored)}, nil
}

// attachmentList renders the files attached to one thing, in the order given.
func attachmentList(rows []attach.Attachment) *attachmentsOutput {
	out := &attachmentsOutput{}
	out.Body.Items = make([]AttachmentBody, 0, len(rows))
	for i := range rows {
		out.Body.Items = append(out.Body.Items, attachmentBody(&rows[i]))
	}
	return out
}

func attachmentBody(a *attach.Attachment) AttachmentBody {
	out := AttachmentBody{
		Token: a.Token, Reference: markdown.Attachment + ":" + a.Token,
		Filename: a.Filename, ContentType: a.ContentType, Size: a.SizeBytes,
		Inline: a.Inline(), UploadedAt: core.Stamp(a.UploadedAt),
	}
	if a.Redacted() {
		out.Redacted = true
		if a.RedactedReason != nil {
			out.RedactedReason = *a.RedactedReason
		}
	}
	return out
}

// attachmentParts is what an upload carries.
type attachmentParts struct {
	File huma.FormFile `form:"file" required:"true"`
	// Evidence says the file hangs off the issue itself rather than off text
	// somebody is part way through writing.
	//
	// Declared as a boolean so the framework parses it and refuses what is
	// not one. Compared against the literal "true", every other spelling —
	// "True", "1", "yes" — reads as false and marks the file for deletion a
	// day later, with the uploader told it worked.
	Evidence bool `form:"evidence"`
}

// arrivedParts is what an upload against a report carries.
//
// The file alone. An issue's upload asks whether the file hangs off the issue
// or off text somebody is part way through writing; a report has no text, so
// the question has one answer and offering it would be offering a field that
// changes nothing.
type arrivedParts struct {
	File huma.FormFile `form:"file" required:"true"`
}

func registerAttachments(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "upload-attachment", Method: http.MethodPost,
		Path:    "/v1/products/{product}/issues/{vulnerability}/attachments",
		Summary: "Attach a file to an issue",
		Description: "Stores one file against an issue and returns the reference to put in text. " +
			"Refer to it as `attachment:<token>` — as a link for anything downloaded, or as a " +
			"markdown image for the raster types displayed in the page. An address of the store " +
			"never appears in text.\n\n" +
			"The content type is decided here from the bytes and is never the one that was " +
			"uploaded. Everything outside a small allowlist of raster images is served as an " +
			"attachment download whatever it is.\n\n" +
			"Refused when the file is larger than this deployment accepts, when it has no " +
			"room left, or when it would take you past your own share of the store; all " +
			"three limits are settings. A deployment that has configured no store " +
			"holds no attachments and says so. Answers 503 with `Retry-After` when the " +
			"deployment is already reading as many uploads as it takes at once.\n\n" +
			"An upload nothing refers to is removed after a day, so a file attached and then " +
			"abandoned does not accumulate. Send `evidence=true` where the file hangs off the " +
			"issue itself — a test case that proves the flaw — rather than off text you are " +
			"about to write: it is then listed at once and never swept, because the issue is " +
			"what points at it.",
		Tags: []string{"Findings"},
		// The caller is authorized for the issue and the request capped at
		// the size this deployment accepts before the form is read. A part
		// is otherwise spooled to the temporary directory in full before
		// anything looks at its size, which is a disk somebody fills from
		// outside.
		Middlewares: huma.Middlewares{core.BoundedForm(api, in, core.Admission{
			Admit: func(hc huma.Context) error {
				_, _, err := issueAttaching(hc.Context(), in, hc.Param("product"), hc.Param("vulnerability"))
				return err
			},
			Limit: attachmentRequest(in),
		})},
	}, core.PerProduct, "A collaborator brought onto this issue may attach to it too.",
		core.TriageRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability" doc:"The issue, under any identifier it goes by"`
		RawBody       huma.MultipartFormFiles[attachmentParts]
	}) (*attachmentUploaded, error) {
		subject, at, err := issueAttaching(ctx, in, input.Product, input.Vulnerability)
		if err != nil {
			return nil, err
		}
		files := in.Attachments()

		maxSize, quota, share, err := attachmentLimits(ctx, in)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "cannot tell what this deployment accepts", err)
		}

		part := input.RawBody.Data().File
		// Evidence hangs off the issue and is listed at once; anything else is
		// waiting for the text that will refer to it, and is swept if that
		// text never arrives.
		evidence := input.RawBody.Data().Evidence
		stored, err := files.Upload(ctx, subject, at,
			part.Filename, part, part.Size, maxSize, quota, share, evidence)
		return uploaded(in, stored, err, part.Size, maxSize)
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-attachments", Method: http.MethodGet,
		Path:    "/v1/products/{product}/issues/{vulnerability}/attachments",
		Summary: "List files attached to an issue",
		Description: "What text about this issue refers to. An upload nothing refers to yet is " +
			"not listed, because it is not attached to anything — it becomes visible here when " +
			"the justification or comment naming it is saved.\n\n" +
			"A file an administrator removed is still listed, saying so, because the text that " +
			"pointed at it still does.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability"`
	}) (*attachmentsOutput, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		files := in.Attachments()
		productID, vulnerabilityID, err := files.Issue(ctx, subject, input.Product, input.Vulnerability)
		if err != nil {
			return nil, core.Absent(in.Logger, err, "that issue could not be looked up",
				func() error { return huma.Error404NotFound(attach.ErrNoSuchIssue.Error()) })
		}
		rows, err := files.ForIssue(ctx, subject, productID, vulnerabilityID)
		if err != nil {
			return nil, core.Refused(in.Logger, err, "cannot read what is attached")
		}
		return attachmentList(rows), nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "fetch-attachment", Method: http.MethodGet,
		Path:    "/v1/attachments/{token}",
		Summary: "Fetch an attached file",
		Description: "Authorized against the issue the file hangs off — whoever may read the " +
			"text may read what it refers to — and only then served.\n\n" +
			"Two shapes, and a caller has to follow both. An image displayed in the page is " +
			"sent from here; everything else answers 303 with a short-lived address at the " +
			"store. Either way the content type and the disposition are the ones decided at " +
			"upload, never the ones the file arrived with.\n\n" +
			"A file an administrator removed answers 410: the record and the reference remain, " +
			"and the bytes are gone on purpose.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Token string `path:"token" doc:"The identifier text refers to, without the attachment: prefix"`
	}) (*huma.StreamResponse, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		files := in.Attachments()
		if !files.Configured() {
			return nil, huma.Error501NotImplemented(attach.ErrNotConfigured.Error())
		}
		row, address, body, err := files.Fetch(ctx, subject, input.Token, signedFor)
		switch {
		case errors.Is(err, attach.ErrGone):
			return nil, huma.Error410Gone("that file was removed")
		case err != nil:
			return nil, core.Refused(in.Logger, err, "cannot read that file")
		}

		return &huma.StreamResponse{Body: func(hc huma.Context) {
			// Never cached by anything in between. The address is short-lived
			// and the authorization is per request, so a shared cache holding
			// the answer would be handing the file to whoever asked next.
			hc.SetHeader("Cache-Control", "private, no-store")
			if address != "" {
				hc.SetHeader("Location", address)
				hc.SetStatus(http.StatusSeeOther)
				return
			}
			defer func() { _ = body.Close() }()
			hc.SetHeader("Content-Type", row.ContentType)
			hc.SetHeader("Content-Disposition", attach.Disposition(row))
			hc.SetHeader("Content-Length", strconv.FormatInt(row.SizeBytes, 10))
			hc.SetStatus(http.StatusOK)
			if _, err := io.Copy(hc.BodyWriter(), body); err != nil {
				in.Log().ErrorContext(ctx, "sending an attachment stopped part way",
					"error", err, "token", row.Token)
			}
		}}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "redact-attachment", Method: http.MethodDelete,
		Path:    "/v1/attachments/{token}",
		Summary: "Remove an attached file",
		Description: "Takes the bytes back out and leaves the record. The reference in the text " +
			"stays and says the file was removed, which is the difference between a redaction " +
			"and a hole in the record.\n\n" +
			"Administrators only. A reason is required, and it is recorded and shown wherever " +
			"the text referred to the file.",
		Tags: []string{"Administration"},
	}, core.DeploymentWide, ""), func(ctx context.Context, input *struct {
		Token string `path:"token"`
		Body  struct {
			Reason string `json:"reason" minLength:"1" maxLength:"1000" doc:"The reason the file is being removed. Recorded and shown wherever the text referred to it"`
		}
	}) (*struct{}, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		files := in.Attachments()
		if !files.Configured() {
			return nil, huma.Error501NotImplemented(attach.ErrNotConfigured.Error())
		}
		err = files.Redact(ctx, subject, input.Token, input.Body.Reason)
		switch {
		case errors.Is(err, attach.ErrGone):
			return nil, huma.Error410Gone("that file was already removed")
		case errors.Is(err, attach.ErrNoReason):
			return nil, huma.Error422UnprocessableEntity(attach.ErrNoReason.Error())
		case err != nil:
			return nil, core.Refused(in.Logger, err, "cannot remove that file")
		}
		return nil, nil
	})
}

// attachmentLimits reads what this deployment accepts.
func attachmentLimits(ctx context.Context, in core.Deps) (maxSize, quota, share int64, err error) {
	settings := setting.NewStore(in.DB.DB)
	size, err := settings.Count(ctx, setting.AttachmentMaxSize, setting.DefaultAttachmentMaxSize)
	if err != nil {
		return 0, 0, 0, err
	}
	held, err := settings.Count(ctx, setting.AttachmentQuota, setting.DefaultAttachmentQuota)
	if err != nil {
		return 0, 0, 0, err
	}
	each, err := settings.Count(ctx, setting.AttachmentShare, setting.DefaultAttachmentShare)
	if err != nil {
		return 0, 0, 0, err
	}
	return int64(size), int64(held), int64(each), nil
}

// issueAttaching is the person attaching and the issue a file would hang off,
// where they may attach to it, and the refusal otherwise.
//
// Asked before the form is read as well as by the handler, in the words the
// handler answers in, so somebody who may not attach spools nothing and
// learns nothing from which of the two refused.
func issueAttaching(ctx context.Context, in core.Deps, product, vulnerability string) (
	access.Subject, attach.Against, error) {

	subject, err := core.Reading(ctx)
	if err != nil {
		return access.Subject{}, attach.Against{}, err
	}
	files := in.Attachments()
	if !files.Configured() {
		return access.Subject{}, attach.Against{}, huma.Error501NotImplemented(attach.ErrNotConfigured.Error())
	}
	productID, vulnerabilityID, err := files.Issue(ctx, subject, product, vulnerability)
	if err != nil {
		return access.Subject{}, attach.Against{}, core.Absent(in.Logger, err, "that issue could not be looked up",
			func() error { return huma.Error404NotFound(attach.ErrNoSuchIssue.Error()) })
	}
	at := attach.Against{ProductID: productID, VulnerabilityID: vulnerabilityID}
	if err := files.MayAttach(ctx, subject, at); err != nil {
		return access.Subject{}, attach.Against{}, core.Refused(in.Logger, err, "cannot store that file")
	}
	return subject, at, nil
}

// attachmentRequest is the largest attachment upload read at all: one file of
// the size this deployment accepts, and the form around it.
func attachmentRequest(in core.Deps) func(context.Context) (int64, error) {
	return func(ctx context.Context) (int64, error) {
		maxSize, _, _, err := attachmentLimits(ctx, in)
		if err != nil {
			return 0, err
		}
		return maxSize + core.Envelope, nil
	}
}
