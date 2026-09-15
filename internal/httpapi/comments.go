package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// The words people put on a claim, and what they said before.
//
// Their own subject: everything else in triage_read.go is about decisions and
// claims, and this is about text and its revisions — which is why an edit, a
// write, had ended up in a file named for reading.
func registerComments(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-claim-comments", Method: http.MethodGet,
		Path:    "/v1/claims/{id}/comments",
		Summary: "List comments on a claim",
		Description: "Returns the comments on a claim, oldest first, with who wrote each and " +
			"when. A comment that has been edited also carries when it was last changed.\n\n" +
			"Comments are separate from the justification and never affect an approval.",
		Tags: []string{"Triage"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		ID int64 `path:"id"`
	}) (*listOutput[CommentBody], error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		comments, err := store.Discussion(ctx, subject, input.ID)
		if err != nil {
			return nil, refusedDecision(in.Logger, err)
		}

		authors := make([]int64, 0, len(comments))
		for _, comment := range comments {
			authors = append(authors, comment.WrittenBy)
		}
		names, err := access.NewStore(in.DB.DB).Names(ctx, authors)
		if err != nil {
			return nil, wentWrong(in.Logger, "the discussion could not be read", err)
		}

		out := &listOutput[CommentBody]{}
		out.Body.Items = make([]CommentBody, 0, len(comments))
		for _, comment := range comments {
			body := CommentBody{
				ID: comment.ID, Body: comment.Body,
				WrittenBy: names[comment.WrittenBy],
				WrittenAt: comment.WrittenAt.Format(time.RFC3339),
			}
			if comment.EditedAt != nil {
				body.EditedAt = comment.EditedAt.Format(time.RFC3339)
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "edit-comment", Method: http.MethodPut, Path: "/v1/comments/{id}",
		Summary: "Edit a comment",
		Description: "Replaces the text of a comment. Only its author may do this.\n\n" +
			"**What it said before is kept**, and read back with " +
			"`GET /v1/comments/{id}/history`. A comment is part of the record that goes " +
			"public at disclosure, and a record whose earlier text is unrecoverable is " +
			"readable rather than checkable — which is the property the whole append-only " +
			"history exists for.\n\n" +
			"The text is markdown and is validated before it is stored; a 422 names the line and " +
			"the offending text.",
		Tags: []string{"Triage"},
	}, perProduct, "Only the author may edit a comment.", approveRights()...), func(ctx context.Context, input *struct {
		ID   int64 `path:"id"`
		Body struct {
			Body string `json:"body" minLength:"1"`
		}
	}) (*struct{ Body MentionsBody }, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		claimID, err := store.Reword(ctx, subject, input.ID, input.Body.Body)
		if err != nil {
			return nil, refusedDecision(in.Logger, err)
		}
		dropped := tellMentioned(ctx, in, subject, store, claimID, input.Body.Body)
		return &struct{ Body MentionsBody }{Body: MentionsBody{NotNotified: dropped}}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-comment-history", Method: http.MethodGet,
		Path:    "/v1/comments/{id}/history",
		Summary: "List earlier revisions of a comment",
		Description: "Every version of a comment that has been replaced, oldest first. " +
			"The comment itself carries what it says now.\n\n" +
			"A comment is part of the record that goes public at disclosure, so what it said " +
			"before has to be recoverable: an edit that overwrites leaves a record somebody " +
			"can read and nobody can check.\n\n" +
			"Answers only where you may read what the comment is about — the same rule as " +
			"reading the comment itself, asked of the decision rather than of the comment, " +
			"because two rules for one question is one rule out of step.",
		Tags: []string{"Triage"},
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		ID int64 `path:"id"`
	}) (*listOutput[WasSaidBody], error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		rows, err := store.Earlier(ctx, subject, input.ID)
		if err != nil {
			return nil, refusedDecision(in.Logger, err)
		}
		out := &listOutput[WasSaidBody]{}
		out.Body.Items = make([]WasSaidBody, 0, len(rows))
		for _, row := range rows {
			out.Body.Items = append(out.Body.Items, WasSaidBody{
				Version: row.Ordinal, Body: row.Body,
				ReplacedAt: row.ReplacedAt.Format(time.RFC3339),
			})
		}
		return out, nil
	})
}

// WasSaidBody is one version of a comment that has been replaced.
type WasSaidBody struct {
	Version    int    `json:"version" doc:"Which version this was, counting from one"`
	Body       string `json:"body" doc:"What it said, in markdown"`
	ReplacedAt string `json:"replaced_at" doc:"When it stopped saying that"`
}

// DecisionsOutput is a page of decisions, with how many there are behind it.
type DecisionsOutput struct {
	Body struct {
		Items []DecisionDetail `json:"items"`
		Total int              `json:"total"`
	}
}
