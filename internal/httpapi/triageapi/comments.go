// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// The words people put on a claim, and the revisions before them.
//
// Their own subject: everything in triage_read.go is about decisions and
// claims, and this is about text and its revisions.
func registerComments(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-claim-comments", Method: http.MethodGet,
		Path:    "/v1/claims/{id}/comments",
		Summary: "List comments on a claim",
		Description: "Returns the comments on a claim, oldest first, with who wrote each and " +
			"when. A comment that has been edited also carries when it was last changed.\n\n" +
			"Comments are separate from the justification and never affect an approval.",
		Tags: []string{"Triage"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		ID int64 `path:"id"`
	}) (*core.ListOutput[CommentBody], error) {
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		comments, err := store.Discussion(ctx, subject, input.ID)
		if err != nil {
			return nil, core.RefusedDecision(in.Logger, err)
		}

		authors := make([]int64, 0, len(comments))
		for _, comment := range comments {
			authors = append(authors, comment.WrittenBy)
		}
		who, err := core.WhoSigned(ctx, in.DB.DB, authors)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "the discussion could not be read", err)
		}

		out := &core.ListOutput[CommentBody]{}
		out.Body.Items = make([]CommentBody, 0, len(comments))
		for _, comment := range comments {
			body := CommentBody{
				ID: comment.ID, Body: comment.Body,
				WrittenBy:     who.Identity(comment.WrittenBy),
				WrittenByName: who.Label(comment.WrittenBy),
				WrittenAt:     comment.WrittenAt.UTC().Format(time.RFC3339),
			}
			if comment.EditedAt != nil {
				body.EditedAt = comment.EditedAt.UTC().Format(time.RFC3339)
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		return out, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "edit-comment", Method: http.MethodPut, Path: "/v1/comments/{id}",
		Summary: "Edit a comment",
		Description: "Replaces the text of a comment. Only its author may do this.\n\n" +
			"What it said before is kept, and read back with " +
			"`GET /v1/comments/{id}/history`. A comment is part of the record that goes " +
			"public at disclosure, and a record whose earlier text is unrecoverable is " +
			"readable rather than checkable — which is the property the whole append-only " +
			"history exists for.\n\n" +
			"The text is markdown and is validated before it is stored; a 422 names the line and " +
			"the offending text.",
		Tags: []string{"Triage"},
	}, core.PerProduct, "Only the author may edit a comment.", core.ApproveRights()...), func(ctx context.Context, input *struct {
		ID   int64 `path:"id"`
		Body struct {
			Body string `json:"body" minLength:"1"`
		}
	}) (*struct{ Body core.MentionsBody }, error) {
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		claimID, err := store.Reword(ctx, subject, input.ID, input.Body.Body)
		if err != nil {
			return nil, core.RefusedDecision(in.Logger, err)
		}
		dropped := core.TellMentioned(ctx, in, subject, store, claimID, input.Body.Body)
		return &struct{ Body core.MentionsBody }{Body: core.MentionsBody{NotNotified: dropped}}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "get-comment-history", Method: http.MethodGet,
		Path:    "/v1/comments/{id}/history",
		Summary: "List earlier revisions of a comment",
		Description: "Every version of a comment that has been replaced, oldest first. " +
			"The comment itself carries what it says now.\n\n" +
			"Answers only where you may read what the comment is about, which is the rule " +
			"for reading the comment itself.",
		Tags: []string{"Triage"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		ID int64 `path:"id"`
	}) (*core.ListOutput[core.WasSaidBody], error) {
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		rows, err := store.Earlier(ctx, subject, input.ID)
		if err != nil {
			return nil, core.RefusedDecision(in.Logger, err)
		}
		out := &core.ListOutput[core.WasSaidBody]{}
		out.Body.Items = make([]core.WasSaidBody, 0, len(rows))
		for _, row := range rows {
			out.Body.Items = append(out.Body.Items, core.WasSaidBody{
				Version: row.Ordinal, Body: row.Body,
				ReplacedAt: row.ReplacedAt.UTC().Format(time.RFC3339),
			})
		}
		return out, nil
	})
}

// DecisionsOutput is a page of decisions, with how many there are behind it.
type DecisionsOutput struct {
	Body struct {
		Items []core.DecisionDetail `json:"items"`
		Total int                   `json:"total"`
	}
}
