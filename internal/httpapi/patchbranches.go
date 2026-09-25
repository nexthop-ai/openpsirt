// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/patchbranch"
)

// PatchRepositoryBody is how far one repository's commits have been looked up.
type PatchRepositoryBody struct {
	URL         string `json:"url" doc:"The address the repository is fetched from"`
	Host        string `json:"host"`
	State       string `json:"state" enum:"waiting,working,failed,done,excluded" doc:"'waiting' has commits not yet looked up and no visit under way. 'working' is a visit under way. 'failed' is a last visit that stopped on an error, retried a day after it began. 'done' is every commit looked up. 'excluded' is on a host OPENPSIRT_OUTBOUND_EXCLUDED lists, and is never fetched"`
	Position    int    `json:"position,omitempty" doc:"Where the repository stands in the order repositories with commits due are visited, from 1. Absent when nothing is due or the repository is not being visited"`
	Step        string `json:"step,omitempty" enum:"fetching,looking-up" doc:"What the visit under way is doing: 'fetching' brings the copy up to date and indexes it, 'looking-up' asks it about each commit due. Only on a 'working' repository"`
	VisitLooked int    `json:"visit_looked,omitempty" doc:"How many commits the visit under way has looked up so far"`
	Due         int    `json:"due,omitempty" doc:"How many commits are due a look now, never looked up or looked up more than a week ago"`
	Worst       string `json:"worst,omitempty" doc:"The severity of the most urgent issue linking to a commit due, where the issue is rated"`
	Commits     int    `json:"commits" doc:"How many commits patch links name in this repository"`
	Looked      int    `json:"looked" doc:"How many of those have been looked up"`
	Found       int    `json:"found" doc:"How many of those the repository holds"`
	FetchedAt   string `json:"fetched_at,omitempty" doc:"When a visit last began"`
	ReachedAt   string `json:"reached_at,omitempty" doc:"When a visit last finished"`
	RetryAt     string `json:"retry_at,omitempty" doc:"When a failed repository is next visited"`
	Reason      string `json:"reason,omitempty" doc:"What stopped the last visit"`
	HeldBytes   int64  `json:"held_bytes,omitempty" doc:"The size of the repository's copy when the last visit finished, in bytes"`
}

// PatchBranchesOutput is the whole of the lookup work.
type PatchBranchesOutput struct {
	Body struct {
		On           bool                  `json:"on" doc:"Whether the deployment turned the lookups on. Set in its configuration, not under Settings"`
		Links        int                   `json:"links" doc:"How many patch links reports carry"`
		Commits      int                   `json:"commits" doc:"How many distinct commits in a recognized repository those links name"`
		Looked       int                   `json:"looked" doc:"How many of those commits have been looked up"`
		Found        int                   `json:"found" doc:"How many of those the repository holds"`
		HeldBytes    int64                 `json:"held_bytes" doc:"What every repository copy on disk took when its last visit finished, together, in bytes"`
		Repositories []PatchRepositoryBody `json:"repositories" doc:"The repositories those commits are in, in working order: the visit under way, then those with commits due in the order they are visited, then failed, excluded and done"`
		Total        int                   `json:"total" doc:"How many repositories there are in all"`
	}
}

// registerPatchBranches answers how far the lookups have got.
//
// An operator's question, like the rest of the deployment's own state: whether
// the work is moving, where it is stuck, and how much disk the copies take.
func registerPatchBranches(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-patch-branch-progress", Method: http.MethodGet,
		Path:    "/v1/patch-branches",
		Summary: "Show how far patch branch lookups have got",
		Description: "The repositories patch links point into, and how many of the commits " +
			"each link names have been looked up in a copy of the repository.\n\n" +
			"A link that names no commit in a recognized repository — a pull request, a " +
			"mailing-list post, a patch tracker — is counted in `links` and nowhere else.\n\n" +
			"Repositories come in working order, with `position` on each one due. The one a " +
			"visit is under way on comes first, with its `step` and `visit_looked`.",
		Tags: []string{"Administration"},
	}, deploymentWide, ""), func(ctx context.Context, input *struct {
		Paging
	}) (*PatchBranchesOutput, error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		out := &PatchBranchesOutput{}
		out.Body.Repositories = []PatchRepositoryBody{}
		if in.DB == nil {
			return out, nil
		}
		out.Body.On = in.PatchBranches
		repositories, totals, err := patchbranch.Progress(ctx, in.DB.DB, in.Excluded)
		if err != nil {
			return nil, wentWrong(in.Logger, "how far the lookups have got could not be read", err)
		}
		out.Body.Links, out.Body.Commits = totals.Links, totals.Commits
		out.Body.Looked, out.Body.Found = totals.Looked, totals.Found
		out.Body.HeldBytes = totals.HeldBytes
		out.Body.Total = len(repositories)
		start := min(input.Offset, len(repositories))
		end := min(start+input.Limit, len(repositories))
		for _, one := range repositories[start:end] {
			body := PatchRepositoryBody{
				URL: one.URL, Host: one.Host, State: string(one.State),
				Position: one.Position, Step: string(one.Step), VisitLooked: one.VisitLooked,
				Due: one.Due, Worst: one.Worst,
				Commits: one.Commits, Looked: one.Looked, Found: one.Found,
				Reason: one.Reason,
			}
			if one.RetryAt != nil {
				body.RetryAt = one.RetryAt.UTC().Format(time.RFC3339)
			}
			if one.FetchedAt != nil {
				body.FetchedAt = one.FetchedAt.UTC().Format(time.RFC3339)
			}
			if one.ReachedAt != nil {
				body.ReachedAt = one.ReachedAt.UTC().Format(time.RFC3339)
			}
			if one.HeldBytes != nil {
				body.HeldBytes = *one.HeldBytes
			}
			out.Body.Repositories = append(out.Body.Repositories, body)
		}
		return out, nil
	})
}
