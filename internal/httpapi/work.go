package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// Work that stopped being retried, and putting it back.
//
// The queue sets a job aside once it has run out of attempts, and until there
// was somewhere to see that, a deployment learned about it from a build that
// had quietly stopped being scanned. The two routes here are the whole of the
// operator surface over the dead state: what stopped, and try it again.
//
// Deliberately not a general view of the queue. Work that is waiting or
// running needs no attention and a list of it invites somebody to act on a
// state that changes underneath them; what is set aside has stopped moving by
// definition, which is what makes it worth showing.

// SetAsideBody is one piece of work that stopped being retried.
type SetAsideBody struct {
	ID int64 `json:"id" doc:"The job, for putting it back"`
	// Kind and Reference are what the work was, in the queue's own words. No
	// attempt is made to resolve the reference into whatever it points at:
	// the thing may have been deleted since, and a list of set-aside work
	// that fails to render because one row points at nothing is worse than
	// one that says what the row says.
	Kind      string `json:"kind" doc:"Which worker the job was for"`
	Reference string `json:"reference" doc:"What the work was about"`
	Attempts  int    `json:"attempts" doc:"How many times it was tried"`
	// LastError is what a worker reported, which is not one of this
	// deployment's own records: a failed parse quotes the cause it was given,
	// and that can carry a component name or a package address out of an
	// SBOM. It is why this route asks for administration rather than for the
	// grant that reads the records — that grant is declared, three times over,
	// to reach no product's findings.
	LastError string    `json:"last_error,omitempty" doc:"Why it stopped, where anything reported one. Worker output, which may quote what the job was about"`
	StoppedAt time.Time `json:"stopped_at" doc:"When it was set aside"`
}

// QueuedBody is how much of one kind of work is waiting, against the bound
// that refuses more of it.
//
// Per kind, because the bound is per kind: counted across the queue, a
// runaway producer's own backlog is what hides behind everybody else's empty
// queues, and the one number an operator has says the deployment is idle.
type QueuedBody struct {
	Kind    string `json:"kind" doc:"Which worker the work is for"`
	Waiting int    `json:"waiting" doc:"How much is waiting, including work held by a worker that has stopped reporting"`
	Limit   int    `json:"limit" doc:"How much of this kind may wait before more is refused"`
}

func registerWork(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-set-aside-work", Method: http.MethodGet, Path: "/v1/work/set-aside",
		Summary: "List work that stopped being retried",
		Description: "Returns background work the queue has set aside, newest first, with why " +
			"each stopped where anything reported a reason. A job is set aside once it has " +
			"been tried as many times as it is allowed to be, whether it reported a failure " +
			"or its worker stopped answering.\n\n" +
			"At most 200 are returned. `total` is how many are set aside in all, so a clipped " +
			"page can be told from a complete one.\n\n" +
			"`waiting` is what has not stopped: how much of each kind is queued, against the " +
			"bound that refuses more of it. A queue filling up and a queue that has given up " +
			"are different faults and only one of them leaves rows here.",
		Tags: []string{"Administration"},
	}, deploymentWide, ""), func(ctx context.Context, _ *struct{}) (*struct {
		Body struct {
			Items   []SetAsideBody `json:"items"`
			Total   int            `json:"total"`
			Waiting []QueuedBody   `json:"waiting"`
		}
	}, error) {
		type answer = struct {
			Body struct {
				Items   []SetAsideBody `json:"items"`
				Total   int            `json:"total"`
				Waiting []QueuedBody   `json:"waiting"`
			}
		}
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		if in.Queue == nil {
			return &answer{}, nil
		}
		jobs, total, err := in.Queue.SetAside(ctx, 0)
		if err != nil {
			return nil, wentWrong(in.Logger, "work that was set aside could not be read", err)
		}
		out := &answer{}
		out.Body.Total = total
		limit, err := in.Queue.Backlog(ctx)
		if err != nil {
			return nil, wentWrong(in.Logger, "the bound on the queue could not be read", err)
		}
		out.Body.Waiting = make([]QueuedBody, 0, len(queue.Kinds()))
		for _, kind := range queue.Kinds() {
			depth, err := in.Queue.Depth(ctx, kind)
			if err != nil {
				return nil, wentWrong(in.Logger, "the queue could not be measured", err)
			}
			out.Body.Waiting = append(out.Body.Waiting,
				QueuedBody{Kind: kind, Waiting: depth, Limit: limit})
		}
		out.Body.Items = make([]SetAsideBody, 0, len(jobs))
		for _, job := range jobs {
			body := SetAsideBody{
				ID: job.ID, Kind: job.Kind, Reference: job.Reference,
				Attempts: job.Attempts, StoppedAt: job.UpdatedAt,
			}
			if job.LastError != nil {
				body.LastError = *job.LastError
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "retry-set-aside-work", Method: http.MethodPost,
		Path:    "/v1/work/set-aside/{id}/retry",
		Summary: "Retry work that was set aside",
		Description: "Puts one set-aside job back in the queue for whichever worker takes it " +
			"next, with its attempts reset to zero and its last error kept.\n\n" +
			"A job that is not set aside is refused rather than moved.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, in2 *struct {
		ID int64 `path:"id" doc:"The job to put back"`
	}) (*struct{}, error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		if in.Queue == nil {
			return nil, huma.Error404NotFound("there is no queue here")
		}
		if err := in.Queue.Requeue(ctx, in2.ID); err != nil {
			if errors.Is(err, queue.ErrNotSetAside) {
				return nil, huma.Error404NotFound("that job was not set aside")
			}
			return nil, wentWrong(in.Logger, "the job could not be put back", err)
		}
		return &struct{}{}, nil
	})
}
