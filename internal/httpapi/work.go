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
	Kind      string    `json:"kind" doc:"Which worker the job was for"`
	Reference string    `json:"reference" doc:"What the work was about"`
	Attempts  int       `json:"attempts" doc:"How many times it was tried"`
	LastError string    `json:"last_error,omitempty" doc:"Why it stopped, where anything reported one"`
	StoppedAt time.Time `json:"stopped_at" doc:"When it was set aside"`
}

func registerWork(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-set-aside-work", Method: http.MethodGet, Path: "/v1/work/set-aside",
		Summary: "List work that stopped being retried",
		Description: "Returns background work the queue has set aside, newest first, with " +
			"why each stopped where anything reported a reason.\n\n" +
			"A job is set aside after it has been tried as many times as it is allowed to be. " +
			"That includes a job whose worker was killed rather than one that reported a " +
			"failure: nothing reports a worker that is gone, so the reason reads as the worker " +
			"never having come back.",
		Tags: []string{"Administration"},
	}, deploymentWide, ""), func(ctx context.Context, _ *struct{}) (*listOutput[SetAsideBody], error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		if in.Queue == nil {
			return &listOutput[SetAsideBody]{}, nil
		}
		jobs, err := in.Queue.SetAside(ctx, 0)
		if err != nil {
			return nil, wentWrong(in.Logger, "work that was set aside could not be read", err)
		}
		out := &listOutput[SetAsideBody]{}
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
		Description: "Puts one set-aside job back in the queue with its attempts started " +
			"again, for whichever worker takes it next.\n\n" +
			"Whoever does this has decided the reason it kept failing is dealt with, so the " +
			"count starts from nothing: a job put back with one attempt left would be set " +
			"aside again by the next transient failure. A job that is not set aside is " +
			"refused rather than moved.",
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
