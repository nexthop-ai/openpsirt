package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// changing runs one administrative act and the record of it in one
// transaction.
//
// **A failure to record fails the act.** Both are one change: a setting moved
// with nobody recorded as having moved it is exactly the state REQ-22 says the
// record exists to prevent, and it used to be reachable by a write that
// succeeded beside a record that did not. Answering with an error invites a
// retry, which is what the retry is for — nothing was committed.
//
// The act is written against the transaction rather than against the handle,
// so everything it decides from is read inside it (REQ-71).
func changing(ctx context.Context, db *database.DB, logger *slog.Logger,
	do func(ctx context.Context, tx bun.Tx) error) error {

	if db == nil {
		return noDatabase(logger)
	}
	return database.InTransaction(ctx, db.DB, do)
}

// noted records an administrative act against whoever made it, in the
// transaction that made it.
//
// Called from the request rather than from the store underneath. The stores
// take no subject — a setting write knows the name and the value and nothing
// about who is asking — and threading one through every one of them to reach
// this would make those signatures about auditing rather than about the thing
// being written. The cost is that a new administrative route can forget, so a
// test walks the routes and asserts each leaves a row.
func noted(ctx context.Context, tx bun.IDB, kind trail.Kind, name string, was, became *string) error {
	by, err := reading(ctx)
	if err != nil {
		return err
	}
	return trail.NewStore(tx).Record(ctx, by, kind, name, was, became)
}

// recording answers a store write that is part of an act.
//
// **A lost race goes back untouched.** A store handed somebody else's
// transaction cannot go again itself — the failed statement has already
// aborted it on one engine — so it says it lost, and the helper that opened
// the transaction takes the whole act again. Reported as a fault instead, the
// sentinel is destroyed: wentWrong builds a fresh refusal that wraps nothing,
// so the retry helper never sees it and the loser of an ordinary race is
// handed a 500 where the path this replaces went round and won.
//
// One spelling rather than an arm at each site, because the way this stops
// working again is a third write that forgets it.
func recording(logger *slog.Logger, what string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, database.ErrGoAgain) {
		return err
	}
	return wentWrong(logger, what, err)
}

// notRecorded refuses an act whose record could not be written.
//
// The act is rolled back with it, so the sentence says that: a caller told
// only that recording failed would be left wondering which of the two stood.
func notRecorded(logger *slog.Logger, err error) error {
	return wentWrong(logger, "that change could not be recorded, so it was not made", err)
}

// onDay spells a date for the trail, where absent means there is none.
func onDay(at *time.Time) *string {
	if at == nil {
		return nil
	}
	said := dayOf(at)
	return &said
}

// dayOf is a moment as the day it falls on, or nothing where there is none.
func dayOf(at *time.Time) string {
	if at == nil || at.IsZero() {
		return ""
	}
	return at.UTC().Format(time.DateOnly)
}

// ChangeBody is one administrative act, as an administrator reads it.
type ChangeBody struct {
	At   string `json:"at"`
	By   string `json:"by" doc:"The person who made the change, by sign-in identity"`
	Kind string `json:"kind" enum:"setting,role,routing,support,release,credential,account,team,case,alias" doc:"The kind of thing that changed"`
	// About is which one: the setting's name, the person and product a role
	// was granted on, the release whose support date moved.
	About string `json:"about"`
	// Was and Became are what it held before and after. Absent before means
	// nobody had set it; absent after means it was cleared. The two are
	// different acts and a blank cannot tell them apart.
	Was    string `json:"was,omitempty"`
	Became string `json:"became,omitempty"`
	// Unset and Cleared say which of those an absent value is, because a
	// value that is genuinely the empty string is also absent in JSON.
	Unset   bool `json:"unset,omitempty" doc:"Nobody had set it before this"`
	Cleared bool `json:"cleared,omitempty" doc:"This change cleared it"`
}

func registerTrail(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-administrative-changes", Method: http.MethodGet,
		Path:    "/v1/administration/changes",
		Summary: "List administrative changes",
		Description: "Who changed a setting, a role grant, a routing rule, a support date, a " +
			"credential, an account, a team or an issue's names — with what it held " +
			"before and what it holds now.\n\n" +
			"This is the layer above the triage record rather than part of it. Three of the " +
			"things listed here silently rewrite what the tool reports: the deadline windows " +
			"recompute every open finding's deadline, the triage floor takes the deadline off " +
			"everything below it, and an end-of-life date takes it off everything past it.\n\n" +
			"Newest first, and paged: it only grows.\n\n" +
			"Takes a period, because the question an audit asks is what changed in the " +
			"stretch the certificate covers. Asked for none, it answers about everything " +
			"it holds.",
		Tags: []string{"Administration"},
	}, deploymentRecords, ""), func(ctx context.Context, input *struct {
		Kind string `query:"kind" enum:"setting,role,routing,support,release,credential,account,team,case,alias" doc:"Keep only changes of one kind"`
		Period
		Limit  int `query:"limit" default:"50" minimum:"1" maximum:"200"`
		Offset int `query:"offset" minimum:"0"`
	}) (*struct {
		Body struct {
			Items []ChangeBody `json:"items"`
			Total int          `json:"total"`
			// From and To say the period back, so a page of rows is never
			// read without the stretch it covers. Empty where that side is
			// unbounded.
			From string `json:"from,omitempty"`
			To   string `json:"to,omitempty"`
		}
	}, error) {
		subject, err := requester(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		// No default window. A trail read with one would answer about the
		// last stretch while looking like it answered about everything, which
		// is the reading an audit must not be given.
		since, until, err := input.window(0, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		store := access.NewStore(in.DB.DB)
		// Refused by the store rather than here. A row names who was brought
		// into which case, undisclosed ones among them, so who may read it is
		// a question about the query (REQ-42 and REQ-43).
		changes, total, err := trail.NewStore(in.DB.DB).Changes(ctx, subject,
			trail.Kind(input.Kind), trail.Over{Since: since, Until: until},
			input.Limit, input.Offset)
		if err != nil {
			return nil, refused(in.Logger, err, "what has been changed could not be read")
		}

		who := make([]int64, 0, len(changes))
		for _, change := range changes {
			who = append(who, change.By)
		}
		names, err := store.Names(ctx, who)
		if err != nil {
			return nil, wentWrong(in.Logger, "who changed these could not be read", err)
		}

		out := &struct {
			Body struct {
				Items []ChangeBody `json:"items"`
				Total int          `json:"total"`
				From  string       `json:"from,omitempty"`
				To    string       `json:"to,omitempty"`
			}
		}{}
		out.Body.Total = total
		out.Body.From, out.Body.To = stating(since, until)
		out.Body.Items = make([]ChangeBody, 0, len(changes))
		for _, change := range changes {
			body := ChangeBody{
				At: change.At.Format("2006-01-02T15:04:05Z"), By: names[change.By],
				Kind: string(change.Kind), About: change.Name,
				Unset: change.Was == nil, Cleared: change.Became == nil,
			}
			if change.Was != nil {
				body.Was = *change.Was
			}
			if change.Became != nil {
				body.Became = *change.Became
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		return out, nil
	})
}
