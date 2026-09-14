package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// What people write about an issue in a product, and what they wrote before.
//
// Apart from the claim comments beside them, because they hang off different
// things: a comment is about one argument at one place, and a note is about
// the issue here. Merging them is not available — a claim is keyed on a place
// and a note on an issue, so they cannot become one record.
func registerIssueNotes(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-issue-notes", Method: http.MethodGet,
		Path:    "/v1/products/{product}/issues/{vulnerability}/notes",
		Summary: "List notes on an issue in a product",
		Description: "Returns the notes written about this issue in this product, oldest " +
			"first, with who wrote each and when. A note that has been edited also carries " +
			"when it was last changed.\n\n" +
			"A note records no judgment and changes nothing: not what ranks, not a deadline, " +
			"not a triage line. It is context for whoever decides.\n\n" +
			"**It is about the issue in this product, not about one component.** A row in the " +
			"findings list is one issue at one source package, and one issue is often several " +
			"rows — so a note kept against a row would be written on one of them and hidden " +
			"from the rest. What is about a judgment at a place is a comment on that claim " +
			"instead.",
		Tags: []string{"Triage"},
	}, anyPerson, "Answers where you may read a finding of this issue in this product, at its "+
		"visibility — an issue with one undisclosed place here is undisclosed for this. "+
		"Anywhere else it answers as an issue that is not there."), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability" doc:"The issue, by any name it is known under"`
	}) (*listOutput[NoteBody], error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		product, issue, _, err := noteAbout(ctx, in, subject, input.Product, input.Vulnerability)
		if err != nil {
			return nil, err
		}
		notes, err := store.Notes(ctx, subject, product, issue)
		if err != nil {
			return nil, refusedNote(in.Logger, err)
		}
		return notesOut(ctx, in, notes)
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "note-on-issue", Method: http.MethodPost,
		Path:    "/v1/products/{product}/issues/{vulnerability}/notes",
		Summary: "Add a note to an issue in a product",
		Description: "Adds a markdown note about this issue in this product. It records no " +
			"judgment: nothing about what ranks, what a deadline is, or what the product " +
			"triages changes because somebody wrote one.\n\n" +
			"**This is the way to leave something for whoever decides without deciding.** A " +
			"comment hangs off a claim; a note does not, so nothing has to be judged before " +
			"anything can be said.\n\n" +
			"It reaches every build of the product and does not lapse when a version moves. " +
			"Something true of one copy and not another — \"we do not call that function in " +
			"the vendored build\" — is about a place, and belongs on the claim there.\n\n" +
			"A name written after an `@` is told, where that person may read what the note is " +
			"about; the response lists the names that reached nobody.\n\n" +
			"The text is markdown and is validated before it is stored; a 422 names the line " +
			"and the offending text.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability" doc:"The issue, by any name it is known under"`
		Body          struct {
			Body string `json:"body" minLength:"1" doc:"What to say, in markdown"`
		}
	}) (*struct{ Body NoteWritten }, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		product, issue, filed, err := noteAbout(ctx, in, subject, input.Product, input.Vulnerability)
		if err != nil {
			return nil, err
		}
		note, err := store.NoteOn(ctx, subject, product, issue, input.Body.Body)
		if err != nil {
			return nil, refusedNote(in.Logger, err)
		}
		out := &struct{ Body NoteWritten }{}
		out.Body.ID = note.ID
		out.Body.NotNotified = tellNamed(ctx, in, subject, store, *note, filed)
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "edit-issue-note", Method: http.MethodPut, Path: "/v1/notes/{id}",
		Summary: "Edit a note on an issue",
		Description: "Replaces the text of a note. Only its author may do this: an edit " +
			"another person could make is not a correction.\n\n" +
			"**What it said before is kept**, and read back with " +
			"`GET /v1/notes/{id}/history`. A note is part of the record that goes public at " +
			"disclosure, and a record whose earlier text is unrecoverable is readable rather " +
			"than checkable.\n\n" +
			"The text is markdown and is validated before it is stored; a 422 names the line " +
			"and the offending text.",
		Tags: []string{"Triage"},
	}, perProduct, "Only the author may edit a note. The product is the note's own, not one in "+
		"the path.", triageRights()...), func(ctx context.Context, input *struct {
		ID   int64 `path:"id"`
		Body struct {
			Body string `json:"body" minLength:"1" doc:"What it should say now, in markdown"`
		}
	}) (*struct{ Body NoteWritten }, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		note, err := store.RewordNote(ctx, subject, input.ID, input.Body.Body)
		if err != nil {
			return nil, refusedNote(in.Logger, err)
		}
		named, err := finding.NewVulnerabilities(in.DB.DB).
			NamesByID(ctx, []int64{note.VulnerabilityID})
		if err != nil {
			return nil, wentWrong(in.Logger, "the note could not be read back", err)
		}
		out := &struct{ Body NoteWritten }{}
		out.Body.ID = note.ID
		out.Body.NotNotified = tellNamed(ctx, in, subject, store, *note,
			named[note.VulnerabilityID])
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-issue-note-history", Method: http.MethodGet,
		Path:    "/v1/notes/{id}/history",
		Summary: "List earlier revisions of a note",
		Description: "Every version of a note that has been replaced, oldest first. The note " +
			"itself carries what it says now.\n\n" +
			"A note is part of the record that goes public at disclosure, so what it said " +
			"before has to be recoverable: an edit that overwrites leaves a record somebody " +
			"can read and nobody can check.\n\n" +
			"Answers only where you may read what the note is about — the same rule as " +
			"reading the note itself, asked of the issue rather than of the note, because two " +
			"rules for one question is one rule out of step.",
		Tags: []string{"Triage"},
	}, anyPerson, "Answers only where you may read what the note is about, which is the "+
		"note's own product and issue rather than anything in the path."), func(ctx context.Context, input *struct {
		ID int64 `path:"id"`
	}) (*listOutput[WasSaidBody], error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		rows, err := store.EarlierNote(ctx, subject, input.ID)
		if err != nil {
			return nil, refusedNote(in.Logger, err)
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

// NoteBody is one note on an issue in a product.
type NoteBody struct {
	ID        int64  `json:"id"`
	Body      string `json:"body" doc:"What it says, in markdown"`
	WrittenBy string `json:"written_by" doc:"Who wrote it"`
	WrittenAt string `json:"written_at"`
	EditedAt  string `json:"edited_at,omitempty" doc:"When the author last changed it, where they have"`
}

// NoteWritten is what comes back from writing or changing a note.
type NoteWritten struct {
	ID          int64    `json:"id"`
	NotNotified []string `json:"not_notified,omitempty" doc:"Names written after an @ that reached nobody. Either no such person is recorded, or they cannot read what the note is about — deliberately not said which"`
}

// noteAbout resolves the product and the issue a request names, and what the
// issue is filed under here.
//
// The product first, and the issue only afterwards. Resolving the issue first
// and refusing after would answer "is this issue known here" for anybody with
// an account, which is what authorizing before resolving a name forbids
// (REQ-42).
//
// **A name nobody has filed answers exactly as one this product cannot reach.**
// Answered apart, anybody holding read on a single product could tell the two
// apart and walk identifiers — including ones this deployment minted for a
// flaw nobody has announced. It is the same collapse recording a rating makes,
// and for the same reason.
//
// The identifier comes back as the issue is filed under here rather than as it
// was typed. A note may be reached through any name the issue answers to, and
// a notification naming whichever alias the writer happened to use says a
// different thing about the same note depending on who wrote it.
func noteAbout(ctx context.Context, in Ingest, subject access.Subject,
	product, vulnerability string) (int64, int64, string, error) {

	named, err := productForIssue(ctx, in, subject, product)
	if err != nil {
		return 0, 0, "", err
	}
	issues := finding.NewVulnerabilities(in.DB.DB)
	issue, err := issues.ByName(ctx, vulnerability)
	if err != nil {
		return 0, 0, "", noSuchNote()
	}
	filed, err := issues.NamesByID(ctx, []int64{issue})
	if err != nil {
		return 0, 0, "", wentWrong(in.Logger, "the issue could not be read", err)
	}
	return named.ID, issue, filed[issue], nil
}

// notesOut renders a thread, naming its authors in one lookup.
func notesOut(ctx context.Context, in Ingest, notes []triage.IssueNote) (*listOutput[NoteBody], error) {
	authors := make([]int64, 0, len(notes))
	for _, note := range notes {
		authors = append(authors, note.WrittenBy)
	}
	names, err := access.NewStore(in.DB.DB).Names(ctx, authors)
	if err != nil {
		return nil, wentWrong(in.Logger, "the notes could not be read", err)
	}
	out := &listOutput[NoteBody]{}
	out.Body.Items = make([]NoteBody, 0, len(notes))
	for _, note := range notes {
		body := NoteBody{
			ID: note.ID, Body: note.Body,
			WrittenBy: names[note.WrittenBy],
			WrittenAt: note.WrittenAt.Format(time.RFC3339),
		}
		if note.EditedAt != nil {
			body.EditedAt = note.EditedAt.Format(time.RFC3339)
		}
		out.Body.Items = append(out.Body.Items, body)
	}
	return out, nil
}

// tellNamed tells whoever a note named, at the visibility of the issue in that
// product.
//
// Failing to tell somebody never fails the write. The words are on record by
// the time this runs, and losing a note because a notification could not be
// stored would be sacrificing the wrong half.
func tellNamed(ctx context.Context, in Ingest, subject access.Subject, store *triage.Store,
	note triage.IssueNote, identifier string) []string {

	visibility, err := store.NoteVisibility(ctx, note.ProductID, note.VulnerabilityID)
	if err != nil {
		in.Logger.WarnContext(ctx, "could not tell who was named", "error", err)
		return nil
	}
	dropped, err := mentioned(ctx, in, subject, mentionTarget{
		ProductID: note.ProductID, VulnerabilityID: note.VulnerabilityID,
		Visibility: visibility, About: identifier,
		// The issue's own screen, which is where the thread is read. A
		// note carries no address of its own: it is one line of a thread
		// about an issue in a product, and there is no screen showing one
		// by itself for a link to point at.
	}, note.Body, fmt.Sprintf("/issues/%s", identifier))
	if err != nil {
		in.Logger.WarnContext(ctx, "could not tell who was named", "error", err)
	}
	return dropped
}

// refusedNote turns the store's refusal into an answer.
//
// A note somebody may not reach answers as one that is not there, so that
// guessing identifiers says nothing.
func refusedNote(logger *slog.Logger, err error) error {
	switch {
	case errors.Is(err, triage.ErrNoSuchNote):
		return noSuchNote()
	case errors.Is(err, access.ErrDenied):
		return huma.Error403Forbidden("not authorized")
	}
	var faults markdown.Faults
	if errors.As(err, &faults) {
		return refusedText(faults)
	}
	// What is left is a sentence the store wrote for a person to read: a note
	// that says nothing, an edit by somebody who did not write it. Those are
	// the caller's to fix, and the message is the answer.
	return asked(logger, err)
}
