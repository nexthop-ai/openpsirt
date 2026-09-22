package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/obligation"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// WindowBody is a window this deployment counts after an attack.
type WindowBody struct {
	ID         int64  `json:"id"`
	Name       string `json:"name" doc:"What the window is called here"`
	Hours      int    `json:"hours" doc:"How long the window runs, in hours, from the moment an attack became known"`
	DeclaredAt string `json:"declared_at" format:"date-time"`
}

// WindowSaid is what an administrator supplies to declare or change a window.
type WindowSaid struct {
	Name  string `json:"name" minLength:"1" maxLength:"191" doc:"What the window is called here. Unique among the windows in force, without regard to capitals"`
	Hours int    `json:"hours" minimum:"1" maximum:"8784" doc:"How long the window runs, in hours, from the moment an attack became known"`
}

// DueBody is one window as it runs for one incident.
type DueBody struct {
	Window   WindowBody `json:"window"`
	EndsAt   string     `json:"ends_at" format:"date-time" doc:"When the attack became known, plus the window"`
	Passed   bool       `json:"passed" doc:"Whether that moment has gone"`
	Answered bool       `json:"answered" doc:"Whether a notice recorded against this incident names this window"`
}

// NoticeBody is a record that somebody outside was told about an attack.
type NoticeBody struct {
	ID         int64  `json:"id"`
	Recipient  string `json:"recipient" doc:"Who was told"`
	ToldAt     string `json:"told_at" format:"date-time" doc:"When they were told"`
	Said       string `json:"said" doc:"What they were told"`
	WindowID   int64  `json:"window_id,omitempty" doc:"The window this notice answers, where whoever recorded it named one. A retired window's name may be declared again, so this is what tells the two apart"`
	Window     string `json:"window,omitempty" doc:"That window's name"`
	RecordedBy string `json:"recorded_by,omitempty" doc:"Who recorded the notice"`
	RecordedAt string `json:"recorded_at" format:"date-time"`
}

// NoticeSaid is what a caller supplies to record a notice.
type NoticeSaid struct {
	Recipient string `json:"recipient" minLength:"1" maxLength:"200" doc:"Who was told: a regulator, a customer, a response team"`
	ToldAt    string `json:"told_at" format:"date-time" doc:"When they were told. Not before the attack became known, and not in the future"`
	Said      string `json:"said" minLength:"1" maxLength:"65536" doc:"What they were told"`
	Window    int64  `json:"window,omitempty" doc:"The window in force this notice answers. Left off, it answers none"`
}

// ObligationBody is one incident on the shelf.
type ObligationBody struct {
	ExploitedHereBody
	Undisclosed bool      `json:"undisclosed" doc:"Whether the issue is undisclosed somewhere in this product"`
	MayTell     bool      `json:"may_tell" doc:"Whether you may record a notice about this record"`
	Windows     []DueBody `json:"windows" doc:"Every window in force, shortest first, as it runs from when the attack became known"`
}

// ObligationsBody is every standing attack a reader may be told of.
type ObligationsBody struct {
	Items []ObligationBody `json:"items"`
}

// WindowsBody is every window in force.
type WindowsBody struct {
	Items []WindowBody `json:"items"`
}

func registerObligations(api huma.API, in Ingest) {
	huma.Register(api, answering(huma.Operation{
		OperationID: "list-obligations", Method: http.MethodGet, Path: "/v1/obligations",
		Summary: "List standing attacks and their windows",
		Description: "Every standing record that a product was exploited through an issue, " +
			"earliest known first. Each carries every window this deployment counts, as it " +
			"runs from the moment the attack became known, and every notice recorded about " +
			"it.\n\n" +
			"A window is answered where a notice names it. Nothing here says whether a " +
			"notice met anything.\n\n" +
			"Unpaged. A record you may not be told of is left out and counted nowhere.",
		Tags: []string{"Obligations"},
	}, perProduct, "A product you may not read contributes nothing, not even a count.",
		readRights()...), func(ctx context.Context, _ *struct{}) (*struct{ Body ObligationsBody }, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		store := obligation.NewStore(in.DB.DB)
		shelf, err := store.Shelf(ctx, subject)
		if err != nil {
			return nil, wentWrong(in.Logger, "the standing attacks could not be read", err)
		}
		records := make([]triage.ExploitedHere, 0, len(shelf))
		told := map[int64][]obligation.Told{}
		for _, entry := range shelf {
			records = append(records, entry.Record)
			told[entry.Record.ID] = entry.Told
		}
		people, err := triage.NewStore(in.DB.DB).PeopleNamed(ctx, whoToldOrTouched(records, told))
		if err != nil {
			return nil, wentWrong(in.Logger, "who recorded these could not be read", err)
		}
		named, err := store.WindowsNamed(ctx, told)
		if err != nil {
			return nil, wentWrong(in.Logger, "the windows could not be read", err)
		}
		out := &struct{ Body ObligationsBody }{}
		out.Body.Items = make([]ObligationBody, 0, len(shelf))
		for _, entry := range shelf {
			body := ObligationBody{
				ExploitedHereBody: exploitedHereBody(entry.Record, entry.Issue, people),
				Undisclosed:       entry.Private,
				MayTell:           subject.Triages(access.Public, entry.Record.ProductID),
				Windows:           make([]DueBody, 0, len(entry.Windows)),
			}
			body.Product, body.ProductName = entry.Product, entry.ProductName
			body.Told = toldBodies(entry.Told, named, people)
			for _, due := range entry.Windows {
				body.Windows = append(body.Windows, DueBody{
					Window: windowBody(due.Window), EndsAt: due.EndsAt.Format(time.RFC3339),
					Passed: due.Passed, Answered: due.Answered,
				})
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-obligation-windows", Method: http.MethodGet,
		Path:    "/v1/obligation-windows",
		Summary: "List obligation windows",
		Description: "Every window in force, shortest first. Each runs from the moment an " +
			"attack on a product became known. None ships: a deployment declares the windows " +
			"it answers to.",
		Tags: []string{"Obligations"},
	}, anyPerson, ""), func(ctx context.Context, _ *struct{}) (*struct{ Body WindowsBody }, error) {
		if _, err := reading(ctx); err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		windows, err := obligation.NewStore(in.DB.DB).Windows(ctx)
		if err != nil {
			return nil, wentWrong(in.Logger, "the windows could not be read", err)
		}
		out := &struct{ Body WindowsBody }{}
		out.Body.Items = make([]WindowBody, 0, len(windows))
		for _, window := range windows {
			out.Body.Items = append(out.Body.Items, windowBody(window))
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "declare-obligation-window", Method: http.MethodPost,
		Path:    "/v1/obligation-windows",
		Summary: "Declare an obligation window",
		Description: "Adds a window every standing attack is watched against, counted from " +
			"the moment each became known. Recorded in the administrative trail.\n\n" +
			"A name already in force, in any capitals, is refused with 409: retire that " +
			"window or pick another name.",
		Tags: []string{"Obligations"}, DefaultStatus: http.StatusCreated,
	}, deploymentWide, ""), func(ctx context.Context, input *struct {
		Body WindowSaid
	}) (*struct{ Body WindowBody }, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		window, err := obligation.NewStore(in.DB.DB).DeclareWindow(ctx, subject,
			input.Body.Name, input.Body.Hours)
		if err != nil {
			return nil, refusedWindow(in, err)
		}
		return &struct{ Body WindowBody }{Body: windowBody(*window)}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "change-obligation-window", Method: http.MethodPut,
		Path:    "/v1/obligation-windows/{id}",
		Summary: "Change an obligation window",
		Description: "Renames a window in force or changes how long it runs. Every " +
			"incident's end moves with it, and notices already recorded against it keep " +
			"naming it. Recorded in the administrative trail.\n\n" +
			"A name another window in force holds is refused with 409. A retired or " +
			"unknown window answers 404.",
		Tags: []string{"Obligations"},
	}, deploymentWide, ""), func(ctx context.Context, input *struct {
		ID   int64 `path:"id"`
		Body WindowSaid
	}) (*struct{ Body WindowBody }, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		window, err := obligation.NewStore(in.DB.DB).ChangeWindow(ctx, subject, input.ID,
			input.Body.Name, input.Body.Hours)
		if err != nil {
			return nil, refusedWindow(in, err)
		}
		return &struct{ Body WindowBody }{Body: windowBody(*window)}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "retire-obligation-window", Method: http.MethodDelete,
		Path:    "/v1/obligation-windows/{id}",
		Summary: "Retire an obligation window",
		Description: "Stops counting a window. Notices recorded against it keep naming it, " +
			"and its name may be declared again. Recorded in the administrative trail.\n\n" +
			"A window already retired, or never declared, answers 404.",
		Tags: []string{"Obligations"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, input *struct {
		ID int64 `path:"id"`
	}) (*struct{}, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		if err := obligation.NewStore(in.DB.DB).RetireWindow(ctx, subject, input.ID); err != nil {
			return nil, refusedWindow(in, err)
		}
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "record-told-outside", Method: http.MethodPost,
		Path:    "/v1/exploited-here/{id}/told",
		Summary: "Record that somebody outside was told",
		Description: "Records who was told about an attack, when, and what they were told. " +
			"Append-only: a notice recorded in error is corrected by recording another " +
			"beside it.\n\n" +
			"Name a window to say this notice answers it. The window then stops raising " +
			"its notification for this incident.\n\n" +
			"Allowed on a cleared record, because a notice given before the clearing still " +
			"happened.",
		Tags: []string{"Obligations"}, DefaultStatus: http.StatusCreated,
	}, perProduct, "The product is the record's own, not one in the path.",
		triageRights()...), func(ctx context.Context, input *struct {
		ID   int64 `path:"id"`
		Body NoticeSaid
	}) (*struct{ Body NoticeBody }, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		toldAt, err := time.Parse(time.RFC3339, input.Body.ToldAt)
		if err != nil {
			return nil, huma.Error422UnprocessableEntity(
				"say when they were told, as a moment: " + err.Error())
		}
		var window *int64
		if input.Body.Window != 0 {
			window = &input.Body.Window
		}
		store := obligation.NewStore(in.DB.DB)
		told, err := store.RecordTold(ctx, subject, input.ID, window,
			input.Body.Recipient, toldAt, input.Body.Said)
		if err != nil {
			switch {
			case errors.Is(err, obligation.ErrNoSuchRecord):
				return nil, noSuchExploitedHere()
			case errors.Is(err, obligation.ErrNoSuchWindow):
				return nil, huma.Error422UnprocessableEntity(
					"no window in force goes by that. Name one in force, or none")
			}
			return nil, refusedDecision(in.Logger, err)
		}
		byRecord := map[int64][]obligation.Told{told.ExploitedHereID: {*told}}
		named, err := store.WindowsNamed(ctx, byRecord)
		if err != nil {
			return nil, wentWrong(in.Logger, "the window could not be read", err)
		}
		people, err := triage.NewStore(in.DB.DB).PeopleNamed(ctx, []int64{told.RecordedBy})
		if err != nil {
			return nil, wentWrong(in.Logger, "who recorded this could not be read", err)
		}
		return &struct{ Body NoticeBody }{Body: toldBodies([]obligation.Told{*told}, named, people)[0]}, nil
	})
}

// refusedWindow answers a store's refusal to change a window.
func refusedWindow(in Ingest, err error) error {
	switch {
	case errors.Is(err, obligation.ErrNoSuchWindow):
		return huma.Error404NotFound("no window in force goes by that")
	case errors.Is(err, obligation.ErrWindowNamed):
		return huma.Error409Conflict("a window in force already has that name")
	case errors.Is(err, access.ErrDenied):
		return huma.Error403Forbidden("not authorized")
	}
	return refusedDecision(in.Logger, err)
}

func windowBody(window obligation.Window) WindowBody {
	return WindowBody{
		ID: window.ID, Name: window.Name, Hours: window.Hours,
		DeclaredAt: window.DeclaredAt.Format(time.RFC3339),
	}
}

// toldBodies is a record's notices as a caller reads them.
func toldBodies(told []obligation.Told, windows map[int64]string,
	people map[int64]string) []NoticeBody {

	out := make([]NoticeBody, 0, len(told))
	for _, one := range told {
		body := NoticeBody{
			ID: one.ID, Recipient: one.Recipient, ToldAt: one.ToldAt.Format(time.RFC3339),
			Said: one.Said, RecordedBy: people[one.RecordedBy],
			RecordedAt: one.RecordedAt.Format(time.RFC3339),
		}
		if one.WindowID != nil {
			body.WindowID, body.Window = *one.WindowID, windows[*one.WindowID]
		}
		out = append(out, body)
	}
	return out
}

// whoToldOrTouched is everybody named by a page of records and their notices.
func whoToldOrTouched(records []triage.ExploitedHere,
	told map[int64][]obligation.Told) []int64 {

	wanted := whoTouched(records)
	for _, each := range told {
		for _, one := range each {
			wanted = append(wanted, one.RecordedBy)
		}
	}
	return wanted
}
