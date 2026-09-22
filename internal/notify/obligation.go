package notify

import (
	"context"
	"fmt"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/obligation"
)

// The conditions about an attack somebody outside may be waiting to hear of.
//
// Beside the embargo conditions rather than among the waits, because they are
// the same shape: a date with a counterparty on the other side of it. A
// remediation deadline has no such date and raises nothing, which is correct
// as it stands.
//
// Every window this deployment declares, counted from the moment each
// standing record says the attack became known. Nothing here decides whether
// a window applies to an incident; a deployment under none declares none, and
// hears nothing.

// windowsOpen is every window still running with no notice named against it,
// against the people who may act on the product.
//
// From the moment the attack became known, rather than from a lead time
// before the end. The windows in force anywhere are a day to a fortnight, and
// an incident is rare: a warning that waits for most of a day to pass gives
// back the hours it exists to save.
func (w *Watch) windowsOpen(ctx context.Context) (map[int64][]Holds, error) {
	return w.windows(ctx, ObligationOpen, false)
}

// windowsPassed is every window whose end has gone with no notice named
// against it.
//
// It says the time passed and that nothing is recorded, which are both facts.
// Whether anybody owed anything is not the tool's answer to give.
func (w *Watch) windowsPassed(ctx context.Context) (map[int64][]Holds, error) {
	return w.windows(ctx, ObligationPassed, true)
}

// windows is the one pass behind both, which differ in which side of the end
// they report.
func (w *Watch) windows(ctx context.Context, kind Kind, passed bool) (map[int64][]Holds, error) {
	store := obligation.NewStore(w.db)
	standing, err := store.Standings(ctx)
	if err != nil {
		return nil, err
	}
	windows, err := store.Windows(ctx)
	if err != nil {
		return nil, err
	}
	acts, err := whoActs(ctx, w.db)
	if err != nil {
		return nil, err
	}
	// Everybody currently being told is handed a list, empty included, so a
	// window answered since the last sweep clears.
	out, err := w.everybody(ctx, kind, acts)
	if err != nil {
		return nil, err
	}
	if len(standing) == 0 || len(windows) == 0 {
		return out, nil
	}
	ids := make([]int64, 0, len(standing))
	for _, one := range standing {
		ids = append(ids, one.Record.ID)
	}
	told, err := store.ToldAbout(ctx, ids)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	for _, one := range standing {
		for _, due := range obligation.Running(windows, one.Record.KnownAt,
			told[one.Record.ID], now) {

			if due.Answered || due.Passed != passed {
				continue
			}
			about, verb := "obligation-open", "ends"
			if passed {
				about, verb = "obligation-passed", "ended"
			}
			holds := Holds{
				About: identify(fmt.Sprintf("%s %d %d", about, one.Record.ID, due.Window.ID)),
				Body: fmt.Sprintf("%s in %s: the window %q, counted from when this became "+
					"known, %s %s. No notice outside is recorded against it.",
					one.Issue, one.ProductName, due.Window.Name, verb,
					due.EndsAt.Format("2006-01-02 15:04 MST")),
				Link:            "/obligations",
				Private:         one.Private,
				ProductID:       &one.Record.ProductID,
				VulnerabilityID: &one.Record.VulnerabilityID,
			}
			for personID, per := range acts {
				if !per[one.Record.ProductID].triages(one.Private) {
					continue
				}
				out[personID] = append(out[personID], holds)
			}
		}
	}
	return out, nil
}
