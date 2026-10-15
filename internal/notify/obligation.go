// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"fmt"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/obligation"
	"github.com/nexthop-ai/openpsirt/internal/weblink"
)

// The conditions about an attack somebody outside may be waiting to hear of.
//
// Beside the embargo conditions rather than among the waits, because they are
// the same shape: a date with a counterparty on the other side of it. A
// remediation deadline has no such date and raises nothing, which is correct
// as it stands.
//
// Every window this deployment declares, counted from the moment each
// standing record says the attack became known, from the first notice for
// the window it counts from, or from the release of a fix the record names. Nothing here decides whether a window applies to
// an incident; a deployment under none declares none, and hears nothing.

// windowsOpen is every window still running with no notice named against it,
// against the people who may act on the product.
//
// From the moment the window starts, rather than from a lead time before the
// end. A window waiting on another window's notice raises nothing until that
// notice is recorded, and one counting from the fix nothing until a release
// date stated for a release the record names has arrived. The windows in force anywhere are a day to a fortnight, and
// an incident is rare: a warning that waits for most of a day to pass gives
// back the hours it exists to save.
func (w *sweep) windowsOpen(ctx context.Context) (map[int64][]Holds, error) {
	return w.windows(ctx, ObligationOpen)
}

// windowsNear is every window whose warning has come and whose end has not,
// with no notice named against it.
func (w *sweep) windowsNear(ctx context.Context) (map[int64][]Holds, error) {
	return w.windows(ctx, ObligationNear)
}

// windowsPassed is every window whose end has gone with no notice named
// against it.
//
// It says the time passed and that nothing is recorded, which are both facts.
// Whether anybody owed anything is not the tool's answer to give.
func (w *sweep) windowsPassed(ctx context.Context) (map[int64][]Holds, error) {
	return w.windows(ctx, ObligationPassed)
}

// shelf is every standing record with each window as it runs, read once per
// sweep for the three kinds.
//
// As the deployment, which reads everything; each recipient is narrowed by
// what they may act on. The shelf is the obligation screen's own read, so the
// screen and these alerts agree on when a window starts and ends.
func (w *sweep) shelf(ctx context.Context) ([]obligation.Entry, error) {
	if w.shelved == nil {
		entries, err := obligation.NewStore(w.db).Shelf(ctx,
			access.Everything("the obligation sweep"))
		if err != nil {
			return nil, err
		}
		w.shelved = &entries
	}
	return *w.shelved, nil
}

// windows is the one pass behind all three, which differ in which part of a
// window they report.
func (w *sweep) windows(ctx context.Context, kind Kind) (map[int64][]Holds, error) {
	entries, err := w.shelf(ctx)
	if err != nil {
		return nil, err
	}
	acts := w.reach
	// Everybody currently being told is handed a list, empty included, so a
	// window answered since the last sweep clears.
	out, err := w.everybody(ctx, kind)
	if err != nil {
		return nil, err
	}
	for _, one := range entries {
		for _, due := range one.Windows {
			if due.Answered || !due.Started {
				continue
			}
			var verb string
			switch {
			case kind == ObligationPassed && due.Passed:
				verb = "ended"
			case kind == ObligationNear && due.Near:
				verb = "ends"
			case kind == ObligationOpen && !due.Passed:
				verb = "ends"
			default:
				continue
			}
			about := string(kind)
			from := "when this became known"
			switch {
			case due.Window.FromID != nil:
				from = fmt.Sprintf("the first notice for %q", due.Window.FromName)
			case due.Window.FromFix:
				from = "the release of the fix, " + day(due.StartsAt)
			}
			holds := Holds{
				About: identify(fmt.Sprintf("%s %d %d", about, one.Record.ID, due.Window.ID)),
				Body: fmt.Sprintf("%s in %s: the window %q, counted from %s, %s %s. "+
					"No notice outside is recorded against it.",
					one.Issue, one.ProductName, due.Window.Name, from, verb,
					minute(due.EndsAt)),
				Link:            weblink.ExploitedHere(),
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
