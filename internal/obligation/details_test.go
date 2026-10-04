// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package obligation_test

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/obligation"
)

// A notice keeps the reference its recipient gave it, the places it named in
// the order given, and what it said about malice, and reads them back on the
// shelf. A place named twice in other capitals is kept once, as first typed.
func TestANoticeKeepsItsReferencePlacesAndWordOnMalice(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		record := f.attacked(t)
		if _, err := f.store.RecordTold(ctx, f.triager, record.ID, nil, "A regulator",
			knownAt.Add(time.Hour), "Early warning.", obligation.Details{
				Reference: "  CASE-2026-0042 ",
				Places:    []string{"Ireland", " Germany", "IRELAND", "France"},
				Malicious: obligation.MaliciousUnknown,
			}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.RecordTold(ctx, f.triager, record.ID, nil, "A customer",
			knownAt.Add(2*time.Hour), "Heads up.", obligation.Details{}); err != nil {
			t.Fatal(err)
		}
		shelf, err := f.store.Shelf(ctx, f.triager)
		if err != nil {
			t.Fatal(err)
		}
		told := shelf[0].Told
		if len(told) != 2 {
			t.Fatalf("%d notices on the shelf, want 2", len(told))
		}
		first := told[0]
		if first.Reference == nil || *first.Reference != "CASE-2026-0042" {
			t.Errorf("the reference reads %v, want CASE-2026-0042", first.Reference)
		}
		if want := []string{"Ireland", "Germany", "France"}; !slices.Equal(first.Places, want) {
			t.Errorf("the places read %v, want %v", first.Places, want)
		}
		if first.Malicious == nil || *first.Malicious != obligation.MaliciousUnknown {
			t.Errorf("what it said of malice reads %v, want unknown", first.Malicious)
		}
		second := told[1]
		if second.Reference != nil || second.Malicious != nil || len(second.Places) != 0 {
			t.Errorf("a notice saying none of them reads %v, %v, %v",
				second.Reference, second.Malicious, second.Places)
		}
	})
}

// What a notice says beyond who, when and what is held to the same bounds a
// typed name is, and a word about malice is one of the three.
func TestANoticesDetailsAreBoundedAndMaliceIsOneOfThreeWords(t *testing.T) {
	long := strings.Repeat("x", database.NameWidth+1)
	many := make([]string, obligation.PlacesLimit+1)
	for i := range many {
		many[i] = "Place " + strconv.Itoa(i)
	}
	cases := []struct {
		name    string
		details obligation.Details
	}{
		{"a reference too long", obligation.Details{Reference: long}},
		{"a place too long", obligation.Details{Places: []string{long}}},
		{"a blank place", obligation.Details{Places: []string{"Ireland", "  "}}},
		{"too many places", obligation.Details{Places: many}},
		{"a word about malice nobody offered", obligation.Details{Malicious: "maybe"}},
	}
	each(t, func(t *testing.T, f *fixture) {
		record := f.attacked(t)
		for _, tc := range cases {
			if _, err := f.store.RecordTold(t.Context(), f.triager, record.ID, nil, "A regulator",
				knownAt.Add(time.Hour), "Told.", tc.details); err == nil {
				t.Errorf("a notice with %s was recorded", tc.name)
			}
		}
		shelf, err := f.store.Shelf(t.Context(), f.triager)
		if err != nil {
			t.Fatal(err)
		}
		if len(shelf[0].Told) != 0 {
			t.Errorf("%d refused notices were kept", len(shelf[0].Told))
		}
	})
}

// A window counting from another window's notice has no start and no end
// until that notice is recorded, and then counts from the first one given:
// a correction recorded beside it later does not move it.
func TestAWindowCountingFromANoticeStartsAtTheFirstOne(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		notification := f.window(t, "Notification", 72)
		final, err := f.store.DeclareWindow(ctx, f.admin, obligation.WindowSaid{
			Name: "Final report", Hours: 24 * 30, LeadHours: ptr(48), From: &notification.ID,
		})
		if err != nil {
			t.Fatal(err)
		}
		if final.FromName != "Notification" {
			t.Errorf("the window counts from %q, want Notification", final.FromName)
		}
		record := f.attacked(t)

		due := func(t *testing.T) obligation.Due {
			t.Helper()
			shelf, err := f.store.Shelf(ctx, f.triager)
			if err != nil {
				t.Fatal(err)
			}
			for _, one := range shelf[0].Windows {
				if one.Window.ID == final.ID {
					if one.Window.FromName != "Notification" {
						t.Errorf("on the shelf the window counts from %q", one.Window.FromName)
					}
					return one
				}
			}
			t.Fatal("the window counting from a notice is not on the shelf")
			return obligation.Due{}
		}

		waiting := due(t)
		if waiting.Started || !waiting.EndsAt.IsZero() || waiting.Passed || waiting.Near {
			t.Errorf("before any notice the window reads %+v, want not started", waiting)
		}

		told := knownAt.Add(50 * time.Hour)
		for _, at := range []time.Time{told, told.Add(10 * time.Hour)} {
			if _, err := f.store.RecordTold(ctx, f.triager, record.ID, &notification.ID, "A regulator",
				at, "Notification.", obligation.Details{}); err != nil {
				t.Fatal(err)
			}
		}
		started := due(t)
		if !started.Started || !started.StartsAt.Equal(told) {
			t.Errorf("the window starts %v (%v), want %s", started.StartsAt, started.Started, told)
		}
		if want := told.Add(30 * 24 * time.Hour); !started.EndsAt.Equal(want) {
			t.Errorf("the window ends %s, want %s", started.EndsAt, want)
		}
		if started.Answered {
			t.Error("a notice for the window it counts from answers it")
		}
	})
}

// Running is the shelf's arithmetic alone: a window counting from a notice
// nobody gave is not counting, whatever the time, so nothing is near or past.
func TestAWindowWaitingOnANoticeIsNeitherNearNorPast(t *testing.T) {
	anchor := int64(1)
	windows := []obligation.Window{
		{ID: anchor, Name: "Notification", Hours: 72},
		{ID: 2, Name: "Final report", Hours: 24, LeadHours: ptr(1), FromID: &anchor},
	}
	due := obligation.Running(windows, 7, knownAt, nil, knownAt.Add(365*24*time.Hour))
	if len(due) != 2 {
		t.Fatalf("%d windows run, want 2", len(due))
	}
	if !due[0].Started || !due[0].Passed {
		t.Errorf("the window counting from the attack reads %+v, want started and past", due[0])
	}
	if due[1].Started || due[1].Passed || due[1].Near {
		t.Errorf("the window waiting on a notice reads %+v, want none of it", due[1])
	}
}

// A window counts only from a window in force that applies to every product it
// does, never from itself or from a window that counts back to it, and the
// window it counts from is neither narrowed past it nor retired under it.
func TestAWindowCountsFromAnotherOnlyWhereThatOneAlwaysStartsIt(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		limited, err := f.store.DeclareWindow(ctx, f.admin, obligation.WindowSaid{
			Name: "Notification", Hours: 72, Products: []string{world.ProductName},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.DeclareWindow(ctx, f.admin, obligation.WindowSaid{
			Name: "Final report", Hours: 720, From: &limited.ID,
		}); err == nil {
			t.Error("a window over every product counts from one limited to a product")
		}
		final, err := f.store.DeclareWindow(ctx, f.admin, obligation.WindowSaid{
			Name: "Final report", Hours: 720, From: &limited.ID, Products: []string{world.ProductName},
		})
		if err != nil {
			t.Fatalf("a window over the same product was refused: %v", err)
		}

		if _, err := f.store.ChangeWindow(ctx, f.admin, limited.ID, obligation.WindowSaid{
			Name: "Notification", Hours: 72, Products: []string{"other"},
		}); err == nil {
			t.Error("a window was narrowed past one counting from it")
		}
		if _, err := f.store.ChangeWindow(ctx, f.admin, limited.ID, obligation.WindowSaid{
			Name: "Notification", Hours: 72, Products: []string{world.ProductName}, From: &final.ID,
		}); err == nil {
			t.Error("two windows count from each other")
		}
		if _, err := f.store.ChangeWindow(ctx, f.admin, final.ID, obligation.WindowSaid{
			Name: "Final report", Hours: 720, Products: []string{world.ProductName}, From: &final.ID,
		}); err == nil {
			t.Error("a window counts from itself")
		}
		if err := f.store.RetireWindow(ctx, f.admin, limited.ID); !errors.Is(err, obligation.ErrCountedFrom) {
			t.Errorf("retiring a window another counts from answered %v", err)
		}

		if _, err := f.store.ChangeWindow(ctx, f.admin, final.ID, obligation.WindowSaid{
			Name: "Final report", Hours: 720, Products: []string{world.ProductName},
		}); err != nil {
			t.Fatal(err)
		}
		if err := f.store.RetireWindow(ctx, f.admin, limited.ID); err != nil {
			t.Errorf("a window nothing counts from any more was not retired: %v", err)
		}
		if _, err := f.store.ChangeWindow(ctx, f.admin, final.ID, obligation.WindowSaid{
			Name: "Final report", Hours: 720, From: &limited.ID,
		}); err == nil {
			t.Error("a window counts from a retired one")
		}
	})
}

func ptr(n int) *int { return &n }
