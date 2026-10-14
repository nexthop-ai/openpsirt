// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestAStoreMethodQueryingWithNoSubjectIsReported(t *testing.T) {
	source := []byte(`package finding

func (s *Store) Narrowed(ctx context.Context, subject access.Subject, id int64) error {
	return s.db.NewSelect().Where("id = ?", id).Scan(ctx)
}

func (s *Store) Unnarrowed(ctx context.Context, id int64) error {
	return s.db.NewSelect().Where("id = ?", id).Scan(ctx)
}

func (v *Vulnerabilities) Raw(ctx context.Context, id int64) error {
	_, err := v.db.NewRaw("SELECT 1").Exec(ctx)
	return err
}

func (s *Store) Arithmetic(a, b int) int { return a + b }

func (s *Store) unexported(ctx context.Context) error {
	return s.db.NewSelect().Scan(ctx)
}

func (o *Other) Elsewhere(ctx context.Context) error {
	return o.db.NewSelect().Scan(ctx)
}

func (s *Store) Through(ctx context.Context, id int64) error {
	return s.helper(ctx, id)
}

func (s *Store) helper(ctx context.Context, id int64) error {
	return read(ctx, s.db, id)
}

func read(ctx context.Context, db bun.IDB, id int64) error {
	return db.NewSelect().Where("id = ?", id).Scan(ctx)
}

func (s *Store) Pure(a int) int { return twice(a) }

func twice(a int) int { return a * 2 }
`)
	found, examined, err := inSource("finding", "x.go", source)
	if err != nil {
		t.Fatal(err)
	}
	if examined != 6 {
		t.Errorf("%d store methods were examined, want the six exported ones", examined)
	}
	reported := map[string]bool{}
	for _, one := range found {
		reported[one.name] = true
	}
	for name, want := range map[string]bool{
		"finding.Store.Narrowed":      false,
		"finding.Store.Unnarrowed":    true,
		"finding.Vulnerabilities.Raw": true,
		"finding.Store.Arithmetic":    false,
		"finding.Store.unexported":    false,
		"finding.Other.Elsewhere":     false,
		"finding.Store.Through":       true,
		"finding.Store.Pure":          false,
	} {
		if reported[name] != want {
			t.Errorf("%s reported = %v, want %v", name, reported[name], want)
		}
	}
}

func TestAnExemptionNamesItsReason(t *testing.T) {
	if _, err := parseExempt([]byte("finding.Store.Apply\n")); err == nil {
		t.Error("an exemption with no reason was accepted")
	}
	exempt, err := parseExempt([]byte("# a comment\n\nfinding.Store.Apply A background pass.\n"))
	if err != nil {
		t.Fatal(err)
	}
	if exempt["finding.Store.Apply"] != "A background pass." {
		t.Errorf("the exemption reads %v", exempt)
	}
}
