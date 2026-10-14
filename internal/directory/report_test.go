// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package directory

import (
	"context"
	"errors"
	"log/slog"
	"testing"
)

// kept is a log handler that keeps each line's message and level.
type kept struct{ lines []slog.Record }

func (k *kept) Enabled(context.Context, slog.Level) bool { return true }
func (k *kept) Handle(_ context.Context, r slog.Record) error {
	k.lines = append(k.lines, r)
	return nil
}
func (k *kept) WithAttrs([]slog.Attr) slog.Handler { return k }
func (k *kept) WithGroup(string) slog.Handler      { return k }

// What a pass reports, for each shape of pass.
func TestEachPassSaysWhatItDid(t *testing.T) {
	for _, c := range []struct {
		name    string
		written Written
		err     error
		want    string
		level   slog.Level
	}{
		{"failed", Written{}, errors.New("the store could not be reached"),
			"writing the published advisory directory", slog.LevelError},
		{"skipped", Written{Documents: 3, Skipped: 1, Unchanged: true},
			nil, "wrote the published advisory directory past documents that could not be read",
			slog.LevelError},
		{"everything held back", Written{Held: 2},
			nil, "nothing in the published advisory directory may travel", slog.LevelInfo},
		{"some held back", Written{Documents: 1, Held: 2},
			nil, "wrote the published advisory directory", slog.LevelInfo},
		{"written", Written{Documents: 1},
			nil, "wrote the published advisory directory", slog.LevelInfo},
		{"unchanged", Written{Documents: 1, Unchanged: true}, nil, "", 0},
		{"nothing at all", Written{Unchanged: true}, nil, "", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			logged := &kept{}
			w := &Writer{logger: slog.New(logged)}
			w.report(t.Context(), c.written, c.err)
			if c.want == "" {
				if len(logged.lines) != 0 {
					t.Errorf("a pass that changed nothing said %q", logged.lines[0].Message)
				}
				return
			}
			if len(logged.lines) != 1 {
				t.Fatalf("said %d lines, want one", len(logged.lines))
			}
			if logged.lines[0].Message != c.want || logged.lines[0].Level != c.level {
				t.Errorf("said %q at %v, want %q at %v", logged.lines[0].Message,
					logged.lines[0].Level, c.want, c.level)
			}
		})
	}
}
