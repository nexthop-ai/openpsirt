package scanner

import (
	"bytes"

	"github.com/nexthop-ai/openpsirt/internal/bound"
)

// bounded collects what a subprocess writes, up to a limit.
//
// Past the limit the excess is dropped and the fact that it was is recorded,
// rather than the write failing. A failed write closes the pipe, which kills
// the scanner with a broken pipe and loses the reason: the caller ends up with
// the signal instead of the limit, so whether being past the limit is fatal is
// the caller's decision to make once the run has finished.
type bounded struct {
	kept bytes.Buffer
	most int64
	// over says the limit was reached and the rest was dropped.
	over bool
}

// Write takes what the subprocess wrote, within the limit.
func (b *bounded) Write(p []byte) (int, error) {
	if b.over {
		// Reported as written so that the copy keeps draining the pipe. A
		// short write stops os/exec's copy, which leaves the scanner blocked
		// on a pipe nobody is reading.
		return len(p), nil
	}
	room := b.most - int64(b.kept.Len())
	if int64(len(p)) <= room {
		return b.kept.Write(p)
	}
	b.over = true
	// Cut on a character boundary: what is kept is stored, and three engines
	// of four refuse invalid UTF-8.
	b.kept.WriteString(bound.Head(string(p[:room]), int(room)))
	return len(p), nil
}

// String is what was kept.
func (b *bounded) String() string { return b.kept.String() }
