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
	//
	// The whole of what is on offer, bounded to the room left. Handed
	// `p[:room]`, which is already exactly that many bytes, the bound had
	// nothing to cut and returned it as it was — so the buffer still ended
	// mid-character and the cut was a no-op.
	b.kept.WriteString(bound.Head(string(p), int(room)))
	return len(p), nil
}

// String is what was kept.
func (b *bounded) String() string { return b.kept.String() }

// Bytes is what was kept, without copying it.
//
// The report is read from this, and it is bounded at about half of what the
// chart ships for the whole process — so a copy taken to read from spends the
// other half, and the ceiling stops bounding what it was chosen to bound.
func (b *bounded) Bytes() []byte { return b.kept.Bytes() }
