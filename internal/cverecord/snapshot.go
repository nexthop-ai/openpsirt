// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package cverecord

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/bound"
)

// FileName is the snapshot's name in its directory. A bundle carried to an
// air-gapped deployment is this file, placed in the directory the deployment
// reads.
const FileName = "cve-records.jsonl.gz"

// format is the snapshot layout this reads and writes.
const format = 1

// header is the first line of a snapshot.
type header struct {
	Format int `json:"format"`
	// Taken is the newest moment any record read was updated, withdrawn and
	// rejected ones included, which is the moment the snapshot describes.
	Taken time.Time `json:"taken"`
	// From is the published file the snapshot was read from, where it was
	// fetched. The fetcher compares it with what is published now.
	From    string `json:"from,omitempty"`
	Records int    `json:"records"`
}

// Snapshot is the records a deployment holds at one moment.
type Snapshot struct {
	taken   time.Time
	from    string
	records map[string]*Record
}

// Version is how a scan run records which snapshot it read: the moment the
// snapshot describes, in UTC.
func (s *Snapshot) Version() string {
	if s == nil {
		return ""
	}
	return s.taken.UTC().Format(time.RFC3339)
}

// Len is how many records the snapshot holds.
func (s *Snapshot) Len() int {
	if s == nil {
		return 0
	}
	return len(s.records)
}

// What a snapshot file may hold. It is either written here or
// carried in by an operator, and the second is a file from outside. Writing
// refuses what reading refuses, so a snapshot built here is always one a scan
// can read.
//
// Variables so a test can lower them.
var (
	// mostRecords is far above the records with ordered unaffected lines in
	// the whole CVE List: 22,481 of 402,541 on 2026-10-07.
	mostRecords = 1_000_000
	// longestLine bounds one record's line, its newline included. The
	// largest kept on 2026-10-07 is a kernel record well under this.
	longestLine = 4 << 20
	// mostSnapshotBytes bounds the snapshot decompressed, which is about what
	// reading it holds in memory. The whole snapshot was 534 KB compressed on
	// 2026-10-07.
	mostSnapshotBytes int64 = 128 << 20
)

// tooLarge is a refusal for passing one of the bounds on what the CVE records
// hold.
type tooLarge string

func (e tooLarge) Error() string { return string(e) }

// sized counts the bytes of a snapshot's lines against the bounds.
type sized struct {
	records int
	bytes   int64
}

// add counts one record's line, newline included, and refuses it where it
// passes a bound.
func (s *sized) add(id string, line int) error {
	s.records++
	if s.records > mostRecords {
		return tooLarge(fmt.Sprintf("the CVE record snapshot holds more than %d records", mostRecords))
	}
	if line > longestLine {
		return tooLarge(fmt.Sprintf("the CVE record %s is larger than the %d bytes a snapshot holds of one",
			trimmed(id), longestLine))
	}
	s.bytes += int64(line)
	if s.bytes > mostSnapshotBytes {
		return tooLarge(fmt.Sprintf("the CVE record snapshot is larger than %d bytes", mostSnapshotBytes))
	}
	return nil
}

// trimmed bounds a record identifier quoted in a message, since the identifier
// is the archive's.
func trimmed(id string) string {
	if cut := bound.Head(id, 40); len(cut) < len(id) {
		return cut + "…"
	}
	return id
}

// Write writes a snapshot, and refuses records a snapshot cannot hold and a
// moment of none, which reading a snapshot refuses.
func Write(w io.Writer, taken time.Time, from string, records []Record) error {
	if taken.IsZero() {
		return errors.New("the CVE records carry no time they were updated, so the snapshot cannot say when it was taken")
	}
	head, err := json.Marshal(header{Format: format, Taken: taken.UTC(), From: from, Records: len(records)})
	if err != nil {
		return err
	}
	count := sized{bytes: int64(len(head) + 1)}
	zipped := gzip.NewWriter(w)
	if _, err := zipped.Write(append(head, '\n')); err != nil {
		return err
	}
	for i := range records {
		line, err := json.Marshal(&records[i])
		if err != nil {
			return err
		}
		if err := count.add(records[i].ID, len(line)+1); err != nil {
			return err
		}
		if _, err := zipped.Write(append(line, '\n')); err != nil {
			return err
		}
	}
	return zipped.Close()
}

// Read reads a snapshot.
func Read(r io.Reader) (*Snapshot, error) {
	unzipped, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("read the CVE record snapshot: %w", err)
	}
	defer func() { _ = unzipped.Close() }()
	held := &capped{r: unzipped, left: mostSnapshotBytes}
	snapshot, err := readLines(held)
	if held.over {
		return nil, tooLarge(fmt.Sprintf("the CVE record snapshot is larger than %d bytes", mostSnapshotBytes))
	}
	return snapshot, err
}

// capped reads at most left bytes, and says when there was more.
type capped struct {
	r    io.Reader
	left int64
	over bool
}

func (c *capped) Read(p []byte) (int, error) {
	if c.left <= 0 {
		// One byte more decides whether the stream ended at the bound or
		// went past it.
		var probe [1]byte
		if n, _ := io.ReadFull(c.r, probe[:]); n > 0 {
			c.over = true
			return 0, errors.New("past the bound")
		}
		return 0, io.EOF
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

// readLines reads a snapshot's decompressed lines.
func readLines(r io.Reader) (*Snapshot, error) {
	lines := bufio.NewScanner(r)
	lines.Buffer(make([]byte, min(64<<10, longestLine)), longestLine)

	if !lines.Scan() {
		if err := lines.Err(); err != nil {
			return nil, fmt.Errorf("read the CVE record snapshot: %w", err)
		}
		return nil, errors.New("the CVE record snapshot is empty")
	}
	var head header
	if err := json.Unmarshal(lines.Bytes(), &head); err != nil {
		return nil, fmt.Errorf("read the CVE record snapshot's header: %w", err)
	}
	if head.Format != format {
		return nil, fmt.Errorf("the CVE record snapshot is in format %d, and this reads format %d",
			head.Format, format)
	}
	if head.Taken.IsZero() {
		return nil, errors.New("the CVE record snapshot does not say when it was taken")
	}
	snapshot := &Snapshot{taken: head.Taken, from: head.From, records: map[string]*Record{}}
	var count sized
	for lines.Scan() {
		if err := count.add("", 0); err != nil {
			return nil, err
		}
		var record Record
		if err := json.Unmarshal(lines.Bytes(), &record); err != nil {
			return nil, fmt.Errorf("read a record in the CVE record snapshot: %w", err)
		}
		id := strings.ToUpper(strings.TrimSpace(record.ID))
		if id == "" {
			continue
		}
		snapshot.records[id] = &record
	}
	if err := lines.Err(); errors.Is(err, bufio.ErrTooLong) {
		return nil, tooLarge(fmt.Sprintf("a record in the CVE record snapshot is larger than the %d bytes a snapshot holds of one",
			longestLine))
	} else if err != nil {
		return nil, fmt.Errorf("read the CVE record snapshot: %w", err)
	}
	return snapshot, nil
}

// Held is the snapshot in a directory, read again whenever the file changes.
//
// Read on demand rather than once at start, because the file is replaced
// while the server runs: by the fetcher, or by an operator copying a bundle
// in. The file is replaced by a rename, so a reader sees the old file or the
// new one and never half of either.
type Held struct {
	dir string

	mu       sync.Mutex
	snapshot *Snapshot
	modified time.Time
	size     int64
}

// NewHeld returns the snapshot kept in dir.
func NewHeld(dir string) *Held {
	return &Held{dir: dir}
}

// Dir is where the snapshot is kept.
func (h *Held) Dir() string {
	if h == nil {
		return ""
	}
	return h.dir
}

// Current is the snapshot in the directory, or nil where there is none.
//
// A file that cannot be read is an error, never an empty snapshot: a scan
// that narrowed nothing because a bundle was damaged would read as records
// that excluded nothing.
func (h *Held) Current() (*Snapshot, error) {
	if h == nil || h.dir == "" {
		return nil, nil
	}
	path := filepath.Join(h.dir, FileName)
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("look for the CVE record snapshot: %w", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.snapshot != nil && info.ModTime().Equal(h.modified) && info.Size() == h.size {
		return h.snapshot, nil
	}
	file, err := os.Open(path) //nolint:gosec // G304: the directory is configuration and the name is fixed
	if err != nil {
		return nil, fmt.Errorf("open the CVE record snapshot: %w", err)
	}
	defer file.Close()
	snapshot, err := Read(file)
	if err != nil {
		return nil, err
	}
	h.snapshot, h.modified, h.size = snapshot, info.ModTime(), info.Size()
	return snapshot, nil
}
