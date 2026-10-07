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
	// Taken is the newest moment any kept record was updated, which is the
	// moment the snapshot describes.
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

// Bounds on what a snapshot file may hold. It is either written here or
// carried in by an operator, and the second is a file from outside.
const (
	// mostRecords is far above the records with ordered unaffected lines in
	// the whole CVE List: 22,763 of 402,541 on 2026-10-07.
	mostRecords = 1_000_000
	// longestLine bounds one record. The largest kept on 2026-10-07 is a
	// kernel record well under this.
	longestLine = 4 << 20
)

// Write writes a snapshot.
func Write(w io.Writer, taken time.Time, from string, records []Record) error {
	zipped := gzip.NewWriter(w)
	encoder := json.NewEncoder(zipped)
	if err := encoder.Encode(header{Format: format, Taken: taken.UTC(), From: from,
		Records: len(records)}); err != nil {
		return err
	}
	for i := range records {
		if err := encoder.Encode(&records[i]); err != nil {
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
	lines := bufio.NewScanner(unzipped)
	lines.Buffer(make([]byte, 64<<10), longestLine)

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
	for lines.Scan() {
		if len(snapshot.records) >= mostRecords {
			return nil, fmt.Errorf("the CVE record snapshot holds more than %d records", mostRecords)
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
	if err := lines.Err(); err != nil {
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
