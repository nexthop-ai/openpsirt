// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package cverecord

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// The zip records the member count reads, by their signatures.
var (
	directoryEnd     = []byte("PK\x05\x06")
	directory64End   = []byte("PK\x06\x06")
	directory64Locus = []byte("PK\x06\x07")
	directoryEntry   = []byte("PK\x01\x02")
)

// Fixed lengths of those records, before their variable parts.
const (
	directoryEndLen   = 22
	directory64EndLen = 56
	locusLen          = 20
	entryLen          = 46
	// endSearched is how far from the end of an archive its directory end is
	// looked for, which is as far as a reader of the format looks.
	endSearched = 65 * 1024
)

// countMembers refuses an archive whose central directory holds more than
// mostMembers entries, before anything opens it.
//
// The count is the entries walked, never the count the directory end states:
// a reader of the format walks entries until one does not begin as an entry
// does, and compares the stated count only in its low sixteen bits, so the
// stated count is no bound on what opening an archive reads. The walk starts
// where a reader starts, and holds one entry's fixed part at a time.
//
// An archive this cannot find a directory in is left to the reader opening it
// to refuse.
func countMembers(path string) error {
	f, err := os.Open(path) //nolint:gosec // G304: a path this package wrote or an operator named
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	start, found, err := directoryStart(f, info.Size())
	if err != nil || !found {
		return err
	}
	r := bufio.NewReader(io.NewSectionReader(f, start, info.Size()-start))
	fixed := make([]byte, entryLen)
	for walked := 0; ; walked++ {
		if _, err := io.ReadFull(r, fixed); err != nil {
			return nil
		}
		if !bytes.Equal(fixed[:4], directoryEntry) {
			return nil
		}
		if walked == mostMembers {
			return tooLarge(fmt.Sprintf("the archive holds more than %d files", mostMembers))
		}
		skip := int64(binary.LittleEndian.Uint16(fixed[28:])) +
			int64(binary.LittleEndian.Uint16(fixed[30:])) + int64(binary.LittleEndian.Uint16(fixed[32:]))
		if _, err := r.Discard(int(skip)); err != nil {
			return nil
		}
	}
}

// directoryStart finds where an archive's central directory begins, the way a
// reader of the format does: from the directory end, through the zip64 record
// where the directory end defers to one, offset by whatever precedes the
// archive proper.
func directoryStart(f io.ReaderAt, size int64) (int64, bool, error) {
	tail := min(size, endSearched)
	block := make([]byte, tail)
	if _, err := f.ReadAt(block, size-tail); err != nil && !errors.Is(err, io.EOF) {
		return 0, false, err
	}
	at := -1
	for i := len(block) - directoryEndLen; i >= 0; i-- {
		if !bytes.Equal(block[i:i+4], directoryEnd) {
			continue
		}
		// The last signature is the directory end, and one whose comment
		// runs past the archive is no directory end at all.
		if comment := int(binary.LittleEndian.Uint16(block[i+20:])); i+directoryEndLen+comment <= len(block) {
			at = i
		}
		break
	}
	if at < 0 {
		return 0, false, nil
	}
	end := block[at:]
	endOffset := size - tail + int64(at)
	records := uint64(binary.LittleEndian.Uint16(end[10:]))
	dirSize := uint64(binary.LittleEndian.Uint32(end[12:]))
	dirOffset := uint64(binary.LittleEndian.Uint32(end[16:]))

	// A file's size is never negative, so it compares as unsigned.
	limit := uint64(size) //nolint:gosec // G115: a file size, never negative
	if records == 0xffff || dirSize == 0xffffffff || dirOffset == 0xffffffff {
		if loc := endOffset - locusLen; loc >= 0 {
			locus := make([]byte, locusLen)
			if _, err := f.ReadAt(locus, loc); err == nil && bytes.Equal(locus[:4], directory64Locus) {
				if at := binary.LittleEndian.Uint64(locus[8:]); at < limit {
					at64 := int64(at) //nolint:gosec // G115: below a file size, which an int64 holds
					record := make([]byte, directory64EndLen)
					if _, err := f.ReadAt(record, at64); err == nil && bytes.Equal(record[:4], directory64End) {
						endOffset = at64
						dirSize = binary.LittleEndian.Uint64(record[40:])
						dirOffset = binary.LittleEndian.Uint64(record[48:])
					}
				}
			}
		}
	}
	if dirOffset > limit || dirSize > limit {
		return 0, false, nil
	}
	// Both are at most a file size, which an int64 holds.
	offset := int64(dirOffset)                  //nolint:gosec // G115: bounded by the file size above
	base := endOffset - int64(dirSize) - offset //nolint:gosec // G115: bounded by the file size above
	if base > 0 {
		// Data before the archive moves every offset in it, unless an entry
		// is found where the directory end says without moving it.
		probe := make([]byte, 4)
		if _, err := f.ReadAt(probe, offset); err == nil && bytes.Equal(probe, directoryEntry) {
			base = 0
		}
	}
	start := base + offset
	if start < 0 || start >= size {
		return 0, false, nil
	}
	return start, true, nil
}
