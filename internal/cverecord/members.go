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
	"math"
	"os"
)

// The zip records the member count reads, by their signatures.
var (
	directoryEnd     = []byte("PK\x05\x06")
	directory64End   = []byte("PK\x06\x06")
	directory64Locus = []byte("PK\x06\x07")
	directoryEntry   = []byte("PK\x01\x02")
)

// zip64Field is the tag of the extra field holding an entry's zip64 values.
const zip64Field = 0x0001

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

	if records == 0xffff || dirSize == 0xffffffff || dirOffset == 0xffffffff {
		if at, found := zip64End(f, endOffset, size); found {
			record := make([]byte, directory64EndLen)
			if _, err := f.ReadAt(record, at); err == nil && bytes.Equal(record[:4], directory64End) {
				endOffset = at
				dirSize = binary.LittleEndian.Uint64(record[40:])
				dirOffset = binary.LittleEndian.Uint64(record[48:])
			}
		}
	}
	if dirOffset > math.MaxInt64 || dirSize > math.MaxInt64 {
		return 0, false, nil
	}
	// The base is worked out as a reader works it out, wrapping where it
	// wraps, so the directory found is the one a reader walks: a directory
	// end naming an offset past the file still has its directory found
	// where its size says, which is inside the file.
	offset := int64(dirOffset)                  //nolint:gosec // G115: at most the largest int64, checked above
	base := endOffset - int64(dirSize) - offset //nolint:gosec // G115: at most the largest int64, checked above
	if o := base + offset; o < 0 || o >= size {
		return 0, false, nil
	}
	if base > 0 && entryAt(f, offset, size) {
		// Data before the archive moves every offset in it, unless a whole
		// entry is found where the directory end says without moving it.
		base = 0
	}
	return base + offset, true, nil
}

// zip64End reads the zip64 locator just before a directory end and names
// where it says the zip64 record is. A locator naming a disk other than the
// first of one is no locator, as a reader of the format has it.
func zip64End(f io.ReaderAt, endOffset, size int64) (int64, bool) {
	loc := endOffset - locusLen
	if loc < 0 {
		return 0, false
	}
	locus := make([]byte, locusLen)
	if _, err := f.ReadAt(locus, loc); err != nil || !bytes.Equal(locus[:4], directory64Locus) {
		return 0, false
	}
	if binary.LittleEndian.Uint32(locus[4:]) != 0 || binary.LittleEndian.Uint32(locus[16:]) != 1 {
		return 0, false
	}
	at := binary.LittleEndian.Uint64(locus[8:])
	if at >= uint64(size) { //nolint:gosec // G115: a file size, never negative
		return 0, false
	}
	return int64(at), true //nolint:gosec // G115: below a file size, which an int64 holds
}

// entryAt reports whether a whole directory entry begins at an offset, by the
// checks a reader of the format makes of one: its fixed part and its variable
// parts are inside the file, it carries the entry signature, and a zip64
// field it declares holds every value its fixed part defers to one.
func entryAt(f io.ReaderAt, off, size int64) bool {
	if off < 0 || size-off < entryLen {
		return false
	}
	fixed := make([]byte, entryLen)
	if _, err := f.ReadAt(fixed, off); err != nil || !bytes.Equal(fixed[:4], directoryEntry) {
		return false
	}
	nameLen := int64(binary.LittleEndian.Uint16(fixed[28:]))
	extraLen := int64(binary.LittleEndian.Uint16(fixed[30:]))
	commentLen := int64(binary.LittleEndian.Uint16(fixed[32:]))
	if size-off-entryLen < nameLen+extraLen+commentLen {
		return false
	}
	extra := make([]byte, extraLen)
	if _, err := f.ReadAt(extra, off+entryLen+nameLen); err != nil {
		return false
	}
	deferred := 0
	for _, at := range []int{24, 20, 42} {
		if binary.LittleEndian.Uint32(fixed[at:]) == 0xffffffff {
			deferred++
		}
	}
	for len(extra) >= 4 {
		tag := binary.LittleEndian.Uint16(extra)
		fieldLen := int(binary.LittleEndian.Uint16(extra[2:]))
		extra = extra[4:]
		if len(extra) < fieldLen {
			break
		}
		if tag == zip64Field && fieldLen < 8*deferred {
			return false
		}
		extra = extra[fieldLen:]
	}
	return true
}
