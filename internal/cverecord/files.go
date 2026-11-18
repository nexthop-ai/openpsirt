// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package cverecord

import (
	"path"
	"sort"
	"strings"
)

// What one record's file list may hold before it is read as listing none.
// The snapshot is a file from outside, so its lists are bounded where they are
// read. Variables so a test can lower them.
var (
	// mostFiles is far above the 36 files the longest list named on
	// 2026-11-18.
	mostFiles = 1_000
	// longestFile is far above the 179 bytes of the longest path named on
	// 2026-11-18.
	longestFile = 1_024
	// mostFileBytes bounds the list joined, one path a line, far above the
	// 6.4 KB of the longest joined list on 2026-11-18. A list is stored whole
	// in one value, which one engine refuses past its packet size.
	mostFileBytes = 16 << 10
)

// Listed is the files the record for an issue says the issue is in.
type Listed struct {
	// Held says a snapshot was read. Without one nothing is known about any
	// record, which differs from a record listing no files.
	Held bool
	// Files is every path the record's entries list, deduplicated and in
	// byte order. Empty where the snapshot holds no record for the issue, the
	// record lists none, or the list is one this does not read.
	Files []string
}

// Files reads which files the record for an issue says the issue is in.
//
// The identifiers are the issue's own and its aliases, in that order; the
// first the snapshot holds is the record read, as Decide reads it. The list is
// every entry's, the numbering authority's and each third party's, joined: a
// file any of them names is one the issue may be in.
//
// A list past a bound, or naming a path that leaves the repository's root, is
// read as listing none. A list read in part would answer a correction on the
// files it kept.
func (s *Snapshot) Files(identifiers []string) Listed {
	if s == nil {
		return Listed{}
	}
	listed := Listed{Held: true}
	var record *Record
	for _, id := range identifiers {
		if held, ok := s.records[strings.ToUpper(strings.TrimSpace(id))]; ok {
			record = held
			break
		}
	}
	if record == nil {
		return listed
	}
	seen := map[string]bool{}
	var files []string
	joined := 0
	for _, entry := range record.Affected {
		for _, stated := range entry.ProgramFiles {
			file, ok := SourcePath(stated)
			if !ok || len(file) > longestFile {
				return listed
			}
			if file == "" || seen[file] {
				continue
			}
			seen[file] = true
			files = append(files, file)
			joined += len(file) + 1
			if len(files) > mostFiles || joined-1 > mostFileBytes {
				return listed
			}
		}
	}
	sort.Strings(files)
	listed.Files = files
	return listed
}

// SourcePath is a path within a source tree in the one spelling it is compared
// in: relative to the tree's root, with no "." segment, repeated slash or
// trailing slash. The second result is false for a path that leaves the root
// or holds a control character, which a list joined a path a line would split.
// Empty is the root itself.
func SourcePath(stated string) (string, bool) {
	if strings.ContainsFunc(stated, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", false
	}
	trimmed := strings.Trim(strings.TrimSpace(stated), "/")
	if trimmed == "" {
		return "", true
	}
	cleaned := path.Clean(trimmed)
	if cleaned == "." {
		return "", true
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", false
	}
	return cleaned, true
}

// Under reports whether a file lies within a directory of the same tree, both
// in the spelling SourcePath gives. A directory is whole segments: drivers/phy
// holds drivers/phy/ti/phy-omap-usb2.c and not drivers/phylib.c. The root
// holds everything.
func Under(file, directory string) bool {
	if directory == "" {
		return true
	}
	return file == directory || strings.HasPrefix(file, directory+"/")
}
