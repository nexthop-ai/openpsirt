// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysisclient

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// source reads the checkout's files, each once, for the fingerprints and
// snippets a run carries.
type source struct {
	root  string
	files map[string][]string
	salt  []byte
}

// largestRead is the largest file read for a fingerprint or a snippet.
// Generated sources past it are left without either.
const largestRead = 16 << 20

// lines is a file of the checkout as its lines, with their line endings
// removed, or nil where it cannot be read.
func (s *source) lines(rel string) []string {
	if got, ok := s.files[rel]; ok {
		return got
	}
	var out []string
	full, ok := s.inside(rel)
	if !ok {
		s.files[rel] = nil
		return nil
	}
	if info, err := os.Stat(full); err == nil && info.Mode().IsRegular() && info.Size() <= largestRead {
		if data, err := os.ReadFile(full); err == nil { //nolint:gosec // G304: inside reached it through every link and found it in the checkout
			// A file's last line ends with a line feed, and opens no line
			// after it.
			out = strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
			for i, l := range out {
				out[i] = strings.TrimSuffix(l, "\r")
			}
		}
	}
	s.files[rel] = out
	return out
}

// inside is a checkout path as a file, with every link along it followed. A
// path whose links lead out of the checkout is not read: a snippet carries
// what it reads off the build host.
func (s *source) inside(rel string) (string, bool) {
	root, err := filepath.EvalSymlinks(s.root)
	if err != nil {
		return "", false
	}
	full, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return "", false
	}
	back, err := filepath.Rel(root, full)
	if err != nil || back == ".." || strings.HasPrefix(back, ".."+string(filepath.Separator)) || filepath.IsAbs(back) {
		return "", false
	}
	return full, true
}

// contextPrint is the content fingerprint of the line a result is about: a
// hash of that line and one line either side, each with its surrounding white
// space removed and every run of white space inside it written as one space,
// joined by line feeds. A line before the first or after the last is empty.
// The same text gives the same fingerprint whatever line endings or
// indentation a checkout has, and a reindented or moved block keeps it.
//
// With a salt it is an HMAC keyed on the salt, so a short line cannot be
// recovered by hashing guesses.
func (s *source) contextPrint(rel string, line int) string {
	text := s.lines(rel)
	if text == nil || line < 1 || line > len(text) {
		return ""
	}
	at := func(n int) string {
		if n < 1 || n > len(text) {
			return ""
		}
		return normalizedLine(text[n-1])
	}
	var h hash.Hash
	if s.salt != nil {
		h = hmac.New(sha256.New, s.salt)
	} else {
		h = sha256.New()
	}
	h.Write([]byte(at(line-1) + "\n" + at(line) + "\n" + at(line+1)))
	return hex.EncodeToString(h.Sum(nil))
}

func normalizedLine(l string) string {
	return strings.Join(strings.FieldsFunc(l, unicode.IsSpace), " ")
}

// snippetAround is how many lines either side of a location its context
// region holds.
const snippetAround = 2

// longestSnippet bounds one snippet's text.
const longestSnippet = 4096

// snippets writes the text of a location's lines into its region, and the
// lines around them into its context region.
func (s *source) snippets(loc obj) {
	physical := child(loc, "physicalLocation")
	art := child(physical, "artifactLocation")
	region := child(physical, "region")
	if str(art, "uriBaseId") != rootBase || region == nil {
		return
	}
	rel, ok := relativePath(str(art, "uri"))
	if !ok {
		return
	}
	text := s.lines(rel)
	start, ok := num(region, "startLine")
	if text == nil || !ok || start < 1 || start > len(text) {
		return
	}
	end, ok := num(region, "endLine")
	if !ok || end < start || end > len(text) {
		end = start
	}
	region["snippet"] = obj{"text": bounded(text[start-1 : end])}
	from, to := max(1, start-snippetAround), min(len(text), end+snippetAround)
	physical["contextRegion"] = obj{
		"startLine": from, "endLine": to,
		"snippet": obj{"text": bounded(text[from-1 : to])},
	}
}

func bounded(lines []string) string {
	s := strings.Join(lines, "\n")
	if len(s) <= longestSnippet {
		return s
	}
	cut := longestSnippet
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut]
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// saltID names a salt without revealing it: the first eight bytes of its
// SHA-256, in lower-case hexadecimal. A changed salt changes every
// fingerprint, and the deployment reads a changed name as a re-baseline.
func saltID(salt []byte) string {
	sum := sha256.Sum256(salt)
	return hex.EncodeToString(sum[:8])
}
