// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package docread reads a document somebody else wrote as a stream, bounded
// in size and in nesting, and tells a fault in the document apart from a fault
// in whatever it was read from.
package docread

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// MostQuoted is how much of a document's own token a refusal quotes.
const MostQuoted = 64

// ErrTooLarge is returned when a document runs past the size it is allowed.
var ErrTooLarge = refusal.New("document is larger than the configured limit")

// Capped stops a reader at a byte count.
//
// io.LimitedReader reports the truncation as an end of file, which reaches the
// caller as "unexpected end of JSON" — a message that sends whoever sees it
// looking for a malformed file rather than an oversized one.
type Capped struct {
	r    io.Reader
	left int64
}

// Cap reads r up to max bytes, refusing a document that runs past them.
func Cap(r io.Reader, max int64) *Capped { return &Capped{r: r, left: max} }

// Read stops at the cap. A reader with nothing left still asks the source
// for one byte, so a document of exactly the cap ends at its end of file
// rather than at the refusal meant for one larger.
func (c *Capped) Read(p []byte) (int, error) {
	if c.left <= 0 {
		var probe [1]byte
		n, err := io.ReadFull(c.r, probe[:])
		if n == 0 && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
			return 0, io.EOF
		}
		if n == 0 && err != nil {
			return 0, err
		}
		return 0, ErrTooLarge
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

// JSON reads JSON as a stream, holding only the value being read rather
// than the whole document, and refusing anything nested deeper than it is
// allowed.
//
// Decoding a document into a structure is simpler and is what a small file
// wants. It is not what tens of megabytes and tens of thousands of components
// want, and it carries no depth bound anyone can set — so a document nested
// far enough to exhaust memory is something we would discover by running out
// of it rather than by refusing the file.
//
// Every method consumes exactly one JSON value, which is what keeps the stream
// in step: a handler that ignores a key must still skip its value.
type JSON struct {
	dec      *json.Decoder
	maxDepth int
	depth    int
	src      *Source
}

// NewJSON reads r as JSON, at most maxBytes of it and nested at most
// maxDepth deep.
func NewJSON(r io.Reader, maxBytes int64, maxDepth int) *JSON {
	src := &Source{r: r}
	dec := json.NewDecoder(Cap(src, maxBytes))
	// A number is held as its text, so an integer too large for a float is
	// refused as one rather than read as a neighbor.
	dec.UseNumber()
	return &JSON{dec: dec, maxDepth: maxDepth, src: src}
}

// Source is the reader beneath a document, and what it failed with.
//
// A read that failed is a fault of whatever was read from, not of the
// document: a connection cut short, or stored bytes let go partway through.
// Wrapped as a refusal, it would be published to the sender as a fault in
// their file.
type Source struct {
	r   io.Reader
	err error
}

// NewSource wraps r to remember what it failed with.
func NewSource(r io.Reader) *Source { return &Source{r: r} }

func (s *Source) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if err != nil && err != io.EOF {
		s.err = err
	}
	return n, err
}

// Refused states what went wrong reading the document under what, as a
// refusal where the document is at fault and as a fault where the reader
// beneath it failed.
func (b *JSON) Refused(what string, err error) error { return b.src.Refused(what, err) }

// Refused is the decision itself, shared by both encodings' streams.
func (s *Source) Refused(what string, err error) error {
	if s.err != nil {
		return fmt.Errorf("%s: %w", what, s.err)
	}
	return refusal.Errorf("%s: %w", what, err)
}

// Token reads the next token, stating a document that ends inside a value in
// words.
//
// The decoder reports that as the same end-of-file error a database driver
// returns for a connection cut short, and a caller that tells the two apart by
// the error's identity answers the sender's malformed file as a fault of its
// own.
func (b *JSON) Token() (json.Token, error) {
	tok, err := b.dec.Token()
	if errors.Is(err, io.ErrUnexpectedEOF) && b.src.err == nil {
		return nil, refusal.New("the document ends partway through a value")
	}
	// Every string a document carries may reach the database, and the query
	// builder refuses a NUL on two of the engines. The decoder has already
	// replaced each invalid byte.
	if s, ok := tok.(string); ok && strings.IndexByte(s, 0) >= 0 {
		tok = strings.ReplaceAll(s, "\x00", "")
	}
	return tok, err
}

// End refuses a document that continues after its top-level value.
//
// Whitespace may follow it and nothing else may. Two documents written one
// after the other are read as the first otherwise, and an inventory missing
// everything the second held reads as a product that shrank.
func (b *JSON) End() error {
	tok, err := b.dec.Token()
	if errors.Is(err, io.EOF) {
		return nil
	}
	var syntax *json.SyntaxError
	if errors.As(err, &syntax) {
		return refusal.New("the document continues after its top-level value")
	}
	if err != nil {
		return err
	}
	return refusal.Errorf("the document continues after its top-level value with %v", tok)
}

func (b *JSON) enter() error {
	b.depth++
	if b.depth > b.maxDepth {
		return refusal.Errorf("document nests deeper than the %d level limit", b.maxDepth)
	}
	return nil
}

func (b *JSON) leave() { b.depth-- }

// Object reads one object, calling fn with each key. fn consumes that key's
// value.
func (b *JSON) Object(fn func(key string) error) error {
	if err := b.open('{'); err != nil {
		return err
	}
	defer b.leave()
	for b.dec.More() {
		tok, err := b.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return refusal.Errorf("object key is %v, not a string", tok)
		}
		if err := fn(key); err != nil {
			return err
		}
	}
	return b.close()
}

// Array reads one array, calling fn per element. fn consumes that element.
func (b *JSON) Array(fn func() error) error {
	if err := b.open('['); err != nil {
		return err
	}
	defer b.leave()
	for b.dec.More() {
		if err := fn(); err != nil {
			return err
		}
	}
	return b.close()
}

// open consumes an opening delimiter and descends a level.
func (b *JSON) open(want json.Delim) error {
	tok, err := b.Token()
	if err != nil {
		return err
	}
	if tok != want {
		// The token is the document's own, and a string token is as long as
		// the document lets it be.
		return refusal.Errorf("want %v, got %s", want, bound.Head(fmt.Sprint(tok), MostQuoted))
	}
	return b.enter()
}

// close consumes a closing delimiter.
func (b *JSON) close() error {
	_, err := b.Token()
	return err
}

// Str reads one string. A null reads as empty, which is how a producer that
// emits a field it has no value for is treated the same as one that omits it.
func (b *JSON) Str() (string, error) {
	tok, err := b.Token()
	if err != nil {
		return "", err
	}
	switch v := tok.(type) {
	case string:
		return v, nil
	case nil:
		return "", nil
	default:
		return "", refusal.Errorf("want a string, got %v", v)
	}
}

// StringOrObject reads a field a format states either way, calling fn with
// each key when it is an object and returning the text when it is not.
//
// A format that names a thing as a string in one version and as an object with
// a name in the next is common enough that reading only one of the two would
// refuse documents that are perfectly well formed.
func (b *JSON) StringOrObject(fn func(key string) error) (string, error) {
	tok, err := b.Token()
	if err != nil {
		return "", err
	}
	switch v := tok.(type) {
	case string:
		return v, nil
	case nil:
		return "", nil
	case json.Delim:
		if v != '{' {
			return "", refusal.Errorf("want a string or an object, got %v", v)
		}
	default:
		return "", refusal.Errorf("want a string or an object, got %v", v)
	}
	if err := b.enter(); err != nil {
		return "", err
	}
	defer b.leave()
	for b.dec.More() {
		key, err := b.Token()
		if err != nil {
			return "", err
		}
		name, ok := key.(string)
		if !ok {
			return "", refusal.Errorf("object key is %v, not a string", key)
		}
		if err := fn(name); err != nil {
			return "", err
		}
	}
	return "", b.close()
}

// Skip consumes one value of any shape, descending through it so that nesting
// inside a part of the document we do not read is still bounded.
func (b *JSON) Skip() error {
	tok, err := b.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	if err := b.enter(); err != nil {
		return err
	}
	defer b.leave()
	for b.dec.More() {
		if delim == '{' {
			if _, err := b.Token(); err != nil { // the key
				return err
			}
		}
		if err := b.Skip(); err != nil {
			return err
		}
	}
	return b.close()
}

// Each reads a field a format states either as one string or as an array of
// them, calling fn per value.
//
// A format that says "one or more" and serializes the one without its brackets
// is common enough that reading only the array would refuse documents that are
// perfectly well formed.
//
// An object is walked past rather than refused, for the same reason an edge
// naming nothing is dropped rather than taken as a malformed file: a linked
// format lets a field that is a reference be written out as the thing it
// refers to, and a document doing that in a field whose text is all this reads
// has nothing here to offer rather than being broken.
func (b *JSON) Each(fn func(string) error) error {
	tok, err := b.Token()
	if err != nil {
		return err
	}
	switch v := tok.(type) {
	case string:
		return fn(v)
	case nil:
		return nil
	case json.Delim:
		if v == '{' {
			if err := b.enter(); err != nil {
				return err
			}
			defer b.leave()
			for b.dec.More() {
				if _, err := b.Token(); err != nil { // the key
					return err
				}
				if err := b.Skip(); err != nil {
					return err
				}
			}
			return b.close()
		}
		if v != '[' {
			return refusal.Errorf("want a string or an array, got %v", v)
		}
	default:
		return refusal.Errorf("want a string or an array, got %v", v)
	}
	if err := b.enter(); err != nil {
		return err
	}
	defer b.leave()
	for b.dec.More() {
		value, err := b.Str()
		if err != nil {
			return err
		}
		if err := fn(value); err != nil {
			return err
		}
	}
	return b.close()
}

// Int reads one integer. A null reads as absent; a fraction, or a value past
// what 32 bits hold, is refused.
func (b *JSON) Int() (*int, error) {
	tok, err := b.Token()
	if err != nil {
		return nil, err
	}
	switch v := tok.(type) {
	case json.Number:
		n, err := strconv.ParseInt(string(v), 10, 32)
		if err != nil {
			return nil, refusal.Errorf("want an integer, got %s", bound.Head(string(v), MostQuoted))
		}
		i := int(n)
		return &i, nil
	case nil:
		return nil, nil
	default:
		return nil, refusal.Errorf("want an integer, got %s", bound.Head(fmt.Sprint(v), MostQuoted))
	}
}

// Bool reads one boolean. A null reads as absent.
func (b *JSON) Bool() (*bool, error) {
	tok, err := b.Token()
	if err != nil {
		return nil, err
	}
	switch v := tok.(type) {
	case bool:
		return &v, nil
	case nil:
		return nil, nil
	default:
		return nil, refusal.Errorf("want a boolean, got %s", bound.Head(fmt.Sprint(v), MostQuoted))
	}
}

// ArrayOrNull reads one array as Array does, or a null, and reports which: a
// format that tells an absent list from an empty one states the absence as
// null.
func (b *JSON) ArrayOrNull(fn func() error) (bool, error) {
	tok, err := b.Token()
	if err != nil {
		return false, err
	}
	if tok == nil {
		return false, nil
	}
	if tok != json.Delim('[') {
		return false, refusal.Errorf("want an array, got %s", bound.Head(fmt.Sprint(tok), MostQuoted))
	}
	if err := b.enter(); err != nil {
		return false, err
	}
	defer b.leave()
	for b.dec.More() {
		if err := fn(); err != nil {
			return true, err
		}
	}
	return true, b.close()
}
