// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// errTooLarge is returned when a document runs past the size it is allowed.
var errTooLarge = refusal.New("document is larger than the configured limit")

// capped stops a reader at a byte count.
//
// io.LimitedReader reports the truncation as an end of file, which reaches the
// caller as "unexpected end of JSON" — a message that sends whoever sees it
// looking for a malformed file rather than an oversized one.
type capped struct {
	r    io.Reader
	left int64
}

// Read stops at the cap. A reader with nothing left still asks the source
// for one byte, so a document of exactly the cap ends at its end of file
// rather than at the refusal meant for one larger.
func (c *capped) Read(p []byte) (int, error) {
	if c.left <= 0 {
		var probe [1]byte
		n, err := io.ReadFull(c.r, probe[:])
		if n == 0 && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
			return 0, io.EOF
		}
		if n == 0 && err != nil {
			return 0, err
		}
		return 0, errTooLarge
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

// bounded reads JSON as a stream, holding only the value being read rather
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
type bounded struct {
	dec      *json.Decoder
	maxDepth int
	depth    int
}

func newBounded(r io.Reader, maxDepth int) *bounded {
	return &bounded{dec: json.NewDecoder(r), maxDepth: maxDepth}
}

// token reads the next token, stating a document that ends inside a value in
// words.
//
// The decoder reports that as the same end-of-file error a database driver
// returns for a connection cut short, and a caller that tells the two apart by
// the error's identity answers the sender's malformed file as a fault of its
// own.
func (b *bounded) token() (json.Token, error) {
	tok, err := b.dec.Token()
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, refusal.New("the document ends partway through a value")
	}
	return tok, err
}

// end refuses a document that continues after its top-level value.
//
// Whitespace may follow it and nothing else may. Two documents written one
// after the other are read as the first otherwise, and an inventory missing
// everything the second held reads as a product that shrank.
func (b *bounded) end() error {
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

func (b *bounded) enter() error {
	b.depth++
	if b.depth > b.maxDepth {
		return refusal.Errorf("document nests deeper than the %d level limit", b.maxDepth)
	}
	return nil
}

func (b *bounded) leave() { b.depth-- }

// object reads one object, calling fn with each key. fn consumes that key's
// value.
func (b *bounded) object(fn func(key string) error) error {
	if err := b.open('{'); err != nil {
		return err
	}
	defer b.leave()
	for b.dec.More() {
		tok, err := b.token()
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

// array reads one array, calling fn per element. fn consumes that element.
func (b *bounded) array(fn func() error) error {
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
func (b *bounded) open(want json.Delim) error {
	tok, err := b.token()
	if err != nil {
		return err
	}
	if tok != want {
		return refusal.Errorf("want %v, got %v", want, tok)
	}
	return b.enter()
}

// close consumes a closing delimiter.
func (b *bounded) close() error {
	_, err := b.token()
	return err
}

// str reads one string. A null reads as empty, which is how a producer that
// emits a field it has no value for is treated the same as one that omits it.
func (b *bounded) str() (string, error) {
	tok, err := b.token()
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

// stringOrObject reads a field a format states either way, calling fn with
// each key when it is an object and returning the text when it is not.
//
// A format that names a thing as a string in one version and as an object with
// a name in the next is common enough that reading only one of the two would
// refuse documents that are perfectly well formed.
func (b *bounded) stringOrObject(fn func(key string) error) (string, error) {
	tok, err := b.token()
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
		key, err := b.token()
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

// skip consumes one value of any shape, descending through it so that nesting
// inside a part of the document we do not read is still bounded.
func (b *bounded) skip() error {
	tok, err := b.token()
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
			if _, err := b.token(); err != nil { // the key
				return err
			}
		}
		if err := b.skip(); err != nil {
			return err
		}
	}
	return b.close()
}

// each reads a field a format states either as one string or as an array of
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
func (b *bounded) each(fn func(string) error) error {
	tok, err := b.token()
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
				if _, err := b.token(); err != nil { // the key
					return err
				}
				if err := b.skip(); err != nil {
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
		value, err := b.str()
		if err != nil {
			return err
		}
		if err := fn(value); err != nil {
			return err
		}
	}
	return b.close()
}
