// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"encoding/xml"
	"errors"
	"io"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// boundedXML reads XML as a stream, under the bounds bounded reads JSON
// under: at most so many bytes, nested at most so deep, and holding only the
// element being read rather than the whole document.
//
// It also refuses a document type declaration where it meets one. A
// declaration is where XML defines entities, and an entity is how a document
// makes its reader fetch a file or a URL, or expand a few hundred bytes into
// gigabytes by defining each entity as ten of the one before. The decoder
// fetches nothing and expands only the five entities XML predefines, so
// neither would happen here — but no producer writes a declaration into an
// inventory, and a reader that never accepts one cannot be talked into
// processing one by a later change to the decoder or to how it is set up.
//
// The encoding is UTF-8 or nothing. A document declaring another is refused
// by the decoder, which has nothing to translate it with.
//
// Every method consumes the rest of exactly one element, up to and including
// its end, which is what keeps the stream in step: a handler that ignores an
// element must still skip it.
type boundedXML struct {
	dec      *xml.Decoder
	maxDepth int
	depth    int
	src      *source
	// space is the namespace the document's own elements are in, set once the
	// top-level element has said what it is. An element in any other is an
	// extension, and is walked past whatever it is called: a component a
	// producer defines in a namespace of its own is not one the format
	// defines.
	space string
}

// newBoundedXML reads r as XML, at most maxBytes of it and nested at most
// maxDepth deep.
func newBoundedXML(r io.Reader, maxBytes int64, maxDepth int) *boundedXML {
	src := &source{r: r}
	return &boundedXML{
		dec:      xml.NewDecoder(&capped{r: src, left: maxBytes}),
		maxDepth: maxDepth,
		src:      src,
	}
}

// refused states what went wrong under what, as bounded does.
func (x *boundedXML) refused(what string, err error) error { return x.src.refused(what, err) }

// token reads the next token, refusing a document type declaration.
func (x *boundedXML) token() (xml.Token, error) {
	tok, err := x.dec.Token()
	if errors.Is(err, io.EOF) {
		return nil, err
	}
	if err != nil {
		// The decoder says what is wrong with a document by quoting it: a
		// whole element name, an entity's, or the encoding or version the
		// declaration names. Each is as long as the document lets it be, and
		// the refusal goes back to whoever sent it. A failure of the reader
		// beneath is told apart where every walk ends, in refused, from what
		// the reader recorded rather than from anything said here.
		return nil, refusal.Errorf("%s", trim(err.Error()))
	}
	if _, ok := tok.(xml.Directive); ok {
		return nil, refusal.New("the document carries a document type declaration, " +
			"which is where XML defines entities, and none is read")
	}
	return tok, nil
}

func (x *boundedXML) enter() error {
	x.depth++
	if x.depth > x.maxDepth {
		return refusal.Errorf("document nests deeper than the %d level limit", x.maxDepth)
	}
	return nil
}

func (x *boundedXML) leave() { x.depth-- }

// byteOrderMark is the character a producer may open a UTF-8 document with.
const byteOrderMark = rune(0xfeff)

// blank reports whether text between elements is only layout. A byte-order
// mark arrives as text before the top-level element, and is layout too.
func blank(text xml.CharData) bool {
	return strings.TrimLeft(string(text), " \t\r\n"+string(byteOrderMark)) == ""
}

// root reads up to the document's top-level element and returns it.
func (x *boundedXML) root() (xml.StartElement, error) {
	for {
		tok, err := x.token()
		if err != nil {
			return xml.StartElement{}, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return t, x.enter()
		case xml.CharData:
			if !blank(t) {
				return xml.StartElement{}, refusal.New("the document has text before its top-level element")
			}
		}
	}
}

// end refuses a document that continues after its top-level element.
//
// The decoder reads a second top-level element as readily as the first, so
// two documents written one after the other would be read as the first, and
// an inventory missing everything the second held reads as a product that
// shrank. Comments and layout may follow it and nothing else may.
func (x *boundedXML) end() error {
	for {
		tok, err := x.token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.Comment:
		case xml.CharData:
			if !blank(t) {
				return refusal.New("the document continues after its top-level element")
			}
		default:
			return refusal.New("the document continues after its top-level element")
		}
	}
}

// children reads the elements inside the one just opened, calling fn with each
// that is in the document's own namespace. fn consumes that element. Text
// between them is layout, and is passed over.
func (x *boundedXML) children(fn func(xml.StartElement) error) error {
	defer x.leave()
	for {
		tok, err := x.token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if err := x.enter(); err != nil {
				return err
			}
			if t.Name.Space != x.space {
				err = x.skip()
			} else {
				err = fn(t)
			}
			if err != nil {
				return err
			}
		case xml.EndElement:
			return nil
		}
	}
}

// text reads the text of the element just opened.
//
// Trimmed, because a producer laying its document out may put the text of an
// element on lines of its own, and the layout is not the value.
func (x *boundedXML) text() (string, error) {
	defer x.leave()
	var text strings.Builder
	for {
		tok, err := x.token()
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.CharData:
			text.Write(t)
		case xml.StartElement:
			// The element is the document's own, and its name is as long as
			// the document lets it be.
			return "", refusal.Errorf("want text, got the element %s", bound.Head(t.Name.Local, mostQuoted))
		case xml.EndElement:
			return strings.TrimSpace(text.String()), nil
		}
	}
}

// into reads the text of the element just opened into dst.
func (x *boundedXML) into(dst *string) error {
	value, err := x.text()
	if err != nil {
		return err
	}
	*dst = value
	return nil
}

// skip consumes the rest of the element just opened, descending through it so
// that nesting inside a part of the document we do not read is still bounded.
func (x *boundedXML) skip() error {
	defer x.leave()
	for {
		tok, err := x.token()
		if err != nil {
			return err
		}
		switch tok.(type) {
		case xml.StartElement:
			if err := x.enter(); err != nil {
				return err
			}
			if err := x.skip(); err != nil {
				return err
			}
		case xml.EndElement:
			return nil
		}
	}
}

// attr is the value of one of an element's own attributes: those in no
// namespace, which is where a format puts the attributes it defines.
func attr(el xml.StartElement, name string) string {
	for _, a := range el.Attr {
		if a.Name.Space == "" && a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}
