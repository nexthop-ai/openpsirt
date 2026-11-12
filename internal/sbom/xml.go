// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"encoding/xml"
	"errors"
	"io"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/docread"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// boundedXML reads XML as a stream, under the bounds docread.JSON reads JSON
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
	src      *docread.Source
	// space is the namespace the document's own elements are in, set once the
	// top-level element has said what it is. An element in any other is an
	// extension, and is walked past whatever it is called: a component a
	// producer defines in a namespace of its own is not one the format
	// defines.
	space string
}

// newBoundedXML reads r as XML, at most maxBytes of it, nested at most
// maxDepth deep, and with no element's start or end tag longer than mostTag.
func newBoundedXML(r io.Reader, maxBytes int64, maxDepth int) *boundedXML {
	src := docread.NewSource(r)
	return &boundedXML{
		dec:      xml.NewDecoder(&tagGuard{r: docread.Cap(src, maxBytes), most: mostTag}),
		maxDepth: maxDepth,
		src:      src,
	}
}

// mostTag is the longest an element's start or end tag may be, in bytes.
//
// The decoder holds a start tag's every attribute before it returns the
// element, so a tag as long as the size bound allows holds many times that
// bound before any check here sees it: a 16 MiB tag of empty attributes
// allocated 985 MiB. Far above any producer's tag, which is a few hundred
// bytes at the top-level element's namespace declarations.
const mostTag = 64 << 10

// tagGuard refuses a document one of whose start or end tags runs past most
// bytes, as the decoder reads the tag rather than once it has returned it.
//
// It follows the document's markup only as far as telling where a tag ends:
// an attribute value may hold a closing angle bracket inside its quotes, and
// a comment, a character data section, a processing instruction or a
// declaration is ended by its own terminator and is not a tag. None of those
// is bounded here, because the decoder holds each as the bytes it is, which
// the size bound already bounds.
type tagGuard struct {
	r    io.Reader
	most int
	// state is where in the markup the last byte read left the guard, and
	// opened is what follows an opening angle bracket while it still could
	// begin a comment or a character data section.
	state  markup
	opened []byte
	// length is how much of the tag being read has been read, quote the quote
	// an attribute value inside it opened, and last the two bytes before this
	// one, which end a comment or a character data section.
	length int
	quote  byte
	last   [2]byte
	// nested is how many angle brackets a declaration has opened and not
	// closed, as the decoder counts them: a declaration ends at the bracket
	// closing the first, outside quotes. opening is how much of a comment's
	// opening an angle bracket inside a declaration has begun, the bracket
	// included, and commented whether a comment inside one is being read.
	nested    int
	opening   int
	commented bool
}

// markup is where a document's reader stands: between tags, or inside one of
// the constructs an opening angle bracket begins.
type markup int

const (
	inText markup = iota
	afterOpening
	inBang
	inTag
	inComment
	inCharData
	inInstruction
	inDeclaration
)

// The openings that begin a comment and a character data section, after the
// angle bracket.
const (
	commentOpening  = "!--"
	charDataOpening = "![CDATA["
)

func (g *tagGuard) Read(p []byte) (int, error) {
	n, err := g.r.Read(p)
	for _, c := range p[:n] {
		if refused := g.step(c); refused != nil {
			return 0, refused
		}
	}
	return n, err
}

// step moves the guard past one byte of the document.
func (g *tagGuard) step(c byte) error {
	ended := g.last
	g.last = [2]byte{g.last[1], c}
	switch g.state {
	case inText:
		if c == '<' {
			g.state = afterOpening
		}
	case afterOpening:
		switch c {
		case '!':
			g.state, g.opened = inBang, append(g.opened[:0], c)
		case '?':
			g.state = inInstruction
		default:
			g.state, g.length, g.quote = inTag, 1, 0
			return g.tag(c)
		}
	case inBang:
		g.opened = append(g.opened, c)
		switch {
		case string(g.opened) == commentOpening:
			g.state, g.last = inComment, [2]byte{}
		case string(g.opened) == charDataOpening:
			g.state, g.last = inCharData, [2]byte{}
		case !strings.HasPrefix(commentOpening, string(g.opened)) &&
			!strings.HasPrefix(charDataOpening, string(g.opened)):
			g.state, g.quote, g.nested = inDeclaration, 0, 0
			g.opening, g.commented = 0, false
			g.declaration(c, ended)
		}
	case inComment:
		if c == '>' && ended == [2]byte{'-', '-'} {
			g.state = inText
		}
	case inCharData:
		if c == '>' && ended == [2]byte{']', ']'} {
			g.state = inText
		}
	case inInstruction:
		if c == '>' && ended[1] == '?' {
			g.state = inText
		}
	case inDeclaration:
		g.declaration(c, ended)
	case inTag:
		g.length++
		return g.tag(c)
	}
	return nil
}

// declaration moves the guard past one byte of a declaration, ended being
// the two bytes before it. A bracket inside quotes is text, one closing a
// bracket the declaration opened does not end it, and a comment inside it is
// skipped whole, quotes and brackets included, which is how the decoder reads
// one; read any other way, the guard and the decoder disagree on where the
// tags after it are.
func (g *tagGuard) declaration(c byte, ended [2]byte) {
	if g.commented {
		// The decoder ends the comment at the byte after its two dashes,
		// and refuses the document where that byte is not a closing bracket.
		if ended == [2]byte{'-', '-'} {
			g.commented = false
		}
		return
	}
	if g.opening > 0 {
		if c == commentOpening[g.opening-1] {
			g.opening++
			if g.opening > len(commentOpening) {
				// The opening's own dashes never end the comment.
				g.opening, g.commented, g.last = 0, true, [2]byte{}
			}
			return
		}
		// Not a comment: the bracket opened a nested one, and this byte is
		// read as any other.
		g.opening = 0
		g.nested++
	}
	switch {
	case g.quote != 0:
		if c == g.quote {
			g.quote = 0
		}
	case c == '"' || c == '\'':
		g.quote = c
	case c == '<':
		g.opening = 1
	case c == '>' && g.nested > 0:
		g.nested--
	case c == '>':
		g.state = inText
	}
}

// tag moves the guard past one byte of a start or end tag.
func (g *tagGuard) tag(c byte) error {
	if g.length > g.most {
		return refusal.Errorf("an element's tag is longer than the %d byte limit", g.most)
	}
	switch {
	case g.quote != 0:
		if c == g.quote {
			g.quote = 0
		}
	case c == '"' || c == '\'':
		g.quote = c
	case c == '>':
		g.state = inText
	}
	return nil
}

// refused states what went wrong under what, as docread.JSON does.
func (x *boundedXML) refused(what string, err error) error { return x.src.Refused(what, err) }

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
		// The decoder states a document cut off inside an element in words,
		// and one holding no element at all as a bare end of file.
		if errors.Is(err, io.EOF) {
			return xml.StartElement{}, refusal.New("the document holds no top-level element")
		}
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
			return "", refusal.Errorf("want text, got the element %s", bound.Head(t.Name.Local, docread.MostQuoted))
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
