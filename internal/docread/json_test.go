// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package docread_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/docread"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

var errTooMany = refusal.New("too many properties")

// bounded reads doc with the members under "properties" bounded at two, and
// every other key's value read by value.
func bounded(doc string, value func(b *docread.JSON) error) error {
	b := docread.NewJSON(strings.NewReader(doc), 1<<20, 32)
	b.BoundMembers("properties", 2, func() error { return errTooMany })
	return b.Object(func(key string) error { return value(b) })
}

// A bounded key is bounded however the object under it is read: as an
// object, as a string or an object, as one string or many, or walked past.
func TestABoundedKeyIsBoundedWhereverItsObjectIsRead(t *testing.T) {
	const over = `{"properties":{"a":1,"b":2,"c":3}}`
	const within = `{"properties":{"a":1,"b":2}}`
	readers := map[string]func(b *docread.JSON) error{
		"Object": func(b *docread.JSON) error {
			return b.Object(func(string) error { return b.Skip() })
		},
		"StringOrObject": func(b *docread.JSON) error {
			_, err := b.StringOrObject(func(string) error { return b.Skip() })
			return err
		},
		"Each": func(b *docread.JSON) error {
			return b.Each(func(string) error { return nil })
		},
		"Skip": func(b *docread.JSON) error { return b.Skip() },
	}
	for name, read := range readers {
		t.Run(name, func(t *testing.T) {
			if err := bounded(over, read); !errors.Is(err, errTooMany) {
				t.Errorf("an object over the bound read by %s answered %v", name, err)
			}
			if err := bounded(within, read); err != nil {
				t.Errorf("an object within the bound read by %s answered %v", name, err)
			}
		})
	}
}

// Only the object held under the bounded key is bounded. An array under it
// holds objects that are not, however the array is read.
func TestAnObjectInsideAnArrayUnderTheBoundedKeyIsNotBounded(t *testing.T) {
	const doc = `{"properties":[{"a":1,"b":2,"c":3}]}`
	element := func(b *docread.JSON) func() error {
		return func() error { return b.Object(func(string) error { return b.Skip() }) }
	}
	readers := map[string]func(b *docread.JSON) error{
		"Array": func(b *docread.JSON) error { return b.Array(element(b)) },
		"ArrayOrNull": func(b *docread.JSON) error {
			_, err := b.ArrayOrNull(element(b))
			return err
		},
	}
	for name, read := range readers {
		t.Run(name, func(t *testing.T) {
			if err := bounded(doc, read); err != nil {
				t.Errorf("an array under the bounded key read by %s answered %v", name, err)
			}
		})
	}
}

// A document that is empty, or that stops between two tokens, is refused in
// words. The decoder reports either as a bare end of file, which reads to the
// sender as a fault of the server.
func TestADocumentCutOffBetweenTokensIsRefusedInWords(t *testing.T) {
	cases := map[string]struct{ doc, want string }{
		"empty":                 {``, "the document is empty"},
		"only whitespace":       {" \n", "the document is empty"},
		"after an opening":      {`{"items":[`, "ends partway through a value"},
		"after a comma":         {`{"items":["a",`, "ends partway through a value"},
		"after a number":        {`{"items":[1`, "ends partway through a value"},
		"after a key":           {`{"name":`, "ends partway through a value"},
		"after an object opens": {`{`, "ends partway through a value"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			b := docread.NewJSON(strings.NewReader(c.doc), 1<<20, 32)
			err := b.Object(func(string) error { return b.Skip() })
			if err == nil {
				err = b.End()
			}
			err = b.Refused("reading", err)
			if !refusal.In(err) {
				t.Fatalf("answered %v, want a refusal", err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("refused as %q, want %q", err, c.want)
			}
			if strings.Contains(err.Error(), "EOF") {
				t.Errorf("refused as %q, which names an end of file rather than saying what is wrong", err)
			}
		})
	}
}

// A refusal quotes the token it turns away, and a token is as long as the
// document lets it be. Every reader quotes a bounded head of it.
func TestARefusalQuotesAMistypedTokenBounded(t *testing.T) {
	long := strings.Repeat("7", 1<<16)
	readers := map[string]func(b *docread.JSON) error{
		"Str": func(b *docread.JSON) error {
			_, err := b.Str()
			return err
		},
		"StringOrObject": func(b *docread.JSON) error {
			_, err := b.StringOrObject(func(string) error { return b.Skip() })
			return err
		},
		"Each": func(b *docread.JSON) error {
			return b.Each(func(string) error { return nil })
		},
		"Int": func(b *docread.JSON) error {
			_, err := b.Int()
			return err
		},
		"Bool": func(b *docread.JSON) error {
			_, err := b.Bool()
			return err
		},
		"Object": func(b *docread.JSON) error {
			return b.Object(func(string) error { return b.Skip() })
		},
		"ArrayOrNull": func(b *docread.JSON) error {
			_, err := b.ArrayOrNull(func() error { return b.Skip() })
			return err
		},
	}
	for name, read := range readers {
		t.Run(name, func(t *testing.T) {
			b := docread.NewJSON(strings.NewReader(`{"v":`+long+`}`), 1<<20, 32)
			err := b.Object(func(string) error { return read(b) })
			if !refusal.In(err) {
				t.Fatalf("answered %v, want a refusal", err)
			}
			if len(err.Error()) > 4*docread.MostQuoted {
				t.Errorf("a refusal quoted %d bytes of the document", len(err.Error()))
			}
		})
	}
	t.Run("End", func(t *testing.T) {
		b := docread.NewJSON(strings.NewReader(`{} "`+long+`"`), 1<<20, 32)
		err := b.Object(func(string) error { return b.Skip() })
		if err == nil {
			err = b.End()
		}
		if !refusal.In(err) {
			t.Fatalf("answered %v, want a refusal", err)
		}
		if len(err.Error()) > 4*docread.MostQuoted {
			t.Errorf("a refusal quoted %d bytes of the document", len(err.Error()))
		}
	})
}
