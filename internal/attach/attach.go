// Package attach holds files that hang off an issue, and the rules about what
// may be stored and what may be served back.
//
// The bytes never live in the database. What lives here is the record of them
// — what the text refers to, what the file is, and what happened to it — and
// one interface with a store behind it.
package attach

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/bound"
)

// Attachment is one file, and the record that outlives it.
type Attachment struct {
	bun.BaseModel `bun:"table:attachment,alias:at"`

	ID int64 `bun:"id,pk,autoincrement"`
	// Token is what the text refers to and the only identifier that leaves
	// this deployment.
	Token           string `bun:"token,notnull"`
	ProductID       int64  `bun:"product_id,notnull"`
	VulnerabilityID int64  `bun:"vulnerability_id,notnull"`
	Filename        string `bun:"filename,notnull"`
	// ContentType is what we decided, never what was uploaded.
	ContentType string    `bun:"content_type,notnull"`
	SizeBytes   int64     `bun:"size_bytes,notnull"`
	Digest      string    `bun:"digest,notnull"`
	ObjectKey   string    `bun:"object_key,notnull"`
	UploadedBy  int64     `bun:"uploaded_by,notnull"`
	UploadedAt  time.Time `bun:"uploaded_at,notnull"`
	// AttachedAt is when saved text first referred to it. Null is an
	// upload nothing points at, which is what the sweep collects.
	AttachedAt *time.Time `bun:"attached_at"`
	// The tombstone: the row and the reference stay, the file goes.
	RedactedAt     *time.Time `bun:"redacted_at"`
	RedactedBy     *int64     `bun:"redacted_by"`
	RedactedReason *string    `bun:"redacted_reason"`
}

// Redacted reports whether the bytes have been removed.
func (a *Attachment) Redacted() bool { return a.RedactedAt != nil }

// Inline reports whether this is displayed in the page rather than downloaded.
//
// The answer is read off the type we chose rather than asked of the file
// again: the allowlist moves, and a file accepted under an older one has to go
// on being served the way it was accepted.
func (a *Attachment) Inline() bool { return inlineTypes[a.ContentType] }

// The types displayed in a page, and nothing else.
//
// Raster only, deliberately. A vector image is a document with a scripting
// engine in it, and serving one inline on our own origin is stored cross-site
// scripting with extra steps. Everything absent from this map downloads, which
// is the safe direction for a list nobody remembered to update.
var inlineTypes = map[string]bool{
	"image/png":  true,
	"image/jpeg": true,
	"image/gif":  true,
	"image/webp": true,
}

// Octet is what anything not on the allowlist is served as.
const Octet = "application/octet-stream"

// TypeOf decides what a file will be served as, from its bytes.
//
// What the uploader called it is not consulted at all. A browser asked to
// render text/html from our own origin runs whatever is in it, and the content
// type is the whole of what decides that — so it is ours to choose, and the
// choice is between one of a few image types and "some bytes".
func TypeOf(head []byte) string {
	sniffed := http.DetectContentType(head)
	// DetectContentType returns parameters on some types; the bare type is
	// what the allowlist is keyed on.
	if i := strings.IndexByte(sniffed, ';'); i >= 0 {
		sniffed = strings.TrimSpace(sniffed[:i])
	}
	if inlineTypes[sniffed] {
		return sniffed
	}
	return Octet
}

// SafeName is the filename as it will be given back, with everything that
// makes a name a path taken out of it.
//
// The name is never used to decide where bytes go — the object key is ours —
// so this exists only so that a disposition header cannot be made to carry a
// directory, a quote or a line break out to a browser.
func SafeName(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	name = strings.Map(func(r rune) rune {
		switch {
		case r < 0x20, r == 0x7f:
			return -1
		case r == '"', r == '\\', r == '/':
			return '_'
		}
		return r
	}, name)
	if name == "" || name == "." || name == ".." {
		return "attachment"
	}
	// Bounded so that a name cannot make a header enormous. The digits are
	// arbitrary; what matters is that there is a limit — and that the cut
	// falls between characters, because the name is stored as well as served
	// and three engines of four refuse half a character.
	return bound.Head(name, 120)
}

// Disposition is the header a file is served with.
//
// Always "attachment" for anything downloaded, and "inline" only for the
// allowlist. The filename is quoted and has already had quotes taken out of
// it, so nothing in it can end the parameter early.
func Disposition(a *Attachment) string {
	how := "attachment"
	if a.Inline() {
		how = "inline"
	}
	return fmt.Sprintf(`%s; filename="%s"`, how, SafeName(a.Filename))
}

// mintToken returns an identifier nobody can guess.
//
// Authorization is what protects a file; this is what stops the existence of
// one being discoverable by counting. 128 bits, hex, because it travels inside
// markdown people copy between screens and an encoding with case in it invites
// a store that folds it.
func mintToken() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("mint an attachment identifier: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// keyFor is where one attachment's bytes go in the store.
//
// Derived from the token and never from anything a person typed. Two levels of
// prefix because object stores and filesystems alike behave badly with a
// single directory of a hundred thousand entries.
func keyFor(token string) string {
	return "attachments/" + token[:2] + "/" + token[2:4] + "/" + token
}
