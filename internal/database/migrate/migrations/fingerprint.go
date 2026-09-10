package migrations

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sync"
)

// The sources of every migration in this package.
//
// Embedded so that a database somebody built earlier can be recognized as
// still built by these. Until the first release a schema change edits the
// migration that created the thing rather than adding one beside it, so the
// set of migration names says nothing about whether a database matches the
// schema this build expects — the version stays where it was and the tables
// are wrong. Only the content distinguishes them.
//
//go:embed *.go
var sources embed.FS

var (
	fingerprintOnce sync.Once
	fingerprint     string
	fingerprintErr  error
)

// Fingerprint identifies this migration set by what it contains.
//
// The same bytes give the same value on every machine and every run: the files
// are read in name order and hashed with their names, so adding, removing or
// editing one changes it. It is not a version — nothing orders two of these —
// and nothing about the running application depends on it. It exists for the
// test harness, which keeps a migrated database between runs and needs to know
// whether the migrations that built it are the ones in hand.
func Fingerprint() (string, error) {
	fingerprintOnce.Do(func() {
		names, err := fs.Glob(sources, "*.go")
		if err != nil {
			fingerprintErr = err
			return
		}
		// Glob answers in lexical order, which is what makes the hash the same
		// on two machines; sorting again would only hide it if that changed.
		sum := sha256.New()
		for _, name := range names {
			content, err := sources.ReadFile(name)
			if err != nil {
				fingerprintErr = fmt.Errorf("read %s: %w", name, err)
				return
			}
			_, _ = fmt.Fprintf(sum, "%s\x00%d\x00", name, len(content))
			_, _ = sum.Write(content)
		}
		fingerprint = hex.EncodeToString(sum.Sum(nil))
	})
	return fingerprint, fingerprintErr
}
