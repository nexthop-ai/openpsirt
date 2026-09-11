package attach

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"
)

// Files keeps bytes on this machine, which is what makes the tool runnable
// without standing an object store up first.
//
// **It is the development and test backend and never a production one**, the
// same way SQLite is for the database: one process, one disk, no replication
// and no signing authority of its own. Two replicas would disagree about what
// exists.
//
// **Everything goes through an os.Root**, so a name cannot reach outside the
// directory even if a caller one day passes one that tries. The keys are ours
// and contain nothing a person typed, so nothing can reach that today — which
// is a property of the callers rather than of this type, and confinement that
// depends on every caller staying careful is the kind that stops holding.
type Files struct {
	root *os.Root
}

// NewFiles returns a store under root, or nil where none is configured.
func NewFiles(dir string) (*Files, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("attachment directory: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("attachment directory: %w", err)
	}
	return &Files{root: root}, nil
}

// Name is the kind of store rather than the directory it came up on. The
// interface says it is "what this store is called in a log line and in the
// readiness answer", which is a question about which backend is configured —
// and the directory was kept on the struct for it and never read.
func (f *Files) Name() string { return "files" }

func (f *Files) Put(ctx context.Context, key string, body io.Reader, size int64, _ string) error {
	if err := f.root.MkdirAll(path.Dir(key), 0o700); err != nil {
		return fmt.Errorf("store a file: %w", err)
	}
	// Written beside and renamed, so a failure part way through leaves nothing
	// a later read could mistake for a whole file.
	partial := key + ".partial"
	file, err := f.root.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("store a file: %w", err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = f.root.Remove(partial)
		}
	}()

	written, err := io.Copy(file, io.LimitReader(body, size))
	if err != nil {
		return fmt.Errorf("store a file: %w", err)
	}
	if written != size {
		return fmt.Errorf("store a file: %d bytes arrived of %d", written, size)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("store a file: %w", err)
	}
	if err := f.root.Rename(partial, key); err != nil {
		return fmt.Errorf("store a file: %w", err)
	}
	remove = false
	return nil
}

func (f *Files) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	file, err := f.root.Open(key)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoSuchObject
	}
	if err != nil {
		return nil, fmt.Errorf("read a file: %w", err)
	}
	return file, nil
}

func (f *Files) Delete(ctx context.Context, key string) error {
	if err := f.root.Remove(key); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove a file: %w", err)
	}
	return nil
}

// URLFor is empty, always: this store has no signing authority, so the
// application serves what it holds (inline images served here, and the note on
// Storage.URLFor).
func (f *Files) URLFor(context.Context, string, time.Duration, string, string) (string, error) {
	return "", nil
}

func (f *Files) Reachable(context.Context) error {
	// Writable, not merely present: a directory that exists and refuses writes
	// is the failure this check is for, and it is invisible from a stat.
	const probe = ".probe"
	file, err := f.root.OpenFile(probe, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("write to the attachment directory: %w", err)
	}
	if err := file.Close(); err != nil {
		return err
	}
	return f.root.Remove(probe)
}

// Close releases the directory handle.
func (f *Files) Close() error { return f.root.Close() }
