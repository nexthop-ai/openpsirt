package patchbranch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DefaultQuota is how much the copies may hold where nobody has said, in
// bytes.
//
// Sized for the worst repository measured, with room beside it: the kernel's
// stable tree fetched from a host that sends whole history is the largest
// thing a report links to, and a cache that cannot hold it re-fetches it on
// every visit.
const DefaultQuota = 20 << 30

// marker is the file whose modification time says when a copy was last used.
//
// Read rather than recorded in the database, because the copies are this
// replica's disk and the database is every replica's: a second replica
// taking the work over has copies of its own, or none.
const marker = "openpsirt-used"

// partial marks a copy still being made. One found at start is what a process
// killed mid-clone left behind.
const partial = ".partial"

// copies is the directory of repository copies, and the bound on it.
type copies struct {
	root  string
	quota int64
	now   func() time.Time
	// poll is how often a copy being written is measured against the quota.
	poll time.Duration
	// gone is told the names of copies removed to make room, so what the
	// database says each copy takes stops counting them. Nil answers nothing.
	gone func(names []string)
}

// ErrTooLarge is a repository whose copy alone is larger than the cache may
// hold.
var ErrTooLarge = errors.New("the repository is larger than the cache may hold")

// dirFor is where a repository's copy lives.
//
// Named by a digest of the address. The address came out of a report, and a
// report never chooses a path on this disk (REQ-66).
func (c copies) dirFor(repository string) string {
	sum := sha256.Sum256([]byte(repository))
	return filepath.Join(c.root, hex.EncodeToString(sum[:]))
}

// has reports whether a repository's copy is on this disk.
func (c copies) has(repository string) bool {
	_, err := os.Stat(filepath.Join(c.dirFor(repository), "HEAD"))
	return err == nil
}

// prepare makes the directory and removes what an interrupted clone left.
func (c copies) prepare() error {
	if err := os.MkdirAll(c.root, 0o750); err != nil {
		return fmt.Errorf("make the directory repository copies are kept in: %w", err)
	}
	entries, err := os.ReadDir(c.root)
	if err != nil {
		return fmt.Errorf("read the directory repository copies are kept in: %w", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), partial) {
			if err := os.RemoveAll(filepath.Join(c.root, entry.Name())); err != nil {
				return fmt.Errorf("remove an interrupted copy: %w", err)
			}
		}
	}
	return nil
}

// ensure brings a repository's copy up to date, making it where there is
// none, and answers where it is.
func (c copies) ensure(ctx context.Context, g git, repository string) (string, error) {
	dir := c.dirFor(repository)
	if c.has(repository) {
		err := c.watched(ctx, dir, false, func(ctx context.Context) error {
			return g.fetch(ctx, repository, dir)
		})
		if errors.Is(err, ErrTooLarge) {
			// A copy that has outgrown the quota is not kept, whichever
			// fetch took it there.
			_ = os.RemoveAll(dir)
			c.forgotten([]string{filepath.Base(dir)})
		}
		if err != nil {
			return "", err
		}
		c.touch(dir)
		return dir, nil
	}
	if err := c.prepare(); err != nil {
		return "", err
	}
	making := dir + partial
	err := c.watched(ctx, making, true, func(ctx context.Context) error {
		return g.clone(ctx, repository, c.root, making)
	})
	if err != nil {
		_ = os.RemoveAll(making)
		return "", err
	}
	if err := os.Rename(making, dir); err != nil {
		_ = os.RemoveAll(making)
		return "", fmt.Errorf("put the new copy in place: %w", err)
	}
	c.touch(dir)
	return dir, nil
}

// watched runs write, which adds to the copy at dir, measuring the copy as it
// grows. Room is made as it grows rather than after, so the directory never
// holds much more than the quota; a copy that alone outgrows the quota is
// stopped, because it is never kept and the disk it would fill is shared with
// everything else this deployment keeps.
//
// A copy still arriving is named apart from the finished ones, so it is
// counted as arriving; one being fetched into is a finished copy, and is kept
// while others make room for it.
func (c copies) watched(ctx context.Context, dir string, arriving bool, write func(context.Context) error) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	// The watcher is stopped and waited for before this returns. A tick
	// landing after the write finished would measure a copy that has moved,
	// and remove copies beside whatever the caller does next.
	quit, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(c.poll)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-quit:
				return
			case <-ticker.C:
				grown := size(dir)
				if grown > c.quota {
					cancel(ErrTooLarge)
					return
				}
				var err error
				if arriving {
					_, err = c.evict("", grown)
				} else {
					_, err = c.evict(dir, 0)
				}
				if err != nil {
					cancel(err)
					return
				}
			}
		}
	}()
	err := write(ctx)
	close(quit)
	<-stopped
	if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) &&
		!errors.Is(cause, context.DeadlineExceeded) {
		return cause
	}
	if err == nil && size(dir) > c.quota {
		return ErrTooLarge
	}
	return err
}

// touch records that a copy was used now.
func (c copies) touch(dir string) {
	path := filepath.Join(dir, marker)
	moment := c.now()
	if err := os.Chtimes(path, moment, moment); err != nil {
		_ = os.WriteFile(path, nil, 0o600)
		_ = os.Chtimes(path, moment, moment)
	}
}

// held is one copy on disk.
type held struct {
	dir  string
	size int64
	used time.Time
}

// evict removes the least recently used copies until what is left, with
// pending bytes still arriving, fits the quota. Never the one named in keep.
// Answers what it removed.
//
// A copy is removed while nothing is reading it, because the one pass that
// reads them is the one running this.
func (c copies) evict(keep string, pending int64) ([]string, error) {
	entries, err := os.ReadDir(c.root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the directory repository copies are kept in: %w", err)
	}
	var all []held
	total := pending
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasSuffix(entry.Name(), partial) {
			continue
		}
		dir := filepath.Join(c.root, entry.Name())
		one := held{dir: dir, size: size(dir)}
		if info, err := os.Stat(filepath.Join(dir, marker)); err == nil {
			one.used = info.ModTime()
		}
		all = append(all, one)
		total += one.size
	}
	sort.Slice(all, func(i, j int) bool { return all[i].used.Before(all[j].used) })
	var removed []string
	for _, one := range all {
		if total <= c.quota {
			break
		}
		if one.dir == keep {
			continue
		}
		if err := os.RemoveAll(one.dir); err != nil {
			return removed, fmt.Errorf("remove a copy to make room: %w", err)
		}
		total -= one.size
		removed = append(removed, filepath.Base(one.dir))
	}
	c.forgotten(removed)
	return removed, nil
}

// forgotten tells whoever is listening which copies were removed.
func (c copies) forgotten(names []string) {
	if c.gone != nil && len(names) > 0 {
		c.gone(names)
	}
}

// size is how many bytes a directory holds.
func size(dir string) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.Type().IsRegular() {
			if info, err := entry.Info(); err == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total
}
