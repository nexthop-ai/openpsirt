// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package cverecord

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/background"
	"github.com/nexthop-ai/openpsirt/internal/outward"
)

// Where the CVE List is published. The List is a public repository that
// publishes a release every hour, each carrying an archive of every record as
// it stood at a midnight: the release tagged for midnight carries the day
// before's, and every later release that day carries the day's own.
//
// The newest release is found from where its page redirects rather than from
// the repository host's API. The API answers sixty unauthenticated requests an
// hour per address, which a deployment behind a shared address does not have
// to itself.
const (
	repository = "https://github.com/CVEProject/cvelistV5"
	// archiveSuffix names a day's archive among a release's files.
	archiveSuffix = "_all_CVEs_at_midnight.zip.zip"
)

// hosts are the only hosts the fetcher reaches: the repository host, which
// names the newest release and serves its files, and the two hosts it hands a
// download on to.
var hosts = []string{
	"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com",
}

// releaseTag is how the List tags a release: the day and the hour.
var releaseTag = regexp.MustCompile(`^cve_([0-9]{4}-[0-9]{2}-[0-9]{2})_[0-9]{4}Z$`)

// largestArchive bounds the download: 622 MB on 2026-10-07.
const largestArchive = 8 << 30

// Fetcher keeps the snapshot in a directory current with the CVE List.
type Fetcher struct {
	dir    string
	logger *slog.Logger
	// Client reaches the List. A field so a test can answer without a
	// network.
	Client *http.Client
	// Repository is where the List is published. A field for the same
	// reason.
	Repository string
}

// NewFetcher returns a fetcher keeping the snapshot in dir.
func NewFetcher(dir string, logger *slog.Logger) *Fetcher {
	return &Fetcher{
		dir: dir, logger: logger,
		Client:     outward.GuardedWithin(time.Hour, hosts...),
		Repository: repository,
	}
}

// betweenLooks is how often the fetcher asks whether a newer archive is out
// where the caller says nothing. The List publishes one archive a day, so an
// hour finds a new one within an hour of it appearing and asks the
// repository host's API twenty-four times a day.
const betweenLooks = time.Hour

// Run keeps the snapshot current until the context ends.
func (f *Fetcher) Run(ctx context.Context, interval time.Duration) {
	background.Every(ctx, interval, betweenLooks, func(ctx context.Context) {
		if _, err := f.Once(ctx); err != nil && ctx.Err() == nil {
			f.logger.Error("could not bring the CVE record snapshot up to date", "error", err)
		}
	})
}

// Once brings the snapshot up to date, and reports whether it replaced it.
func (f *Fetcher) Once(ctx context.Context) (bool, error) {
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		return false, fmt.Errorf("make the CVE record directory: %w", err)
	}
	tag, day, err := f.latest(ctx)
	if err != nil {
		return false, err
	}
	held, err := NewHeld(f.dir).Current()
	if err != nil {
		f.logger.Warn("the CVE record snapshot held cannot be read, and is fetched again", "error", err)
		held = nil
	}

	// The day's own archive, and the day before's where the release is the
	// one tagged for midnight and carries that instead.
	for _, when := range []time.Time{day, day.AddDate(0, 0, -1)} {
		name := when.Format(time.DateOnly) + archiveSuffix
		if held != nil && held.from == name {
			return false, nil
		}
		address := f.Repository + "/releases/download/" + url.PathEscape(tag) + "/" + url.PathEscape(name)
		archive, err := f.download(ctx, address)
		if errors.Is(err, errAbsent) {
			continue
		}
		if err != nil {
			return false, err
		}
		defer func() { _ = os.Remove(archive) }()
		if err := Build(archive, f.dir, name); err != nil {
			return false, err
		}
		f.logger.Info("brought the CVE record snapshot up to date", "from", name)
		return true, nil
	}
	return false, fmt.Errorf("the CVE List release %s carries no archive of every record", tag)
}

// errAbsent says a release does not carry the file asked for.
var errAbsent = errors.New("not published")

// Build reads a CVE List archive and replaces the snapshot in dir with what it
// holds. from names the archive in the snapshot, for the fetcher to compare
// against what is published next.
func Build(archive, dir, from string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("make the CVE record directory: %w", err)
	}
	records, taken, err := FromArchive(archive, dir)
	if err != nil {
		return err
	}
	if from == "" {
		from = filepath.Base(archive)
	}
	written, err := os.CreateTemp(dir, ".snapshot-*.jsonl.gz")
	if err != nil {
		return fmt.Errorf("make room for the CVE record snapshot: %w", err)
	}
	err = Write(written, taken, from, records)
	if closed := written.Close(); err == nil {
		err = closed
	}
	if err == nil {
		// Replaced by a rename, so a scan reading the snapshot sees the old
		// file or the new one and never half of either.
		err = os.Rename(written.Name(), filepath.Join(dir, FileName))
	}
	if err != nil {
		_ = os.Remove(written.Name())
		return fmt.Errorf("write the CVE record snapshot: %w", err)
	}
	return nil
}

// latest names the List's newest release, and the day its tag names.
//
// The repository host answers a request for the latest release with a
// redirect to the release's own page, and the tag is the last part of where
// it points.
func (f *Fetcher) latest(ctx context.Context) (string, time.Time, error) {
	resp, err := f.get(ctx, f.Repository+"/releases/latest")
	if err != nil {
		return "", time.Time{}, fmt.Errorf("ask which CVE List release is newest: %w", err)
	}
	resp.Body.Close()
	if !isRedirect(resp.StatusCode) {
		return "", time.Time{}, fmt.Errorf("ask which CVE List release is newest: answered %s", resp.Status)
	}
	to, err := resp.Location()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("ask which CVE List release is newest: %w", err)
	}
	tag := path.Base(to.Path)
	m := releaseTag.FindStringSubmatch(tag)
	if m == nil {
		return "", time.Time{}, fmt.Errorf("the newest CVE List release is tagged %q, which names no day", tag)
	}
	day, err := time.Parse(time.DateOnly, m[1])
	if err != nil {
		return "", time.Time{}, fmt.Errorf("the newest CVE List release is tagged %q: %w", tag, err)
	}
	return tag, day, nil
}

// agent is what the fetcher calls itself.
const agent = "openpsirt (+https://github.com/nexthop-ai/openpsirt)"

// download fetches an archive into the directory and names the file.
//
// The repository host answers a download with a redirect to the host that
// stores it. The client follows none, so the one hop is taken here, and only
// to a host this names.
func (f *Fetcher) download(ctx context.Context, address string) (string, error) {
	resp, err := f.get(ctx, address)
	for hop := 0; err == nil && hop < 3 && isRedirect(resp.StatusCode); hop++ {
		next, problem := resp.Location()
		resp.Body.Close()
		if problem != nil {
			return "", fmt.Errorf("download the CVE List archive: %w", problem)
		}
		resp, err = f.get(ctx, next.String())
	}
	if err != nil {
		return "", fmt.Errorf("download the CVE List archive: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", errAbsent
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download the CVE List archive: answered %s", resp.Status)
	}
	target, err := os.CreateTemp(f.dir, ".archive-*.zip")
	if err != nil {
		return "", fmt.Errorf("make room for the CVE List archive: %w", err)
	}
	written, err := io.Copy(target, io.LimitReader(resp.Body, largestArchive+1))
	if closed := target.Close(); err == nil {
		err = closed
	}
	if err == nil && written > largestArchive {
		err = fmt.Errorf("the CVE List archive is larger than %d bytes", int64(largestArchive))
	}
	if err != nil {
		_ = os.Remove(target.Name())
		return "", fmt.Errorf("download the CVE List archive: %w", err)
	}
	return target.Name(), nil
}

// get asks for one address, answering a redirect as a response rather than an
// error so the caller can take the hop.
func (f *Fetcher) get(ctx context.Context, address string) (*http.Response, error) {
	if _, err := url.Parse(address); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", agent)
	resp, err := f.Client.Do(req)
	if resp != nil && isRedirect(resp.StatusCode) && errors.Is(err, outward.ErrRefused) {
		return resp, nil
	}
	return resp, err
}

func isRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}
