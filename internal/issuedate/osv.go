// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package issuedate asks OSV when each issue was published and last
// modified, and stores the two dates (REQ-82), with the record's links to the
// change that fixes it as the issue's patch links (REQ-78).
//
// No scanner report carries either date, and the date an issue was first seen
// here is not when it became public. The pass runs beside the scans and never
// in their path: a scan reads only what is stored (REQ-12).
//
// What leaves is an issue's public identifier, one request per name asked.
// OSV answers a record by identifier and has no lookup of several identifiers
// at once: its batch query takes packages and commits, and answers
// identifiers and modification times without publication dates.
package issuedate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/outward"
	"github.com/nexthop-ai/openpsirt/internal/patchbranch"
)

// DefaultOSV is OSV's API.
const DefaultOSV = "https://api.osv.dev"

// osvHost is the one host the client reaches.
const osvHost = "api.osv.dev"

// Record is what is read from OSV about one issue.
type Record struct {
	Published time.Time
	Modified  time.Time
	// Patches is the record's links to the change that fixes the issue: its
	// references marked as a fix, then each fixed commit of a git range as a
	// page on its repository's host.
	Patches []string
}

// Asker answers what OSV records about one issue by one of its names.
type Asker interface {
	Ask(ctx context.Context, name string) (Record, error)
}

// ErrUnknown says OSV holds no record under the name.
var ErrUnknown = errors.New("OSV holds no record under this name")

// Aliased says OSV holds no record under the name asked, and names the
// records it holds under it as an alias. It reads as ErrUnknown to a caller
// that does not follow the names.
type Aliased struct {
	Names []string
}

func (a *Aliased) Error() string {
	return "OSV holds this name as an alias of " + strings.Join(a.Names, ", ")
}

// Is makes an alias answer an unknown name to a caller that does not follow it.
func (a *Aliased) Is(target error) bool { return target == ErrUnknown }

// ErrUnaskable says the name cannot be asked about, or OSV refuses it in a way
// it repeats every time.
var ErrUnaskable = errors.New("this name cannot be asked about")

// ErrNotAnswering says OSV is unreachable or unwell, and the question is asked
// again on a later pass.
var ErrNotAnswering = errors.New("OSV is not answering")

// mostBody bounds one record. A kernel issue's record lists every affected
// branch, which runs to hundreds of kilobytes.
const mostBody = 8 << 20

// mostNotFound bounds a not-found answer, which is one short sentence.
const mostNotFound = 64 << 10

// mostAliased bounds the names one not-found answer may send the pass to.
const mostAliased = 3

// aliasesWere is the words that end OSV's not-found message where it holds the
// name as an alias of other records, which follow them, comma-separated.
const aliasesWere = "aliases were:"

// askable is the shape of an advisory identifier: letters, digits and the
// separators advisory databases use. Anything else is never sent.
var askable = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// OSV asks OSV's API.
type OSV struct {
	HTTP *http.Client
	Base string
}

// NewOSV returns a client reaching only OSV's host, following no redirect and
// connecting nowhere inside this network (REQ-69).
func NewOSV() *OSV {
	return &OSV{HTTP: outward.Guarded(osvHost), Base: DefaultOSV}
}

// Ask reads the record OSV holds under one name.
func (o *OSV) Ask(ctx context.Context, name string) (Record, error) {
	if !askable.MatchString(name) {
		return Record{}, fmt.Errorf("%w: %q", ErrUnaskable, name)
	}
	at := o.Base + "/v1/vulns/" + url.PathEscape(Spelled(name))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, at, nil)
	if err != nil {
		return Record{}, fmt.Errorf("%w: %s: %w", ErrUnaskable, at, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := o.HTTP.Do(req)
	if err != nil {
		// A refusal by the outbound guard is the network, not the name: a
		// redirect, or the host resolving inside this network.
		return Record{}, fmt.Errorf("%w: %s: %w", ErrNotAnswering, at, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return Record{}, notFound(resp.Body)
	case resp.StatusCode == http.StatusBadRequest:
		return Record{}, fmt.Errorf("%w: %s answered %s", ErrUnaskable, at, resp.Status)
	case resp.StatusCode != http.StatusOK:
		// A proxy's 403 or anything else unexpected says nothing about the
		// issue, so it stays due.
		return Record{}, fmt.Errorf("%w: %s answered %s", ErrNotAnswering, at, resp.Status)
	}
	// A page in place of a record is a proxy or a portal answering, not OSV,
	// so the issue stays due; a record that fails to read is recorded.
	if media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil ||
		media != "application/json" {
		return Record{}, fmt.Errorf("%w: %s answered %s, not a record", ErrNotAnswering, at,
			bound.HeadRunes(bound.Text(resp.Header.Get("Content-Type")), 100))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, mostBody+1))
	if err != nil {
		return Record{}, fmt.Errorf("%w: %s: %w", ErrNotAnswering, at, err)
	}
	if len(body) > mostBody {
		return Record{}, fmt.Errorf("%w: %s answered more than %d bytes", ErrUnaskable, at, mostBody)
	}
	return parse(body)
}

// Spelled is a name as OSV spells it. OSV matches identifiers exactly, and a
// name is stored here in capitals: a GitHub advisory's suffix is lower case,
// and openSUSE's prefix is mixed. Every other scheme OSV serves is written in
// capitals already.
func Spelled(name string) string {
	upper := strings.ToUpper(name)
	switch {
	case strings.HasPrefix(upper, "GHSA-"):
		return "GHSA-" + strings.ToLower(name[len("GHSA-"):])
	case strings.HasPrefix(upper, "OPENSUSE-"):
		return "openSUSE-" + name[len("OPENSUSE-"):]
	default:
		return name
	}
}

// notFound reads a not-found answer: the records OSV names where it holds the
// name as their alias, otherwise ErrUnknown.
//
// OSV answers `{"code":5,"message":"Vulnerability not found, but the following
// aliases were: CURL-CVE-2026-86409"}`, and states the names nowhere else.
// Only names shaped as identifiers are kept, at most mostAliased of them.
func notFound(body io.Reader) error {
	read, err := io.ReadAll(io.LimitReader(body, mostNotFound))
	if err != nil {
		return ErrUnknown
	}
	var answer struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(read, &answer) != nil {
		return ErrUnknown
	}
	_, listed, found := strings.Cut(answer.Message, aliasesWere)
	if !found {
		return ErrUnknown
	}
	aliased := &Aliased{}
	for _, name := range strings.Split(listed, ",") {
		name = strings.TrimSpace(name)
		if !askable.MatchString(name) {
			continue
		}
		aliased.Names = append(aliased.Names, name)
		if len(aliased.Names) == mostAliased {
			break
		}
	}
	if len(aliased.Names) == 0 {
		return ErrUnknown
	}
	return aliased
}

// mostPatches bounds the patch links taken from one record. A kernel issue's
// record names a fixed commit per maintained branch, a dozen or so.
const mostPatches = 100

// mostLink bounds one patch link's address.
const mostLink = 2048

// osvRecord is the part of an OSV record read here.
type osvRecord struct {
	Published  string `json:"published"`
	Modified   string `json:"modified"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	Affected []struct {
		Ranges []struct {
			Type   string `json:"type"`
			Repo   string `json:"repo"`
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// parse reads the two dates and the patch links from a record. A record
// stating no publication date is no answer.
func parse(body []byte) (Record, error) {
	var record osvRecord
	if err := json.Unmarshal(body, &record); err != nil {
		return Record{}, fmt.Errorf("%w: %w", ErrUnaskable, err)
	}
	published, err := time.Parse(time.RFC3339Nano, record.Published)
	if err != nil {
		return Record{}, ErrUnknown
	}
	out := Record{Published: published.UTC(), Patches: patches(record)}
	if modified, err := time.Parse(time.RFC3339Nano, record.Modified); err == nil {
		out.Modified = modified.UTC()
	}
	return out, nil
}

// patches is a record's links to the change that fixes it, without repeats
// and at most mostPatches of them.
//
// A reference marked as a fix is kept where it is a link (linkable). A git
// range's fixed commit is kept where its repository's host has a known page
// for a commit; on any other host it has none.
func patches(record osvRecord) []string {
	var out []string
	seen := map[string]bool{}
	keep := func(link string) bool {
		if !seen[link] {
			seen[link] = true
			out = append(out, link)
		}
		return len(out) < mostPatches
	}
	for _, reference := range record.References {
		if reference.Type != "FIX" || !linkable(reference.URL) {
			continue
		}
		if !keep(reference.URL) {
			return out
		}
	}
	for _, affected := range record.Affected {
		for _, span := range affected.Ranges {
			if span.Type != "GIT" {
				continue
			}
			for _, event := range span.Events {
				if event.Fixed == "" {
					continue
				}
				if link, ok := patchbranch.CommitLink(span.Repo, event.Fixed); ok && !keep(link) {
					return out
				}
			}
		}
	}
	return out
}

// linkable reports whether an address from a record may become a link: an
// absolute http or https address naming a host, with no credentials, bounded,
// and holding no space, control character or invalid UTF-8.
func linkable(address string) bool {
	if address == "" || len(address) > mostLink || !utf8.ValidString(address) ||
		strings.IndexFunc(address, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return false
	}
	parsed, err := url.Parse(address)
	return err == nil && (parsed.Scheme == "https" || parsed.Scheme == "http") &&
		parsed.Host != "" && parsed.User == nil
}
