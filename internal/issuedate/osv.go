// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package issuedate asks OSV when each issue was published and last
// modified, and stores the two dates (REQ-82).
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

	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/outward"
)

// DefaultOSV is OSV's API.
const DefaultOSV = "https://api.osv.dev"

// osvHost is the one host the client reaches.
const osvHost = "api.osv.dev"

// Dates is what OSV states about one issue.
type Dates struct {
	Published time.Time
	Modified  time.Time
}

// Asker answers one issue's dates by one of its names.
type Asker interface {
	Dates(ctx context.Context, name string) (Dates, error)
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

// Dates reads the record OSV holds under one name.
func (o *OSV) Dates(ctx context.Context, name string) (Dates, error) {
	if !askable.MatchString(name) {
		return Dates{}, fmt.Errorf("%w: %q", ErrUnaskable, name)
	}
	at := o.Base + "/v1/vulns/" + url.PathEscape(Spelled(name))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, at, nil)
	if err != nil {
		return Dates{}, fmt.Errorf("%w: %s: %w", ErrUnaskable, at, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := o.HTTP.Do(req)
	if err != nil {
		// A refusal by the outbound guard is the network, not the name: a
		// redirect, or the host resolving inside this network.
		return Dates{}, fmt.Errorf("%w: %s: %w", ErrNotAnswering, at, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return Dates{}, notFound(resp.Body)
	case resp.StatusCode == http.StatusBadRequest:
		return Dates{}, fmt.Errorf("%w: %s answered %s", ErrUnaskable, at, resp.Status)
	case resp.StatusCode != http.StatusOK:
		// A proxy's 403 or anything else unexpected says nothing about the
		// issue, so it stays due.
		return Dates{}, fmt.Errorf("%w: %s answered %s", ErrNotAnswering, at, resp.Status)
	}
	// A page in place of a record is a proxy or a portal answering, not OSV,
	// so the issue stays due; a record that fails to read is recorded.
	if media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil ||
		media != "application/json" {
		return Dates{}, fmt.Errorf("%w: %s answered %s, not a record", ErrNotAnswering, at,
			bound.HeadRunes(bound.Text(resp.Header.Get("Content-Type")), 100))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, mostBody+1))
	if err != nil {
		return Dates{}, fmt.Errorf("%w: %s: %w", ErrNotAnswering, at, err)
	}
	if len(body) > mostBody {
		return Dates{}, fmt.Errorf("%w: %s answered more than %d bytes", ErrUnaskable, at, mostBody)
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

// parse reads the two dates from a record. A record stating no publication
// date is no answer.
func parse(body []byte) (Dates, error) {
	var record struct {
		Published string `json:"published"`
		Modified  string `json:"modified"`
	}
	if err := json.Unmarshal(body, &record); err != nil {
		return Dates{}, fmt.Errorf("%w: %w", ErrUnaskable, err)
	}
	published, err := time.Parse(time.RFC3339Nano, record.Published)
	if err != nil {
		return Dates{}, ErrUnknown
	}
	out := Dates{Published: published.UTC()}
	if modified, err := time.Parse(time.RFC3339Nano, record.Modified); err == nil {
		out.Modified = modified.UTC()
	}
	return out, nil
}
