// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	findingkind "github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/series"
)

// undisclosedSeed is the undisclosed work seedUndisclosed writes, each kind
// carrying words of its own, and the names a path is filled with.
type undisclosedSeed struct {
	// marks are the words only undisclosed work holds. A component's name is
	// not one: the inventory is read at any visibility.
	marks []string
	// fill is the values each path parameter is tried with.
	fill map[string][]string
}

// seedUndisclosed writes a disclosed finding for a public reader to read, and
// beside it: a recorded flaw with a note, a decision over it with a comment
// naming the reader, a report with a message and a note, an advisory covering
// the flaw, a file attached to it, a promise to upgrade a package whose
// findings are undisclosed, security testing work, an analyzer upload turned
// away, and a failed job's error.
func seedUndisclosed(t *testing.T, r *httpapitest.Reach) undisclosedSeed {
	t.Helper()
	ctx := t.Context()
	occurrence := r.Scanned(t)

	// The flaw, the decision over it and the comment naming the reader.
	flaw := r.Embargoed(t)
	decision, _ := r.Claimed(t, "private-triage", flaw, "libnl-3-200",
		`{"outcome":"not-applicable","justification":"vulnerable_code_not_present",`+
			`"reasoning":"Undisclosed reasoning about the socket."}`)
	if said := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
		"/v1/decisions/"+httpapitest.Itoa(decision)+"/comments",
		`{"body":"@reader Undisclosed comment about the socket."}`); said.Code >= 400 {
		t.Fatalf("commenting answered %d: %s", said.Code, said.Body.String())
	}

	if noted := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
		"/v1/products/mine/issues/"+flaw+"/notes",
		`{"body":"Undisclosed issue note about the socket."}`); noted.Code >= 400 {
		t.Fatalf("noting on the flaw answered %d: %s", noted.Code, noted.Body.String())
	}

	reference := r.Reported(t, "Undisclosed report about the socket")
	for _, said := range []struct{ path, body string }{
		{"/messages", `{"direction":"received","body":"Undisclosed message from the reporter."}`},
		{"/notes", `{"body":"Undisclosed report note about the socket."}`},
	} {
		if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/mine/reports/"+reference+said.path, said.body); got.Code >= 400 {
			t.Fatalf("writing %s on the report answered %d: %s", said.path, got.Code, got.Body.String())
		}
	}
	advisory := httpapitest.AdvisoryOver(t, r, "private-triage", "mine", flaw)

	// A promise to upgrade a package in a variant whose findings are all
	// undisclosed.
	r.SiblingsAlsoIn(t, "hidden")
	if _, err := r.DB.DB.NewUpdate().Table("finding").
		Set(`"visibility" = ?`, access.Private).
		Where(`"vulnerability_id" IN (SELECT "id" FROM "vulnerability" WHERE "identifier" LIKE ?)`, "CVE-2026-CURL%").
		Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
		"/v1/products/mine/components/libcurl4t64/upgrade",
		`{"to":"8.5.0-1","by":"`+httpapitest.AheadOfUs+`",`+
			`"reasoning":"Undisclosed upgrade reasoning.",`+
			`"builds":[{"branch_or_tag":"master","variant":"hidden"}]}`); got.Code != http.StatusCreated {
		t.Fatalf("declaring an upgrade answered %d: %s", got.Code, got.Body.String())
	}

	codeFinding := httpapitest.SeededCodeFinding(t, r)

	// A file attached to the flaw, and a team, so the routes naming either
	// are asked.
	body, kind := httpapitest.Form(t,
		httpapitest.Part{Field: "file", Filename: "socket.txt", Content: "Undisclosed attachment about the socket"},
		httpapitest.Part{Field: "evidence", Content: "true"})
	attached := r.Post(t, "private-triage", http.MethodPost, "/v1/products/mine/issues/"+flaw+"/attachments", body, kind)
	if attached.Code != http.StatusCreated {
		t.Fatalf("attaching a file answered %d: %s", attached.Code, attached.Body.String())
	}
	var file struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(attached.Body.Bytes(), &file); err != nil || file.Token == "" {
		t.Fatalf("attaching a file returned no token: %s", attached.Body.String())
	}
	if _, _, err := r.Rights.DeclareTeam(ctx, "kernel", "Kernel"); err != nil {
		t.Fatal(err)
	}

	// An analyzer upload turned away, whose reason is security testing
	// material, and a job that failed quoting its cause.
	if _, err := r.DB.DB.NewInsert().Model(&series.Refusal{
		BuildID: r.BuildOf(t, httpapitest.SeededBuild), Series: "semgrep", SeriesFolded: "semgrep",
		Kind: findingkind.Analysis, At: time.Now().UTC().Truncate(time.Second),
		Reason: "Undisclosed refusal reason about the socket",
	}).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	job := r.FailJob(t, queue.Scan, "1")
	if _, err := r.DB.DB.NewUpdate().Model((*queue.Job)(nil)).
		Set(`"last_error" = ?`, "Undisclosed job error about the socket").
		Where(`"id" = ?`, job).Exec(ctx); err != nil {
		t.Fatal(err)
	}

	numbers := seededNumbers(t, r)

	return undisclosedSeed{
		marks: []string{
			flaw, "management socket", "Undisclosed reasoning", "Undisclosed comment",
			reference, "Undisclosed report", advisory, "Undisclosed upgrade", "CVE-2026-CURL", "8.5.0-1",
			codeFinding, "Undisclosed attachment", "Undisclosed issue note", "Undisclosed message",
			"Undisclosed report note", "Undisclosed refusal reason", "Undisclosed job error",
		},
		fill: map[string][]string{
			"{product}": {"mine"}, "{branch_or_tag}": {"master"}, "{variant}": {"broadcom", "hidden"},
			"{format}": {"csv", "json"}, "{issue}": {"CVE-2026-9999", flaw, "CVE-2026-CURL1"},
			"{component}": {"libnl-3-200", "libcurl4t64"}, "{occurrence}": {occurrence, codeFinding},
			"{id}": append([]string{httpapitest.Itoa(decision)}, numbers...), "{reference}": {reference},
			"{advisory}": {advisory}, "{identity}": {"reader"}, "{token}": {file.Token}, "{team}": {"kernel"},
			"{run}": numbers, "{sbom}": numbers, "{document}": numbers, "{version}": numbers,
			"{ruling}": numbers, "{note}": numbers,
		},
	}
}

// seededNumbers is the identifiers a route taking a number is tried with: the
// first few of every table holding rows. An engine's sequences go on counting
// across the tests sharing a database, so the seeded rows are found where they
// are rather than assumed to start at one.
func seededNumbers(t *testing.T, r *httpapitest.Reach) []string {
	t.Helper()
	ctx := t.Context()
	seen := map[int64]bool{}
	for _, table := range dbtest.Tables() {
		rows, err := r.DB.QueryContext(ctx, `SELECT * FROM "`+table+`" WHERE 1 = 0`)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		_ = rows.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(columns, "id") {
			continue
		}
		var least sql.NullInt64
		if err := r.DB.QueryRowContext(ctx, `SELECT MIN("id") FROM "`+table+`"`).Scan(&least); err != nil {
			t.Fatal(err)
		}
		for n := range int64(6) {
			if least.Valid {
				seen[least.Int64+n] = true
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("no table holds a row, so no route taking a number is asked")
	}
	numbers := make([]string, 0, len(seen))
	for n := range seen {
		numbers = append(numbers, strconv.FormatInt(n, 10))
	}
	sort.Strings(numbers)
	return numbers
}

// filledEvery is a templated path with each parameter tried with each of its
// values, or nothing where a parameter has none.
func filledEvery(path string, fill map[string][]string) []string {
	paths := []string{path}
	for param, values := range fill {
		if !strings.Contains(path, param) {
			continue
		}
		var next []string
		for _, p := range paths {
			for _, value := range values {
				next = append(next, strings.ReplaceAll(p, param, value))
			}
		}
		paths = next
	}
	var out []string
	for _, p := range paths {
		if !strings.Contains(p, "{") {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func TestNothingUndisclosedReachesAPublicReader(t *testing.T) {
	// Every read path the API offers, asked by somebody who reads only
	// disclosed work in the product, over the undisclosed work seedUndisclosed
	// writes: no answer carries a word of it, a refusal included. Query parameters are left at their defaults. A read that narrows its
	// findings and joins another table without the same narrowing fails here
	// whichever route it is behind.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		seed := seedUndisclosed(t, r)
		answered, asked := 0, 0
		for _, op := range r.API.OpenAPI().Paths {
			operation := op.Get
			if operation == nil {
				continue
			}
			paths := filledEvery(operation.Path, seed.fill)
			// Every read is asked: a parameter the seed cannot fill is a read
			// this walk would pass without looking at.
			if len(paths) == 0 {
				t.Errorf("GET %s has a parameter the walk fills with nothing, so it is never asked", operation.Path)
			}
			asked++
			for _, path := range paths {
				got := r.Body(t, "reader", http.MethodGet, path)
				if got.Code == http.StatusOK {
					answered++
				}
				for _, mark := range seed.marks {
					// A path naming the mark is answered with the name it
					// asked about, as a name nothing holds is.
					if !strings.Contains(path, mark) && strings.Contains(got.Text, mark) {
						t.Errorf("GET %s answered a reader of disclosed work with %q:\n%s",
							path, mark, excerpt(got.Text, mark))
					}
				}
			}
		}
		// A walk that reached nothing looks exactly like one that found
		// nothing undisclosed.
		if asked == 0 || answered == 0 {
			t.Fatalf("%d operations were asked and %d answers came back, so this checked nothing", asked, answered)
		}
		// The reader does read the disclosed finding, so a clean walk is a
		// narrowing rather than a refusal of everything.
		var found struct {
			Total int `json:"total"`
		}
		got := r.Body(t, "reader", http.MethodGet, "/v1/products/mine/findings")
		if err := json.Unmarshal([]byte(got.Text), &found); err != nil || found.Total == 0 {
			t.Fatalf("the reader reads no disclosed finding (%d: %s), so this proves nothing", got.Code, got.Text)
		}
	})
}

// excerpt is the text around the first place a mark appears.
func excerpt(text, mark string) string {
	at := strings.Index(text, mark)
	from, to := max(0, at-200), min(len(text), at+len(mark)+200)
	return text[from:to]
}
