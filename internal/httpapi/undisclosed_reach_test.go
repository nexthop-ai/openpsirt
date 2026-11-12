// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// undisclosedSeed is undisclosed work of every kind a secondary read reaches,
// each carrying words of its own, and the names a path is filled with.
type undisclosedSeed struct {
	// marks are the words only undisclosed work holds. A component's name is
	// not one: the inventory is read at any visibility.
	marks []string
	// fill is the values each path parameter is tried with.
	fill map[string][]string
}

// seedUndisclosed writes a disclosed finding for a public reader to read, and
// beside it: a recorded flaw, a decision over it with a comment naming the
// reader, a report, an advisory covering the flaw, a file attached to it, a
// promise to upgrade a package whose findings are undisclosed, and security
// testing work.
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

	reference := r.Reported(t, "Undisclosed report about the socket")
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

	// Identifiers the routes take as numbers are tried over the first few,
	// which is where a test database numbers what was seeded.
	numbers := []string{"1", "2", "3", "4", "5", "6"}

	return undisclosedSeed{
		marks: []string{
			flaw, "management socket", "Undisclosed reasoning", "Undisclosed comment",
			reference, "Undisclosed report", advisory, "Undisclosed upgrade", "CVE-2026-CURL", "8.5.0-1",
			codeFinding, "Undisclosed attachment",
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
	// Every read the API offers, asked by somebody who reads only disclosed
	// work in the product, over undisclosed work of every kind a secondary
	// read reaches: no answer carries a word of it. A read that narrows its
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
				if got.Code != http.StatusOK {
					continue
				}
				answered++
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
