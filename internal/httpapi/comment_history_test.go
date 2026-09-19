package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

func TestWhatACommentSaidBeforeIsKept(t *testing.T) {
	// An edit overwrote and recorded only that it happened. A comment is
	// part of the record that goes public at disclosure, so a record whose
	// earlier text is unrecoverable is readable and not checkable — which
	// is the property the whole append-only history exists for.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", dismissal)

		made := asPerson(t, r, "triager", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/comments", claim),
			`{"body":"Checked against the vendor's patch list."}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("commenting answered %d: %s", made.Code, made.Body.String())
		}
		var comment struct {
			ID int64 `json:"id"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &comment); err != nil {
			t.Fatal(err)
		}
		at := fmt.Sprintf("/v1/comments/%d", comment.ID)

		// Nothing has been replaced yet, which is an empty answer rather than
		// a missing one.
		var history struct {
			Items []struct {
				Version    int    `json:"version"`
				Body       string `json:"body"`
				ReplacedAt string `json:"replaced_at"`
			} `json:"items"`
		}
		read(t, r, "triager", at+"/history", &history)
		if len(history.Items) != 0 {
			t.Fatalf("a comment nobody edited has %d earlier versions", len(history.Items))
		}

		if got := asPerson(t, r, "triager", http.MethodPut, at,
			`{"body":"Checked against the vendor's patch list and the changelog."}`,
		); got.Code != http.StatusOK {
			t.Fatalf("editing answered %d: %s", got.Code, got.Body.String())
		}
		if got := asPerson(t, r, "triager", http.MethodPut, at,
			`{"body":"Withdrawn: I had the wrong package."}`); got.Code != http.StatusOK {
			t.Fatalf("editing again answered %d: %s", got.Code, got.Body.String())
		}

		var after struct {
			Items []struct {
				Version    int    `json:"version"`
				Body       string `json:"body"`
				ReplacedAt string `json:"replaced_at"`
			} `json:"items"`
		}
		read(t, r, "triager", at+"/history", &after)
		if len(after.Items) != 2 {
			t.Fatalf("two edits left %d earlier versions: %+v", len(after.Items), after.Items)
		}
		if after.Items[0].Version != 1 || !contains(after.Items[0].Body, "patch list.") {
			t.Errorf("the first version reads as %+v", after.Items[0])
		}
		if after.Items[1].Version != 2 || !contains(after.Items[1].Body, "changelog") {
			t.Errorf("the second version reads as %+v", after.Items[1])
		}
		if after.Items[0].ReplacedAt == "" {
			t.Error("a version does not say when it stopped saying that")
		}

		// And what it says now is the current text, not a version.
		var discussion struct {
			Items []struct {
				Body string `json:"body"`
			} `json:"items"`
		}
		read(t, r, "triager", fmt.Sprintf("/v1/claims/%d/comments", claim), &discussion)
		if len(discussion.Items) != 1 || !contains(discussion.Items[0].Body, "wrong package") {
			t.Errorf("the comment reads as %+v", discussion.Items)
		}

		// Somebody who may not read what it is about is told nothing about
		// its earlier revisions either.
		if got := asPerson(t, r, "nothing", http.MethodGet, at+"/history", ""); got.Code < 400 {
			t.Errorf("somebody who reaches nothing read a comment's history: %d", got.Code)
		}
	})
}
