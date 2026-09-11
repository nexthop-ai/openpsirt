package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// How far a judgment reaches, asked of the two operations that answer it and
// of the one that writes across builds.

func TestReachSortsBuildsByTheVersionTheDecisionIsKeyedOn(t *testing.T) {
	// The decision is keyed on the upstream version where a component is a
	// patched fork, and on the shipped version otherwise. The reach compared
	// the raw upstream column instead, which is empty for anything that is
	// not a fork: every other build then read as differing, including one at
	// the very same version, which the decision already reached by lookup.
	// And what it named as the version was that empty column, so the
	// interface had nothing to pass when it applied the decision there — a
	// build shipping the name at four versions refused the request.
	eachReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)
		r.scannedAlso(t, "arista", "3.7.0")
		r.scannedAlso(t, "mellanox", "3.8.0")
		var reached struct {
			Automatic []struct {
				Variant string `json:"variant"`
				Version string `json:"version"`
			} `json:"automatic"`
			Differing []struct {
				Variant string `json:"variant"`
				Version string `json:"version"`
			} `json:"differing"`
		}
		read(t, r, "triager", fmt.Sprintf("/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/CVE-2026-9999/places/%s/reach", place), &reached)
		if len(reached.Automatic) != 1 || reached.Automatic[0].Variant != "arista" {
			t.Errorf("the build at the same version should be reached by lookup: %+v", reached)
		}
		if len(reached.Differing) != 1 || reached.Differing[0].Variant != "mellanox" ||
			reached.Differing[0].Version != "3.8.0" {
			t.Fatalf("the build at another version should be offered with that version: %+v", reached)
		}
		// What it named is what the route resolves a name by.
		path := "/v1/products/mine/streams/master/variants/mellanox/findings/CVE-2026-9999" +
			"/components/libnl-3-200/decision?version=" + reached.Differing[0].Version
		got := asPerson(t, r, "triager", http.MethodPost, path,
			`{"outcome":"not-applicable","justification":"vulnerable_code_not_in_execute_path",`+
				`"reasoning":"The parser is never reached there either."}`)
		if got.Code != http.StatusCreated {
			t.Errorf("applying the decision by the version the reach named answered %d: %s",
				got.Code, got.Body.String())
		}
	})
}

func TestAnOutcomeIsOfferedOnlyWhereItsEvidenceCanBeSent(t *testing.T) {
	// already-fixed carries the packager's version, which the claim is
	// refused without. The finding-level route offered the outcome in its
	// enum and had nowhere in the body to put that version, so every
	// request choosing it was refused — an outcome listed and unreachable,
	// which reads as the tool being broken rather than as the request
	// being wrong.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		const path = "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/decision"

		got := asPerson(t, r, "triager", http.MethodPost, path,
			`{"outcome":"already-fixed","fixed_version":"3.7.0-r4",`+
				`"reasoning":"Alpine backported it in r4, which is what we ship."}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("recording an already-fixed claim answered %d: %s", got.Code, got.Body.String())
		}

		// And the evidence is still required: the outcome without it is a
		// claim nobody can check.
		if got := asPerson(t, r, "triager", http.MethodPost, path,
			`{"outcome":"already-fixed","reasoning":"Trust me."}`); got.Code < 400 {
			t.Errorf("an already-fixed claim with no version answered %d", got.Code)
		}
	})
}

func TestReachingAnotherBuildCoversOnlyWhatIsLeftThere(t *testing.T) {
	// A build at the same versions is already reached by lookup, so a second
	// claim about its places is refused — and the guided review, which posts
	// to each build it applies to, has no way to know which places those are.
	// Asked to decide only what remains, the route records nothing there and
	// says so, rather than refusing.
	eachReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)
		r.scannedAlso(t, "arista", "3.7.0")
		r.decided(t, place)
		body := `{"outcome":"not-applicable","justification":"vulnerable_code_not_in_execute_path",` +
			`"reasoning":"The parser is never reached there either."`
		path := "/v1/products/mine/streams/master/variants/arista/findings/CVE-2026-9999" +
			"/components/libnl-3-200/decision?version=3.7.0"
		if got := asPerson(t, r, "triager", http.MethodPost, path, body+`}`); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("a second claim about a place already reached answered %d, want 422: %s",
				got.Code, got.Body.String())
		}
		got := asPerson(t, r, "triager", http.MethodPost, path, body+`,"remaining":true}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("deciding what remains answered %d: %s", got.Code, got.Body.String())
		}
		var out struct {
			Recorded int `json:"recorded"`
			Left     int `json:"left"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out.Recorded != 0 || out.Left != 1 {
			t.Errorf("recorded %d and left %d on a build wholly reached by lookup, want 0 and 1",
				out.Recorded, out.Left)
		}
	})
}

func TestHowFarADecisionWouldReachComesBackInThreeParts(t *testing.T) {
	// Presenting it as one number is what turns a considered judgment into a
	// reflex, and it is how a decision comes to reach builds the person making
	// it never knew about. The first two parts are consequences of the
	// matching rules and are not choices; only the third is.
	eachReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)
		var reached struct {
			Here      int `json:"here"`
			Automatic []struct {
				Stream string `json:"stream"`
			} `json:"automatic"`
			Differing []struct {
				Stream  string `json:"stream"`
				Version string `json:"version"`
			} `json:"differing"`
		}
		read(t, r, "triager", fmt.Sprintf("/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/CVE-2026-9999/places/%s/reach", place), &reached)

		if reached.Here != 1 {
			t.Errorf("the judgment covers %d places here, want 1", reached.Here)
		}
		// One build in this deployment, so nothing else to reach either way —
		// what matters is that both lists come back rather than being absent.
		if reached.Automatic == nil || reached.Differing == nil {
			t.Errorf("reach came back incomplete: %+v", reached)
		}
	})
}
