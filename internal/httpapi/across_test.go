package httpapi_test

import (
	"net/http"
	"testing"
)

// listedRow is what the findings list says about one issue in one component,
// including the three fields that only appear once the selection is wider
// than a build.
type listedRow struct {
	Vulnerability string `json:"vulnerability"`
	Component     string `json:"component"`
	Places        int    `json:"places"`
	Builds        int    `json:"builds"`
	Stream        string `json:"stream"`
	Variant       string `json:"variant"`
	Owner         string `json:"owner"`
	Parent        string `json:"parent"`
	Chains        int    `json:"chains"`
}

type listed struct {
	Items []listedRow `json:"items"`
	Total int         `json:"total"`
}

func TestTheFindingsListAnswersForEveryBuildWithTheBranchAndVariantLeftOut(t *testing.T) {
	// The same issue in the same component in two variants is one piece of
	// work, and while the list was a build's there was nowhere it could be
	// read as one.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		r.scannedAlso(t, "mellanox", "3.7.0")

		var oneBuild listed
		read(t, r, "triager", "/v1/products/mine/findings?stream=master&variant=broadcom",
			&oneBuild)
		if oneBuild.Total != 1 || len(oneBuild.Items) != 1 {
			t.Fatalf("one build lists %d rows of %d, want one", len(oneBuild.Items), oneBuild.Total)
		}
		if row := oneBuild.Items[0]; row.Places != 1 || row.Builds != 0 {
			t.Errorf("a build's own row counts %d places and names %d builds,"+
				" want its own place and no build count: %+v", row.Places, row.Builds, row)
		}
		if row := oneBuild.Items[0]; row.Parent == "" {
			t.Errorf("a build's own row lost its way down: %+v", row)
		}

		var whole listed
		read(t, r, "triager", "/v1/products/mine/findings", &whole)
		if whole.Total != 1 || len(whole.Items) != 1 {
			t.Fatalf("the product lists %d rows of %d, want the two builds collapsed to one",
				len(whole.Items), whole.Total)
		}
		row := whole.Items[0]
		if row.Places != 2 || row.Builds != 2 {
			t.Errorf("the row counts %d places in %d builds, want one place in each of two: %+v",
				row.Places, row.Builds, row)
		}
		if row.Stream == "" || row.Variant == "" {
			t.Errorf("the row names no build to link to: %+v", row)
		}
		// The two builds reach the same component different ways, so no way
		// down is drawn rather than one of them being shown as the answer.
		if row.Owner != "" || row.Parent != "" || row.Chains != 0 {
			t.Errorf("a row spanning builds drew a way down: %+v", row)
		}
	})
}

func TestNarrowingBeneathAComponentNeedsOneBuildToWalk(t *testing.T) {
	// A subtree is a walk over one build's edges. Asked of a selection holding
	// several it is refused as the caller's to fix, not answered emptily —
	// which is what a subtree with nothing open in it also looks like.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		r.scannedAlso(t, "mellanox", "3.7.0")

		got := asPerson(t, r, "triager", http.MethodGet,
			"/v1/products/mine/findings?beneath=libswsscommon", "")
		if got.Code != http.StatusUnprocessableEntity {
			t.Errorf("a subtree across every build answered %d, want it named as the caller's"+
				" to fix: %s", got.Code, got.Body.String())
		}
		got = asPerson(t, r, "triager", http.MethodGet,
			"/v1/products/mine/findings?stream=master&variant=broadcom&beneath=libswsscommon", "")
		if got.Code != http.StatusOK {
			t.Errorf("a subtree in one build answered %d: %s", got.Code, got.Body.String())
		}
	})
}
