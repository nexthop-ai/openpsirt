// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapitest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// ScannedTwoIssues is a build whose one component carries two issues that
// look nothing alike: one exploited, high and fixable, one low with no fix and
// a driver in its description. The shape a bulk claim's outliers are read from.
func (r *Reach) ScannedTwoIssues(t *testing.T) {
	t.Helper()
	r.ScannedTwoIssuesArguing(t, "two-issues", nil)
}

// ScannedTwoIssuesArguing is the same build on a scan of its own, carrying
// what the build argues about what it ships.
func (r *Reach) ScannedTwoIssuesArguing(t *testing.T, hash string, claims []sbom.Suppression) {
	t.Helper()
	ctx := t.Context()

	names := catalog.NewStore(r.DB.DB)
	located, err := names.Locate(ctx, "mine", "master", "broadcom")
	if err != nil {
		t.Fatal(err)
	}
	target, err := names.TargetFor(ctx, located.StreamID, located.VariantID)
	if err != nil {
		t.Fatal(err)
	}
	scan, outcome, err := ingest.NewStore(r.DB.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: hash, BuiltAt: time.Now().UTC(),
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}

	product := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
	kernel := graph.Described{
		Purl: "pkg:deb/debian/linux-image@5.10", Name: "linux-image", Version: "5.10",
	}
	if _, err := graph.NewStore(r.DB.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
		Root:         product,
		Components:   []graph.Described{kernel},
		Dependencies: []graph.Dependency{{Parent: product, Child: kernel}},
	}); err != nil {
		t.Fatal(err)
	}

	findings := finding.NewStore(r.DB.DB)
	if _, err := findings.RecordClaims(ctx, target.ID, scan.ID, claims,
		map[sbom.Origin]bool{sbom.FromStatement: true, sbom.FromPedigree: true}); err != nil {
		t.Fatal(err)
	}
	run, err := findings.Begin(ctx, finding.Run{
		TargetID: target.ID, Scanner: "grype", ScannerVersion: "0.112.0",
		DatabaseVersion: "2026-08-28", RanHere: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Apply(ctx, target.ID, run.ID, []finding.Reported{
		{
			Issue: finding.Named{
				Identifier: "CVE-2026-9999", Severity: "high",
				Description: "A crafted packet writes past the end of a buffer in the netfilter connection tracker.",
				Exploited:   true, Score: 8.1,
			},
			Component: kernel, FixState: finding.FixedUpstream, FixedIn: "5.10.0-27",
		},
		{
			Issue: finding.Named{
				Identifier: "CVE-2026-1000", Severity: "low",
				Description: "Race in a joystick driver.",
				Score:       3.1,
			},
			Component: kernel, FixState: finding.NoFix,
		},
	}); err != nil {
		t.Fatal(err)
	}
}

// Claimed records one judgment about a finding through the API and returns
// the claim it made.
func (r *Reach) Claimed(t *testing.T, who, vulnerability, component, body string) (claim int64, ids []int64) {
	t.Helper()
	path := fmt.Sprintf("/v1/products/mine/streams/master/variants/broadcom"+
		"/findings/%s/components/%s/decision", vulnerability, component)
	got := AsPerson(t, r, who, http.MethodPost, path, body)
	if got.Code != http.StatusCreated {
		t.Fatalf("deciding answered %d: %s", got.Code, got.Body.String())
	}
	var out struct {
		ClaimID int64   `json:"claim_id"`
		IDs     []int64 `json:"ids"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, got.Body.String())
	}
	if out.ClaimID == 0 {
		t.Fatalf("a judgment came back without the claim it made: %s", got.Body.String())
	}
	return out.ClaimID, out.IDs
}

const Dismissal = `{"outcome":"not-applicable","justification":"vulnerable_code_not_present",` +
	`"reasoning":"The driver is not built for this image."}`

// AgreedThenLapsed claims one issue across the whole curl fold, has it agreed
// to, then moves the code under it — which is what makes a decision lapse. It
// answers with the claim whose rows are now lapsed.
func (r *Reach) AgreedThenLapsed(t *testing.T) int64 {
	t.Helper()
	ctx := t.Context()
	// One judgment over the fold: two packages, two places, one claim.
	decided := AsPerson(t, r, "triager", http.MethodPost,
		"/v1/products/mine/streams/master/variants/broadcom"+
			"/components/libcurl4t64/decisions",
		`{"vulnerabilities":["CVE-2026-CURL1"],"outcome":"not-applicable",`+
			`"justification":"vulnerable_code_cannot_be_controlled_by_adversary",`+
			`"selected_by":"the transfer path",`+
			`"reasoning":"Nothing an attacker sends reaches the transfer path."}`)
	if decided.Code != http.StatusCreated {
		t.Fatalf("deciding together answered %d: %s", decided.Code, decided.Body.String())
	}
	var made struct {
		ClaimID int64   `json:"claim_id"`
		IDs     []int64 `json:"ids"`
	}
	if err := json.Unmarshal(decided.Body.Bytes(), &made); err != nil {
		t.Fatal(err)
	}
	if len(made.IDs) != 2 {
		t.Fatalf("the claim covers %d places, want the two of the fold", len(made.IDs))
	}
	r.Agreed(t, made.ClaimID)

	// The code moves under them, which is what a lapse is.
	if _, err := r.DB.DB.NewUpdate().Table("component").
		Set("version = ?", "8.6.0-1").Set("upstream_version = ?", "8.6.0").
		Where("name LIKE ?", "%curl%").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	var targets []int64
	if err := r.DB.DB.NewSelect().TableExpr(`"target" AS "t"`).
		ColumnExpr("t.id").Scan(ctx, &targets); err != nil {
		t.Fatal(err)
	}
	store := triage.NewStore(r.DB.DB)
	for _, target := range targets {
		if _, err := store.Lapse(ctx, target); err != nil {
			t.Fatal(err)
		}
	}
	var lapsed int
	lapsed, err := r.DB.DB.NewSelect().Table("decision").
		Where("claim_id = ?", made.ClaimID).Where("state = ?", "lapsed").Count(ctx)
	if err != nil || lapsed != 2 {
		t.Fatalf("%d rows of the claim lapsed (err %v), want both", lapsed, err)
	}

	return made.ClaimID
}

// AgreedAcrossTheFold claims one issue over the curl fold with the reason
// given, has it agreed to, and answers with the claim.
func (r *Reach) AgreedAcrossTheFold(t *testing.T, issue, justification string) int64 {
	t.Helper()
	decided := AsPerson(t, r, "triager", http.MethodPost,
		"/v1/products/mine/streams/master/variants/broadcom/components/libcurl4t64/decisions",
		fmt.Sprintf(`{"vulnerabilities":[%q],"outcome":"not-applicable",`+
			`"justification":%q,"selected_by":"the transfer path",`+
			`"reasoning":"Judged at 8.4.0."}`, issue, justification))
	if decided.Code != http.StatusCreated {
		t.Fatalf("deciding answered %d: %s", decided.Code, decided.Body.String())
	}
	var made struct {
		ClaimID int64 `json:"claim_id"`
	}
	if err := json.Unmarshal(decided.Body.Bytes(), &made); err != nil {
		t.Fatal(err)
	}
	r.Agreed(t, made.ClaimID)
	return made.ClaimID
}

// Agreed has the reviewer agree to a claim.
func (r *Reach) Agreed(t *testing.T, claim int64) {
	t.Helper()
	r.AgreedBy(t, "reviewer", claim)
}

// AgreedBy is one person agreeing to a claim, failing the test where the
// approval is refused.
func (r *Reach) AgreedBy(t *testing.T, who string, claim int64) {
	t.Helper()
	if ok := AsPerson(t, r, who, http.MethodPost,
		fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); ok.Code != http.StatusOK {
		t.Fatalf("%s approving answered %d: %s", who, ok.Code, ok.Body.String())
	}
}

// CurlMovedTo moves curl to a new upstream version and sweeps every build, which
// is what lapses the decisions made about the old one.
func (r *Reach) CurlMovedTo(t *testing.T, upstream string) {
	t.Helper()
	ctx := t.Context()
	if _, err := r.DB.DB.NewUpdate().Table("component").
		Set("version = ?", upstream+"-1").Set("upstream_version = ?", upstream).
		Where("name LIKE ?", "%curl%").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	var targets []int64
	if err := r.DB.DB.NewSelect().TableExpr(`"target" AS "t"`).
		ColumnExpr("t.id").Scan(ctx, &targets); err != nil {
		t.Fatal(err)
	}
	store := triage.NewStore(r.DB.DB)
	for _, target := range targets {
		if _, err := store.Lapse(ctx, target); err != nil {
			t.Fatal(err)
		}
	}
}

// Rated records a rating of CVE-2026-CURL1 here, has the reviewer agree where it
// waits, and answers the assessment.
func (r *Reach) Rated(t *testing.T, severity string) int64 {
	t.Helper()
	made := AsPerson(t, r, "triager", http.MethodPost,
		"/v1/products/mine/issues/CVE-2026-CURL1/assessment",
		`{"severity":"`+severity+`","reasoning":"How we use it."}`)
	if made.Code != http.StatusCreated {
		t.Fatalf("rating answered %d: %s", made.Code, made.Body.String())
	}
	var claim struct {
		ID            int64 `json:"id"`
		NeedsApproval bool  `json:"needs_approval"`
	}
	if err := json.Unmarshal(made.Body.Bytes(), &claim); err != nil {
		t.Fatal(err)
	}
	if claim.NeedsApproval {
		if ok := AsPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/assessments/%d/agreement", claim.ID), ""); ok.Code >= 300 {
			t.Fatalf("agreeing to the rating answered %d: %s", ok.Code, ok.Body.String())
		}
	}
	return claim.ID
}

// StateOfClaim reads the state of one row of a claim.
func (r *Reach) StateOfClaim(t *testing.T, claim int64) string {
	t.Helper()
	var state string
	if err := r.DB.DB.NewSelect().Table("decision").Column("state").
		Where("claim_id = ?", claim).Limit(1).Scan(t.Context(), &state); err != nil {
		t.Fatal(err)
	}
	return state
}

// LimitsOf sets the two issue limits.
func (r *Reach) LimitsOf(t *testing.T, review, agreed string) {
	t.Helper()
	for key, value := range map[string]string{
		"triage.review-issues": review, "triage.agreed-issues": agreed,
	} {
		if got := AsPerson(t, r, "admin", http.MethodPut, "/v1/settings/"+key,
			`{"value":"`+value+`"}`); got.Code != http.StatusNoContent {
			t.Fatalf("setting %s answered %d: %s", key, got.Code, got.Body.String())
		}
	}
}

// TwoPlacesOf is the places one issue sits at in the seeded build.
func (r *Reach) TwoPlacesOf(t *testing.T, vulnerability string) []string {
	t.Helper()
	r.ScannedAtTwoPlaces(t)
	var found struct {
		Places []struct {
			Place string `json:"place"`
		} `json:"places"`
	}
	Read(t, r, "triager", FindingAt(vulnerability), &found)
	if len(found.Places) < 2 {
		t.Fatalf("the fixture holds this issue at %d places, so there is nothing to prove",
			len(found.Places))
	}
	out := make([]string, 0, len(found.Places))
	for _, one := range found.Places {
		out = append(out, one.Place)
	}
	return out
}

// AgreedAt records a judgment about one place and has a second person agree.
func (r *Reach) AgreedAt(t *testing.T, place, body string) {
	t.Helper()
	made := AsPerson(t, r, "triager", http.MethodPost,
		"/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/CVE-2026-9999/places/"+place+"/decision", body)
	if made.Code != http.StatusCreated {
		t.Fatalf("deciding a place answered %d: %s", made.Code, made.Body.String())
	}
	var claim struct {
		ClaimID int64 `json:"claim_id"`
	}
	if err := json.Unmarshal(made.Body.Bytes(), &claim); err != nil {
		t.Fatal(err)
	}
	r.Agreed(t, claim.ClaimID)
}

// StandsOn is what the comparison says stands about one still-present row.
func (r *Reach) StandsOn(t *testing.T, vulnerability string) (string, string) {
	t.Helper()
	var out struct {
		Still []struct {
			Vulnerability string `json:"vulnerability"`
			Outcome       string `json:"outcome"`
			Justification string `json:"justification"`
		} `json:"still_present"`
	}
	Read(t, r, "private-triage",
		"/v1/products/mine/comparison?from=master&from_variant=broadcom"+
			"&to=master&to_variant=broadcom&include_undisclosed=true", &out)
	for _, row := range out.Still {
		if row.Vulnerability == vulnerability {
			return row.Outcome, row.Justification
		}
	}
	t.Fatalf("%s is not in the comparison", vulnerability)
	return "", ""
}

// Each of these is wrong because nothing has happened, which is the
// one thing no message driven by an event can report — so each is derived by
// the sweep and each clears by the thing finally happening.

// Aged moves a claim's rows back in time, which is how a threshold measured in
// days is tested without waiting days.
func (r *Reach) Aged(t *testing.T, claim int64, column string, when time.Time) {
	t.Helper()
	if _, err := r.DB.DB.NewUpdate().Table("decision").
		Set(column+" = ?", when).
		Where("claim_id = ?", claim).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// Told is what somebody has been told, of one kind, without running the sweep.
//
// Apart from alerts because these two are events: they were written when
// somebody acted, and driving the condition pass to read them would say the
// sweep had something to do with it.
func (r *Reach) Told(t *testing.T, who, kind string) []string {
	t.Helper()
	var waiting struct {
		Items []struct {
			Kind string `json:"kind"`
			Body string `json:"body"`
		} `json:"items"`
	}
	Read(t, r, who, "/v1/notifications", &waiting)
	var about []string
	for _, one := range waiting.Items {
		if one.Kind == kind {
			about = append(about, one.Body)
		}
	}
	return about
}

// Became is what somebody's own page says happened to what they proposed.
func (r *Reach) Became(t *testing.T, who string) []becameRow {
	t.Helper()
	var out struct {
		Items []becameRow `json:"items"`
	}
	Read(t, r, who, "/v1/my-claims", &out)
	return out.Items
}

type becameRow struct {
	Claim struct {
		ID int64 `json:"id"`
	} `json:"claim"`
	Happened string `json:"happened"`
	When     string `json:"when"`
	By       string `json:"by"`
}

// AgreedTo has a second person agree to what the advisory at this path says,
// which is what an issuance asks for.
//
// private-dispatcher holds private triage on the one product and did not start
// any of these advisories, which is the pair of things agreeing asks of
// somebody.
func AgreedTo(t *testing.T, r *Reach, at string) {
	t.Helper()
	if got := AsPerson(t, r, "private-dispatcher", http.MethodPost,
		at+"/approval", ""); got.Code != http.StatusCreated {
		t.Fatalf("agreeing to the advisory at %s answered %d: %s",
			at, got.Code, got.Body.String())
	}
}

func (r *Reach) Claim(t *testing.T, summary string) string {
	t.Helper()
	got := AsPerson(t, r, "private-triage", http.MethodPost, "/v1/products/mine/reports",
		`{"summary":"`+summary+`"}`)
	if got.Code != http.StatusCreated {
		t.Fatalf("recording a claim answered %d: %s", got.Code, got.Body.String())
	}
	var recorded ReportRead
	if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
		t.Fatal(err)
	}
	return recorded.Reference
}

// Swept runs the routing sweep the way the worker does.
func (r *Reach) Swept(t *testing.T) int {
	t.Helper()
	work := queue.New(r.DB, queue.DefaultOptions())
	placed, err := finding.NewSweeper(r.DB, work,
		slog.New(slog.NewTextHandler(io.Discard, nil)), "test").Once(t.Context())
	if err != nil {
		t.Fatalf("sweeping: %v", err)
	}
	return placed
}

type caught struct {
	Components []string `json:"components"`
	Total      int      `json:"total"`
	Work       int      `json:"work"`
	Unheld     int      `json:"unheld"`
}

func (r *Reach) Preview(t *testing.T, query string) caught {
	t.Helper()
	var out caught
	Read(t, r, "triager", "/v1/products/mine/routing-rules/preview?"+query, &out)
	return out
}

// PreviewAs is the routing preview read as somebody in particular, because
// what it answers is supposed to depend on that.
func (r *Reach) PreviewAs(t *testing.T, who, query string) caught {
	t.Helper()
	var out caught
	Read(t, r, who, "/v1/products/mine/routing-rules/preview?"+query, &out)
	return out
}

// The root of the seeded build, and the two components the seeds below hang
// off it. Named once so a test reading a component by name reads the name the
// seed wrote.
var (
	SeededRoot = graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
	SeededLib  = graph.Described{
		Purl: "pkg:deb/debian/libnl-3-200@3.7.0", Name: "libnl-3-200", Version: "3.7.0",
	}
	SeededConsumer = graph.Described{
		Purl: "pkg:deb/debian/libswsscommon@1.0.0", Name: "libswsscommon", Version: "1.0.0",
	}
)

// AttackedAt records that "mine" was exploited through the scanned issue, as
// having become known at a moment, and returns the record.
func (r *Reach) AttackedAt(t *testing.T, known time.Time) int64 {
	t.Helper()
	got := AsPerson(t, r, "private-triage", http.MethodPost,
		"/v1/products/mine/issues/CVE-2026-9999/exploited-here",
		`{"known_at":"`+known.UTC().Format(time.RFC3339)+`",`+
			`"grounds":"A customer sent packet captures."}`)
	if got.Code != http.StatusCreated {
		t.Fatalf("recording answered %d: %s", got.Code, got.Body.String())
	}
	var kept struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &kept); err != nil {
		t.Fatal(err)
	}
	return kept.ID
}

// Declared adds a window as the administrator and returns its identifier.
func (r *Reach) Declared(t *testing.T, name string, hours int) int64 {
	t.Helper()
	got := AsPerson(t, r, "admin", http.MethodPost, "/v1/obligation-windows",
		fmt.Sprintf(`{"name":%q,"hours":%d}`, name, hours))
	if got.Code != http.StatusCreated {
		t.Fatalf("declaring a window answered %d: %s", got.Code, got.Body.String())
	}
	var window struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &window); err != nil {
		t.Fatal(err)
	}
	return window.ID
}

// Undisclosed makes every finding the fixture scanned undisclosed.
func (r *Reach) Undisclosed(t *testing.T) {
	t.Helper()
	if _, err := r.DB.DB.NewUpdate().Table("finding").
		Set("visibility = ?", "private").Where("1 = 1").Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// DeclaredAs adds a window as the administrator from a body of its own, and
// returns the answer.
func (r *Reach) DeclaredAs(t *testing.T, body string) int {
	t.Helper()
	return AsPerson(t, r, "admin", http.MethodPost, "/v1/obligation-windows", body).Code
}

// Embargoed records a flaw nobody has announced and returns its identifier.
func (r *Reach) Embargoed(t *testing.T) string {
	t.Helper()
	got := AsPerson(t, r, "private-triage", http.MethodPost, "/v1/products/mine/findings",
		`{"builds":[{"stream":"master","variant":"broadcom"}],`+
			`"summary":"The management socket answers before anyone has authenticated.",`+
			`"severity":"high","component":"libnl-3-200"}`)
	if got.Code != http.StatusCreated {
		t.Fatalf("recording a flaw answered %d: %s", got.Code, got.Body.String())
	}
	var recorded struct {
		Identifier string `json:"identifier"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
		t.Fatal(err)
	}
	return recorded.Identifier
}

// FindingAt is where one issue in the scanned build is read.
func FindingAt(vulnerability string) string {
	return "/v1/products/mine/streams/master/variants/broadcom/findings/" +
		vulnerability + "/components/libnl-3-200"
}

// ReportRead is what the report routes answer, as a test reads it.
type ReportRead struct {
	Reference      string `json:"reference"`
	Summary        string `json:"summary"`
	ReportedBy     string `json:"reported_by"`
	Contact        string `json:"contact"`
	Received       string `json:"received"`
	Acknowledged   string `json:"acknowledged"`
	AcknowledgedBy string `json:"acknowledged_by"`
	Issue          string `json:"issue"`
	Evaluated      string `json:"evaluated"`
	EvaluatedBy    string `json:"evaluated_by"`
	RecordedBy     string `json:"recorded_by"`
	RecordedAt     string `json:"recorded_at"`
}

// EndingIn declares a second release of the product with its own end-of-life
// date, so an ordering over more than one row means something.
//
// A second release rather than a second variant: the report is per release,
// and two variants of one are one row.
func (r *Reach) EndingIn(t *testing.T, stream string, days int) {
	t.Helper()
	made := AsPerson(t, r, "admin", http.MethodPost, "/v1/products/mine/streams",
		fmt.Sprintf(`{"name":%q,"kind":"tag","parent":"master"}`, stream))
	if made.Code != http.StatusCreated {
		t.Fatalf("declaring a release answered %d: %s", made.Code, made.Body.String())
	}
	on := time.Now().UTC().AddDate(0, 0, days).Format(time.DateOnly)
	ended := AsPerson(t, r, "admin", http.MethodPut,
		"/v1/products/mine/streams/"+stream+"/end-of-life", fmt.Sprintf(`{"on":%q}`, on))
	if ended.Code != http.StatusNoContent {
		t.Fatalf("giving it an end date answered %d: %s", ended.Code, ended.Body.String())
	}
}

// SetAside queues one job and sets it aside, answering its identifier.
func (r *Reach) SetAside(t *testing.T, kind, reference string) int64 {
	t.Helper()
	ctx := t.Context()
	job, err := queue.New(r.DB, queue.DefaultOptions()).Add(ctx, kind, reference)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.DB.NewUpdate().Model((*queue.Job)(nil)).
		Set("state = ?", queue.Dead).Set("attempts = max_attempts").
		Where("id = ?", job.ID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	return job.ID
}

// RanAgainst records a finished scanner run stating a data version.
func (r *Reach) RanAgainst(t *testing.T, version string, started time.Time) {
	t.Helper()
	ctx := t.Context()
	names := catalog.NewStore(r.DB.DB)
	located, err := names.Locate(ctx, "mine", "master", "broadcom")
	if err != nil {
		t.Fatal(err)
	}
	target, err := names.TargetFor(ctx, located.StreamID, located.VariantID)
	if err != nil {
		t.Fatal(err)
	}
	finished := started.Add(time.Minute)
	if _, err := r.DB.NewInsert().Model(&finding.Run{
		TargetID: target.ID, Scanner: "grype", DatabaseVersion: version, RanHere: true,
		StartedAt: started, FinishedAt: &finished,
	}).Exec(ctx); err != nil {
		t.Fatal(err)
	}
}

// Attached puts one file against the scanned issue and returns its token.
func (r *Reach) Attached(t *testing.T, who string) string {
	t.Helper()
	body := &bytes.Buffer{}
	form := multipart.NewWriter(body)
	part, err := form.CreateFormFile("file", "evidence.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("the request that answered before anybody signed in")); err != nil {
		t.Fatal(err)
	}
	// Hanging off the issue rather than off text somebody is part way
	// through writing, so it is listed at once and never swept.
	if err := form.WriteField("evidence", "true"); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost,
		"/v1/products/mine/issues/CVE-2026-9999/attachments", body)
	req.Header.Set("Content-Type", form.FormDataContentType())
	req.Header.Set(TestHeader, who)
	FromOurOwnPage(req)
	rec := httptest.NewRecorder()
	r.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("attaching a file answered %d: %s", rec.Code, rec.Body.String())
	}
	var stored struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Token == "" {
		t.Fatalf("attaching a file returned no token: %s", rec.Body.String())
	}
	return stored.Token
}
