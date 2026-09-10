package httpapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// testHeader is what the fixture's proxy would set. Requests from the test
// client arrive from the address httptest uses, which the fixture trusts.
const testHeader = "X-Test-User"

// declaring is a server over an empty catalog, with an administrator to speak
// as and a way to speak as anybody else.
type declaring struct {
	handler http.Handler
	access  *access.Store
	admin   string
	// db is the same database the handler reads, for the grants an
	// administrator now has to make rather than hold by being one.
	db *database.DB
}

func (d *declaring) post(t *testing.T, path, body string) (int, map[string]any) {
	t.Helper()
	return d.postAs(t, d.admin, path, body)
}

func (d *declaring) postAs(t *testing.T, who, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	fromOurOwnPage(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(testHeader, who)
	return d.do(t, req)
}

func (d *declaring) put(t *testing.T, path, body string) (int, map[string]any) {
	t.Helper()
	return d.putAs(t, d.admin, path, body)
}

func (d *declaring) putAs(t *testing.T, who, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewBufferString(body))
	fromOurOwnPage(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(testHeader, who)
	return d.do(t, req)
}

func (d *declaring) get(t *testing.T, path string) (int, map[string]any) {
	t.Helper()
	return d.getAs(t, d.admin, path)
}

func (d *declaring) getAs(t *testing.T, who, path string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set(testHeader, who)
	return d.do(t, req)
}

func (d *declaring) do(t *testing.T, req *http.Request) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	d.handler.ServeHTTP(rec, req)
	var body map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode %s: %v (%s)", req.URL, err, rec.Body.String())
		}
	}
	return rec.Code, body
}

// The four-engine form and the two-engine form of the same fixture. Which
// one a test uses is decided by the rule at dbtest.Two: a test that pins what
// a query does — what a list contains, what a filter hides, what a conflict
// looks like, what text comes back — runs on every engine, and a test that
// pins routing, who may reach what, or the shape of a response runs on two.
func eachCatalog(t *testing.T, fn func(t *testing.T, d *declaring)) {
	t.Helper()
	catalogOn(t, dbtest.Each, fn)
}

func twoCatalog(t *testing.T, fn func(t *testing.T, d *declaring)) {
	t.Helper()
	catalogOn(t, dbtest.Two, fn)
}

func catalogOn(t *testing.T, on engines, fn func(t *testing.T, d *declaring)) {
	t.Helper()
	on(t, func(t *testing.T, db *database.DB) {
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		if err := schema.Up(t.Context(), db, quiet); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		administrator, err := rights.Ensure(t.Context(), "admin", "Administrator", true)
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.Claim(t.Context(), administrator.ID, access.ProxyProvider, "admin"); err != nil {
			t.Fatal(err)
		}
		// httptest sends from a documentation address; the fixture's proxy is
		// taken to sit there.
		sources, err := access.ParseSources("192.0.2.1")
		if err != nil {
			t.Fatal(err)
		}
		handler, _ := httpapi.New(quiet, nil, httpapi.Ingest{
			DB: db, Queue: queue.New(db, queue.DefaultOptions()),
			Access: access.NewResolver(rights, access.Trust{Header: testHeader, From: sources}),
		})
		fn(t, &declaring{handler: handler, access: rights, admin: "admin", db: db})
	})
}

func TestDeclaringTheSameThingTwiceSucceeds(t *testing.T) {
	// A pipeline declares before every build. Failing the second one makes the
	// step something everybody works around, and then a scan arrives against
	// something nobody declared.
	eachCatalog(t, func(t *testing.T, d *declaring) {
		code, body := d.post(t, "/v1/products", `{"name": "sonic", "display_name": "SONiC"}`)
		if code != http.StatusCreated {
			t.Fatalf("first declaration returned %d, want 201: %v", code, body)
		}
		if body["created"] != true {
			t.Errorf("first declaration reported created=%v", body["created"])
		}

		code, body = d.post(t, "/v1/products", `{"name": "sonic", "display_name": "SONiC"}`)
		if code != http.StatusOK {
			t.Fatalf("declaring it again returned %d, want 200: %v", code, body)
		}
		if body["created"] != false {
			t.Errorf("declaring it again reported created=%v", body["created"])
		}
	})
}

func TestRedeclaringSomethingDifferentlyIsRefused(t *testing.T) {
	// The other half of being able to declare repeatedly. A pipeline that has
	// quietly changed what it means by a name must not pass, or the name stops
	// meaning anything.
	eachCatalog(t, func(t *testing.T, d *declaring) {
		d.post(t, "/v1/products", `{"name": "sonic"}`)
		d.post(t, "/v1/products/sonic/streams", `{"name": "2.4.0", "kind": "tag"}`)

		code, body := d.post(t, "/v1/products/sonic/streams", `{"name": "2.4.0", "kind": "branch"}`)
		if code != http.StatusConflict {
			t.Fatalf("a tag redeclared as a branch returned %d, want 409", code)
		}
		if detail, _ := body["detail"].(string); detail == "" {
			t.Errorf("the refusal says nothing: %v", body)
		}
	})
}

func TestAVariantShipsUnlessItSaysOtherwise(t *testing.T) {
	// An unclassified artifact should rank as though it reaches customers, so
	// leaving the field out must not read as a denial.
	eachCatalog(t, func(t *testing.T, d *declaring) {
		d.post(t, "/v1/products", `{"name": "sonic"}`)
		d.post(t, "/v1/products/sonic/streams", `{"name": "master", "kind": "branch"}`)

		_, body := d.post(t, "/v1/products/sonic/variants", `{"name": "broadcom"}`)
		item, _ := body["item"].(map[string]any)
		if item["customer_facing"] != true {
			t.Errorf("a variant declared without saying reported %v", item["customer_facing"])
		}

		_, body = d.post(t, "/v1/products/sonic/variants",
			`{"name": "test-only", "customer_facing": false}`)
		item, _ = body["item"].(map[string]any)
		if item["customer_facing"] != false {
			t.Errorf("a variant declared as internal reported %v", item["customer_facing"])
		}
	})
}

func TestDeclaringUnderSomethingUndeclaredSaysWhichPart(t *testing.T) {
	twoCatalog(t, func(t *testing.T, d *declaring) {
		code, body := d.post(t, "/v1/products/sonic/streams", `{"name": "master", "kind": "branch"}`)
		if code != http.StatusNotFound {
			t.Fatalf("a stream under an undeclared product returned %d, want 404", code)
		}
		if detail, _ := body["detail"].(string); !bytes.Contains([]byte(detail), []byte("sonic")) {
			t.Errorf("the refusal does not name what is missing: %v", body)
		}
	})
}

func TestATagRecordsTheBranchItWasCutFrom(t *testing.T) {
	// It is what lets a branch be compared against its last release.
	eachCatalog(t, func(t *testing.T, d *declaring) {
		d.post(t, "/v1/products", `{"name": "sonic"}`)
		d.post(t, "/v1/products/sonic/streams", `{"name": "master", "kind": "branch"}`)

		code, _ := d.post(t, "/v1/products/sonic/streams",
			`{"name": "2.4.0", "kind": "tag", "parent": "master"}`)
		if code != http.StatusCreated {
			t.Fatalf("declaring a tag cut from a branch returned %d", code)
		}
		code, body := d.post(t, "/v1/products/sonic/streams",
			`{"name": "2.5.0", "kind": "tag", "parent": "nonexistent"}`)
		if code != http.StatusNotFound {
			t.Errorf("a tag cut from an undeclared branch returned %d, want 404: %v", code, body)
		}
	})
}

func TestWhatHasBeenDeclaredCanBeListed(t *testing.T) {
	// The first question after an upload is refused for naming something
	// undeclared.
	eachCatalog(t, func(t *testing.T, d *declaring) {
		d.post(t, "/v1/products", `{"name": "sonic"}`)
		d.post(t, "/v1/products", `{"name": "onie"}`)
		d.post(t, "/v1/products/sonic/streams", `{"name": "master", "kind": "branch"}`)
		d.post(t, "/v1/products/sonic/variants", `{"name": "broadcom"}`)

		_, body := d.get(t, "/v1/products")
		items, _ := body["items"].([]any)
		if len(items) != 2 {
			t.Errorf("listed %d products, want 2", len(items))
		}
		_, body = d.get(t, "/v1/products/sonic/streams")
		items, _ = body["items"].([]any)
		if len(items) != 1 {
			t.Errorf("listed %d streams, want 1", len(items))
		}
		_, body = d.get(t, "/v1/products/sonic/variants")
		items, _ = body["items"].([]any)
		if len(items) != 1 {
			t.Errorf("listed %d variants, want 1", len(items))
		}
	})
}

func TestADeclaredTargetCanBeUploadedAgainst(t *testing.T) {
	// The two halves have to meet: what declaration writes is what an upload
	// resolves. Testing them apart would let the names diverge.
	eachCatalog(t, func(t *testing.T, d *declaring) {
		d.post(t, "/v1/products", `{"name": "sonic"}`)
		d.post(t, "/v1/products/sonic/streams", `{"name": "master", "kind": "branch"}`)
		d.post(t, "/v1/products/sonic/variants", `{"name": "broadcom"}`)

		// Sent by hand rather than by a pipeline, which is triage work
		// — so the administrator who declared the product grants
		// themselves triage on it first. That is the whole of what
		// changed with an administrator stopped reading by
		// administering: declaring a product is administration and
		// filing a build against it is not, so the second one is
		// granted rather than assumed.
		d.grants(t, d.admin, "sonic", access.PublicTriage)
		req := upload(t, "/v1/products/sonic/streams/master/variants/broadcom/scans",
			inventory(nowish(), "libc6"))
		req.Header.Set(testHeader, d.admin)
		fromOurOwnPage(req)
		rec := httptest.NewRecorder()
		d.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusAccepted {
			t.Errorf("an upload against a freshly declared target returned %d: %s", rec.Code, rec.Body)
		}
	})
}

// grants gives somebody a role on a product, for the acts an administrator
// does not hold by being one.
func (d *declaring) grants(t *testing.T, identity, product string, role access.Role) {
	t.Helper()
	ctx := t.Context()
	person, err := d.access.ByIdentity(ctx, identity)
	if err != nil {
		t.Fatal(err)
	}
	named, err := catalog.NewStore(d.db.DB).ProductByName(ctx, product)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.access.GrantRole(ctx, person.ID, named.ID, role); err != nil {
		t.Fatal(err)
	}
}

// floorOf reads back what the catalog says a product triages from.
func (d *declaring) floorOf(t *testing.T, name string) (string, bool) {
	t.Helper()
	_, body := d.get(t, "/v1/products")
	items, _ := body["items"].([]any)
	for _, each := range items {
		row, _ := each.(map[string]any)
		if row["name"] != name {
			continue
		}
		word, stated := row["triage_floor"].(string)
		return word, stated
	}
	t.Fatalf("product %q is not in the catalog: %v", name, body)
	return "", false
}

func TestAProductStatesWhatItTriagesAndCanStopSayingSo(t *testing.T) {
	// the line a deployment triages at says a deployment states a line and
	// a product may state something different. The column that holds a
	// product's own has been read since it existed and written by nothing,
	// so the settings screen's "a product may state its own instead" was a
	// claim about software that could not do it.
	//
	// Clearing rather than storing the deployment's word is the part worth
	// pinning: a product that stated the deployment's current line would stop
	// following it the next time the deployment changed, and nobody would see
	// that happen.
	eachCatalog(t, func(t *testing.T, d *declaring) {
		d.post(t, "/v1/products", `{"name": "sonic"}`)
		d.post(t, "/v1/products", `{"name": "onie"}`)

		if word, stated := d.floorOf(t, "sonic"); stated {
			t.Errorf("a product nobody has set a line on reports %q", word)
		}

		code, body := d.put(t, "/v1/products/sonic/triage-floor", `{"floor": "high"}`)
		if code != http.StatusNoContent {
			t.Fatalf("stating a line returned %d, want 204: %v", code, body)
		}
		if word, stated := d.floorOf(t, "sonic"); !stated || word != "high" {
			t.Errorf("the product reports %q (stated=%v), want high", word, stated)
		}
		// And only that product.
		if word, stated := d.floorOf(t, "onie"); stated {
			t.Errorf("another product picked up the line as %q", word)
		}

		code, body = d.put(t, "/v1/products/sonic/triage-floor", `{"floor": ""}`)
		if code != http.StatusNoContent {
			t.Fatalf("clearing a line returned %d, want 204: %v", code, body)
		}
		if word, stated := d.floorOf(t, "sonic"); stated {
			t.Errorf("after clearing, the product still states %q", word)
		}
	})
}

func TestALineAProductCannotHoldIsRefused(t *testing.T) {
	// The same words the deployment's line takes, checked the same way. A
	// product that could be set to something the deployment could not would be
	// a second vocabulary for one idea, and a value nothing reads is a policy
	// that silently reverted.
	twoCatalog(t, func(t *testing.T, d *declaring) {
		d.post(t, "/v1/products", `{"name": "sonic"}`)
		code, body := d.put(t, "/v1/products/sonic/triage-floor", `{"floor": "catastrophic"}`)
		if code != http.StatusUnprocessableEntity {
			t.Fatalf("a line nobody recognizes returned %d, want 422: %v", code, body)
		}
		if detail, _ := body["detail"].(string); detail == "" {
			t.Errorf("the refusal says nothing: %v", body)
		}
		if word, stated := d.floorOf(t, "sonic"); stated {
			t.Errorf("a refused line was stored as %q", word)
		}
	})
}

func TestStatingALineOnAProductNobodyDeclaredSaysSo(t *testing.T) {
	twoCatalog(t, func(t *testing.T, d *declaring) {
		code, body := d.put(t, "/v1/products/nowhere/triage-floor", `{"floor": "high"}`)
		if code != http.StatusNotFound {
			t.Fatalf("a line on an undeclared product returned %d, want 404: %v", code, body)
		}
	})
}

// endOfLifeOf reads back what the catalog says about when something goes out
// of support.
func (d *declaring) endOfLifeOf(t *testing.T, product string) string {
	t.Helper()
	_, body := d.get(t, "/v1/products")
	items, _ := body["items"].([]any)
	for _, each := range items {
		row, _ := each.(map[string]any)
		if row["name"] == product {
			word, _ := row["end_of_life"].(string)
			return word
		}
	}
	t.Fatalf("product %q is not in the catalog: %v", product, body)
	return ""
}

// releaseEndOfLife reads back a release's date and whether it is the product's.
func (d *declaring) releaseEndOfLife(t *testing.T, product, stream string) (string, bool) {
	t.Helper()
	_, body := d.get(t, "/v1/products/"+product+"/streams")
	items, _ := body["items"].([]any)
	for _, each := range items {
		row, _ := each.(map[string]any)
		if row["name"] == stream {
			word, _ := row["end_of_life"].(string)
			inherited, _ := row["end_of_life_inherited"].(bool)
			return word, inherited
		}
	}
	t.Fatalf("release %q is not in %q: %v", stream, product, body)
	return "", false
}

func TestSomethingSaysWhenItGoesOutOfSupportAndCanTakeItBack(t *testing.T) {
	// A date rather than a flag: a date answers "what goes out of support next
	// quarter", which is a real planning question, and it takes effect on its
	// own rather than waiting for somebody to remember. Reversible, because
	// extended support happens and recreating a release to undo a date is not
	// an answer.
	eachCatalog(t, func(t *testing.T, d *declaring) {
		d.post(t, "/v1/products", `{"name": "sonic"}`)
		d.post(t, "/v1/products/sonic/streams", `{"name": "master", "kind": "branch"}`)
		d.post(t, "/v1/products/sonic/streams", `{"name": "2.4.0", "kind": "tag"}`)

		if held := d.endOfLifeOf(t, "sonic"); held != "" {
			t.Errorf("a product nobody has dated reports %q", held)
		}

		code, body := d.put(t, "/v1/products/sonic/end-of-life", `{"on": "2027-03-01"}`)
		if code != http.StatusNoContent {
			t.Fatalf("dating a product returned %d, want 204: %v", code, body)
		}
		if held := d.endOfLifeOf(t, "sonic"); held != "2027-03-01" {
			t.Errorf("the product reports %q, want 2027-03-01", held)
		}
		// Every release follows it, and says that it is following rather than
		// stating one of its own.
		for _, stream := range []string{"master", "2.4.0"} {
			held, inherited := d.releaseEndOfLife(t, "sonic", stream)
			if held != "2027-03-01" || !inherited {
				t.Errorf("%s reports %q (inherited=%v), want the product's date", stream, held, inherited)
			}
		}

		// One release says something else.
		code, body = d.put(t, "/v1/products/sonic/streams/2.4.0/end-of-life", `{"on": "2027-06-01"}`)
		if code != http.StatusNoContent {
			t.Fatalf("dating a release returned %d, want 204: %v", code, body)
		}
		if held, inherited := d.releaseEndOfLife(t, "sonic", "2.4.0"); held != "2027-06-01" || inherited {
			t.Errorf("the release reports %q (inherited=%v), want its own June date", held, inherited)
		}
		if held, inherited := d.releaseEndOfLife(t, "sonic", "master"); held != "2027-03-01" || !inherited {
			t.Errorf("another release picked up %q (inherited=%v)", held, inherited)
		}

		// And both are reversible.
		if code, _ := d.put(t, "/v1/products/sonic/streams/2.4.0/end-of-life", `{"on": ""}`); code != http.StatusNoContent {
			t.Fatalf("clearing a release's date returned %d", code)
		}
		if held, inherited := d.releaseEndOfLife(t, "sonic", "2.4.0"); held != "2027-03-01" || !inherited {
			t.Errorf("after clearing, the release reports %q (inherited=%v), want the product's", held, inherited)
		}
		if code, _ := d.put(t, "/v1/products/sonic/end-of-life", `{"on": ""}`); code != http.StatusNoContent {
			t.Fatalf("clearing a product's date returned %d", code)
		}
		if held := d.endOfLifeOf(t, "sonic"); held != "" {
			t.Errorf("after clearing, the product reports %q", held)
		}
	})
}

func TestADateNobodyCanReadIsRefused(t *testing.T) {
	// A value nothing can parse would be stored and then silently ignored,
	// which is a policy that quietly stopped applying.
	twoCatalog(t, func(t *testing.T, d *declaring) {
		d.post(t, "/v1/products", `{"name": "sonic"}`)
		code, body := d.put(t, "/v1/products/sonic/end-of-life", `{"on": "next March"}`)
		if code != http.StatusUnprocessableEntity {
			t.Fatalf("a date nobody can read returned %d, want 422: %v", code, body)
		}
		if held := d.endOfLifeOf(t, "sonic"); held != "" {
			t.Errorf("a refused date was stored as %q", held)
		}
	})
}

func TestTheStreamsListSaysWhatEachTagWasCutFrom(t *testing.T) {
	// The screen has had a "Cut from" column all along and this list never
	// resolved the parent, so it was empty whatever the data said — which
	// reads as "none of these was cut from anything". Release readiness
	// compares a branch against the last release cut from it, so the one
	// column that shows whether that will work showed nothing.
	eachCatalog(t, func(t *testing.T, d *declaring) {
		d.post(t, "/v1/products", `{"name":"sonic"}`)
		d.post(t, "/v1/products/sonic/streams", `{"name":"master","kind":"branch"}`)
		d.post(t, "/v1/products/sonic/streams", `{"name":"v1.0","kind":"tag","parent":"master"}`)
		d.post(t, "/v1/products/sonic/streams", `{"name":"orphan","kind":"tag"}`)

		_, body := d.get(t, "/v1/products/sonic/streams")
		items, _ := body["items"].([]any)
		cutFrom := map[string]string{}
		for _, each := range items {
			row, _ := each.(map[string]any)
			name, _ := row["name"].(string)
			parent, _ := row["parent"].(string)
			cutFrom[name] = parent
		}
		if cutFrom["v1.0"] != "master" {
			t.Errorf("v1.0 reads as cut from %q, want master", cutFrom["v1.0"])
		}
		// One that genuinely was not says so, rather than every row saying the
		// same thing whichever it is.
		if cutFrom["orphan"] != "" {
			t.Errorf("a tag cut from nothing reads as cut from %q", cutFrom["orphan"])
		}
		if cutFrom["master"] != "" {
			t.Errorf("a branch reads as cut from %q", cutFrom["master"])
		}
	})
}

func TestWhenAReleaseWentOutIsSaidAfterTheFact(t *testing.T) {
	// A tag is declared here so scans can be filed against it, which happens
	// whenever somebody gets to it — before the release, months after, or
	// while backfilling a year. Fixed at declaration, the release-over-release
	// chart is an accident of administration: a release recorded late orders
	// after ones that came out before it.
	twoReach(t, func(t *testing.T, r *reach) {
		if made := asPerson(t, r, "admin", http.MethodPost, "/v1/products/mine/streams",
			`{"name":"v2.0","kind":"tag"}`); made.Code >= 300 {
			t.Fatalf("declaring the tag answered %d: %s", made.Code, made.Body.String())
		}
		const at = "/v1/products/mine/streams/v2.0/release"

		// Cut from itself, and cut from another tag: both are refused rather
		// than stored, because one is a comparison that never returns and the
		// other is a line that does not exist.
		if got := asPerson(t, r, "admin", http.MethodPut, at,
			`{"released_on":"2026-03-31","cut_from":"v2.0"}`); got.Code < 400 {
			t.Errorf("a release cut from itself answered %d", got.Code)
		}
		if made := asPerson(t, r, "admin", http.MethodPost, "/v1/products/mine/streams",
			`{"name":"v1.9","kind":"tag"}`); made.Code >= 300 {
			t.Fatalf("declaring a second tag answered %d: %s", made.Code, made.Body.String())
		}
		if got := asPerson(t, r, "admin", http.MethodPut, at,
			`{"released_on":"2026-03-31","cut_from":"v1.9"}`); got.Code < 400 {
			t.Errorf("a release cut from another tag answered %d", got.Code)
		}

		if got := asPerson(t, r, "admin", http.MethodPut, at,
			`{"released_on":"2026-03-31","cut_from":"master"}`); got.Code >= 300 {
			t.Fatalf("recording the release answered %d: %s", got.Code, got.Body.String())
		}
		var streams struct {
			Items []struct {
				Name       string `json:"name"`
				Parent     string `json:"parent"`
				ReleasedOn string `json:"released_on"`
			} `json:"items"`
		}
		read(t, r, "admin", "/v1/products/mine/streams", &streams)
		var one struct {
			Name       string `json:"name"`
			Parent     string `json:"parent"`
			ReleasedOn string `json:"released_on"`
		}
		for _, row := range streams.Items {
			if row.Name == "v2.0" {
				one = row
			}
		}
		if one.ReleasedOn != "2026-03-31" || one.Parent != "master" {
			t.Errorf("the release reads as %+v", one)
		}

		// The parent fills in and never changes: a tag is one frozen
		// point and it came from wherever it came from. Saying the
		// same one again is not a change and is accepted.
		if got := asPerson(t, r, "admin", http.MethodPut, at,
			`{"released_on":"2026-03-31","cut_from":"master"}`); got.Code >= 300 {
			t.Errorf("saying the same parent again answered %d", got.Code)
		}
		if made := asPerson(t, r, "admin", http.MethodPost, "/v1/products/mine/streams",
			`{"name":"other","kind":"branch"}`); made.Code >= 300 {
			t.Fatalf("declaring a second branch answered %d: %s", made.Code, made.Body.String())
		}
		if got := asPerson(t, r, "admin", http.MethodPut, at,
			`{"released_on":"2026-03-31","cut_from":"other"}`); got.Code < 400 {
			t.Errorf("a release was re-cut from a different branch: %d", got.Code)
		}

		// The date clears, and the day it was declared here stands in again.
		// The parent does not: an empty one leaves whatever stands alone.
		if got := asPerson(t, r, "admin", http.MethodPut, at,
			`{"released_on":"","cut_from":""}`); got.Code >= 300 {
			t.Fatalf("clearing answered %d: %s", got.Code, got.Body.String())
		}
		// A fresh value rather than the one above: decoding an object into a
		// struct that already has fields set leaves absent fields alone, and
		// both of these are absent once cleared — so reusing it would have
		// read back what was there before and called it what is there now.
		var after struct {
			Items []struct {
				Name       string `json:"name"`
				Parent     string `json:"parent"`
				ReleasedOn string `json:"released_on"`
			} `json:"items"`
		}
		read(t, r, "admin", "/v1/products/mine/streams", &after)
		for _, row := range after.Items {
			if row.Name != "v2.0" {
				continue
			}
			if row.ReleasedOn != "" {
				t.Errorf("clearing the date left %+v", row)
			}
			if row.Parent != "master" {
				t.Errorf("an empty parent moved it: %+v", row)
			}
		}

		// Administration, like every other catalog change.
		if got := asPerson(t, r, "triager", http.MethodPut, at,
			`{"released_on":"2026-03-31"}`); got.Code < 400 {
			t.Errorf("somebody who does not administer set a release date: %d", got.Code)
		}
	})
}
