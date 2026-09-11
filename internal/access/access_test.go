package access_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// fixture is a migrated database with two products, so that holding something
// on one says nothing about the other.
type fixture struct {
	store    *access.Store
	products map[string]int64
	streams  map[string]int64
	variants map[string]int64
}

func each(t *testing.T, fn func(t *testing.T, f *fixture)) {
	t.Helper()
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		if err := schema.Up(ctx, db, quiet); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		dbtest.Reset(t, db)

		cat := catalog.NewStore(db.DB)
		f := &fixture{
			store:    access.NewStore(db.DB),
			products: map[string]int64{}, streams: map[string]int64{}, variants: map[string]int64{},
		}
		for _, name := range []string{"sonic", "onie"} {
			product, err := cat.DeclareProduct(ctx, name, name)
			if err != nil {
				t.Fatal(err)
			}
			f.products[name] = product.ID
			stream, err := cat.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil)
			if err != nil {
				t.Fatal(err)
			}
			f.streams[name] = stream.ID
			variant, err := cat.DeclareVariant(ctx, product.ID, "broadcom", true)
			if err != nil {
				t.Fatal(err)
			}
			f.variants[name] = variant.ID
		}
		fn(t, f)
	})
}

func TestSomebodyUnknownAndSomebodyUngrantedGetTheSameAnswer(t *testing.T) {
	// Telling an outsider which of the two applies is free reconnaissance:
	// one answer says the name is wrong, the other says the name is right.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if _, err := f.store.Ensure(ctx, "known", "Known Person", false); err != nil {
			t.Fatal(err)
		}

		_, unknownErr := f.store.Resolve(ctx, "nobody")
		_, ungrantedErr := f.store.Resolve(ctx, "known")

		if !errors.Is(unknownErr, access.ErrDenied) || !errors.Is(ungrantedErr, access.ErrDenied) {
			t.Fatalf("unknown: %v; granted nothing: %v", unknownErr, ungrantedErr)
		}
		if unknownErr.Error() != ungrantedErr.Error() {
			t.Errorf("the two are distinguishable: %q and %q", unknownErr, ungrantedErr)
		}
	})
}

func TestAuthenticatingCreatesNobody(t *testing.T) {
	// Authenticating proves who somebody is and says nothing about whether
	// they should be here. The first person to arrive gains nothing by being
	// first.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if _, err := f.store.Resolve(ctx, "first-to-arrive"); !errors.Is(err, access.ErrDenied) {
			t.Fatalf("resolving an unknown identity: %v", err)
		}
		if _, err := f.store.ByIdentity(ctx, "first-to-arrive"); err == nil {
			t.Error("signing in created an account")
		}
	})
}

func TestARoleOnOneProductSaysNothingAboutAnother(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, err := f.store.Ensure(ctx, "reader", "", false)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.GrantRole(ctx, person.ID, f.products["sonic"], access.PublicRead); err != nil {
			t.Fatal(err)
		}

		subject, err := f.store.Resolve(ctx, "reader")
		if err != nil {
			t.Fatal(err)
		}
		if !subject.Reads(access.Public, f.products["sonic"]) {
			t.Error("a public reader cannot read the product they were granted")
		}
		if subject.Reads(access.Public, f.products["onie"]) {
			t.Error("a grant on one product reached another")
		}
		// A product held nothing on is invisible, not merely unreadable.
		if subject.Sees(f.products["onie"]) {
			t.Error("a product held nothing on is visible")
		}
		if !subject.Sees(f.products["sonic"]) {
			t.Error("a product held something on is invisible")
		}
	})
}

func TestReadingPublicIsNotReadingPrivate(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, _ := f.store.Ensure(ctx, "public-only", "", false)
		if err := f.store.GrantRole(ctx, person.ID, f.products["sonic"], access.PublicRead); err != nil {
			t.Fatal(err)
		}
		subject, err := f.store.Resolve(ctx, "public-only")
		if err != nil {
			t.Fatal(err)
		}
		if subject.Reads(access.Private, f.products["sonic"]) {
			t.Error("a public reader reached something undisclosed")
		}
	})
}

func TestACapabilityHandsOverNoVisibility(t *testing.T) {
	// Approving and assigning are things somebody may do, bounded by what they
	// may read. Otherwise granting the ability to approve would quietly grant
	// everything there is to approve.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, _ := f.store.Ensure(ctx, "approver", "", false)
		for _, role := range []access.Role{access.Approver, access.Assigner} {
			if err := f.store.GrantRole(ctx, person.ID, f.products["sonic"], role); err != nil {
				t.Fatal(err)
			}
		}
		subject, err := f.store.Resolve(ctx, "approver")
		if err != nil {
			t.Fatal(err)
		}
		if subject.Reads(access.Public, f.products["sonic"]) || subject.Reads(access.Private, f.products["sonic"]) {
			t.Error("a capability granted visibility on its own")
		}
		if !subject.Holds(access.Approver, f.products["sonic"]) {
			t.Error("the capability itself was not granted")
		}
	})
}

func TestAReportingRoleCannotBeGranted(t *testing.T) {
	// It was in the baseline set and gated nothing, which is the shape a
	// capability granting nothing always has: the person is recorded, the
	// grant is in force, and it changes no answer anywhere. What it was
	// reaching for is breadth of view, and that is said directly now.
	//
	// Pinned as a refusal rather than as an absence from a list, because
	// the list is what a caller reads and the refusal is what a caller
	// hits.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, _ := f.store.Ensure(ctx, "auditor", "", false)
		if err := f.store.GrantRole(ctx, person.ID, f.products["sonic"], access.Role("reporting")); err == nil {
			t.Error("a retired role was granted")
		}
		for _, role := range access.Roles() {
			if role == "reporting" {
				t.Error("a retired role is still in the baseline set")
			}
		}
	})
}

func TestAnAdministratorAdministersRatherThanHoldingEveryRole(t *testing.T) {
	// It read the other way and nothing said so: an administrator held
	// every role on every product, so one account proposed and approved
	// its own work, re-rated severities and read every embargo. That
	// defeats separation of duties silently, and it made a read-only
	// auditor impossible — nobody could see everything without also being
	// able to change everything.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if _, err := f.store.Ensure(ctx, "admin", "", true); err != nil {
			t.Fatal(err)
		}
		subject, err := f.store.Resolve(ctx, "admin")
		if err != nil {
			t.Fatal(err)
		}

		for _, product := range f.products {
			// Administering the catalog is knowing a product exists.
			if !subject.Sees(product) {
				t.Error("an administrator cannot see a product they administer")
			}
			// Reading what is open against it is not.
			if subject.Reads(access.Public, product) || subject.Reads(access.Private, product) {
				t.Error("an administrator reads findings they were never granted")
			}
			for _, role := range []access.Role{
				access.PublicTriage, access.PrivateTriage, access.Approver, access.Assigner,
			} {
				if subject.Holds(role, product) {
					t.Errorf("an administrator holds %s without being granted it", role)
				}
			}
		}
		if subject.HoldsAnywhere(access.PublicTriage, access.PrivateTriage) {
			t.Error("an administrator triages somewhere without being granted it")
		}

		// The catalog and the findings are answered by different questions.
		if _, all := subject.Knows(); !all {
			t.Error("an administrator is not told which products exist")
		}
		if ids, all := subject.Products(); all || len(ids) != 0 {
			t.Errorf("an administrator reads findings in %v (all=%v), want none", ids, all)
		}

		// And granting themselves a role works like anybody else's, which is
		// what makes the grant visible in the same record.
		sonic := f.products["sonic"]
		if err := f.store.GrantRole(ctx, mustID(t, f, "admin"), sonic, access.PublicRead); err != nil {
			t.Fatal(err)
		}
		granted, err := f.store.Resolve(ctx, "admin")
		if err != nil {
			t.Fatal(err)
		}
		if !granted.Reads(access.Public, sonic) {
			t.Error("an administrator who granted themselves reading still cannot read")
		}
		if granted.Reads(access.Private, sonic) {
			t.Error("public reading reached undisclosed work")
		}
	})
}

// mustID is the account identifier for somebody already recorded.
func mustID(t *testing.T, f *fixture, identity string) int64 {
	t.Helper()
	person, err := f.store.ByIdentity(t.Context(), identity)
	if err != nil {
		t.Fatal(err)
	}
	return person.ID
}

func TestAKeyMaySendAndNothingElse(t *testing.T) {
	// A build server has no business holding a person's permissions, which is
	// also what keeps the visibility rules out of its reach entirely.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		_, secret, err := f.store.NewKey(ctx, "nightly", access.Scope{ProductID: f.products["sonic"]})
		if err != nil {
			t.Fatal(err)
		}
		subject, err := f.store.ResolveKey(ctx, secret)
		if err != nil {
			t.Fatal(err)
		}
		if !subject.MaySend(f.products["sonic"], f.streams["sonic"], f.variants["sonic"]) {
			t.Error("a key cannot send against the product it is scoped to")
		}
		if subject.Reads(access.Public, f.products["sonic"]) ||
			subject.Reads(access.Private, f.products["sonic"]) {
			t.Error("a pipeline can read")
		}
		if subject.Holds(access.PublicRead, f.products["sonic"]) {
			t.Error("a pipeline holds a role")
		}
		// It does know the product it may send to exists, because it may send
		// there. Pretending otherwise would mean an upload to its own product
		// could not be told apart from one to a product that is not there,
		// and the sender needs that difference to fix a misconfigured
		// pipeline.
		if !subject.Sees(f.products["sonic"]) {
			t.Error("a pipeline cannot see the product it sends to")
		}
		if subject.Sees(f.products["onie"]) {
			t.Error("a pipeline can see a product it holds nothing for")
		}
		if ids, all := subject.Products(); all || len(ids) != 0 {
			t.Error("a pipeline appears in the list of what somebody may reach")
		}
	})
}

func TestAKeyIsRefusedWhereItsConstraintsDoNotMatch(t *testing.T) {
	// Every constraint present must match, and a mismatch is refused rather
	// than redirected: a key pinned to one release must not quietly accept a
	// scan of another.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		stream := f.streams["sonic"]
		_, secret, err := f.store.NewKey(ctx, "pinned", access.Scope{
			ProductID: f.products["sonic"], StreamID: &stream,
		})
		if err != nil {
			t.Fatal(err)
		}
		subject, err := f.store.ResolveKey(ctx, secret)
		if err != nil {
			t.Fatal(err)
		}
		if !subject.MaySend(f.products["sonic"], stream, f.variants["sonic"]) {
			t.Error("a pinned key was refused its own release")
		}
		if subject.MaySend(f.products["sonic"], f.streams["onie"], f.variants["sonic"]) {
			t.Error("a key pinned to one release accepted another")
		}
		if subject.MaySend(f.products["onie"], f.streams["onie"], f.variants["onie"]) {
			t.Error("a key reached another product entirely")
		}
	})
}

func TestASecretIsNeverStoredAndARevokedKeyStopsWorking(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		key, secret, err := f.store.NewKey(ctx, "nightly", access.Scope{ProductID: f.products["sonic"]})
		if err != nil {
			t.Fatal(err)
		}
		if key.SecretHash == secret || key.SecretHash == "" {
			t.Error("the secret is recoverable from what is stored")
		}
		if _, err := f.store.ResolveKey(ctx, secret+"x"); !errors.Is(err, access.ErrDenied) {
			t.Errorf("a wrong secret: %v", err)
		}

		if err := f.store.Revoke(ctx, key.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.ResolveKey(ctx, secret); !errors.Is(err, access.ErrDenied) {
			t.Errorf("a revoked key still works: %v", err)
		}
	})
}

func TestAQueryWithNobodyAttachedIsAFault(t *testing.T) {
	// Not a denial: it means a query was written that does not say who is
	// asking, and treating that as "show nothing" hides it until somebody
	// writes the one that treats it as "show everything".
	if _, err := access.From(context.Background()); !errors.Is(err, access.ErrNoSubject) {
		t.Errorf("a context with no subject gave %v", err)
	}
	ctx := access.With(context.Background(), access.NewPerson(1, "someone", true, nil, 0))
	if _, err := access.From(ctx); err != nil {
		t.Errorf("a context with a subject gave %v", err)
	}
}

func TestTheTrustedHeaderIsOffUnlessBothHalvesAreSet(t *testing.T) {
	// Trusting it unconditionally would let anybody reaching this process
	// directly be anybody at all. Naming the header and naming what to trust
	// it from are two deliberate acts, and half of it is the dangerous state.
	sources, err := access.ParseSources("10.0.0.1, 192.168.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name  string
		trust access.Trust
		on    bool
		valid bool
	}{
		{"neither", access.Trust{}, false, true},
		{"header only", access.Trust{Header: "X-User"}, false, false},
		{"sources only", access.Trust{From: sources}, false, false},
		{"both", access.Trust{Header: "X-User", From: sources}, true, true},
	} {
		if got := c.trust.Enabled(); got != c.on {
			t.Errorf("%s: enabled is %v", c.name, got)
		}
		if got := c.trust.Configured() == nil; got != c.valid {
			t.Errorf("%s: configured reads as %v", c.name, got)
		}
	}
}

func TestTheHeaderIsRefusedFromSomewhereUntrusted(t *testing.T) {
	// Reaching the process directly bypasses the proxy that was supposed to
	// have authenticated somebody.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, err := f.store.Ensure(ctx, "someone", "", true)
		if err != nil {
			t.Fatal(err)
		}
		// The proxy asserts a username, and that is what it is matched on.
		if err := f.store.Claim(ctx, person.ID, "someone"); err != nil {
			t.Fatal(err)
		}

		sources, err := access.ParseSources("10.9.9.9")
		if err != nil {
			t.Fatal(err)
		}
		resolver := access.NewResolver(f.store, access.Trust{Header: "X-User", From: sources})

		trusted := httptest.NewRequest(http.MethodGet, "/", nil)
		trusted.Header.Set("X-User", "someone")
		trusted.RemoteAddr = "10.9.9.9:5555"
		if _, _, err := resolver.Resolve(ctx, trusted); err != nil {
			t.Errorf("a header from a trusted source: %v", err)
		}

		elsewhere := httptest.NewRequest(http.MethodGet, "/", nil)
		elsewhere.Header.Set("X-User", "someone")
		elsewhere.RemoteAddr = "203.0.113.7:5555"
		if _, _, err := resolver.Resolve(ctx, elsewhere); !errors.Is(err, access.ErrDenied) {
			t.Errorf("a header from anywhere else was honored: %v", err)
		}
	})
}

func TestAKeyIsAcceptedWhereverItComesFrom(t *testing.T) {
	// A pipeline holds a credential rather than being vouched for by position,
	// so where it connects from says nothing.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		_, secret, err := f.store.NewKey(ctx, "nightly", access.Scope{ProductID: f.products["sonic"]})
		if err != nil {
			t.Fatal(err)
		}
		resolver := access.NewResolver(f.store, access.Trust{})

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		req.RemoteAddr = "203.0.113.7:5555"

		subject, _, err := resolver.Resolve(ctx, req)
		if err != nil {
			t.Fatalf("a key from an ordinary address: %v", err)
		}
		if subject.Kind != access.Pipeline {
			t.Errorf("resolved to %q", subject.Kind)
		}
	})
}

func TestTrustingEveryAddressIsRefused(t *testing.T) {
	// The guard that halts on a header with no sources would be decorative if
	// the setting meant to satisfy it could name every address instead.
	for _, sources := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/8, 0.0.0.0/0"} {
		parsed, err := access.ParseSources(sources)
		if err != nil {
			t.Fatalf("%q: %v", sources, err)
		}
		trust := access.Trust{Header: "X-User", From: parsed}
		if err := trust.Configured(); err == nil {
			t.Errorf("%q was accepted as a set of trusted sources", sources)
		}
	}
	// A real range still works.
	parsed, err := access.ParseSources("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if err := (access.Trust{Header: "X-User", From: parsed}).Configured(); err != nil {
		t.Errorf("an ordinary range was refused: %v", err)
	}
}

func TestBeingOnACaseIsNotReadingTheProduct(t *testing.T) {
	// The grant is one issue in one product, and the whole of its safety
	// is that the product-wide question keeps answering no: every list,
	// count, report and export narrows by that one, and a case that
	// widened it would hand somebody the embargo list of a product they
	// were let into one finding of.
	on := access.NewPerson(7, "engineer", false,
		map[int64][]access.Role{4: {access.PublicRead}}, 70).
		OnCases(map[int64][]int64{4: {91}, 5: {92}})

	if !on.OnCase(4, 91) || !on.OnCase(5, 92) {
		t.Fatal("somebody brought into a case is not on it")
	}
	if on.OnCase(4, 92) {
		t.Error("a case in one product carried into another issue")
	}
	if on.Reads(access.Private, 4) {
		t.Error("being on a case reads the product's undisclosed work")
	}
	// And in a product they hold nothing else on, it does not even make the
	// product readable: what they may reach there is asked about the issue.
	if on.Reads(access.Public, 5) || on.Sees(5) {
		t.Error("being on a case made a product readable")
	}
	// Which is why the per-issue question exists beside it.
	if !access.SeesOn(on, 5, 92) {
		t.Error("somebody on a case cannot reach the issue they are on")
	}
	if access.SeesOn(on, 5, 91) {
		t.Error("a case reached an issue nobody was brought into")
	}
	visible := access.VisibleOn(on, 5, 92)
	if len(visible) != 2 {
		t.Errorf("a collaborator reads %v of their case, want both visibilities", visible)
	}
	if len(access.VisibleOn(on, 5, 91)) != 0 {
		t.Error("a collaborator reads an issue they were not brought into")
	}
}

// A capability grants no visibility of its own, including to an
// administrator.
//
// The set that narrows findings, counts, aggregates and exports was built by
// asking whether the subject may know the product exists, which is true for
// an administrator everywhere and true for anybody holding a bare capability
// there. So an administrator who granted themselves the ability to assign
// work on a product — and no read role — read every disclosed finding in it.
// A non-administrator with the same grant was correctly excluded, which is
// what makes it a widening rather than a policy.
func TestACapabilityAloneNarrowsNoFindings(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		sonic, onie := f.products["sonic"], f.products["onie"]

		boss := access.NewPerson(1, "boss", true, map[int64][]access.Role{
			sonic: {access.Assigner},
			onie:  {access.PublicRead},
		}, 0)
		products, all := boss.Products()
		if all {
			t.Fatal("an administrator narrows to every product, which is not what Products is")
		}
		for _, id := range products {
			if id == sonic {
				t.Error("a product held by nothing but a capability narrows findings")
			}
		}
		if len(products) != 1 || products[0] != onie {
			t.Errorf("the products whose findings they read are %v, want the one read role", products)
		}

		// And they still know the product exists, which is what administering
		// the catalog means.
		if !boss.Sees(sonic) {
			t.Error("an administrator cannot see a product they administer")
		}
	})
}

// A grant that grants nothing is not access, including here.
//
// Every other question about what somebody holds reads past an inactive
// grant; this one counted every row. So in group-bound mode — where every
// assigned grant is inactive by construction — withdrawing somebody's last
// live role answered "they still hold something here", their assigned
// findings stayed with somebody who can no longer open them, and the
// response said nothing had been released. That is the exact outcome the
// question exists to prevent.
func TestAnInactiveGrantIsNotSomethingSomebodyHolds(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		sonic := f.products["sonic"]
		person, err := f.store.Ensure(ctx, "alice", "Alice", false)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.GrantRole(ctx, person.ID, sonic, access.PrivateTriage); err != nil {
			t.Fatal(err)
		}
		if held, err := f.store.HoldsAnythingIn(ctx, person.ID, sonic); err != nil || !held {
			t.Fatalf("a live grant reads as nothing: %v %v", held, err)
		}

		// The deployment switches to group-bound roles, which leaves every
		// assigned grant inactive rather than deleting it.
		if err := f.store.SwitchTo(ctx, access.GroupBound); err != nil {
			t.Fatal(err)
		}
		held, err := f.store.HoldsAnythingIn(ctx, person.ID, sonic)
		if err != nil {
			t.Fatal(err)
		}
		if held {
			t.Error("a grant that grants nothing reads as something they hold, " +
				"so their assigned work is never handed back")
		}
	})
}
