package signin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// A provider, standing where a real one would.
//
// Without one, every method of both adapters goes unexecuted: the nonce
// comparison that ties a token to the sign-in that started here, the
// blank-subject refusal that access.MatchProvider's own comment relies on
// these adapters to make, and the endpoint-host check that stops a discovery
// document redirecting sign-ins somewhere else. Each could be deleted with the
// suite green.
//
// Difficulty is not what decides it: where a boundary here has an in-process
// stand-in the package behind it is at 65–96%, and where it has none the
// boundary code is at 0.0% while the pure code in the same file is at
// 88.9–100%.
type provider struct {
	*httptest.Server
	key *rsa.PrivateKey
	// claims is what the identity token will carry, which each test sets.
	claims map[string]any
	// document overrides what discovery publishes, for the tests about a
	// provider naming its endpoints somewhere else.
	document map[string]any
	// asked records what was fetched, because what these adapters get wrong is
	// the request they build and only the server sees that.
	asked []string
}

func standing(t *testing.T) *provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &provider{key: key, claims: map[string]any{}}
	mux := http.NewServeMux()
	p.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.asked = append(p.asked, r.URL.Path)
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(p.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		published := map[string]any{
			"issuer":                 p.URL,
			"authorization_endpoint": p.URL + "/authorize",
			"token_endpoint":         p.URL + "/token",
			"jwks_uri":               p.URL + "/keys",
			"userinfo_endpoint":      p.URL + "/userinfo",
		}
		for key, value := range p.document {
			published[key] = value
		}
		writeJSON(w, published)
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "one",
			"n": base64.RawURLEncoding.EncodeToString(p.key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(
				big.NewInt(int64(p.key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Kept, because the proof key is the control: what goes out in the
		// address is the digest and what is redeemed here is the secret.
		p.asked = append(p.asked, "verifier="+r.Form.Get("code_verifier"))
		writeJSON(w, map[string]any{
			"access_token": "an-access-token", "token_type": "Bearer",
			"id_token": p.token(),
		})
	})
	return p
}

// token mints an identity token carrying whatever the test set.
//
// Signed with the library the verifier already uses, rather than a second one
// brought in for the tests: a dependency is a decision, and this needs none.
func (p *provider) token() string {
	claims := map[string]any{
		"iss": p.URL, "aud": "a-client", "sub": "the-subject",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	}
	for key, value := range p.claims {
		claims[key] = value
	}
	body, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: p.key},
		(&jose.SignerOptions{}).WithHeader("kid", "one"))
	if err != nil {
		panic(err)
	}
	signed, err := signer.Sign(body)
	if err != nil {
		panic(err)
	}
	out, err := signed.CompactSerialize()
	if err != nil {
		panic(err)
	}
	return out
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

// adapter builds a real OIDC adapter against the standing provider.
//
// The guard the real one carries refuses plain HTTP, refuses any host but the
// issuer's, and refuses to connect inside this network — all three of which
// describe a test server exactly. It is stood down here so that what these
// tests measure is what this package does; the guard has its own tests,
// against the layers rather than through them.
func (p *provider) adapter(t *testing.T, cfg OIDCConfig) (*OIDC, error) {
	t.Helper()
	if cfg.Name == "" {
		cfg.Name = "acme"
	}
	cfg.Issuer, cfg.ClientID, cfg.ClientSecret = p.URL, "a-client", "a-secret"
	if cfg.UsernameClaim == "" {
		cfg.UsernameClaim = "preferred_username"
	}
	cfg.client = p.Client()
	return NewOIDC(t.Context(), cfg)
}

func TestTheAddressASignInStartsAtCarriesTheDigestAndNotTheSecret(t *testing.T) {
	// The control this names lives in the address Begin produces, and the test
	// that claimed to pin it compared a sha256 digest with its own preimage —
	// false for every implementation, including a broken one, and it sent
	// nothing anywhere.
	p := standing(t)
	adapter, err := p.adapter(t, OIDCConfig{})
	if err != nil {
		t.Fatal(err)
	}
	at, pending, err := adapter.Begin(t.Context(), "https://here.example/back")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(at)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if got := query.Get("code_challenge"); got != pending.challenge() {
		t.Errorf("the address carries %q as the challenge, want the digest", got)
	}
	if query.Get("code_challenge") == pending.Verifier {
		t.Error("the address carries the secret the proof key hashes")
	}
	if got := query.Get("code_challenge_method"); got != "S256" {
		t.Errorf("the challenge method is %q", got)
	}
	if query.Get("nonce") != pending.Nonce || pending.Nonce == "" {
		t.Errorf("the address does not carry the nonce this sign-in will be tied to")
	}
	if query.Get("state") != pending.State || pending.State == "" {
		t.Error("the address does not carry the state this sign-in will be matched on")
	}
}

func TestATokenForADifferentSignInIsRefused(t *testing.T) {
	// The nonce is the only thing tying a verified identity token to the
	// sign-in that started here. Without the comparison a token issued for
	// some other sign-in verifies perfectly well and is accepted.
	p := standing(t)
	adapter, err := p.adapter(t, OIDCConfig{})
	if err != nil {
		t.Fatal(err)
	}
	_, pending, err := adapter.Begin(t.Context(), "https://here.example/back")
	if err != nil {
		t.Fatal(err)
	}

	// The provider answers with a token minted for somebody else's sign-in.
	p.claims["nonce"] = "a-different-sign-in"
	p.claims["preferred_username"] = "ana"
	if _, err := adapter.Complete(t.Context(), "a-code", pending,
		"https://here.example/back"); err == nil {
		t.Error("a token belonging to a different sign-in was accepted")
	}

	// And the matching one is accepted, so the refusal above is the nonce
	// rather than the whole path being broken.
	p.claims["nonce"] = pending.Nonce
	who, err := adapter.Complete(t.Context(), "a-code", pending, "https://here.example/back")
	if err != nil {
		t.Fatalf("a token for this sign-in was refused: %v", err)
	}
	if who.Subject != "the-subject" || who.Username != "ana" {
		t.Errorf("the sign-in resolved to %+v", who)
	}
	// And the secret was redeemed rather than the digest.
	var redeemed string
	for _, one := range p.asked {
		if rest, found := strings.CutPrefix(one, "verifier="); found {
			redeemed = rest
		}
	}
	if redeemed != pending.Verifier || redeemed == "" {
		t.Errorf("the exchange redeemed %q, want the verifier", redeemed)
	}
}

func TestATokenNamingNobodyIsRefused(t *testing.T) {
	// The specification requires a subject and the verifier does not check for
	// one, so a token naming nobody would be accepted and leave the sign-in
	// with nothing stable to match on. access.MatchProvider's own comment
	// relies on the adapters to make this check.
	p := standing(t)
	adapter, err := p.adapter(t, OIDCConfig{})
	if err != nil {
		t.Fatal(err)
	}
	_, pending, err := adapter.Begin(t.Context(), "https://here.example/back")
	if err != nil {
		t.Fatal(err)
	}
	p.claims["nonce"] = pending.Nonce
	p.claims["sub"] = "   "
	if _, err := adapter.Complete(t.Context(), "a-code", pending,
		"https://here.example/back"); err == nil {
		t.Error("a token naming no subject was accepted")
	}
}

func TestAProviderNamingItsEndpointsElsewhereIsRefusedAtStartup(t *testing.T) {
	// A discovery document names the addresses this deployment will send
	// people to, and it arrives over the network. Pinning the fetch to the
	// issuer's host does not stop the document naming somewhere else inside
	// itself — and the keys endpoint, which the library does not expose, was
	// the one address nothing checked.
	for _, c := range []struct {
		what  string
		named string
	}{
		{"authorization", "authorization_endpoint"},
		{"token", "token_endpoint"},
		{"keys", "jwks_uri"},
	} {
		p := standing(t)
		p.document = map[string]any{c.named: "https://somewhere.else.example/x"}
		_, err := p.adapter(t, OIDCConfig{})
		if err == nil {
			t.Errorf("a provider naming its %s endpoint on another host was accepted", c.what)
			continue
		}
		if !strings.Contains(err.Error(), "somewhere.else.example") {
			t.Errorf("the refusal for the %s endpoint does not say where: %v", c.what, err)
		}
	}
}

func TestWhatAProviderMustSupplyBeforeItIsUsable(t *testing.T) {
	// The three refusals that return before any network call, and the two
	// fields that escaped the constructor: the provider name becomes a path
	// segment and a route parameter, and an unusable one produces a deployment
	// that starts, logs "sign-in configured", and signs nobody in.
	for _, c := range []struct {
		what string
		cfg  OIDCConfig
	}{
		{"an unreadable issuer", OIDCConfig{Issuer: "://", UsernameClaim: "sub"}},
		{"an issuer over plain http", OIDCConfig{
			Issuer: "http://issuer.example", UsernameClaim: "sub"}},
		{"no client secret", OIDCConfig{
			Issuer: "https://issuer.example", UsernameClaim: "sub"}},
		{"no username claim", OIDCConfig{
			Issuer: "https://issuer.example", ClientID: "c", ClientSecret: "s"}},
		{"a name carrying a slash", OIDCConfig{
			Name: "acme/corp", Issuer: "https://issuer.example",
			ClientID: "c", ClientSecret: "s", UsernameClaim: "sub"}},
		{"a name carrying a space", OIDCConfig{
			Name: "acme corp", Issuer: "https://issuer.example",
			ClientID: "c", ClientSecret: "s", UsernameClaim: "sub"}},
		{"an empty name", OIDCConfig{
			Issuer: "https://issuer.example", ClientID: "c", ClientSecret: "s",
			UsernameClaim: "sub"}},
	} {
		if _, err := NewOIDC(context.Background(), c.cfg); err == nil {
			t.Errorf("a provider configured with %s was accepted", c.what)
		}
	}
}

// forge stands where GitHub's API would.
func forge(t *testing.T, org string, handler http.HandlerFunc) *GitHub {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	adapter, err := NewGitHub(GitHubConfig{
		ClientID: "a-client", ClientSecret: "a-secret", Organization: org,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Pointed at the stand-in, and the guard stood down for the reason the
	// OIDC adapter's is: it refuses a test server by design.
	adapter.api = server.URL
	adapter.client = server.Client()
	adapter.config.Endpoint.TokenURL = server.URL + "/token"
	return adapter
}

func TestAnOrganizationIsMatchedHoweverItWasTyped(t *testing.T) {
	// GitHub's organization logins are case-insensitive to look up and
	// canonical in what it hands back, so the operator's spelling and GitHub's
	// need not match byte for byte. Compared byte for byte, a mismatch of
	// capitals skipped every membership — teams came back empty with no error,
	// nobody derived any role in group-bound mode, and startup logged "sign-in
	// configured" with the operator's own spelling echoed back.
	// Both spellings vary: what the operator typed, and what GitHub hands
	// back. GitHub answers with the organization's canonical casing, which is
	// whatever its owner registered — so folding the operator's input at
	// construction is half the rule and folding at the compare is the other.
	for _, c := range []struct{ typed, canonical string }{
		{"nexthop-ai", "nexthop-ai"},
		{"Nexthop-AI", "nexthop-ai"},
		{"  NEXTHOP-AI  ", "nexthop-ai"},
		{"nexthop-ai", "Nexthop-AI"},
		{"NEXTHOP-AI", "Nexthop-AI"},
	} {
		typed, canonical := c.typed, c.canonical
		adapter := forge(t, typed, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasPrefix(r.URL.Path, "/token"):
				writeJSON(w, map[string]any{
					"access_token": "a-token", "token_type": "Bearer"})
			case r.URL.Path == "/user":
				writeJSON(w, map[string]any{"login": "ana", "id": 42, "name": "Ana Ruiz"})
			case r.URL.Path == "/user/emails":
				writeJSON(w, []any{})
			case r.URL.Path == "/user/teams":
				// The canonical casing, which is what GitHub answers with.
				writeJSON(w, []any{
					map[string]any{"slug": "kernel",
						"organization": map[string]any{"login": canonical}},
					map[string]any{"slug": "elsewhere",
						"organization": map[string]any{"login": "another-org"}},
				})
			default:
				http.NotFound(w, r)
			}
		})
		who, err := adapter.Complete(t.Context(), "a-code", Pending{Verifier: "v"},
			"https://here.example/back")
		if err != nil {
			t.Fatalf("%q: completing: %v", typed, err)
		}
		if len(who.Groups) != 1 || who.Groups[0] != "kernel" {
			t.Errorf("an organization typed %q and registered as %q derived groups %v, "+
				"want the one team", typed, canonical, who.Groups)
		}
		// The numeric identifier rather than the login: a login can be changed
		// by its owner and then taken by somebody else.
		if who.Subject != "42" {
			t.Errorf("the sign-in is matched on %q rather than the account", who.Subject)
		}
	}
}

func TestAPublicAddressIsNotTakenForAVerifiedOne(t *testing.T) {
	// The address on the profile is whatever somebody chose to show publicly.
	// An authorization waiting under a work address would be redeemable by
	// anybody willing to claim it, so only the verified list counts.
	adapter := forge(t, "", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/token"):
			writeJSON(w, map[string]any{"access_token": "a-token", "token_type": "Bearer"})
		case r.URL.Path == "/user":
			writeJSON(w, map[string]any{
				"login": "ana", "id": 42, "email": "public@example.test"})
		case r.URL.Path == "/user/emails":
			writeJSON(w, []any{
				map[string]any{"email": "unverified@example.test",
					"primary": true, "verified": false},
				map[string]any{"email": "verified@example.test",
					"primary": false, "verified": true},
			})
		default:
			http.NotFound(w, r)
		}
	})
	who, err := adapter.Complete(t.Context(), "a-code", Pending{Verifier: "v"},
		"https://here.example/back")
	if err != nil {
		t.Fatal(err)
	}
	if who.Email == "public@example.test" || who.Email == "unverified@example.test" {
		t.Errorf("an address nobody verified was taken as the identity's: %q", who.Email)
	}
	if who.Email != "verified@example.test" || !who.EmailVerified {
		t.Errorf("the verified address was not used: %q verified=%v", who.Email, who.EmailVerified)
	}
}

func TestTeamsAreReadPastTheFirstPage(t *testing.T) {
	// This endpoint reports teams across every organization somebody belongs
	// to, so one page is not a page of ours — and truncating it would silently
	// strip roles from whoever happens to be in a lot of teams, which is a
	// refusal nobody could diagnose from either side.
	adapter := forge(t, "ours", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/token"):
			writeJSON(w, map[string]any{"access_token": "a-token", "token_type": "Bearer"})
		case r.URL.Path == "/user":
			writeJSON(w, map[string]any{"login": "ana", "id": 42})
		case r.URL.Path == "/user/emails":
			writeJSON(w, []any{})
		case r.URL.Path == "/user/teams":
			// A full first page of somebody else's teams, then ours on the
			// second: read once, the answer is no teams at all.
			if r.URL.Query().Get("page") == "1" {
				full := make([]any, 0, teamPageSize)
				for i := range teamPageSize {
					full = append(full, map[string]any{
						"slug":         "other" + strconv.Itoa(i),
						"organization": map[string]any{"login": "theirs"}})
				}
				writeJSON(w, full)
				return
			}
			writeJSON(w, []any{map[string]any{
				"slug": "kernel", "organization": map[string]any{"login": "ours"}}})
		default:
			http.NotFound(w, r)
		}
	})
	who, err := adapter.Complete(t.Context(), "a-code", Pending{Verifier: "v"},
		"https://here.example/back")
	if err != nil {
		t.Fatal(err)
	}
	if len(who.Groups) != 1 || who.Groups[0] != "kernel" {
		t.Errorf("reading stopped at the first page: %v", who.Groups)
	}
}

func TestBothAdaptersStartASignInTheSameWay(t *testing.T) {
	// Written out once per adapter, the proof key and its method are two
	// copies of the same literals. A hardening change landing in one and not
	// the other downgrades that provider alone, with nothing observing
	// either.
	//
	// So both are asked, and what differs is stated: OpenID Connect carries a
	// nonce, because it has an identity token to tie to this sign-in, and
	// GitHub issues none.
	p := standing(t)
	oidc, err := p.adapter(t, OIDCConfig{})
	if err != nil {
		t.Fatal(err)
	}
	forge, err := NewGitHub(GitHubConfig{ClientID: "a-client", ClientSecret: "a-secret"})
	if err != nil {
		t.Fatal(err)
	}

	for _, adapter := range []Provider{oidc, forge} {
		at, pending, err := adapter.Begin(t.Context(), "https://here.example/back")
		if err != nil {
			t.Fatalf("%s: %v", adapter.Name(), err)
		}
		parsed, err := url.Parse(at)
		if err != nil {
			t.Fatal(err)
		}
		query := parsed.Query()
		if got := query.Get("code_challenge"); got != pending.challenge() {
			t.Errorf("%s carries %q as the challenge", adapter.Name(), got)
		}
		if query.Get("code_challenge") == pending.Verifier {
			t.Errorf("%s sends the secret the proof key hashes", adapter.Name())
		}
		if got := query.Get("code_challenge_method"); got != "S256" {
			t.Errorf("%s states the challenge method as %q", adapter.Name(), got)
		}
		if query.Get("redirect_uri") != "https://here.example/back" {
			t.Errorf("%s sends the browser back to %q",
				adapter.Name(), query.Get("redirect_uri"))
		}
		// The nonce is the one difference, and it is the one that matters:
		// without it there is nothing tying a verified identity token to this
		// sign-in.
		if _, isOIDC := adapter.(*OIDC); isOIDC != (query.Get("nonce") != "") {
			t.Errorf("%s carries nonce=%q", adapter.Name(), query.Get("nonce"))
		}
	}
}
