// Package httpapi builds the HTTP surface.
//
// The OpenAPI document is generated from the operations registered here — it is
// never written by hand, so it cannot drift from what the server actually does.
package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/version"
)

// Ready reports whether the service can do its job. A nil Ready means the
// readiness probe only reflects the process being up.
type Ready func(context.Context) error

// contentSecurityPolicy is what a page served here may load and run: what the
// bundled interface ships, and nothing from anywhere else.
//
// Scripts, fonts and stylesheets are its own files; images may also be
// data: URIs, which is how an inline SVG reaches an img element; requests go
// to this origin only; and no page anywhere may frame it. Inline styles are
// the one concession — the chart library writes them — and it is styles
// rather than scripts, which is the half that matters. It is the second line
// policy on the server at submission accepted behind the sanitizer: a bug there lands in a page that can
// run no inline script it did not hash.
//
// **The page's own inline script is allowed by its hash, and by nothing
// wider.** This said "the interface has no inline script", which was true when
// it was written and stopped being true when the page grew one — the snippet
// that reads the chosen theme before the first paint. Nothing said so: the
// browser refused it silently, the theme was applied a moment later by the
// bundle instead, and what the snippet exists to prevent — a flash of the
// wrong one — happened on every load. The hash is taken from what is actually
// served rather than written down beside it, so the two cannot drift again.
const baseContentSecurityPolicy = "default-src 'self'; img-src 'self' data:; " +
	// The bundler inlines the small font files as data URIs, so fonts are
	// allowed from the page itself as well as from the origin.
	"font-src 'self' data:; " +
	"style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; " +
	"frame-ancestors 'none'; " +
	// The two the rest of the policy does not cover. A <base> element
	// rewrites what every relative URL on the page resolves to, which
	// turns a link this deployment wrote into somebody else's address
	// without any of the directives above being violated; and a form's
	// action is not a fetch, so connect-src says nothing about where a
	// submission goes. Both are the shape policy on the server at
	// submission accepted this policy as a second line for: something that
	// got past the sanitizer lands in a page that can do neither.
	"base-uri 'none'; form-action 'self'"

// inlineScript finds the bodies of any inline <script> in a page.
//
// Written against the served bytes rather than against the source, because
// what a browser enforces the policy over is what was served — a build step
// that inlines something is exactly the case a hash written by hand misses.
var inlineScript = regexp.MustCompile(`(?s)<script(?:\s[^>]*)?>(.*?)</script>`)

// policyFor is the policy with the page's own inline scripts allowed by hash.
//
// One hash per script and nothing wider: `'unsafe-inline'` would allow every
// inline script including one somebody smuggled past the sanitizer, which is
// the thing this policy is a second line against.
func policyFor(files fs.FS) string {
	if files == nil {
		return baseContentSecurityPolicy
	}
	page, err := fs.ReadFile(files, "index.html")
	if err != nil {
		return baseContentSecurityPolicy
	}
	var hashes []string
	for _, found := range inlineScript.FindAllSubmatch(page, -1) {
		body := found[1]
		if len(bytes.TrimSpace(body)) == 0 {
			continue
		}
		sum := sha256.Sum256(body)
		hashes = append(hashes, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'")
	}
	if len(hashes) == 0 {
		return baseContentSecurityPolicy
	}
	return strings.Replace(baseContentSecurityPolicy, "script-src 'self'",
		"script-src 'self' "+strings.Join(hashes, " "), 1)
}

// browserHeaders sets, on every response, the headers that turn off what
// nothing served here needs: a browser guessing a content type, any page
// framing this one, and a referrer carrying a finding's path to somebody
// else's server. Set here rather than per route so that a route added later
// cannot lack them, and on the API's responses as well as the page's, because
// a JSON body opened directly in a browser is still a page.
func browserHeaders(policy string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "same-origin")
			h.Set("Content-Security-Policy", policy)
			next.ServeHTTP(w, r)
		})
	}
}

// changesSomething reports whether a method is one that writes.
//
// Named as a list of what is safe rather than of what is not: a method absent
// from the list is treated as changing something, so an unusual one is guarded
// by default rather than by having been thought of.
func changesSomething(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// New returns the HTTP handler and the API description it was built from.
//
// The description is returned so the OpenAPI document can be written out
// without starting a server.
func New(logger *slog.Logger, ready Ready, in Ingest) (http.Handler, huma.API) {
	in.Logger = logger
	router := chi.NewMux()
	router.Use(middleware.RequestID)
	router.Use(middleware.Recoverer)
	router.Use(browserHeaders(policyFor(in.Interface.Files)))
	// One resolution step, before any handler. Doing it here rather than in
	// each handler is the whole point: a handler that forgets is a handler
	// answering for everybody, and the forgetting is invisible until somebody
	// reads the one that did.
	//
	// It attaches whoever was recognized and refuses nobody. What a subject
	// may reach is decided further down, where the query is, so that a route
	// added later cannot be less careful than the one beside it.
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Named exceptions rather than a guarded prefix. Guarding one
			// prefix leaves everything else open by default, and the
			// framework registers routes of its own: the API document and
			// the schemas it references were served to anybody who asked,
			// including the running version that the endpoint reporting it
			// is authenticated to withhold.
			//
			// The probes are the exception, because a container probe cannot
			// sign in and they report nothing beyond whether this process can
			// serve.
			if open[r.URL.Path] || strings.HasPrefix(r.URL.Path, openPrefix) {
				next.ServeHTTP(w, r)
				return
			}

			// A path this server has no route for belongs to the interface,
			// which does its own routing — and the page has to load for
			// somebody holding nothing, because the sign-in screen is the
			// page. Asked of the router rather than by matching a prefix, so
			// this cannot shadow a route: anything registered, including the
			// framework's own document and schema routes, still goes through
			// the check below. What is served here is a compiled page and its
			// assets, which carry no data.
			if in.Interface.Files != nil && !reserved(r.URL.Path) &&
				!router.Match(chi.NewRouteContext(), r.Method, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			var subject access.Subject
			var session *access.Session
			var err error
			if in.Access == nil {
				err = access.ErrDenied
			} else {
				subject, session, err = in.Access.Resolve(r.Context(), r)
			}
			if err != nil {
				// Refused here rather than in a handler, so that nothing
				// about the request is examined first. Otherwise an
				// unauthenticated caller learns whether their body was
				// well-formed, which is a small thing to hand somebody who
				// has not identified themselves at all.
				refuse(w)
				return
			}
			// A request a browser made by itself is one somebody
			// else's page may have caused, because the credential
			// goes along without anybody asking — our cookie, or
			// the proxy's. Requests carrying a key are exempt:
			// nothing sends those automatically, so the guard
			// would protect nothing and break every build.
			if !meantToBeSent(r, session, in.BaseURL) {
				// Logged, because the answer a caller gets cannot tell them
				// why without telling somebody else's page the same thing —
				// and a deployment reached by a name it was not told about
				// refuses every write while every read works, which looks
				// like nothing at all from the outside. Somebody loses a
				// half-written decision at submit and the only clue is
				// "not authorized".
				//
				// What is logged is what the browser said and what this
				// deployment answers to. Both are already known to whoever
				// can read the log.
				if in.Logger != nil {
					in.Logger.Warn("a write was refused because it did not come from a page this deployment served",
						"origin", r.Header.Get("Origin"),
						"referer", r.Header.Get("Referer"),
						"answers_to", strings.Join(origins(r, in.BaseURL), ", "),
						"path", r.URL.Path)
				}
				refuse(w)
				return
			}

			ctx := access.With(r.Context(), subject)
			if session != nil {
				ctx = access.WithSession(ctx, session)
			}
			carrying := r.WithContext(ctx)
			// The server removes spooled multipart parts from the request it
			// handed us, and what parses a form is this copy — so the copy's
			// temporary files belong to nobody and stayed on disk for the life
			// of the container. A refused upload leaked them just as well as
			// an accepted one, which is a disk anybody with a credential can
			// fill by repeating a request that fails.
			defer func() {
				if carrying.MultipartForm != nil {
					_ = carrying.MultipartForm.RemoveAll()
				}
			}()
			next.ServeHTTP(w, carrying)
		})
	})

	// Sign-in is mounted before the API description is built, because these
	// are browser redirects rather than operations: nothing calls them with a
	// generated client, and the answer is a 302 carrying cookies.
	registerSignIn(router, in)

	// RealIP is deliberately absent. It rewrites the client address from
	// X-Forwarded-For and similar, which any caller can set, so it is only
	// safe behind a proxy known to overwrite them. Trusting proxy-supplied
	// headers happens in one place, guarded by a trusted-source check.

	// Liveness and readiness are deliberately outside the documented API and
	// carry no authentication: a container probe cannot sign in, and these
	// report nothing beyond whether the process can serve.
	//
	// Liveness answers as long as the process is running. Readiness also needs
	// the database, because a process that cannot reach its database is up but
	// useless, and sending it traffic helps nobody.
	router.Get("/healthz", plainOK)
	router.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if ready != nil {
			if err := ready(r.Context()); err != nil {
				logger.Warn("not ready", "error", err)
				http.Error(w, "not ready\n", http.StatusServiceUnavailable)
				return
			}
		}
		plainOK(w, r)
	})

	cfg := huma.DefaultConfig("OpenPSIRT", version.Get().Version)
	cfg.Info.Description = "Track vulnerabilities in the products you ship."
	// Documentation is published separately, so the server serves no page
	// for it. The document itself stays on the framework's own route,
	// authenticated like everything else.
	cfg.DocsPath = ""

	api := humachi.New(router, cfg)
	// Before anything registers, so no operation can be added without the
	// scope on its own declaration being enforced.
	enforceDeclarations(api)
	registerVersion(api)
	registerScans(api, in)
	registerFindings(api, in)
	registerComponentFindings(api, in)
	// The findings list across every product somebody may see.
	registerAnywhere(api, in)
	registerHolders(api, in)
	registerComponent(api, in)
	registerPlanUpgrade(api, in)
	registerReceipts(api, in)
	// Reading back a document a build sent.
	registerRetained(api, in)
	// What one run of the scanner did.
	registerRun(api, in)
	// One product's own page.
	registerOverview(api, in)
	registerCoverage(api, in)
	registerCoverageExport(api, in)
	registerOutOfSupport(api, in)
	registerScrutiny(api, in)
	registerPublished(api, in)
	registerAudit(api, in)
	registerNotifications(api, in)
	registerDigest(api, in)
	registerSession(api, in)
	registerTokens(api, in)
	registerFindingDetail(api, in)
	registerAssignment(api, in)
	registerFixTargets(api, in)
	registerReadiness(api, in)
	registerEntry(api, in)
	registerDisclosure(api, in)
	registerResolution(api, in)
	registerAdvisory(api, in)
	registerAttachments(api, in)
	registerRemediation(api, in)
	registerNotes(api, in)
	registerReleaseTrend(api, in)
	registerCarrying(api, in)
	registerScoring(api, in)
	registerAffects(api, in)
	registerExtensions(api, in)
	registerDue(api, in)
	registerGraph(api, in)
	registerSettings(api, in)
	registerTrail(api, in)
	registerSaved(api, in)
	registerBundles(api, in)
	registerPendingUpgrades(api, in)
	registerVexImport(api, in)
	registerExport(api, in)
	registerAnywhereExport(api, in)
	// The three lists that could be read and not taken away.
	registerMoreExports(api, in)
	registerRegister(api, in)
	registerCompliance(api, in)
	registerRouting(api, in)
	registerProviders(api, in)
	registerWhoAmI(api, in)
	registerMentions(api, in)
	registerBulk(api, in)
	registerReports(api, in)
	registerMeasures(api, in)
	registerCarried(api, in)
	registerCarry(api, in)
	registerTriage(api, in)
	registerFindingDecision(api, in)
	registerAssessment(api, in)
	registerTriageReading(api, in)
	registerComments(api, in)
	registerClaims(api, in)
	registerProposing(api, in)
	registerPlaceDecisions(api, in)
	registerElsewhere(api, in)
	registerReachAcross(api, in)
	registerBindings(api, Administering{
		Access: in.rights, Catalog: in.catalog, Logger: logger, Mode: in.Mode,
	}, func() *setting.Store {
		if in.DB == nil {
			return nil
		}
		return setting.NewStore(in.DB.DB)
	})
	registerCatalog(api, Declaring{
		Store: in.catalog, Logger: logger,
		Findings: func() *finding.Store {
			if in.DB == nil {
				return nil
			}
			return finding.NewStore(in.DB.DB)
		},
		Scans: func() *ingest.Store {
			if in.DB == nil {
				return nil
			}
			return ingest.NewStore(in.DB.DB)
		},
		RewriteDeadlines: deadlinesRewritten(in),
		Trail:            in.trail,
	})
	registerAdministration(api, Administering{
		Access: in.rights, Catalog: in.catalog, Logger: logger, Mode: in.Mode,
		Findings: func() *finding.Store {
			if in.DB == nil {
				return nil
			}
			return finding.NewStore(in.DB.DB)
		},
		Trail: in.trail,
	})
	registerTeams(api, Administering{
		Access: in.rights, Catalog: in.catalog, Logger: logger, Mode: in.Mode,
		Trail: in.trail,
	})
	// Who is on one undisclosed case. It takes both: the grant is managed
	// by whoever reads the case rather than by an administrator, and it
	// lands in the administration trail like every other access change.
	// Who told us, and the names an issue goes by.
	registerWhoTold(api, in)
	// What stands about the third-party components a build ships.
	registerVEX(api, in)
	// One issue, everywhere it sits, across products.
	registerIssue(api, in)
	// The words people put on findings.
	registerTags(api, in)
	// The tree seen upward, for somebody narrowed to their own work.
	registerUpward(api, in)
	// Where a claim's work is happening, stored and never sent to.
	registerClaimLink(api, in)
	registerCollaborators(api, in, Administering{
		Access: in.rights, Catalog: in.catalog, Logger: logger, Mode: in.Mode,
		Trail: in.trail,
	})
	// One person, whole: what they hold, what they used to hold, their part
	// in the record, and what they were told.
	registerPerson(api, in, Administering{
		Access: in.rights, Catalog: in.catalog, Logger: logger, Mode: in.Mode,
		Trail: in.trail,
	})
	// Where this deployment sends what it has to say.
	registerOutbound(api, in, Administering{
		Access: in.rights, Catalog: in.catalog, Logger: logger, Mode: in.Mode,
		Trail: in.trail,
	})
	registerRevocation(api, Administering{
		Access: in.rights, Catalog: in.catalog, Logger: logger, Mode: in.Mode,
		Trail: in.trail,
	})

	// Last, so it claims only what nothing above it did.
	mountInterface(router, in.Interface)

	return router, api
}

// wentWrong reports a fault to the caller without describing it to them.
//
// The framework serializes an error passed alongside the message, so handing
// it one hands the caller the query text and whatever the driver put in its
// message — which for a connection failure is the address and the user it
// tried. Whoever operates this deployment needs that; whoever is asking does
// not.
func wentWrong(logger *slog.Logger, what string, err error) error {
	if logger != nil {
		logger.Error(what, "error", err)
	}
	return huma.Error500InternalServerError(what)
}

// asked is the answer when a store refused what the caller asked for.
//
// A store returns two kinds of error through one return: a sentence written
// for a person — a decision already standing here, a version that is not a
// version, a threshold crossed — and a query that failed, which carries the
// statement text and whatever the driver put in its message. Thirty handlers
// answered both the same way, as a 422 with the message in it, so a lost
// connection reached whoever asked as a bad request carrying the address the
// driver had tried.
//
// The engine's own error types decide which it is, rather than the message,
// and where it cannot tell it errs toward treating it as a refusal — the
// direction that is already safe, because a store's own sentences are the only
// thing that reaches the caller.
func asked(logger *slog.Logger, err error) error {
	if database.FromEngine(err) {
		return wentWrong(logger, "that could not be recorded", err)
	}
	return huma.Error422UnprocessableEntity(err.Error())
}

// noDatabase is the answer when this process has no database behind it.
//
// One sentence rather than twenty-one. Every handler guards against it,
// because a nil pointer inside one is worse than a refusal, and each guard had
// invented its own wording — "cannot read findings", "cannot record
// decisions", "cannot list teams" — which reads as twenty-one conditions and
// is one. None of them was logged either, so the only trace of a deployment
// wired up wrong was a 500 with a sentence in it.
//
// It says nothing about what the caller asked for, because the caller did not
// cause it and cannot fix it: this is a process that came up without the thing
// it exists to read.
func noDatabase(logger *slog.Logger) error {
	if logger != nil {
		logger.Error("this process has no database behind it, so it can answer nothing")
	}
	return huma.Error500InternalServerError("this deployment is not fully configured")
}

// open is every path served without a credential. It is a list rather than a
// rule so that adding a route never quietly adds an exception.
var open = map[string]bool{
	"/healthz": true,
	"/readyz":  true,
	// What somebody sees before they have a credential. It lists the
	// providers an operator configured and nothing else — the sign-in page
	// has to draw a button per provider, and it cannot ask for that list
	// while holding nothing. Everything under openPrefix already answers
	// without a credential for the same reason; this is the list of what is
	// down there.
	"/v1/sign-in": true,
}

// openPrefix is the one place a prefix is used rather than a named route,
// because sign-in cannot name its routes in advance: the provider is part of
// the path and the set of providers is configuration.
//
// It is narrow on purpose. Everything under it either redirects to a provider
// or refuses, and nothing under it reads anything — so a route added here by
// mistake can leak a redirect and not data.
const openPrefix = "/v1/sign-in/"

// refuse answers somebody unrecognized.
//
// The same answer whoever they are: unknown, known and granted nothing, or
// holding a credential that has been revoked. Saying which would tell an
// outsider whether a name or a key is real.
func refuse(w http.ResponseWriter) {
	Problem(w, http.StatusUnauthorized, "not authorized")
}

// Problem writes a refusal in the shape every other refusal here takes.
//
// The API answers `application/problem+json` for everything it refuses, and
// the handlers in front of the router — the credential check, and the sign-in
// callbacks, which are ordinary handlers because a redirect from a provider is
// not an API call — answered `text/plain`. A client that parses one shape and
// gets the other reads a failure as a transport fault, and the shape of a
// refusal is part of the answer.
//
// One field it still cannot carry: the schema link, which the API's response
// transformer adds and which nothing in front of the router reaches.
func Problem(w http.ResponseWriter, status int, detail string) {
	// The shape huma writes, built by huma, rather than a literal beside it.
	// The commonest of these is every request arriving without a credential —
	// the first thing a client written against the documented error model
	// meets, and once the one answer not built from that model.
	body, err := json.Marshal(huma.NewError(status, detail))
	if err != nil {
		// Marshaling a fixed value cannot fail; if it somehow does, the status
		// is the part that matters and it still goes.
		body = []byte(`{"title":"Error","status":` +
			strconv.Itoa(status) + `,"detail":"` + detail + `"}`)
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}

func plainOK(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// VersionOutput is the body of a version response.
type VersionOutput struct {
	Body version.Info
}

func registerVersion(api huma.API) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-version",
		Method:      http.MethodGet,
		Path:        "/v1/version",
		Summary:     "Get the server version",
		Description: "Identifies the build that is answering, so an operator can tell which version they are looking at.",
		Tags:        []string{"Meta"},
	}, anySubject, "A person rather than a pipeline: a build server has no "+
		"business asking what version is running."),
		func(ctx context.Context, _ *struct{}) (*VersionOutput, error) {
			// A person, not a pipeline. A build server has no business asking
			// what is deployed, and "nothing else" has to mean this too or it
			// means whatever each new endpoint remembers.
			if _, err := reading(ctx); err != nil {
				return nil, err
			}
			return &VersionOutput{Body: version.Get()}, nil
		})
}
