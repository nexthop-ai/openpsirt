// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package httpapi builds the HTTP surface: the router, the middleware in front
// of every route, sign-in and the served interface. The operations live in one
// package per area beneath it, and New registers each of them into one API.
//
// The OpenAPI document is generated from the operations registered — it is
// never written by hand, so it cannot drift from what the server actually does.
package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"github.com/nexthop-ai/openpsirt/internal/httpapi/adminapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/advisoryapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/assignapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/findingsapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/reportsapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/scansapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/triageapi"
	"github.com/nexthop-ai/openpsirt/internal/version"
)

// Ready reports whether the service can do its job. A nil Ready means the
// readiness probe only reflects the process being up.
type Ready func(context.Context) error

// contentSecurityPolicy is the sources a page served here may load and run:
// the files the bundled interface ships, and nothing from anywhere else.
//
// Scripts, fonts and stylesheets are its own files; images may also be
// data: URIs, which is how an inline SVG reaches an img element; requests go
// to this origin only; and no page anywhere may frame it. Inline styles are
// the one concession — the chart library writes them — and it is styles
// rather than scripts, which is the half that matters. It is the second line
// behind the markdown sanitizer: a bug there lands in a page that can run no
// inline script it did not hash.
//
// The page's own inline script is allowed by its hash and by nothing wider.
// The page carries one — the snippet that reads the chosen theme before the
// first paint — and a policy written for a page with none refuses it silently:
// the theme is applied a moment later by the bundle, and the flash of the
// wrong one the snippet exists to prevent happens on every load. The hash is
// taken from what is served rather than written down beside it, so the two
// cannot drift.
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
	// submission goes. Both are the shape this policy is a second line
	// against: something past the sanitizer lands in a page that can do
	// neither.
	"base-uri 'none'; form-action 'self'"

// inlineScript finds the bodies of any inline <script> in a page.
//
// Written against the served bytes rather than against the source, because a
// browser enforces the policy over the bytes it was served — a build step that
// inlines something is exactly the case a hash written by hand misses.
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
func New(logger *slog.Logger, ready Ready, in core.Deps) (http.Handler, huma.API) {
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
			// the schemas it references are served to anybody who asks,
			// including the running version the endpoint reporting it is
			// authenticated to withhold.
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
			// the check below. Served here is a compiled page and its assets,
			// which carry no data.
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
			if err != nil && !errors.Is(err, access.ErrDenied) {
				// A credential that could not be looked up is a fault, not
				// a stranger. Logged, and answered in words that say
				// nothing about the caller or the database.
				in.Log().Error("who is asking could not be resolved", "error", err)
				unavailable(w)
				return
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
				// The log carries what the browser said and what this
				// deployment answers to. Both are already known to whoever
				// can read the log.
				{
					in.Log().Warn("a write was refused because it did not come from a page this deployment served",
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
			// handed us, and this copy is what parses a form — so the copy's
			// temporary files belong to nobody and stay on disk for the life
			// of the container. A refused upload leaks them just as well as an
			// accepted one, which is a disk anybody with a credential can fill
			// by repeating a request that fails.
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
	cfg.Info.Description = "Track vulnerabilities in the products you ship.\n\n" +
		"A request carrying a query parameter the operation does not take is refused " +
		"with a 400 naming the parameter."
	// Documentation is published separately, so the server serves no page
	// for it. The document itself stays on the framework's own route,
	// authenticated like everything else.
	cfg.DocsPath = ""
	// Every API this process builds shares the schemas worked out from Go
	// types, which is most of what building one costs.
	components := newSchemas()
	cfg.Components.Schemas = components
	// A response that writes its own bytes is sent as it writes them. The
	// schema link the framework adds rebuilds the value as a type of its
	// own, which drops the writer, so a CSAF document written with its keys
	// in order would go out in declaration order with a key the standard
	// does not define at its head.
	cfg.CreateHooks = append(cfg.CreateHooks, func(c huma.Config) huma.Config {
		for i, each := range c.Transformers {
			inner := each
			c.Transformers[i] = func(ctx huma.Context, status string, v any) (any, error) {
				if _, writes := v.(json.Marshaler); writes {
					return v, nil
				}
				return inner(ctx, status, v)
			}
		}
		return c
	})

	api := humachi.New(router, cfg)
	// Before anything registers, so no operation can be added without the
	// scope on its own declaration being enforced.
	core.EnforceDeclarations(api)
	refuseUnknownParameters(api)
	registerVersion(api)
	registerSession(api, in)
	registerProviders(api, in)
	scansapi.Register(api, in)
	findingsapi.Register(api, in)
	assignapi.Register(api, in)
	triageapi.Register(api, in)
	reportsapi.Register(api, in)
	advisoryapi.Register(api, in)
	adminapi.Register(api, in)
	components.complete()

	// Last, so it claims only what nothing above it did.
	mountInterface(router, in.Interface)

	return router, api
}

// open is every path served without a credential. It is a list rather than a
// rule so that adding a route never quietly adds an exception.
var open = map[string]bool{
	"/healthz": true,
	"/readyz":  true,
	// The view before anybody has a credential. It lists the
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
// It is narrow on purpose, and it is not empty of reads: everything under it
// is sign-in machinery, which reads and writes the deployment's own sign-in
// key, the session it is creating and the account row a first arrival needs.
// It reaches no product, finding, issue or credential.
//
// A route added here is checked against what sign-in touches. Nothing under
// this prefix is harmless by construction.
const openPrefix = "/v1/sign-in/"

// refuse answers somebody unrecognized.
//
// The same answer whoever they are: unknown, known and granted nothing, or
// holding a credential that has been revoked. Saying which would tell an
// outsider whether a name or a key is real.
func refuse(w http.ResponseWriter) {
	Problem(w, http.StatusUnauthorized, "not authorized")
}

// unavailable answers a request whose caller could not be looked up.
//
// Not a refusal: telling somebody they are not authorized because the
// database did not answer sends them to sign in again, which cannot help.
func unavailable(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "30")
	Problem(w, http.StatusServiceUnavailable, "this could not be answered just now; try again shortly")
}

// Problem writes a refusal in the shape every other refusal here takes.
//
// The API answers `application/problem+json` for everything it refuses. The
// handlers in front of the router — the credential check, and the sign-in
// callbacks, which are ordinary handlers because a redirect from a provider is
// not an API call — write their refusals through this rather than as
// `text/plain`: a client that parses one shape and gets the other reads a
// failure as a transport fault, and the shape of a refusal is part of the
// answer.
//
// One field it still cannot carry: the schema link, which the API's response
// transformer adds and which nothing in front of the router reaches.
func Problem(w http.ResponseWriter, status int, detail string) {
	// The shape huma writes, built by huma, rather than a literal beside it.
	// The commonest of these is every request arriving without a credential,
	// the first thing a client written against the documented error model
	// meets.
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
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "get-version",
		Method:      http.MethodGet,
		Path:        "/v1/version",
		Summary:     "Get the server version",
		Description: "Identifies the build that is answering, so an operator can tell which version they are looking at.",
		Tags:        []string{"Meta"},
	}, core.AnyPerson, "A person rather than a pipeline: a build server has no "+
		"business asking what version is running."),
		func(ctx context.Context, _ *struct{}) (*VersionOutput, error) {
			// A person, not a pipeline. A build server has no business asking
			// what is deployed, and "nothing else" has to mean this too or it
			// means whatever each new endpoint remembers.
			if _, err := core.Reading(ctx); err != nil {
				return nil, err
			}
			return &VersionOutput{Body: version.Get()}, nil
		})
}
