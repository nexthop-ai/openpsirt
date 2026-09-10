package httpapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// SignOutOutput carries nothing. What matters is the cookie it clears.
type SignOutOutput struct {
	// SetCookie clears what the browser holds as well as what the database
	// does. Clearing only the database leaves a browser holding a credential
	// that stopped working, which reads as the application being broken rather
	// than as having signed out.
	//
	// Both cookies, because both were set. The value a page echoes is not a
	// credential on its own, but leaving it behind means a signed-out browser
	// still carries something from the session it left.
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Status    int
}

func registerSession(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "sign-out", Method: http.MethodDelete, Path: "/v1/session",
		Summary: "Sign out",
		Description: "Ends the session the request arrived on, everywhere rather than in this " +
			"browser alone — the session is stored, so it stops working whichever copy of the " +
			"application answers next.",
		Tags:          []string{"Access"},
		DefaultStatus: http.StatusNoContent,
	}, ownSubject, ""), func(ctx context.Context, _ *struct{}) (*SignOutOutput, error) {
		// Signing out is not something a pipeline's key can do: there is no
		// session behind it to end, and answering as though there were would
		// suggest one existed.
		session := access.SessionFrom(ctx)
		if session == nil {
			return nil, huma.Error400BadRequest("this request did not arrive on a session")
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		if err := access.NewStore(in.DB.DB).EndSession(ctx, session.ID); err != nil {
			return nil, wentWrong(in.Logger, "the session could not be ended", err)
		}
		return &SignOutOutput{
			SetCookie: []http.Cookie{
				clearedCookie(in.PlainHTTP),
				browserCookie(csrfCookieName, "", true, in.PlainHTTP, -1),
			},
			Status: http.StatusNoContent,
		}, nil
	})
}

// SessionCookie builds the cookie a browser holds after signing in.
//
// HttpOnly so no script can read it, which is what keeps the token out of
// reach of anything injected into a page.
func SessionCookie(token string, plainHTTP bool) http.Cookie {
	return browserCookie(access.SessionCookie, token, false, plainHTTP, 0)
}

// CSRFCookie carries the value a page reads and echoes back.
//
// Readable by script on purpose: that is the entire mechanism. A page from
// another origin cannot read it, so a request that echoes it correctly came
// from one of ours, and marking it HttpOnly would leave nothing able to read
// it and no state-changing request able to be made at all.
//
// It is not a credential. It authenticates nothing by itself — the session
// cookie does that — so what a script reading it gains is the ability to make
// a request the browser could already have been made to make.
func CSRFCookie(token string, plainHTTP bool) http.Cookie {
	return browserCookie(csrfCookieName, token, true, plainHTTP, 0)
}

// csrfCookieName is where a page reads the value it echoes back.
const csrfCookieName = "openpsirt_csrf"

// clearedCookie is what tells a browser to forget the session. Its attributes
// match the ones it was set with, because a browser matches on those before it
// will replace a cookie.
func clearedCookie(plainHTTP bool) http.Cookie {
	return browserCookie(access.SessionCookie, "", false, plainHTTP, -1)
}

// browserCookie builds the cookies this API sets, in one place so the
// attributes are argued about once.
//
// SameSite=Lax so a browser does not attach them to a state-changing request
// from another site — a second guard beside the echoed value rather than a
// replacement for it, since neither covers every browser somebody arrives
// with.
//
// plainHTTP clears Secure, for running this locally without TLS. A Secure
// cookie is simply never sent over plain HTTP, so leaving it set there would
// make sign-in fail silently: the browser drops the cookie and every request
// afterwards looks like a stranger's. It is a parameter rather than a default
// so that reaching it is deliberate.
//
// that asked for it, and that HttpOnly is off only for the value a page has to
// read in order to echo it.
//
// browserCookie builds the cookies this API sets, in one place so their
// attributes are argued about once.
//
// SameSite=Lax so a browser does not attach them to a state-changing request
// from another site — a second guard beside the value a page echoes rather
// than a replacement for it, since neither covers every browser somebody
// arrives with.
//
// plainHTTP clears Secure, for running this locally without TLS. A Secure
// cookie is simply never sent over plain HTTP, so leaving it set there would
// make sign-in fail silently: the browser drops the cookie and every request
// afterwards looks like a stranger's. It is a parameter rather than a default
// so that reaching it is deliberate.
//
// readable turns HttpOnly off, which exactly one cookie needs: the value a
// page has to read in order to echo it back.
//
//nolint:gosec // G124 cannot see that Secure is cleared only for a deployment that asked for it, nor that HttpOnly is off only for the value a page must read.
func browserCookie(name, value string, readable, plainHTTP bool, maxAge int) http.Cookie {
	return http.Cookie{
		Name: name, Value: value, Path: "/",
		HttpOnly: !readable, Secure: !plainHTTP, SameSite: http.SameSiteLaxMode,
		MaxAge: maxAge,
	}
}
