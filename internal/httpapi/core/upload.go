// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"

	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// Envelope is what a multipart request carries beyond its files: boundaries,
// part headers and the small fields beside a file. A request bounded at a
// file's limit alone refuses a file of exactly that size.
const Envelope = 1 << 20

// Admission is what an upload route decides before a byte of its body is
// read.
type Admission struct {
	// Admit refuses a caller the route refuses. It asks what the handler
	// asks, in the same order and answering in the same words, so a caller
	// learns nothing from which of the two refused. Nil is a route whose
	// declared scope is the whole of its authorization, which runs before
	// this does.
	Admit func(huma.Context) error
	// Limit is the largest request the route reads, decided per request.
	Limit func(context.Context) (int64, error)
}

// Uploads counts the requests spooling a form at once, across every route
// of one server.
type Uploads struct {
	active atomic.Int64
}

// take holds a place, and reports false where most are already held.
func (u *Uploads) take(most int64) bool {
	if u.active.Add(1) > most {
		u.active.Add(-1)
		return false
	}
	return true
}

func (u *Uploads) give() { u.active.Add(-1) }

// BoundedForm admits a multipart request and caps how much of it is read at
// all.
//
// A form is read as it streams, part by part, to the temporary directory, so
// everything about whether it may be read is settled first:
//
//  1. The caller is authorized for the route, as the handler would.
//  2. A request declaring a length past the route's limit is refused unread.
//  3. A place is held among the uploads this server spools at once, and a
//     request finding none is answered 503 with a time to retry after.
//  4. The body is capped at the limit and the form parsed here, before the
//     operation's own parsing runs, which then finds it read and reads
//     nothing more.
//
// Anything other than these is left for that parsing to report, in its own
// terms.
func BoundedForm(api huma.API, in Deps, admission Admission) func(ctx huma.Context, next func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		if in.DB == nil {
			// The handler answers that there is no database.
			next(ctx)
			return
		}
		if admission.Admit != nil {
			if err := admission.Admit(ctx); err != nil {
				writeRefusal(api, ctx, err)
				return
			}
		}
		limit, err := admission.Limit(ctx.Context())
		if err != nil {
			writeRefusal(api, ctx, WentWrong(in.Logger, "cannot tell what this deployment accepts", err))
			return
		}
		r, w := humachi.Unwrap(ctx)
		tooLarge := func() {
			_ = huma.WriteErr(api, ctx, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("the request is larger than the %d bytes an upload may be", limit))
		}
		if r.ContentLength > limit {
			tooLarge()
			return
		}
		most, err := setting.NewStore(in.DB.DB).Count(ctx.Context(),
			setting.UploadsAtOnce, setting.DefaultUploadsAtOnce)
		if err != nil {
			writeRefusal(api, ctx, WentWrong(in.Logger, "cannot tell what this deployment accepts", err))
			return
		}
		if !in.Uploads.take(int64(most)) {
			ctx.SetHeader("Retry-After", "5")
			_ = huma.WriteErr(api, ctx, http.StatusServiceUnavailable,
				"this deployment is receiving as many uploads as it takes at once; send again shortly")
			return
		}
		// Held until the handler returns, because the spooled files are
		// removed only once the request is answered.
		defer in.Uploads.give()

		r.Body = http.MaxBytesReader(w, r.Body, limit)
		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
			var over *http.MaxBytesError
			if err := r.ParseMultipartForm(humachi.MultipartMaxMemory); errors.As(err, &over) {
				tooLarge()
				return
			}
		}
		next(ctx)
	}
}

// writeRefusal answers with an error a handler returned, in the shape the
// framework gives a handler's answer.
func writeRefusal(api huma.API, ctx huma.Context, err error) {
	var se huma.StatusError
	if !errors.As(err, &se) {
		se = huma.NewError(http.StatusInternalServerError, "unexpected error occurred")
	}
	ct, negotiated := api.Negotiate(ctx.Header("Accept"))
	if negotiated != nil {
		ct = "application/json"
	}
	if filter, ok := se.(huma.ContentTypeFilter); ok {
		ct = filter.ContentType(ct)
	}
	ctx.SetHeader("Content-Type", ct)
	status := se.GetStatus()
	body, terr := api.Transform(ctx, strconv.Itoa(status), se)
	ctx.SetStatus(status)
	if terr != nil {
		return
	}
	_ = api.Marshal(ctx.BodyWriter(), ct, body)
}

// Fixed is a limit no setting moves.
func Fixed(most int64) func(context.Context) (int64, error) {
	return func(context.Context) (int64, error) { return most, nil }
}

// MaxUpload bounds a whole request, which is more than one document.
//
// A build sends an inventory and however many suppression documents it has, so
// the request ceiling is not the document ceiling. Twice leaves room for the
// suppressions without letting a request be unbounded.
func MaxUpload(limits sbom.Limits) int64 {
	return 2 * limits.OrDefault().MaxBytes
}
