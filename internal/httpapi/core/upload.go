// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"

	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// BoundedForm caps how much of a multipart request is read at all.
//
// The operation's body limit applies to a body read whole. A form is read as
// it streams, part by part, with nothing above it: a part larger than the
// limit is spooled to the temporary directory in full before the document
// limit ever sees a byte of it, which is a disk somebody fills from outside.
// So the request body itself is capped here, and the form is parsed here,
// before the operation's own parsing runs — which then finds the form already
// read and reads nothing more. Anything other than the cap is left for that
// parsing to report, in its own terms.
func BoundedForm(api huma.API, limit int64) func(ctx huma.Context, next func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r, w := humachi.Unwrap(ctx)
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
			var tooLarge *http.MaxBytesError
			if err := r.ParseMultipartForm(humachi.MultipartMaxMemory); errors.As(err, &tooLarge) {
				_ = huma.WriteErr(api, ctx, http.StatusRequestEntityTooLarge,
					fmt.Sprintf("the request is larger than the %d bytes an upload may be", limit))
				return
			}
		}
		next(ctx)
	}
}

// MaxUpload bounds a whole request, which is more than one document.
//
// A build sends an inventory and however many suppression documents it has, so
// the request ceiling is not the document ceiling. Twice leaves room for the
// suppressions without letting a request be unbounded.
func MaxUpload(limits sbom.Limits) int64 {
	return 2 * limits.OrDefault().MaxBytes
}
