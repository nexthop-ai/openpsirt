// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

func TestEachAdvisoryRefusalAnswersItsOwnStatus(t *testing.T) {
	// Each store refusal reaches one arm. A denial answers 403 rather than
	// the sentence at the end, a product nobody holds answers as an issue
	// that is not there, and anything unnamed is a fault in words of ours.
	in := core.Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for _, each := range []struct {
		err  error
		want int
	}{
		{advisory.ErrNoPublisher, http.StatusConflict},
		{advisory.ErrNoPrefix, http.StatusConflict},
		{advisory.ErrNotOurs, http.StatusUnprocessableEntity},
		{advisory.ErrAlreadyCovered, http.StatusUnprocessableEntity},
		{advisory.ErrNothingToSay, http.StatusUnprocessableEntity},
		{advisory.ErrAlreadyAgreed, http.StatusUnprocessableEntity},
		{advisory.ErrNothingAgreed, http.StatusUnprocessableEntity},
		{access.Denied("agree to an advisory"), http.StatusForbidden},
		{advisory.ErrSamePerson, http.StatusConflict},
		{advisory.ErrNotAgreed, http.StatusConflict},
		{advisory.ErrNoSuchAdvisory, http.StatusNotFound},
		{advisory.ErrNoSuchRelease, http.StatusNotFound},
		{advisory.ErrNoSuchIssue, http.StatusNotFound},
		{fmt.Errorf("product %q: %w", "elsewhere", catalog.ErrNotFound), http.StatusNotFound},
		{errors.New("the connection dropped"), http.StatusInternalServerError},
	} {
		got := advisoryRefused(in, fmt.Errorf("wrapped: %w", each.err), "that could not be done")
		var status huma.StatusError
		if !errors.As(got, &status) || status.GetStatus() != each.want {
			t.Errorf("%v answered %v, want %d", each.err, got, each.want)
		}
	}
}
