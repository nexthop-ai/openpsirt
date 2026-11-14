// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// An admission that failed for a reason nobody classified is a fault: logged,
// and answered in fixed words that carry nothing the failure said.
func TestAnAdmissionFaultIsLoggedAndAnsweredInFixedWords(t *testing.T) {
	logged := &tally{}
	_, api := humatest.New(t)
	in := Deps{Logger: slog.New(logged)}
	huma.Register(api, huma.Operation{
		OperationID: "upload", Method: http.MethodPost, Path: "/upload",
		Middlewares: huma.Middlewares{BoundedForm(api, in, Admission{
			Admit: func(huma.Context) error {
				return errors.New("dial tcp 10.0.0.5:5432: connection refused")
			},
			Limit: Fixed(1 << 10),
		})},
	}, func(context.Context, *struct{}) (*struct{}, error) { return nil, nil })

	got := api.Post("/upload")
	if got.Code != http.StatusInternalServerError {
		t.Errorf("an admission fault answered %d", got.Code)
	}
	if strings.Contains(got.Body.String(), "10.0.0.5") {
		t.Errorf("an admission fault published what it said: %s", got.Body.String())
	}
	if logged.n == 0 {
		t.Error("an admission fault was not logged")
	}
}
