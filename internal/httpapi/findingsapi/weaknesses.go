// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/weakness"
)

// WeaknessesOutput is the weaknesses a lookup names.
type WeaknessesOutput struct {
	Body struct {
		Items []core.WeaknessBody `json:"items"`
	}
}

// registerWeaknesses is the lookup a picker and a filter name weaknesses
// through.
//
// It reads no finding, so there is nothing to narrow: the catalog is public,
// and the screen's own names are a vocabulary rather than a record.
func registerWeaknesses(api huma.API) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-weaknesses", Method: http.MethodGet, Path: "/v1/weaknesses",
		Summary: "Look up weaknesses",
		Description: "Names weaknesses from the CWE catalog, each with a short name where it is " +
			"a common one.\n\n" +
			"`id` names exactly the identifiers given, in the order given, whether or not " +
			"either list holds them: one neither holds comes back with no names.\n\n" +
			"`q` searches. Digits, with or without `CWE-`, find every identifier whose number " +
			"begins with them, the one typed exactly first. Words find every weakness whose " +
			"catalog name and short name together hold each of them, without regard to " +
			"capitals. Nothing typed answers the common weaknesses. Matches come most common " +
			"first: the common ones in their own order, then the rest by number.\n\n" +
			"A request carrying both `id` and `q` is refused. Reads no finding.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Answers from the catalog, and reads no finding."), func(ctx context.Context, input *struct {
		IDs   []string `query:"id,explode" maxItems:"200" doc:"Identifiers to name, such as CWE-787"`
		Q     string   `query:"q" maxLength:"200" doc:"A number or words to search for"`
		Limit int      `query:"limit" minimum:"1" maximum:"100" default:"25" doc:"The most matches a search answers"`
	}) (*WeaknessesOutput, error) {
		if _, err := core.Reading(ctx); err != nil {
			return nil, err
		}
		out := &WeaknessesOutput{}
		if len(input.IDs) > 0 {
			if input.Q != "" {
				return nil, huma.Error422UnprocessableEntity(
					"name weaknesses by id or search them with q, not both")
			}
			out.Body.Items = core.Weaknesses(input.IDs)
			return out, nil
		}
		found := weakness.Find(input.Q, database.APicker.Of(input.Limit))
		out.Body.Items = make([]core.WeaknessBody, 0, len(found))
		for _, one := range found {
			out.Body.Items = append(out.Body.Items, core.WeaknessOf(one))
		}
		return out, nil
	})
}
