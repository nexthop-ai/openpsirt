// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// OwnCaseBody is one case the caller was brought into.
type OwnCaseBody struct {
	Product     string `json:"product" doc:"The product the case is in"`
	ProductName string `json:"product_name,omitempty" doc:"The label shown for the product, where it differs from its name"`
	Issue       string `json:"issue" doc:"The issue the case is about"`
	AddedAt     string `json:"added_at" doc:"When they were brought in"`
}

// OwnCodeFindingBody is one code finding recorded as a flaw the caller was
// granted.
type OwnCodeFindingBody struct {
	Product         string `json:"product" doc:"The product the code finding is in"`
	ProductName     string `json:"product_name,omitempty" doc:"The label shown for the product, where it differs from its name"`
	BranchOrTag     string `json:"branch_or_tag" doc:"The branch or tag of the build the code finding was last seen in"`
	BranchOrTagName string `json:"branch_or_tag_name,omitempty" doc:"The label shown for the branch or tag, where it differs from its name"`
	Variant         string `json:"variant" doc:"The variant of the build the code finding was last seen in"`
	VariantName     string `json:"variant_name,omitempty" doc:"The label shown for the variant, where it differs from its name"`
	Occurrence      string `json:"occurrence" doc:"The code finding's occurrence identity"`
	Rule            string `json:"rule" doc:"The rule that reported the code finding"`
	Path            string `json:"path" doc:"The file the code finding is in"`
	Flaw            string `json:"flaw" doc:"The flaw the code finding was recorded as"`
	AddedAt         string `json:"added_at" doc:"When they were granted it"`
}

// OwnCasesBody is everything the caller was granted one at a time.
type OwnCasesBody struct {
	Cases        []OwnCaseBody        `json:"cases" doc:"The cases they were brought into, newest first"`
	CodeFindings []OwnCodeFindingBody `json:"code_findings" doc:"The code findings recorded as a flaw they were granted, newest first, while the flaw is undisclosed"`
}

func registerOwnCases(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-own-cases", Method: http.MethodGet, Path: "/v1/session/me/cases",
		Summary: "List your cases",
		Description: "Returns the cases the caller was brought into, one issue in one product each, and the " +
			"code findings recorded as a flaw they were granted, one occurrence in one product each.\n\n" +
			"A code finding is listed while its flaw is undisclosed: disclosure ends the grant. A withdrawn " +
			"grant is not listed. A pipeline key is refused with 403.",
		Tags: []string{"Access"},
	}, core.OwnSubject, ""), func(ctx context.Context, _ *struct{}) (*struct{ Body OwnCasesBody }, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		cases, codeFindings, err := finding.NewStore(in.DB.DB).OwnCases(ctx, subject)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "your cases could not be read", err)
		}
		body := OwnCasesBody{Cases: []OwnCaseBody{}, CodeFindings: []OwnCodeFindingBody{}}
		for _, row := range cases {
			body.Cases = append(body.Cases, OwnCaseBody{
				Product: row.Product, ProductName: core.LabelBeside(row.ProductName, row.Product),
				Issue: row.Issue, AddedAt: core.Stamp(row.AddedAt),
			})
		}
		for _, row := range codeFindings {
			body.CodeFindings = append(body.CodeFindings, OwnCodeFindingBody{
				Product: row.Product, ProductName: core.LabelBeside(row.ProductName, row.Product),
				BranchOrTag:     row.BranchOrTag,
				BranchOrTagName: core.LabelBeside(row.BranchOrTagName, row.BranchOrTag),
				Variant:         row.Variant, VariantName: core.LabelBeside(row.VariantName, row.Variant),
				Occurrence: row.Occurrence, Rule: row.Rule, Path: row.Path, Flaw: row.Flaw,
				AddedAt: core.Stamp(row.AddedAt),
			})
		}
		return &struct{ Body OwnCasesBody }{Body: body}, nil
	})
}
