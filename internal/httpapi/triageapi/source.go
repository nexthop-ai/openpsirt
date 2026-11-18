// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// SourceRuleBody is what a correction by source paths names.
type SourceRuleBody struct {
	Package string   `json:"package" doc:"The package it answers, by the name it is identified by, in lower case"`
	Source  string   `json:"source" doc:"The source package that package is matched through, in lower case"`
	Paths   []string `json:"paths" doc:"The paths within the source the package is built from, in byte order"`
}

// sourceRule reads what a decision names where it is a correction by source
// paths, for a caller that has read the decision.
func sourceRule(ctx context.Context, store *triage.Store, decisionID int64) (*SourceRuleBody, error) {
	rule, err := store.SourceOf(ctx, decisionID)
	if err != nil || rule == nil {
		return nil, err
	}
	return &SourceRuleBody{Package: rule.Package, Source: rule.Source, Paths: rule.PathList()}, nil
}

func registerSourceCorrection(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "correct-by-source-paths", Method: http.MethodPost,
		Path:    "/v1/products/{product}/source-corrections",
		Summary: "Propose a correction by source paths",
		Description: "Records that a package is not the rest of the source it is built from: a " +
			"wrong match answering every issue the package is matched through that source for, " +
			"where the issue's CVE record lists the files it is in and every one of them lies " +
			"outside the paths the package is built from. linux-perf, matched through linux and " +
			"built from tools/perf, tools/lib and tools/include, is the case.\n\n" +
			"It answers in this product only, at every version, and keeps answering issues " +
			"published later as scans report them. It never answers an issue whose record lists " +
			"no files or any file under the paths, a finding matched on the package's own name " +
			"or a CPE, an undisclosed finding, or an issue this product records an incident " +
			"through; those stay for a person.\n\n" +
			"The reason is one of the two saying something is not there, and the reasoning is " +
			"required. A second person agrees, always; until then it answers nothing, and an " +
			"issue answered after the reasoning changes waits for agreement again. It ends only " +
			"when withdrawn, and is published as not affected with its reason.\n\n" +
			"Refused where nothing open in the product is answered by it now. Each answer " +
			"records the files that justified it, read back as `answered_on` on the decision's " +
			"occurrences.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, core.PerProduct, "", core.TriageRights()...), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Body    struct {
			Package       string                `json:"package" minLength:"1" maxLength:"191" doc:"The package answered, by the name it is identified by, such as linux-perf"`
			Source        string                `json:"source" minLength:"1" maxLength:"191" doc:"The source package it is matched through, such as linux"`
			Paths         []string              `json:"paths" minItems:"1" maxItems:"64" doc:"The paths within the source the package is built from, such as tools/perf, each at most 1,024 bytes. A file under any of them is one the package may hold"`
			Justification core.CorrectionReason `json:"justification" doc:"Why the issues are not there"`
			Reasoning     string                `json:"reasoning" minLength:"1" doc:"The reasoning, in markdown, holding for every issue it answers"`
		}
	}) (*struct {
		Body struct {
			DecisionID int64 `json:"decision_id" doc:"The decision recorded, which is what the review queue lists and what is approved"`
			Answered   int   `json:"answered" doc:"The occurrences it answers now, each waiting for a second person"`
		}
	}, error) {
		in := core.Of(ctx, in)
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		product, err := core.TriagedProduct(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		proposed, err := store.ProposeBySource(ctx, subject, triage.SourceProposal{
			ProductID: product.ID, Package: input.Body.Package, Source: input.Body.Source,
			Paths:         input.Body.Paths,
			Justification: triage.Justification(input.Body.Justification),
			Reasoning:     input.Body.Reasoning, By: subject.ID,
		})
		if err != nil {
			if errors.Is(err, triage.ErrNothingMatchedThrough) {
				return nil, huma.Error422UnprocessableEntity(err.Error() +
					"; check the package and source names against a finding, or name fewer paths")
			}
			return nil, core.RefusedDecision(in.Logger, err)
		}
		out := &struct {
			Body struct {
				DecisionID int64 `json:"decision_id" doc:"The decision recorded, which is what the review queue lists and what is approved"`
				Answered   int   `json:"answered" doc:"The occurrences it answers now, each waiting for a second person"`
			}
		}{}
		out.Body.DecisionID, out.Body.Answered = proposed.DecisionID, proposed.Answered
		return out, nil
	})
}
