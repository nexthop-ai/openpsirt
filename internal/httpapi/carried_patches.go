package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// CarriedClaimBody is one thing a build says it deals with itself, and how
// long it has been saying so.
type CarriedClaimBody struct {
	Vulnerability string `json:"vulnerability" doc:"The identifier the build argued about, as it wrote it"`
	Subject       string `json:"subject" doc:"The claim's subject — a package name, or its identifier where it named no name"`
	Status        string `json:"status" doc:"The claim, in the exchange format's own vocabulary"`
	Justification string `json:"justification,omitempty"`
	Statement     string `json:"statement,omitempty" doc:"The build's own reasoning, shown as written and never rendered"`
	// Pedigree is the one that matters here: a claim attached to a component
	// is a carried patch declaring what it fixes, which is the only way a
	// backport can be seen at all.
	Pedigree bool `json:"pedigree" doc:"The claim arrived attached to a component — a carried patch saying what it fixes — rather than in a document of its own"`
	// Suppresses says the claim takes a finding off the list rather than
	// merely recording what the build thinks.
	Suppresses bool   `json:"suppresses" doc:"Whether it takes a finding off the list. 'affected' and 'under investigation' are information, not answers"`
	Since      string `json:"since" doc:"The scan the build first said it in"`
	Until      string `json:"until,omitempty" doc:"The moment it stopped saying it. Absent while it is still being said"`
}

// registerCarried answers what a build declares it deals with itself.
//
// The one thing a version comparison can never see. A distribution carries a
// fix into a package without moving its version, and the only evidence is the
// build saying so in its own inventory. Stored and read by nothing a person
// can reach, the start and the persistence of a carried patch are facts held
// only in the database.
func registerCarried(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-carried-patches", Method: http.MethodGet,
		Path: "/v1/products/{product}/streams/{stream}/variants/{variant}" +
			"/carried-patches",
		Summary: "List what a build says it deals with itself",
		Description: "Everything this build has argued about in its own inventories: carried " +
			"patches saying what they fix, and statements it sent alongside.\n\n" +
			"A history rather than a list of what is true tonight. Each row says when the " +
			"build first said it and when it stopped, because a claim that stopped is the " +
			"interesting one — somebody dropped a patch, and the finding it answered is " +
			"back. A list of what is current would not have that row at all.\n\n" +
			"A carried patch is the only way a backport can be seen here. No version " +
			"comparison finds one: the fix is in the package and the version has not moved, " +
			"so unless the build declares it, the finding sits open with nothing true to say " +
			"about it.\n\n" +
			"`suppresses` says whether a claim takes a finding off the list. Saying it is " +
			"affected, or that it has not decided, is information rather than an answer.\n\n" +
			"Narrow to one package with `component`, matched on what the claim says it is " +
			"about rather than on a component this build carries — a claim naming something " +
			"that is no longer here is exactly the row somebody asking why a patch stopped " +
			"working is looking for.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Stream    string `path:"stream"`
		Variant   string `path:"variant"`
		Component string `query:"component" doc:"Narrow to what one package was claimed about"`
		Paging
	}) (*struct {
		Body struct {
			Items []CarriedClaimBody `json:"items"`
			Total int                `json:"total" doc:"The total, so a page says what it is a page of"`
		}
	}, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		located, err := locatedVisibly(ctx, in, subject, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		target, err := targetRow(ctx, in, located.StreamID, located.VariantID)
		if err != nil {
			return nil, err
		}
		rows, total, err := finding.NewStore(in.DB.DB).CarriedPatches(ctx, subject, target.ID,
			input.Component, input.Limit, input.Offset)
		if err != nil {
			return nil, refusedFinding(in, err)
		}
		out := &struct {
			Body struct {
				Items []CarriedClaimBody `json:"items"`
				Total int                `json:"total" doc:"The total, so a page says what it is a page of"`
			}
		}{}
		out.Body.Total = total
		out.Body.Items = make([]CarriedClaimBody, 0, len(rows))
		for _, row := range rows {
			body := CarriedClaimBody{
				Vulnerability: row.Vulnerability, Subject: row.Subject,
				Status: row.Status, Justification: row.Justification,
				Statement: row.Statement, Pedigree: row.Pedigree,
				Suppresses: row.Suppresses,
				Since:      row.Since.Format(time.DateOnly),
			}
			if row.Until != nil {
				body.Until = row.Until.Format(time.DateOnly)
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		return out, nil
	})
}
