// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// DocumentUploadBody is one VEX document or supplier advisory that arrived for
// a product.
type DocumentUploadBody struct {
	ReceivedAt     string            `json:"received_at" format:"date-time" doc:"When it arrived"`
	Status         core.UploadStatus `json:"status" doc:"Completed where its statements were recorded, refused where it was turned away"`
	Reason         string            `json:"reason,omitempty" doc:"Why it was turned away, as the sender was told"`
	Publisher      string            `json:"publisher" doc:"The publisher the document names, as it is matched. Empty where it was turned away before that was read"`
	Identifier     string            `json:"identifier,omitempty" doc:"The name the publisher gave the advisory. Absent for a VEX document, which a publisher issues one of"`
	Document       string            `json:"document" doc:"The file name it was uploaded as, or the address a supplier feed fetched it from"`
	Digest         string            `json:"digest,omitempty" doc:"SHA-256 of what arrived. Absent where it was turned away before it was read whole"`
	UploadedBy     string            `json:"uploaded_by,omitempty" doc:"Who uploaded it: a person by sign-in identity, or an API key by name. Absent where a feed fetched it"`
	UploadedByName string            `json:"uploaded_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	FetchedBy      string            `json:"fetched_by,omitempty" doc:"The supplier whose feed fetched it. Absent where somebody uploaded it"`
	Recorded       int               `json:"recorded" doc:"Statements it recorded"`
	SetAside       int               `json:"set_aside" doc:"Statements an earlier copy of the same document made that it no longer did, kept and no longer applied"`
	Current        bool              `json:"current" doc:"Whether what it says is what stands: it was completed, and no later copy of the same document has been"`
}

// DocumentsOutput is a page of the documents of one kind that arrived for a
// product.
type DocumentsOutput struct {
	Body struct {
		Items []DocumentUploadBody `json:"items"`
		Total int                  `json:"total"`
	}
}

// documentsInput is a page of the documents one product holds.
type documentsInput struct {
	Product string `path:"product"`
	Limit   int    `query:"limit" default:"50" minimum:"1" maximum:"200" doc:"The number returned"`
	Offset  int    `query:"offset" minimum:"0" doc:"The number skipped"`
}

func registerDocuments(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-vex-documents", Method: http.MethodGet,
		Path:    "/v1/products/{product}/vex-statements",
		Summary: "List uploaded VEX documents",
		Description: "Returns every VEX document uploaded to this product, newest first, " +
			"taken or turned away: who uploaded it, what became of it, and how many " +
			"statements it recorded and set aside. The newest copy taken from each " +
			"publisher is marked `current`.\n\n" +
			"Uploads made before v0.11.0 are not listed. Their statements still apply.\n\n" +
			"Statements a trusted upstream publishes are listed with that upstream.",
		Tags: []string{"Ingest"},
	}, core.AnyPerson, "Answers for a product you may see."), documentsOf(in, finding.FromVex))

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-supplier-advisories", Method: http.MethodGet,
		Path:    "/v1/products/{product}/supplier-advisories",
		Summary: "List supplier advisories",
		Description: "Returns every supplier security advisory that arrived for this product, " +
			"newest first, taken or turned away: who uploaded it or which supplier feed " +
			"fetched it, what became of it, and how many statements it recorded and set " +
			"aside. The newest copy taken of each advisory is marked `current`.\n\n" +
			"Uploads made before v0.11.0 are not listed. Their statements still apply.\n\n" +
			"An advisory a feed fetched is listed where it said something about a component " +
			"this product ships, set aside something an earlier copy said, or arrived whole and was " +
			"turned away.",
		Tags: []string{"Ingest"},
	}, core.AnyPerson, "Answers for a product you may see."), documentsOf(in, finding.FromAdvisory))
}

// documentsOf answers a page of the documents of one kind that arrived for a
// product.
func documentsOf(in core.Deps, source string) func(context.Context, *documentsInput) (*DocumentsOutput, error) {
	return func(ctx context.Context, input *documentsInput) (*DocumentsOutput, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		product, err := core.ProductNamedVisibly(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		held, total, err := finding.NewStore(in.DB.DB).Uploads(ctx, subject, product.ID,
			source, input.Limit, input.Offset)
		if err != nil {
			return nil, core.Absent(in.Logger, err, "the documents could not be read", core.NoSuchProduct)
		}
		senders, err := sendersOf(ctx, in, held)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "who uploaded them could not be read", err)
		}
		out := &DocumentsOutput{}
		out.Body.Items, out.Body.Total = make([]DocumentUploadBody, 0, len(held)), total
		for _, u := range held {
			body := DocumentUploadBody{
				ReceivedAt: core.Stamp(u.ReceivedAt), Status: core.UploadStatus(u.Status),
				Publisher: u.Publisher, Identifier: u.Identifier, Document: u.Document,
				FetchedBy: u.Feed, Recorded: u.Recorded, SetAside: u.Superseded, Current: u.Current(),
			}
			body.Reason, body.Digest = core.OrBlank(u.Reason), core.OrBlank(u.Digest)
			if u.Credential != nil {
				body.UploadedBy, body.UploadedByName = senders.named(*u.Credential)
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		return out, nil
	}
}

// senders is the names of the people and keys that uploaded a page of
// documents.
type senders struct {
	people map[int64][2]string
	keys   map[int64]string
}

// named is a sender's identity and display name, or a key's name. A sender
// that cannot be read back names nobody.
func (s senders) named(credential string) (string, string) {
	switch kind, id, ok := access.SenderOf(credential); {
	case !ok:
		return "", ""
	case kind == access.Pipeline:
		return s.keys[id], ""
	default:
		return s.people[id][0], s.people[id][1]
	}
}

// sendersOf reads who uploaded each of a page of documents.
func sendersOf(ctx context.Context, in core.Deps, held []finding.Upload) (senders, error) {
	var people, keys []int64
	for _, u := range held {
		if u.Credential == nil {
			continue
		}
		switch kind, id, ok := access.SenderOf(*u.Credential); {
		case !ok:
		case kind == access.Pipeline:
			keys = append(keys, id)
		default:
			people = append(people, id)
		}
	}
	out := senders{people: map[int64][2]string{}}
	who, err := core.WhoSigned(ctx, in.DB.DB, people)
	if err != nil {
		return senders{}, err
	}
	for _, id := range people {
		out.people[id] = [2]string{who.Identity(id), who.Label(id)}
	}
	out.keys, err = database.NamesByID(ctx, in.DB.DB, `"api_key"`, `"name"`, keys)
	if err != nil {
		return senders{}, err
	}
	return out, nil
}
