package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/supplier"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// AdvisorySourceBody is one supplier this deployment reads advisories from.
type AdvisorySourceBody struct {
	Name string `json:"name" doc:"The name this supplier is configured under"`
	URL  string `json:"url" doc:"Where the supplier describes what they publish"`
	// Tried, Read, CaughtUpTo and Because say whether it is working, which is
	// the question an operator has about a source and one nothing else
	// answers.
	Tried      *time.Time `json:"tried,omitempty" doc:"When this supplier was last tried"`
	Read       *time.Time `json:"read,omitempty" doc:"When a read of this supplier last succeeded"`
	CaughtUpTo *time.Time `json:"caught_up_to,omitempty" doc:"The newest moment in what they list that has been read"`
	Because    string     `json:"because,omitempty" doc:"The reason the last attempt stopped, where one did"`
}

// registerAdvisorySources configures which suppliers this deployment reads
// published advisories from.
func registerAdvisorySources(api huma.API, in Ingest) {
	const path = "/v1/products/{product}/advisory-sources"

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-advisory-sources", Method: http.MethodGet, Path: path,
		Summary: "List the suppliers advisories are read from",
		Description: "The suppliers configured for this product, when each was last " +
			"tried, when one last succeeded, and how far through what they publish this " +
			"deployment has read.\n\n" +
			"Two moments rather than one. An attempt that failed still happened, so how " +
			"long a supplier has been unreachable is the gap between them; the reason the " +
			"last attempt stopped is returned beside them.",
		Tags: []string{"Administration"},
	}, deploymentWide, ""), func(ctx context.Context, input *struct {
		Product string `path:"product"`
	}) (*listOutput[AdvisorySourceBody], error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		by, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		product, err := catalog.NewStore(in.DB.DB).ProductByName(ctx, input.Product)
		if err != nil {
			return nil, absent(in.Logger, err, "that product could not be looked up", noSuchProduct)
		}
		rows, err := supplier.NewStore(in.DB.DB).For(ctx, by, product.ID)
		if err != nil {
			// Through asked rather than reported as a fault. The store refuses
			// anybody but an administrator too, and a refusal answered 500 is
			// a fault in the log for a rule working exactly as written.
			return nil, asked(in.Logger, err)
		}
		out := &listOutput[AdvisorySourceBody]{}
		out.Body.Items = make([]AdvisorySourceBody, 0, len(rows))
		for _, row := range rows {
			out.Body.Items = append(out.Body.Items, AdvisorySourceBody{
				Name: row.Display, URL: row.URL, Tried: row.FetchedAt,
				Read: row.ReachedAt, CaughtUpTo: row.CaughtUpTo, Because: row.Failed,
			})
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "add-advisory-source", Method: http.MethodPost, Path: path,
		Summary: "Read advisories from a supplier",
		Description: "Records a supplier whose published security advisories are read on " +
			"the scan schedule. What they say arrives as evidence beside a finding and a " +
			"prefill for a decision, and is never applied.\n\n" +
			"The address is the supplier's CSAF provider description, which names where " +
			"their advisories are listed. Both shapes the format defines are read: a ROLIE " +
			"feed and a directory of documents. Only the listings a publisher labels " +
			"TLP:WHITE or TLP:CLEAR are read.\n\n" +
			"Only claims naming a component this product ships are recorded.\n\n" +
			"Reading starts from the moment the supplier is added. To take an advisory " +
			"published before that, upload it.\n\n" +
			"A VEX document listed beside the advisories is not read here. Upload it to " +
			"the VEX endpoint to take it.\n\n" +
			"A supplier withdrawn and added again under the same name starts from today, " +
			"the way a new one does.\n\n" +
			"The name is matched without regard to capitals. A name already in use for " +
			"this product is refused with 409; withdraw the supplier first to change its " +
			"address.\n\n" +
			"The address must be https and carry no user information. A product that is " +
			"out of use takes no supplier.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusCreated,
	}, deploymentWide, ""), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Body    struct {
			Name string `json:"name" minLength:"1" maxLength:"191" doc:"The name this supplier is configured under"`
			URL  string `json:"url" minLength:"1" maxLength:"1000" doc:"The address of the supplier's CSAF provider description"`
		}
	}) (*struct {
		Status int
		Body   AdvisorySourceBody
	}, error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		by, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		product, err := catalog.NewStore(in.DB.DB).ProductByName(ctx, input.Product)
		if err != nil {
			return nil, absent(in.Logger, err, "that product could not be looked up", noSuchProduct)
		}
		// Normalized here so the stored value is the address as it parses. The
		// rule for what may be stored is the store's, where the rest of this
		// table's rules live.
		address := strings.TrimSpace(input.Body.URL)
		parsed, err := url.Parse(address)
		if err == nil {
			address = parsed.String()
		}
		var row *supplier.Source
		if err := changing(ctx, in.DB, in.logger(), func(ctx context.Context, tx bun.Tx) error {
			var err error
			row, err = supplier.NewStore(tx).Add(ctx, by, product.ID, input.Body.Name, address)
			switch {
			case errors.Is(err, supplier.ErrNameTaken):
				// Somebody adding the same supplier twice, which is an answer
				// rather than a fault: the row it collides with is one they
				// can see.
				return huma.Error409Conflict(
					"a supplier is already read under that name for this product")
			case err != nil:
				return asked(in.Logger, err)
			}
			// The host rather than the whole address, which is what an
			// administrator reading the trail needs: which publisher this
			// deployment started reading from.
			if err := noted(ctx, tx, trail.Setting,
				"advisory source · "+product.Name+" · "+row.Display,
				nil, trail.Said(hostOf(row.URL), true)); err != nil {
				return notRecorded(in.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct {
			Status int
			Body   AdvisorySourceBody
		}{Status: http.StatusCreated, Body: AdvisorySourceBody{Name: row.Display, URL: row.URL}}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "withdraw-advisory-source", Method: http.MethodDelete,
		Path:    path + "/{name}",
		Summary: "Stop reading a supplier",
		Description: "Stops reading a supplier. What they have already said stays " +
			"standing, because an approval may have been granted on the strength of it.\n\n" +
			"The name is matched without regard to capitals. A name no supplier is " +
			"configured under is refused with 404.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Name    string `path:"name"`
	}) (*struct{}, error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		by, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		product, err := catalog.NewStore(in.DB.DB).ProductByName(ctx, input.Product)
		if err != nil {
			return nil, absent(in.Logger, err, "that product could not be looked up", noSuchProduct)
		}
		if err := changing(ctx, in.DB, in.logger(), func(ctx context.Context, tx bun.Tx) error {
			// Mapped before the trail row, which would otherwise record a
			// withdrawal that did not happen — and the pass goes on reaching
			// out to a publisher somebody believes it has stopped reading.
			switch err := supplier.NewStore(tx).Retire(ctx, by, product.ID, input.Name); {
			case errors.Is(err, access.ErrNothingMatched):
				return huma.Error404NotFound("no supplier is read from under that name")
			case err != nil:
				return asked(in.Logger, err)
			}
			if err := noted(ctx, tx, trail.Setting,
				"advisory source · "+product.Name+" · "+input.Name,
				trail.Said("in use", true), nil); err != nil {
				return notRecorded(in.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	})
}

// hostOf is the host an address names, for a record that keeps what matters
// and not the rest of the path.
func hostOf(address string) string {
	parsed, err := url.Parse(address)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}
