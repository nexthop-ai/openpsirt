package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"log/slog"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// Declaring is what the catalog endpoints need.
//
// Everything a scan is filed against is declared before it can be targeted, so
// this has to be reachable from whatever cuts a branch — a step that can only
// be done by hand is the step every pipeline works around.
type Declaring struct {
	Store  func() *catalog.Store
	Logger *slog.Logger
	// Findings and Scans answer what is open against a catalog entry and
	// when it was last scanned. A list of names alone makes somebody open
	// every row to find out whether there is anything behind it, which is the
	// question the list exists to answer.
	Findings func() *finding.Store
	Scans    func() *ingest.Store
	// RewriteDeadlines applies a changed line to what is already open,
	// away from the request. Moving what a product triages moves what is
	// on a clock at all, so it invalidates stored deadlines for the same
	// reason changing a window does — and it goes through the same
	// one-replica-at-a- time path, because two rewrites racing is the same
	// problem whichever setting started them.
	RewriteDeadlines func(ctx context.Context, what, value string)
	// Trail records an administrative change. A support date takes the
	// deadline off everything past it, which is one of the three levers
	// that silently rewrite what the tool reports.
	Trail func() *trail.Store
}

// reading is who a handler is answering, where the answer is something to
// read.
//
// A pipeline is refused rather than shown an empty list. A key may send scans
// and nothing else, and answering "here is nothing" is a different statement
// from "you cannot ask" — the first invites a caller to believe the list is
// empty.
func reading(ctx context.Context) (access.Subject, error) {
	subject, err := requester(ctx)
	if err != nil {
		return access.Subject{}, err
	}
	if subject.Kind != access.Person {
		return access.Subject{}, huma.Error403Forbidden("not authorized")
	}
	return subject, nil
}

// requester is who a handler is answering, resolved once before it ran.
//
// Nothing here reaches for a request or a header: resolution happens in one
// place for every route, so a handler cannot answer for everybody by
// forgetting to ask.
func requester(ctx context.Context) (access.Subject, error) {
	subject, err := access.From(ctx)
	if err != nil {
		// Nobody is attached, which for a route behind the resolver means
		// nobody was recognized. The same answer whoever they are.
		return access.Subject{}, huma.Error401Unauthorized("not authorized")
	}
	return subject, nil
}

// ProductBody is a product as the API states it.
type ProductBody struct {
	Name        string `json:"name" minLength:"1" maxLength:"191" doc:"How scans name this product"`
	DisplayName string `json:"display_name,omitempty" doc:"What people see. Defaults to the name"`
	// What the product holds, so a catalog answers what exists rather than
	// making somebody open each row to find out. Counts of what is open are
	// issues at components, the way the findings list counts, so the two
	// agree; a declaration returns them as zero because it has just been made.
	Branches int `json:"branches,omitempty" doc:"How many branches are declared"`
	Tags     int `json:"tags,omitempty" doc:"How many tags are declared"`
	Variants int `json:"variants,omitempty" doc:"How many variants are declared"`
	Open     int `json:"open,omitempty" doc:"Issues open against it, counted at components rather than at every place they sit"`
	// LastScanAt is absent where nothing has ever been filed against any of
	// this product's builds.
	LastScanAt string `json:"last_scan_at,omitempty" doc:"When a scan last arrived for any of its builds"`
	// TriageFloor is what this product considers worth triaging where it has
	// said something of its own. Absent means it follows the deployment, which
	// is a different statement from stating the same word — a product that
	// stated it would stop following when the deployment changed its mind.
	TriageFloor string `json:"triage_floor,omitempty" enum:"everything,low,medium,high,critical" doc:"What this product considers worth triaging, where it says something other than the deployment. Absent means it follows the deployment"`
	// EndOfLife is when support ends for every release that has not stated its
	// own. Absent means nothing has said one, which reads as supported.
	EndOfLife string `json:"end_of_life,omitempty" doc:"The date support ends for releases that have not stated their own, as YYYY-MM-DD"`
}

// EndOfLifeBody is when something goes out of support.
type EndOfLifeBody struct {
	// On is the date, written as a calendar date rather than a moment: support
	// ends on a day. Empty clears it — for a release that means following its
	// product again, and for a product that means nothing has said one.
	On string `json:"on" pattern:"^(\\d{4}-\\d{2}-\\d{2})?$" doc:"The date support ends, as YYYY-MM-DD, or empty to clear it"`
}

// TriageFloorBody is what a product considers worth triaging.
type TriageFloorBody struct {
	// Floor is the least severity worth triaging here, "everything" for a
	// product that hides nothing, or empty to follow the deployment.
	Floor string `json:"floor" enum:"everything,low,medium,high,critical," doc:"The least severity worth triaging here, \"everything\" to hide nothing, or empty to follow the deployment"`
}

// StreamBody is a branch or a tag.
type StreamBody struct {
	Name string `json:"name" minLength:"1" maxLength:"191" doc:"How scans name this branch or tag"`
	Kind string `json:"kind" enum:"branch,tag" doc:"Whether this line moves. A branch is rebuilt; a tag never changes"`
	// Parent is the branch a tag was cut from, which is what lets a branch be
	// compared against its last release.
	Parent string `json:"parent,omitempty" doc:"For a tag, the branch it was cut from"`
	// ReleasedOn is the day a tag actually went out, where somebody said. It
	// is what orders the release-over-release chart, because the day a release
	// was recorded here is an accident of administration.
	ReleasedOn string `json:"released_on,omitempty" doc:"For a tag, the day it went out, as YYYY-MM-DD. Absent where nobody has said, and the day it was declared here stands in"`
	// Open and LastScanAt, for the same reason the product list carries them:
	// a line that has stopped being built looks identical to a healthy one
	// until somebody opens it.
	Open       int    `json:"open,omitempty" doc:"Issues open against it, counted at components rather than at every place they sit"`
	LastScanAt string `json:"last_scan_at,omitempty" doc:"When a scan last arrived for any build of it"`
	// EndOfLife is the date support ends and whether this release stated it.
	// Absent with Inherited set means it follows its product; absent with
	// neither means nothing has said one anywhere.
	EndOfLife string `json:"end_of_life,omitempty" doc:"The date support ends, as YYYY-MM-DD"`
	// EndOfLifeInherited says the date shown came from the product rather than
	// from this release. Following a date and stating the same one are
	// different things: a release that stated it would stop following.
	EndOfLifeInherited bool `json:"end_of_life_inherited,omitempty" doc:"The date shown is the product's, not this release's own"`
}

// VariantBody is one of the ways a stream is built.
type VariantBody struct {
	Name string `json:"name" minLength:"1" maxLength:"191" doc:"How scans name this build of the stream"`
	// CustomerFacing is a pointer so that leaving it out is not the same as
	// saying no. An unclassified artifact should rank as though it ships,
	// which means the default is yes and silence must not read as a denial.
	CustomerFacing *bool `json:"customer_facing,omitempty" doc:"Whether this reaches customers. Defaults to yes"`
	Open           int   `json:"open,omitempty" doc:"Issues open against it here, counted at components rather than at every place they sit"`
}

// declaredOutput reports what a declaration did.
type declaredOutput[T any] struct {
	Status int
	Body   declared[T]
}

type declared[T any] struct {
	// Created says whether this declaration made something. Declaring the same
	// thing twice succeeds, so a caller that needs to know reads this.
	Created bool `json:"created"`
	Item    T    `json:"item"`
}

type listOutput[T any] struct {
	Body listBody[T]
}

type listBody[T any] struct {
	Items []T `json:"items"`
}

func registerCatalog(api huma.API, d Declaring) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "declare-product", Method: http.MethodPost, Path: "/v1/products",
		Summary: "Create a product",
		Description: "Records a product so scans may be filed against it. Declaring one that " +
			"already exists succeeds without changing anything, so this can run on every build.",
		Tags: []string{"Catalog"}, DefaultStatus: http.StatusCreated,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Body ProductBody
	}) (*declaredOutput[ProductBody], error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		store, err := storeFor(d)
		if err != nil {
			return nil, err
		}
		product, created, err := store.EnsureProduct(ctx, in.Body.Name, in.Body.DisplayName)
		if err != nil {
			return nil, declineDeclaration(err)
		}
		return answer(created, ProductBody{Name: product.Name, DisplayName: product.DisplayName}), nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "declare-stream", Method: http.MethodPost, Path: "/v1/products/{product}/streams",
		Summary: "Create a branch or tag",
		Description: "Records a line of a product. A branch moves and is rebuilt; a tag never " +
			"changes and is what somebody received.",
		Tags: []string{"Catalog"}, DefaultStatus: http.StatusCreated,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Body    StreamBody
	}) (*declaredOutput[StreamBody], error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		store, err := storeFor(d)
		if err != nil {
			return nil, err
		}
		product, err := store.ProductByName(ctx, in.Product)
		if err != nil {
			return nil, huma.Error404NotFound(err.Error())
		}

		var parentID *int64
		if in.Body.Parent != "" {
			parent, err := store.StreamByName(ctx, product.ID, in.Body.Parent)
			if err != nil {
				return nil, huma.Error404NotFound(err.Error())
			}
			parentID = &parent.ID
		}

		stream, created, err := store.EnsureStream(ctx, product.ID, in.Body.Name,
			catalog.Kind(in.Body.Kind), parentID)
		if err != nil {
			return nil, declineDeclaration(err)
		}
		return answer(created, StreamBody{
			Name: stream.DisplayName, Kind: string(stream.Kind), Parent: in.Body.Parent,
		}), nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "declare-variant", Method: http.MethodPost,
		Path:    "/v1/products/{product}/variants",
		Summary: "Create a build variant",
		Description: "Records one of the parallel builds of a product — a chip variant, an " +
			"architecture, an operating system. Declared once for the product, not once per " +
			"release: a release is filed against it the first time a scan arrives, so nobody " +
			"restates the list and no release ends up with the name spelled differently.",
		Tags: []string{"Catalog"}, DefaultStatus: http.StatusCreated,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Body    VariantBody
	}) (*declaredOutput[VariantBody], error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		store, err := storeFor(d)
		if err != nil {
			return nil, err
		}
		product, err := store.ProductByName(ctx, in.Product)
		if err != nil {
			return nil, huma.Error404NotFound(err.Error())
		}

		facing := true
		if in.Body.CustomerFacing != nil {
			facing = *in.Body.CustomerFacing
		}
		variant, created, err := store.EnsureVariant(ctx, product.ID, in.Body.Name, facing)
		if err != nil {
			return nil, declineDeclaration(err)
		}
		return answer(created, VariantBody{Name: variant.DisplayName, CustomerFacing: &variant.CustomerFacing}), nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-products", Method: http.MethodGet, Path: "/v1/products",
		Summary: "List products",
		Description: "Lists the products declared here, with what each one holds.\n\n" +
			"A scan may only be filed against something declared, so this is the first question " +
			"to ask after an upload is refused for naming something unknown.",
		Tags: []string{"Catalog"},
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, _ *struct{}) (*listOutput[ProductBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		store, err := storeFor(d)
		if err != nil {
			return nil, err
		}
		rows, err := store.Products(ctx, subject)
		if err != nil {
			return nil, wentWrong(d.Logger, "cannot list products", err)
		}

		ids := make([]int64, 0, len(rows))
		for _, row := range rows {
			ids = append(ids, row.ID)
		}
		shapes, err := store.Shapes(ctx, subject, ids)
		if err != nil {
			return nil, wentWrong(d.Logger, "cannot count what the products hold", err)
		}
		open, err := d.Findings().OpenBy(ctx, subject, finding.Scope{}, finding.ByProduct)
		if err != nil {
			return nil, wentWrong(d.Logger, "cannot count what is open", err)
		}
		// When each product was last scanned comes from the same answer the
		// home page reads, rather than a second query that could disagree
		// with it about which build counts.
		seen, err := lastScans(ctx, d.Scans(), subject)
		if err != nil {
			return nil, wentWrong(d.Logger, "cannot read when these were last scanned", err)
		}

		out := &listOutput[ProductBody]{}
		out.Body.Items = make([]ProductBody, 0, len(rows))
		for _, row := range rows {
			shape := shapes[row.ID]
			out.Body.Items = append(out.Body.Items, ProductBody{
				Name: row.Name, DisplayName: row.DisplayName,
				Branches: shape.Branches, Tags: shape.Tags, Variants: shape.Variants,
				Open:        open[row.ID],
				LastScanAt:  seen[row.Name],
				TriageFloor: stated(row.TriageFloor),
				EndOfLife:   onDate(row.EOLOn),
			})
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "set-product-triage-floor", Method: http.MethodPut,
		Path:    "/v1/products/{product}/triage-floor",
		Summary: "Set what a product considers worth triaging",
		Description: "Sets the least severity worth triaging for one product, overriding what " +
			"the deployment says. Below the line a finding is still recorded, still counted and " +
			"still reportable, and it carries no deadline — it is out of the working list, not " +
			"out of the system.\n\n" +
			"An empty value clears the override, so the product follows the deployment again. " +
			"Clearing is not the same as stating the deployment's current line: a product that " +
			"stated it would stop following when the deployment changed.\n\n" +
			"Deadlines are rewritten afterwards, away from the request, because moving the line " +
			"moves what is on a clock at all. The response returns before that has finished.",
		Tags: []string{"Catalog"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Body    TriageFloorBody
	}) (*struct{}, error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		// The same words the deployment's line takes, checked the same way. A
		// product that could be set to something the deployment could not
		// would be a second vocabulary for one idea.
		word := strings.TrimSpace(strings.ToLower(in.Body.Floor))
		if word != "" && !slices.Contains(theFloor, word) {
			return nil, huma.Error422UnprocessableEntity(
				fmt.Sprintf("%q is not a line to triage from — write one of %s, "+
					"or nothing at all to follow the deployment",
					in.Body.Floor, strings.Join(theFloor, ", ")))
		}
		store, err := storeFor(d)
		if err != nil {
			return nil, err
		}
		product, err := store.ProductByName(ctx, in.Product)
		if err != nil {
			return nil, huma.Error404NotFound(err.Error())
		}
		if err := store.SetTriageFloor(ctx, product.ID, word); err != nil {
			return nil, wentWrong(d.Logger, "that line could not be recorded", err)
		}
		if d.RewriteDeadlines != nil {
			d.RewriteDeadlines(ctx, "triage floor of product "+product.Name, word)
		}
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "set-product-end-of-life", Method: http.MethodPut,
		Path:    "/v1/products/{product}/end-of-life",
		Summary: "Set when a product goes out of support",
		Description: "Sets the date support ends for every release of a product that has not " +
			"stated its own. Past it, nothing on the product carries a remediation deadline and " +
			"a build that stops being scanned is expected rather than a fault.\n\n" +
			"Nothing is deleted or hidden: the findings and the history stay, and stay " +
			"reportable. What ends is what is expected of us.\n\n" +
			"An empty date clears it, because extended support happens. Deadlines are rewritten " +
			"afterwards, away from the request; the response returns before that has finished.",
		Tags: []string{"Catalog"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Body    EndOfLifeBody
	}) (*struct{}, error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		on, err := aDate(in.Body.On)
		if err != nil {
			return nil, err
		}
		store, err := storeFor(d)
		if err != nil {
			return nil, err
		}
		product, err := store.ProductByName(ctx, in.Product)
		if err != nil {
			return nil, huma.Error404NotFound(err.Error())
		}
		before := product.EOLOn
		if err := store.SetProductEndOfLife(ctx, product.ID, on); err != nil {
			return nil, wentWrong(d.Logger, "that date could not be recorded", err)
		}
		noteDeclared(ctx, d, trail.Support, product.Name, onDay(before), onDay(on))
		if d.RewriteDeadlines != nil {
			d.RewriteDeadlines(ctx, "end of life of product "+product.Name, in.Body.On)
		}
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "set-release-details", Method: http.MethodPut,
		Path:    "/v1/products/{product}/streams/{stream}/release",
		Summary: "Set when a release went out and what it was cut from",
		Description: "Records the day a tag actually shipped, and the branch it was cut " +
			"from.\n\n" +
			"**Both are settable after the fact, because that is when they are usually " +
			"known.** A tag is declared here so scans can be filed against it, which happens " +
			"whenever somebody gets to it — before the release, months after, or while " +
			"backfilling a year. Fixed at declaration, a release recorded late ordered after " +
			"ones that came out before it, and a year entered in an afternoon plotted as a " +
			"single day.\n\n" +
			"The date orders and labels the release-over-release chart. Left unset, the day " +
			"the release was declared here stands in.\n\n" +
			"**The parent fills in, and never changes.** It is what a branch is " +
			"compared against for release notes, and a pipeline that does not know declares " +
			"the tag without it — so saying it late is the same act arriving late, because " +
			"nothing had been said for it to contradict. Naming a different branch is refused, " +
			"and so is clearing one: a tag is one frozen point and it came from wherever it " +
			"came from. It is a branch and nothing is cut from itself; both are refused rather " +
			"than stored, because a cycle here is a comparison that never returns.\n\n" +
			"An empty date clears the date. An empty parent leaves whatever stands alone.",
		Tags: []string{"Catalog"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Body    struct {
			ReleasedOn string `json:"released_on" doc:"The day it went out, as 2026-03-31. Empty clears it, and the day it was declared here stands in"`
			CutFrom    string `json:"cut_from,omitempty" doc:"The branch it was cut from, by name. Fills in where nothing has been said; naming a different one is refused, and empty leaves whatever stands alone"`
		}
	}) (*struct{}, error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		on, err := aDate(in.Body.ReleasedOn)
		if err != nil {
			return nil, err
		}
		store, err := storeFor(d)
		if err != nil {
			return nil, err
		}
		product, err := store.ProductByName(ctx, in.Product)
		if err != nil {
			return nil, huma.Error404NotFound(err.Error())
		}
		stream, err := store.StreamByName(ctx, product.ID, in.Stream)
		if err != nil {
			return nil, huma.Error404NotFound(err.Error())
		}
		if named := strings.TrimSpace(in.Body.CutFrom); named != "" {
			from, err := store.StreamByName(ctx, product.ID, named)
			if err != nil {
				return nil, huma.Error404NotFound(err.Error())
			}
			if err := store.FillInParent(ctx, stream.ID, from.ID); err != nil {
				return nil, asked(d.Logger, err)
			}
		}
		if err := store.SetReleasedOn(ctx, stream.ID, on); err != nil {
			return nil, wentWrong(d.Logger, "that date could not be recorded", err)
		}
		noteDeclared(ctx, d, trail.Release, product.Name+" "+stream.Name,
			onDay(stream.ReleasedOn), onDay(on))
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "set-stream-end-of-life", Method: http.MethodPut,
		Path:    "/v1/products/{product}/streams/{stream}/end-of-life",
		Summary: "Set when a branch or tag goes out of support",
		Description: "Sets the date support ends for one release, overriding what its product " +
			"says. Past it, nothing on the release carries a remediation deadline and a build " +
			"that stops being scanned is expected rather than a fault.\n\n" +
			"An empty date clears the override, so the release follows its product again. " +
			"Clearing is not the same as stating the product's current date: a release that " +
			"stated it would stop following when the product changed.",
		Tags: []string{"Catalog"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Body    EndOfLifeBody
	}) (*struct{}, error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		on, err := aDate(in.Body.On)
		if err != nil {
			return nil, err
		}
		store, err := storeFor(d)
		if err != nil {
			return nil, err
		}
		product, err := store.ProductByName(ctx, in.Product)
		if err != nil {
			return nil, huma.Error404NotFound(err.Error())
		}
		stream, err := store.StreamByName(ctx, product.ID, in.Stream)
		if err != nil {
			return nil, huma.Error404NotFound(err.Error())
		}
		before := stream.EOLOn
		if err := store.SetStreamEndOfLife(ctx, stream.ID, on); err != nil {
			return nil, wentWrong(d.Logger, "that date could not be recorded", err)
		}
		noteDeclared(ctx, d, trail.Support, product.Name+" "+stream.Name,
			onDay(before), onDay(on))
		if d.RewriteDeadlines != nil {
			d.RewriteDeadlines(ctx, "end of life of "+product.Name+" "+stream.Name, in.Body.On)
		}
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-streams", Method: http.MethodGet, Path: "/v1/products/{product}/streams",
		Summary: "List a product's branches and tags",
		Description: "Every stream declared under this product, with how many variants each " +
			"has and how much is open in it.\n\n" +
			"A stream is a branch or a tag: a branch is scanned nightly and superseded, a " +
			"tag is immutable and kept. Both are declared before a scan may name one, so a " +
			"typo in a pipeline is refused rather than quietly creating a line with findings " +
			"and reports of its own.\n\n" +
			"A stream past its end-of-life date is listed and says so. It stops being a " +
			"place a fix may be declared for, and what is open against it is still counted.",
		Tags: []string{"Catalog"},
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, in *struct {
		Product string `path:"product"`
	}) (*listOutput[StreamBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		store, err := storeFor(d)
		if err != nil {
			return nil, err
		}
		product, err := store.VisibleProduct(ctx, subject, in.Product)
		if err != nil {
			return nil, huma.Error404NotFound(err.Error())
		}
		rows, err := store.Streams(ctx, subject, product.ID)
		if err != nil {
			return nil, refused(d.Logger, err, "cannot list streams")
		}
		open, err := d.Findings().OpenBy(ctx, subject, finding.Scope{ProductID: &product.ID}, finding.ByStream)
		if err != nil {
			return nil, wentWrong(d.Logger, "cannot count what is open", err)
		}
		seen, err := lastScansIn(ctx, d.Scans(), subject, product.ID, func(c ingest.Coverage) string {
			return c.Stream
		})
		if err != nil {
			return nil, wentWrong(d.Logger, "cannot read when these were last scanned", err)
		}

		// The product's date, read once, so a release that has not stated one
		// shows what actually applies to it rather than a blank that reads as
		// "supported for ever".
		// What each tag was cut from, by name. The rows carry the parent as an
		// identifier and this list never resolved it, so the column reporting
		// it was empty whatever the data said — which reads as "none of these
		// was cut from anything" and is what release readiness depends on.
		named := make(map[int64]string, len(rows))
		for _, row := range rows {
			named[row.ID] = row.Name
		}

		out := &listOutput[StreamBody]{}
		out.Body.Items = make([]StreamBody, 0, len(rows))
		for _, row := range rows {
			body := StreamBody{
				Name: row.Name, Kind: string(row.Kind),
				Open: open[row.ID], LastScanAt: seen[row.Name],
			}
			if row.ParentID != nil {
				body.Parent = named[*row.ParentID]
			}
			body.ReleasedOn = onDate(row.ReleasedOn)
			switch {
			case row.EOLOn != nil:
				body.EndOfLife = onDate(row.EOLOn)
			case product.EOLOn != nil:
				body.EndOfLife, body.EndOfLifeInherited = onDate(product.EOLOn), true
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-variants", Method: http.MethodGet,
		Path:    "/v1/products/{product}/variants",
		Summary: "List a product's build variants",
		Description: "Every variant declared under this product, with how much is open in " +
			"each.\n\n" +
			"A variant is a way one release is built — a hardware platform, a flavor — and " +
			"it is independent of the branch: every stream may be built as any of them. One " +
			"variant is the ordinary case, and the interface hides the dimension where there " +
			"is only one.\n\n" +
			"Each says whether it is customer-facing, which feeds how urgent a finding in it " +
			"is, and defaults to customer-facing where nobody has said.",
		Tags: []string{"Catalog"},
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, in *struct {
		Product string `path:"product"`
	}) (*listOutput[VariantBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		store, err := storeFor(d)
		if err != nil {
			return nil, err
		}
		product, err := store.VisibleProduct(ctx, subject, in.Product)
		if err != nil {
			return nil, huma.Error404NotFound(err.Error())
		}
		rows, err := store.Variants(ctx, subject, product.ID)
		if err != nil {
			return nil, refused(d.Logger, err, "cannot list variants")
		}
		open, err := d.Findings().OpenBy(ctx, subject, finding.Scope{ProductID: &product.ID}, finding.ByVariant)
		if err != nil {
			return nil, wentWrong(d.Logger, "cannot count what is open", err)
		}
		list := variantList(rows)
		for i := range list.Body.Items {
			list.Body.Items[i].Open = open[rows[i].ID]
		}
		return list, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-release-variants", Method: http.MethodGet,
		Path:    "/v1/products/{product}/streams/{stream}/variants",
		Summary: "List the variants a release was built as",
		Description: "Lists the variants one release was actually built as — a subset of what " +
			"the product declares.\n\n" +
			"A release predating a variant has never been filed against it and does not list " +
			"it, which is what keeps something introduced later from appearing to have shipped " +
			"years ago.",
		Tags: []string{"Catalog"},
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
	}) (*listOutput[VariantBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		store, err := storeFor(d)
		if err != nil {
			return nil, err
		}
		_, stream, err := store.VisibleStream(ctx, subject, in.Product, in.Stream)
		if err != nil {
			return nil, huma.Error404NotFound(err.Error())
		}
		rows, err := store.BuiltAs(ctx, subject, stream.ID)
		if err != nil {
			return nil, refused(d.Logger, err, "cannot list what a release is built as")
		}
		// Counted within this stream rather than across the product. The list
		// of what a release was built as carried no count at all, so every
		// screen drawing the column drew zeroes — including for a variant
		// holding twenty-five, which reads as a clean build rather than as a
		// number nobody filled in.
		productID := stream.ProductID
		open, err := d.Findings().OpenBy(ctx, subject,
			finding.Scope{ProductID: &productID, StreamID: &stream.ID}, finding.ByVariant)
		if err != nil {
			return nil, wentWrong(d.Logger, "cannot count what is open", err)
		}
		list := variantList(rows)
		for i := range list.Body.Items {
			list.Body.Items[i].Open = open[rows[i].ID]
		}
		return list, nil
	})
}

// variantList renders variants for a response.
func variantList(rows []catalog.Variant) *listOutput[VariantBody] {
	out := &listOutput[VariantBody]{}
	out.Body.Items = make([]VariantBody, 0, len(rows))
	for _, row := range rows {
		facing := row.CustomerFacing
		out.Body.Items = append(out.Body.Items, VariantBody{Name: row.Name, CustomerFacing: &facing})
	}
	return out
}

// refused turns a refusal from the data layer into one the caller sees as a
// refusal. Anything else is a fault here rather than a decision about them.
func refused(logger *slog.Logger, err error, what string) error {
	if errors.Is(err, access.ErrDenied) {
		return huma.Error403Forbidden("not authorized")
	}
	return wentWrong(logger, what, err)
}

// administrating refuses anybody who is not an administrator.
//
// Declaring what exists is administration: it decides what scans may be filed
// against and what every later grant is written in terms of. A pipeline cannot
// do it at all, and neither can somebody who merely reads — a role on a
// product says what they may see in it, not that they may invent another.
func administrating(ctx context.Context) error {
	subject, err := requester(ctx)
	if err != nil {
		return err
	}
	if !subject.Admin {
		return huma.Error403Forbidden("not authorized")
	}
	return nil
}

// mintingCredentials is administrating, for the two acts that create a
// credential outliving whoever asked.
//
// **A credential may not mint another**. That already
// held for a personal token issuing a token, and it was got around by what an
// administrator's token could make instead: recording a person — an
// administrator, even — and creating a pipeline key. Both outlive the token
// and neither is bounded by it, so the narrow credential could always ask for
// a wide one.
//
// Only these two. The rest of administration is reversible by another
// administrator and leaves the record every change here leaves; creating a
// credential is the one that hands out a new way in.
func mintingCredentials(ctx context.Context) error {
	if err := administrating(ctx); err != nil {
		return err
	}
	subject, err := requester(ctx)
	if err != nil {
		return err
	}
	if subject.Delegated() {
		return huma.Error403Forbidden(
			"a credential cannot create another — sign in to record a person or create a key")
	}
	return nil
}

// storeFor gives the handlers a catalog, or says plainly that this process
// has none.
func storeFor(d Declaring) (*catalog.Store, error) {
	if d.Store == nil {
		return nil, noDatabase(d.Logger)
	}
	store := d.Store()
	if store == nil {
		return nil, noDatabase(d.Logger)
	}
	return store, nil
}

// answer reports a declaration, distinguishing one that made something from
// one that found it already there.
func answer[T any](created bool, item T) *declaredOutput[T] {
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	return &declaredOutput[T]{Status: status, Body: declared[T]{Created: created, Item: item}}
}

// declineDeclaration turns a refusal into the answer that describes it.
func declineDeclaration(err error) error {
	switch {
	case errors.Is(err, catalog.ErrDiffers):
		// Declared before, meaning something else. Answering with success
		// would let a pipeline quietly redefine what a name refers to.
		return huma.NewError(http.StatusConflict, err.Error())
	case errors.Is(err, catalog.ErrNotFound):
		return huma.Error404NotFound(err.Error())
	default:
		return huma.Error400BadRequest(err.Error())
	}
}

// lastScans is when a scan last arrived for each product, by product name.
//
// It reads the same answer the front page reads rather than asking a question
// of its own: two queries about when something was last scanned are two
// numbers that can disagree, and the one on the catalog would be the one
// nobody checks.
func lastScans(ctx context.Context, scans *ingest.Store, subject access.Subject) (map[string]string, error) {
	rows, err := scans.Scanning(ctx, subject, finding.Scope{}, 0)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]string, len(rows))
	for _, row := range rows {
		if row.LastReceivedAt == nil {
			continue
		}
		at := stamp(*row.LastReceivedAt)
		// The newest across a product's builds. Rows arrive quietest first,
		// so the last one to win is the most recent.
		if at > seen[row.Product] {
			seen[row.Product] = at
		}
	}
	return seen, nil
}

// lastScansIn is the same within one product, keyed by whichever level the
// caller is listing.
// Narrowed in the query rather than filtered afterwards, so a deployment with
// many products does not read every build to answer about one.
func lastScansIn(ctx context.Context, scans *ingest.Store, subject access.Subject, productID int64,
	key func(ingest.Coverage) string) (map[string]string, error) {

	rows, err := scans.Scanning(ctx, subject, finding.Scope{ProductID: &productID}, 0)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]string, len(rows))
	for _, row := range rows {
		if row.LastReceivedAt == nil {
			continue
		}
		if at := stamp(*row.LastReceivedAt); at > seen[key(row)] {
			seen[key(row)] = at
		}
	}
	return seen, nil
}

// stated reads an override that may be absent as the word it states, or as
// nothing where the product has no opinion of its own.
func stated(word *string) string {
	if word == nil {
		return ""
	}
	return *word
}

// aDate reads a calendar date, or nothing where one was cleared.
//
// A date rather than a moment: support ends on a day, and keeping a time of
// day would make "past" depend on the hour a deployment happened to be asked.
func aDate(written string) (*time.Time, error) {
	if strings.TrimSpace(written) == "" {
		return nil, nil
	}
	on, err := time.Parse(time.DateOnly, strings.TrimSpace(written))
	if err != nil {
		return nil, huma.Error422UnprocessableEntity(
			fmt.Sprintf("%q is not a date — write it as YYYY-MM-DD, or leave it empty to clear",
				written))
	}
	return &on, nil
}

// onDate reads a date that may be absent as the day it names.
func onDate(on *time.Time) string {
	if on == nil {
		return ""
	}
	return on.UTC().Format(time.DateOnly)
}
