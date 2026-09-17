package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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

// ProductBody is a product as the API states it.
type ProductBody struct {
	Name        string `json:"name" minLength:"1" maxLength:"191" doc:"How scans name this product"`
	DisplayName string `json:"display_name,omitempty" maxLength:"191" doc:"What people see. Defaults to the name"`
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

// overPeriod is a listing that covers a stretch of time and says which.
//
// Its own shape rather than two more fields on every listing: most lists here
// are about now, and a from and a to on those would be two empty strings a
// reader has to work out the meaning of.
type overPeriod[T any] struct {
	Body struct {
		Items []T `json:"items"`
		Total int `json:"total,omitempty"`
		// The period these cover, said back, so a figure is never read apart
		// from the window it was worked out over.
		From string `json:"from,omitempty" doc:"The first day of the period. Absent where it runs from the beginning"`
		To   string `json:"to" doc:"The day it ends, which is not itself in it"`
	}
}

type listBody[T any] struct {
	Items []T `json:"items"`
	// Total is how many there are in all, where a listing is capped and the
	// caller would otherwise be unable to tell a clipped page from a complete
	// answer. Omitted by the listings that return everything.
	Total int `json:"total,omitempty"`
}

// registerCatalog registers the three groups the catalog is made of.
//
// They share the Declaring handle and nothing else. Declaring something is an
// administrator inventing a thing scans may be filed against; stating policy
// on it moves what is on a clock at all, away from the request; reading it
// answers what exists, narrowed to what the reader may see. One 531-line
// function held all three, which made the middle group — the four that
// silently rewrite what the tool reports — the hardest of the three to find.
func registerCatalog(api huma.API, d Declaring) {
	registerDeclaring(api, d)
	registerCatalogPolicy(api, d)
	registerCatalogReading(api, d)
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
		// Composed from the names the caller supplied and fixed words, which
		// is what makes it safe to publish: an administrator declaring under
		// a product that does not exist needs to know which name was wrong.
		return undeclared(nil, err, "")
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
