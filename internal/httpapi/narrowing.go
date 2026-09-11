package httpapi

import (
	"context"
	"errors"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// errNoProduct is the fault this reports rather than dereferencing nothing:
// every caller reaches it with a product named in the path, so an absent one
// is a route registered without one rather than anything a caller did.
var errNoProduct = errors.New("no product in scope")

// listing is everything a handler answering about one product's findings works
// out before it asks its question: who is asking, which builds that means, the
// line the product triages at, the filter, and the store to ask.
type listing struct {
	Subject access.Subject
	Scope   finding.Scope
	Floor   finding.Floor
	Filter  finding.Filter
	Store   *finding.Store
}

// narrowing does the eight steps every such handler does, in the order they
// have to happen in.
//
// Copied at five sites before this. The cost of that is on the record: a
// hand-copied version of the mapping left nineteen filters out, with no error,
// so a screen's Export link produced a file answering a different question
// than the screen it came from — and a filter that changes the population
// rather than narrowing it, like asking for what has closed, silently produced
// a file that could not contain a single row of what was asked for. A sixth
// copy is a sixth chance at that, and the parts that must not be forgotten —
// the floor, the whole filter, the subtree resolution — are exactly the parts
// a copy drops quietly.
//
// The scope is resolved and authorized together, so a product somebody may not
// see reads as one that was never declared. A selection matching no build —
// declared and never scanned — comes back empty from the store rather than as
// a refusal: nothing is open because nothing has run.
//
// `whyFloor` is what a failure reading the line says, because two of these
// answer a list and three answer a file and the sentence differs.
func narrowing(ctx context.Context, in Ingest, q ScopeQuery,
	at AtOneBuild, by Narrowing, whyFloor string) (listing, error) {

	var out listing
	subject, scope, floor, err := scopedFloor(ctx, in, q, whyFloor)
	if err != nil {
		return out, err
	}
	out.Subject, out.Scope, out.Floor = subject, scope, floor

	// The list's own mapping, not a second one written beside it.
	filter, err := by.filter(floor)
	if err != nil {
		return out, err
	}
	filter.DiffersBetweenBuilds = at.Differs
	out.Store = finding.NewStore(in.DB.DB)
	if filter.Beneath, err = beneathIn(ctx, in, scope, at.Beneath); err != nil {
		return out, err
	}
	out.Filter = filter
	return out, nil
}

// scopedFloor is the first half of that, for a handler that builds its own
// filter out of parameters of its own rather than taking the list's.
//
// Who is asking, which builds that means, and the line the product triages at,
// in the order they have to happen in: the scope is what says the product
// exists and may be reached, and the line is read against the product the
// scope resolved to.
func scopedFloor(ctx context.Context, in Ingest, q ScopeQuery,
	whyFloor string) (access.Subject, finding.Scope, finding.Floor, error) {

	var none finding.Scope
	subject, err := reading(ctx)
	if err != nil {
		return access.Subject{}, none, finding.Floor{}, err
	}
	if in.DB == nil {
		return access.Subject{}, none, finding.Floor{}, noDatabase(in.Logger)
	}
	scope, err := scoped(ctx, in, subject, q)
	if err != nil {
		return subject, none, finding.Floor{}, err
	}
	// One dereference rather than one per site. Every caller reaches this
	// with a product named in the path, which is what makes the pointer safe
	// — and naming that once is better than assuming it at each.
	if scope.ProductID == nil {
		return subject, scope, finding.Floor{}, wentWrong(in.Logger, whyFloor, errNoProduct)
	}
	floor, err := finding.FloorFor(ctx, in.DB.DB, *scope.ProductID)
	if err != nil {
		return subject, scope, finding.Floor{}, wentWrong(in.Logger, whyFloor, err)
	}
	return subject, scope, floor, nil
}

// tell records one notification, and says so where it cannot.
//
// Telling somebody is never what the request was for, so a failure here does
// not fail the act: the work stays assigned, the claim stays sent back, the
// agreement stays undone. What it must not do is disappear — an operator whose
// notification writes are failing finds out from a log line, and each call
// site had written its own.
//
// `why` is the sentence for that line and `about` the pairs that say which
// act it was, in the logger's own key-and-value form.
func tell(ctx context.Context, in Ingest, why string, telling notify.Telling, about ...any) {
	if err := notify.NewStore(in.DB.DB).Tell(ctx, telling); err != nil && in.Logger != nil {
		in.Logger.Error(why, append([]any{"error", err}, about...)...)
	}
}
