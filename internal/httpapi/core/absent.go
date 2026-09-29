// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// The words for a name that reaches nothing.
//
// One place, because several spellings of the same sentence include two that
// describe the wrong thing entirely — a missing person and a missing
// credential both answering "not declared", which names neither and reads as
// though the request were about a product.
//
// These are all 404, including for things somebody may not reach. A product
// somebody holds nothing on is invisible rather than merely unreadable, and
// telling "you may not see that" apart from "that does not exist" hands
// somebody holding one product the name of every other, by guessing and
// watching which guess answers differently.
//
// A few refusals are 403, and they are not exceptions to that. The rule is
// about existence: an answer that differs between "not there" and "not yours"
// is what a guesser reads. Where a name has *already* been resolved visibly —
// the catalog reads through VisibleProduct and answers 404 for a product
// nobody may see, before anything else is asked — the caller has been told the
// product exists because they may see it, and refusing what they then try to
// do reveals nothing they did not already have. The same holds for the two
// assessment routes: the store answers "no such assessment" for a claim about
// an issue the asker may not be told of, so a 403 means the claim is one they
// can see and the act is one they may not do.
//
// Read the other way round, the difference is: 404 answers a *name*, and 403
// answers an *act* on something already shown. A 403 in front of a name is the
// bug; a 404 in place of a refused act is a lie about what happened.
func NoSuchProduct() error {
	return huma.Error404NotFound("no product is declared by that name")
}

func NoSuchPerson() error {
	return huma.Error404NotFound("nobody here is called that")
}

// NoSuchGrant is the answer to withdrawing something nobody holds.
//
// A 404 rather than a 200: "this grant does not exist" and "this grant has
// been removed" are different answers, and only one of them means the caller
// should go on to record what it did. Answered as success, the trail gains a
// row saying a role was withdrawn that never existed, and every finding the
// person is dealing with in that product is handed back.
func NoSuchGrant() error {
	return huma.Error404NotFound("they do not hold that")
}

func NoSuchKey() error {
	return huma.Error404NotFound("no credential is recorded under that name")
}

func noSuchDecision() error {
	return huma.Error404NotFound("no decision is recorded there")
}

func NoSuchFinding() error {
	return huma.Error404NotFound("no open finding is recorded there")
}

func NoSuchIssue() error {
	return huma.Error404NotFound("no issue is known by that name")
}

// NoSuchNote answers a note that is not there, an issue this product cannot
// reach, and a name nobody has filed. Three questions, one sentence: told
// apart, a note route becomes a way to walk identifiers.
func NoSuchNote() error {
	return huma.Error404NotFound("no note is recorded there")
}

// NoSuchRule answers a routing rule nobody declared, and one belonging to a
// product the caller cannot reach.
func NoSuchRule() error {
	return huma.Error404NotFound("no routing rule is recorded there")
}

func NoSuchAssessment() error {
	return huma.Error404NotFound("no assessment is recorded there")
}

// Nobody is a person identifier no account can hold, for the reads that answer
// a name nobody holds exactly as they answer a name somebody holds whose work
// the caller cannot see.
//
// A number rather than a refusal, because the query is what has to come back
// empty. Refusing would restore the difference the whole rule exists to
// remove, and answering an empty list without asking the database would be a
// second spelling of "what this caller may see" to keep in step with the
// first.
const Nobody = int64(-1)

func NothingScannedThere() error {
	return huma.Error404NotFound("nothing has been scanned there")
}

// ComponentQuery is what picks one component where a name is not enough, on a
// route that addresses a finding by its component's name.
type ComponentQuery struct {
	Version   string `query:"version" doc:"The version, where the build ships that name at more than one"`
	Ecosystem string `query:"ecosystem" doc:"The ecosystem, for the few names one build holds at one version as two components — a source repository and the package built from it"`
	Namespace string `query:"namespace" doc:"The namespace, for the few names one build holds at one version in one ecosystem as two components — one package a producer described twice"`
}

// Choice is the query as the lookup takes it.
func (q ComponentQuery) Choice() graph.Choice {
	return graph.Choice{Version: q.Version, Ecosystem: q.Ecosystem, Namespace: q.Namespace}
}

// ComponentCarrying resolves the component a finding route names, narrowed
// where the name is ambiguous to the components this issue is open at.
//
// The lookup raises the ambiguity before it knows which issue is being asked
// about, so on its own it offers every component of the name, and a real image
// ships one library at fifteen versions of which three carry a given issue.
// Where one carries it, that one is taken: one choice is not a choice. none
// answers where none does.
func ComponentCarrying(ctx context.Context, in Deps, subject access.Subject,
	targetID, issue int64, name string, which graph.Choice, none func(error) error) (int64, error) {

	id, err := graph.NewStore(in.DB.DB).ComponentAs(ctx, targetID, name, which)
	// A part left out after one was named may have been read as "none" by
	// the lookup, which picks the component with nothing there. What carries
	// the issue has its say first: a link naming a version alone means the
	// component the issue is open at, and the twin with no identifier is the
	// answer only where nothing carries it.
	leftOut := which.Namespace == "" && (which.Version != "" || which.Ecosystem != "")
	if err == nil && !leftOut {
		return id, nil
	}
	if err != nil && !errors.Is(err, graph.ErrAmbiguous) {
		return 0, none(err)
	}
	all, second := finding.NewStore(in.DB.DB).VersionsWithIssue(ctx, subject, targetID, issue, name)
	if second != nil {
		// Logged rather than discarded. Silently falling through makes a
		// database failure indistinguishable from "the issue is at none of
		// them", and the caller gets the wide list with nothing saying why.
		in.Log().Error("which versions carry this issue could not be read",
			"component", name, "error", second)
	}
	// Only the ones the caller's own narrowing names: a version named and a
	// namespace left out is still a version named.
	var carrying []graph.Choice
	for _, i := range graph.Narrowed(which, all) {
		carrying = append(carrying, all[i])
	}
	switch {
	case len(carrying) == 1:
		id, err = graph.NewStore(in.DB.DB).ComponentAs(ctx, targetID, name, carrying[0])
		if err != nil {
			return 0, none(err)
		}
		return id, nil
	case len(carrying) > 1:
		return 0, ambiguousAmong(name, carrying)
	case err == nil:
		return id, nil
	default:
		return 0, none(err)
	}
}

// Answered is the status a refusal answers with, and zero for anything that is
// not one.
func Answered(err error) int {
	var refusal huma.StatusError
	if errors.As(err, &refusal) {
		return refusal.GetStatus()
	}
	return 0
}

// ambiguousAmong offers the ways a name could be meant, having narrowed them
// to the ones that answer the question being asked.
func ambiguousAmong(name string, choices []graph.Choice) error {
	detail := make([]error, 0, len(choices))
	for _, choice := range choices {
		detail = append(detail, &huma.ErrorDetail{
			// "carrying" rather than "component", because these have been
			// narrowed to the ones this issue is actually open at. The screen
			// says different things about the two, and saying the wrong one is
			// telling somebody an issue affects a version it does not.
			Location: "carrying", Message: choice.Version, Value: kindOf(choice),
		})
	}
	return huma.Error409Conflict(fmt.Sprintf(
		"this build ships %q as more than one component, and this issue is open at %d of "+
			"them — say which one with ?version=, &ecosystem= and &namespace=", name, len(choices)),
		detail...)
}

// kindOf is what tells a choice apart besides its version: the ecosystem, and
// the namespace where the identifier has one.
func kindOf(choice graph.Choice) map[string]string {
	kind := map[string]string{"ecosystem": choice.Ecosystem}
	if choice.Namespace != "" {
		kind["namespace"] = choice.Namespace
	}
	return kind
}

// AmbiguousOrMissing answers a component lookup that could not settle on one.
//
// A name matching several is a different answer from a name matching none: the
// first is something the caller can fix by saying which one, and the second is
// not. Telling them apart discloses nothing — whoever is asking has already
// been authorized to read this build.
func AmbiguousOrMissing(logger *slog.Logger, err error) error {
	// The choices as structured detail rather than a sentence listing them. A
	// real image ships one library at fifteen versions, and fifteen of them in
	// prose is a paragraph nobody reads — as a list the screen can offer each
	// as a link, which is the thing the reader actually wants. Naming them
	// discloses nothing further: the versions in a build are already readable
	// by anyone who can read the build.
	//
	// Each choice carries its ecosystem and namespace, because a version
	// alone does not always resolve one: 13 names in a real image are held at
	// one version by two components, a source repository and the package built
	// from it, and 170 in another by one package described under two
	// namespaces. Left as versions alone, the refusal offers a choice that
	// leads straight back to the same refusal.
	var several *graph.Ambiguous
	if errors.As(err, &several) {
		return SeveralComponents(several,
			"?version= and, where two share a version, &ecosystem= and &namespace=")
	}
	return Absent(logger, err, "that component could not be looked up", NoSuchFinding)
}

// SeveralComponents offers every way a name could be meant, and says how to
// pick one.
//
// The way to say which one differs by where the name arrived — a query
// parameter for a lookup, a body field for something being recorded — so the
// caller supplies that sentence and the list is built once.
func SeveralComponents(several *graph.Ambiguous, sayWith string) error {
	detail := make([]error, 0, len(several.Choices))
	for _, choice := range several.Choices {
		detail = append(detail, &huma.ErrorDetail{
			// Every component of that name, *not* narrowed to an issue —
			// which is why the location differs from the narrowed list above.
			// Some of these may not carry it at all.
			Location: "component", Message: choice.Version, Value: kindOf(choice),
		})
	}
	return huma.Error409Conflict(fmt.Sprintf(
		"this build ships %q as %d different components — say which one with %s",
		several.Name, len(several.Choices), sayWith), detail...)
}

// Absent turns a store error into the right answer: the caller's own 404 for a
// row that is not there, and a fault for a read that could not be made.
//
// One place, because the split made by hand at every call site is made
// correctly at a handful of them. Elsewhere a failed read answers as an
// authoritative negative, so a database nobody can reach tells every
// authenticated caller that their products, builds, issues and findings do not
// exist, with the driver's own message in some of the bodies.
//
// missing is the sentence for a name that reaches nothing, passed as the
// function rather than called, so a caller cannot build one from the error.
func Absent(logger *slog.Logger, err error, reading string, missing func() error) error {
	switch {
	// A refusal answers as a name that is not there, which is the rule at the
	// top of this file. Its own text names the product and the act, so it is
	// the fixed sentence that goes out and never the error.
	case errors.Is(err, access.ErrDenied):
		return missing()
	// The absence sentinels, named one at a time rather than matched by
	// shape. Each package words absence for itself, and a store that has not
	// been given a sentinel yet must fall through to the fault arm rather than
	// be guessed at — which is how a failed read turns into "that does not
	// exist".
	case errors.Is(err, catalog.ErrNotFound),
		errors.Is(err, finding.ErrNoSuchIssue),
		errors.Is(err, ingest.ErrNoScan),
		errors.Is(err, access.ErrNoSuchTeam),
		errors.Is(err, access.ErrNoSuchToken),
		errors.Is(err, finding.ErrNoSuchRun),
		errors.Is(err, finding.ErrNoOpenFinding),
		errors.Is(err, attach.ErrNoSuchIssue),
		errors.Is(err, access.ErrNoSuchPerson),
		errors.Is(err, graph.ErrNoComponent):
		return missing()
	default:
		return WentWrong(logger, reading, err)
	}
}

// Undeclared is absent for the paths where saying which part of an address did
// not resolve is the answer's whole value: a pipeline whose upload was refused
// has to know what to declare, and "no product is declared by that name" does
// not say whether the product, the branch or the variant was the problem.
//
// The one place a 404 body is built from an error here. It is reached only
// once the error is known to be the catalog's own ErrNotFound, whose message is
// composed from the names the caller supplied and fixed words — nothing a
// driver wrote can be in it. Everything else goes the ordinary way: a refusal
// gets the fixed sentence, and a read that could not be made is a fault rather
// than an authoritative negative.
func Undeclared(logger *slog.Logger, err error, reading string) error {
	if errors.Is(err, catalog.ErrNotFound) {
		return huma.Error404NotFound(err.Error())
	}
	return Absent(logger, err, reading, NoSuchProduct)
}

// ProductNamedVisibly resolves a product this subject may know exists.
//
// Paired with LocatedVisibly rather than folded into it: catalog.VisibleProduct
// asks whether the subject sees the product, and catalog.LocateVisible admits
// somebody brought into a case here as well. Two deliberately different
// contracts, and which one an endpoint wants is a security judgment — made by
// hand at every call site, it is invisible at all of them.
func ProductNamedVisibly(ctx context.Context, in Deps, subject access.Subject,
	name string) (*catalog.Product, error) {

	product, err := catalog.NewStore(in.DB.DB).VisibleProduct(ctx, subject, name)
	if err != nil {
		return nil, Absent(in.Logger, err, "that product could not be looked up", NoSuchProduct)
	}
	return product, nil
}

// ProductForIssue resolves a product for a route that is about one issue in
// it.
//
// The wider of the two rules here, and the pair is deliberate. A route about
// the product as a whole asks ProductNamedVisibly, which is what somebody may
// see; a route about one named issue asks this, which admits somebody brought
// into a case. Which of the two an endpoint wants is a security judgment, and
// made by hand at every call site it is visible at none — including one
// handler that applies both in a single request, so one answer about one
// subject and one product contradicts the other four lines later.
//
// Wider than ProductNamedVisibly by the case grants: somebody brought into one
// case holds nothing on the product and may still act on the issue they were
// brought in on, so refusing to resolve the product would refuse them the one
// thing they were granted while telling them nothing they did not already
// know. Every read past this still asks about the issue, which is where the
// case grant is honored again. It is the rule the catalog already applies when
// it resolves a build for somebody on a case.
func ProductForIssue(ctx context.Context, in Deps, subject access.Subject,
	name string) (*catalog.Product, error) {

	product, err := catalog.NewStore(in.DB.DB).ProductByName(ctx, name)
	if err != nil {
		return nil, Absent(in.Logger, err, "that product could not be looked up", NoSuchProduct)
	}
	if !subject.Sees(product.ID) && len(subject.Cases(product.ID)) == 0 {
		return nil, NoSuchProduct()
	}
	return product, nil
}

// LocatedVisibly resolves the three names a build is addressed by.
//
// The refusal is NoSuchProduct whichever of the three did not resolve. Which
// part of an address is wrong is a statement about what exists under the
// other two, and answering it turns the route into a way to walk the catalog.
func LocatedVisibly(ctx context.Context, in Deps, subject access.Subject,
	product, stream, variant string) (*catalog.Named, error) {

	named, err := catalog.NewStore(in.DB.DB).LocateVisible(ctx, subject, product, stream, variant)
	if err != nil {
		return nil, Absent(in.Logger, err, "that build could not be looked up", NoSuchProduct)
	}
	return named, nil
}

// VisibleBuild is the reader and the build a route is about: the build
// resolved as the reader may see it and required to have been scanned.
func VisibleBuild(ctx context.Context, in Deps, product, stream, variant string) (access.Subject, int64, error) {
	subject, err := Reading(ctx)
	if err != nil {
		return access.Subject{}, 0, err
	}
	if in.DB == nil {
		return access.Subject{}, 0, NoDatabase(in.Logger)
	}
	target, err := TargetIDOf(ctx, in, subject, product, stream, variant)
	if err != nil {
		return access.Subject{}, 0, err
	}
	return subject, target, nil
}

// TargetIDOf is the build a route is about, resolved and required to have been
// scanned.
//
// One function rather than a closure copied into three report routes, so that
// "the names do not resolve" and "nothing has been filed here" stay two
// answers: the first is a typo and the second is a build waiting for its first
// scan, and a reader can act on only one of them.
func TargetIDOf(ctx context.Context, in Deps, subject access.Subject,
	product, stream, variant string) (int64, error) {

	named, err := LocatedVisibly(ctx, in, subject, product, stream, variant)
	if err != nil {
		return 0, err
	}
	target, err := TargetRow(ctx, in, named.StreamID, named.VariantID)
	if err != nil {
		return 0, err
	}
	return target.ID, nil
}

// TargetRow is the build a pair of names was already resolved to, required to
// have been scanned.
//
// "Nothing has been scanned there" is an answer about the build. A read that
// could not be made does not support it, and this is the reader with the most
// callers in the tree — nearly all of which answer 404.
func TargetRow(ctx context.Context, in Deps, streamID, variantID int64) (*catalog.Target, error) {
	target, err := catalog.NewStore(in.DB.DB).ExistingTarget(ctx, streamID, variantID)
	if err != nil {
		return nil, Absent(in.Logger, err, "that build could not be looked up", NothingScannedThere)
	}
	return target, nil
}

// IssueHere resolves an issue named in a path about a place, and answers as
// though the name were unused wherever the subject may not read a finding of
// it in this product.
//
// One helper rather than a check at each route, because the shape that leaks
// is the ordering — resolve the name, then check what it reached — and every
// route here has that shape. Written once so a new route gets it by using the
// resolver rather than by remembering the rule.
//
// The refusal is NoSuchFinding, which is what these routes already answer when
// the place is not one the caller may read. That is the point: the two have to
// be the same sentence, or the difference between them is the disclosure.
func IssueHere(ctx context.Context, in Deps, subject access.Subject,
	productID int64, name string) (int64, error) {

	issue, err := finding.NewVulnerabilities(in.DB.DB).ByName(ctx, name)
	if err != nil {
		return 0, Absent(in.Logger, err, "that issue could not be looked up", NoSuchFinding)
	}
	told, err := finding.NewStore(in.DB.DB).MayBeToldOfIn(ctx, subject, productID, issue)
	if err != nil {
		return 0, WentWrong(in.Logger, "that could not be looked up", err)
	}
	if !told {
		return 0, NoSuchFinding()
	}
	return issue, nil
}

// IssuesHere is IssueHere for a list of names: what each resolves to, and the
// names, as the caller spelled them, that are filed nowhere or only where the
// subject may not read a finding of them in this product.
//
// The two go into one list because they have to be answered in the same
// words. A name filed where the caller may not look, answered differently
// from a name nobody filed, is a lookup that counts what is kept quiet.
func IssuesHere(ctx context.Context, in Deps, subject access.Subject,
	productID int64, names []string) (map[string]int64, []string, error) {

	found, err := finding.NewVulnerabilities(in.DB.DB).IDsByName(ctx, names)
	if err != nil {
		return nil, nil, WentWrong(in.Logger, "which issues these are could not be read", err)
	}
	ids := make([]int64, 0, len(found))
	for _, id := range found {
		ids = append(ids, id)
	}
	told, err := finding.NewStore(in.DB.DB).ToldOfIn(ctx, subject, productID, ids)
	if err != nil {
		return nil, nil, WentWrong(in.Logger, "that could not be looked up", err)
	}
	here := make(map[string]int64, len(found))
	var unknown []string
	for _, name := range names {
		id, ok := found[name]
		if !ok || !told[id] {
			unknown = append(unknown, name)
			continue
		}
		here[name] = id
	}
	return here, unknown, nil
}

// NarrowedTo resolves an optional product name a list narrows by.
//
// Empty is every product, which is what a list asks for when nothing is
// selected. A name nobody holds answers as a name nobody has declared, for the
// reason every other product lookup does.
func NarrowedTo(ctx context.Context, in Deps, subject access.Subject,
	name string) (int64, error) {

	if name == "" {
		return 0, nil
	}
	product, err := ProductNamedVisibly(ctx, in, subject, name)
	if err != nil {
		return 0, err
	}
	return product.ID, nil
}
