package httpapi

import (
	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// The closed vocabularies the API offers, built from the package that owns
// them.
//
// They were retyped as literals in struct tags, at eight sites with four
// memberships, so an outcome added to the domain was accepted by the store and
// refused by every route — and one route carried no list at all, which typed
// its field as a bare string where its neighbours gave a union. A subset is a
// named rule in `internal/triage` rather than a shorter literal here, so what
// is left out is stated and stays stated.

// words is a closed vocabulary as a schema, in the order the domain lists it.
func words[T ~string](all []T) *huma.Schema {
	offered := make([]any, 0, len(all))
	for _, each := range all {
		offered = append(offered, string(each))
	}
	return &huma.Schema{Type: huma.TypeString, Enum: offered}
}

// outcome is what somebody decided, any of them.
type outcome string

// Schema answers with every outcome the domain recognizes, in its order.
func (outcome) Schema(huma.Registry) *huma.Schema { return words(triage.Outcomes()) }

// outcomeOneAtATime is what one act may record against one finding.
type outcomeOneAtATime string

// Schema answers with the outcomes one act may record against one finding.
func (outcomeOneAtATime) Schema(huma.Registry) *huma.Schema {
	return words(triage.OutcomesOneAtATime())
}

// outcomeInBulk is what one act may record against many issues.
type outcomeInBulk string

// Schema answers with the outcomes one act may record against many issues.
func (outcomeInBulk) Schema(huma.Registry) *huma.Schema { return words(triage.OutcomesInBulk()) }

// justification is why something does not apply.
type justification string

// Schema answers with the reasons the exchange format defines.
func (justification) Schema(huma.Registry) *huma.Schema { return words(triage.Justifications()) }

// plainly is a repeatable query parameter's words as plain strings, which is
// what the stores take.
func plainly[T ~string](all []T) []string {
	out := make([]string, 0, len(all))
	for _, each := range all {
		out = append(out, string(each))
	}
	return out
}

// outcomeHidingRisk is what takes something out of the working queue, which is
// what needing a second person turns on.
type outcomeHidingRisk string

// Schema answers with the outcomes that hide risk.
func (outcomeHidingRisk) Schema(huma.Registry) *huma.Schema {
	return words(triage.OutcomesThatHideRisk())
}

// outcomeOffered is what a publisher's statement prefills, where it prefills
// one.
type outcomeOffered string

// Schema answers with the outcomes a statement can offer, derived from the
// mapping that decides which of them it is.
func (outcomeOffered) Schema(huma.Registry) *huma.Schema {
	return words(finding.OutcomesOffered())
}

// vexStatus is what a publisher said, in the exchange format's own vocabulary.
type vexStatus string

// Schema answers with the statuses the format defines.
func (vexStatus) Schema(huma.Registry) *huma.Schema { return words(finding.VexStatuses()) }

// origin is where a finding came from, as a narrowing.
type origin string

// Schema answers with the words the narrowing takes.
func (origin) Schema(huma.Registry) *huma.Schema { return words(finding.Origins()) }
