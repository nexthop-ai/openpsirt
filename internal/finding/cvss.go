package finding

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

// ErrNotAVector is what an unusable vector answers with.
//
// A sentinel because it is the caller's to fix rather than something that went
// wrong here, and the difference has to survive the trip up to the handler: a
// vector from a scheme this does not implement answered with "something went
// wrong" tells somebody to report a fault instead of to fix their input.
var ErrNotAVector = errors.New("that is not a vector this can score")

// A severity as a vector and the number derived from it.
//
// **The vector is what is recorded and the score is worked out from it**, so
// the two cannot disagree. Taking both from a caller would let somebody state
// a vector saying one thing and a number saying another, and there would be no
// way afterwards to know which they meant — the number is what sorts and the
// vector is what somebody can argue with.
//
// Only the base metrics. Temporal and environmental scores describe a moment
// and a deployment, and this deployment is not the one the finding is about:
// a score meaning "here, today" stored against a shipped release would be
// answering a question nobody asked of it.
type Scored struct {
	// Vector as it was given, normalized to upper case.
	Vector string
	// ScoreCenti is the base score in hundredths, so it sorts in an index and
	// compares the same on every engine.
	ScoreCenti int
	// Severity is the word the score falls in, by the published bands.
	Severity string
}

// The base metrics, and what each value weighs.
//
// Spelled as tables rather than as a switch so that the vector's grammar and
// its arithmetic are the same list: a metric added to one and forgotten in the
// other is the shape of a score that is wrong by a little and looks right.
var (
	attackVector     = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	attackComplexity = map[string]float64{"L": 0.77, "H": 0.44}
	userInteraction  = map[string]float64{"N": 0.85, "R": 0.62}
	impactOf         = map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	scopeValues      = map[string]bool{"U": true, "C": true}
	// Privileges weigh differently when the scope changes, which is the one
	// place in the base score where two metrics are not independent.
	privilegesUnchanged = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	privilegesChanged   = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
)

// Score reads a CVSS base vector and works out what it says.
//
// **Version 3.0 and 3.1 only, and anything else is refused by name.** They
// share a base formula; version 4 does not, and version 2 is a different
// scheme entirely. Scoring an unrecognized vector with whatever formula is to
// hand produces a number that looks like every other number here.
func Score(vector string) (*Scored, error) {
	vector = strings.ToUpper(strings.TrimSpace(vector))
	if vector == "" {
		return nil, nil
	}
	parts := strings.Split(vector, "/")
	if len(parts) < 2 || (parts[0] != "CVSS:3.1" && parts[0] != "CVSS:3.0") {
		return nil, fmt.Errorf(
			"%w: a score is worked out from a CVSS 3.0 or 3.1 base vector, and scoring "+
				"anything else with that formula would produce a number nothing could tell "+
				"apart from a real one", ErrNotAVector)
	}

	given := map[string]string{}
	for _, part := range parts[1:] {
		metric, value, found := strings.Cut(part, ":")
		if !found || metric == "" || value == "" {
			return nil, fmt.Errorf("%w: %q is not a metric and a value", ErrNotAVector, part)
		}
		if _, twice := given[metric]; twice {
			return nil, fmt.Errorf("%w: %s is given twice", ErrNotAVector, metric)
		}
		given[metric] = value
	}

	// Every base metric, all required. A vector missing one is not a base
	// vector, and filling in a default would be choosing the answer.
	for _, metric := range []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"} {
		if _, held := given[metric]; !held {
			return nil, fmt.Errorf("%w: it states no %s, and a base score needs all eight",
				ErrNotAVector, metric)
		}
	}

	changed := given["S"] == "C"
	privileges := privilegesUnchanged
	if changed {
		privileges = privilegesChanged
	}
	weights := []struct {
		metric string
		from   map[string]float64
	}{
		{"AV", attackVector}, {"AC", attackComplexity}, {"PR", privileges},
		{"UI", userInteraction}, {"C", impactOf}, {"I", impactOf}, {"A", impactOf},
	}
	value := map[string]float64{}
	for _, w := range weights {
		weight, known := w.from[given[w.metric]]
		if !known {
			return nil, fmt.Errorf("%w: %s:%s is not a value that metric takes",
				ErrNotAVector, w.metric, given[w.metric])
		}
		value[w.metric] = weight
	}
	if !scopeValues[given["S"]] {
		return nil, fmt.Errorf("%w: S:%s is not a value that metric takes", ErrNotAVector, given["S"])
	}

	iss := 1 - ((1 - value["C"]) * (1 - value["I"]) * (1 - value["A"]))
	impact := 6.42 * iss
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	exploitability := 8.22 * value["AV"] * value["AC"] * value["PR"] * value["UI"]

	score := 0.0
	if impact > 0 {
		raw := impact + exploitability
		if changed {
			raw *= 1.08
		}
		score = roundUp(math.Min(raw, 10))
	}
	return &Scored{
		Vector: vector, ScoreCenti: int(math.Round(score * 100)), Severity: bandOf(score),
	}, nil
}

// roundUp is CVSS 3.1's own rounding, which is not the language's.
//
// It rounds *up* to one decimal, and it is specified in integer arithmetic
// precisely because doing it in floating point gets a different answer for
// some inputs — 8.6 has no exact representation, so a naive ceiling of a
// value that should be exactly 8.6 returns 8.7.
func roundUp(x float64) float64 {
	scaled := int(math.Round(x * 100000))
	if scaled%10000 == 0 {
		return float64(scaled) / 100000
	}
	return (math.Floor(float64(scaled)/10000) + 1) / 10
}

// bandOf is the word a score falls in, by the published bands.
func bandOf(score float64) string {
	switch {
	case score == 0:
		return "none"
	case score < 4:
		return "low"
	case score < 7:
		return "medium"
	case score < 9:
		return "high"
	}
	return "critical"
}
