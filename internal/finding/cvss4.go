package finding

import (
	"fmt"
	"math"
	"strings"
)

// Version 4 scoring.
//
// The base score is a lookup rather than an equation. Every vector falls into
// one of a few hundred equivalence classes — a MacroVector — each of which
// carries a published score, and a vector's own score is that class's score
// less how far the vector sits from the worst member of its class. The tables
// below are the published ones; the arithmetic between them is the published
// procedure.
//
// Scoring is over the base metrics, so the threat and environmental metrics
// take the values the scheme defines for them when they are unstated:
// exploitation Attacked, and all three requirements High.

// baseFour is every metric a version 4 base vector states, all required.
var baseFour = []string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}

// The values each base metric takes, and how far down its own scale each one
// sits. The distance is what separates two vectors inside one equivalence
// class, so the values and the ordering are one table rather than two.
//
// A tenth per step, carried as the fraction the scheme states rather than as a
// step count multiplied afterwards. A tenth has no exact representation, so
// summing three of them and multiplying three by one are different numbers,
// and the scheme's published procedure sums.
var levelsFour = map[string]map[string]float64{
	"AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
	"AC": {"L": 0.0, "H": 0.1},
	"AT": {"N": 0.0, "P": 0.1},
	"PR": {"N": 0.0, "L": 0.1, "H": 0.2},
	"UI": {"N": 0.0, "P": 0.1, "A": 0.2},
	"VC": {"H": 0.0, "L": 0.1, "N": 0.2},
	"VI": {"H": 0.0, "L": 0.1, "N": 0.2},
	"VA": {"H": 0.0, "L": 0.1, "N": 0.2},
	"SC": {"H": 0.1, "L": 0.2, "N": 0.3},
	"SI": {"H": 0.1, "L": 0.2, "N": 0.3},
	"SA": {"H": 0.1, "L": 0.2, "N": 0.3},
}

// eqs is the equivalence class a vector falls in, one entry per class.
//
// Written as the six digits of a MacroVector, which is how the published
// tables are keyed.
type eqs [6]int

// key is the MacroVector the classes spell.
func (e eqs) key() string {
	k := make([]byte, len(e))
	for i, v := range e {
		k[i] = "0123456789"[v]
	}
	return string(k)
}

// stepsIn is how many steps each class has, which is how many values the
// scheme gives it.
//
// Read rather than the table of scores, so that a class the table has lost is
// a class this still reaches and the gap is reported.
var stepsIn = [6]int{3, 2, 3, 3, 3, 2}

// down is every MacroVector one step below in the given class.
//
// A class at its lowest has nothing below it, and the distance it would have
// contributed is left out of the mean rather than counted as zero. Where there
// is more than one step down, all of them are answered: the drop the scheme
// takes is to the highest-scoring of them, so each is consulted.
//
// Classes three and six move together: they are the impact a flaw has and how
// much that impact is wanted, and the scheme steps them as a pair. From the
// top there are two ways down — give up impact, or give up the requirement
// that wants it. From the bottom there is none. Stepping impact alone out of
// the middle would name a class that cannot exist, because wanting an impact
// nothing has is not a thing a vector can say.
func (e eqs) down(class int) []eqs {
	next := func(i int) []eqs {
		lower := e
		lower[i]++
		if lower[i] >= stepsIn[i] {
			return nil
		}
		return []eqs{lower}
	}
	switch class {
	case 1, 2, 4, 5:
		return next(class - 1)
	}
	// A base vector reaches three of the pairs: impact on confidentiality and
	// integrity both high, one of the three high, and none of them — because
	// the requirements are all High when nothing states them, so a vector
	// wants whatever impact it has.
	switch {
	case e[2] == 0 && e[5] == 0:
		return append(next(2), next(5)...)
	case e[2] == 1 && e[5] == 0:
		return next(5)
	}
	return nil
}

// The furthest a vector can sit from the worst member of its class, per class.
//
// The divisor that turns a vector's distance into a proportion. Only the
// classes that have a step below them: a class at its lowest contributes no
// distance, so a reach for it would never be divided by anything. Class five
// carries none for the same reason it contributes nothing.
var reachFour = map[int]map[int]int{
	1: {0: 1, 1: 4},
	2: {0: 1},
	4: {1: 5},
}

// reachThreeSix is the same for the pair of classes that move together, keyed
// on both of them.
var reachThreeSix = map[int]map[int]int{0: {0: 7}, 1: {0: 8}}

// reachOf is that divisor for one class of one vector.
func reachOf(e eqs, class int) int {
	if class == threeSix {
		return reachThreeSix[e[2]][e[5]]
	}
	return reachFour[class][e[class-1]]
}

// threeSix is the class that carries class six along with it.
const threeSix = 3

// spans is the metrics whose distances each class is measured over.
var spans = map[int][]string{
	1: {"AV", "PR", "UI"}, 2: {"AC", "AT"},
	threeSix: {"VC", "VI", "VA"}, 4: {"SC", "SI", "SA"},
}

// The worst vector in each class, which is what a member's distance is
// measured from.
//
// The scheme lists several worst members for some classes — reachable over the
// network with no privileges is as bad as adjacent with low privileges. Every
// member of a class that has a step below it sits at the same total distance
// from the class floor, so the first is taken and the rest are there to be
// checked against it. A class with nothing below it contributes no distance at
// all, and its members do not have to agree.
var worstFour = map[int]map[int][]string{
	1: {0: {"AV:N/PR:N/UI:N"}, 1: {"AV:A/PR:N/UI:N", "AV:N/PR:L/UI:N", "AV:N/PR:N/UI:P"},
		2: {"AV:P/PR:N/UI:N", "AV:A/PR:L/UI:P"}},
	2: {0: {"AC:L/AT:N"}, 1: {"AC:H/AT:N", "AC:L/AT:P"}},
	4: {1: {"SC:H/SI:H/SA:H"}, 2: {"SC:L/SI:L/SA:L"}},
}

// worstThreeSix is the same for the pair of classes that move together.
var worstThreeSix = map[int]map[int][]string{
	0: {0: {"VC:H/VI:H/VA:H"}},
	1: {0: {"VC:L/VI:H/VA:H", "VC:H/VI:L/VA:H"}},
	2: {1: {"VC:L/VI:L/VA:L"}},
}

// scoreFour works out a version 4.0 base vector.
func scoreFour(vector string, given map[string]string) (*Scored, error) {
	if metric := missing(given, baseFour); metric != "" {
		return nil, fmt.Errorf("%w: it states no %s, and a base score needs all eleven",
			ErrNotAVector, metric)
	}
	for _, metric := range baseFour {
		if _, known := levelsFour[metric][given[metric]]; !known {
			return nil, fmt.Errorf("%w: %s:%s is not a value that metric takes",
				ErrNotAVector, metric, given[metric])
		}
	}
	score := 0.0
	if !harmless(given) {
		score = macroScore(given)
	}
	return &Scored{
		Vector: vector, ScoreCenti: int(math.Round(score * 100)), Severity: bandOf(score),
	}, nil
}

// harmless says whether the flaw does nothing to anything.
//
// A vector claiming no impact on the vulnerable system and none on anything
// downstream scores zero without going near the tables, which is the one
// answer the interpolation cannot arrive at.
func harmless(given map[string]string) bool {
	for _, metric := range []string{"VC", "VI", "VA", "SC", "SI", "SA"} {
		if given[metric] != "N" {
			return false
		}
	}
	return true
}

// classesOf is the equivalence class a vector falls in.
//
// The threat and environmental metrics are at the values the scheme gives them
// when unstated, which fixes class five at its top and ties class six to class
// three: with every requirement High, a flaw wants whatever impact it has.
func classesOf(given map[string]string) eqs {
	var e eqs
	switch {
	case given["AV"] == "N" && given["PR"] == "N" && given["UI"] == "N":
		e[0] = 0
	case given["AV"] != "P" &&
		(given["AV"] == "N" || given["PR"] == "N" || given["UI"] == "N"):
		e[0] = 1
	default:
		e[0] = 2
	}
	if given["AC"] != "L" || given["AT"] != "N" {
		e[1] = 1
	}
	switch {
	case given["VC"] == "H" && given["VI"] == "H":
		e[2] = 0
	case given["VC"] == "H" || given["VI"] == "H" || given["VA"] == "H":
		e[2] = 1
	default:
		e[2] = 2
	}
	// Class four asks whether anything downstream is affected at all. Its top
	// step says a downstream system loses its safety, which only an
	// environmental metric states, so a base vector reaches the lower two.
	e[3] = 2
	if given["SC"] == "H" || given["SI"] == "H" || given["SA"] == "H" {
		e[3] = 1
	}
	e[4] = 0
	e[5] = 1
	if given["VC"] == "H" || given["VI"] == "H" || given["VA"] == "H" {
		e[5] = 0
	}
	return e
}

// macroScore is the published score of a vector's class, less how far the
// vector sits from the worst member of it.
//
// The distance is taken one class at a time. Each class contributes the drop
// to the class below it, scaled by how far down its own scale the vector sits,
// and the score is the class score less the mean of those contributions. A
// class with nothing below it contributes nothing and is not counted.
func macroScore(given map[string]string) float64 {
	e := classesOf(given)
	value := macroScores[e.key()]
	worst := worstOf(e)

	// Class five never separates two base vectors: nothing states
	// exploitation, so every base vector sits at the top of it. It still
	// counts, because the mean is over the classes that have something below
	// them and this one does.
	// Class five never separates two base vectors: nothing states
	// exploitation, so every base vector sits at the top of it. It still
	// counts, because the mean is over the classes that have something below
	// them and this one does.
	total, counted := 0.0, 0
	for class := 1; class <= 5; class++ {
		steps := e.down(class)
		if len(steps) == 0 {
			continue
		}
		counted++
		if class == 5 {
			continue
		}
		below := macroScores[steps[0].key()]
		for _, step := range steps[1:] {
			below = math.Max(below, macroScores[step.key()])
		}
		// The scale is in tenths, which is what turns a reach into a length.
		total += (value - below) *
			(away(given, worst, spans[class]...) / (float64(reachOf(e, class)) * 0.1))
	}
	if counted > 0 {
		value -= total / float64(counted)
	}
	return math.Round(math.Min(math.Max(value, 0), 10)*10) / 10
}

// worstOf is the worst vector in the class a vector falls in.
func worstOf(e eqs) map[string]string {
	return stateOf(worstFour[1][e[0]][0] + "/" + worstFour[2][e[1]][0] + "/" +
		worstThreeSix[e[2]][e[5]][0] + "/" + worstFour[4][e[3]][0])
}

// stateOf reads the metrics a fragment of a vector names.
func stateOf(fragment string) map[string]string {
	state := map[string]string{}
	for _, part := range strings.Split(fragment, "/") {
		metric, value, _ := strings.Cut(part, ":")
		state[metric] = value
	}
	return state
}

// away is how far down their own scales the named metrics sit from the worst
// vector's.
func away(given, worst map[string]string, of ...string) float64 {
	distance := 0.0
	for _, metric := range of {
		distance += levelsFour[metric][given[metric]] - levelsFour[metric][worst[metric]]
	}
	return distance
}

// macroScores is the published score of each equivalence class.
//
// Transcribed from the reference calculator FIRST publishes for the scheme,
// which carries it as a table of 270. Ninety-six of those are the classes a
// base vector falls in or steps down to; the rest are reached only once the
// threat and environmental metrics are scored, and the table grows with the
// code that reads them. A transcribed number nothing runs is a number nobody
// would find wrong.
//
// Copyright FIRST.ORG, Inc., Red Hat, and contributors. BSD-2-Clause.
var macroScores = map[string]float64{
	"000100": 10.0, "000101": 9.6, "000110": 9.3, "000200": 9.3,
	"000201": 9.0, "000210": 8.9, "001100": 9.3, "001101": 9.2,
	"001110": 8.9, "001200": 8.8, "001201": 8.0, "001210": 7.8,
	"002101": 7.9, "002111": 6.9, "002201": 6.9, "002211": 5.5,
	"010100": 9.5, "010101": 9.1, "010110": 9.0, "010200": 9.2,
	"010201": 8.1, "010210": 8.2, "011100": 9.2, "011101": 8.2,
	"011110": 8.0, "011200": 8.4, "011201": 7.0, "011210": 7.1,
	"012101": 7.1, "012111": 5.2, "012201": 6.3, "012211": 2.9,
	"100100": 9.4, "100101": 8.9, "100110": 8.6, "100200": 8.7,
	"100201": 7.5, "100210": 7.4, "101100": 8.6, "101101": 7.6,
	"101110": 7.4, "101200": 7.2, "101201": 5.7, "101210": 5.7,
	"102101": 6.5, "102111": 5.8, "102201": 5.3, "102211": 2.1,
	"110100": 9.0, "110101": 7.7, "110110": 7.5, "110200": 7.7,
	"110201": 6.6, "110210": 6.8, "111100": 7.4, "111101": 5.9,
	"111110": 5.7, "111200": 6.1, "111201": 5.2, "111210": 5.7,
	"112101": 5.8, "112111": 2.6, "112201": 2.3, "112211": 1.3,
	"200100": 8.6, "200101": 7.4, "200110": 7.4, "200200": 7.0,
	"200201": 5.4, "200210": 5.2, "201100": 7.2, "201101": 5.7,
	"201110": 5.5, "201200": 5.3, "201201": 3.6, "201210": 3.4,
	"202101": 4.7, "202111": 2.1, "202201": 2.4, "202211": 0.9,
	"210100": 7.3, "210101": 5.5, "210110": 5.9, "210200": 5.4,
	"210201": 4.3, "210210": 4.5, "211100": 6.1, "211101": 5.1,
	"211110": 4.8, "211200": 4.6, "211201": 1.8, "211210": 1.7,
	"212101": 2.4, "212111": 1.2, "212201": 1.0, "212211": 0.3,
}
