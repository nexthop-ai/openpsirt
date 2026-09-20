package finding

import (
	"bufio"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
)

// The published corpus, read once. Each line is a vector and the score the
// scheme's own calculator gives it.
func corpus(t *testing.T) map[string]int {
	t.Helper()
	file, err := os.Open("testdata/cvss4-scores.txt")
	if err != nil {
		t.Fatalf("reading the published scores: %v", err)
	}
	defer file.Close()
	scores := map[string]int{}
	lines := bufio.NewScanner(file)
	for lines.Scan() {
		line := strings.TrimSpace(lines.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		vector, score, found := strings.Cut(line, " ")
		if !found {
			t.Fatalf("%q is not a vector and a score", line)
		}
		published, err := strconv.ParseFloat(score, 64)
		if err != nil {
			t.Fatalf("%q does not state a score: %v", line, err)
		}
		scores[vector] = int(math.Round(published * 100))
	}
	if err := lines.Err(); err != nil {
		t.Fatalf("reading the published scores: %v", err)
	}
	if len(scores) == 0 {
		t.Fatal("the published scores are empty, so this checked nothing")
	}
	return scores
}

func TestAVersionFourVectorScoresWhatTheSchemesOwnCalculatorScoresIt(t *testing.T) {
	for vector, want := range corpus(t) {
		t.Run(vector, func(t *testing.T) {
			got, err := Score(vector)
			if err != nil {
				t.Fatalf("scoring: %v", err)
			}
			if got.ScoreCenti != want {
				t.Errorf("scored %d, want the published %d", got.ScoreCenti, want)
			}
		})
	}
}

// baseFours calls back with every version 4 base vector there is.
//
// A hundred thousand of them, which is small enough to walk: the base metrics
// are eleven, and the widest takes four values.
func baseFours(each func(given map[string]string, vector string)) {
	values := [][]string{}
	for _, metric := range baseFour {
		held := []string{}
		for value := range levelsFour[metric] {
			held = append(held, value)
		}
		values = append(values, held)
	}
	given := map[string]string{}
	var walk func(int)
	walk = func(i int) {
		if i == len(baseFour) {
			parts := make([]string, len(baseFour))
			for n, metric := range baseFour {
				parts[n] = metric + ":" + given[metric]
			}
			each(given, "CVSS:4.0/"+strings.Join(parts, "/"))
			return
		}
		for _, value := range values[i] {
			given[baseFour[i]] = value
			walk(i + 1)
		}
	}
	walk(0)
}

func TestTheClassScoresAreTheOnesABaseVectorReaches(t *testing.T) {
	// Both directions. A class a vector falls in or steps down to and the
	// table does not carry scores as zero with nothing saying so; a class the
	// table carries and no vector reaches is a transcribed number that could
	// be wrong for years without anything failing.
	reached := map[string]bool{}
	walked := 0
	baseFours(func(given map[string]string, _ string) {
		walked++
		e := classesOf(given)
		reached[e.key()] = true
		for class := 1; class <= 5; class++ {
			for _, step := range e.down(class) {
				reached[step.key()] = true
			}
		}
	})
	if walked == 0 {
		t.Fatal("no base vectors were walked, so this checked nothing")
	}
	for key := range reached {
		if _, held := macroScores[key]; !held {
			t.Errorf("a base vector reaches class %s and the table does not carry it", key)
		}
	}
	for key := range macroScores {
		if !reached[key] {
			t.Errorf("the table carries class %s and no base vector reaches it", key)
		}
	}
}

func TestTheReachesAreTheOnesAClassWithAStepBelowItNeeds(t *testing.T) {
	// A reach is the divisor that turns a vector's distance into a
	// proportion, and it is only ever divided by where the class has a step
	// below it to move toward. Both directions: a class that needs one and
	// has none divides by zero, and one carried for a class that never needs
	// it is a transcribed number nothing would find wrong.
	needed := map[[2]int]bool{}
	walked := 0
	baseFours(func(given map[string]string, _ string) {
		walked++
		e := classesOf(given)
		for class := 1; class <= 4; class++ {
			if len(e.down(class)) == 0 {
				continue
			}
			needed[[2]int{class, classValue(e, class)}] = true
			if reachOf(e, class) <= 0 {
				t.Fatalf("class %s divides its distance for step %d by nothing",
					e.key(), class)
			}
		}
	})
	if walked == 0 {
		t.Fatal("no base vectors were walked, so this checked nothing")
	}
	for class, byValue := range reachFour {
		for held := range byValue {
			if !needed[[2]int{class, held}] {
				t.Errorf("a reach is carried for step %d at %d and nothing needs it",
					class, held)
			}
		}
	}
	for three, by := range reachThreeSix {
		for six := range by {
			if !needed[[2]int{threeSix, three*10 + six}] {
				t.Errorf("a reach is carried for the pair %d and %d and nothing needs it",
					three, six)
			}
		}
	}
}

// classValue is what a class sits at, spelled the way its reach is keyed.
func classValue(e eqs, class int) int {
	if class == threeSix {
		return e[2]*10 + e[5]
	}
	return e[class-1]
}

func TestEveryClassAndEveryStepBetweenThemIsScoredByTheCorpus(t *testing.T) {
	// The corpus is what says the table is transcribed correctly, so a table
	// entry it never reads is an entry nothing checks.
	read := map[string]bool{}
	for vector := range corpus(t) {
		given, err := stated(strings.Split(vector, "/")[1:])
		if err != nil {
			t.Fatalf("%s: %v", vector, err)
		}
		e := classesOf(given)
		read[e.key()] = true
		for class := 1; class <= 5; class++ {
			for _, step := range e.down(class) {
				read[step.key()] = true
			}
		}
	}
	if len(read) == 0 {
		t.Fatal("the corpus read no classes, so this checked nothing")
	}
	for key := range macroScores {
		if !read[key] {
			t.Errorf("no vector in the corpus reads class %s", key)
		}
	}
}

func TestTheWorstVectorsOfAClassAreAllTheSameDistanceAway(t *testing.T) {
	// A distance is measured from the first worst vector the scheme lists for
	// a class. That is only honest because the others are the same distance
	// from the class floor — adjacent with low privileges is as far down as
	// network with none. A class with nothing below it contributes no
	// distance, so its members are free to disagree and two of them do.
	of := map[int]struct {
		members func(e eqs) []string
		metrics []string
	}{
		1: {func(e eqs) []string { return worstFour[1][e[0]] }, []string{"AV", "PR", "UI"}},
		2: {func(e eqs) []string { return worstFour[2][e[1]] }, []string{"AC", "AT"}},
		3: {func(e eqs) []string { return worstThreeSix[e[2]][e[5]] }, []string{"VC", "VI", "VA"}},
		4: {func(e eqs) []string { return worstFour[4][e[3]] }, []string{"SC", "SI", "SA"}},
	}
	classes, several := map[eqs]bool{}, 0
	baseFours(func(given map[string]string, _ string) { classes[classesOf(given)] = true })
	if len(classes) == 0 {
		t.Fatal("no classes were reached, so this checked nothing")
	}
	for e := range classes {
		for class := 1; class <= 4; class++ {
			if len(e.down(class)) == 0 {
				continue
			}
			members := of[class].members(e)
			if len(members) > 1 {
				several++
			}
			want := reach(stateOf(members[0]), of[class].metrics)
			for _, member := range members[1:] {
				if got := reach(stateOf(member), of[class].metrics); got != want {
					t.Errorf("class %s step %d: %s is %v from the floor and %s is %v",
						e.key(), class, members[0], want, member, got)
				}
			}
		}
	}
	if several == 0 {
		t.Fatal("no class with a step below it lists more than one worst vector, " +
			"so this checked nothing")
	}
}

// reach is how far down their own scales the named metrics sit.
func reach(state map[string]string, metrics []string) float64 {
	distance := 0.0
	for _, metric := range metrics {
		distance += levelsFour[metric][state[metric]]
	}
	return distance
}

func TestAVersionFourVectorWithNoImpactAnywhereScoresNothing(t *testing.T) {
	// The one answer the interpolation cannot arrive at: the lowest class is
	// worth more than zero, so a flaw that does nothing has to be recognized
	// before the tables are consulted.
	got, err := Score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")
	if err != nil {
		t.Fatalf("scoring: %v", err)
	}
	if got.ScoreCenti != 0 || got.Severity != "none" {
		t.Errorf("scored %d and banded %q, want 0 and none", got.ScoreCenti, got.Severity)
	}
}

func TestAVersionFourVectorIsRefusedForWhatItLeavesOutOrGetsWrong(t *testing.T) {
	for _, c := range []struct{ what, vector string }{
		{"a metric missing", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N"},
		{"the metric version 3 has in its place",
			"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/S:U/C:H/I:H/A:H/SC:N/SI:N/SA:N"},
		{"a value that metric does not take",
			"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
		{"a metric given twice",
			"CVSS:4.0/AV:N/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
	} {
		t.Run(c.what, func(t *testing.T) {
			if _, err := Score(c.vector); err == nil {
				t.Errorf("%s was scored anyway", c.what)
			}
		})
	}
}

func TestAVersionFourVectorIsScoredOverItsBaseMetricsAlone(t *testing.T) {
	// Threat and environmental metrics describe a moment and a deployment,
	// and the deployment reading a finding is not the one it is about. A
	// vector carrying them scores as the base vector inside it, the way a
	// version 3 vector carrying temporal metrics does.
	base := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	plain, err := Score(base)
	if err != nil {
		t.Fatalf("scoring: %v", err)
	}
	for _, extra := range []string{"E:U", "CR:L/IR:L/AR:L", "MAV:P", "S:P/AU:Y/R:A/V:D/RE:L/U:Red"} {
		t.Run(extra, func(t *testing.T) {
			got, err := Score(base + "/" + extra)
			if err != nil {
				t.Fatalf("scoring: %v", err)
			}
			if got.ScoreCenti != plain.ScoreCenti {
				t.Errorf("scored %d with %s beside it, want the base %d",
					got.ScoreCenti, extra, plain.ScoreCenti)
			}
		})
	}
}

func TestTheTwoSchemesBandOneScoreTheSameWay(t *testing.T) {
	// A list holds findings from both schemes and sorts them together, which
	// only reads honestly because the bands are the same five words over the
	// same five ranges. The numbers underneath are not comparable; the words
	// are.
	for _, band := range []struct {
		word         string
		three, four4 string
	}{
		{"critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"},
		{"medium", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
			"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"},
	} {
		t.Run(band.word, func(t *testing.T) {
			for _, vector := range []string{band.three, band.four4} {
				got, err := Score(vector)
				if err != nil {
					t.Fatalf("scoring %s: %v", vector, err)
				}
				if got.Severity != band.word {
					t.Errorf("%s banded as %q, want %q", vector, got.Severity, band.word)
				}
			}
		})
	}
}

func TestAPublishedVectorScoresAsTheBaseVectorInsideIt(t *testing.T) {
	// Version 4 ratings arrive carrying every metric the scheme has, with X
	// where nothing was stated. Where the exploit maturity is one of those,
	// the number published beside the vector is that metric applied — under a
	// field its producer still calls the base score. This scores the base
	// metrics, so the two agree only where nothing was claimed about
	// exploitation.
	file, err := os.Open("testdata/cvss4-published.txt")
	if err != nil {
		t.Fatalf("reading the published ratings: %v", err)
	}
	defer file.Close()
	unstated, stated := 0, 0
	lines := bufio.NewScanner(file)
	for lines.Scan() {
		line := strings.TrimSpace(lines.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			t.Fatalf("%q is not an issue, a vector and a score", line)
		}
		issue, vector := parts[0], parts[1]
		published, err := strconv.ParseFloat(parts[2], 64)
		if err != nil {
			t.Fatalf("%s states no score: %v", issue, err)
		}
		t.Run(issue, func(t *testing.T) {
			got, err := Score(vector)
			if err != nil {
				t.Fatalf("scoring: %v", err)
			}
			// The same answer as the base metrics alone, which is what says
			// the rest were read and ignored rather than refused.
			bare := []string{"CVSS:4.0"}
			for _, part := range strings.Split(vector, "/")[1:] {
				metric, _, _ := strings.Cut(part, ":")
				for _, base := range baseFour {
					if metric == base {
						bare = append(bare, part)
					}
				}
			}
			alone, err := Score(strings.Join(bare, "/"))
			if err != nil {
				t.Fatalf("scoring the base metrics alone: %v", err)
			}
			if got.ScoreCenti != alone.ScoreCenti {
				t.Errorf("the whole vector scored %d and its base metrics %d",
					got.ScoreCenti, alone.ScoreCenti)
			}
			claimed := strings.Contains(vector, "/E:P/") || strings.Contains(vector, "/E:U/")
			switch {
			case claimed:
				stated++
				if got.ScoreCenti <= int(math.Round(published*100)) {
					t.Errorf("scored %d against a published %v, and a claim that exploitation "+
						"is less than certain only ever lowers a number",
						got.ScoreCenti, published)
				}
			default:
				unstated++
				if got.ScoreCenti != int(math.Round(published*100)) {
					t.Errorf("scored %d against a published %v", got.ScoreCenti, published)
				}
			}
		})
	}
	if unstated == 0 || stated == 0 {
		t.Fatalf("%d ratings claim nothing about exploitation and %d do, and this needs "+
			"both to have checked anything", unstated, stated)
	}
}
