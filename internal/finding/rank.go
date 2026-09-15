package finding

// Rank is how urgent a finding is, as one number that sorts.
//
// One number because sorting tens of thousands of rows has to hit an index, and
// a rank computed while reading cannot be indexed. It is written when a scan is
// applied and read back as written — and rewritten by a later scan that finds
// the issue's record has moved, because storing it is about not recomputing it
// on every read rather than about freezing it.
//
// The number is **packed rather than weighted**: each signal owns a range of
// digits, so a signal never trades against a lower one. That is deliberate,
// and the reason is explainability — somebody has to be able to
// read a position and see why, and "it scored 0.4 higher on a weighted sum of
// four things" is not something anybody trusts or argues with. Packing gives a
// rule that can be stated in a sentence: exploited first, then what reaches
// customers, then how likely, then how bad.
//
// The trade is that a small difference in a higher signal always beats any
// difference in a lower one. That is clearly right for exploitation and
// arguably strong for where something ships, and it is the kind of judgment
// that should be made against a real queue rather than in the abstract — which
// is why the weighting lives in this one function.
type Rank int64

// The place value each signal owns.
//
// Sized so nothing can carry into the band above it: a severity is at most a
// thousand hundredths, and a likelihood at most a million parts.
const (
	exploitedBand = 1_000_000_000_000
	shippedBand   = 100_000_000_000
	// severityStep lifts severity above likelihood, which sits underneath it
	// and orders things that are equally severe.
	severityStep  = 10_000_000
	maxScore      = 1_000
	maxLikelihood = 1_000_000
)

// Rating is everything on record about an issue that decides where its
// findings sit and how long they have.
//
// One type, read from the issue in one place, because the alternative is what
// this project keeps being bitten by: the same fact spelled once at ingest and
// again on reassessment, agreeing until one of them is changed.
type Rating struct {
	// Published is the word the world rated it. Never overwritten by a
	// rating of ours — a rating of ours shown where the world's goes reads
	// as the world's.
	Published string
	// Assessed is what we say instead, where somebody has said something.
	Assessed string
	// Exploited says somebody is known to be using it. Stored as the worst
	// anybody has claimed, so a later report that does not mention it is read
	// as a gap in that report rather than as the exploitation having stopped.
	Exploited bool
	// ScoreCenti and LikelihoodPPM are the published numbers, each the highest
	// anybody has claimed.
	ScoreCenti    int
	LikelihoodPPM int
}

// Severity is the word in force: ours where somebody has made a rating, the
// published word otherwise.
func (r Rating) Severity() string {
	if r.Assessed != "" {
		return r.Assessed
	}
	return r.Published
}

// Score is the number the order compares.
//
// A rating of ours replaces it, because the word is the whole of what we are
// claiming. Where there is none the published score stands, and the published
// word stands in for it where no score was given — so an issue rated only in
// words does not sort below everything rated at all.
func (r Rating) Score() int {
	if r.Assessed != "" {
		return SeverityScore(r.Assessed)
	}
	if r.ScoreCenti == 0 {
		return SeverityScore(r.Published)
	}
	return r.ScoreCenti
}

// Ranked is what a rank was made of, so a position can be explained.
//
// Kept alongside the number rather than derived from it. Reading the digits
// back out would work and would be exactly the sort of cleverness that breaks
// silently the first time the weighting changes.
type Ranked struct {
	// Exploited says somebody is known to be using it. It outranks everything
	// else, because it is the difference between a risk and an incident.
	Exploited bool
	// Shipped says this reaches customers. A critical in something only the
	// build system runs matters less than a medium in what people install.
	Shipped bool
	// LikelihoodPPM is the published estimate that it will be exploited, in
	// parts per million.
	LikelihoodPPM int
	// ScoreCenti is the severity in hundredths.
	ScoreCenti int
}

// Rank packs the signals into one sortable number, highest first.
//
// Exploited, then whether it reaches customers, then **severity, then
// likelihood** — each owning a range of digits so it never trades against a
// lower signal.
//
// Likelihood used to sit above severity, and that was measured wrong on a real
// image: a 2004 negligible with no score at all outranked every one of 379
// criticals, because its likelihood was 0.80 where theirs topped out at 0.073
// and any difference in the higher signal won outright.
//
// Multiplying the two was tried next, which is the published practice for
// these two scores, and the same image argued against it: **95% of its issues
// sit between 0.001 and 0.01 likelihood**, one order of magnitude, where the
// differences are not differences anybody should act on. Multiplied, that 4.5×
// ratio inside the spike outweighs the 2× between a medium and a critical, so
// mediums would jump criticals constantly and on noise.
//
// So severity leads and likelihood orders what is equally severe. It gives up
// letting a very likely medium jump a high — on this data almost always noise,
// and the case that actually matters, something known to be used, is a fact
// rather than a forecast and already ranks above everything.
func (r Ranked) Rank() Rank {
	rank := int64(0)
	if r.Exploited {
		rank += exploitedBand
	}
	if r.Shipped {
		rank += shippedBand
	}
	rank += int64(bounded(r.ScoreCenti, maxScore)) * severityStep
	rank += int64(bounded(r.LikelihoodPPM, maxLikelihood))
	return Rank(rank)
}

// Exploited reports whether a rank says the issue is known to be exploited.
//
// The band is the fact: exploitation lifts a rank above anything the other
// signals can add together, so the flag is readable from the number — which
// is what lets a query that has only the urgency, from an index, answer it.
func (r Rank) Exploited() bool {
	return int64(r) >= exploitedBand
}

// bounded keeps a signal inside the range its place value allows.
//
// A source that reports something out of range would otherwise carry into the
// band above it and rank as though it were exploited, which is the one thing
// this must never invent.
func bounded(value, limit int) int {
	switch {
	case value < 0:
		return 0
	case value > limit:
		return limit
	default:
		return value
	}
}

// SeverityWord turns a score back into the band it falls in, for the places
// that hold a number and have to show a word.
//
// The bands the scoring standard defines. A score of zero means nothing rated
// it, which is reported as nothing rather than as a low — an unrated finding
// is not a mild one, and saying "low" about it is a claim nobody made.
func SeverityWord(centi int) string {
	switch {
	case centi <= 0:
		return ""
	case centi >= 900:
		return "critical"
	case centi >= 700:
		return "high"
	case centi >= 400:
		return "medium"
	default:
		return "low"
	}
}

// SeverityScore turns a severity word into a score, for the reports that give
// a word and no number.
//
// Most findings carry a number and this is what stands in for the rest, so
// that a finding rated only in words does not sort below everything rated at
// all. The values are the midpoints of the bands the scoring standard defines,
// which is the least arbitrary reading available.
func SeverityScore(word string) int {
	switch word {
	case "critical":
		return 950
	case "high":
		return 800
	case "medium":
		return 550
	// "negligible" and "none" are words a scanner reports and no band holds.
	// The fold has already decided they are lows, everywhere a query asks —
	// so the Go side answers the same rather than giving them a score of
	// their own, which ranked them above unrated and below every low, and
	// turned back into "low" anywhere a stored number became a word again.
	case "low", "negligible", "none":
		return 300
	default:
		return 0
	}
}
