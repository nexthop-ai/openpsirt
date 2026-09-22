package finding

// FixedBecause is how a closure is said in a release note, for the test.
//
// Exported for the test alone: it is what the note writes beside each line,
// and what is being held is that every closure counting as a fix has words —
// otherwise a reader gets the issue and the component with nothing after them.
func FixedBecause(because Closure) string { return fixedBecause(because) }

// RankCase is the severity ordering as SQL, and WordAt its inverse, for the
// test.
//
// Exported for the test alone: the two are what every list orders by and what
// the bundle page turns a rank back into, and a mapping that disagrees with
// its own inverse about a band is the defect they were written to end.
func RankCase(over string, otherwise int) string { return rankCase(over, otherwise) }

// WordAt is the severity word a rank stands for.
func WordAt(rank int) string { return wordAt(rank) }

// JudgingAfter puts fn between a judgment reading the report and writing to
// it, for the test.
//
// Exported for the test alone: the condition on the write exists for two
// people judging one claim at the same moment, and the read above it answers
// every input a single caller can produce — so without a way into that window
// the condition can be deleted with the suite green.
func (s *Store) JudgingAfter(fn func()) { s.afterReadingReport = fn }
