package advisory

import (
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Stumble makes the first attempt to write an issuance report a lost race, so
// the helper re-runs the whole closure.
//
// What the retry carries is the subject: everything the closure reads has to
// be read again, and anything taken before it began describes a database that
// has moved. Losing the race for real would need another connection to commit
// inside this transaction's window, which one of the four engines will not
// allow, so the outcome is driven rather than raced.
func Stumble(s *Store, reached func()) {
	ran := false
	s.beforeWrite = func() error {
		if ran {
			return nil
		}
		ran = true
		reached()
		return database.ErrGoAgain
	}
}

// Ticking gives this store a clock that moves an hour at every reading, and
// answers with every moment it handed out.
//
// An hour so that two readings are told apart by more than the microseconds
// between them, and a record of them because what is being pinned is which
// reading was kept.
func Ticking(s *Store, from time.Time) *[]time.Time {
	var handed []time.Time
	s.now = func() time.Time {
		from = from.Add(time.Hour)
		handed = append(handed, from)
		return from
	}
	return &handed
}

// Between runs fn the first time the store reads the clock, which is while a
// document is being assembled and before anything it decides is written.
//
// The window every rule here about reading inside the transaction exists for:
// what has gone out is read once to build the document and again to record
// the issuance, and another writer landing between the two is the case those
// rules are written against. Waiting for it to happen by itself is a test
// that passes by never racing.
func Between(s *Store, fn func()) {
	ordinary := s.now
	ran := false
	s.now = func() time.Time {
		if !ran {
			ran = true
			fn()
		}
		return ordinary()
	}
}
