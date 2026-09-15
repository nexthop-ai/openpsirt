package attach

// AfterPage runs fn between the collection pass reading its page and acting on
// it.
//
// The window the pass's guard exists for: text naming an attachment is saved
// after the transaction that wrote it, so a comment landing in that gap is the
// ordinary case rather than a contrived one. Waiting for it to happen by
// itself is a test that passes by never racing.
func AfterPage(s *Store, fn func()) { s.afterPage = fn }
