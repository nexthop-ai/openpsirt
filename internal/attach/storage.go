package attach

import (
	"context"
	"errors"
	"io"
	"time"
)

// ErrNoSuchObject is what a store reports for bytes that are not there.
//
// Told apart from a failure because they mean opposite things to a caller: a
// redacted file is expected to be gone, and a store that cannot be reached is
// an outage somebody has to hear about.
var ErrNoSuchObject = errors.New("no such object")

// Storage is where the bytes live.
//
// Two implementations, and the interface is what keeps the second from being
// a second version of the rules: what may be stored, what it is served as and
// who may have it are decided above this line, and a store decides only how to
// hold bytes.
type Storage interface {
	// Name is what this store is called in a log line and in the readiness
	// answer, so an operator can see which one a deployment came up with.
	Name() string

	// Put stores size bytes read from body under key.
	//
	// The reader is streamed rather than held: the size limit bounds one file,
	// and holding each one would mean every upload happening at once is
	// resident at once.
	Put(ctx context.Context, key string, body io.Reader, size int64, contentType string) error

	// Open reads bytes back, for the files this application serves itself
	// .
	Open(ctx context.Context, key string) (io.ReadCloser, error)

	// Delete removes bytes, for a redaction. Removing what is already gone
	// is the outcome asked for and not an error.
	Delete(ctx context.Context, key string) error

	// URLFor is a short-lived address a browser may be sent to, carrying
	// the disposition and content type we chose as response overrides.
	//
	// **An empty string is a legitimate answer**, and means this store cannot
	// hand out an address of its own — so the caller serves the bytes instead.
	// That is not a fallback for a failure; it is what a store without a
	// signing authority looks like, and the only one of those is the local
	// one.
	URLFor(ctx context.Context, key string, ttl time.Duration,
		disposition, contentType string) (string, error)

	// Reachable answers whether the store actually answers, so that a
	// deployment configured wrongly says so at startup rather than at the
	// first upload somebody tries.
	Reachable(ctx context.Context) error
}
