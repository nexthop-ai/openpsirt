// Package currency asks each ecosystem's index what the newest version of
// something is, and when it shipped.
//
// This is the one thing here that reaches the network. Everything a scan
// needs arrives as a file somebody imports, deliberately, so that a scan
// answers the same way twice and nothing it depends on is somebody else's
// server being up (REQ-12). That rule is about the scan path, and this is not
// on it: it asks a public index what the newest version of something is, it is
// off unless a deployment turns it on, and a deployment that cannot reach out
// loses this answer and nothing else.
//
// What leaves is a component's name. One request per component, carrying
// the name and nothing else. For an open-source dependency that is public
// knowledge; for something built here it is the name of a project, a team or a
// product nobody has announced, so what this deployment calls its own is held
// back rather than asked about — see Ours.
//
// Two facts and no judgment. The newest version says whether we are behind;
// its date says whether the thing is still moving. Together they say why there
// is no fix — an issue disclosed after a component's newest release and still
// unfixed means upstream has shipped nothing since the flaw became known,
// which is arithmetic rather than an opinion about anybody's project.
//
// Only for what we build ourselves. For a distribution package the
// distribution is the maintainer, and its release date says nothing about the
// software inside.
package currency

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/outward"
)

// Latest is the newest version of a package, and what the index says about it.
type Latest struct {
	Version string
	// Released is when that version shipped. Zero where the index gives a
	// version and no date, which is honest — a date we do not have is not a
	// date of zero, and the caller stores nothing rather than storing the
	// beginning of time.
	Released time.Time
	// Summary is one line saying what the package is, for somebody reading a
	// dependency of a dependency they have never heard of. Taken where the
	// index serves one and absent where it does not, which is normal rather
	// than a fault: the module proxy has no such field at all.
	//
	// One line, never the long description. What some indexes call the
	// description is a whole README — measured at 2,894 characters for one
	// ordinary package — which is a document rather than a label.
	Summary string
	// Project is where the package is developed, as the index says rather than
	// as an address worked out from the name. Absent where the index does not
	// say, in which case a caller can still build one from the identifier.
	Project string
}

// Asker looks up one ecosystem.
type Asker interface {
	Latest(ctx context.Context, name string) (Latest, error)
}

// ErrUnknown is returned where an ecosystem has no index we ask, or the index
// has never heard of the package. Neither is a fault: a private module and a
// vendored fork both look like this, and treating them as failures would fill
// the log with things nobody can act on.
var ErrUnknown = fmt.Errorf("nothing upstream to ask")

// ErrUnaskable is returned where a name cannot be turned into a request at
// all — a package identifier carrying something that is not a name.
//
// Told apart from an index having a bad day, because the two want opposite
// treatment: a bad day should be retried, and this never will succeed. Left
// as a retryable failure it is also a denial of service, since one uploaded
// document full of such names keeps the whole pass busy failing.
var ErrUnaskable = fmt.Errorf("this name cannot be asked about")

// ErrNotAnswering is returned where an index is having a bad day: it refused
// the request for a reason that will not be true tomorrow, or could not
// answer at all.
//
// The one class that is worth coming back to, and the reason the others are
// told apart from it. Everything that is not one of these three is a refusal
// the index will repeat every time — a package withdrawn, a region blocked, a
// document nothing can read — and taking this arm leaves the component
// unrecorded, at the head of every pass afterwards for ever, because the
// window takes the never-asked first.
var ErrNotAnswering = fmt.Errorf("the index is not answering")

// Client asks the public index for an ecosystem.
type Client struct {
	HTTP *http.Client
	// Agent identifies us to the indexes. crates.io refuses a request that
	// does not say who is asking, and it is right to.
	Agent string
	// The address of each index. Fields rather than constants so a test can point
	// them at a local server: without this the only way to exercise any of
	// this code is to call somebody else's service, whose answers change, so
	// in practice it was not exercised at all.
	GoProxy, NPM, PyPI, Crates string
}

// The public indexes, which is what a deployment talks to unless a test says
// otherwise.
const (
	DefaultGoProxy = "https://proxy.golang.org"
	DefaultNPM     = "https://registry.npmjs.org"
	DefaultPyPI    = "https://pypi.org"
	DefaultCrates  = "https://crates.io"
)

// New returns a client with sensible bounds.
//
// Timeouts rather than patience: this runs in the background against thousands
// of packages, and an index that has stopped answering should cost one request
// rather than the whole pass.
//
// Guarded, like every other fetch out of this process. one configured host names this feed
// as the case it was written for and it was the one client that had none of
// it: no host pin, no refusal to follow a redirect, and nothing stopping a
// connection inside this network. A public index answering — or being made to
// answer — with a redirect to an address on the deployment's own network was
// followed silently, ten hops deep, downgrading to plain HTTP if it was told
// to, by a background pass nobody is watching.
func New() *Client {
	return &Client{
		HTTP: outward.Guarded(
			hostOf(DefaultGoProxy), hostOf(DefaultNPM),
			hostOf(DefaultPyPI), hostOf(DefaultCrates),
		),
		Agent:   "openpsirt (+https://github.com/nexthop-ai/openpsirt)",
		GoProxy: DefaultGoProxy, NPM: DefaultNPM,
		PyPI: DefaultPyPI, Crates: DefaultCrates,
	}
}

// hostOf is the host part of one of the index addresses above, which are
// compile-time constants — so a value that will not parse is a mistake in this
// file rather than anything a deployment can cause.
func hostOf(address string) string {
	parsed, err := url.Parse(address)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// askers is every ecosystem this has an index for, beside the asker for each.
//
// One table rather than a list beside a switch. The pass selecting candidates
// builds its condition from the names and the pass asking picks the asker by
// name, so kept apart an index added to one and forgotten in the other is
// either components selected and never asked or components asked about and
// never selected — and silently, because nothing joins the two spellings.
//
// Lower case, because that is how a package identifier's type is compared.
var askers = map[string]func(*Client) Asker{
	"golang": func(c *Client) Asker { return goProxy{c} },
	"npm":    func(c *Client) Asker { return npmRegistry{c} },
	"pypi":   func(c *Client) Asker { return pyPI{c} },
	"cargo":  func(c *Client) Asker { return cratesIO{c} },
}

// Askable is every ecosystem this has an index for.
//
// The one list, so that the pass selecting candidates can be built from it
// rather than from its complement. Maintained as a complement — one entry
// excluding distribution packages — every other unaskable ecosystem passed the
// filter, reached the asker, found none and was recorded empty, spending one
// of the two hundred slots a pass has. On an image with ten thousand Alpine
// packages that is fifty passes writing nothing before the Go and Rust
// components it can answer are reached.
//
// Sorted, so the condition a pass builds from this is the same statement every
// time rather than whatever order a map walk gave it.
func Askable() []string {
	names := make([]string, 0, len(askers))
	for name := range askers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// For returns the asker for an ecosystem, or nil where there is none.
//
// Named by the type in a package identifier, so the caller does not have to
// keep its own mapping of what is askable.
func (c *Client) For(ecosystem string) Asker {
	asker, held := askers[ecosystem]
	if !held {
		return nil
	}
	return asker(c)
}

// mostBody is how much of somebody else's document we will read.
//
// Generous, because an index answers with what it answers with and npm's full
// document for a widely-forked package runs to megabytes. Bounded, because an
// index having a bad day should not be able to exhaust us.
const mostBody = 32 << 20

func (c *Client) get(ctx context.Context, at string, into any) error {
	return c.getAs(ctx, at, "application/json", into)
}

func (c *Client) getAs(ctx context.Context, at, accept string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, at, nil)
	if err != nil {
		// The name could not be made into a request. That is a fact about the
		// component and will not come right on a retry, so it is reported as
		// such rather than as a transient failure the caller keeps returning
		// to.
		return fmt.Errorf("%w: %s: %w", ErrUnaskable, at, err)
	}
	req.Header.Set("User-Agent", c.Agent)
	req.Header.Set("Accept", accept)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return ErrUnknown
	case resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
		// A bad day: asked for too much, or the index itself is unwell.
		// Nothing is recorded, so the component stays due and the next pass
		// asks again.
		return fmt.Errorf("%w: %s answered %s", ErrNotAnswering, at, resp.Status)
	case resp.StatusCode != http.StatusOK:
		// Every other refusal is one the index will repeat: a package the
		// registry withdrew, a region it will not serve, a request it will
		// not accept in that shape. Recorded as asked, because an answer we
		// will never get is still an answer about this component.
		return fmt.Errorf("%w: %s answered %s", ErrUnaskable, at, resp.Status)
	}
	// One byte past the ceiling, so a document over it is refused as too large
	// rather than cut off and reported as unreadable — which sent the
	// component down the arm for a document nothing can parse and left it
	// there.
	body, err := io.ReadAll(io.LimitReader(resp.Body, mostBody+1))
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrNotAnswering, at, err)
	}
	if int64(len(body)) > mostBody {
		return fmt.Errorf("%w: %s answered more than the %d bytes this reads",
			ErrUnaskable, at, mostBody)
	}
	if err := json.Unmarshal(body, into); err != nil {
		// A document this cannot read is a fact about what the index serves
		// for this name rather than a bad day, so it is recorded.
		return fmt.Errorf("%w: %s: %w", ErrUnaskable, at, err)
	}
	return nil
}

// goProxy asks the module proxy, which answers with the version and its time
// in one request — the only index here that does.
type goProxy struct{ c *Client }

func (g goProxy) Latest(ctx context.Context, name string) (Latest, error) {
	var answer struct {
		Version string    `json:"Version"`
		Time    time.Time `json:"Time"`
		// Origin is where the module is developed, which the proxy
		// states and nothing else here has to work out. There is no
		// description anywhere in the protocol — not in this answer
		// and not in a go.mod — so a Go module carries an address and
		// no summary.
		Origin struct {
			URL string `json:"URL"`
		} `json:"Origin"`
	}
	// Escaped per segment, like every other asker here. This was the one that
	// interpolated the name raw, and a package identifier is somebody else's
	// input: `pkg:golang/foo%3Fx=1` decodes to a name carrying a `?`, which
	// turned the path into a query string and let an uploaded document choose
	// part of the request. The separators that belong are kept because the
	// split happens first.
	at := g.c.GoProxy + "/" + escapePath(escapeModule(name)) + "/@latest"
	if err := g.c.get(ctx, at, &answer); err != nil {
		return Latest{}, err
	}
	if answer.Version == "" {
		return Latest{}, ErrUnknown
	}
	return Latest{
		Version: answer.Version, Released: answer.Time, Project: answer.Origin.URL,
	}, nil
}

// escapePath escapes each segment of a module path, keeping the separators
// between them.
func escapePath(name string) string {
	segments := strings.Split(name, "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	return strings.Join(segments, "/")
}

// escapeModule spells a module path the way the proxy requires.
//
// An uppercase letter becomes "!" and its lowercase, because the proxy serves
// from a case-insensitive filesystem and would otherwise confuse two modules
// whose paths differ only in case.
func escapeModule(name string) string {
	var out strings.Builder
	for _, r := range name {
		if r >= 'A' && r <= 'Z' {
			out.WriteByte('!')
			out.WriteRune(r + ('a' - 'A'))
			continue
		}
		out.WriteRune(r)
	}
	return out.String()
}

type npmRegistry struct{ c *Client }

func (n npmRegistry) Latest(ctx context.Context, name string) (Latest, error) {
	var answer struct {
		DistTags    map[string]string `json:"dist-tags"`
		Time        map[string]string `json:"time"`
		Description string            `json:"description"`
		Homepage    string            `json:"homepage"`
		Repository  struct {
			URL string `json:"url"`
		} `json:"repository"`
	}
	// A scoped name keeps its slash escaped. "@types/node" is one package
	// rather than a package inside a directory, and unescaping it asks the
	// registry for something else entirely.
	at := n.c.NPM + "/" + url.PathEscape(name)
	if err := n.c.get(ctx, at, &answer); err != nil {
		// A definite "no such package" is already the answer. Asking the
		// abbreviated document for the same name returns the same 404, which
		// doubles the load on a free service for nothing.
		if errors.Is(err, ErrUnknown) {
			return Latest{}, err
		}
		// The full document is the only one npm dates each version in, and
		// for a heavily published package it is tens of megabytes. Where it
		// will not come back, the abbreviated one still says which version is
		// current — so we answer the half we can and leave the date empty.
		//
		// Empty rather than approximate. The abbreviated document carries a
		// "modified" time, and it is an *upper* bound on the newest release:
		// editing the metadata of an old version moves it. Using it would make
		// an abandoned package look freshly maintained, which is precisely the
		// mistake this date exists to prevent.
		version, second := n.abbreviated(ctx, at)
		if second != nil {
			return Latest{}, err
		}
		return Latest{Version: version}, nil
	}
	version := answer.DistTags["latest"]
	if version == "" {
		return Latest{}, ErrUnknown
	}
	return Latest{
		Version: version, Released: parseTime(answer.Time[version]),
		Summary: answer.Description,
		Project: firstOf(answer.Homepage, answer.Repository.URL),
	}, nil
}

func (n npmRegistry) abbreviated(ctx context.Context, at string) (string, error) {
	var answer struct {
		DistTags map[string]string `json:"dist-tags"`
	}
	if err := n.c.getAs(ctx, at, "application/vnd.npm.install-v1+json", &answer); err != nil {
		return "", err
	}
	version := answer.DistTags["latest"]
	if version == "" {
		return "", ErrUnknown
	}
	return version, nil
}

type pyPI struct{ c *Client }

func (p pyPI) Latest(ctx context.Context, name string) (Latest, error) {
	var answer struct {
		Info struct {
			Version string `json:"version"`
			// The one-line summary. Deliberately not "description", which in
			// this index is the package's whole README.
			Summary  string            `json:"summary"`
			HomePage string            `json:"home_page"`
			URLs     map[string]string `json:"project_urls"`
		} `json:"info"`
		URLs []struct {
			Uploaded string `json:"upload_time_iso_8601"`
		} `json:"urls"`
	}
	at := p.c.PyPI + "/pypi/" + url.PathEscape(name) + "/json"
	if err := p.c.get(ctx, at, &answer); err != nil {
		return Latest{}, err
	}
	if answer.Info.Version == "" {
		return Latest{}, ErrUnknown
	}
	// The earliest file of the newest release, because a release is dated by
	// when it appeared rather than by when somebody added another wheel to it.
	latest := Latest{
		Version: answer.Info.Version, Summary: answer.Info.Summary,
		// Whichever the project stated, in the order somebody reading about it
		// would want: its own pages before its repository.
		Project: firstOf(answer.Info.HomePage, answer.Info.URLs["Homepage"],
			answer.Info.URLs["Source"], answer.Info.URLs["Repository"]),
	}
	for _, file := range answer.URLs {
		at := parseTime(file.Uploaded)
		if at.IsZero() {
			continue
		}
		if latest.Released.IsZero() || at.Before(latest.Released) {
			latest.Released = at
		}
	}
	return latest, nil
}

type cratesIO struct{ c *Client }

func (r cratesIO) Latest(ctx context.Context, name string) (Latest, error) {
	var answer struct {
		Crate struct {
			MaxStable   string `json:"max_stable_version"`
			MaxAny      string `json:"max_version"`
			Description string `json:"description"`
			Homepage    string `json:"homepage"`
			Repository  string `json:"repository"`
		} `json:"crate"`
		Versions []struct {
			Num     string `json:"num"`
			Created string `json:"created_at"`
		} `json:"versions"`
	}
	at := r.c.Crates + "/api/v1/crates/" + url.PathEscape(name)
	if err := r.c.get(ctx, at, &answer); err != nil {
		return Latest{}, err
	}
	// A stable release where there is one. The newest thing published may be a
	// pre-release, and "you are behind" measured against a release candidate
	// is not a claim anybody should act on.
	version := answer.Crate.MaxStable
	if version == "" {
		version = answer.Crate.MaxAny
	}
	if version == "" {
		return Latest{}, ErrUnknown
	}
	latest := Latest{
		Version: version, Summary: answer.Crate.Description,
		Project: firstOf(answer.Crate.Homepage, answer.Crate.Repository),
	}
	for _, each := range answer.Versions {
		if each.Num == version {
			latest.Released = parseTime(each.Created)
			break
		}
	}
	return latest, nil
}

// firstOf is the first of several fields an index might have filled in.
//
// Three of the four state where a project lives in more than one place and fill
// in whichever the publisher bothered with, so the caller asks for them in the
// order a reader would want rather than picking one and hoping.
func firstOf(said ...string) string {
	for _, each := range said {
		if at := strings.TrimSpace(each); at != "" {
			return at
		}
	}
	return ""
}

// parseTime reads the shapes these indexes use, and gives up quietly.
//
// A date we cannot read is not a date of zero and not an error worth stopping
// for: the version is still the useful half, and the caller stores what it has.
func parseTime(text string) time.Time {
	if text == "" {
		return time.Time{}
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999",
		"2006-01-02T15:04:05",
	} {
		if at, err := time.Parse(layout, text); err == nil {
			return at.UTC()
		}
	}
	return time.Time{}
}
