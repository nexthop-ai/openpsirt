package finding

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// Statement is what a VEX document says about a component we ship.
//
// A third layer beside the build's own claims and our decisions. Evidence, and
// a prefill; never applied to anything by itself.
type Statement struct {
	bun.BaseModel `bun:"table:vex_statement,alias:ss"`

	ID        int64 `bun:"id,pk,autoincrement"`
	ProductID int64 `bun:"product_id,notnull"`
	// Publisher is who published it and Vulnerability and Component what
	// it is about. All three are normalized on the way in, so a match is
	// an equality test rather than something an engine is asked to fold —
	// the four fold differently outside ASCII, and asking them to would
	// make whether a statement attaches to a finding depend on which one
	// is running. It also leaves the index over these columns usable,
	// which wrapping them in a function did not.
	Publisher     string `bun:"publisher,notnull"`
	Vulnerability string `bun:"vulnerability,notnull"`
	Purl          string `bun:"purl"`
	Component     string `bun:"component,notnull"`
	// Status is what they said in the format's own vocabulary, Justification
	// the term they gave for it, and Statement the reasoning — which is the
	// part worth having, because the status is in the fix state already.
	Status        string `bun:"status,notnull"`
	Justification string `bun:"justification"`
	Statement     string `bun:"statement"`
	// Document and Digest say where it came from and what it hashed to, so a
	// revision can be noticed rather than silently replacing what an approval
	// was granted against.
	Document   string     `bun:"document,notnull"`
	Digest     string     `bun:"digest,notnull"`
	UploadedBy int64      `bun:"uploaded_by,notnull"`
	UploadedAt time.Time  `bun:"uploaded_at,notnull"`
	Superseded *time.Time `bun:"superseded_at"`
}

// Prefills is the outcome a statement offers, and whether it offers one.
//
// **A distribution saying it will not fix something is not the distribution
// saying it is not affected**. Debian's `no-dsa`, Ubuntu's `ignored`
// and Red Hat's will-not-fix all mean *affected, and judged minor* — so they
// offer a will-not-fix, never a dismissal. Prefilling `not-applicable` from one
// would record a claim the publisher never made, with their name on it, which
// is the one way a third party's evidence turns into a lie rather than into
// help.
func (s Statement) Prefills() (outcome string, offers bool) {
	switch s.Status {
	case "not_affected":
		// The one status that *is* a claim of non-applicability, and the
		// justification is the publisher's own term from the same vocabulary
		// ours uses.
		return "not-applicable", true
	case "affected":
		// They say it applies and they are not fixing it here, which is a
		// will-not-fix in our vocabulary and never a dismissal.
		return "wont-fix", true
	case "fixed":
		return "already-fixed", true
	}
	// Under investigation offers nothing: it is a publisher saying they do not
	// know yet, and a prefill from it would be a judgment nobody made.
	return "", false
}

// RecordStatements replaces what one VEX publisher has said about one product.
//
// Superseded rather than deleted: what an approval was granted on the strength
// of has to stay readable, which is the same reason a withdrawn decision is a
// state rather than a delete. Everything the publisher said before this
// document is marked superseded, and what this document says is written — so
// "they changed their mind" is a fact the record holds rather than one it
// silently loses.
func (s *Store) RecordStatements(ctx context.Context, by access.Subject, productID int64,
	publisher, document, digest string, said []Statement) (recorded, superseded int, err error) {

	publisher = strings.ToLower(strings.TrimSpace(publisher))
	if publisher == "" {
		return 0, 0, fmt.Errorf("a statement is somebody's, and this document names nobody")
	}
	// Refused here as well as at the endpoint, because this is reachable from
	// any other caller and what it is refusing is a key collapsing into
	// somebody else's.
	if len(publisher) > MostPublisher {
		return 0, 0, fmt.Errorf(
			"who published it is longer than the %d characters this records", MostPublisher)
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	err = database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		recorded, superseded = 0, 0
		res, err := tx.NewUpdate().Model((*Statement)(nil)).
			Set("superseded_at = ?", now).
			Where("product_id = ?", productID).
			Where("publisher = ?", publisher).
			Where("superseded_at IS NULL").
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("set aside what they said before: %w", err)
		}
		n, err := database.Affected(res)
		if err != nil {
			return fmt.Errorf("set aside what they said before: %w", err)
		}
		superseded = int(n)
		for i := range said {
			said[i].ProductID = productID
			said[i].Publisher = publisher
			said[i].Vulnerability = folded(said[i].Vulnerability)
			said[i].Component = folded(said[i].Component)
			said[i].Document, said[i].Digest = document, digest
			said[i].UploadedBy, said[i].UploadedAt = by.ID, now
			said[i].Superseded = nil
			if _, err := tx.NewInsert().Model(&said[i]).Exec(ctx); err != nil {
				return fmt.Errorf("record what they said: %w", err)
			}
			recorded++
		}
		return nil
	})
	return recorded, superseded, err
}

// SaidAbout is what VEX publishers have said about one issue at one component,
// newest first, standing statements only.
//
// Matched on the issue's name and its aliases, because which identifier a
// publisher chose is a preference of whichever database they consulted.
func (s *Store) SaidAbout(ctx context.Context, subject access.Subject, productID,
	vulnerabilityID int64, names []string, component, purl string) ([]Statement, error) {

	// Asked about the issue rather than about the product, because what comes
	// back is narrowed to this issue's names and this component — it is
	// evidence for the one finding, and a collaborator brought in on that
	// finding is who it is for. Asked product-wide, the detail route answered
	// a fault for the one row their grant exists to let them open.
	if !access.SeesOn(subject, productID, vulnerabilityID) {
		return nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	if len(names) == 0 || strings.TrimSpace(component) == "" {
		return nil, nil
	}
	lowered := make([]string, 0, len(names))
	for _, name := range names {
		lowered = append(lowered, folded(name))
	}
	var said []Statement
	err := s.db.NewSelect().Model(&said).
		Where("product_id = ?", productID).
		Where("superseded_at IS NULL").
		Where("vulnerability IN (?)", bun.List(lowered)).
		Where("component = ?", folded(component)).
		Order("uploaded_at DESC", "id DESC").Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read what publishers have said about this: %w", err)
	}
	return namingTheSamePackage(said, purl), nil
}

// namingTheSamePackage drops statements whose package identifier names
// something other than this component.
//
// The stored name is the short one, because that is what a component in the
// graph is called and matching on anything else would match nothing. A short
// name is not a package, though: two registries and two namespaces hold
// different packages under one, so a publisher's statement about
// `pkg:npm/@acme/parser` was shown against every component called `parser`,
// from anywhere, with that publisher's name on it.
//
// Compared in the type and the namespace, never the version: a statement says
// which versions it is about in its own terms, and this only asks whether the
// two are the same package. A statement that carries no identifier is kept —
// that is the claim against a source tree, which the name is all there is of.
func namingTheSamePackage(said []Statement, purl string) []Statement {
	here := graph.PartsOfPurl(purl)
	if here.Name == "" {
		return said
	}
	kept := make([]Statement, 0, len(said))
	for _, one := range said {
		there := graph.PartsOfPurl(one.Purl)
		if there.Name != "" && (there.Type != here.Type ||
			!strings.EqualFold(there.Namespace, here.Namespace)) {
			continue
		}
		kept = append(kept, one)
	}
	return kept
}

// MostPublisher is how long the name of whoever published a statement may be.
//
// The width of the column, which carries an index. Refused rather than
// shortened: it is the key a later upload supersedes on, so two publishers
// agreeing for that many characters would collapse into one and the second
// upload would set aside statements it has nothing to do with.
const MostPublisher = 191

// folded is how a name is stored so that every engine compares it alike.
//
// Done here rather than by the engine because the four do not agree: SQLite's
// LOWER folds ASCII and nothing else, while the three servers fold the whole
// character set — so a component named with any letter outside ASCII matched a
// statement on three engines and not on the fourth, and which one a deployment
// runs decided whether a publisher's judgment reached a finding. Normalizing
// on write is the same answer matching a typed name without capitals gives for
// every other name people type.
func folded(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
