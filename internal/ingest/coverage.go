package ingest

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// Coverage is when a build was last scanned, and whether that is long enough
// ago to be worth saying out loud.
//
// A build that stops being scanned looks healthier than one that is: no new
// findings appear against it, every count holds still, and nothing fails. It
// is the one failure that makes every other number here wrong rather than
// merely incomplete, so it is reported rather than left to be noticed.
//
// A build nothing has ever been filed against is the same failure caught
// earlier, so it is included and measured from when it was declared. A
// pipeline that was pointed at a name nobody declared is refused loudly; one
// declared and never pointed at anything fails silently, and this is what
// says so.
type Coverage struct {
	ProductID  int64
	Product    string
	Stream     string
	StreamKind string
	Variant    string
	// LastReceivedAt is when a scan that could be read last arrived, or nil
	// where none ever has. An upload that was taken and could not be parsed
	// is not one of these: it is the producer being heard from and the build
	// still not being scanned.
	LastReceivedAt *time.Time
	// LastRefusedAt is when an upload against this build was last turned away,
	// and RefusedBecause what the producer was told. Both nil where nothing
	// has been refused.
	//
	// Beside the quiet count rather than folded into it: quiet says nothing
	// arrived, and this says something arrived and was not taken. A build that
	// is quiet and being refused is a pipeline failing nightly; one that is
	// quiet and has never been refused is a pipeline nobody wired up.
	LastRefusedAt  *time.Time
	RefusedBecause *string
	// Since is how long it has been, measured from the last arrival or, where
	// there has never been one, from when the build was declared.
	Since time.Duration
	// Quiet is whether Since has passed the threshold asked for.
	//
	// Never true for a build out of support, nor for one taken out of use: a
	// release that stopped being scanned because it stopped being supported
	// is expected rather than a fault, and a build nothing may be filed
	// against cannot stop being silent — the scan that would is refused.
	// Coverage that filled with either would stop catching the product that
	// dropped out silently.
	Quiet bool
	// OutOfSupport says this build's release has gone out of support. It is
	// reported rather than left out, because "not scanned, and that is
	// fine" and "not listed" are different answers and only one of them is
	// true .
	//
	// Not the same as taken out of use, which is RetiredFromUse below. A date
	// says support ended and hides nothing; retiring says the build is not
	// tracked here at all.
	OutOfSupport bool
	// RetiredFromUse says the product, the release or the variant has been
	// taken out of use. Nothing may be filed against such a build, so it is
	// never quiet: the one act that would end the silence is refused.
	RetiredFromUse bool
}

// Scanning reports when each build in scope was last scanned, quietest first.
//
// Ordering by silence rather than by name is the point: the answer somebody
// needs is which build has stopped, and a list alphabetical by product buries
// it among the ones that are fine.
//
// quietAfter of zero or less reports every build with Quiet false, which is
// how a caller asks "when was each of these last seen" without also asking
// for a judgment about it.
func (s *Store) Scanning(ctx context.Context, subject access.Subject, scope finding.Scope,
	quietAfter time.Duration) ([]Coverage, error) {

	// A person's question. A pipeline key sees the receipts for what it sent
	// and nothing more, and when a build was last scanned by anybody is a fact
	// about the deployment rather than about that key's uploads.
	// Not merely empty: "here is nothing" and "you cannot ask" are
	// different statements, and this is the second. A person holding
	// nothing is the first, and is answered below.
	if subject.Kind != access.Person {
		return nil, access.Denied("read when these were last scanned")
	}
	products, all := subject.Products()
	if !all && len(products) == 0 {
		return nil, nil
	}

	var rows []struct {
		ProductID  int64      `bun:"product_id"`
		StreamID   int64      `bun:"stream_id"`
		Product    string     `bun:"product"`
		Stream     string     `bun:"stream"`
		StreamKind string     `bun:"stream_kind"`
		Variant    string     `bun:"variant"`
		DeclaredAt time.Time  `bun:"declared_at"`
		LastSeen   *time.Time `bun:"last_seen"`
		// LastRefused is when an upload against this build was last turned
		// away, which is what tells a quiet build apart from one being
		// refused. Null where nothing has been.
		LastRefused *time.Time `bun:"last_refused"`
		RefusedWhy  *string    `bun:"refused_why"`
		// RetiredFromUse is whether any of the three levels is out of use.
		RetiredFromUse bool `bun:"retired_from_use"`
	}

	// One row per declared build, with the newest arrival against it as a
	// correlated subquery rather than a join: a build with no scans is the
	// case this exists to report, and joining the scan table would drop
	// exactly those rows.
	query := s.db.NewSelect().
		TableExpr(`"target" AS "tg"`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN "product" AS "p" ON p.id = st.product_id`).
		Join(`JOIN "variant" AS "va" ON va.id = tg.variant_id`).
		ColumnExpr(`st.product_id AS "product_id"`).
		ColumnExpr(`st.id AS "stream_id"`).
		ColumnExpr(`p.name AS "product"`).
		ColumnExpr(`st.name AS "stream"`).
		ColumnExpr(`st.kind AS "stream_kind"`).
		ColumnExpr(`va.name AS "variant"`).
		ColumnExpr(`tg.created_at AS "declared_at"`).
		// Out of use at any of the three levels. A build is a product, a
		// release and a variant together, and retiring any one of them stops
		// a scan being filed against it.
		ColumnExpr(`(CASE WHEN p.retired_at IS NULL AND st.retired_at IS NULL `+
			`AND va.retired_at IS NULL THEN ? ELSE ? END) AS "retired_from_use"`,
			false, true).
		// Only a scan that could be read counts as having been heard from. A
		// build whose upload is taken nightly and fails to parse nightly is
		// the failure this report exists for, and counting the arrival drew
		// it as perfectly quiet on the one report whose subject is that
		// silence must not look like health.
		ColumnExpr(`(SELECT MAX(sc.received_at) FROM "scan" AS "sc" `+
			`WHERE sc.target_id = tg.id AND sc.status = ?) AS "last_seen"`, Accepted).
		// And whether anybody is trying. Quiet says nothing arrived; this says
		// whether something arrived and was turned away, which is a different
		// fault with a different person to tell — a pipeline nobody wired up,
		// against one failing nightly and reporting success to its own log.
		ColumnExpr(`(SELECT sr.at FROM "scan_refusal" AS "sr" ` +
			`WHERE sr.target_id = tg.id) AS "last_refused"`).
		ColumnExpr(`(SELECT sr.reason FROM "scan_refusal" AS "sr" ` +
			`WHERE sr.target_id = tg.id) AS "refused_why"`)
	if !all {
		query = query.Where("st.product_id IN (?)", bun.List(products))
	}
	query = scope.Narrow(query)

	if err := query.Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read when each build was last scanned: %w", err)
	}

	now := s.now().UTC()
	// The releases out of support, read once for the whole list. "Past end of
	// life" is spelled in the catalog and nowhere else, because the same fact
	// decides whether a finding carries a deadline and what this list says
	// about a build.
	ended, err := catalog.NewStore(s.db).StreamsPastEndOfLife(ctx, now)
	if err != nil {
		return nil, err
	}
	past := make(map[int64]bool, len(ended))
	for _, id := range ended {
		past[id] = true
	}

	out := make([]Coverage, 0, len(rows))
	for _, r := range rows {
		from := r.DeclaredAt
		if r.LastSeen != nil {
			from = *r.LastSeen
		}
		since := now.Sub(from.UTC())
		// A clock that disagrees with a stored timestamp reads as a build
		// scanned in the future, and a negative age sorts to the top of a list
		// meant to lead with the worst.
		if since < 0 {
			since = 0
		}
		out = append(out, Coverage{
			ProductID:      r.ProductID,
			Product:        r.Product,
			Stream:         r.Stream,
			StreamKind:     r.StreamKind,
			Variant:        r.Variant,
			LastReceivedAt: r.LastSeen,
			LastRefusedAt:  r.LastRefused,
			RefusedBecause: r.RefusedWhy,
			Since:          since,
			OutOfSupport:   past[r.StreamID],
			RetiredFromUse: r.RetiredFromUse,
			Quiet: quietAfter > 0 && since > quietAfter &&
				!past[r.StreamID] && !r.RetiredFromUse,
		})
	}

	// Quietest first, and by name where two have been silent equally long, so
	// the order does not shuffle between reads.
	slices.SortFunc(out, func(a, b Coverage) int {
		if a.Since != b.Since {
			if a.Since > b.Since {
				return -1
			}
			return 1
		}
		return strings.Compare(
			a.Product+"\x00"+a.Stream+"\x00"+a.Variant,
			b.Product+"\x00"+b.Stream+"\x00"+b.Variant)
	})
	return out, nil
}
