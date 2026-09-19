package finding

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// Claim is one thing a build argued about one vulnerability in one of the
// things it ships.
//
// A statement naming several packages becomes several of these. Each row is a
// claim about one subject, because that is what has to be matched against a
// component and because a claim that reached one package and not another is a
// thing worth being able to see.
type Claim struct {
	bun.BaseModel `bun:"table:suppression,alias:sup"`

	ID       int64  `bun:"id,pk,autoincrement"`
	TargetID int64  `bun:"target_id,notnull"`
	Identity string `bun:"identity,notnull"`
	// Vulnerability is the identifier the build argued about, as it wrote it.
	Vulnerability string `bun:"vulnerability,notnull"`
	Status        string `bun:"status,notnull"`
	Justification string `bun:"justification"`
	Statement     string `bun:"statement"`
	// Origin says whether this came attached to a component or in a document
	// of its own, which is the difference between a claim that knows exactly
	// what it is about and one that names something we have to match.
	Origin       string `bun:"origin,notnull"`
	SubjectPurl  string `bun:"subject_purl"`
	SubjectName  string `bun:"subject_name"`
	OpenedScanID int64  `bun:"opened_scan_id,notnull"`
	ClosedScanID *int64 `bun:"closed_scan_id"`
}

// covers reports whether this claim is about the component described.
func (c Claim) covers(d graph.Described) bool {
	return sbom.Target{Purl: c.SubjectPurl, Name: c.SubjectName}.Covers(d)
}

// suppresses reports whether the claim removes a finding from what somebody
// has to look at. A build saying it is affected, or that it has not decided,
// is information rather than an answer.
func (c Claim) suppresses() bool { return sbom.Status(c.Status).Suppresses() }

// claimIdentity derives a stable key from what a claim says.
//
// Everything that makes the claim a different claim is in it, so re-sending
// the same argument writes nothing and changing the reasoning is a change.
func claimIdentity(c Claim) string {
	basis := strings.Join([]string{
		strings.ToUpper(strings.TrimSpace(c.Vulnerability)),
		c.Status, c.Justification, c.Origin, c.SubjectPurl, c.SubjectName,
	}, "\x00")
	sum := sha256.Sum256([]byte(basis))
	return hex.EncodeToString(sum[:])
}

// ClaimsApplied describes what recording a build's claims changed.
type ClaimsApplied struct {
	Opened int
	Closed int
	// Unstated counts claims left open because the scan's format could not
	// express them, rather than because the build repeated them.
	Unstated int
}

// Unchanged reports whether a build argued exactly what it argued last time.
func (a ClaimsApplied) Unchanged() bool { return a.Opened == 0 && a.Closed == 0 }

// RecordClaims stores what a build argued, writing only the difference.
//
// Kept as data rather than left in the document it arrived in: a nightly
// scan's documents are discarded once read, the scan itself runs later, and it
// runs again on a schedule. A claim that lived only in the file would be gone
// by the time anything needed it, and every carried patch would come back as
// an outstanding vulnerability on the next re-scan.
//
// stated is where the scan could have made a claim, and a claim of any
// other origin is left alone rather than closed. Closing works by difference —
// a claim the build no longer argues is a claim the build withdrew — and that
// reading only holds where the build had somewhere to argue it. An inventory
// in a format that cannot attach a claim to a component says nothing about
// carried patches whether or not the patches are still carried, so a product
// moving from one format to the other would otherwise close every claim it had
// at once and reopen every finding they suppressed, with nothing saying why.
func (s *Store) RecordClaims(ctx context.Context, targetID, scanID int64, claims []sbom.Suppression, stated map[sbom.Origin]bool) (ClaimsApplied, error) {
	var applied ClaimsApplied
	err := database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		var err error
		applied, err = RecordClaimsWithin(ctx, tx, targetID, scanID, claims, stated)
		return err
	})
	return applied, err
}

// RecordClaimsWithin is the same, inside a transaction the caller opened.
//
// Ingest applies a graph and records what the build argued about its own
// patches as one act: claims recorded without the graph, or a graph without
// them, is a build reading as having withdrawn every patch it carries.
func RecordClaimsWithin(ctx context.Context, tx bun.IDB, targetID, scanID int64,
	claims []sbom.Suppression, stated map[sbom.Origin]bool) (ClaimsApplied, error) {

	var applied ClaimsApplied
	err := func() error {
		wanted := map[string]Claim{}
		for _, claim := range claims {
			for _, subject := range claim.Targets {
				row := Claim{
					TargetID: targetID, Vulnerability: claim.Vulnerability,
					Status: string(claim.Status), Justification: claim.Justification,
					Statement: claim.Statement, Origin: string(claim.Origin),
					SubjectPurl: subject.Purl, SubjectName: subject.Name,
					OpenedScanID: scanID,
				}
				row.Identity = claimIdentity(row)
				wanted[row.Identity] = row
			}
		}

		var open []Claim
		err := tx.NewSelect().Model(&open).
			Where("target_id = ?", targetID).Where("closed_scan_id IS NULL").Scan(ctx)
		if err != nil {
			return fmt.Errorf("read what this build argued before: %w", err)
		}

		held := map[string]int64{}
		for _, row := range open {
			held[row.Identity] = row.ID
		}

		var opening []Claim
		for identity, row := range wanted {
			if _, already := held[identity]; !already {
				opening = append(opening, row)
			}
		}
		if len(opening) > 0 {
			if err := database.InBatches(ctx, tx, opening); err != nil {
				return fmt.Errorf("record %d claims: %w", len(opening), err)
			}
			applied.Opened = len(opening)
		}

		var closing []int64
		for _, row := range open {
			if _, still := wanted[row.Identity]; still {
				continue
			}
			if !stated[sbom.Origin(row.Origin)] {
				// The scan had nowhere to say this. Left open, and counted so
				// a receipt can say how many claims this scan carried forward
				// without restating.
				applied.Unstated++
				continue
			}
			closing = append(closing, held[row.Identity])
		}
		if len(closing) > 0 {
			err := database.IDsInBatches(ctx, closing, func(ctx context.Context, batch []int64) error {
				_, err := tx.NewUpdate().Model((*Claim)(nil)).
					Set("closed_scan_id = ?", scanID).
					Where("id IN (?)", bun.List(batch)).Exec(ctx)
				return err
			})
			if err != nil {
				return fmt.Errorf("close %d claims: %w", len(closing), err)
			}
			applied.Closed = len(closing)
		}
		return nil
	}()
	return applied, err
}

func openClaims(ctx context.Context, db bun.IDB, targetID int64) ([]Claim, error) {
	// Ordered so that reading them twice gives the same answer. Where two
	// claims cover one finding and neither is the precise sort, which one is
	// recorded should not depend on what a map felt like doing.
	var rows []Claim
	err := db.NewSelect().Model(&rows).
		Where("target_id = ?", targetID).Where("closed_scan_id IS NULL").
		Order("id").Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read what this build argues: %w", err)
	}
	return rows, nil
}

// Carried is one thing a build says it has dealt with itself, and the stretch
// of scans it has been saying it over.
type Carried struct {
	// Vulnerability is the identifier the build argued about, as it wrote it,
	// and Subject what it said the claim was about.
	Vulnerability string
	Subject       string
	// Status is what the build claimed in the exchange format's own
	// vocabulary, Justification the term it gave, and Statement the reasoning.
	Status        string
	Justification string
	Statement     string
	// Pedigree says the claim arrived attached to a component rather than in a
	// document of its own — a carried patch declaring what it fixes, which is
	// the only way a backport can be seen here at all.
	Pedigree bool
	// Since is when the build first said it, and Until when it stopped. A
	// claim it is still making has no Until, which is the ordinary case.
	Since time.Time
	Until *time.Time
	// Suppresses says the claim takes a finding off the list rather than
	// merely recording what the build thinks: "affected" and "under
	// investigation" are information, not answers.
	Suppresses bool
}

// CarriedPatches is what a build has been declaring it deals with itself, over
// time.
//
// The one thing a version comparison can never see. A distribution carries
// a fix into a package without moving its version, and the only evidence of it
// is the build saying so in its own inventory — which is stored here and, until
// now, read by nothing a person could reach. So the answer to "when did we
// start carrying this, and are we still" was in the database and nowhere else.
//
// Held over intervals against scans, like the graph: a build argues the
// same things night after night, and the stretch is what makes this a history
// rather than a list of what is true tonight. A claim that stopped is the
// interesting row — somebody dropped a patch, and the finding it answered is
// back — and it is the row a list of what is current would not have.
func (s *Store) CarriedPatches(ctx context.Context, subject access.Subject, targetID int64,
	component string, limit, offset int) ([]Carried, int, error) {

	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return nil, 0, err
	}
	// A build's own claims say what it ships and what it has patched, which is
	// as much about the build as its inventory is — so it is read by whoever
	// may read the product's findings and by nobody else.
	if !subject.Sees(productID) {
		return nil, 0, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	limit = database.AList.Of(limit)

	where := func(q *bun.SelectQuery) *bun.SelectQuery {
		q = q.Where("sup.target_id = ?", targetID)
		if name := strings.TrimSpace(component); name != "" {
			// Matched on what the claim says it is about rather than on a
			// component row, because a claim naming something this build does
			// not carry is exactly the row somebody is looking for when they
			// ask why a patch stopped working.
			q = q.Where("LOWER(sup.subject_name) = ?", strings.ToLower(name))
		}
		return q
	}

	total, err := where(s.db.NewSelect().Model((*Claim)(nil))).Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count what this build carries: %w", err)
	}

	var rows []struct {
		Vulnerability string     `bun:"vulnerability"`
		Subject       string     `bun:"subject"`
		Status        string     `bun:"status"`
		Justification string     `bun:"justification"`
		Statement     string     `bun:"statement"`
		Origin        string     `bun:"origin"`
		Since         time.Time  `bun:"since"`
		Until         *time.Time `bun:"until"`
	}
	q := where(s.db.NewSelect().Model((*Claim)(nil))).
		// The moment it was first said and the moment it stopped, read off the
		// scans the interval is held against: the claim itself carries scan
		// identifiers, and a screen needs moments.
		Join(`JOIN "scan" AS "opened" ON opened.id = sup.opened_scan_id`).
		Join(`LEFT JOIN "scan" AS "closed" ON closed.id = sup.closed_scan_id`).
		ColumnExpr(`sup.vulnerability AS "vulnerability"`).
		ColumnExpr(`COALESCE(NULLIF(sup.subject_name, ''), sup.subject_purl) AS "subject"`).
		ColumnExpr(`sup.status AS "status"`).
		ColumnExpr(`COALESCE(sup.justification, '') AS "justification"`).
		ColumnExpr(`COALESCE(sup.statement, '') AS "statement"`).
		ColumnExpr(`sup.origin AS "origin"`).
		ColumnExpr(`opened.built_at AS "since"`).
		ColumnExpr(`closed.built_at AS "until"`).
		// Anything still being said first, newest first within that: a claim
		// that stopped is history and a claim that stands is the estate.
		OrderExpr("CASE WHEN sup.closed_scan_id IS NULL THEN 0 ELSE 1 END, " +
			"opened.built_at DESC, sup.id DESC").
		Limit(limit).Offset(offset)
	if err := q.Scan(ctx, &rows); err != nil {
		return nil, 0, fmt.Errorf("read what this build carries: %w", err)
	}
	out := make([]Carried, 0, len(rows))
	for _, row := range rows {
		out = append(out, Carried{
			Vulnerability: row.Vulnerability, Subject: row.Subject,
			Status: row.Status, Justification: row.Justification,
			Statement: row.Statement,
			Pedigree:  sbom.Origin(row.Origin) == sbom.FromPedigree,
			Since:     row.Since, Until: row.Until,
			Suppresses: sbom.Status(row.Status).Suppresses(),
		})
	}
	return out, total, nil
}
