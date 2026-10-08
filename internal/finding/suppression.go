// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

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
	Origin      string `bun:"origin,notnull"`
	SubjectPurl string `bun:"subject_purl"`
	SubjectName string `bun:"subject_name"`
	// SubjectFolded is the subject's name folded, which is what a name
	// somebody types is matched against. The name itself is the producer's
	// spelling and is what a screen shows.
	SubjectFolded string `bun:"subject_folded,nullzero"`
	// SubjectVersion is the version the claim was made about, where the
	// document stated one outside the package identifier. A publisher naming
	// no package states it as the branch its product sits in.
	SubjectVersion string `bun:"subject_version,nullzero"`
	// WithinPurl, WithinName and WithinVersion are the product the subject
	// ships inside, where the document named one. A claim about a component
	// inside a product of the build applies beneath that product; one whose
	// product is the build's root, or nothing the build ships, applies across
	// the build.
	WithinPurl    string `bun:"within_purl,nullzero"`
	WithinName    string `bun:"within_name,nullzero"`
	WithinVersion string `bun:"within_version,nullzero"`
	// StatedBy is the published statement this claim was taken from, where a
	// document uploaded on its own named the build's root as its product.
	// Nil for a claim the build sent with its inventory.
	StatedBy     *int64 `bun:"stated_by"`
	OpenedScanID int64  `bun:"opened_scan_id,notnull"`
	ClosedScanID *int64 `bun:"closed_scan_id"`
	// Said is when the claim was last said: the build's latest upload for a
	// claim sent with the inventory, which restates every claim it still
	// makes, and the last document that said the statement for one taken from
	// a published document. Read with the open claims, never stored.
	Said time.Time `bun:"said,scanonly"`
}

// Published is the origin of a claim taken from a published statement whose
// product is the build's root. The document arrived on its own rather than
// with an inventory, and what it says about the build is the build's own claim.
// A scan restates the claims of the two origins it reads, and never this one:
// a run keeps these in step with the statements that stand.
const Published = "published"

// within is the product a claim's target ships inside, and nil where the
// document named the target alone.
func (c Claim) within() *sbom.Target {
	if c.WithinPurl == "" && c.WithinName == "" {
		return nil
	}
	return &sbom.Target{Purl: c.WithinPurl, Name: c.WithinName, Version: c.WithinVersion}
}

// covers reports whether this claim is about the component described.
//
// At the version the claim was made about, where it names one: a statement
// that acme-fw 4.2 is not affected says nothing about acme-fw 5.0. A claim
// naming no version, in its identifier or beside it, covers every version of
// the name it states.
func (c Claim) covers(d graph.Described) bool {
	return sbom.Target{Purl: c.SubjectPurl, Name: c.SubjectName, Version: c.SubjectVersion}.Covers(d)
}

// suppresses reports whether the claim removes a finding from what somebody
// has to look at. A build saying it is affected, or that it has not decided,
// is information rather than an answer.
func (c Claim) suppresses() bool { return sbom.Status(c.Status).Suppresses() }

// fixes reports whether the claim closes the findings it covers.
func (c Claim) fixes() bool { return sbom.Status(c.Status).Fixes() }

// claimIdentity derives a stable key from what a claim says.
//
// Everything that makes the claim a different claim is in it, so re-sending
// the same argument writes nothing and changing the reasoning is a change. The
// version is part of it where one is stated, so a claim about 4.2 and one about
// 5.0 are two claims; a claim stating none outside its package identifier
// keys as it did before a version could be stored. The product the subject
// ships inside and the statement a claim was taken from are part of it the same
// way.
func claimIdentity(c Claim) string {
	parts := []string{
		strings.ToUpper(strings.TrimSpace(c.Vulnerability)),
		c.Status, c.Justification, c.Origin, c.SubjectPurl, c.SubjectName,
	}
	if c.SubjectVersion != "" {
		parts = append(parts, c.SubjectVersion)
	}
	// A claim about zlib inside curl and one about every zlib are two claims.
	// A claim naming no product keys as it did before a product was stored.
	if c.WithinPurl != "" || c.WithinName != "" {
		parts = append(parts, "within", c.WithinPurl, c.WithinName, c.WithinVersion)
	}
	if c.StatedBy != nil {
		parts = append(parts, "stated", fmt.Sprint(*c.StatedBy))
	}
	basis := strings.Join(parts, "\x00")
	sum := sha256.Sum256([]byte(basis))
	return hex.EncodeToString(sum[:])
}

// statedBeside is the version a claim states outside its package identifier,
// and nothing where the identifier carries one: that version is already part of
// the claim through the identifier, and storing it twice would give every claim
// about a versioned identifier a new identity.
func statedBeside(subject sbom.Target) string {
	if _, inside := graph.PackageOf(subject.Purl); inside != "" {
		return ""
	}
	return strings.TrimSpace(subject.Version)
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
					SubjectFolded:  graph.Folded(subject.Name),
					SubjectVersion: statedBeside(subject),
					OpenedScanID:   scanID,
				}
				if subject.Within != nil {
					row.WithinPurl = subject.Within.Purl
					row.WithinName = subject.Within.ComponentNamed()
					row.WithinVersion = subject.Within.VersionNamed()
				}
				row.Identity = claimIdentity(row)
				wanted[row.Identity] = row
			}
		}

		// A claim taken from a document uploaded on its own is no scan's to
		// restate or withdraw.
		var open []Claim
		err := tx.NewSelect().Model(&open).
			Where("target_id = ?", targetID).Where("closed_scan_id IS NULL").
			Where("origin <> ?", Published).Scan(ctx)
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
		ColumnExpr("sup.*").
		Join(`JOIN "target" AS "t" ON t.id = sup.target_id`).
		Join(`JOIN "scan" AS "latest" ON latest.id = t.last_scan_id`).
		Join(`LEFT JOIN "vex_statement" AS "ss" ON ss.id = sup.stated_by`).
		ColumnExpr(`COALESCE(ss.restated_at, ss.uploaded_at, latest.received_at) AS "said"`).
		Where("sup.target_id = ?", targetID).Where("sup.closed_scan_id IS NULL").
		Order("sup.id").Scan(ctx)
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
	// Version is the version of the subject the claim was made about, where
	// the document stated one outside the package identifier, and empty
	// otherwise.
	Version string
	// Status is what the build claimed in the exchange format's own
	// vocabulary, Justification the term it gave, and Statement the reasoning.
	Status        string
	Justification string
	Statement     string
	// Within and WithinVersion are the product of the build the claim names
	// its subject as shipping inside, where it names one: "zlib inside curl"
	// and "zlib inside openssl" are two claims.
	Within        string
	WithinVersion string
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

	// A build's own claims say what it ships and what it has patched, which is
	// as much about the build as its inventory is — so it is read by whoever
	// may read the product's findings and by nobody else.
	_, _, err := readableIn(ctx, s.db, subject, targetID)
	if err != nil {
		return nil, 0, err
	}
	limit = database.AList.Of(limit)

	where := func(q *bun.SelectQuery) *bun.SelectQuery {
		// What the build sent with its inventories. A claim taken from a
		// document uploaded on its own is shown on the findings it covers,
		// and it is held over no stretch of the build's own scans.
		q = q.Where("sup.target_id = ?", targetID).Where("sup.origin <> ?", Published)
		if name := strings.TrimSpace(component); name != "" {
			// Matched on what the claim says it is about rather than on a
			// component row, because a claim naming something this build does
			// not carry is exactly the row somebody is looking for when they
			// ask why a patch stopped working.
			q = q.Where("sup.subject_folded = ?", graph.Folded(name))
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
		Version       string     `bun:"version"`
		Status        string     `bun:"status"`
		Justification string     `bun:"justification"`
		Statement     string     `bun:"statement"`
		Origin        string     `bun:"origin"`
		WithinPurl    string     `bun:"within_purl"`
		WithinName    string     `bun:"within_name"`
		WithinVersion string     `bun:"within_version"`
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
		ColumnExpr(`COALESCE(sup.subject_version, '') AS "version"`).
		ColumnExpr(`sup.status AS "status"`).
		ColumnExpr(`COALESCE(sup.justification, '') AS "justification"`).
		ColumnExpr(`COALESCE(sup.statement, '') AS "statement"`).
		ColumnExpr(`sup.origin AS "origin"`).
		ColumnExpr(`COALESCE(sup.within_purl, '') AS "within_purl"`).
		ColumnExpr(`COALESCE(sup.within_name, '') AS "within_name"`).
		ColumnExpr(`COALESCE(sup.within_version, '') AS "within_version"`).
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
		var within, withinVersion string
		if row.WithinPurl != "" || row.WithinName != "" {
			product := sbom.Target{Purl: row.WithinPurl, Name: row.WithinName, Version: row.WithinVersion}
			within, withinVersion = product.ComponentNamed(), product.VersionNamed()
		}
		out = append(out, Carried{
			Within: within, WithinVersion: withinVersion,
			Vulnerability: row.Vulnerability, Subject: row.Subject, Version: row.Version,
			Status: row.Status, Justification: row.Justification,
			Statement: row.Statement,
			Pedigree:  sbom.Origin(row.Origin) == sbom.FromPedigree,
			Since:     row.Since, Until: row.Until,
			Suppresses: sbom.Status(row.Status).Suppresses(),
		})
	}
	return out, total, nil
}
