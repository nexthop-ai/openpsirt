package finding

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
)

// Upgrade is one build's commitment to move a fold.
//
// Keyed on the build and the fold — the source package at the version it was
// built at — because that is the unit the work is done in. It was keyed per
// issue and per component and per target version, so changing which version a
// release was moving to meant rewriting every row of it, and an issue that
// arrived overnight against the same package was not covered until somebody
// declared it too.
//
// **Coverage is a join, not a stamp.** A finding is covered when its component
// folds to this key in this build; nothing is written onto findings. So one row
// changes the version and everything covered follows, and a bump declared today
// answers a vulnerability published tomorrow with nobody acting.
type Upgrade struct {
	bun.BaseModel `bun:"table:upgrade,alias:ug"`

	ID       int64  `bun:"id,pk,autoincrement"`
	TargetID int64  `bun:"target_id,notnull"`
	FoldKey  string `bun:"fold_key,notnull"`
	// FromVersion is the version in hand when the commitment was made and
	// ToVersion the version it moves to. Both are kept because neither can be
	// recovered: they are read off the findings that are still open, and
	// landing the bump closes them. A plan that stops naming the versions as
	// the work succeeds is a plan that goes blank exactly when it is working.
	FromVersion string `bun:"from_version,notnull"`
	ToVersion   string `bun:"to_version,notnull"`
	// CommittedTo is when the work will have happened, where a judgment
	// promised a date. Absent where the plan is intent rather than a promise.
	CommittedTo *time.Time `bun:"committed_to"`
	// ClaimID is the claim that argued for it, where one did. A citation:
	// editing the commitment is editing what somebody agreed to, so it goes
	// through the act that withdraws the agreement.
	ClaimID    *int64    `bun:"claim_id"`
	DeclaredBy int64     `bun:"declared_by,notnull"`
	DeclaredAt time.Time `bun:"declared_at,notnull"`
}

// CommitWithin records a commitment to move a fold, against a database handle
// the caller owns.
//
// Exported and taking a handle because promising one bump is one act that
// writes both a judgment and a commitment for every build it reaches, and those
// live in two packages. One act is one transaction, so the transaction has to
// be opened once, outside both — half a bump declared is a release plan that is
// a lie.
//
// `wanted` is already resolved to builds and `retired` says which of them are
// out of support. Both are the caller's to read, and the caller reads them
// inside the transaction it opened, for the reason reading inside the
// transaction gives: a retry runs this against a database that has moved, so a
// build list settled beforehand describes a world that may be gone.
func (s *Store) CommitWithin(ctx context.Context, db bun.IDB, subject access.Subject,
	productID, componentID int64, to string, by *time.Time, claimID *int64,
	wanted []int64, retired map[int64]bool) (int, error) {

	fold, from, err := s.foldOf(ctx, db, componentID)
	if err != nil {
		return 0, err
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	declared := 0
	// Everything that is no longer wanted goes. Withdrawing a commitment is not
	// a different kind of act from making one, and making it one produces two
	// paths that drift.
	remove := db.NewDelete().Model((*Upgrade)(nil)).
		Where("fold_key = ?", fold).
		Where(`target_id IN (SELECT tg.id FROM "target" AS "tg"
			JOIN "stream" AS "st" ON st.id = tg.stream_id
			WHERE st.product_id = ?)`, productID)
	if len(wanted) > 0 {
		remove = remove.Where("target_id NOT IN (?)", bun.List(wanted))
	}
	if _, err := remove.Exec(ctx); err != nil {
		return 0, fmt.Errorf("withdraw what is no longer committed: %w", err)
	}

	// What is already committed, read inside the transaction. A retry re-runs
	// this closure against a database that has moved, so a set read before it
	// began describes a world that is gone — and reading it here rather than
	// upserting keeps the statement portable: "on conflict do nothing" is two
	// different spellings across the four engines, and neither belongs in the
	// core.
	var already []int64
	if err := db.NewSelect().
		TableExpr(`upgrade AS "ug"`).
		ColumnExpr("ug.target_id").
		Where("ug.fold_key = ?", fold).
		Where(`ug.target_id IN (SELECT tg.id FROM "target" AS "tg"
			JOIN "stream" AS "st" ON st.id = tg.stream_id
			WHERE st.product_id = ?)`, productID).
		Scan(ctx, &already); err != nil {
		return 0, fmt.Errorf("read what is already committed: %w", err)
	}
	have := make(map[int64]bool, len(already))
	for _, id := range already {
		have[id] = true
	}

	for _, id := range wanted {
		if retired[id] {
			// A release past end-of-life will not be fixed, so nothing can be
			// committed for it. Refused rather than accepted and ignored:
			// silently dropping it leaves somebody believing a release is
			// covered.
			return 0, access.Denied(fmt.Sprintf(
				"declare a fix in build %d, which is out of support", id))
		}
		// Committing what is already committed keeps the first commitment.
		// When somebody said they would do this is a fact about a moment, and
		// rewriting the set to add one release would move every date in it to
		// today.
		if have[id] {
			// The version a release is moving to is what somebody agreed
			// to.** Where a claim argued for it, changing it here would leave
			// the agreement standing over a promise nobody read, so it is
			// refused and the claim named — revising that is the act that
			// withdraws the agreement. Where nothing argued for it, the
			// commitment is intent and moving it is editing one row, which is
			// the whole reason it is one row.
			if err := s.movedTo(ctx, db, fold, id, strings.TrimSpace(to), by, claimID); err != nil {
				return 0, err
			}
			continue
		}
		row := &Upgrade{
			TargetID: id, FoldKey: fold,
			FromVersion: from, ToVersion: strings.TrimSpace(to),
			CommittedTo: by, ClaimID: claimID,
			DeclaredBy: subject.ID, DeclaredAt: now,
		}
		if _, err := db.NewInsert().Model(row).Exec(ctx); err != nil {
			return 0, fmt.Errorf("record the commitment: %w", err)
		}
		declared++
	}
	return declared, nil
}

// UpgradeState is where a promised upgrade stands.
//
// Derived on every read rather than stored, for the reason resolution is: the
// scans say what has landed and the calendar says whether the date has passed,
// so a stored state is a third opinion that can be wrong about both.
//
// There is no separate "replanned". Re-promising writes a new date and the
// standing promise is the one read, so a replanned upgrade is a planned one
// with a later date — a state nothing could tell apart from that is a word
// rather than a fact.
type UpgradeState string

const (
	// UpgradePlanned is promised, with work outstanding and the date ahead.
	UpgradePlanned UpgradeState = "planned"
	// UpgradeLanded is every piece of it gone, which the scans say.
	UpgradeLanded UpgradeState = "landed"
	// UpgradeLapsed is the date past with work outstanding.
	//
	// **It returns the upgrade, not its findings.** The findings are still
	// covered — deciding them again one at a time is the thing the promise
	// was made instead of — and what comes back is one item, to whoever holds
	// it. Findings return on their own only when the component moved and they
	// did not close, which needs nothing here: a decision is keyed on the
	// version it was made against, so it stops applying the moment that
	// version changes.
	UpgradeLapsed UpgradeState = "lapsed"
)

// Planned is one bump a build is waiting on, and how far it has landed.
type Planned struct {
	// The commitment's key: the build's fold, exactly as the fix-bundle list
	// gives it, because this is that query read from the other end.
	Fold string
	// Upstream is what to call it — the source package — and From and To the
	// version in hand and the version it moves to, as whoever packages the
	// component wrote them. Never compared, only reported: comparing them
	// needs an ordering per ecosystem this does not have.
	Upstream string
	From     string
	To       string
	// Components are the packages it moves here, which is what makes a row
	// keyed on a fold readable: somebody committing to a curl bump should see
	// which packages move with it.
	Components []string
	// Issues is how many distinct issues are still open at this fold in this
	// build — what the bump would close — and Places how many findings those
	// sit at.
	//
	// Nothing is declared done. A build is clear when it stops holding what
	// the bump answers, which the scans already say, and a chosen build that
	// still holds it after a scan has run is a missed target.
	Issues int
	Places int
	// DeclaredAt is when the commitment was made, which is what "waiting
	// since" means for a bump.
	DeclaredAt time.Time
	// By is the date the promise named, where a judgment promised one. Read
	// from the commitment, which is the record a release plan is kept in.
	By *time.Time
	// HeldBy is the party carrying it, where one party carries all of what is
	// still open under it. A bump split between two people is nobody's, and
	// saying it is somebody's would hand them work that is half theirs.
	HeldBy string
	// State is where this stands, derived from the scans and the date and set
	// by nobody.
	State UpgradeState
	// ClaimID is the claim that argued for it, where one did, so a reader can
	// reach the argument — where the reasoning is, and where the conversation
	// about it happens.
	ClaimID int64
}

// PendingUpgrades is everything committed for one build, by the bump that would
// deliver it, and how much of each is still open.
//
// **The fix-bundle query inverted.** The triager reads a bump and the issues it
// closes; the coordinator reads a build and the bumps it is waiting on. One
// query read from either end, which is why they are one piece rather than two
// reports that will disagree.
//
// A commitment outlives the findings it was made about, which is the whole
// point: what has landed is exactly the part where the findings are closed, and
// a plan that dropped those rows could only ever say what is left.
func (s *Store) PendingUpgrades(ctx context.Context, subject access.Subject,
	targetID int64) ([]Planned, error) {

	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return nil, err
	}
	if !subject.Sees(productID) {
		return nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	visible := access.Visible(subject, productID)
	if len(visible) == 0 {
		return nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}

	var rows []Upgrade
	if err := s.db.NewSelect().Model(&rows).
		Where("target_id = ?", targetID).Order("declared_at ASC", "id ASC").
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what this build is waiting on: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	folds := make([]string, 0, len(rows))
	for _, row := range rows {
		folds = append(folds, row.FoldKey)
	}

	// What is still open under each of them, and which packages those are.
	// Joined from the finding rather than from the commitment, because
	// coverage is a match on the fold rather than a row somebody wrote: a
	// vulnerability published tonight against the same package is covered by
	// this morning's commitment with nobody acting.
	var open []struct {
		Fold   string `bun:"fold"`
		Issues int    `bun:"issues"`
		Places int    `bun:"places"`
	}
	if err := s.db.NewSelect().
		TableExpr(`finding AS "f"`).
		Join(`JOIN component AS "c" ON c.id = f.component_id`).
		ColumnExpr(FoldedOn+` AS "fold"`).
		ColumnExpr(`COUNT(DISTINCT f.vulnerability_id) AS "issues"`).
		ColumnExpr(`COUNT(*) AS "places"`).
		Where("f.target_id = ?", targetID).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		Where(FoldedOn+" IN (?)", bun.List(folds)).
		GroupExpr(FoldedOn).
		Scan(ctx, &open); err != nil {
		return nil, fmt.Errorf("read what those bumps would close: %w", err)
	}
	counts := make(map[string]struct{ Issues, Places int }, len(open))
	for _, row := range open {
		counts[row.Fold] = struct{ Issues, Places int }{row.Issues, row.Places}
	}

	named, err := s.packagesIn(ctx, targetID, visible, folds)
	if err != nil {
		return nil, err
	}
	held, err := s.heldPerFold(ctx, targetID, visible, folds)
	if err != nil {
		return nil, err
	}

	today := s.now().UTC()
	planned := make([]Planned, 0, len(rows))
	for _, row := range rows {
		one := Planned{
			Fold: row.FoldKey, From: row.FromVersion, To: row.ToVersion,
			DeclaredAt: row.DeclaredAt, By: row.CommittedTo,
		}
		if row.ClaimID != nil {
			one.ClaimID = *row.ClaimID
		}
		if what, ok := named[row.FoldKey]; ok {
			one.Upstream, one.Components = what.Upstream, what.Components
		}
		count := counts[row.FoldKey]
		one.Issues, one.Places = count.Issues, count.Places
		one.State = upgradeStanding(one, today)
		planned = append(planned, one)
	}
	if err := s.holders(ctx, planned, held); err != nil {
		return nil, err
	}
	return planned, nil
}

// movedTo changes what a commitment is moving to, or refuses where an
// agreement stands over it.
func (s *Store) movedTo(ctx context.Context, db bun.IDB, fold string, targetID int64,
	to string, by *time.Time, claimID *int64) error {

	var standing Upgrade
	if err := db.NewSelect().Model(&standing).
		Where("fold_key = ?", fold).Where("target_id = ?", targetID).
		Scan(ctx); err != nil {
		return fmt.Errorf("read what is already committed: %w", err)
	}
	if standing.ToVersion == to && sameDate(standing.CommittedTo, by) {
		return nil
	}
	// A commitment made by the same claim is that claim writing its own
	// promise again, which is what revising it does.
	if standing.ClaimID != nil && (claimID == nil || *claimID != *standing.ClaimID) {
		return fmt.Errorf(
			"this release is committed to %s under claim %d: revise that claim rather than "+
				"recording a second promise about the same package",
			standing.ToVersion, *standing.ClaimID)
	}
	if _, err := db.NewUpdate().Model((*Upgrade)(nil)).
		Set("to_version = ?", to).
		Set("committed_to = ?", by).
		Set("claim_id = ?", claimID).
		Where("fold_key = ?", fold).Where("target_id = ?", targetID).Exec(ctx); err != nil {
		return fmt.Errorf("change what this release is moving to: %w", err)
	}
	return nil
}

// packages is what one fold is called and which binaries of it a build ships.
type packages struct {
	Upstream   string
	Components []string
}

// packagesIn names the packages each fold covers in one build.
func (s *Store) packagesIn(ctx context.Context, targetID int64,
	visible []access.Visibility, folds []string) (map[string]packages, error) {

	var rows []struct {
		Fold     string `bun:"fold"`
		Upstream string `bun:"upstream"`
		Name     string `bun:"name"`
	}
	if err := s.db.NewSelect().
		TableExpr(`finding AS "f"`).
		Join(`JOIN component AS "c" ON c.id = f.component_id`).
		ColumnExpr(FoldedOn+` AS "fold"`).
		ColumnExpr(PerFold(SourceName)+` AS "upstream"`).
		ColumnExpr(`c.name AS "name"`).
		Where("f.target_id = ?", targetID).
		Where("f.visibility IN (?)", bun.List(visible)).
		Where(FoldedOn+" IN (?)", bun.List(folds)).
		GroupExpr(FoldedOn+", c.name").
		OrderExpr("c.name").
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read which packages a bump moves: %w", err)
	}
	out := make(map[string]packages, len(folds))
	for _, row := range rows {
		one := out[row.Fold]
		one.Upstream = row.Upstream
		one.Components = append(one.Components, row.Name)
		out[row.Fold] = one
	}
	return out, nil
}

// holder is who carries a fold's work, where one party carries all of it.
type holder struct {
	party  *int64
	places int
	held   int
}

// heldPerFold reads who is carrying what is still open under each fold.
func (s *Store) heldPerFold(ctx context.Context, targetID int64,
	visible []access.Visibility, folds []string) (map[string]holder, error) {

	var rows []struct {
		Fold   string `bun:"fold"`
		Least  *int64 `bun:"least_holder"`
		Most   *int64 `bun:"most_holder"`
		Places int    `bun:"places"`
		Held   int    `bun:"held"`
	}
	if err := s.db.NewSelect().
		TableExpr(`finding AS "f"`).
		Join(`JOIN component AS "c" ON c.id = f.component_id`).
		ColumnExpr(FoldedOn+` AS "fold"`).
		// The party rather than a name: the column holds a party, which may be
		// a person or a team, and the name is looked up once for the few that
		// come back rather than joined per row.
		ColumnExpr(`MIN(f.assigned_to) AS "least_holder"`).
		ColumnExpr(`MAX(f.assigned_to) AS "most_holder"`).
		// Two counts rather than a conditional sum: that sum comes back as a
		// decimal on two of the four engines, and the cast that makes it an
		// integer is spelled per engine. Counted, a group is wholly held when
		// the count of holders is the count of rows.
		ColumnExpr(`COUNT(*) AS "places"`).
		ColumnExpr(`COUNT(f.assigned_to) AS "held"`).
		Where("f.target_id = ?", targetID).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		Where(FoldedOn+" IN (?)", bun.List(folds)).
		GroupExpr(FoldedOn).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read who is carrying these: %w", err)
	}
	out := make(map[string]holder, len(rows))
	for _, row := range rows {
		one := holder{places: row.Places, held: row.Held}
		if row.Held == row.Places && row.Least != nil && row.Most != nil && *row.Least == *row.Most {
			one.party = row.Least
		}
		out[row.Fold] = one
	}
	return out, nil
}

// holders fills in the name of the party carrying each bump, where one is.
func (s *Store) holders(ctx context.Context, planned []Planned, held map[string]holder) error {
	parties := map[int64]bool{}
	for _, one := range planned {
		if who := held[one.Fold].party; who != nil {
			parties[*who] = true
		}
	}
	if len(parties) == 0 {
		return nil
	}
	named, err := s.partiesNamed(ctx, parties)
	if err != nil {
		return err
	}
	for i := range planned {
		if who := held[planned[i].Fold].party; who != nil {
			planned[i].HeldBy = named[*who]
		}
	}
	return nil
}

// upgradeStanding is where a promise stands: landed when the scans say every
// piece of it is gone, lapsed when the date has passed with work outstanding,
// and planned otherwise.
//
// Nobody sets it. The scans say what has landed and the calendar says whether
// the date is past, so a stored state would be a third opinion able to be
// wrong about both.
func upgradeStanding(one Planned, now time.Time) UpgradeState {
	// Nothing left open at this fold in this build, which is what landed
	// means: the scans stopped reporting it. Coverage is a match rather than a
	// stamp, so this answers for an issue published after the commitment was
	// made as readily as for one it was made about.
	if one.Issues == 0 {
		return UpgradeLanded
	}
	if one.By != nil && one.By.Before(now) {
		return UpgradeLapsed
	}
	return UpgradePlanned
}

// partiesNamed is what to call each of these parties: a person by the identity
// they sign in as, a team by its name.
//
// Both, because the column holds a party and a team is a perfectly good holder
// of work — a lookup that knew only people would report a team's upgrade as
// held by nobody, which is the opposite of what it is.
func (s *Store) partiesNamed(ctx context.Context, parties map[int64]bool) (map[int64]string, error) {
	ids := make([]int64, 0, len(parties))
	for id := range parties {
		ids = append(ids, id)
	}
	var rows []struct {
		PartyID int64  `bun:"party_id"`
		Name    string `bun:"name"`
	}
	err := s.db.NewSelect().
		TableExpr(`person AS "p"`).
		ColumnExpr(`p.party_id AS "party_id"`).
		ColumnExpr(`p.identity AS "name"`).
		Where("p.party_id IN (?)", bun.List(ids)).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read who is carrying it: %w", err)
	}
	named := make(map[int64]string, len(ids))
	for _, row := range rows {
		named[row.PartyID] = row.Name
	}
	var teams []struct {
		PartyID int64  `bun:"party_id"`
		Name    string `bun:"name"`
	}
	err = s.db.NewSelect().
		TableExpr(`team AS "t"`).
		ColumnExpr(`t.party_id AS "party_id"`).
		ColumnExpr(`t.name AS "name"`).
		Where("t.party_id IN (?)", bun.List(ids)).
		Scan(ctx, &teams)
	if err != nil {
		return nil, fmt.Errorf("read which team is carrying it: %w", err)
	}
	for _, row := range teams {
		named[row.PartyID] = row.Name
	}
	return named, nil
}

// foldOf reads what a component folds to, and the version it is at.
//
// Both come from the row rather than from the caller: the fold is written as a
// scan is applied and the version it is at is the version that fold names, so
// a caller supplying either would be choosing what a commitment covers.
func (s *Store) foldOf(ctx context.Context, db bun.IDB, componentID int64) (key, from string, err error) {
	var row struct {
		FoldKey string `bun:"fold_key"`
		From    string `bun:"from_version"`
	}
	err = db.NewSelect().
		TableExpr(`"component" AS "c"`).
		ColumnExpr(`c.fold_key AS "fold_key"`).
		ColumnExpr(`COALESCE(NULLIF(c.upstream_version, ''), c.version, '') AS "from_version"`).
		Where("c.id = ?", componentID).Scan(ctx, &row)
	if err != nil {
		return "", "", fmt.Errorf("read what that component folds to: %w", err)
	}
	return row.FoldKey, row.From, nil
}

// BuildsForWithin is the builds a set of identifiers names, within one
// product, and RetiredWithin says which of them are past end-of-life. Both
// take the handle to read through, because the caller that needs them opens
// the transaction itself and a retry re-runs its closure against a database
// that has moved: read outside, "this release is still supported" describes a
// world that may be gone by the time the write lands, and the refusal that
// exists to stop a fix being declared against a retired release is exactly
// what would be skipped.
func (s *Store) BuildsForWithin(ctx context.Context, db bun.IDB, productID int64,
	builds []int64) ([]int64, error) {
	return s.buildsOf(ctx, db, productID, builds)
}

// RetiredWithin says which of these builds are past end-of-life.
func (s *Store) RetiredWithin(ctx context.Context, db bun.IDB,
	builds []int64) (map[int64]bool, error) {
	return s.retired(ctx, db, builds)
}

// buildsOf narrows a list of builds to the ones belonging to this product.
//
// A build of somebody else's product is refused rather than dropped: naming
// one is either a mistake worth reporting or an attempt to write across a
// boundary, and both want the same answer.
func (s *Store) buildsOf(ctx context.Context, db bun.IDB, productID int64,
	builds []int64) ([]int64, error) {
	if len(builds) == 0 {
		return nil, nil
	}
	var here []int64
	err := db.NewSelect().
		TableExpr(`target AS "tg"`).
		Join(`JOIN stream AS "st" ON st.id = tg.stream_id`).
		ColumnExpr("tg.id").
		Where("st.product_id = ?", productID).
		Where("tg.id IN (?)", bun.List(builds)).
		OrderExpr("tg.id").
		Scan(ctx, &here)
	if err != nil {
		return nil, fmt.Errorf("check the builds named are this product's: %w", err)
	}
	if len(here) != len(builds) {
		return nil, access.Denied("declare a fix in a build of another product")
	}
	return here, nil
}

// retired says which of these builds are out of support.
func (s *Store) retired(ctx context.Context, db bun.IDB, ids []int64) (map[int64]bool, error) {
	out := map[int64]bool{}
	if len(ids) == 0 {
		return out, nil
	}
	past, err := catalog.NewStore(db).StreamsPastEndOfLife(ctx, s.now().UTC())
	if err != nil {
		return nil, err
	}
	if len(past) == 0 {
		return out, nil
	}
	var retired []int64
	err = db.NewSelect().
		TableExpr(`target AS "tg"`).
		ColumnExpr("tg.id").
		Where("tg.id IN (?)", bun.List(ids)).
		Where("tg.stream_id IN (?)", bun.List(past)).
		Scan(ctx, &retired)
	if err != nil {
		return nil, fmt.Errorf("read which of these builds are out of support: %w", err)
	}
	for _, id := range retired {
		out[id] = true
	}
	return out, nil
}
