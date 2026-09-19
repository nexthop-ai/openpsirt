package notify

import (
	"context"
	"fmt"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// Two conditions about the deployment rather than about anybody's work: data
// that has stopped moving, and a control that did not hold.
//
// **Both are questions a report already answers, asked as conditions.** A
// report that must come back empty is one nobody opens — checked twice, seen
// to be empty, stopped — so it is read after something has gone wrong rather
// than before. Mailing it on a schedule fails either way round: sent only when
// it has something to say, silence means the control held or the job did not
// run and nothing tells the two apart; sent always, fifty-one messages saying
// nothing teach somebody to filter the fifty-second.
//
// **What goes out is the fact and a link, never the rows.** The same rule an
// outbound notification already holds to, for a stronger reason here: one of
// these is a list of places a security control failed, and a condition that
// carried it would put that list wherever the channel goes.

// dataStale is the condition that the vulnerability data has stopped moving.
//
// **The check is inequality, never ordering.** What a scanner reports as its
// data version is an opaque string — a date for one, a schema revision and a
// build stamp for another — so the only question that can be asked of it is
// whether it is the same string as last time. That is enough: what matters is
// that it moved, not which is newer.
//
// Only a finished run that stated a version counts. A run that failed says
// nothing about the data and one still going has not reported yet, and a
// deployment that has never finished a scan has nothing to be stale — which is
// the quiet-build condition's question rather than this one's.
//
// **Measured from the most recent time any version was seen for the first
// time.** A version that comes back was not a change the second time, so the
// first sighting is when the data moved; taking the latest of those makes the
// answer move forward only when something genuinely new arrives, and never
// backward.
//
// Read as the first sighting of whichever version ran most recently, it did
// both. A data bundle is a build stamp for the scanner this ships with, so
// restoring last quarter's data reproduces a version string exactly, and the
// age was then measured from the first time that string was ever seen — an
// air-gapped deployment re-importing an old bundle was told the data had not
// moved in seven months and sent somebody looking for a fetch that never
// failed. Worse, the chart ships two replicas with a cache each, so two of
// them can hold different versions and both keep scanning: whichever ran last
// decided the answer, the condition held on one sweep and not the next, and a
// condition that clears and re-raises is a fresh unread alert for ever, which
// is what REQ-49 is about.
func (w *Watch) dataStale(ctx context.Context) ([]Holds, error) {
	after, err := setting.NewStore(w.db).Duration(ctx,
		setting.VulnerabilityDataStaleAfter, setting.DefaultVulnerabilityDataStaleAfter)
	if err != nil {
		return nil, fmt.Errorf("read how long counts as stale: %w", err)
	}

	since, err := w.dataLastMoved(ctx)
	if err != nil {
		return nil, err
	}
	if since == nil {
		// Nothing has finished a scan and stated its data version. That is a
		// deployment nobody has pointed at anything yet, which the quiet-build
		// condition is what reports.
		return nil, nil
	}

	// The wall clock, as every other condition here reads it. A sweep is a
	// pass over what is true now rather than a computation a test pins to a
	// moment, and the fixtures below place their rows relative to it.
	stopped := time.Now().UTC().Sub(*since)
	if stopped < after {
		return nil, nil
	}
	version, err := w.dataInForce(ctx)
	if err != nil {
		return nil, err
	}
	days := int(stopped.Hours() / 24)
	return []Holds{{
		// One key however the data moves, because the condition is that it
		// stopped moving and that either holds or does not. Keyed on the
		// version, a deployment that fetched once and stalled again would see
		// this clear and re-open while it had never stopped being true — and
		// the sentence stays right either way, because a standing condition's
		// body is rewritten as what it says changes.
		About: identify("vulnerability-data"),
		Body: fmt.Sprintf("The vulnerability data has not moved in %s. Every scan "+
			"since has answered against %s, so a finding that would have opened on newer "+
			"data has not — and nothing has failed to say so.", plainly(days), version),
		Link: "/system",
	}}, nil
}

// VulnerabilityData is what a deployment's scans are answering against.
//
// Read by the condition that reports it stopped moving and by the screen that
// condition links to, which is the point: the fact was in the database and on
// no screen anywhere, so the notification saying the data had stopped moving
// sent somebody to the job queue.
type VulnerabilityData struct {
	// Version is what the newest finished run stated, in the scanner's own
	// spelling. Empty where nothing has finished a scan and said.
	Version string
	// Since is the most recent time any version was seen for the first time,
	// which is when the data last moved. Nil alongside an empty version.
	Since *time.Time
	// After is how long counts as stopped, so a screen can say how close this
	// is to being reported rather than only whether it has been.
	After time.Duration
}

// DataInForce answers what the scans are running against and when it last
// moved, for the screen the staleness condition links to.
func (w *Watch) DataInForce(ctx context.Context) (VulnerabilityData, error) {
	after, err := setting.NewStore(w.db).Duration(ctx,
		setting.VulnerabilityDataStaleAfter, setting.DefaultVulnerabilityDataStaleAfter)
	if err != nil {
		return VulnerabilityData{}, fmt.Errorf("read how long counts as stale: %w", err)
	}
	since, err := w.dataLastMoved(ctx)
	if err != nil {
		return VulnerabilityData{}, err
	}
	version, err := w.dataInForce(ctx)
	if err != nil {
		return VulnerabilityData{}, err
	}
	return VulnerabilityData{Version: version, Since: since, After: after}, nil
}

// dataLastMoved is the most recent time any data version was seen for the
// first time, or nothing where no run has ever stated one.
//
// A pointer rather than a zero time, because the aggregate over an empty set
// is null rather than no row at all: asked as one statement it answers once,
// with nothing in it, and a zero time there would read as data that stopped
// moving at the beginning of the era.
func (w *Watch) dataLastMoved(ctx context.Context) (*time.Time, error) {
	var since *time.Time
	err := w.db.NewSelect().
		TableExpr(`(?) AS "firsts"`, w.db.NewSelect().
			Model((*finding.Run)(nil)).
			ColumnExpr(`MIN(sr.started_at) AS "first_seen"`).
			Where("sr.finished_at IS NOT NULL").
			Where("sr.failure = ?", "").
			Where("sr.database_version <> ?", "").
			GroupExpr("sr.database_version")).
		ColumnExpr(`MAX(firsts.first_seen) AS "since"`).
		Scan(ctx, &since)
	if err != nil {
		if database.IsNoRows(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read when the vulnerability data last moved: %w", err)
	}
	return since, nil
}

// dataInForce is the version the newest finished run stated.
//
// Read apart from when the data last moved, because they are answers to
// different questions and one statement answering both gets the age wrong:
// what the newest run is carrying says nothing about when that string first
// appeared, and on a deployment running two replicas with a cache each it is
// whichever of them finished last.
func (w *Watch) dataInForce(ctx context.Context) (string, error) {
	var version string
	err := w.db.NewSelect().
		Model((*finding.Run)(nil)).
		ColumnExpr(`sr.database_version`).
		Where("sr.finished_at IS NOT NULL").
		Where("sr.failure = ?", "").
		Where("sr.database_version <> ?", "").
		OrderExpr(`sr.started_at DESC`).
		Limit(1).Scan(ctx, &version)
	if err != nil && !database.IsNoRows(err) {
		return "", fmt.Errorf("read which vulnerability data is in force: %w", err)
	}
	return version, nil
}

// riskUnagreed is the condition that something is hidden with nobody's
// agreement behind it.
//
// **This query returning nothing is what the second-person rule means.** Every
// outcome that hides risk needs a second person, so a row here is not a backlog
// item: it is a control that did not hold, and it is the one thing the record
// cannot discover on its own after the fact.
//
// Asked as the deployment rather than as anybody in it, like the conditions
// about the tool's health beside it: administering grants no reading, so an
// administrator's own subject would answer about the products they happen to
// hold rather than about the deployment. What it produces carries a count and a
// link and none of the rows.
func (w *Watch) riskUnagreed(ctx context.Context) ([]Holds, error) {
	claims, rows, err := triage.NewStore(w.db).HiddenWithNobodyAgreeing(ctx)
	if err != nil {
		return nil, err
	}
	if claims == 0 {
		return nil, nil
	}
	return []Holds{{
		// One condition however many there are, because it is one control and
		// one thing to go and look at. Keyed on neither the count nor the
		// claims, so that it stays the same condition while it holds and is
		// not re-raised each time the number moves.
		About: identify("risk-unagreed"),
		Body: fmt.Sprintf("%s hides risk with nobody's agreement behind it, covering %s. "+
			"Anything that hides something needed a second person, so this is a control "+
			"that did not hold rather than work waiting to be done. Counted across every "+
			"product and the whole record; what the report shows is what you may read.",
			claimsSaid(claims), rowsSaid(rows)),
		// The window the report opens on decides whether it can contain what
		// this counted. It counts the whole record, and the sheet opens on a
		// quarter — so an administrator was told a control had failed and
		// shown a page with nothing on it, which is the alert nobody can clear
		// that REQ-49 is about. The longest window the sheet offers reads as
		// "everything" and is also the bound on what an address may ask for.
		Link: "/reports/rubber-stamp?days=" + everythingBack,
	}}, nil
}

// everythingBack is the longest window a report sheet offers, which reads as
// "everything" on the screen and is the bound the address parser accepts.
//
// Spelled here rather than derived, because the number lives in the interface
// and nothing in either language can see the other. A link that asks for more
// is refused and falls back to the sheet's own default, which is the quarter
// this exists to get past — so the two are pinned together by a test rather
// than by a shared constant that does not exist.
const everythingBack = "3650"

// claimsSaid and rowsSaid put a count into words, because "1 claims" on the one
// case somebody hopes never to see reads as a tool nobody finished.
func claimsSaid(n int) string {
	if n == 1 {
		return "One judgment"
	}
	return fmt.Sprintf("%d judgments", n)
}

// rowsSaid counts decisions rather than findings. The two were conflated here
// and the pair this reports is named the other way where it is produced: how
// many acts, and how many decisions those acts wrote. A kernel flaw at
// forty-five places is forty-five rows and one thing on the findings list, and
// `internal/finding/compliance.go` records the same conflation as a past
// defect.
func rowsSaid(n int) string {
	if n == 1 {
		return "one decision"
	}
	return fmt.Sprintf("%d decisions", n)
}
