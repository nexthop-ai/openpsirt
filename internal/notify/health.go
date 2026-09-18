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
// Measured from the newest finished run that stated one, because a run that
// failed says nothing about the data and a run still going has not reported
// yet. A deployment that has never finished a scan has nothing to be stale.
func (w *Watch) dataStale(ctx context.Context) ([]Holds, error) {
	after, err := setting.NewStore(w.db).Duration(ctx,
		setting.VulnerabilityDataStaleAfter, setting.DefaultVulnerabilityDataStaleAfter)
	if err != nil {
		return nil, fmt.Errorf("read how long counts as stale: %w", err)
	}

	var row struct {
		Version string    `bun:"database_version"`
		Since   time.Time `bun:"since"`
	}
	// The newest run carrying each version, then the newest version by when it
	// first arrived: what is wanted is when the data last changed, which is
	// the first run that reported the version in force rather than the last.
	err = w.db.NewSelect().
		Model((*finding.Run)(nil)).
		ColumnExpr(`sr.database_version AS "database_version"`).
		ColumnExpr(`MIN(sr.started_at) AS "since"`).
		Where("sr.finished_at IS NOT NULL").
		Where("sr.failure = ?", "").
		Where("sr.database_version <> ?", "").
		GroupExpr("sr.database_version").
		OrderExpr(`MAX(sr.started_at) DESC`).
		Limit(1).Scan(ctx, &row)
	if err != nil {
		if database.IsNoRows(err) {
			// Nothing has finished a scan and stated its data version. That is
			// a deployment nobody has pointed at anything yet, which the
			// quiet-build condition is what reports.
			return nil, nil
		}
		return nil, fmt.Errorf("read when the vulnerability data last moved: %w", err)
	}

	// The wall clock, as every other condition here reads it. A sweep is a
	// pass over what is true now rather than a computation a test pins to a
	// moment, and the fixtures below place their rows relative to it.
	stopped := time.Now().UTC().Sub(row.Since)
	if stopped < after {
		return nil, nil
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
		Body: fmt.Sprintf("The vulnerability data has not moved in %d days. Every scan "+
			"since has answered against %s, so a finding that would have opened on newer "+
			"data has not — and nothing has failed to say so.", days, row.Version),
		Link: "/system",
	}}, nil
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
			"Every outcome that hides something needs a second person, so this is a "+
			"control that did not hold rather than work waiting to be done.",
			claimsSaid(claims), rowsSaid(rows)),
		Link: "/reports/rubber-stamp",
	}}, nil
}

// claimsSaid and rowsSaid put a count into words, because "1 claims" on the one
// case somebody hopes never to see reads as a tool nobody finished.
func claimsSaid(n int) string {
	if n == 1 {
		return "One judgment"
	}
	return fmt.Sprintf("%d judgments", n)
}

func rowsSaid(n int) string {
	if n == 1 {
		return "one finding"
	}
	return fmt.Sprintf("%d findings", n)
}
