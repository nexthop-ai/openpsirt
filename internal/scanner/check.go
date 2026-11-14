// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/issuedate"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// Checking is one check of a replaced inventory and what it recorded.
type Checking struct {
	BuildID, ScanID, RunID int64
	Checked                finding.Checked
}

// untilData is how long a check whose scanner data is dated too early is put
// back for, and untilDated how long one waiting for the date pass is: data is
// rebuilt daily, and the pass asks a new issue within minutes.
const (
	untilData  = 6 * time.Hour
	untilDated = time.Hour
)

// Check claims one replaced inventory and checks it, reporting whether there
// was anything to do.
//
// A scan of what a build holds is claimed first, by Run, so a backlog of
// checks never delays one.
func (r *Runner) Check(ctx context.Context) (*Checking, error) {
	job, err := r.queue.Claim(ctx, r.name, queue.Check)
	if err != nil || job == nil {
		return nil, err
	}
	working, release := r.queue.Holding(ctx, job.ID, r.name, r.logger)
	outcome, wait, err := r.checkOne(working, job.Reference)
	taken := release()
	if err == nil && wait != nil {
		r.logger.Info("a check of a replaced inventory waits", "scan", job.Reference, "reason", wait.why)
		if err := r.queue.Postpone(ctx, job.ID, r.name, wait.after, wait.why); err != nil {
			return nil, fmt.Errorf("hand back a check that has to wait: %w", err)
		}
		return nil, nil
	}
	ending := r.queue.Settle(ctx, job, r.name, "replaced inventory", r.logger, err, taken, nil)
	if ending.HandedOver {
		return nil, nil
	}
	return outcome, ending.Err
}

// waiting is a check handed back untried, and for how long.
type waiting struct {
	after time.Duration
	why   string
}

// checkOne checks one replaced inventory.
//
// The scanner is given both inventories at once, the replaced one and its
// replacement, as the graph's intervals hold them; nothing the build sent is
// read again.
func (r *Runner) checkOne(ctx context.Context, reference string) (*Checking, *waiting, error) {
	scanID, err := strconv.ParseInt(reference, 10, 64)
	if err != nil {
		return nil, nil, fmt.Errorf("job names %q, which is not a scan: %w", reference, err)
	}
	replaced, err := ingest.NewStore(r.db.DB).Replaced(ctx, scanID)
	if err != nil {
		return nil, nil, err
	}
	records, wait := r.narrowedWith(ctx, strconv.FormatInt(replaced.BuildID, 10))
	if wait != nil {
		return nil, &waiting{untilRecords, wait.Error()}, nil
	}
	settle, err := setting.NewStore(r.db.DB).Duration(ctx, setting.CheckSettle, setting.DefaultCheckSettle)
	if err != nil {
		return nil, nil, fmt.Errorf("read how long a replaced inventory waits for its check: %w", err)
	}
	asking, err := issuedate.Enabled(ctx, r.db.DB)
	if err != nil {
		return nil, nil, err
	}

	held := graph.NewStore(r.db.DB)
	before, err := held.ComponentsAt(ctx, replaced.BuildID, graph.AtScan(replaced.ScanID))
	if err != nil {
		return nil, nil, err
	}
	after, err := held.ComponentsAt(ctx, replaced.BuildID, graph.AtScan(replaced.ReplacementID))
	if err != nil {
		return nil, nil, err
	}
	components := both(before, after)

	var result Result
	if len(components) > 0 {
		var inventory bytes.Buffer
		if err := sbom.WriteInventory(&inventory, components); err != nil {
			return nil, nil, err
		}
		if result, err = r.scanner.Scan(ctx, &inventory); err != nil {
			return nil, nil, err
		}
	}
	owed := replaced.ReplacedAt.Add(settle)
	if dated := finding.DataDate(result.DatabaseVersion, time.Now()); dated.Before(owed) {
		return nil, &waiting{untilData, fmt.Sprintf("the scanner's data is dated %s, and the check is owed "+
			"data dated %s or later", dated.Format(time.RFC3339), owed.Format(time.RFC3339))}, nil
	}
	if err := narrow(records, components, result.Reported); err != nil {
		return nil, nil, err
	}
	findings := finding.NewStore(r.db.DB)
	undated, err := findings.Undated(ctx, result.Reported, asking, owed)
	if err != nil {
		return nil, nil, err
	}
	if undated > 0 {
		return nil, &waiting{untilDated, fmt.Sprintf("%d issues wait for OSV to be asked when "+
			"they were published", undated)}, nil
	}

	run, err := findings.Begin(ctx, finding.Run{
		BuildID: replaced.BuildID, Scanner: r.scanner.Name(), RanHere: true,
		RecordsVersion: records.Version(), CheckedScanID: &scanID,
	})
	if err != nil {
		return nil, nil, err
	}
	replaced.Lag = settle
	checked, err := findings.CheckReplaced(ctx, replaced, run.ID, result.Reported)
	r.finish(ctx, findings, run.ID, result, err, "check run")
	if err != nil {
		return nil, nil, err
	}
	return &Checking{BuildID: replaced.BuildID, ScanID: scanID, RunID: run.ID, Checked: checked}, nil, nil
}

// both is two inventories as one, each component once.
func both(one, other []graph.Described) []graph.Described {
	seen := make(map[graph.Described]bool, len(one)+len(other))
	out := make([]graph.Described, 0, len(one)+len(other))
	for _, each := range append(append([]graph.Described{}, one...), other...) {
		if !seen[each] {
			seen[each] = true
			out = append(out, each)
		}
	}
	return out
}
