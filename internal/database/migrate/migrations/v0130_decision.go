// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// decisionOccurrenceV0130 is v0.13.0's declaration of the decision occurrence
// table.
//
// v0.11.0's, with who withdrew a row. Any triager on the product may withdraw
// a decision, so its proposer is not who did; a lapse is nobody's act.
func decisionOccurrenceV0130(t *columnTypes) []string {
	statements := declaredV0110(t, "decision_occurrence")
	statements[0] = withColumn(statements[0], `"ended_at"                   `+t.timestamp+` NULL,`,
		`-- Who withdrew this row. Null while it stands, where it lapsed, and
			-- on every row withdrawn before v0.13.0 recorded it.
			"ended_by"                   `+t.refNull+` NULL,`)
	statements[0] = strings.Replace(statements[0],
		`CONSTRAINT "decision_occurrence_proposer_fk" FOREIGN KEY ("proposed_by") REFERENCES "person"("id")`,
		`CONSTRAINT "decision_occurrence_proposer_fk" FOREIGN KEY ("proposed_by") REFERENCES "person"("id"),
			CONSTRAINT "decision_occurrence_ender_fk" FOREIGN KEY ("ended_by") REFERENCES "person"("id")`, 1)
	return statements
}

// decisionEndedByV0130 adds who withdrew a decision occurrence and its key.
// v0.12.0 recorded nobody, so every row starts with none.
//
// The key is asked for whatever the column says: a stopped upgrade on MySQL
// or MariaDB can leave the column added and the key not.
func decisionEndedByV0130(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	present, err := u.hasColumn("decision_occurrence", "ended_by")
	if err != nil {
		return err
	}
	c := change{table: "decision_occurrence"}
	if !present {
		c.add = []added{{column: "ended_by"}}
	}
	if u.engine == database.SQLite {
		if !present {
			c.constraints = []string{"decision_occurrence_ender_fk"}
		}
	} else {
		keyed, err := u.hasForeignKey("decision_occurrence", "decision_occurrence_ender_fk")
		if err != nil {
			return err
		}
		if !keyed {
			c.constraints = []string{"decision_occurrence_ender_fk"}
		}
	}
	if len(c.add) == 0 && len(c.constraints) == 0 {
		return nil
	}
	return u.change(decisionOccurrenceV0130(u.t), c)
}
