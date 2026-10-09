// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// Work waiting to be done.
//
// The queue lives in the database rather than in a broker because the
// alternatives do not fit: the mature Go queues are tied to one engine or need
// a separate service, and neither is acceptable for something an operator
// installs against whatever database they already run.
func jobBaseline(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "job" (
			"id"           ` + t.id + `,
			"kind"         ` + t.name + ` NOT NULL,
			"reference"    ` + t.name + ` NOT NULL,
			"state"        ` + t.kind + ` NOT NULL,
			"attempts"     INTEGER NOT NULL,
			"max_attempts" INTEGER NOT NULL,
			"run_after"    ` + t.timestamp + ` NOT NULL,
			"claimed_by"   ` + t.name + ` NULL,
			"claimed_at"   ` + t.timestamp + ` NULL,
			"last_error"   ` + t.text + ` NULL,
			"created_at"   ` + t.timestamp + ` NOT NULL,
			"updated_at"   ` + t.timestamp + ` NOT NULL
		)` + t.suffix,

		// Claiming asks for the oldest runnable job of one kind, which is the
		// query on the path of every worker poll. Kind leads, because workers
		// of different sorts share this table and a worker that scanned rows
		// belonging to another would lock and skip them on every poll.
		`CREATE INDEX "job_runnable_idx" ON "job" ("kind", "state", "run_after", "id")`,

		// What an operator opens because the queue has gone wrong. It filters
		// on state and orders by when the row last moved, and the index above
		// leads with the kind, which this query does not name — so without
		// this it scans every job the deployment has ever run, and nothing
		// deletes a finished one.
		`CREATE INDEX "job_set_aside_idx" ON "job" ("state", "updated_at", "id")`,
	}
}

// Which replica is doing a piece of recurring work.
//
// Every replica runs the same binary with no leader and no process-local state
// that decides anything, so work that should happen once happens on all of
// them unless something in the database says otherwise. The job queue answers
// that for discrete work; this answers it for the recurring passes, which have
// no work item to claim.
//
// A row per named piece of work, taken by a conditional update and let go when
// it lapses — the same mechanism the queue claims a job with, and portable for
// the same reason: the statement repeats the conditions that made the lease
// available, so a second replica's update matches nothing.
func leaseBaseline(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "lease" (
			"name"       ` + t.name + ` NOT NULL,
			-- Which replica holds it, and until when. Null once nobody does.
			--
			-- A lease that lapses rather than one that is only ever handed
			-- back: a replica that dies holding one would otherwise stop the
			-- work happening at all, which is the failure the whole
			-- arrangement exists to avoid.
			"held_by"    ` + t.name + ` NULL,
			"held_until" ` + t.timestamp + ` NULL,
			CONSTRAINT "lease_pk" PRIMARY KEY ("name")
		)` + t.suffix,
	}
}

// The commitments a build is waiting on.
//
// Declared intent, not commits. Nothing here watches a repository, so what can
// be recorded is which releases a bump is meant to reach; whether it arrived is
// answered by the next scan of each of them rather than by anybody saying so.
//
// **The row is the commitment and nothing else.** There is no state column, no
// "done", no resolved-at. A build is clear when it stops holding the issues the
// bump answers, which the findings already say — a second record of the same
// fact would be one somebody has to keep true, and the way that fails is the
// tool reporting a fix that shipped in nobody's release.
//
// **Keyed on the build and the fold**, which is the unit the work is actually
// done in: a source package at a version, moving to another version. It was
// keyed per issue *and* per component *and* per target version, so changing
// which version a release is moving to meant rewriting every row of it — and a
// vulnerability that arrived last night against the same package was not
// covered until somebody declared it too.
//
// **Coverage is a join, not a stamp.** A finding is covered when its component
// folds to this key in this build. Nothing is written onto findings, so a bump
// declared today answers a CVE published tomorrow without anybody acting, and
// changing 2.41.6 to 2.41.7 is one row.
//
// **No version comparison is involved.** An upgrade covers everything open on
// the fold rather than only what records this version as its fix, which is the
// rule the fix-bundle work already settled: deciding otherwise needs an
// ordering per ecosystem that nothing here has.
//
// The product is not a column. It is reached through the build, like every
// other query here, and storing it beside a build that already answers it is a
// second copy of one fact.
func upgradeBaseline(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "upgrade" (
			"id"           ` + t.id + `,
			"target_id"    ` + t.ref + ` NOT NULL,
			-- What moves: the source package, at the version it was built at,
			-- in the ecosystem and distribution it came from. See the fold in
			-- DESIGN-data-model.md.
			"fold_key"     ` + t.hash + ` NOT NULL,
			-- The version in hand when the commitment was made, and the version
			-- it moves to. Both stored because neither can be worked out again:
			-- they are read off the open findings, and the moment the bump
			-- lands those close and the answer is gone. A release plan that
			-- stopped naming the versions as the work began landing is a plan
			-- that goes blank exactly when it is working.
			"from_version" ` + t.free + ` NOT NULL,
			"to_version"   ` + t.free + ` NOT NULL,
			-- When the work will have happened, where a judgment promised a
			-- date. Absent where the plan is intent rather than a promise.
			"committed_to" ` + t.date + ` NULL,
			-- The claim that argued for it, where one did. A citation: editing
			-- the commitment is editing what somebody agreed to, so it goes
			-- through the act that withdraws the agreement.
			--
			-- No foreign key on the claim for the same reason the finding's
			-- assignee has none: nothing is ever deleted from that table, and
			-- the constraint would only order the two deletes in a test reset.
			"claim_id"     ` + t.refNull + ` NULL,
			"declared_by"  ` + t.ref + ` NOT NULL,
			"declared_at"  ` + t.timestamp + ` NOT NULL,
			-- Reading a build's plan is how a release answers "what is this
			-- waiting on", and the unique constraint leads with the build, so
			-- it answers that lookup too. A second index on the build alone
			-- would be a prefix of this one.
			CONSTRAINT "upgrade_unique" UNIQUE ("target_id", "fold_key"),
			CONSTRAINT "upgrade_target_id_fk" FOREIGN KEY ("target_id") REFERENCES "target"("id"),
			CONSTRAINT "upgrade_declared_by_fk" FOREIGN KEY ("declared_by") REFERENCES "person"("id")
		)` + t.suffix,
	}
}
