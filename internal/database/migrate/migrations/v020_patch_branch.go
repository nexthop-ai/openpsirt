// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// The repositories patch links point into, the commits they name, and the
// branches each commit was found on.
//
// Keyed on the commit rather than on the link. One fix is named by several
// spellings of a link, and by the records of several issues, and the branches
// it is on are a fact about the commit in its repository whichever of them
// asked (REQ-78).
//
// Nothing here records which copy of a repository answered. The copies are
// one replica's disk and these rows are every replica's, so what is kept is
// what the history said rather than where it was read.
func patchBranchStatements(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "patch_repository" (
			"id"           ` + t.id + `,
			-- The address the history is fetched from, as built from a link
			-- rather than as the link spelled it.
			"url"          ` + t.free + ` NOT NULL,
			-- Its digest, because the address is longer than an index key may
			-- be on some engines.
			"url_identity" ` + t.hash + ` NOT NULL,
			-- The host, lowered, so the report of what is fetched from where
			-- can say which an administrator excluded without parsing every
			-- address again.
			"host"         ` + t.name + ` NOT NULL,
			-- When a pass last began a visit, when one last finished, and
			-- what stopped the last one. Two moments for the reason a
			-- supplier has two: a visit that failed still happened, and how
			-- long a repository has been out of reach is the gap between them.
			"fetched_at"   ` + t.timestamp + ` NULL,
			"reached_at"   ` + t.timestamp + ` NULL,
			"failed"       ` + t.free + ` NULL,
			-- How large the copy was when the last visit finished, in bytes.
			-- What an operator sizing the cache reads.
			"held_bytes"   ` + t.refNull + ` NULL,
			"created_at"   ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "patch_repository_url_unique" UNIQUE ("url_identity")
		)` + t.suffix,

		`CREATE TABLE "patch_commit" (
			"id"            ` + t.id + `,
			"repository_id" ` + t.ref + ` NOT NULL,
			-- The commit's name as a link gave it, lowered. Possibly
			-- abbreviated, which the copy resolves.
			"commit_hash"   ` + t.hash + ` NOT NULL,
			-- When the copy was last asked about it. Null is never, which is
			-- what the pass takes first.
			"looked_at"     ` + t.timestamp + ` NULL,
			-- Whether the copy held it when asked. A commit in a pull request
			-- nobody merged, or one a history rewrite dropped, is named by a
			-- link and held by no branch.
			"found"         ` + t.boolean + ` NOT NULL,
			-- How many branches held it, which may be more than are kept
			-- below: a commit early in a long-lived repository is on every
			-- branch cut since.
			"branch_count"  ` + t.ref + ` NOT NULL,
			"created_at"    ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "patch_commit_unique" UNIQUE ("repository_id", "commit_hash"),
			CONSTRAINT "patch_commit_repository_fk" FOREIGN KEY ("repository_id")
				REFERENCES "patch_repository"("id")
		)` + t.suffix,

		// What the pass reads to find a repository's commits due a look.
		`CREATE INDEX "patch_commit_due_idx" ON "patch_commit"
			("repository_id", "looked_at")`,

		`CREATE TABLE "patch_commit_branch" (
			"id"        ` + t.id + `,
			"commit_id" ` + t.ref + ` NOT NULL,
			"branch"    ` + t.name + ` NOT NULL,
			CONSTRAINT "patch_commit_branch_unique" UNIQUE ("commit_id", "branch"),
			CONSTRAINT "patch_commit_branch_commit_fk" FOREIGN KEY ("commit_id")
				REFERENCES "patch_commit"("id")
		)` + t.suffix,
	}
}
