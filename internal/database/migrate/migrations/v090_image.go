// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// imageVersionV090 is v0.9.0's declaration of the image version table, and its
// index.
//
// A container image is identified by its name, so its node stays open while a
// build rebuilds it. The version each build states for it moves every build,
// and is kept here: one row per version a build stated, open across the scans
// that stated it, the interval a node and an edge carry.
func imageVersionV090(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "image_version" (
			"id"             ` + t.id + `,
			"node_id"        ` + t.ref + ` NOT NULL,
			-- What the build stated, as it stated it: the format's version,
			-- empty where it stated none, and the package identifier whole.
			-- Unbounded, as the component's own are.
			"version"        ` + t.free + ` NOT NULL,
			"purl"           ` + t.text + ` NULL,
			"opened_scan_id" ` + t.ref + ` NOT NULL,
			"closed_scan_id" ` + t.refNull + ` NULL,
			CONSTRAINT "image_version_node_fk" FOREIGN KEY ("node_id") REFERENCES "graph_node"("id"),
			CONSTRAINT "image_version_opened_fk" FOREIGN KEY ("opened_scan_id") REFERENCES "scan"("id"),
			CONSTRAINT "image_version_closed_fk" FOREIGN KEY ("closed_scan_id") REFERENCES "scan"("id")
		)` + t.suffix,

		// The open row of each node, and a node's history in order. Every
		// apply reads the open rows of a build's images, through the node.
		`CREATE INDEX "image_version_node_idx" ON "image_version" ("node_id", "closed_scan_id")`,
	}
}
