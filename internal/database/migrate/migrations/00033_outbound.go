package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upOutbound, downOutbound)
}

// The destinations this deployment posts to.
//
// One signed request, not an adapter each. Nothing leaves this deployment
// but mail, and every comparable tool reaches a chat channel and a tracker;
// without one, a fix target is a wish and an approver discovers a claim by
// opening the queue. One signed HTTP request gives Slack, Teams, a tracker
// driven by automation and paging without writing an adapter for any of them —
// which is what the channel interface was for, reached more cheaply than by
// writing two of them.
//
// Per kind, so a deployment can send what is worth interrupting somebody
// for to a paging endpoint and leave the rest in the notification area.
//
// The secret is stored as it is, and that is deliberate. Every other
// credential here is hashed because it authenticates somebody to us;
// this one authenticates *us* to somebody else, so it has to be recoverable to
// sign with — the same reason a mail password is. It is never returned by any
// endpoint.
func upOutbound(ctx context.Context, tx *sql.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}

	statements := []string{
		`CREATE TABLE "outbound" (
			"id"         ` + t.id + `,
			-- What it is called, so a screen and a log line can name it.
			"name"       ` + t.name + ` NOT NULL,
			-- Which kinds go here. A name matches one kind; "*" matches every
			-- one. A row per kind rather than a list in a column, because
			-- "which destinations take this kind" is the question the sweep
			-- asks and a list would make it a scan.
			"kind"       ` + t.name + ` NOT NULL,
			"url"        ` + t.free + ` NOT NULL,
			-- What the signature is made with. Recoverable by necessity: it
			-- signs our requests rather than authenticating anybody to us.
			"secret"     ` + t.free + ` NOT NULL,
			"created_by" ` + t.ref + ` NOT NULL,
			"created_at" ` + t.timestamp + ` NOT NULL,
			-- Retired rather than deleted, like every other configured thing:
			-- what was sent where is a question asked afterwards.
			"retired_at" ` + t.timestamp + ` NULL,
			CONSTRAINT "outbound_named_once" UNIQUE ("name", "kind"),
			CONSTRAINT "outbound_by_fk" FOREIGN KEY ("created_by") REFERENCES "person"("id")
		)` + t.suffix,

		`CREATE INDEX "outbound_kind_idx" ON "outbound" ("kind", "retired_at")`,

		// Everything already delivered, and where it went.
		//
		// Keyed on the thing rather than on the notification, because a
		// condition is opened once per person who should hear it and a channel
		// wants it once: "the kernel team's queue has fourteen pieces of work
		// sitting in it" is one thing to say, however many people are told.
		`CREATE TABLE "outbound_delivery" (
			"id"          ` + t.id + `,
			"outbound_id" ` + t.ref + ` NOT NULL,
			-- What was said, as a key: the condition's identity where it has
			-- one, and the notification's own identifier otherwise.
			"about"       ` + t.hash + ` NOT NULL,
			-- Which notification produced the claim. Not part of the key,
			-- because a condition opened for six people is six rows and one
			-- delivery — it is what lets the sweep ask "has this row been
			-- settled here" without rebuilding the key in SQL, which needs a
			-- string concatenation the four engines spell differently.
			"notification_id" ` + t.ref + ` NOT NULL,
			"attempts"    ` + t.ref + ` NOT NULL,
			"sent_at"     ` + t.timestamp + ` NULL,
			"failed"      ` + t.free + ` NULL,
			"first_seen"  ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "outbound_delivery_once" UNIQUE ("outbound_id", "about"),
			-- What the sweep reads: the rows this destination has settled,
			-- so it can select the oldest that is not among them rather than
			-- re-reading the same oldest two hundred for ever.
			CONSTRAINT "outbound_delivery_nt" FOREIGN KEY ("notification_id")
				REFERENCES "notification"("id") ON DELETE CASCADE,
			CONSTRAINT "outbound_delivery_fk" FOREIGN KEY ("outbound_id") REFERENCES "outbound"("id")
		)` + t.suffix,
		// The sweep asks, per destination, which of the oldest uncleared
		// notifications it has already settled. Without this that is a scan
		// of every delivery ever made, on every cycle.
		`CREATE INDEX "outbound_delivery_settled_idx" ON "outbound_delivery"
			("outbound_id", "notification_id")`,
	}

	return apply(ctx, tx, statements)
}

func downOutbound(ctx context.Context, tx *sql.Tx) error {
	return dropTables(ctx, tx, "outbound_delivery", "outbound")
}
