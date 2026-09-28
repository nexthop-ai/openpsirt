// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// outboundV050 is v0.5.0's declaration of where this deployment sends what it
// has to say.
//
// v0.1.0's, with a destination able to be a chat channel as well as a signed
// request, and able to belong to a product or a team rather than to the whole
// deployment.
func outboundV050(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "outbound" (
			"id"         ` + t.id + `,
			-- What it is called, so a screen and a log line can name it.
			"name"       ` + t.name + ` NOT NULL,
			-- Which kinds go here. A name matches one kind; "*" matches every
			-- one. A row per kind rather than a list in a column, because
			-- "which destinations take this kind" is the question the sweep
			-- asks and a list would make it a scan.
			"kind"       ` + t.name + ` NOT NULL,
			-- The address a signed request goes to. Empty for a chat channel,
			-- which is reached through the platform's own interface.
			"url"        ` + t.free + ` NOT NULL,
			-- What the signature is made with. Recoverable by necessity: it
			-- signs our requests rather than authenticating anybody to us.
			-- Empty for a chat channel, whose credential is configuration.
			"secret"     ` + t.free + ` NOT NULL,
			"created_by" ` + t.ref + ` NOT NULL,
			"created_at" ` + t.timestamp + ` NOT NULL,
			-- Retired rather than deleted, like every other configured thing:
			-- what was sent where is a question asked afterwards.
			"retired_at" ` + t.timestamp + ` NULL,
			-- How it is reached: a signed request, or a chat platform this
			-- deployment holds a credential for.
			"platform"   ` + t.kind + ` NOT NULL,
			-- The channel on that platform, and on Zulip the topic within it.
			-- Null for a signed request.
			"channel"    ` + t.name + ` NULL,
			"topic"      ` + t.name + ` NULL,
			-- What it belongs to. Both null is the whole deployment; one set
			-- narrows what it is sent to that product or that team.
			"product_id" ` + t.ref + ` NULL,
			"team_id"    ` + t.ref + ` NULL,
			CONSTRAINT "outbound_named_once" UNIQUE ("name", "kind"),
			CONSTRAINT "outbound_by_fk" FOREIGN KEY ("created_by") REFERENCES "person"("id"),
			CONSTRAINT "outbound_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "outbound_team_fk" FOREIGN KEY ("team_id") REFERENCES "team"("id")
		)` + t.suffix,

		`CREATE INDEX "outbound_kind_idx" ON "outbound" ("kind", "retired_at")`,
	}
}

// chatV050 is v0.5.0's declaration of what a person chose about chat, and of
// what has been carried to them there.
func chatV050(t *columnTypes) []string {
	return []string{
		// A row only for somebody who changed something. No row is the
		// defaults: direct messages on, what a channel carries off.
		`CREATE TABLE "chat_preference" (
			"id"         ` + t.id + `,
			"person_id"  ` + t.ref + ` NOT NULL,
			-- Whether they are sent direct messages at all.
			"direct"     ` + t.boolean + ` NOT NULL,
			-- Whether what a channel carries is sent to them directly as
			-- well, for somebody who does not sit in the channels.
			"shared"     ` + t.boolean + ` NOT NULL,
			"updated_at" ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "chat_preference_once" UNIQUE ("person_id"),
			CONSTRAINT "chat_preference_person_fk" FOREIGN KEY ("person_id")
				REFERENCES "person"("id")
		)` + t.suffix,

		// What has gone to a person directly, per platform. A notification is
		// carried by mail and by each chat platform independently, and one of
		// them failing is not another one's retry.
		`CREATE TABLE "chat_delivery" (
			"id"              ` + t.id + `,
			"notification_id" ` + t.ref + ` NOT NULL,
			"platform"        ` + t.kind + ` NOT NULL,
			"attempts"        ` + t.ref + ` NOT NULL,
			"sent_at"         ` + t.timestamp + ` NULL,
			-- Why the last attempt did not arrive, where it did not: the
			-- platform refused, or nobody there is registered to the address.
			"failed"          ` + t.free + ` NULL,
			"first_seen"      ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "chat_delivery_once" UNIQUE ("notification_id", "platform"),
			CONSTRAINT "chat_delivery_nt" FOREIGN KEY ("notification_id")
				REFERENCES "notification"("id") ON DELETE CASCADE
		)` + t.suffix,
	}
}
