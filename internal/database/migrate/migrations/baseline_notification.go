// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// notificationBaseline declares everything somebody is told, with the team a
// notification is about beside the product and the issue it is about.
func notificationBaseline(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "notification" (
			"id"        ` + t.id + `,
			"person_id" ` + t.ref + ` NOT NULL,
			-- What happened, as a word the interface knows how to draw.
			"kind"      ` + t.name + ` NOT NULL,
			-- 'event' or 'condition'. An event is acknowledged; a condition
			-- clears itself when what it is about stops being true.
			"lifetime"  ` + t.kind + ` NOT NULL,
			-- What a condition is about, so the pass that derives them can
			-- tell "still true" from "true again". Empty for an event, which
			-- is about a moment rather than a state.
			"about"     ` + t.name + ` NOT NULL,
			-- The same value while the condition holds, and null once it has
			-- cleared. It exists to carry the uniqueness below: every engine
			-- here treats nulls as distinct in a unique index, so cleared rows
			-- never collide with each other while open ones still do — which
			-- is the invariant, expressed without a partial index that two of
			-- the four engines do not have.
			"about_open" ` + t.name + ` NULL,
			-- What to say, and where it points. The line is stored rather
			-- than derived at read time because it describes a moment: the
			-- finding it names may since have been decided, closed or
			-- reopened, and re-deriving it later would describe the world now
			-- rather than the world somebody was told about.
			"body"      ` + t.text + ` NOT NULL,
			"link"      ` + t.free + ` NOT NULL,
			-- Whether what this is about is a finding nobody has announced.
			--
			-- Recorded here rather than worked out when something is sent,
			-- because the answer belongs to the moment the row was written:
			-- a finding disclosed since would otherwise make an old message
			-- about an embargo readable, and one made private since would
			-- not make an old message about a public issue secret again. The
			-- channel that leaves the building reads this and says nothing
			-- but a link; the area inside it is unaffected, because
			-- reaching that is already the visibility check.
			"private"   ` + t.boolean + ` NOT NULL,
			-- Which product this is about, and which issue, where it is
			-- about either.
			--
			-- Columns rather than something derived from "about" or parsed
			-- back out of "concerns", because what a read narrows by cannot
			-- be a string another pass invented the shape of. Every read of
			-- this table is narrowed by them: what somebody was told about an
			-- undisclosed finding stops being readable when the role that
			-- reached it is withdrawn, and comes back if it is granted again,
			-- because they *were* told and destroying that record is what an
			-- auditor most wants to find (REQ-42 and REQ-43).
			--
			-- Nullable, because plenty is about neither: a mailbox that keeps
			-- refusing, an account somebody created, a build that stopped
			-- being scanned. A row marked private is refused without a
			-- product, so the narrowing has no hole to fall through.
			"product_id" ` + t.ref + ` NULL,
			"vulnerability_id" ` + t.ref + ` NULL,
			-- What an event was about, where it was about a finding.
			--
			-- Not "about" above, which carries a condition's identity and its
			-- uniqueness: an event that named one would be deduplicated
			-- against an unrelated row, which is why that column refuses one.
			-- This one is never matched on for uniqueness. It exists so the
			-- digest can answer "was this person already told about this",
			-- which is the whole of what a digest carries.
			"concerns"  ` + t.name + ` NULL,
			-- What makes one thing said to many people one thing to carry
			-- outside this deployment. Empty for everything personal.
			--
			-- A message about somebody's own work names them and is theirs;
			-- one saying a build's contents changed sharply is the same
			-- sentence for every reader of that product, and a channel wants
			-- it once however many people hold the product. The area inside
			-- the application is per person either way — this decides what a
			-- delivery is keyed on, which is the same question a condition's
			-- "about" answers for the rows a sweep opens.
			"together"  ` + t.name + ` NOT NULL,
			-- When this was carried outside the application, and how many
			-- times that has been tried.
			--
			-- A row nobody has sent is one to send, which makes retrying the
			-- ordinary path rather than a mechanism of its own: a message
			-- that failed is simply still unsent. The count is what stops
			-- that being forever — an address that refuses every time is a
			-- mailbox that has gone, and a sweep that keeps trying it is one
			-- that eventually does nothing else.
			"sent_at"   ` + t.timestamp + ` NULL,
			"attempts"  ` + t.ref + ` NOT NULL,
			"created_at" ` + t.timestamp + ` NOT NULL,
			-- When they acknowledged it. Unread is the ordinary state, so it
			-- is the null one.
			"read_at"   ` + t.timestamp + ` NULL,
			-- When the condition stopped being true. Kept rather than deleted
			-- so that "this cleared" is answerable, and so a condition that
			-- comes back is a new row rather than an edit of an old one.
			"cleared_at" ` + t.timestamp + ` NULL,
			-- Which team's queue this is about, where it is about one. A chat
			-- channel belonging to a team is sent what names its team, so the
			-- read that routes to it narrows by a column rather than by a key
			-- another pass hashed.
			"team_id"   ` + t.ref + ` NULL,
			CONSTRAINT "notification_person_fk" FOREIGN KEY ("person_id")
				REFERENCES "person"("id"),
			CONSTRAINT "notification_product_fk" FOREIGN KEY ("product_id")
				REFERENCES "product"("id"),
			CONSTRAINT "notification_vulnerability_fk" FOREIGN KEY ("vulnerability_id")
				REFERENCES "vulnerability"("id"),
			CONSTRAINT "notification_team_fk" FOREIGN KEY ("team_id")
				REFERENCES "team"("id")
		)` + t.suffix,

		// The area's own read: one person's unread, newest first. The
		// visibility narrowing that follows it is over one person's unread
		// rows, which is the small set this index already produces.
		`CREATE INDEX "notification_unread_idx"
			ON "notification" ("person_id", "read_at", "cleared_at")`,

		// One *open* row per condition per person. A build that has been quiet
		// for a week is one thing to be told, however many times the pass
		// runs, and a condition that comes back after clearing is a new row
		// rather than an edit of an old one.
		//
		// Keyed on about_open rather than on about and cleared_at: a unique
		// index over a nullable cleared_at would let two open rows through,
		// because null is distinct from null on all four engines — which is
		// the same property this relies on to let cleared rows accumulate.
		`CREATE UNIQUE INDEX "notification_condition_idx"
			ON "notification" ("person_id", "kind", "about_open")`,
	}
}

// outboundBaseline declares where this deployment sends what it has to say. A
// destination is a chat channel or a signed request, and belongs to a product, a
// team or the whole deployment.
func outboundBaseline(t *columnTypes) []string {
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

// Where this deployment sends what it has to say.
//
// **One signed request, not an adapter each.** Nothing leaves this deployment
// but mail, and every comparable tool reaches a chat channel and a tracker;
// without one, a fix target is a wish and an approver discovers a claim by
// opening the queue. One signed HTTP request gives Slack, Teams, a tracker
// driven by automation and paging without writing an adapter for any of them —
// which is what the channel interface was for, reached more cheaply than by
// writing two of them.
//
// **Per kind**, so a deployment can send what is worth interrupting somebody
// for to a paging endpoint and leave the rest in the notification area.
//
// **The secret is stored as it is, and that is deliberate.** Every other
// credential here is hashed because it authenticates somebody to us;
// this one authenticates *us* to somebody else, so it has to be recoverable to
// sign with — the same reason a mail password is. It is never returned by any
// endpoint.
func outboundDeliveryBaseline(t *columnTypes) []string {
	return []string{

		// What has already gone where.
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
}

// chatBaseline declares what a person chose about chat, and what has been
// carried to them there.
func chatBaseline(t *columnTypes) []string {
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

// A standing rule that hands work nobody holds to a team.
//
// **It matches on component identity as well as on a place in the tree.** The
// upstream name is the key that matters: one rule naming a source package
// catches every binary package built from it, wherever they sit. The earlier
// framing had this as a subtree rule, and the case that motivates it is not a
// subtree at all — a kernel is one source package appearing at many places
// under many consumers, so a subtree rule would need a line per place and would
// still miss tomorrow's.
//
// **Ordered, and the first match wins**. An unwritten precedence rule
// is forgettable, and the question it answers — where did this come from — is
// asked months later by somebody who was not there. Which rule placed a finding
// is written on the finding, the same choice already made for how a match was
// made: a placement nobody can explain is one nobody can correct, and at this
// fan-out there will be thousands of them.
func routingBaseline(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "routing_rule" (
			"id"         ` + t.id + `,
			"product_id" ` + t.ref + ` NOT NULL,
			-- Where work lands. A team rather than a person, because what a
			-- rule makes is a queue somebody picks out of.
			"team_id"    ` + t.ref + ` NOT NULL,
			-- What to call it, so a placement can be explained in words rather
			-- than by an identifier.
			"name"       ` + t.free + ` NOT NULL,
			-- Where it sits among the others. First match wins, so this is the
			-- whole of the precedence and it is written down rather than
			-- implied by insertion order.
			"ordinal"    ` + t.ref + ` NOT NULL,
			-- The two ways a rule matches, and at least one is required. The
			-- upstream name is the one that matters: it catches every binary
			-- package of a source package at once. The subtree is the other
			-- kind, kept because a rule about a part of the product is a real
			-- thing people want.
			"upstream"   ` + t.name + ` NULL,
			"beneath"    ` + t.name + ` NULL,
			"created_by" ` + t.ref + ` NOT NULL,
			"created_at" ` + t.timestamp + ` NOT NULL,
			-- Retired rather than deleted, for the reason a team is: a finding
			-- says which rule placed it, and that has to keep resolving to
			-- something a screen can name.
			"retired_at" ` + t.timestamp + ` NULL,
			CONSTRAINT "routing_rule_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "routing_rule_team_fk" FOREIGN KEY ("team_id") REFERENCES "team"("id"),
			CONSTRAINT "routing_rule_by_fk" FOREIGN KEY ("created_by") REFERENCES "person"("id")
		)` + t.suffix,

		// The rules of one product, in the order they are tried.
		`CREATE INDEX "routing_rule_order_idx"
			ON "routing_rule" ("product_id", "retired_at", "ordinal")`,
	}
}

// savedFilterBaseline declares a kept narrowing of the findings list. It names
// no product.
func savedFilterBaseline(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "saved_filter" (
			"id"         ` + t.id + `,
			"person_id"  ` + t.ref + ` NOT NULL,
			-- What they called it, matched without regard to capitals and
			-- stored normalized like every other name people type,
			-- with the spelling they used kept beside it.
			"name"         ` + t.name + ` NOT NULL,
			"display_name" ` + t.free + ` NULL,
			-- The query string of the list it opens, without a leading "?".
			-- It names what the list is narrowed by and never where: the
			-- branch, the variant and anything naming one build or one run
			-- are the scope on screen, which a filter is applied within.
			"query"      ` + t.text + ` NOT NULL,
			-- What a saved filter proposes about what it catches, where
			-- somebody made it a prepared claim. All four absent is an
			-- ordinary saved filter.
			"outcome"       ` + t.kind + ` NULL,
			"justification" ` + t.free + ` NULL,
			"reasoning"     ` + t.text + ` NULL,
			"defer_days"    INTEGER NULL,
			"created_at" ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "saved_filter_person_fk" FOREIGN KEY ("person_id") REFERENCES "person"("id"),
			-- One name per person, so saving over one replaces it rather than
			-- leaving two that differ in a way nothing shows.
			CONSTRAINT "saved_filter_name_unique" UNIQUE ("person_id", "name")
		)` + t.suffix,
	}
}
