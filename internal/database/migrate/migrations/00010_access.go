package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationContext(upAccess, downAccess)
}

// Who may do what.
//
// A person exists because somebody granted them access, never because they
// managed to authenticate. Authenticating proves who someone is and says
// nothing about whether they should be here, so no sign-in path creates an
// account and the first person to arrive gains nothing by being first .
//
// Admin is a property of the person rather than a grant against a product,
// because it is the one role that is global. Modeling it as a grant would mean
// a row whose product is absent, and a uniqueness rule over a column that may
// be absent behaves differently on each of the four engines.
func upAccess(ctx context.Context, tx *sql.Tx) error {
	e := migrate.EngineFrom(ctx)
	t := typesFor(e)
	if t == nil {
		return fmt.Errorf("no schema for %s", e)
	}

	statements := []string{
		// The one name space a person and a team share, so that work
		// can be assigned to either through the column it already has.
		//
		// "Who holds this" has to stay one question. Two columns are
		// right in nine places and forgotten in the tenth, and the
		// tenth is a list that quietly omits work; a discriminator
		// beside the identifier is the same defect wearing a subtler
		// shape, because person 4 and team 4 would then match the same
		// condition. One table, so a foreign key can point at it and a
		// join resolves it once.
		//
		// The kind is here so a row reached through this table can be
		// resolved without asking both tables which of them has it.
		// Nothing else is: what a party *is* lives in person or team.
		`CREATE TABLE "party" (
			"id"   ` + t.id + `,
			"kind" ` + t.kind + ` NOT NULL
		)` + t.suffix,

		// identity is what the sign-in path says the person is — a username
		// from a trusted header, or a subject from a provider. It is compared
		// exactly, which is why the collation is pinned.
		`CREATE TABLE "person" (
			"id"           ` + t.id + `,
			-- The party this person is assignable as. Made with the person and
			-- living as long as they do: nobody is ever deleted here, so an
			-- assignment never points at a row that has gone.
			"party_id"     ` + t.ref + ` NOT NULL,
			"identity"     ` + t.name + ` NOT NULL,
			"display_name" ` + t.free + ` NULL,
			"is_admin"     ` + t.boolean + ` NOT NULL,
			-- is_bootstrap is set from configuration at every startup and is
			-- kept apart from is_admin so the two cannot overwrite each other.
			-- In group-bound mode admin is re-derived from group membership at
			-- every sign-in, and without this that derivation would strip the
			-- administrator named in configuration — who is the documented way
			-- back in when the group mapping is wrong.
			"is_bootstrap" ` + t.boolean + ` NOT NULL,
			-- admin_derived says a group granted administration rather than a
			-- person. Only what a group gave is taken back when groups stop
			-- deciding, so somebody promoted inside the application survives a
			-- change of mode rather than losing access nothing can restore.
			"admin_derived" ` + t.boolean + ` NOT NULL,
			-- Where to reach this person outside the application, and which
			-- of the two sources it came from. Null is the ordinary state:
			-- an address is optional, and somebody without one is told
			-- nothing outside the application and keeps the area inside it.
			--
			-- The flag is the same shape as admin_derived above and for the
			-- same reason: a provider may refresh what a provider gave and
			-- may never overwrite what somebody here decided.
			"email"        ` + t.free + ` NULL,
			-- Who last decided the address: nobody, a sign-in provider, or
			-- somebody here. Three states rather than a flag, because two
			-- cannot tell "nobody has said" from "somebody said none" — and
			-- reading the second as the first is how a sign-in puts back an
			-- address an administrator had just removed.
			"email_source" ` + t.kind + ` NOT NULL,
			-- Whether they get a digest, and whether it lists what nobody
			-- owns. Two switches rather than one because they answer
			-- different questions — "remind me what is mine" and "tell me
			-- what arrived" — and both are off by default: a digest nobody
			-- asked for is mail somebody filters, and a filtered channel is
			-- worse than none because it looks like it is working.
			"digest"           ` + t.boolean + ` NOT NULL,
			"digest_unassigned" ` + t.boolean + ` NOT NULL,
			-- When the last one went, which is what "since the last digest"
			-- means. Null until the first, and a first digest reports what is
			-- outstanding rather than everything that ever arrived.
			"digest_sent_at"   ` + t.timestamp + ` NULL,
			"created_at"   ` + t.timestamp + ` NOT NULL,
			"last_seen_at" ` + t.timestamp + ` NULL,
			-- When somebody stopped being somebody who may sign in.
			--
			-- A timestamp rather than a flag, because "when" is the whole of
			-- what an audit asks after a departure and a boolean cannot
			-- answer it. Null is the ordinary state.
			--
			-- Nobody is ever deleted here: the record names them as the
			-- proposer of judgments, the approver of others, and the person
			-- an assignment used to point at, and deleting the row would
			-- either break those or rewrite what happened. So leaving is a
			-- date on the row, and every path in reads it (REQ-45).
			"deactivated_at" ` + t.timestamp + ` NULL,
			CONSTRAINT "person_identity_unique" UNIQUE ("identity"),
			CONSTRAINT "person_party_unique" UNIQUE ("party_id"),
			CONSTRAINT "person_party_fk" FOREIGN KEY ("party_id") REFERENCES "party"("id")
		)` + t.suffix,

		// A role is held against one product. What somebody may reach
		// is the union of their grants, and a product they hold no
		// grant on is not merely unreadable but invisible.
		`CREATE TABLE "role_grant" (
			"id"         ` + t.id + `,
			"person_id"  ` + t.ref + ` NOT NULL,
			"product_id" ` + t.ref + ` NOT NULL,
			"role"       ` + t.kind + ` NOT NULL,
			-- source says where a grant came from. A grant derived from group
			-- membership is replaced wholesale at each sign-in, so losing the
			-- group loses the role; one assigned by an administrator
			-- is not touched by a sign-in at all.
			"source"     ` + t.kind + ` NOT NULL,
			-- active is what makes switching role-assignment modes reversible.
			-- Turning on group-bound mode marks the assignments an
			-- administrator made inactive rather than deleting them, so
			-- switching back restores them instead of asking somebody to
			-- reconstruct them from memory. An inactive row grants
			-- nothing and is never counted as access.
			"active"     ` + t.boolean + ` NOT NULL,
			"created_at" ` + t.timestamp + ` NOT NULL,
			-- The source is part of what makes a grant one grant. Somebody can
			-- hold the same role on the same product from both sides at once:
			-- an assignment set aside when group-bound mode was turned on, and
			-- a live one derived from a group that happens to grant the same
			-- thing. Keying without the source forbids that pair, which is the
			-- pair inactive assignments exists to keep.
			CONSTRAINT "role_grant_person_fk" FOREIGN KEY ("person_id") REFERENCES "person"("id"),
			CONSTRAINT "role_grant_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "role_grant_unique" UNIQUE ("person_id", "product_id", "role", "source")
		)` + t.suffix,

		// A role held across every product, including products declared
		// afterwards (REQ-42). A security team holds the same role over the
		// estate, and issuing that one product at a time leaves every new
		// product a permissions sweep across everybody.
		//
		// Its own table rather than a nullable product on the one above. All
		// four engines treat NULLs in a unique key as distinct from each
		// other, so a nullable product would let duplicate estate rows
		// accumulate with the database enforcing nothing, and the partial
		// index that would fix it is engine-specific.
		//
		// source and active mean what they mean above, so setting assignments
		// aside and restoring them covers these rows by the same act. Nothing
		// derives one today: a group binding names a product, so a derived row
		// here has no way to be written.
		`CREATE TABLE "role_grant_all" (
			"id"         ` + t.id + `,
			"person_id"  ` + t.ref + ` NOT NULL,
			"role"       ` + t.kind + ` NOT NULL,
			"source"     ` + t.kind + ` NOT NULL,
			"active"     ` + t.boolean + ` NOT NULL,
			"created_at" ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "role_grant_all_person_fk" FOREIGN KEY ("person_id") REFERENCES "person"("id"),
			CONSTRAINT "role_grant_all_unique" UNIQUE ("person_id", "role", "source")
		)` + t.suffix,

		// How one person signs in.
		//
		// A username moves — people change their name at work, and a forge
		// login can be renamed and the old one then claimed by somebody
		// else — so matching on it alone eventually hands one person's access
		// to another. A sign-in through the provider is therefore matched on
		// the provider's own stable identifier, and the username is what an
		// administrator types to authorize somebody before that identifier is
		// knowable.
		//
		// Neither the identifier nor the username is qualified by where it
		// came from. One provider is configured at a time, and a username a
		// trusted proxy asserts is the same identity as that username at the
		// provider (REQ-41). Qualifying them made one human two accounts —
		// administration granted to one while the other was the one being
		// signed in as.
		//
		// A proxy binds nothing, so an identity reached only that way is still
		// waiting to be bound and the provider binds it at a later sign-in.
		//
		// subject is absent until that happens. All four engines treat NULLs
		// in a unique key as distinct from each other, so many rows may await
		// binding while no two bound rows share a subject — checked on each
		// engine rather than assumed, because the opposite behavior is a
		// configurable option on one of them.
		`CREATE TABLE "person_identity" (
			"id"         ` + t.id + `,
			"person_id"  ` + t.ref + ` NOT NULL,
			"subject"    ` + t.name + ` NULL,
			-- Which provider issued the subject beside it, written when the
			-- binding is made and null until then.
			--
			-- One provider is configured at a time (REQ-41), and this is what
			-- makes that true across time rather than only at one instant: a
			-- deployment pointed at a second provider would otherwise read
			-- identifiers issued by the first as though the new one had issued
			-- them, and two providers do not agree on what any given subject
			-- names. Recorded so the process can refuse to start instead.
			"provider"   ` + t.name + ` NULL,
			"username"   ` + t.name + ` NOT NULL,
			"created_at" ` + t.timestamp + ` NOT NULL,
			-- When an authorization nobody has redeemed stops being
			-- redeemable.
			--
			-- The name is the only thing matching an unredeemed row, because
			-- the identifier it will be pinned to is not knowable until
			-- somebody arrives holding it. That window is the one place where
			-- a name rather than an identifier decides who gets a set of
			-- roles, so it ends: a grant written for somebody who never came
			-- is withdrawn rather than left standing.
			"claimable_until" ` + t.timestamp + ` NULL,
			"bound_at"   ` + t.timestamp + ` NULL,
			CONSTRAINT "person_identity_person_fk" FOREIGN KEY ("person_id") REFERENCES "person"("id"),
			CONSTRAINT "person_identity_username_unique" UNIQUE ("username"),
			CONSTRAINT "person_identity_subject_unique" UNIQUE ("subject")
		)` + t.suffix,

		`CREATE INDEX "person_identity_person_idx" ON "person_identity" ("person_id")`,

		// A pipeline's credential. Ingest and nothing else: a build
		// server has no business holding a person's permissions, which
		// is also what keeps the visibility rules out of its reach
		// entirely.
		//
		// The secret is stored hashed and shown once. A store readable
		// by whoever reads the database is a store that hands over
		// every pipeline's credential with it.
		//
		// The scope is a set of constraints rather than a path: the
		// product is always required, and the release and the variant
		// are independent and either, both or neither may be pinned.
		// An upload always states its full target; the key only
		// authorizes it.
		`CREATE TABLE "api_key" (
			"id"           ` + t.id + `,
			"name"         ` + t.name + ` NOT NULL,
			"secret_hash"  ` + t.hash + ` NOT NULL,
			"product_id"   ` + t.ref + ` NOT NULL,
			"stream_id"    ` + t.refNull + ` NULL,
			"variant_id"   ` + t.refNull + ` NULL,
			"created_at"   ` + t.timestamp + ` NOT NULL,
			"last_used_at" ` + t.timestamp + ` NULL,
			"revoked_at"   ` + t.timestamp + ` NULL,
			CONSTRAINT "api_key_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "api_key_stream_fk" FOREIGN KEY ("stream_id") REFERENCES "stream"("id"),
			CONSTRAINT "api_key_variant_fk" FOREIGN KEY ("variant_id") REFERENCES "variant"("id"),
			CONSTRAINT "api_key_secret_unique" UNIQUE ("secret_hash"),
			-- The name is what an ingest records as having sent a scan, and
			-- what an administrator revokes by. Two keys sharing one would
			-- make each able to read the other's receipts, and would make a
			-- revocation report success having withdrawn whichever row came
			-- back first.
			CONSTRAINT "api_key_name_unique" UNIQUE ("name")
		)` + t.suffix,

		`CREATE INDEX "api_key_product_idx" ON "api_key" ("product_id")`,

		// A person's session, held here rather than in a process's
		// memory: several copies of the application may answer, and a
		// session has to work whichever one does. Storing it also
		// makes revocation immediate — deleting the row cuts access
		// off at once, which is the mechanism relied on when somebody
		// leaves, because group membership is only ever re-read at the
		// next sign-in.
		//
		// The token is stored hashed for the same reason a key is: a
		// store that can hand back what it holds hands over every live
		// session along with a copy of the database. It is not derived
		// from anything about the person, so there is nothing to guess
		// at.
		//
		// csrf_token is a second value bound to the same session. The
		// session cookie is sent by the browser automatically, which
		// is what makes a hostile page able to act as the signed-in
		// user; this one has to be read and echoed by script that the
		// same-origin policy allows only our own pages to run.
		`CREATE TABLE "session" (
			"id"           ` + t.id + `,
			"token_hash"   ` + t.hash + ` NOT NULL,
			"csrf_token"   ` + t.hash + ` NOT NULL,
			"person_id"    ` + t.ref + ` NOT NULL,
			"created_at"   ` + t.timestamp + ` NOT NULL,
			"expires_at"   ` + t.timestamp + ` NOT NULL,
			"last_used_at" ` + t.timestamp + ` NULL,
			CONSTRAINT "session_person_fk" FOREIGN KEY ("person_id") REFERENCES "person"("id"),
			CONSTRAINT "session_token_unique" UNIQUE ("token_hash")
		)` + t.suffix,

		`CREATE INDEX "session_person_idx" ON "session" ("person_id")`,
		// Expired rows are cleared in bulk rather than one at a time.
		`CREATE INDEX "session_expires_idx" ON "session" ("expires_at")`,

		// A provider group bound to a role on a product. In
		// group-bound mode this table *is* the pre-authorization:
		// somebody arriving for the first time in a mapped group is
		// admitted and recorded then, which is what reconciles
		// admitting them with never creating an account for somebody
		// nobody authorized.
		//
		// The group is matched by the name the provider reports — a
		// team slug from GitHub, a claim value from an identity
		// provider — so it is stored as given rather than resolved to
		// anything of ours.
		`CREATE TABLE "group_role" (
			"id"         ` + t.id + `,
			"group_name" ` + t.name + ` NOT NULL,
			"product_id" ` + t.ref + ` NOT NULL,
			"role"       ` + t.kind + ` NOT NULL,
			"created_at" ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "group_role_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "group_role_unique" UNIQUE ("group_name", "product_id", "role")
		)` + t.suffix,

		// Somebody's own credential for scripting. It is a live reference to
		// its owner rather than a snapshot of what they could do when it was
		// minted: what it reaches shrinks the moment their roles shrink, and
		// it dies with their account. A snapshot would quietly outlive the
		// access it was granted from — including a role withdrawn by a group
		// membership going away, which is the case with nothing to notice it
		// .
		//
		// expires_at is not nullable. A credential that never expires
		// is one nobody ever revokes, and the maximum is an
		// administrator's to set .
		`CREATE TABLE "personal_token" (
			"id"           ` + t.id + `,
			"name"         ` + t.name + ` NOT NULL,
			"secret_hash"  ` + t.hash + ` NOT NULL,
			"person_id"    ` + t.ref + ` NOT NULL,
			-- product_id narrows a token below its owner rather than above:
			-- what it reaches is the intersection, so pinning it to something
			-- they cannot read reaches nothing rather than granting it.
			"product_id"   ` + t.refNull + ` NULL,
			"created_at"   ` + t.timestamp + ` NOT NULL,
			"expires_at"   ` + t.timestamp + ` NOT NULL,
			"last_used_at" ` + t.timestamp + ` NULL,
			"revoked_at"   ` + t.timestamp + ` NULL,
			CONSTRAINT "personal_token_person_fk" FOREIGN KEY ("person_id") REFERENCES "person"("id"),
			CONSTRAINT "personal_token_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "personal_token_secret_unique" UNIQUE ("secret_hash"),
			-- Its owner names it and withdraws it by that name, so two of
			-- theirs may not share one.
			CONSTRAINT "personal_token_name_unique" UNIQUE ("person_id", "name")
		)` + t.suffix,

		// Admin is global rather than held against a product, so a
		// group mapping to it cannot live in the table above: the
		// product would have to be absent, and a uniqueness rule over
		// a column that may be absent behaves differently on each of
		// the four engines. A second table with one column costs less
		// than that difference.
		//
		// At least one row here is required while group-bound mode is
		// on, checked at startup, or a deployment can lock itself out
		// of its own administration.
		`CREATE TABLE "group_admin" (
			"id"         ` + t.id + `,
			"group_name" ` + t.name + ` NOT NULL,
			"created_at" ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "group_admin_unique" UNIQUE ("group_name")
		)` + t.suffix,
	}

	for _, stmt := range statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}

func downAccess(ctx context.Context, tx *sql.Tx) error {
	for _, stmt := range []string{
		`DROP TABLE "personal_token"`,
		`DROP TABLE "person_identity"`,
		`DROP TABLE "group_admin"`,
		`DROP TABLE "group_role"`,
		`DROP TABLE "session"`,
		`DROP TABLE "api_key"`,
		`DROP TABLE "role_grant_all"`,
		`DROP TABLE "role_grant"`,
		`DROP TABLE "person"`,
		`DROP TABLE "party"`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}
