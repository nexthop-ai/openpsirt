// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// groupRoleV060 is v0.6.0's declaration of what configuration
// maps provider groups to.
//
// A mapping names its product by the name configuration states, so a product
// configuration names before any pipeline declares it is held and grants once
// the product exists. A mapping naming no product is a role across every
// product, in a table of its own for the reason administration has one: a
// uniqueness rule over a column that may be absent behaves differently on each
// of the four engines.
func groupRoleV060(t *columnTypes) []string {
	return []string{
		// The group is matched by the name the provider reports — a team slug
		// from GitHub, a claim value from an identity provider — so it is
		// stored as given rather than resolved to anything of ours.
		`CREATE TABLE "group_role" (
			"id"           ` + t.id + `,
			"group_name"   ` + t.name + ` NOT NULL,
			-- The product's name folded the way a product's name is, so it
			-- matches the product whatever capitals configuration wrote.
			"product_name" ` + t.name + ` NOT NULL,
			"role"         ` + t.kind + ` NOT NULL,
			"created_at"   ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "group_role_unique" UNIQUE ("group_name", "product_name", "role")
		)` + t.suffix,

		`CREATE TABLE "group_role_all" (
			"id"         ` + t.id + `,
			"group_name" ` + t.name + ` NOT NULL,
			"role"       ` + t.kind + ` NOT NULL,
			"created_at" ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "group_role_all_unique" UNIQUE ("group_name", "role")
		)` + t.suffix,
	}
}
