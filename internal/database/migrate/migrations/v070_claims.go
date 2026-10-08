// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// suppressionV070 is v0.7.0's declaration of a build's own claims, and its
// index.
//
// v0.5.0's, with the product a claim's target ships inside and the published
// statement a claim was taken from. Derived from v0.5.0's declaration, which a
// tagged release fixed and which never changes again.
func suppressionV070(t *columnTypes) []string {
	statements := suppressionV050(t)
	statements[0] = withColumn(statements[0], `"subject_version" `+t.free+` NULL,`,
		`-- The product the subject ships inside, where the document named
			-- one: the package identifier, the name as the producer spelled
			-- it, and the version it was stated at. A claim about a
			-- component inside a product of the build applies beneath that
			-- product and nowhere else. Null where the document named the
			-- subject alone.
			"within_purl"    `+t.text+` NULL,
			"within_name"    `+t.free+` NULL,
			"within_version" `+t.free+` NULL,
			-- The published statement this claim was taken from, where a
			-- document uploaded on its own named the build's root as its
			-- product. A plain reference without a foreign key: a statement
			-- is superseded and never deleted, so the reference cannot
			-- dangle. Null for a claim the build sent with its inventory.
			"stated_by"      `+t.refNull+` NULL,`)
	return statements
}
