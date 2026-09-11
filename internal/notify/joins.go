package notify

import "github.com/uptrace/bun"

// A finding with the names a message has to say.
//
// Both conditions about findings start from the same seven tables and name the
// same seven columns: what a person is told has to say which product, which
// build, which component and which issue, because a notification is read
// somewhere the row is not. The two copies were the same lines in two files,
// differing only in what they then narrowed by.
//
// The consumer is joined optionally, because whether a decision still covers a
// place is keyed on both upstream versions and one of them is the consumer's —
// so the condition that asks about decisions needs it and the one that does
// not, does not.
func findingsWith(q *bun.SelectQuery, consumer bool) *bun.SelectQuery {
	q = q.TableExpr("finding AS f").
		Join("JOIN target AS tg ON tg.id = f.target_id").
		Join("JOIN stream AS st ON st.id = tg.stream_id").
		Join("JOIN variant AS va ON va.id = tg.variant_id").
		Join("JOIN product AS p ON p.id = st.product_id").
		Join("JOIN component AS c ON c.id = f.component_id").
		Join("JOIN vulnerability AS v ON v.id = f.vulnerability_id")
	if consumer {
		q = q.Join("LEFT JOIN component AS uc ON uc.id = f.consumer_id")
	}
	return q.
		ColumnExpr("p.name AS product").
		ColumnExpr("st.name AS stream").
		ColumnExpr("va.name AS variant").
		ColumnExpr("c.name AS component").
		ColumnExpr("v.identifier AS vulnerability").
		// The product and the issue as identifiers too: what a message says is
		// a name, and what a later read narrows by is a column.
		ColumnExpr("st.product_id AS product_id").
		ColumnExpr("v.id AS vulnerability_id")
}
