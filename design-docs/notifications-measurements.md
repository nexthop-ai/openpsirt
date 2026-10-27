# Notifications measurements

Benchmark runs behind the reconcile and sweep rules in
`design-docs/notifications.md` and `design-docs/notifications-delivery.md`.

## Contents

- [Reconcile batches](#reconcile-batches)
- [Sweep index](#sweep-index)

## Reconcile batches

For `design-docs/notifications.md` § Events and conditions. Opening 152,859 `decision-waiting` conditions for 204 people, on PostgreSQL 16
at one processor over a 1 ms link:

| Writes | Time |
|---|---|
| A row a statement | 700.9 s and 704.4 s |
| A batch a statement | 7.0 to 8.0 s |
| A sweep changing nothing | 7.0 to 7.5 s |

## Sweep index

For `design-docs/notifications-delivery.md` § Delivery. The read of who a sweep has told, per kind, with 152,859 open conditions over
204 people on PostgreSQL:

| Sweep | Without the index | With it |
|---|---|---|
| Steady, changing nothing | 5.0 to 5.2 s | 4.3 to 4.4 s |
| Opening 85,869 conditions | 401 to 404 s | 401 to 404 s |

`design-docs/database-schema.md` § Indexes has the read on each engine.
