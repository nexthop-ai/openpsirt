# Scanner fixtures

`grype-output.json` is **recorded**, not constructed: grype 0.112.0 run against
four real packages, with the vulnerability database of 2026-08-28.

Seven of its sixty-six matches are kept — enough to cover every fix state the
scanner emits, matches with and without aliases, and the descriptor that says
what ran. The provider list is trimmed to one entry; it is a hundred rows of
capture timestamps that no reader of this file needs.

It stands in place of a constructed fixture built from the fields a consumer
that *had* run against real output reads. That is good evidence of what the
fields mean and wrong about where one of them lives: the database describes
itself under a status, not directly, so the version of
the data a finding was matched against read as empty. The lesson is the ordinary
one — a fixture assembled from a description agrees with the description.

`grype-known-exploited.json` is one match, recorded from grype 0.119.0 against
the switch image this project keeps, with its own descriptor because it is its
own run. It exists for the one signal the corpus above carries none of: not a
match in it is listed in the exploitation catalog, so the arm that sets the
flag was reached by nothing.

What that hid is worth keeping. The reader decoded the catalog entry's issue
under `id`, which the scanner has never emitted — the entries state it as
`cve` — and because only the presence of an entry is read, nothing was wrong
and nothing said so. A field nobody reads, naming a key that does not exist,
reads to the next person as a fact about the format.
