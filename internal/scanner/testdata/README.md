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

The entries state the issue under `cve`, and only whether an entry is present
is read. A named field here would be a claim about the scanner's format that
nothing checks.
