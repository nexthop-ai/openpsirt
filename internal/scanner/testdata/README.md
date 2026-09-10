# Scanner fixtures

`grype-output.json` is **recorded**, not constructed: grype 0.112.0 run against
four real packages, with the vulnerability database of 2026-08-28.

Seven of its sixty-six matches are kept — enough to cover every fix state the
scanner emits, matches with and without aliases, and the descriptor that says
what ran. The provider list is trimmed to one entry; it is a hundred rows of
capture timestamps that no reader of this file needs.

It replaced a constructed fixture, which had been built from the fields a
consumer that *had* run against real output reads. That was good evidence of
what the fields mean and it was wrong about where one of them lives: the
database describes itself under a status now, not directly, so the version of
the data a finding was matched against read as empty. The lesson is the ordinary
one — a fixture assembled from a description agrees with the description.
