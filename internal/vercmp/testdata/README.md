# Version-ordering vectors

Both files are the defining projects' own test data, committed verbatim. They
are not edited, reformatted or trimmed: the point of them is that they were
written by the people who defined the ordering, so a pair nobody here thought to
try is still checked.

| File | From | What it holds |
|---|---|---|
| `rpmvercmp.at` | `rpm-software-management/rpm`, `tests/rpmvercmp.at` | Pairs and the sign `rpm.vercmp` answers with, in the autotest format that suite is written in |
| `apk-version.data` | `alpine/apk-tools`, `test/unit/version.data` | Pairs with an operator, then a list of version strings the reader accepts and, marked with `!`, ones it refuses |

**Two things in them are answered differently here, deliberately.**

Alpine sorts a string it cannot read as text, and RPM orders any two strings at
all. Both are right for a package manager, which has to resolve a dependency
somehow; neither is right for a planner, whose answer is a recommendation
somebody schedules a release around. So a version that does not read leaves the
pair unordered, and the tests assert that a refusal only happens where one side
genuinely is not a version — asked by a rule written in the test rather than by
calling the code that refused.

Alpine's list of accepted and refused versions is what makes that checkable in
both directions, which is why the file is kept whole rather than reduced to the
ordering pairs.

`apk-version.data` also carries pairs under `~` operators. Those ask whether one
version is within another's series, which is a different question from which of
two is further along, and nothing here answers it.

## Refreshing them

There is no gate on staleness and deliberately so: these projects publish on
their own schedule, and a check against what they publish today would fail a
build for a reason no change here caused. Re-fetch when there is a reason to,
and run the tests.
