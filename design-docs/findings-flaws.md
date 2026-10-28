# Recorded flaws

A vulnerability in what this deployment ships, recorded by hand before anybody
else knows of it. A finding of its own kind (REQ-21), triaged, assigned,
decided, clocked and reported like any other.

Satisfies REQ-19, REQ-21, REQ-37.

## Contents

- [Recorded flaws](#recorded-flaws)
- [Names on a recorded flaw](#names-on-a-recorded-flaw)
- [Builds and occurrences](#builds-and-occurrences)
- [Recorded words on a shared issue](#recorded-words-on-a-shared-issue)
- [Limits](#limits)

## Recorded flaws

Filed under an identifier this deployment mints (REQ-19): the product's name,
the year, and six digits, `SONIC-2026-481907`, the shape of a vendor advisory.

| Rule | Reason |
|---|---|
| Nothing is configured for the prefix | The product has a name people type |
| The number is drawn at random, never counted | A count discloses how many undisclosed flaws exist and when the last was recorded |
| A collision draws again in the same transaction, against any issue's filed name or alias, folded | Two people recording at once are not handed one name |
| Probing is safe because the routes answer held and unheld names alike (REQ-43) | Width is not the protection |
| It starts undisclosed, and recording asks the private triage right (REQ-37) | The dangerous mistake must not be the quiet one. Already-public is a flag on the request, asking the ordinary right |
| Every flaw has a report | Recorded from a report, it accepts that report; recorded without one, the same request names where it came from and an accepted report is written. `design-docs/findings-reports.md` |
| A flaw found here is marked so on its report | It carries no disclosure date and nobody is owed an answer |
| Its deadline uses the windows for our own products, counted from its first severity (REQ-33) | `design-docs/remediation-deadlines.md` § Recorded flaws. Unrated, it is listed and assignable with no deadline, reason `not-rated` |
| A flaw is recorded from a confirmed code finding through this same path: found here, undisclosed, at no version, flaw and link in one transaction | `design-docs/analysis-flaws.md` § Flaw records |
| A flaw from a code finding records the code finding, the component ranked first and the builds proposed, kept after the flaw record is undone | What a person was offered beside what they chose |

## Names on a recorded flaw

| Rule | Reason |
|---|---|
| A CVE assigned later is another name for the issue (REQ-18); the issue is refiled under it and the minted name stays an alias | Nothing moves |
| A name another issue answers to is refused, checked before the write | A constraint violation cannot tell "already recorded" from "would merge two issues" |
| Names are typed only onto a flaw recorded here | A typed name redirects every product's scans on one person's word |
| A typed name is `CVE-`, a four-digit year and four or more digits, or `GHSA-` and three groups of four in its alphabet | A typo redirects scans nobody expected |
| Recording or removing a name asks triage in every product the issue is open in, and no second person | A format check and the trail row cover a rare, reversible act |
| Each name records whether a person typed it; only typed names are removed, the filed name included | A scan reports its names again. A name typed before v0.5.0 reads as reported |
| Removing a name is undone by the next scan reporting it | Findings that resolved through it stay until that scan |
| Removing the typed filed name refiles under a remaining CVE, otherwise the oldest name; the answer names where it is filed | |
| Every name recorded or removed is an administrative record row | It changes what any product's later scan means |

## Builds and occurrences

One identifier, one finding per occurrence in every build that ships it.

| Rule | Reason |
|---|---|
| Every build is resolved before anything is written; a component one build lacks is refused, naming the build | Which builds are affected is the question |
| One product | The identifier is minted per product |
| A build named twice is one build, here and wherever a request names builds for a fix | |
| Held to the write ceiling alone, 50,000 findings by default, including builds added later | It adds findings and hides none |
| Every row gets the same embargo, rank and deadline, and a later build copies them | They are one flaw |
| It sits at a component of the build, or the build itself; naming nothing puts it on the root | |
| A component at an occurrence, keyed exactly as a scanned one (REQ-17), derived from the build's graph | A hand-recorded and a scanned copy of one flaw share decisions. A component can have several occurrences |
| Against the build itself, the occurrence is the root, with no name of its own | The product's name differs per variant |
| A name the build holds more than once is refused with the choices, through the shared component lookup | A switch image ships three vendored copies of one library, and thirteen names held at one version by two components |

## Recorded words on a shared issue

A recorded flaw writes its summary as the issue's description, its minted name,
addresses and weakness kinds onto the issue. Its rating stays the recording
product's (`design-docs/findings-severity.md` § The rating in force). The issue
row is read by every product holding it, so these follow the record (REQ-42).

| Rule | Reason |
|---|---|
| Description, other names and addresses are left out where a flaw recorded about the issue sits where the reader may not read it | An undisclosed flaw's summary is the embargo |
| A finding's evidence leaves out the weakness kinds too | |
| Every reader asks one rule: issue page and document, merges, evidence, findings and assignment lists, a component's issues, approaching disclosure, a decision's issue, an approver's outliers, an advisory's issues and document | A new reader is not the one that forgets |
| A text match over descriptions matches nothing withheld | A filter would leak one guess at a time |
| A findings search matches no withheld name | It would say where an undisclosed record is filed |
| An advisory document leaves these out wherever another product holds a record of the issue, whoever generates it | A document is public |
| A finding's working severity reads the issue row and the reader's product's rating, in lists, sorting, filtering, deadlines, urgency and a decision's baseline | A recorded flaw's rating is never on the row |

## Limits

| Limit | Detail |
|---|---|
| An identifier is minted per product | A flaw in two products is two records |
