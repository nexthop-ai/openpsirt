# Code finding triage

What people decide about code findings: decisions, fixed closures, suppression
rules, the state worked out from them, assignment, and releases past their end
of life.

Satisfies REQ-15, REQ-24, REQ-25, REQ-27, REQ-28, REQ-30, REQ-34, REQ-42.

## Contents

- [Code finding triage](#code-finding-triage)
- [Fixed code findings](#fixed-code-findings)
- [Suppression rules](#suppression-rules)
- [Code finding states](#code-finding-states)
- [Code finding assignment](#code-finding-assignment)
- [End of life](#end-of-life)
- [Limits](#limits)

## Code finding triage

A decision about a code finding is a decision as `design-docs/triage.md`
describes one: one argument, its rows, its reasoning and every revision, and a
second person's approval of one revision (REQ-24, REQ-28). It is keyed on the
product, the rule the code finding is filed under, and its occurrence, with no
versions, so one decision covers it on every branch or tag and variant (REQ-25).
`POST …/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}/decision`
records one.

| Outcome | Means | Second person |
|---|---|---|
| `dismissed` | Not a flaw to act on, for the reason stated | Yes |
| `not-security` | Real and harmless: a crash on a path no input reaches, a leak in a tool that exits | Yes |
| `confirmed` | A real flaw | No |

| Dismissal reason | Means |
|---|---|
| `false_positive` | The analyzer is wrong: the flaw is not there |
| `wont_fix` | The flaw is there and will not be fixed |
| `used_in_tests` | The code is used only in tests and does not ship |
| `mitigated` | Something in place stops it, which the reasoning names |

| Rule | Reason |
|---|---|
| A code finding takes these outcomes alone, and a vulnerability none of them | A code finding is asked whether it is real; a vulnerability, how a known issue applies |
| A dismissal states one of the four reasons | A second person cannot agree to one nobody can review |
| A decision covers the occurrence at any version | The occurrence is carried by matching, not versions |
| Approval needs `approver` and `internal-read` on the product, never the author | The approval every decision has, at a code finding's visibility |
| A fixed code finding takes no decision | It opens again where seen again |
| A probable pairing, on function or nearest line, lapses a decision dismissing the code finding or calling it no security issue; its author re-affirms it, one or many, as any lapsed decision (`design-docs/triage.md` § Re-affirmation) | The decision was about the result as keyed, and a weaker pairing guesses it is the same |
| A confirmation stands through a probable pairing | A weaker pairing does not make a flaw less real |
| The lapse is written in the transaction recording the pairing | A pairing is never recorded with its decision left standing |
| A decision about a code finding is read through the Decisions consumer (`design-docs/kinds.md` § Consumers) | The review queue, approval and one decision's reads include it; the findings lists do not |

## Fixed code findings

`POST …/code-findings/{occurrence}/fixed` closes a code finding on one build,
with what fixed it and the build that fixed it.

| Rule | Reason |
|---|---|
| Only a code finding the newest comparable run did not see is closed as fixed | That absence is the evidence; a run still reporting it is the authority |
| It closes on the build named and nowhere else | Each build holding it is a statement of its own |
| It names the run whose build fixed it: one of its series on that build, applied and comparable, built at or after the first run not seeing it; any other run is refused | A fix ships in a build. The evidence names the first run not seeing it, and once fixed, the run named |
| It is closed by somebody holding `internal-triage` on the product, who says what fixed it | The closure a person writes, with who, when and why (`design-docs/findings-flaws.md` § Recorded flaws) |
| A code finding seen again opens anew at the same occurrence | Matching carries the result to a closed one's occurrence (`design-docs/analysis-matching.md` § Carrying) |

## Suppression rules

A suppression rule dismisses every code finding of a product it names, with one
reason and one reasoning: `tests/`, vendored code, a checker noisy on this
codebase. `…/products/{product}/suppression-rules` lists, proposes, approves and
retires them.

| A rule names | Covers |
|---|---|
| An analyzer rule | Every code finding filed under it, compared as the rule's issue is, without regard to capitals |
| A path | Every code finding at or under it |
| Both | Every code finding of the rule at or under the path |

| State | When | Dismisses |
|---|---|---|
| `proposed` | Nobody has approved it | Nothing |
| `in-force` | Approved, covering no more than its approver was shown times the growth factor | What it names |
| `outgrown` | Approved, naming an analyzer rule, and covering more than that | What it names, and asks to be approved again |
| `needs-path` | Naming an analyzer rule and no path, where a run has since found the rule to find memory safety or injection | Nothing, until retired and proposed again with a path |
| `retired` | Taken out of use | Nothing |

| Rule | Reason |
|---|---|
| Proposed by somebody holding `internal-triage` on the product, approved by somebody else holding `approver` and `internal-read` there | The second person a dismissal has (REQ-24) |
| It names an analyzer rule, a path, or both, and states one of the four reasons and its reasoning | Naming neither dismisses everything |
| An analyzer rule with no path is refused, at proposal and approval, where the rule finds memory safety or injection (`design-docs/analysis-queue.md` § Weakness families) or no run has recorded the rule; one approved before a run found that stops dismissing at once | Those flaws are judged one at a time. A whole checker is dismissed where it fights a convention, measures style, or cannot model the code, such as a leak checker under a pool allocator it cannot see |
| A path is a prefix from the top of the checkout, with no leading or trailing slash | `src` holds `src/a.c` and `src`, not `src2/a.c` |
| A path is compared exactly, character by character | Paths are case-sensitive, and SQLite's LIKE ignores ASCII case |
| A path climbing out of the checkout or holding an empty segment is refused | It names nothing a run reports |
| Its words never change; a rule worded differently is retired and proposed again | An approval is of what was read (REQ-28) |
| Approval records the open code findings covered as its approved size | What the approver was shown |
| The growth factor is `triage.suppression-rule-growth`, two where nobody has said | Ten covered at approval and a thousand later is not what was read (REQ-27) |
| A rule naming a path alone is never outgrown | Code under a dismissed path grows, and the approver agreed to the path |
| An approval shown no code finding is measured as though shown one | Its first code finding does not outgrow it |
| An outgrown rule is approved again at its new size, and a rule in force is refused | Approving again is reading what it now covers |
| An outgrown rule keeps dismissing | Withdrawn, everything it covers reaches the queue at once |
| Coverage counts open code findings by occurrence, approved or not, that the reader may read | A proposal shows its approver what it would dismiss (REQ-42) |
| Coverage is worked out when read | A new code finding under a rule in force never reaches the queue |
| Proposal, approval and retirement are in the administrative trail | As assignment rules are |

## Code finding states

Worked out when read, from the finding, its sighting and the decision standing
at its occurrence, and carried on the evidence. The first that holds:

| State | When |
|---|---|
| Fixed | The finding is closed |
| Recorded as a flaw | It was recorded as a flaw (`design-docs/analysis-flaws.md` § Flaw records) |
| Dismissed, Not a security issue, Confirmed | A decision with that outcome stands at the occurrence: approved, or waiting on nobody and not sent back |
| Dismissed | No decision stands, and a suppression rule in force or outgrown covers it |
| No longer detected | A comparable run did not see it |
| Open | None of the above |

| Rule | Reason |
|---|---|
| A standing decision comes before a suppression rule | One code finding is more specific than many |
| A standing decision or rule comes before absence | A dismissed code finding a run misses stays dismissed and records the absence |
| A decision waiting for a second person leaves the state where it was | It answers nothing until agreed |
| A code finding recorded as a flaw leaves the queue and takes no decision | Its flaw is what is judged |

## Code finding assignment

`PUT …/code-findings/{occurrence}/assignment` gives a code finding to a person
or a team, or back to nobody, as a finding is assigned (`design-docs/access.md`
§ Assignment, § Teams; REQ-34).

| Rule | Reason |
|---|---|
| It covers the code finding on every build of the product it is open on | A code finding is one occurrence across the builds |
| The assigner triages it at every visibility it is open at; anybody else is answered as though it were not there | Internal, for one not recorded as a flaw |
| Giving it to somebody else, or taking it from them, needs `assigner` as well | |
| A person is given it only where they read it at every visibility it is open at, a team only where one member does | Holding is no way to read. A code finding collaborator reads through their grant and is not given it |
| Asked inside the writing transaction | As every assignment |
| One past its end of life is refused with 409 | § End of life |
| One recorded as a flaw, included in disclosure or not, is refused with 409, and its page offers no holder | Its flaw is assigned instead |
| Seen on a build where it was not open when assigned, it starts unassigned there | As a finding arriving under an assigned component |
| Losing the reading it needs, deactivation and a handover move code findings with everything else, except one recorded as a flaw | One act whatever the work (`design-docs/kinds.md` § Consumers) |
| A team's assignment rules place code findings nobody holds, never one recorded as a flaw; whoever triages internal work in the product reads and previews them | `design-docs/access.md` § Assignment rules |
| The lists of held work list a code finding once, to readers of internal work in the product; a row names the analyzer's rule and opens its page | Unassigned work, one person's work, a team's queue, and totals per holder |
| The unassigned list leaves out sightings in releases past their end of life | Nobody may take one seen only there |
| One recorded as a flaw leaves the lists of held work, included in disclosure or not | Its flaw is held and listed as itself |
| Handing somebody's work to another leaves one recorded as a flaw with them, asking nothing; releasing their work releases it | It is listed to nobody, so a recipient who may not read it is not refused for it |
| The page and every row of the queue and its file name the holder | The page names the holder on its build while open there; a row the holder of the finding it shows |
| The person given it is told "a code finding assigned", at internal visibility | `design-docs/notifications.md` § Code finding notices |

## End of life

A code finding seen only in releases past their end of life is kept as it
stands, nothing deleted (REQ-15). When a release reaches it is
`design-docs/data-model.md` § End of support.

| Rule | Reason |
|---|---|
| A code finding is past its end of life when every release holding a finding of it is | One also seen in a supported release is work there |
| The queue leaves out every sighting in such a release, and counts the open code findings it leaves out; the lists by state still hold them | A list leaving things out says how many (REQ-30) |
| One open only in such releases leaves the queue, and is past its end of life only where its other sightings are too | One closed or no longer detected on a supported release is still that release's to decide |
| A decision, a fixed closure, an assignment and a flaw record are refused with 409 | Nobody fixes a release nobody supports |
| A re-affirmation of a lapsed decision leaves such a code finding out and re-makes the rest, refused with 409 where none is left | The list of what is yours to re-affirm counts the same occurrences and leaves off a decision with none |
| A decision about a code finding in support reaches none of its kin past their end of life | The kin is refused a decision of its own |
| A decision already standing is still agreed to or withdrawn | Somebody made it, and an approval is of what was read (REQ-28) |
| One recorded as a flaw is still included in or taken out of disclosure | The inclusion is about the flaw, judged on its own builds |
| Its evidence says it is past its end of life, and offers none of the refused controls | |
| A retired branch, tag or variant takes no run, so its code findings stop being seen and stay listed with the product | `design-docs/data-model.md` § Catalog retirement |

## Limits

| Limit | Detail |
|---|---|
| A code finding sorts after every finding in the lists of held work | They are ordered by urgency, and a code finding carries none. The rail's Unassigned entry opens the findings list, which holds no code finding: an unassigned code finding is listed by the unassigned list's read, and named unheld in the code finding queue |
