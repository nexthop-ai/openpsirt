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
describes: one argument, its revisions, and a second person's approval of one
(REQ-24, REQ-28). It keys on product, rule and occurrence with no versions, so
it covers the code finding on every branch, tag and variant (REQ-25).
`POST …/code-findings/{occurrence}/decision` records one.

| Outcome | Means | Second person |
|---|---|---|
| `dismissed` | Not a flaw to act on, for the reason stated | Yes |
| `not-security` | Real and harmless: a crash no input reaches, a leak in a tool that exits | Yes |
| `confirmed` | A real flaw | No |

| Dismissal reason | Means |
|---|---|
| `false_positive` | The flaw is not there |
| `wont_fix` | It is there and will not be fixed |
| `used_in_tests` | The code only runs in tests |
| `mitigated` | Something in place stops it, named in the reasoning |

| Rule | Reason |
|---|---|
| A code finding takes these outcomes alone, a vulnerability none | One asks whether it is real; the other how a known issue applies |
| A dismissal states one of the four reasons | |
| Approval needs `approver` and `internal-read` on the product, never the author | |
| A fixed code finding takes no decision | It reopens when seen |
| A probable pairing lapses a dismissal or not-security decision, re-affirmed as any lapsed decision (`design-docs/triage.md` § Re-affirmation); a confirmation stands | The pairing guesses it is the same result |
| The lapse is written with the pairing | |
| Decisions are read through the Decisions consumer (`design-docs/kinds.md` § Consumers) | The review queue and approval include them; the findings lists do not |

## Fixed code findings

`POST …/code-findings/{occurrence}/fixed` closes one on one build, with what
fixed it.

| Rule | Reason |
|---|---|
| Only a code finding the newest comparable run did not see | A run still reporting it is the authority |
| On the build named alone | |
| It names the fixing run: its series on that build, applied, comparable, built at or after the first not seeing it; any other is refused | A fix ships in a build |
| By somebody holding `internal-triage`, saying what fixed it (`design-docs/findings-flaws.md` § Recorded flaws) | |
| Seen again, it opens anew at the same occurrence (`design-docs/analysis-matching.md` § Carrying) | |

## Suppression rules

A suppression rule dismisses every code finding of a product it names, with one
reason and reasoning: `tests/`, vendored code, a noisy checker.
`…/products/{product}/suppression-rules` lists, proposes, approves and retires
them.

| Names | Covers |
|---|---|
| An analyzer rule | Every code finding under it, ignoring capitals |
| A path | Every code finding at or under it |
| Both | The rule's code findings under the path |

| State | When | Dismisses |
|---|---|---|
| `proposed` | Unapproved | Nothing |
| `in-force` | Approved, covering at most its approved size times the growth factor | What it names |
| `outgrown` | Approved, naming an analyzer rule, covering more | What it names, and asks for approval again |
| `needs-path` | An analyzer rule and no path, where a run found the rule to find memory safety or injection | Nothing, until retired and proposed with a path |
| `retired` | Out of use | Nothing |

| Rule | Reason |
|---|---|
| Proposed by `internal-triage`, approved by somebody else with `approver` and `internal-read` | A dismissal's second person (REQ-24) |
| It names a rule, a path or both, and one reason with reasoning | |
| A rule with no path is refused, at proposal and approval, where it finds memory safety or injection (`design-docs/analysis-queue.md` § Weakness families) or no run recorded it; one approved before stops dismissing at once | Those are judged one at a time; a whole checker goes where it fights a convention, measures style or cannot model the code |
| A path is a prefix from the checkout top, no edge slashes, compared exactly | `src` holds `src/a.c`, not `src2/a.c`; SQLite's LIKE ignores case |
| A path leaving the checkout or with an empty segment is refused | |
| Its words never change; rewording is retiring and proposing | Approval is of what was read (REQ-28) |
| Approval records the open code findings covered as its size; one shown none counts as one | |
| The growth factor is `triage.suppression-rule-growth`, two by default (REQ-27) | |
| A path-only rule is never outgrown | The approver agreed to the path |
| An outgrown rule keeps dismissing, and is approved again at its new size; one in force is refused | Withdrawn, its whole cover floods the queue |
| Coverage counts open code findings by occurrence the reader may read, worked out when read (REQ-42) | A new code finding under it never reaches the queue |
| Proposal, approval and retirement are in the administrative trail | |

## Code finding states

Worked out when read, carried on the evidence; the first that holds:

| State | When |
|---|---|
| Fixed | The finding is closed |
| Recorded as a flaw | `design-docs/analysis-flaws.md` § Flaw records |
| Dismissed, Not a security issue, Confirmed | That decision stands: approved, or waiting on nobody and not sent back |
| Dismissed | No decision stands, and a rule in force or outgrown covers it |
| No longer detected | A comparable run missed it |
| Open | Otherwise |

A decision about one code finding outranks a rule about many, and either
outranks absence, which is still recorded. A waiting decision leaves the state
where it was.

## Code finding assignment

`PUT …/code-findings/{occurrence}/assignment` gives one to a person or team, or
to nobody, as a finding is assigned (`design-docs/access.md` § Assignment,
§ Teams; REQ-34).

| Rule | Reason |
|---|---|
| It covers every build of the product it is open on | |
| The assigner triages it at every visibility it is open at; anybody else is answered as though it were absent | |
| Giving it to or taking it from somebody else also needs `assigner` | |
| A person is given it only where they read every visibility, a team where one member does; a collaborator is not given it | Holding is no way to read |
| Asked inside the writing transaction | |
| Past its end of life, or recorded as a flaw, it is refused with 409, and the latter's page offers no holder | Its flaw is assigned instead |
| Seen on a build where it was not open when assigned, it starts unassigned | |
| Lost reading, deactivation and handover move code findings with everything else (`design-docs/kinds.md` § Consumers) | |
| A team's assignment rules place unheld code findings, never one recorded as a flaw; whoever triages internal work reads and previews them (`design-docs/access.md` § Assignment rules) | |
| The lists of held work show each once to readers of internal work, naming the analyzer's rule | |
| The unassigned list and the queue narrowed to unheld work leave out sightings past their end of life | |
| One recorded as a flaw leaves the lists of held work; a handover leaves it with its holder and asks nothing, and releasing their work releases it | It is listed to nobody |
| The page, every queue row and the file name the holder | |
| The person given it is told, at internal visibility (`design-docs/notifications.md` § Code finding notices) | |

## End of life

A code finding seen only in releases past their end of life is kept, nothing
deleted (REQ-15); when that is is `design-docs/data-model.md` § End of support.

| Rule | Reason |
|---|---|
| Past its end of life when every release holding a finding of it is | Otherwise it is work in the supported one |
| The queue leaves out such sightings and counts the open ones left out; the state lists keep them (REQ-30) | |
| One open only in such releases leaves the queue | One closed or undetected on a supported release is still that release's |
| A decision, fixed closure, assignment and flaw record are refused with 409 | |
| A re-affirmation skips such code findings, refused with 409 where none is left; the list to re-affirm counts alike | |
| A decision in support reaches none of its kin past end of life | |
| A standing decision is still agreed or withdrawn (REQ-28), and a flaw's disclosure inclusion still changes | |
| The evidence says so and offers none of the refused controls | |
| A retired branch, tag or variant takes no run (`design-docs/analysis.md` § The upload); its code findings stay listed | |

## Limits

| Limit | Detail |
|---|---|
| A code finding sorts after every finding in the lists of held work | They order by urgency, which it lacks. The rail's Unassigned entry opens the findings list, which holds none; unheld ones are found in the code finding queue |
