# Review and assignment screens

The review queue, the decision page, the assignments screen, work nobody holds,
and the assignment rules screen.

Satisfies REQ-25, REQ-27, REQ-28, REQ-29, REQ-34.

## Contents

- [The review queue](#the-review-queue)
- [The decision page](#the-decision-page)
- [Assignments and assignment rules](#assignments-and-assignment-rules)
- [Work nobody holds](#work-nobody-holds)
- [Limits](#limits)

## The review queue

One card per decision (REQ-28): one proposer's act, however many occurrences. The
card carries the reasoning as it stands, how many records the decision wrote, how
many locations and builds it reaches, whether it was approved before and came
back, and how long the finding has been put off.
`design-docs/triage-approval.md` § The review queue says what the queue holds and
on what terms.

| Tab | Holds | A card offers |
|---|---|---|
| To approve | Decisions waiting for a second person | Approve and Reject |
| Expired deferrals | Deferrals past their date | Decide again |
| Missed fix dates | Promised upgrades and patches past their date | Change the version or the date, or decide again |
| Mine, recent | What the reader proposed and what became of it | Reading, the decision a link away |
| To reaffirm | The reader's own lapsed decisions | Reaffirm, one or many |

Every tab carries its count, read from its own list without the filters.

| Rule | Reason |
|---|---|
| A card names its reason: the state mark says expired deferral or missed fix date, and the outcome reads as promised, "Upgrade to 3.0.15 by 2026-09-01", "Patch by 2026-09-01", "Deferred until 2026-09-01" | |
| A card says whom a stated scope holds for, beside the outcome; absent where the reason decides | The approver agrees to it |
| A card offers only acts answering its reason; the two dated lists carry no Approve, selection or batch | Approval is refused on anything else |
| Deciding again opens the finding, or the decision page for a decision over many issues | |
| Changing a promise is on the card: the version for an upgrade, the date, and a required reason; the confirmation stays until put away | The promise leaves the list once its date moves |
| The two dated lists narrow to the reader's own with a Mine only box | They show everybody's |
| Rejecting needs a reason. Several selected and named as a batch are approved together, so undone together | |
| A batch's undo appears only just after it is agreed | A standing undo of an old batch is unsafe |
| A bulk decision draws its counts and its outliers; any can be set aside, the button then reading "approve N, reject M", both in issues. An extension names the decision it rests on | |
| An outlier is one issue, set aside or held back at every occurrence the decision holds for it; the author holding back and the approver setting aside take the same set | Part left in is agreed with it |
| To reaffirm lists one row per decision: why it lapsed (the code moved, rated worse and between which bands, or both), outcome, justification, issue, component, product, occurrences, when. Ticked across pages; Reaffirm N opens one box for the shared reason, and the result says how many were re-made and how many wait | The lapse message links here |
| Report rulings waiting for approval are a section below, with the ratings and date movements, across products where the reader reads reports, narrowed by a product in the address | A rejecting or out-of-scope ruling waits for a second person |
| Upstream offers for review are a section: one entry per statement and open finding, with issue and component (opening the finding where the statement starts a decision), build, what the upstream says, and the statement's mark, link and decline control; across readable products, narrowed with the rest, drawn only where something is offered (`design-docs/upstream.md` § Offers for review) | |
| A section named in the address (ratings, disclosure dates, rulings) is brought into view | A link lands on it |
| A waiting rating names its product on the card and in every sentence about agreeing (REQ-29) | Two products may rate one issue differently |
| A waiting embargo movement names the act (later, sooner, or public for good), and a disclosure says it cannot be undone | Different things to agree to |

The queue narrows to one product, the one a home figure counted for: the address
carries it and the line under the heading names it.

Filters above the queue narrow by proposer, an age of seven, thirty or ninety
days, severity, outcome and release (`design-docs/triage-approval.md` § Queue filters).
They ride in the address, clear the selection when changed, and sit on the three
lists, not the two tabs about the reader's own decisions.

| Export | Holds |
|---|---|
| A list's file | The list as narrowed: its filters, the list and the Mine only box |
| Mine only on the queue's file | Only what still waits |
| Mine, recent | Every decision the reader proposed with what became of it |
| To reaffirm | No file, so none is offered |

The rail's queue count and home's pending figure count To approve plus the report
rulings the reader may agree to: waiting, proposed by somebody else, in a
product where they may approve a ruling. Waiting ratings and date movements are
their own sections, uncounted there, sharing neither the card, the selection nor
the batch with decisions.

## The decision page

One decision whole, and every act at that grain: revise, withdraw, comment,
agree, send back, hold rows back, and say where the work is happening.
`design-docs/triage-decisions.md` says what a decision is and what the read answers.

| Rule | Reason |
|---|---|
| Nothing on it acts on one occurrence, and the argument names no row and carries no row state | An act on one row is at a grain nobody decided in |
| The state is one word: waiting, sent back, approved, withdrawn, lapsed, agreement undone, or ended several ways; the proposer's list reads the same word | |
| Present reach is said in acted units: one decision at one fold, its packages, their consumers, every build reached; occurrences are a title on the figure; nothing reached reads "none" | |
| What it covers is what it covers now; what was agreed to is on the approval in the revision history | It grows by matching |
| "Reach when withdrawn" and "Reach when it lapsed" sit beside the present reach, as occurrences and builds on the date they stopped; a partly lapsed decision shows both parts | A stopped row is keyed on its occurrence |
| Each stopped part opens the findings list narrowed to those occurrences and that state, across every release and planned or not, as one self-removing chip | The list's defaults would hide a tag or an ended branch |
| A decision occurrence's address resolves here, replacing rather than pushing history | Notices, reports and the evidence list name occurrences, and the audit log names the decision |
| Reaffirming is on the finding | It is one occurrence in one build |
| It says whom a published statement holds for, marked as from the reason where none is stated | |
| Acts offered follow the act-and-needs table in `design-docs/triage-approval.md` § Rights and the session's capabilities, never roles | A second copy disagrees |
| Holding rows back is offered only on a bulk decision with outliers | It is the author's side of the approver's choice |
| The capability is a gate only while it means what the operation accepts: one the operation grants a triager is reported to a triager | A two-person team without the approver capability is otherwise shown a decision it cannot answer |

## Assignments and assignment rules

Assignments is two tabs: what is due soon and undecided, and who holds what.

| Rule | Reason |
|---|---|
| A row nobody holds says "unassigned" in muted text | Nobody is not a person with an avatar |
| A code finding held is a row of its own, named by its rule, marked code finding, opening its page | |
| Every figure counts pieces of work and says so; the findings covered are a quieter second column; the screen says in words what each counts | A row and the list behind it are one measurement |
| Taking unowned work is one action without the assigner right: the picker's first option on a finding, and Take on the list's batch bar | The common case |
| The holder is the field's value, never its placeholder | Placeholder grey reads empty |
| A picker nobody can use says so in the box, "Pick a product to assign", and is drawn disabled | |
| Offering work to somebody needs a product picked, and says so; taking it does not | The list spans products |
| A team's row opens the team's queue | A team holds work as a person does |
| What the reader and their teams hold is two lists, dependency findings and code findings, each with its own count and pages, never one summed figure (`design-docs/kinds.md` § Consumers) | A rule at a place and an advisory at a component are different units |
| Each of the reader's own lists is asked for every reader and drawn where the family is counted at the scope or the reader holds some of it; held in another product and holding none, the family's line stands in its place; held nowhere and holding none, it is absent | Work handed to somebody stays theirs where it is disclosed, so a reader of nothing can still hold some |
| Who else holds what counts findings of both families, so its tab is drawn, and its totals and any one holder's list asked, only where the reader reads one at the scope, with the line for a family read in another product (`design-docs/interface.md` § Families a reader holds) | "Nobody else is holding anything" reads as no open work |
| Where nobody else holds anything in a picked product, it links that product's unassigned code findings where the code family is counted there | The findings list holds no code finding |
| A holder's list carries the reports they hold below their findings, and the people tab the reports nobody holds, drawn only where there are any; the people table counts each holder's open reports in a column; the narrowing is the product picked | Most people read no reports |
| A holder nothing matches holds nothing, never refused; the read is narrowed by what the caller may see | A refusal would answer whether a team exists |

The assignment rules screen (REQ-34) is per product, a numbered list because
order is precedence: the first matching rule places the work.

| Rule | Reason |
|---|---|
| A rule places findings or vulnerability reports, chosen first, and the form says what each kind does before it is filled | |
| A report rule takes no key; its preview says how many unheld open reports it would place | |
| Saving says the sweep has started | One rule can place thousands, so it is queued |
| The finding names the rule that placed it on the holder card, and says taking it picks up unheld work the rule will not take back | |
| Both are read off the occurrences the reader may read, the ones the card shows | Read off an unreadable one, the holder names who works undisclosed work |

## Work nobody holds

Work nobody holds is one list per family, opened from the rail's Unassigned
entry: the findings list under nobody assigned and nothing decided, and the
code finding queue across products under nobody assigned.

| Rule | Reason |
|---|---|
| The two lists stay apart, each with its own count, never summed | An unjudged code result must never reach a published statement, and a rule at a place and an advisory at a component are different units |
| `/unassigned` offers one card per family to a reader counting both, each with its count and the line for a family read in half, opening its list | |
| A reader counting one family is taken from `/unassigned` straight to that family's list | A bookmark or an old digest's link lands on work |
| The dependency count is asked from the list's address through the list's own query, its three silent-address narrowings included; the code count is the queue's total under the same filter | A count is of what its list shows |
| A family's count is asked only where the family is counted (`design-docs/interface.md` § Families a reader holds) | A count not drawn is not asked for |

## Limits

| Limit | Detail |
|---|---|
| The queue card does not say which builds were reached by matching and which by an applied decision | The record keeps one number |
