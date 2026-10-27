# Assignment

Who holds work, the rights to move it, teams and their queues, assignment
rules, and work handed back when reading goes.

Satisfies REQ-34, REQ-42, REQ-43, REQ-45.

## Contents

- [Assignment](#assignment)
- [Teams](#teams)
- [Assignment rules](#assignment-rules)
- [Departure](#departure)
- [Limits](#limits)

## Assignment

Deciding who deals with something is a different act from deciding what it is,
so it asks for a different right (REQ-34).

| Act | Right |
|---|---|
| Taking work nobody owns; handing back your own | Triage |
| Giving work to somebody else; taking what they hold, even for yourself | Assigner |
| Moving everything one person holds | Administration: it is about a person and spans every product |

Findings arriving under an already-assigned component start unowned, so
starting on work needs nobody else's attention.

| Rule | Reason |
|---|---|
| Assigner is held alongside triage, never instead of it | On its own it assigns nothing. Enforced at the endpoint and again at the store, and the session answer carries the same conjunction so an interface draws no control that always fails |
| Who may be assigned is visibility, never a grant of its own | |
| The write that moves the rows refuses a hand-off the caller may not make | A path that forgot to check first still moves nothing |
| Whether the recipient may read the work is asked inside the write's transaction, at every visibility open there | A scan recording an undisclosed occurrence between a separate read and the write would be handed over unasked. The single assignment, a code finding's assignment, assignment by narrowing and an upgrade's holder all ask it there |
| A finding is assigned for a whole group: one issue in one component, however many occurrences | |
| Handing back is giving out, with nobody as the recipient | |
| Nobody-assigned is a state to ask about, listed across every product somebody can see | Work nobody owns hides when every screen shows one product |
| Assigning covers what is there now | Findings arriving under the component tomorrow start unassigned and appear in that list |
| A vulnerability report is assigned under these rules, at undisclosed work | A report is undisclosed whatever its problem (`design-docs/findings-reports.md` § Report visibility), so the recipient, or one member of the team, reads the product's reports. A judged report is not handed over. Moving everything one person holds moves their open reports |

### Assignment by narrowing

One act assigns every row the findings list returns for a narrowing, across all
its pages, or the rows somebody picked out of it (REQ-34).

| Rule | Reason |
|---|---|
| The rows are the list's own: the same filter, at one issue at one fold | A group condition, such as who holds it or how far it is decided, is asked of the group the list shows |
| Each row is assigned as one finding is: across every build of the product, at every binary of the fold | A row of the list names the fold, so the act covers what the row covers |
| Picked rows are intersected with the narrowing | A picked row the filter no longer admits is no longer in front of the person |
| Without the assigner right, a colleague's work stays with them | It moves what nobody holds and what is already the caller's, says how many findings changed hands and names the rows that stayed. The notification counts the rows that arrived |
| An empty selection is refused | Read as no selection, it would assign every row the filter matches |
| Undisclosed work the recipient may not read refuses the whole act, asked at every visibility among the rows inside the writing transaction | The disclosed part alone leaves them holding less than they were told. Taking work yourself, handing it back, and handing it to a reader of undisclosed work are not refused |
| One notification for the act; nobody is told about work handed back | A selection of 2,000 is one thing that happened |
| Not bounded | It changes only who holds something. One statement per fold, so its size follows source packages: 7,868 rows over 757,952 findings commit in 35 s on SQLite, against 52 minutes at 400 ms a request per row |
| One product per act | The list spanning products has no single product to authorize against, so it assigns a row at a time |

## Teams

A team is a named set of people, managed here. It holds work and grants nothing:
no role, no visibility, no capability, so one team carries mixed clearance. A
provider group is no substitute: a deployment in direct mode has none.

| Rule | Reason |
|---|---|
| Creating, retiring and populating a team is administration; assigning work to one asks for the assigner right | A team is deployment-wide and the assigner right per product, so populating one would change who receives work in every product assigning to it. A per-team administration role is not built |
| Team names are answered to anybody; membership to an administrator | Assigning needs the name; membership is a fact about people |
| Assignment points at a party, a person or a team, in one column | "Who holds this" stays one question for every filter, count, digest line, reminder and handover |
| A person and a team draw their assignable name from one place; a person's is made with the person and lives as long as they do | A discriminator beside an identifier lets person 4 and team 4 match one condition |
| A subject carries what counts as theirs: their own name and every team they are on, read once | |
| Naming a person and a team in one request is refused | A precedence rule nobody would remember |
| A team assignment is a queue, never a holding | Its work is unheld until a person takes it, which is picking up unowned work under triage alone. Filling the queue is dispatching |
| Assigning to a team asks that at least one member reads it, at every visibility its open occurrences carry | One undisclosed occurrence among fifty makes the whole undisclosed. For disclosed work, a member reading the product at either visibility is enough. A rule's sweep asks it per occurrence (§ Assignment rules) |
| The queue is narrowed per viewer, counts included, and a matrix test asserts it | "Kernel team · 14" shown to everybody says two embargoed items exist |
| A team gives up queued work no remaining member reads, whenever its members or their reading change | § Lost reading. Retiring a team empties its queue |
| Retiring a team keeps its row and its name, and declaring the name again brings it back | Assigned work keeps resolving to a name; declaring is idempotent everywhere |

| Bound | Reason |
|---|---|
| A team's name and display spelling are at most 191 characters, refused past that by the store | The name carries an index of that width; cut, a second declaration would make a second team |
| One declaration puts at most 500 people on a team | Each is resolved and written on its own |

## Assignment rules

A rule matches on component identity as well as a place in the tree. The
upstream name is the key that matters: one rule naming a source package catches
every binary built from it, where a subtree rule needs a line per occurrence.

| Rule | Reason |
|---|---|
| Either key may be a pattern, with `*` the only metacharacter; `%` and `_` are escaped | Package names are full of dots, plus signs and dashes, and real ones hold `%` and `_` |
| A rule matches without regard to capitals: keys are folded and cut as the component names they match were | A key longer than that width could never match and is refused when written |
| A pattern naming most of a build is refused, when written and again at the preview, as a rule matching nothing is | A bare glob says nowhere in the tree. The subtree is one recursive walk per build, never one per named component |
| The preview records nothing and answers which components the rule names, how many pieces of work sit there, and how many nobody holds | Only the last is what it would place. It ignores the rules already there, so it is named for what it matches |
| The preview asks exactly what the sweep asks, sharing the predicate | |
| The preview names a sample of components and counts all of them | A rule beneath a kernel matches hundreds of modules |
| The preview is narrowed like every count (REQ-42, REQ-43); somebody who may see nothing is told nothing, never zero | Unnarrowed, its gap from the findings list is the undisclosed work |
| The preview names no team, and counts what the asker reads | Work no team member reads is counted and then not placed |
| A rule may place vulnerability reports instead of findings, and then names no package or place; either key is refused | It places a report nobody holds as it is recorded, and sweeps the product's open unheld reports when added. Its preview counts open reports and unheld ones where the asker reads the product's reports, and zero elsewhere |
| A rule places code findings as well as findings, matched by the component | One piece of work each in the preview. A code finding past its end of life is neither placed nor counted (`design-docs/analysis.md` § End of life) |
| A rule places no code finding recorded as a flaw, and the preview counts none | Its flaw is placed as itself (`design-docs/analysis.md` § Code finding assignment) |
| A rule places work only at a visibility one member of its team reads, per occurrence | An occurrence nobody on the team reads stays with nobody while those beside it are placed. A team of nobody is placed nothing |
| A rule places only work nobody holds, re-checked at the moment of the write | A human assignment always wins |
| Rules are ordered, first match wins, and the finding records which rule placed it | |
| The ordinal is one past the highest; ties break by identifier | Two rules created at one moment take one number, and must not swap places between batches |
| Writing a rule asks for the assigner right beside disclosed or undisclosed triage | |
| Reading and previewing ask for triage at any visibility, internal included | Knowing where work goes is part of working it, code findings included |
| Somebody who sees the product and lacks the right is refused 403; a product they cannot see answers as not declared | The answer an issue act gives |
| A rule pointing at a retired team places nothing; retiring a rule leaves what it placed | |
| The listing names a rule's team by identifier and marks a retired one | A team past the first page of teams, or retired, still has a name |

### The sweep

Turning a rule on is a bulk write: one source package reaches thousands of
unowned issues, so the bound counts rows written. How many one pass places is a
setting: too large holds a connection through the pass, too small re-queues a
large product many times.

| Rule | Reason |
|---|---|
| Queued work in bounded batches; a full batch queues the next, never loops in the worker | |
| The next batch is queued before the batch's own job is settled, and a failure to queue fails the job, which is retried | Settled first, a failure to queue ends the sweep as a success |
| A batch run twice places only what nobody holds | |
| The batch size is read before a job is claimed | A failure to read it holds nothing |
| A batch is full when it has read a batch's worth, never when it has written one | The write re-checks the holder, so a human assignment inside the window shortens the writes; counted on writes, the sweep stops there as a success |
| A rule's share of a batch is what the batch has left to read | Measured in writes, room lost to a human assignment passes to the next rule |

## Departure

Nothing tells this software somebody has gone (REQ-45), so moving their work is
an administrator's act. Until it is taken their work is in no list: not the
shared one, because it is assigned, and not theirs.

| Operation | Meaning |
|---|---|
| Releasing | Nobody is dealing with it, and it goes back to be picked up |
| Handing over | Names who deals with it now. Refused whole where any of it sits at a visibility the recipient may not read in its product, asked inside the transaction that moves it. Code findings move with everything else |

Only an administrator does either; a person hands back their own by assigning
it to nobody. Deactivation is `design-docs/access-grants.md` § Somebody who has
left.

### Lost reading

Each write that can take reading away hands back, in its own transaction, the
work it leaves with a holder who cannot open it.

| Write | What goes back |
|---|---|
| A role withdrawn on one product | Their work there they may no longer read: everything where it was their last role, and otherwise the undisclosed or internal work, and the reports, the role let them read |
| A role withdrawn across every product | The same, product by product |
| A group-bound sign-in deriving less than the last | The same, in every product. Asked only when a derived role went or nothing was derived before, because a trusted-header sign-in runs on every request |
| The first group-bound sign-in after a switch into group-bound mode | What the administrator-assigned roles let them hold that their groups do not let them read |
| A switch out of group-bound mode | The same, for everybody holding work, against the assigned roles it restores |
| Somebody taken off a team | The team's work no remaining member reads |
| A team retired | Everything in its queue |
| An account deactivated | Everything it held, everywhere, and its teams' work no remaining member reads |
| Any of the above for a team member | Also their teams' work no remaining member reads |

| Rule | Reason |
|---|---|
| A person keeps undisclosed and internal work where they read it, and disclosed work while they hold any role in the product | Disclosed work travels with its assignment |
| A team keeps work at a visibility one member reads, and disclosed work while one member reads the product at any visibility | The rule a hand assignment to a team asks (§ Teams) |
| A report goes where undisclosed work goes; a code finding by the rule for findings | A report is read under undisclosed reading (`design-docs/findings-reports.md` § Report visibility) |
| It goes back to nobody, and no sweep is queued | The unassigned list holds it, and an assignment rule places it when a rule is next recorded in the product. A full queue must never refuse a withdrawal of access |
| Asked of whoever the write named and every team they are on | A member's reading going can strand the team's queue |
| Inside the write that took the reading away; deactivation hands back after its write commits | Done after, a failure leaves the work with somebody who cannot open it and nothing to retry it. Deactivation's reason is `design-docs/access-grants.md` § Somebody who has left |
| Nobody is told | As with any work handed back |
| A switch into group-bound mode hands nothing back | What somebody reads there is known only at their next sign-in; judged at the switch, work their groups cover would go back |
| A switch out of group-bound mode hands back at once | Nothing derives a role after it, so the restored assignments are final |

## Limits

| Limit | Detail |
|---|---|
| A rule naming a component whose name has a letter outside ASCII matches on the three servers and not on SQLite | SQLite folds ASCII only. No deployment runs SQLite, but a rule proved locally can behave differently; agreement needs a folded name stored beside the spelling, a schema change |
| The batch-fullness rule is reasoned, never pinned by a test | The divergence needs a write between a batch's read and write, and a test runs one thing at a time. What is pinned is that a sweep spanning several batches routes everything it matches |
| After a switch into group-bound mode, work assigned to somebody who never signs in again stays with them until they do, are deactivated, or it is handed back by hand | Their set-aside roles grant nothing meanwhile, so the work is in no list. A person whose groups derive no role is asked about on every sign-in, which finds nothing once they hold nothing |
