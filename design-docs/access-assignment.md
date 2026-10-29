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

Deciding who deals with something asks for a different right from deciding what
it is (REQ-34).

| Act | Right |
|---|---|
| Taking work nobody owns; handing back your own | Triage |
| Giving work to somebody else; taking what they hold, even for yourself | Assigner |
| Moving everything one person holds | Administration, since it spans every product |

| Rule | Reason |
|---|---|
| Findings arriving under an assigned component start unowned | Starting work needs nobody else's attention |
| Assigner is held alongside triage, never instead of it, checked at the endpoint and the store; the session answer carries the same conjunction | An interface draws no control that always fails |
| Who may be assigned is visibility, never a grant of its own | |
| The write that moves the rows refuses a hand-off the caller may not make | A path that skipped its check still moves nothing |
| Whether the recipient reads the work is asked inside the write's transaction, at every visibility open there: the single assignment, a code finding's, assignment by narrowing and an upgrade's holder | A scan recording an undisclosed occurrence in between would be handed over unasked |
| A finding is assigned for a whole group: one issue in one component, however many occurrences | |
| Handing back is giving out to nobody | |
| Nobody-assigned is a state, listed across every product somebody can see | Unowned work hides when each screen shows one product |
| Assigning covers what is there now | Tomorrow's findings under the component start unassigned |
| A vulnerability report is assigned under these rules, at undisclosed work: the recipient, or one team member, reads the product's reports. A judged report is not handed over, and moving everything one person holds moves their open reports | A report is undisclosed whatever its problem (`design-docs/findings-reports.md` § Report visibility) |

### Assignment by narrowing

One act assigns every row the findings list returns for a narrowing, across all
pages, or the rows somebody picked out of it (REQ-34).

| Rule | Reason |
|---|---|
| The rows are the list's own: the same filter, one issue at one fold, with a group condition asked of the group the list shows | |
| Each row is assigned as one finding is, across every build of the product and every binary of the fold | A row names the fold |
| Picked rows are intersected with the narrowing | A row the filter no longer admits has left the list |
| Without the assigner right, a colleague's work stays with them; the act moves what nobody holds and what is already the caller's, says how many findings changed hands and names the rows that stayed | As assigning one row at a time. The notification counts the rows that arrived |
| An empty selection is refused | It would read as every row the filter matches |
| Undisclosed work the recipient may not read refuses the whole act, asked at every visibility among the rows inside the writing transaction; taking work yourself, handing it back, and handing it to a reader of undisclosed work are not refused | The disclosed part alone leaves less than they were told |
| One notification for the act, however large: a selection of 2,000 is one event. Nobody is told of work handed back | |
| Not bounded, and written as one statement per fold | It changes only who holds something. 7,868 rows over 757,952 findings commit in 35 s on SQLite, against 52 minutes at 400 ms a request per row |
| One product per act | The list across products assigns a row at a time |

## Teams

A team is a named set of people, managed here. It holds work and grants nothing,
so one team carries mixed clearance; a deployment in direct mode has no provider
groups to use instead.

| Rule | Reason |
|---|---|
| Creating, retiring and populating a team is administration; assigning to one asks for the assigner right. A per-team administration role is not built | A team is deployment-wide and the assigner right per product |
| Team names are answered to anybody; membership to an administrator | Membership is a fact about people |
| Assignment points at a party, a person or a team, in one column | "Who holds this" stays one question for every filter, count, digest, reminder and handover |
| A person and a team draw their assignable name from one place; a person's lives as long as they do | A discriminator lets person 4 and team 4 match one condition |
| A subject carries its own name and every team it is on, read once | |
| Naming a person and a team in one request is refused | |
| A team assignment is a queue: unheld until a person takes it, which asks for triage alone. Filling the queue is dispatching | Hundreds of rows would otherwise read as owned and unseen |
| Assigning to a team asks that one member reads it, at every visibility its open occurrences carry; for disclosed work a member reading the product at either visibility is enough. A rule's sweep asks it per occurrence (§ Assignment rules) | One undisclosed occurrence among fifty makes the whole undisclosed |
| The queue is narrowed per viewer, counts included, and a matrix test asserts it | "Kernel team · 14" says two embargoed items exist |
| A team gives up queued work no remaining member reads, whenever its members or their reading change; retiring empties the queue | § Lost reading |
| Retiring a team keeps its row and name, and declaring the name again brings it back | Assigned work keeps a name to show |

| Bound | Reason |
|---|---|
| A team's name and display spelling are at most 191 characters, refused past that by the store | The index width; cut, a second declaration makes a second team |
| One declaration puts at most 500 people on a team | Each is resolved and written on its own |

## Assignment rules

A rule matches on component identity as well as a place in the tree. The
upstream name is the key that matters: one rule naming a source package catches
every binary built from it.

| Rule | Reason |
|---|---|
| Either key may be a pattern, with `*` the only metacharacter; `%` and `_` are escaped | Real package names hold them |
| A rule matches without regard to capitals, its keys folded and cut as component names are; a longer key is refused when written | It could never match |
| A pattern naming most of a build is refused, when written and at the preview, as a rule matching nothing is | The subtree is one recursive walk per build |
| The preview records nothing and answers which components the rule names, how many pieces of work sit there, and how many nobody holds | Only the last would be placed; it ignores rules already there, so it reports what the rule matches |
| The preview shares the sweep's predicate | |
| The preview names a sample of components and counts all of them | A rule beneath a kernel matches hundreds |
| The preview is narrowed like every count (REQ-42, REQ-43); somebody who may see nothing is told nothing, never zero | Unnarrowed, its gap from the findings list is the undisclosed work |
| The preview names no team and counts what the asker reads | |
| A rule may place vulnerability reports instead of findings; it then names no package or place, and either key is refused | It places a report nobody holds as recorded, and sweeps the product's open unheld reports when added. Its preview counts them where the asker reads the product's reports, and zero elsewhere |
| A rule places code findings, matched by component; one past its end of life is neither placed nor counted | `design-docs/analysis-triage.md` § End of life |
| A rule places no code finding recorded as a flaw, and the preview counts none | `design-docs/analysis-triage.md` § Code finding assignment |
| A rule places work only at a visibility one member of its team reads, per occurrence; a team of nobody is placed nothing | Unread occurrences stay unassigned beside those placed |
| A rule places only work nobody holds, re-checked at the write | A human assignment always wins |
| Rules are ordered, first match wins, and the finding records which rule placed it | |
| The ordinal is one past the highest; ties break by identifier | Two rules created at once share a number |
| Writing a rule asks for the assigner right beside disclosed or undisclosed triage | |
| Reading and previewing ask for triage at any visibility, security testing included | |
| Somebody who sees the product and lacks the right is refused 403; an unseen product answers as not declared | |
| A rule pointing at a retired team places nothing; retiring a rule leaves what it placed | |
| The listing names a rule's team by identifier and marks a retired one | |

### The sweep

Turning a rule on is a bulk write counted on rows written. How many one pass
places is a setting: too large holds a connection, too small re-queues a large
product many times.

A product's sweep is queued when a rule is written, when work arrives, and for every ruled product once a day.

| Arrival | Queued by |
|---|---|
| A scan opening findings | The scan's write |
| An analyzer run opening code findings | The run's write |
| A flaw recorded here, by hand or from a code finding | The recording |
| A recorded flaw widened to another build | The widening |

| Rule | Reason |
|---|---|
| An arrival queues its sweep in the transaction that opened the work | Queued after, a sweep can be claimed before the work exists |
| An arrival queues a sweep only where the product holds a rule in force that places findings | A product with no rule queues nothing per scan |
| A full sweep queue leaves the arrival to the next one and refuses nothing | A refused scan loses its findings; an unqueued sweep only delays placing them |
| Every product a rule in force places findings in is swept once a day, by one replica holding a lease | Catches an arrival a full queue skipped, and work left unheld before arrivals queued sweeps, in a product nothing scans again |
| Every replica asks every five minutes whether the daily sweep is due | A replica losing the race or stopping is replaced within minutes; asked once a day, rolling deploys can starve it |
| The daily sweep's lease is taken for a day and left to lapse, never handed back; its holder is refused like any other replica until it lapses | The lease's expiry is the durable record of the last run; handed back, every restart runs it again |
| A deployment's first start runs the daily sweep | The lease does not exist yet, so nothing records a run |
| The daily sweep stops at a full queue, keeps the lease, and asks again the next day | Asked again within minutes, it adds to a queue refusing work |
| A daily sweep failing for any other reason hands the lease back | The next replica asking runs it again |
| Every arrival queues its own sweep, never skipping one already waiting | A waiting sweep can be claimed and read before the arrival commits |
| A pass claims sweeps until none is waiting, one placing nothing included | Most arrivals find their work already placed; a pass ending there drains one sweep per interval and fills the queue |
| Queued work in bounded batches; a full batch queues the next, never loops in the worker | |
| The next batch is queued before the batch's own job is settled, and a failure to queue fails the job, which is retried | Settled first, a failed queue ends the sweep as a success |
| A batch run twice places only what nobody holds | |
| The batch size is read before a job is claimed | A failed read holds nothing |
| A batch is full when it has read a batch's worth | Counted on writes, a human assignment in the window ends the sweep as a success |
| A rule's share of a batch is what the batch has left to read | Counted on writes, room lost to a human assignment passes to the next rule |

## Departure

Nothing tells this software somebody has gone (REQ-45), and until an
administrator acts their work is in no list.

| Operation | Meaning |
|---|---|
| Releasing | It goes back to be picked up |
| Handing over | Names who deals with it now. Refused whole where any of it sits at a visibility the recipient may not read in its product, asked inside the moving transaction. Code findings move too |

Only an administrator does either; a person hands back their own by assigning it
to nobody. Deactivation is `design-docs/access-grants.md` § Somebody who has
left.

### Lost reading

Each write that can take reading away hands back, in its own transaction, the
work it leaves with a holder who cannot open it.

| Write | What goes back |
|---|---|
| A role withdrawn on one product | Their work there they may no longer read: everything where it was their last role, otherwise the undisclosed or security testing work, and the reports, the role let them read |
| A role withdrawn across every product | The same, product by product |
| A group-bound sign-in deriving less than the last | The same, in every product. Asked only when a derived role went or nothing was derived before, since a trusted-header sign-in runs on every request |
| The first group-bound sign-in after a switch into group-bound mode | What administrator-assigned roles let them hold that their groups do not let them read |
| A switch out of group-bound mode | The same, for everybody holding work, against the restored assigned roles |
| Somebody taken off a team | The team's work no remaining member reads |
| A team retired | Everything in its queue |
| An account deactivated | Everything it held, everywhere, and its teams' work no remaining member reads |
| Any of the above for a team member | Also their teams' work no remaining member reads |

| Rule | Reason |
|---|---|
| A person keeps undisclosed and security testing work where they read it, and disclosed work while they hold any role in the product | Disclosed work travels with its assignment |
| A team keeps work at a visibility one member reads, and disclosed work while one member reads the product at any visibility | § Teams |
| A report goes where undisclosed work goes; a code finding by the rule for findings | `design-docs/findings-reports.md` § Report visibility |
| It goes back to nobody, and no sweep is queued | The product's next sweep places it, when a rule is written or work arrives; a full queue must never refuse a withdrawal of access |
| Asked of whoever the write named and every team they are on | |
| Inside the write that took the reading away; deactivation's timing is `design-docs/access-trail.md` § The administration trail | Done after, a failure strands the work with nothing to retry it |
| Nobody is told | |
| A switch into group-bound mode hands nothing back | What somebody reads is known only at their next sign-in |
| A switch out of group-bound mode hands back at once | The restored assignments are final |

## Limits

| Limit | Detail |
|---|---|
| A rule naming a component with a letter outside ASCII matches on the three servers and not on SQLite | SQLite folds ASCII only. No deployment runs SQLite; agreement needs a stored folded name, a schema change |
| The batch-fullness rule is reasoned, never pinned by a test | The divergence needs a write between a batch's read and write; what is pinned is that a sweep spanning several batches routes everything it matches |
| After a switch into group-bound mode, work held by somebody who never signs in again stays with them until they do, are deactivated, or it is handed back by hand | Their set-aside roles grant nothing, so the work is in no list. A person whose groups derive no role is asked about on every sign-in |
