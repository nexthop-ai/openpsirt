# Disclosure

Embargo dates, the list of what approaches disclosure, disclosing an issue,
moving a date, and collaborators granted one case.

Satisfies REQ-37, REQ-38, REQ-40, REQ-43.

## Contents

- [Disclosure](#disclosure)
- [Disclosure-date movements](#disclosure-date-movements)
- [Case collaborators](#case-collaborators)
- [Limits](#limits)

## Disclosure

Public and private mean disclosed and undisclosed, so an undisclosed finding is
one somebody intends to disclose. All of this is built.

| Rule | Reason |
|---|---|
| A private finding reported from outside carries a disclosure date, by default ninety days after the report was received (REQ-37) | It gives the embargo an end somebody outside can hold the deployment to |
| A flaw found here and a public finding carry none | Nobody outside counts down to a publication |
| A report from outside ruled a duplicate of a flaw found here gives it a date, counted from that report's arrival, or brings an existing one earlier | `design-docs/findings-reports.md` § Judgment |
| Reaching the date discloses nothing; it escalates | Disclosing while the fix is not ready is a decision a person makes |
| What approaches disclosure is listed soonest first, and noticed at a lead time somebody sets (REQ-38) | The date itself is the last moment to act |
| The date arriving tells administrators, and whoever holds the finding where they still read undisclosed work in the product | A condition, standing while the date is past and nothing is decided |

The list is itself a disclosure: a product somebody may not read undisclosed
work in contributes no row and no count to their copy.

| List rule | Reason |
|---|---|
| A row is one issue in one product | The unit an embargo date is kept and moved in |
| A row names the builds and components carrying it, and counts its findings across them | Where the embargo reaches, without opening each build |
| The grouping is made in the query, before paging | A page holds whole embargoes, and the total counts embargoes |
| A product, branch or variant narrows it as every list; a row then names and counts only builds inside the scope | |
| Builds and components are read under the rows' narrowing | A build the reader's access or the scope leaves out is never named |

### Issue disclosure

A person holding undisclosed triage in the product discloses an issue there,
with a reason (REQ-40). It is the embargo's last movement, recorded beside the
extensions and shortenings as `disclosure`.

| Where the embargo stands | Second person |
|---|---|
| Its date has arrived | Never |
| Its date is ahead | Past the movement threshold, measured as a shortening to today is |
| It has no date | Always: a flaw found here has no end anybody agreed to |

| Rule | Reason |
|---|---|
| The unit is one issue in one product | |
| Every occurrence turns public, open and closed | A closed occurrence carries comments and decisions, and REQ-40 opens the whole record |
| Every decision occurrence about the issue in the product turns public | It carries its finding's visibility to answer who may reach it |
| Nothing else is rewritten | Comments, notes, attachments, assignments and an advisory's distribution label read the finding's visibility when asked |
| A decision's row written after the occurrence was read takes the issue's visibility inside the write | A disclosure landing between leaves no private row |
| One way | Nothing makes a disclosed issue undisclosed, and a later extension or shortening finds nothing to move |
| One disclosure waits at a time | A second that would wait is refused; one taking effect at once is not, and the waiting one leaves the queue |
| The end is read from the open occurrences, and from a closed occurrence's date only where nothing is open | The occurrences a movement reads and moves |
| The disclosure date is cleared; the movement keeps where the embargo stood | A public finding carries none |
| The embargo's history is public once disclosed | Before that, only a reader of undisclosed work in the product reads it |
| A disclosure waiting for agreement changes nothing | As every movement |
| Whoever holds an occurrence is told, except the person who disclosed it; a team's queue has nobody to tell | What they write is public from then on |
| A movement waiting when the issue is disclosed leaves the queue | It can no longer be agreed to |

## Disclosure-date movements

A movement needs a reason and, past a threshold that is a setting of thirty days
by default, a second person (REQ-38), the same shape as a deferral.

| Act | What it says |
|---|---|
| **Extension** | The embargo ends later: the fix slipped |
| **Shortening** | The embargo ends sooner: a coordinator or peer vendor publishes on their own date, or the detail leaked |
| **Disclosure** | The embargo ends today and the issue is public (§ Issue disclosure) |
| **Duplicate** | A report from outside, ruled a duplicate of a flaw found here, started the end or brought it earlier. Names the ruling and the report (`design-docs/findings-reports.md` § Judgment) |
| **Duplicate undone** | That ruling was withdrawn and the end put back where the rest of the record leaves it, possibly no end |

The first three a person asks for; the last two a ruling records. A ruled
movement takes no reason of its own and carries the ruling's reasoning, which
may be empty; that reasoning, the ruling and the report are shown only to a
reader of the product's reports.

| Ruled movement | Second person | Toward the threshold |
|---|---|---|
| A duplicate giving a flaw its first date | Never, as recording a report needs nobody | Nothing |
| A duplicate bringing an existing date earlier | Past the threshold, measured as a shortening is | Its distance, once in force |
| A duplicate undone | Never | Nothing |

A duplicate waiting for agreement moves nothing and is agreed to on the same
list; once its ruling is withdrawn it leaves the list.

| Rule | Reason |
|---|---|
| Which act it was is stored, never read off the two dates | An extension for a slipped fix and a shortening for a leak are different events |
| Each act refuses the date the other takes, as the caller's to correct | A date typed the wrong way round would be recorded as a decision |
| Agreement is refused as a conflict when the date has since moved past the request | Agreeing would move the date the other way |
| Every movement a person asks for needs a reason, however short | |
| The threshold is measured against how far the end has already been carried, by distance, counting only movements that took effect | Measured per request, the exception swallows the rule three weeks at a time; a date pulled in and pushed back is unreliable either way |
| A movement needing agreement moves nothing until it has it | |
| The requester may not be the one who agrees | The control the threshold exists for; a shortening publishes sooner than people relying on the date were told |
| Every request is kept, granted or not, oldest first, with act, reason and person | One movement is a judgment and six is a policy |
| Requests waiting appear on the review queue as their own list | What is agreed is no decision about code |
| That list is narrowed in the query; a request of your own is shown, marked, and cannot be agreed to | It is a state of the case, unlike a review queue entry |

## Case collaborators

A collaborator is granted one issue in one product (REQ-43): that issue wherever
it sits in the product and nothing else, not the embargo list or a count of it.
Coordinated disclosure works from case lists: three named people know before
disclosure, not everybody with private access.

| Rule | Reason |
|---|---|
| Approval stays with the pool that held it | Two collaborators must not supply both people a dismissal asks for. Proposing, revising and reaffirming ask a question naming the issue; agreeing asks one that does not |
| The grant is asked wherever a row is read, never only where a list is narrowed | A row listed and refused when opened is a grant with no content |
| Asked once the row is in hand | It needs the issue; the row already exists, the opposite order from a typed name |
| Adding somebody is an access change: a trail row, an immediate notice in the area inside the application, and a collaborator count on the finding | It stops meaning anything at disclosure |
| Adding somebody already on the case changes nothing, with no trail row and no notice | No grant moved |
| Whoever reads the product manages the case's list; a collaborator does not | Knowing who is needed is knowing the case. The grant carries the finding, never who else was brought in |
| The way down to a component asks whether the build may be known to exist, which a case grant answers | Asked as the stronger question, the collaborator cannot reach their own finding |
| Evidence narrowed to one issue, and how far a decision would reach, are asked about that issue | The evidence is publishers' statements about this issue at this component; the reach is the same issue at the same occurrence, held at a version the decision does not already cover. Asked product-wide, a store refusal with no handler arm faults on the row the grant opens |
| Resolving a build's names admits a collaborator; reading what the build holds does not | Every read reached through that lookup puts the product-wide question itself |
| A decision is asked about each of its rows' own issue | A collaborator reads their case's decisions, argues and revises their own, comments, and is refused a decision with a row about another issue. Agreeing asks the product-wide question |
| Whether a collaborator may resolve a product's names is one rule, for every lookup admitting them | A build, an issue's attachments, a product for an issue-scoped route |
| What was filed against a build is withheld: receipts and kept documents | Refused as a stranger is, before any name past the product resolves |
| A gate reads where a resolved build is used, and reports one handed to something carrying no subject where nothing refused first | A read asking only whether one issue is undisclosed would hand a collaborator the whole build's approved statements |

The product-wide question keeps answering no, and that is the whole of the
safety: every list, count, report and export narrows by it, so widening it would
hand over the product's embargo list. The grant is a second question beside the
first at every read about one named issue.

A collaborator gets no findings list. They reach the case through the
notification the grant sends, the one message naming an undisclosed issue on
purpose.

## Limits

| Limit | Detail |
|---|---|
| Peer coordination is not built: shared embargoes across organizations, a coordinator's record, a peer vendor's schedule | They are organizational practice. A coordinator's date here is one person bringing ours in and another agreeing |
