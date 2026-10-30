# Disclosure

Embargo dates, the list of what approaches disclosure, disclosing an issue,
moving a date, collaborators granted one case, and the list of a person's
own cases.

Satisfies REQ-37, REQ-38, REQ-40, REQ-43.

## Contents

- [Disclosure](#disclosure)
- [Disclosure-date movements](#disclosure-date-movements)
- [Case collaborators](#case-collaborators)
- [Own cases](#own-cases)
- [Limits](#limits)

## Disclosure

An undisclosed finding is one somebody intends to disclose. All of this is
built.

| Rule | Reason |
|---|---|
| A private finding reported from outside carries a disclosure date, by default ninety days after the report was received (REQ-37) | The embargo has an end somebody outside can hold the deployment to |
| A flaw found here and a public finding carry none | Nobody outside counts down |
| A report from outside ruled a duplicate of a flaw found here gives it a date counted from that report's arrival, or brings an existing one earlier | `design-docs/findings-reports.md` § Judgment |
| Reaching the date discloses nothing; it escalates | Disclosing an unready fix is a person's decision |
| What approaches disclosure is listed soonest first, and noticed at a lead time somebody sets (REQ-38) | |
| The date arriving tells administrators, and whoever holds the finding where they still read undisclosed work in the product | A condition, standing while the date is past and nothing is decided |

The list is itself a disclosure: a product somebody may not read undisclosed
work in contributes no row and no count to their copy.

| List rule | Reason |
|---|---|
| A row is one issue in one product, naming the builds and components carrying it and counting its findings across them | The unit an embargo date is kept in |
| The grouping is made in the query, before paging | A page holds whole embargoes, and the total counts them |
| A product, branch or variant narrows it; a row then names and counts only builds inside the scope | |
| Builds and components are read under the rows' narrowing | A build left out is never named |

### Issue disclosure

A person holding undisclosed triage in the product discloses an issue there,
with a reason (REQ-40), recorded as the embargo's last movement, `disclosure`.

| Where the embargo stands | Second person |
|---|---|
| Its date has arrived | Never |
| Its date is ahead | Past the movement threshold, measured as a shortening to today is |
| It has no date | Always: a flaw found here has no agreed end |

| Rule | Reason |
|---|---|
| Every occurrence of the issue in the product turns public, open and closed, and every decision occurrence about it | REQ-40 opens the whole record |
| Nothing else is rewritten | Comments, notes, attachments, assignments and an advisory's distribution label read the finding's visibility when asked |
| A decision's row written after the occurrence was read takes the issue's visibility inside the write | No private row survives a disclosure landing between |
| One way: nothing makes a disclosed issue undisclosed, and a later extension or shortening finds nothing to move | |
| One disclosure waits at a time; a second that would wait is refused, and one taking effect at once is not and removes the waiting one | |
| The end is read from the open occurrences, and from a closed occurrence's date only where nothing is open | |
| The disclosure date is cleared; the movement keeps where the embargo stood | |
| The embargo's history is public once disclosed, and before that read only by readers of undisclosed work in the product | |
| A disclosure waiting for agreement changes nothing | |
| Whoever holds an occurrence is told, apart from the person whose act made it public; a team's queue has nobody to tell | What they write is public from then on |
| A movement waiting when the issue is disclosed leaves the queue | |

## Disclosure-date movements

A movement needs a reason and, past a threshold that is a setting of thirty days
by default, a second person (REQ-38).

| Act | What it says |
|---|---|
| **Extension** | The embargo ends later: the fix slipped |
| **Shortening** | The embargo ends sooner: a coordinator or peer vendor publishes on their own date, or the detail leaked |
| **Disclosure** | The embargo ends today and the issue is public (§ Issue disclosure) |
| **Duplicate** | A report from outside, ruled a duplicate of a flaw found here, started the end or brought it earlier, naming the ruling and the report (`design-docs/findings-reports.md` § Judgment) |
| **Duplicate undone** | That ruling was withdrawn and the end put back where the rest of the record leaves it, possibly no end |

A person asks for the first three; a ruling records the last two, with the
ruling's reasoning, possibly empty, as its reason. The reasoning, the ruling and
the report are shown only to a reader of the product's reports.

| Ruled movement | Second person | Toward the threshold |
|---|---|---|
| A duplicate giving a flaw its first date | Never | Nothing |
| A duplicate bringing an existing date earlier | Past the threshold, measured as a shortening is | Its distance, once in force |
| A duplicate undone | Never | Nothing |

| Rule | Reason |
|---|---|
| A duplicate waiting moves nothing and is agreed to on the same list; once its ruling is withdrawn it leaves the list | |
| Which act it was is stored, never read off the two dates | |
| Each act refuses the date the other takes, as the caller's to correct | |
| Agreement is refused as a conflict when the date has since moved past the request | It would move the date the other way |
| Every movement a person asks for needs a reason | |
| The threshold is measured against how far the end has already been carried, by distance, counting only movements that took effect | Measured per request, it is evaded three weeks at a time |
| A movement needing agreement moves nothing until agreed, and the requester may not agree | A shortening publishes sooner than people relying on the date were told |
| Every request is kept, granted or not, oldest first, with act, reason and person | Six movements are a policy |
| Requests waiting are their own list on the review queue, narrowed in the query; a request of your own is shown, marked, and cannot be agreed to | It is a state of the case |

## Case collaborators

A collaborator is granted one issue in one product (REQ-43): that issue wherever
it sits in the product, never the embargo list or a count of it.

| Rule | Reason |
|---|---|
| Approval stays with the pool that held it: proposing, revising and reaffirming ask a question naming the issue, agreeing one that does not | Two collaborators must not supply both people a dismissal asks for |
| The grant is asked wherever a row is read, once the row is in hand | A listed row refused when opened is no grant |
| Adding somebody is a trail row, an immediate notice in the area inside the application, and a collaborator count on the finding; it means nothing after disclosure | |
| Adding somebody already on the case writes nothing | No grant moved |
| Whoever reads the product manages the case's list; a collaborator never sees it | |
| The way down to a component asks whether the build may be known to exist, which a case grant answers | |
| Evidence narrowed to one issue, and how far a decision would reach (the same issue at the same occurrence, at a version the decision does not cover), are asked about that issue | Asked product-wide, an unmapped store refusal faults on the row the grant opens |
| Resolving a build's names admits a collaborator; every read reached through that lookup puts the product-wide question itself | |
| A decision is asked about each of its rows' own issue: a collaborator reads, argues, revises and comments on their case's decisions, and is refused one with a row about another issue | |
| Whether a collaborator may resolve a product's names is one rule for every lookup: a build, an issue's attachments, a product for an issue-scoped route | |
| What was filed against a build, receipts and kept documents, is refused as to a stranger, before any name past the product resolves | |
| A gate reports a resolved build handed to something carrying no subject where nothing refused first | Asking only whether one issue is undisclosed hands over the build's approved statements |

The product-wide question keeps answering no, and that is the whole of the
safety: every list, count, report and export narrows by it. The grant is a
second question beside it at every read about one named issue. A collaborator
gets no findings list of the product, and reaches the case from the
notification the grant sends and from their own cases.

## Own cases

`GET /v1/session/me/cases` lists what the caller was granted one at a time:
each case, one issue in one product, and each code finding recorded as a flaw,
one occurrence in one product (`design-docs/analysis-flaws.md` § Code finding collaborators). The session
says whether the list holds anything, so a screen asks only then.

| Rule | Reason |
|---|---|
| Only the caller's own grants are listed, narrowed in the query to their person | A grant names the case to whoever reads it |
| A withdrawn grant is not listed | It reaches nothing |
| A code finding is listed while its flaw is undisclosed | Disclosure ends that grant |
| A code finding names the build it was last seen in, its rule, its file and its flaw | Its page is reached through a build |
| Newest grant first | |
| The session's flag is the list's own read: true exactly where the list holds a row | A code finding grant outlives its flaw's disclosure, and a flag counting grants opens an empty panel |
| A pipeline key is refused | It holds no grant |

## Limits

| Limit | Detail |
|---|---|
| Peer coordination is not built: shared embargoes across organizations, a coordinator's record, a peer vendor's schedule | A coordinator's date here is a shortening a second person agrees to |
