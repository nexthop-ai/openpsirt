# Findings list filters

The findings list's filters: how they are drawn, carried in the address and
sent, the two filters about the release, the filters over a group, and saved
filters with the decisions they prepare.

Satisfies REQ-15, REQ-27, REQ-34, REQ-60.

## Contents

- [Filters](#filters)
- [Release filters](#release-filters)
- [Multi-value filters](#multi-value-filters)
- [Saved filters](#saved-filters)
- [Limits](#limits)

## Filters

Every filter the server offers is on the screen (REQ-60); a filter only an
address can set is a narrowing nobody uses.

| Rule | Reason |
|---|---|
| A filter is labeled with the question it asks, grouped: severity and risk, what upstream did, triage progress, where the row came from, the component, time. A value says what it is | |
| One chip per filter in force above the list, naming filter and value, removable by clicking, whether or not the panel is open | A count alone hides what narrows |
| The selection is a chip too, first, one per level, product first | It rides on the path, and a scoped list otherwise looks like the cross-product list with fewer rows |
| Removing a selection chip widens by a level and carries the filters, but not the branch and variant, which the new address puts back | |
| A subtree goes with the build it was walked in; widening out of the build drops it, and a selection that is not one build does not send it | The server refuses it over anything else |
| What qualifies a subtree's root (version, ecosystem, namespace) goes with the root: a new root, a cleared root and a removed chip drop them | |
| A date the server does not take as YYYY-MM-DD, or that rolls over such as February 30, is left off the request | The server refuses the whole list over it |
| A cleared filter drops its key and never writes its default | The list's three silent-address defaults apply only where the key is absent |
| The count of filters in force is read from the address | |
| Filtering is the server's | Filtering in the browser narrows one page |
| The bar holds decision state, severity, holder and due, each one button naming itself and its value, with New today beside them. Everything else is behind More filters, whose control says how many of its filters are on. A filter is on the bar or in the panel, never both | The daily questions |
| New today is a single value of the panel's First seen after, pressed only while that date is a day back; it does not clear another date | |
| A bar filter is one control: name, value and menu. A value in force tints it. A multi-answer filter (decision state, holder) ticks and stays open; a step on a scale (severity, due) picks one and closes | A name cannot wrap away from its value |
| A control holding several answers says the first and how many more: "Undecided +1". The bar's menus and the panel's tick lists keep the offered order, open on an arrow key, move with arrows, Home and End, and close on Escape back to the control | |
| The panel is shut until opened, whatever the address narrows by | It is most of a screen, and the chips already say it |
| Exploited and fix available are two flags; a kept filter in the former single word is rewritten by the upgrade, and an address elsewhere opens without that narrowing | "Exploited, and a fix exists" is a batch somebody assembles |
| The decision state sits beside the severity floor on the bar | The list is ordered by urgency and the fix is a column; what is unanswered is reached for first |

| Filter | Definition |
|---|---|
| Package kind | Read from the package identifier. Offered are the kinds present in the scope on screen, as the server reports them under the list's visibility, each with its row count, read when the panel opens and narrowed by no other filter. A kind chosen and absent is offered without a count, so it can be unticked. A kind whose word is not the reader's has a display name (`cargo` is Rust); others are their own word |
| What holds it | The consumer an occurrence records; what the build holds directly is its own choice |
| How far it has been decided | Undecided: no occurrence decided. Waiting: a decision standing proposed. Agreed: every occurrence answered. Lapsed: an occurrence's decision stopped applying with nothing replacing it. No partly answered value: the row says "12 occurrences · 3 answered" |

## Release filters

Two filters choose between releases, and make the list a work list.

| Filter | Default | Widens to |
|---|---|---|
| Release kind | Branches | Tags, or both; no work lands in a tag |
| Support | In support | Past end-of-life, or both (REQ-15) |

| Rule | Reason |
|---|---|
| They are separable | A tag can be in support and a branch past its date |
| Both defaults are written into the address, so each is a chip | A silent default makes the count less than whole |
| Removing the chip widens to both; deleting the parameter brings the default back | |
| Applied where builds are resolved, never as a row condition; the list spanning products resolves no builds, so there it is a condition | The page is read from an index leading with the build |
| Not applied where the selection names one whole build | The request named the release; applied, a tag of twenty-five findings read "0 of 0" |
| The end-of-life rule is the catalog's own, inheriting the product's date where a release states none | Two copies disagree |

## Multi-value filters

A filter whose values are not exclusive takes several. Decision state, decision
outcome, what upstream did and package kind take several words; who holds it,
what a VEX document says and what the build's claims say take a set; among typed
boxes, the component, label, VEX publisher and weakness are chip fields.

| Rule | Reason |
|---|---|
| Several answers OR | "Mine or nobody's" |
| Severity stays a floor | |
| Ticks sit behind a control saying what is ticked, and the chips name each | A closed control reading "Any" over three ticks looks unnarrowed |
| Carried as the parameter repeated, marked exploded on both sides; an HTTP test asks for two states and counts rows | A server reading the first word narrows less, silently |
| A word the server does not take is left off the request, its chip still naming it; each parameter's words are checked against the generated client both ways | A stale saved word refuses the whole list |
| A comma ends a word in a typed filter | A pasted list is several words |

| Rule over a group | Reason |
|---|---|
| The age is the oldest occurrence's | A month-old group with one new occurrence is a month old |
| What upstream did holds at every occurrence | Otherwise the group reports smaller than it is |
| A group whose occurrences disagree has its own word, Mixed | One fixed variant and one not matches no single state; it is a half-landed upgrade |
| Filtering by outcome asks what stands, never what was proposed | A proposal would count one person's unreviewed decision |
| "Assigned to me" means mine or a team I am on (REQ-34), here as everywhere; a group held by different parties is nobody's | |
| The by-component view and the planned upgrades ask every filter at the list's grain, one issue at one fold: the list's groups are chosen first and joined in, and only row conditions are asked of the component's rows. A filter with no group condition reads the covering index | Asked of a whole component, "exploited" and "has a fix" count differently from the list |

## Saved filters

Personal; nothing is shared.

| Rule | Reason |
|---|---|
| A saved filter keeps what the list is narrowed by, never where; one list per person, offered on every findings list, across products included | A PSIRT working several products keeps a filter once |
| Left out as scope: the product, branch and variant; a subtree of one build with its version, ecosystem and namespace; what differs between a selection's builds; what spreads over one branch's variants; the run that opened it; and the grouping | The list across products groups by issue alone |
| Picking one applies it within the scope on screen | Across products from home, within one product where one is picked |
| Server and interface drop the same scope words, byte for byte, from one test-data list each side's test compares with | A word dropped on one side fails on the other |
| The open filter is named in the address as `rule`, the word a finding reads it from; the open marker, Forget and the prepared decision follow the name | Two filters can keep one query |
| Changing a filter on screen drops the name; paging, page size, branch and variant do not | |
| An address without a name is matched by its query: the first kept filter by name whose query is the address's reads open | Typed and bookmarked addresses |
| A filter keeping nothing is never open by its query, so it prepares nothing until picked by name | |
| Saving with scope in the address (one build, or any scope word but the grouping) reads "Saved. Applies to whatever branch and variant you're viewing."; otherwise "Saved." | |
| A name is one per person, matched regardless of capitals, across products | |
| What is kept is the list's own query string; a parameter the list no longer offers stops narrowing | A column per filter needs a migration per filter and is a second definition |
| A renamed parameter is rewritten in kept queries by that release's migration; the list reads current words only. A bookmarked or sent address is not rewritten and opens without it | |
| Saving over a name replaces it | |
| Two saves of one new name at once keep one: the later addition, refused by the unique index, is taken as a lost race and replaces | |
| Personal is enforced at the query; another person's name answers as no name | |
| Opening one replaces the filters on screen, keeps the scope and grouping, and drops the page | |
| The list is bounded by the per-person limit and says how many are kept in all; under a lowered limit, saving is refused until under it | |

A saved filter can prepare a decision and proposes nothing (REQ-27). Where it
carries an outcome and words, picking it fills the decision form and says so
above the list. Submitting is a person's act, carrying their name and naming the
filter. A decision hiding risk still waits for a second person. It applies in
every product.

| Rule | Reason |
|---|---|
| A deferral it prepares is kept as a number of days, turned into a date when the form opens | A rule saved in March means a quarter, not "until 3 March" |
| The filter the address names prepares the decision; narrowing further drops the name, and returning to the list finds it | A rule outliving its narrowing fills a form on a finding it never drew |
| What it prepares travels with every row and the walk between findings; the finding's address names the filter, never its contents | Decided in one place, never stale against a name saved over |
| Emptying the form on one finding drops it there alone | |
| A sent link carries a name: it prepares what the opener keeps under it, or nothing | A filter is personal |

| Refusal | Reason |
|---|---|
| A rule preparing a deferral without a length | It would prepare a form that cannot be submitted |
| A length beside any other outcome, refused and never dropped | A decision refuses a date beside a non-deferral alike |
| A deferral kept as a date fills nothing and says so | |

## Limits

| Limit | Detail |
|---|---|
| A saved filter is never shared | No ownership or permissions to argue over; the shared half of routing work is assignment rules (REQ-34) |
