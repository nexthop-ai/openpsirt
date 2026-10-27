# Reports and administration screens

Analytics and the audit log, the settings screen, the System screen, the Access
screens, and a person's own page and record.

Satisfies REQ-01, REQ-15, REQ-28, REQ-60.

## Contents

- [Analytics](#analytics)
- [The audit log](#the-audit-log)
- [Settings](#settings)
- [The System screen](#the-system-screen)
- [The administration screens](#the-administration-screens)
- [A person's own page](#a-persons-own-page)
- [A person, whole](#a-person-whole)
- [Limits](#limits)

## Analytics

Analytics is the catalog of named reports under Across products, beside the audit
log: the audit log is what was judged and who agreed; a report is the shape of
the judging. Reports may span products; a person only sees products they hold a
role on.

| Rule | Reason |
|---|---|
| A report is its own page at `/analytics/<name>` | Printable, linkable, quotable |
| The catalog holds the list and files reachable nowhere else; an unnamed question is asked on the findings list | The filters live there |
| A report about the thing stood on stays on that screen and is listed in the catalog; one spanning things lives only there. Release comparison keeps its address and gains an entry arriving with the product chosen | |
| An entry that cannot answer at the selection is listed with a tag beside its name saying it needs a product or a build; the name stays drawn as a name, and pressing it opens the scope picker | A missing report reads as nonexistent |
| Grouped by question: program, controls, coverage, releases, records; an entry leading to an audit log filter sits with its question | |
| A rail screen answering a named question is listed under "Also on screens" by its rail name | |
| One address is one entry; release comparison carries the known issues a build ships with | |
| An unknown name returns to the catalog | A stale link seeks a report |
| Every report states what it was asked of and when taken, and prints with the audit log's stylesheet: the shell, rail, controls, overlays, scope panel, menus and a record's previous and next drop out; a row does not break; a non-printing control's value is in the printed header | |
| A figure opens the list it was counted with: links from home and product figures turn the list's three silent-address narrowings off, and a sheet's figures carry its window and product | |
| A list report exports CSV and JSON; a figures report prints, every figure linking its list | An aggregate has no stream; the list is the traceable form |
| A figure is the response's, never recounted from the page beneath it; each list says its total | |
| A page past a list's end says so and keeps its footer | The register holds its position when the build under it changes, and Previous must be reachable |

## The audit log

| Rule | Reason |
|---|---|
| One card per decision: issue, outcome, state in one word, what it is about or how many components, occurrences covered, states counted where they differ. The issue opens the decision page; "Findings there now" opens the findings list narrowed to the decision and states (`design-docs/analytics.md` § Dismissals and last uploads) | |
| Report rulings sit beside the decisions over its products and period, taking none of their filters, printed without controls | A ruling is accountable and about a report (REQ-28) |
| The change history sits below over its period, narrowed to one kind (roles, keys and tokens, settings), the kind in the address and the file | The question an access review asks |

## Settings

| Rule | Reason |
|---|---|
| One section at a time in tabs, the tab in the address: Deadlines, Our products, Triage, Disclosure, Scanning, Sign-in, Limits, Outbound, then Webhooks and Suppliers for administrators | |
| Values are formatted for the reader (REQ-60): a duration and a size are composed of a count and a unit | The reader is an operator nobody here meets (REQ-01) |
| A tab says how many of its settings hold a stored value, a value set back to its default included; with none, how many it holds | A value on an unopened tab is invisible |
| The sections are the server's list, each named by the screen; an unnamed one does not compile | |
| Every setting is one row: title and one-line summary beside the control, the rest under Details | One text width |
| Title, section, summary and detail are served with the setting; section names and tab order are the screen's | A second list keyed on the name misses additions |
| What a setting does is in words under its name, never only on hover or on the control | A password manager reads text through a control |
| A setting's control has a generated id, never its key; `name` is a constant | A key like `signin.claim-window` reads as a sign-in field |
| Save appears on a row once its value changes, judged against the stored value written the composer's way (2160h0m0s against 2160h) | Saving an untouched default pins it |
| A composed count is a whole number of one or more; 1.5 days shows the hint and no Save | Whole units are stored |
| A date is written on Save, a tag's release date and an end of support included | A date box fires per segment |
| An inherited end of support opens empty, and stating the same date is a change | A stated date stays when the product's moves (REQ-15) |
| A one-of-a-few setting is a select | A free box invites "yes" and "1" |
| The server takes a word regardless of capitals and surrounding space and stores its own spelling: `High` sets a minimum severity | |
| A setting nobody set is composed like a set one; an empty composer opens on days | The plain box cannot ask whether 90 is hours, days or weeks, and an embargo is said in days |
| Patch branch lookups show on Outbound, read-only, to administrators; a failed read says so, never Off | Configured by whoever deployed it; the progress endpoint is administrator-only |
| Webhooks are configured here by administrators, the whole panel hidden from others | The endpoint refuses others |
| A webhook's address and signing secret are masked, and every field tells a password manager it is not a credential | A chat address carries its token; form history leaks |
| Suppliers are configured here by administrators, taking a product before an address | A supplier feeding two products is two rows |
| A publisher's document is uploaded on the suppliers panel: an advisory adds, a statement set replaces, each to the endpoint a script uses; the endpoint refusing the other kind names the right one | |
| A supplier never reached reads differently from one that failed; what stopped the last attempt is on hover | |

## The System screen

What this deployment is doing: the vulnerability data, waiting background jobs,
failed jobs, webhook delivery, and what upstream could not answer, on one screen,
because each fails by looking quiet.

| Rule | Reason |
|---|---|
| The vulnerability data comes first, then the engine, then the optional extra, then what goes out | Every answer is measured against it |
| The data version is shown and never ordered; having none reads as a deployment pointed at nothing yet | A scanner's version is opaque |
| The data-stopped condition links here | The link lands where the fact is checked |
| What upstream could not answer says why of each: held back because the name is ours, sent and unheard of, or an identifier nothing turns into a request | Held-back rows show the default's cost; unheard-of rows are what an operator adds to the held-back names |
| The names matched against are drawn beside the list, whatever the table holds | A hidden derived default gets the feature switched off |
| The table is narrowed to readable products, and the panel says so | A package identifier says what a build is made of |
| Waiting work is said per kind against the per-kind limit, both numbers beside the count, never a bar | At the limit is a state |
| Work held by a worker that stopped reporting counts as waiting | |
| A failed job is shown in the queue's own words | Its subject may be gone |
| An operator's screen, not an auditor's | A worker's report may quote a component from an unreadable SBOM |
| Webhook delivery is here, configuration under Settings; the panel is named for delivery | It fails silently; an empty "failing" panel is good news |
| A webhook shows name, kind and host, never its address; the host is no link | The path is the credential for two services |
| A destination's kinds use the notification area's words, the wildcard "everything", from a closed list | |
| A resolved issue is counted at the severity it held while open | |
| Patch branch lookups show in the pass's order: Now, Next, Failed, Done folded. Now carries the step and a bar of commits looked up against due, re-asked every ten seconds during a visit; Next is numbered; a failure shows its first line, the whole on hover, with its retry time; every repository is reachable a page at a time (`design-docs/findings-patch-branches.md` § Display) | A silent host leaves labels missing |

## The administration screens

Access: who may sign in, what they hold, and the credentials carrying it. A
pipeline key belongs to no person and a personal token is listed against its
person.

| Rule | Reason |
|---|---|
| Every field that ages is shown: made, expires, last used | "Never used, two years old" must differ from "made this morning" |
| A pipeline key says it never expires | A blank reads unset |
| Who has left is on the list | |
| The list narrows to who holds what; a grant out of force does not match | |
| A person's name and address are recorded here | Mail reaches nobody without one |
| An address stated empty clears it; left out leaves it | Coming off mail is not leaving |
| A control an auditor may not use is disabled and says why; only a signed-in administrator mints or withdraws a credential | A credential cannot create another |
| A role chip's withdraw mark is for an administrator only, where roles are assigned here | Manage is disabled for others with the reason |
| The teams screen offers controls to an administrator only; others by address see names, no control, and a dash for members | |
| The credentials panel is drawn for an administrator only | Its reads are administrator-only and its empty state would lie |
| A key's branch and variant are offered from what the product holds, the server refusing; choosing a product clears them | |
| The two deployment-wide holdings are checkboxes beside the grid, each with what it grants | One is a reader who changes nothing |
| A pipeline key is created where keys are listed | |
| A token's product narrowing is asked at creation; the list shows each token's reach | |
| A withdrawn credential stays, dimmed, the button replaced by the word | What used it stays answerable |

## A person's own page

Reached from the person's own menu.

| Rule | Reason |
|---|---|
| It mints personal tokens and turns on the daily digest, which is off until asked for | |
| A switch that changes nothing is not offered: without a recorded address the card says so; unassigned lines without the digest are not offered | |
| A token's secret is shown once, saying so while shown | A digest is stored |
| It shows what they may do, never roles | |
| The version is in the footer, read from the deployment | |

## A person, whole

`/access/:identity`, reached by the person's name on Access. An administrator's
screen: what somebody was told is asked after a leak.

| Section | Answers |
|---|---|
| Grants in force | The roles in force, and whether one grants nothing |
| Their part in the record | Decisions argued, agreements standing, agreements taken back, over every product; sent to an administrator, absent for an auditor, and drawn only where sent |
| Roles granted and withdrawn | Every change, newest first, with who made it. Absent before means nobody set it; absent after means withdrawn |
| Notifications sent | Everything sent, acknowledged and cleared included |

| Rule | Reason |
|---|---|
| An agreement taken back is counted apart | |
| What they were told is not narrowed by what they may read now | A line about undisclosed work sent under a role is the point |
| A name nobody holds and an unreachable one answer alike | |
| Each list is a page with its total | Both only grow |
| Leaving is recorded at the foot, saying first what it does: refused at every way in, sessions ended, work handed back, nothing deleted, no role withdrawn. Once recorded it is said at the top, with bringing them back. Both acts are an administrator's; an auditor sees them disabled with the reason on hover | |

## Limits

| Limit | Detail |
|---|---|
| A webhook's signing secret is never shown | Changing it is recording the destination again |
