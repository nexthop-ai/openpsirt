# Grants and accounts

How roles are granted, by an administrator or from provider groups, the
estate-wide role, personal tokens, the audit permission, and an account that
ends.

Satisfies REQ-41, REQ-42, REQ-43, REQ-45, REQ-61, REQ-71.

## Contents

- [Role assignment modes](#role-assignment-modes)
- [Group name matching](#group-name-matching)
- [The grant grid](#the-grant-grid)
- [A role across every product](#a-role-across-every-product)
- [Personal tokens](#personal-tokens)
- [Statistics and the audit permission](#statistics-and-the-audit-permission)
- [Somebody who has left](#somebody-who-has-left)
- [Absent holders](#absent-holders)
- [Limits](#limits)

## Role assignment modes

Either an administrator assigns roles or provider groups derive them, never
both; a hybrid needs a precedence rule, and a forgotten one lets a stale direct
grant outlive somebody's removal from a team.

Membership is read at sign-in and never again: no provider reports a departure,
and polling a rate-limited API is worse than the drift it closes. Every derived
grant is replaced whole at each sign-in, so a group somebody left takes its
roles with it, and the window a withdrawn role still applies in is the session
lifetime. Ending somebody's sessions closes it at once.

| Rule | Reason |
|---|---|
| Missing or unreadable membership yields no roles, never unrestricted | That failure would be silent and total |
| The mapping is the authorization | Somebody first arriving in a mapped group is admitted and recorded then; the operator stated the mapping in advance. A provider vouching alone admits nobody |
| Switching modes is reversible: the first mapping marks assignments **inactive** and removing the last makes them active | An inactive row grants nothing and is never counted as access, in a query, a report or a review |
| Derived grants are cleared on the way out | They are a cache of what a provider said at the last sign-in |
| A sign-in that takes reading away, and a switch out of group-bound mode, hand back the work they covered | `design-docs/access-assignment.md` § Lost reading |
| A switch into group-bound mode hands back nothing; each person's first sign-in after it hands back what their groups do not cover | `design-docs/access-assignment.md` § Lost reading |
| What makes a grant unique includes where it came from | A set-aside assignment and a live derived grant for one role on one product coexist |
| Granting a role and reading one are different shapes (REQ-61) | A grant is written with product and role, and read back with whether it is in force and whether it was assigned or derived. A refused grant would otherwise answer with its own claim that the role is in force |

### Group mappings

Configuration states which groups grant which roles, and nothing else does
(REQ-41). Nothing running can widen it; the API and the Access screen read it
and offer no change.

| Rule | Reason |
|---|---|
| Applied at every start, writing only what changed | A standing mapping keeps the moment it was first applied |
| Any mapping means group-bound, and none means direct | The mode is a consequence of the mappings. A change of mode at startup is the reversible switch, recorded against configuration |
| Each mapping added or removed is a trail row with configuration as the actor, and each start logs the whole map | An access review reads the trail; an operator who just edited configuration reads the log |
| A mapping names its product by name, folded as a product's name is | A product named before any pipeline declares it is held, and grants from each member's next sign-in after it exists |
| A mapping naming no product is a role on every product | § A role across every product, so a product declared later is covered without a sign-in |
| Mappings with no source of groups stop the process | Every arrival would belong to nothing and the deployment would admit nobody. A source is a groups claim beside an issuer, an organization beside a GitHub client, or a groups header beside a trusted header |
| A name holding a separator is percent-encoded in the environment variable; a file writes each name as it is | A provider may report a group as an email address or a directory name |
| The upgrade from v0.5.0, which v0.8.0 carries and this tree does not, drops the mappings to a role on a product that v0.5.0 held | They were made through the API. Mappings to admin and audit are kept, and the first start removes any configuration does not state. v0.8.0's upgrade note says to carry them across first, only for a deployment taking roles from groups, since a mapping switches a direct deployment to groups |

### Administration sources

Somebody administers when any one of three sources holds, recorded apart.

| Source | Recorded as | Taken back by |
|---|---|---|
| Named in configuration | The name, written at every startup | Removing the name and restarting |
| Granted here | The administration flag | An administrator here |
| Derived from a group | The flag, marked derived and stamped | Leaving the group, the stamp going stale, or configuration mapping no group |

| Rule | Reason |
|---|---|
| A name in configuration grants administration at every startup and survives re-derivation from groups | It is the way back in: add yourself, restart. It stays a pre-authorization, never a bypass |
| Configuration writes only its own source | Removing a name takes back what the name gave and nothing else |
| Somebody named and granted here keeps administration when the name goes | |
| A person reads with two answers: granted here, and named in configuration; a group's grant reads as granted here | Deciding who stays an administrator once a name goes needs both |
| Stating administration here writes only the grant made here | A named person reads as not granted until somebody grants it. The Access screen's box is that grant, with a line where configuration names them too |
| A name added or removed is a trail row with configuration as the actor, and a removal is logged at startup by identity | |
| The upgrade from v0.4.0, which v0.6.0 carries and this tree does not, clears the flag for every named administrator no group derived it for | v0.4.0 wrote the name into the flag. Nobody loses administration at the upgrade; one granted here and also named is granted again once the name goes |
| A deployment may not start unable to administer itself: in group-bound mode, a group mapped to administration or somebody named | The only route back from that is editing the database |
| That check runs at startup, after the mappings are applied | Only configuration changes either input |
| A departed administrator named in configuration is not counted | They are refused at sign-in |

### Session lifetime ceiling

| Rule | Reason |
|---|---|
| The session lifetime is at most thirty days, refused past that at the settings write and at startup | It is the window a role a group withdrew can still be held. Behind single sign-on signing in again is one click. Refused, never shortened, so the asker hears the limit |
| A group-derived grant grants through a token only while younger than the session lifetime | A token never signs in and reads its owner's last sign-in, so a group somebody left stops granting through their token though they never sign in. An administrator-assigned grant is untouched |
| Thirty is a judgment, not a commitment | Where the ceiling belongs is the owner's to settle; ninety is defensible |

## Group name matching

A group name is an identity a provider hands over, so it matches exactly, with
its capitals.

| Rule | Reason |
|---|---|
| Two spellings are two mappings | The provider distinguishes them |
| A mapping whose capitals are wrong grants nothing, silently | The refusal met is the generic one. Every start logs each mapping it applies, where the operator who wrote it looks |

## The grant grid

Products down and capabilities across (REQ-42), one checkbox per pair, so "who
approves on this product" and "what does this person hold" are each one line.

| Feature | Reason |
|---|---|
| The row across the top is the estate grant: checked where held, indeterminate where the role is held on some products and not across the estate | Two different facts |
| A product row covered by the estate grant is drawn and cannot be changed there | It is withdrawn where granted; a click must never expand the estate grant into per-product rows |
| A role derived from a group is drawn disabled and says so | It is withdrawn by changing the group. Where roles come from groups, the grid is not offered |
| A capability granted where nothing is readable is marked as it is granted | Approver and assigner are bounded by what their holder reads |
| The grid is offered before any product is declared | The estate row is meaningful with an empty catalog |

## A role across every product

One standing grant, covering products declared afterwards (REQ-42).

| Rule | Reason |
|---|---|
| One grant, never a copy per product | An expanding grant records the catalog of its moment, and a later product goes uncovered |
| What it covers is worked out when somebody asks, reading the catalog as the subject is resolved | |
| It narrows by visibility exactly as a per-product grant does | The queries' "every product" flag means no narrowing at all, visibility included, and belongs to the deployment's background passes. An estate grant setting it would hand a disclosed reader every undisclosed finding (REQ-43) |
| Withdrawn whole, leaving nothing behind | Anything still wanted on one product is granted there deliberately |
| Withdrawing it hands back the work it let them read, product by product | `design-docs/access-assignment.md` § Lost reading |
| Every question about what somebody holds asks this table too | Whether somebody may be handed a finding, who may be mentioned, whether they still read their work, and whether an approver still holds the right they used each read the grant tables directly |
| The people list and one person's page state it first, as every product, from one builder | An access review reads either, and must not miss the broadest grant |
| A query naming one grant table and not the other is refused, in every package; files naming one alone are listed individually with the reason | Missing the second table answers no for a holder, compiles and passes |
| The union is one builder; what it attaches to is the caller's | One person, a team's members, or everybody mentionable differ; the halves do not. The person column comes from the code, since a placeholder cannot bind one |
| Two EXISTS, never a union | A union inside an EXISTS is a syntax error on SQLite |
| Withdrawing one product from it is not offered | "All except one" is a third fact with its own storage and meaning |
| Set aside and restored by a change of role-assignment mode | It is an assignment |
| Derived from a group mapping naming no product | Replaced at each sign-in and cleared when roles stop coming from groups |
| Stored in its own table, never as a grant with no product | Every engine treats NULLs in a unique key as distinct, and the partial index fixing it is engine-specific (REQ-71) |

A personal token narrowed to one product intersects with it as with anything
else: the estate role is among what its owner holds there.

## Personal tokens

Anything the interface does not offer can still be automated, without a
scripted browser or a borrowed pipeline key.

| Rule | Reason |
|---|---|
| Narrowing removes, never rebuilds | Who somebody is, their teams and their cases are not per-product facts, so "assigned to me" and taking unowned work still work. Cases and code finding grants in other products go, as the roles there do |
| A live reference to its owner, never a snapshot | A role withdrawn, a group's included, cuts the token at once |
| It may not mint or withdraw another | Minting resolves through the owner, so every limit would be one request deep |
| Narrowing intersects | A token pinned to a product its owner cannot read reaches nothing. Narrowing to a product or to named roles drops administration and the audit permission, both held over the whole deployment; an unnarrowed token keeps both |
| A token narrows by what it may do as well as where; naming no role carries all of them | A read-only credential needs no owner holding nothing else. A named role the owner lacks reaches nothing. A case is untouched, so a read-only token still reads the case it was minted for |
| Expiry is required, with a maximum an administrator sets | A credential that never runs out is never revoked. Revoking marks, never deletes |
| A token's name is stored folded and matched exactly, unique among its owner's tokens in force | Other capitals are refused as taken; a withdrawn token's name may be reused, and withdrawing by name reaches the token in force |

## Statistics and the audit permission

A numbers-only role over products is not built and not planned. Reading the
deployment's own records is built, as a permission beside administration.

### Numbers-only is not a role

`public-read` on the right products already is that role: every report runs as
the subject asking (REQ-43), so disclosed reading on two products gives the
numbers for two. A numbers-only mode would thread a second visibility through
every aggregate, linked list and export to protect a product's name, which
REQ-42 already hides, and could disagree with it.

### The audit permission

Reading every decision is not an audit without the deadline policy, who held
which role when, and whether either changed; administration opens those and is
not read-only.

| Rule | Reason |
|---|---|
| It reads the settings, who holds what, the role bindings, and the administrative change log | Records about the deployment, never about anything scanned |
| It reads no product's findings or decisions | It is orthogonal to product visibility |
| Read, never write | Every write over those records asks for administration. An administrator is not asked to hold it too, since they can grant themselves anything |
| The records are shown whole, never narrowed by the products the holder reaches | An audit record with unmarked holes is worse than none. Holding it means knowing which products exist, which granting it accepts |
| What somebody was told is narrowed to products the asker holds a role on, at the visibility read there | The rule administration follows; an auditor reaching no product is answered with nothing |

### Storage

| Rule | Reason |
|---|---|
| Its own column beside administration, never a role | A role is held against a product; spread over every product it grants nothing with no products and appears in every grant list |
| Mapped to a group as administration is | In group-bound mode an unmapped capability is one nobody can hold |
| Derived and stamped like administration | The stamp bounds it for a token whose owner never signs in again |
| No bootstrap arm | Nobody is locked out by holding no audit permission |
| Its mapping names no product, and configuration naming one is refused at startup | It is held over the deployment |

## Somebody who has left

Nothing detects a departure (REQ-45), so an administrator records one, as a
date on the person.

| Rule | Reason |
|---|---|
| A date, never a flag | "When" is what an audit asks |
| Never a deletion | The record names them as proposer and approver, and assignments point at them |
| Their roles stay where they are | They are part of why the record reads as it does, and a return needs no reconstruction. The date is what stops them |
| Read once, where every way in passes | A session, a personal token and a group-bound sign-in all resolve by identity |
| **Every question of the form "may this person do this" excludes them** | A query reading only grants would clear them: to be handed an undisclosed finding, as a person or a team member, and to keep their work |
| Nobody who has left is told anything | Every audience starts from the people still here, a recorded event for them records nothing, and mail, digests and direct chat messages skip them, including what was opened before they left (`design-docs/notifications.md` § Delivery) |
| A departed administrator does not satisfy the startup check | Otherwise a deployment starts with nobody able to administer it |
| Naming somebody in configuration readmits them, and nothing else clears the date | An administrator re-recording a departed colleague must not silently readmit them |
| Sessions are ended at once | Roles are re-read at sign-in; this makes leaving immediate |
| Everything they held is handed back, with their teams' work no member still here reads, after the deactivation commits | `design-docs/access-assignment.md` § Lost reading |
| Deactivating somebody already gone succeeds, moves no date, and still hands back what they hold | Two clicks are ordinary, and asking again finishes a hand-back that failed |
| An administrator may not deactivate themselves | Nobody may be left to undo it |
| Coming back returns no work | Somebody else may have picked it up |
| Granting what is already held succeeds only where the insert was refused as a duplicate, and each caller decides what "already held" means | A grant asks whether it is in force. Any other insert failure, a concurrent insert rolled back included, is a failure |

## Absent holders

An administrator is told when somebody has not signed in for a configured
period and still holds assigned work (REQ-45): "X has not signed in for two
weeks and has six items assigned". It is a condition, since what is wrong is
that nothing happened, and noticing absence is all the software can do.

## Limits

| Limit | Detail |
|---|---|
| A derived grant older than the token window stops granting through a token without any write, and a removed mapping leaves its derived grants until each person's next sign-in | Neither hands work back when it happens. Every hand-back question, and every question of whether somebody may be handed work, reads the grant rows, which stand until a sign-in rewrites them, so the two agree |
| Granting a role somebody already holds succeeds | A script needs no check first. The refused insert stands on its own savepoint, because a refused statement aborts a PostgreSQL transaction |
