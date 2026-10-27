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
both, since a precedence rule between the two lets a stale direct grant outlive
a team removal. Membership is read at sign-in and never again, because no
provider reports a departure. Every derived grant is replaced whole at each
sign-in, so a withdrawn group role applies for at most the session lifetime;
ending somebody's sessions closes that at once.

| Rule | Reason |
|---|---|
| Missing or unreadable membership yields no roles | The failure would otherwise be silent and total |
| The mapping is the authorization: somebody first arriving in a mapped group is admitted and recorded then | A provider vouching alone admits nobody |
| The first mapping marks assignments **inactive**, and removing the last makes them active | An inactive row grants nothing and counts as access nowhere |
| Derived grants are cleared on the way out | They cache what a provider said at the last sign-in |
| Work a mode change or a sign-in stops covering goes back by `design-docs/access-assignment.md` § Lost reading | |
| What makes a grant unique includes where it came from | A set-aside assignment and a live derived grant for one role on one product coexist |
| A grant is written with product and role, and read back with whether it is in force and whether it was assigned or derived (REQ-61) | A refused grant must not answer with its own claim to be in force |

### Group mappings

Configuration states which groups grant which roles, and nothing else does
(REQ-41). The API and the Access screen read the mappings and offer no change.

| Rule | Reason |
|---|---|
| Applied at every start, writing only what changed; a start stating what the last one stated records nothing | A standing mapping keeps the moment it was first applied |
| Any mapping means group-bound, and none means direct; a change of mode at startup is recorded against configuration | The mode cannot disagree with the mappings |
| Each mapping added or removed is a trail row with configuration as the actor, and each start logs the whole map | |
| A mapping names its product by name, folded as a product's name is; one named before any pipeline declares it is held, and grants from each member's next sign-in after it exists | |
| A mapping naming no product is a role on every product | § A role across every product |
| Mappings with no source of groups stop the process: a groups claim beside an issuer, an organization beside a GitHub client, or a groups header beside a trusted header | Every arrival would belong to nothing |
| A name holding a separator is percent-encoded in the environment variable; a file writes names as they are | A group may be an email address or a directory name |
| The upgrade from v0.5.0, which v0.8.0 carries and this tree does not, drops the mappings to a role on a product that v0.5.0 held, keeping those to admin and audit; the first start removes any configuration does not state | v0.8.0's upgrade note says to carry them across first, only for a deployment taking roles from groups, since a mapping switches a direct deployment to groups |

### Administration sources

Somebody administers when any one of three sources holds, recorded apart.

| Source | Recorded as | Taken back by |
|---|---|---|
| Named in configuration | The name, written at every startup | Removing the name and restarting |
| Granted here | The administration flag | An administrator here |
| Derived from a group | The flag, marked derived and stamped | Leaving the group, the stamp going stale, or configuration mapping no group |

| Rule | Reason |
|---|---|
| A configured name grants administration at every startup and survives re-derivation from groups | It is the way back in: add yourself, restart. It stays a pre-authorization |
| Configuration writes only its own source, so somebody named and granted here keeps administration when the name goes | |
| A person reads with two answers, granted here and named in configuration; a group's grant reads as granted here | |
| Stating administration here writes only the grant made here. The Access screen's box is that grant, with a line where configuration names them too | |
| A name added or removed is a trail row with configuration as the actor, and a removal is logged at startup by identity | |
| The upgrade from v0.4.0, which v0.6.0 carries and this tree does not, clears the flag for every named administrator no group derived it for | v0.4.0 wrote the name into the flag. One granted here and also named is granted again once the name goes |
| A deployment may not start unable to administer itself: in group-bound mode, a group mapped to administration or somebody named, checked after the mappings are applied and not counting a departed name | Otherwise the database is the only way back |

### Session lifetime ceiling

| Rule | Reason |
|---|---|
| The session lifetime is at most thirty days, refused past that at the settings write and at startup | It bounds how long a role a group withdrew is held; refused, never shortened |
| A group-derived grant grants through a token only while younger than the session lifetime; an administrator-assigned grant is untouched | A token reads its owner's last sign-in, so a group somebody left stops granting through their token |
| Thirty is a judgment, not a commitment | Where the ceiling belongs is the owner's to settle |

## Group name matching

A group name is an identity a provider hands over, so it matches exactly.

| Rule | Reason |
|---|---|
| Two spellings are two mappings | The provider distinguishes them |
| A mapping with the wrong capitals grants nothing, silently | Every start logs each mapping it applies |

## The grant grid

Products down and capabilities across (REQ-42), one checkbox per pair.

| Feature | Reason |
|---|---|
| The top row is the estate grant: checked where held, indeterminate where held on some products and not across the estate | Two different facts |
| A product row covered by the estate grant is drawn and fixed there | A click must never expand the estate grant |
| A role derived from a group is drawn disabled and says so; where roles come from groups, the grid is not offered | It is withdrawn by changing the group |
| A capability granted where nothing is readable is marked as it is granted | |
| The grid is offered before any product is declared | The estate row needs no catalog |

## A role across every product

One standing grant, covering products declared afterwards (REQ-42).

| Rule | Reason |
|---|---|
| One grant, never a copy per product, its reach worked out as the subject is resolved | A copy records the catalog of its moment |
| It narrows by visibility exactly as a per-product grant does, never through the queries' "every product" flag | That flag means no narrowing at all and belongs to the background passes (REQ-43) |
| Withdrawn whole, leaving nothing behind, and handing back work product by product (`design-docs/access-assignment.md` § Lost reading) | |
| Every question about what somebody holds asks this table too: whether they may be handed a finding, may be mentioned, still read their work, or still hold the approving right | Those predicates read the grant tables directly |
| The people list and one person's page state it first, as every product, from one builder | An access review must not miss the broadest grant |
| A query naming one grant table and not the other is refused in every package; files naming one alone are listed with the reason | Missing the second compiles and passes |
| The union is one builder, attached to whatever the caller asks about; the person column comes from the code | A placeholder cannot bind a column |
| Two EXISTS, never a union | A union inside an EXISTS is a syntax error on SQLite |
| Withdrawing one product from it is not offered | "All except one" is a third fact |
| Set aside and restored by a change of role-assignment mode | |
| Derived from a group mapping naming no product, and replaced and cleared like any derived grant | |
| Stored in its own table | Every engine treats NULLs in a unique key as distinct, and the partial index fixing it is engine-specific (REQ-71) |

A personal token narrowed to one product reaches the estate role there and no
more.

## Personal tokens

Anything the interface offers can be automated without a scripted browser or a
borrowed pipeline key.

| Rule | Reason |
|---|---|
| Narrowing removes, never rebuilds: identity, teams and cases stay, and other products' cases and code finding grants go with their roles | "Assigned to me" and taking unowned work keep working |
| A live reference to its owner | A role withdrawn, a group's included, cuts the token at once |
| It may not mint or withdraw another | A token minting through its owner makes every limit one request deep |
| Narrowing intersects: a product its owner cannot read reaches nothing, and narrowing to a product or to named roles drops administration and the audit permission; an unnarrowed token keeps both | Both are held over the whole deployment |
| A token narrows by role as well as product; naming no role carries all, and a role the owner lacks reaches nothing | A case is untouched, so a read-only token still reads the case it was minted for |
| Expiry is required, with a maximum an administrator sets; revoking marks, never deletes | |
| A token's name is stored folded and matched exactly, unique among its owner's tokens in force | Other capitals are refused as taken, and a withdrawn name may be reused |

## Statistics and the audit permission

A numbers-only role over products is not built and not planned. Reading the
deployment's own records is built, as a permission beside administration.

### Numbers-only is not a role

`public-read` on the right products already is that role, since every report
runs as the subject asking (REQ-43). A numbers-only mode would thread a second
visibility through every aggregate and export to hide a product's name, which
REQ-42 already hides.

### The audit permission

| Rule | Reason |
|---|---|
| It reads the settings, who holds what, the role bindings, and the administrative change log | Decisions alone omit the policy they were measured against and who held which role when |
| It reads no product's findings or decisions | It is orthogonal to product visibility |
| Read, never write; an administrator is not asked to hold it too | Writes ask for administration, and an administrator can grant themselves anything |
| The records are shown whole, never narrowed by the products the holder reaches | Granting it accepts that the holder learns which products exist |
| What somebody was told is narrowed to products the asker holds a role on, at the visibility read there | |

### Storage

| Rule | Reason |
|---|---|
| Its own column beside administration, never a role | A role is held against a product |
| Mapped to a group, derived and stamped as administration is | The stamp bounds it for a token whose owner never signs in again |
| No bootstrap arm | Nobody is locked out by lacking it |
| Its mapping names no product, and configuration naming one is refused at startup | |

## Somebody who has left

Nothing detects a departure (REQ-45), so an administrator records one, as a
date on the person.

| Rule | Reason |
|---|---|
| A date, never a flag or a deletion | "When" is what an audit asks, and the record names them as proposer, approver and holder |
| Their roles stay where they are | A return needs no reconstruction; the date stops them |
| Read once, where every way in passes | A session, a personal token and a group-bound sign-in all resolve by identity |
| **Every question of the form "may this person do this" excludes them** | A query reading grants alone would clear them to be handed undisclosed work, as a person or a team member, and to keep their work |
| Nobody who has left is told anything, including what was opened before they left | `design-docs/notifications.md` § Delivery |
| A departed administrator does not satisfy the startup check | |
| Naming somebody in configuration readmits them, and nothing else clears the date | Re-recording a departed colleague must not readmit them |
| Sessions are ended at once | Leaving is immediate, where a role withdrawal waits for a sign-in |
| Everything they held is handed back, with their teams' work no member still here reads | Timing is `design-docs/access-trail.md` § The administration trail |
| Deactivating somebody already gone succeeds, moves no date, and still hands back what they hold | Asking again finishes a hand-back that failed |
| An administrator may not deactivate themselves | |
| Coming back returns no work | Somebody else may hold it |
| Granting what is already held succeeds only where the insert was refused as a duplicate, and each caller decides what "already held" means | Any other insert failure is a failure |

## Absent holders

An administrator is told when somebody has not signed in for a configured
period and still holds assigned work (REQ-45): "X has not signed in for two
weeks and has six items assigned". It is a condition, since noticing absence is
all the software can do.

## Limits

| Limit | Detail |
|---|---|
| A derived grant older than the token window stops granting through a token without any write, and a removed mapping leaves its derived grants until each person's next sign-in | Neither hands work back then. The hand-back questions and the may-be-handed-work questions both read the grant rows, so they agree |
| A refused duplicate grant stands on its own savepoint | A refused statement aborts a PostgreSQL transaction |
