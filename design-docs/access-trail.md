# Administration trail

The record of every administrative change, which writes leave a row, and the
secrets nothing records or logs.

Satisfies REQ-22, REQ-68.

## Contents

- [The administration trail](#the-administration-trail)
- [Secrets and logs](#secrets-and-logs)
- [Limits](#limits)

## The administration trail

An administrative change is recorded with who, what, before, after and when
(REQ-22): settings, role grants and withdrawals, assignment rules, end-of-life
dates, the minimum severity, credentials, accounts, teams, who is on a case, and
the names an issue answers to. It is read beside the triage record. Changing the
deadline policy, raising the minimum severity and setting an end-of-life date
each rewrite what the tool reports, which makes the record of them evidence.

| Rule | Reason |
|---|---|
| Both values are kept, and absent is not empty | A value nobody had set is an absent before |
| What a setting held is answered by the write that replaced it | A separate earlier read lets two administrators moving one setting both record the original, and the trail then holds a prior value nothing held. A read-back after the write closes the wrong window |
| Recorded in the request, where the actor is known | A setting write knows no actor. The walk catches a route that forgets (§ Recorded writes) |
| Every row names its actor: a person, configuration, a merge, or an upgrade | None but a person is a person, and a person's row names the person |
| Configuration is the startup configuration | It names and stops naming the administrators in `OPENPSIRT_BOOTSTRAP_ADMINS`, adds and removes the group mappings in `OPENPSIRT_GROUP_ROLES`, and sets where roles come from to match, and records nothing else. A start naming the same people as the last records nothing |
| A merge is a scan merging two issues its report named together | It records only a rating claim it withdrew or an incident it cleared because another stood in its place in the same product (`design-docs/findings-issues.md` § Merged issues) |
| An upgrade is the one to v0.5.0 | It recorded only a key withdrawn because another holds its folded name, or a token withdrawn because another of its owner's does. No migration this tree carries writes one |
| The record is written in the transaction that makes the change | A change that succeeded while its record failed answers an auditor wrongly |
| A failure to record fails the change, and the refusal says the change was not made | A retry then changes nothing twice |
| What follows the change is outside it: deactivation ends sessions inside, and hands work back afterwards | The sessions are what deactivation means; the hand-back is bounded by what they held, never by the request |
| A grant and its withdrawal are recorded alike, minting a credential included | A trail of removals alone cannot answer an access review |
| A revocation that matched nothing leaves no row and is refused as not found | Read as a withdrawal, it hands back the person's work for a role they never had. A grant, an estate grant, a removed group mapping, a team membership, a place on a case, a personal token, a pipeline key and a pinned identifier each read what they matched; revoking one already revoked, or unbinding somebody with nothing pinned, is not found |
| Never the secret, and never the whole address: what a credential may send, and a destination's host | A permanent record is the wrong place for a bearer token, and for Slack and Teams the address is the credential |
| **What a change is about is composed from the names it resolved to** | A person's history is read by stored identity, a path segment carries no length, and an issue is looked up keeping its first 191 runes, so the typed form is unbounded and can miss the history |
| The recorder bounds what it writes to the column | A backstop under every caller, since with the record inside the act an overlong value would refuse the act |
| **It is read over a period, and leaves as a file**; asked for no period, it answers about everything | An access review asks what changed in the stretch a certificate covers |
| On screen it grows to two hundred rows, newest first, and past that says the file holds every one; a larger page is refused | A screen asking for one draws the section as a failure |

### Recorded writes

Every write the server registers is one of two things, and the walk fails one
that is neither.

| Kind | Writes |
|---|---|
| **Leaves a row** | Anything changing what somebody may reach, what the deployment is set to, or what a later scan will mean: grants and group mappings, credentials minted and withdrawn, accounts, teams, assignment rules, support dates, the minimum severity, destinations, who is on a case, another name for an issue |
| **Leaves none, deliberately** | A triage decision and the argument around it, which is the decision record (REQ-22); an act already recorded with actor and moment on what it changed, such as editing a report, recording a message to or from its reporter, assigning it, or uploading an attachment; one person's own notifications, saved filters, mail and session; declaring what exists in the catalog; operating the queue. A declaration bringing back something retired, or filling in what a tag was cut from, leaves the row retiring or setting it would, in the same transaction |

| Rule | Reason |
|---|---|
| The second list carries a reason per route, never a count | A route absorbed into it by a line instead of a call to the recorder is the failure the walk exists to show |
| The walk reads the operations the server registered, and its driving half exercises each trailed route and reads the row back | A literal list of acts lets an administrative write record nothing with the suite green |

## Secrets and logs

Connection strings are redacted, and credentials and tokens are never written at
any level (REQ-68): a token at debug is a token in whatever collects the logs.
A database URL with a password is redacted where it is formatted, never where it
is logged, so a second caller cannot reintroduce it.

| Rule | Reason |
|---|---|
| A password parameter in the query is redacted pair by pair, as written | The query parser drops a pair it cannot decode, leaving the password unfound |
| A server URL with an `@` in its path or in a query parameter's name, a fragment, or no `//` after the scheme is refused; an `@` in a query parameter's value is accepted | A password holding an unescaped `/`, `?` or `#` parses split where redaction does not look. An `@` in a value is a user name a driver reads from the query |
| Every error from opening a connection has each spelling of each credential taken out | A driver describes its connection string, and redacts the user information only |
| A PostgreSQL connection string reaches the driver with each `@` in its query escaped | The driver reads it the same, and its error masks up to the last `@`, so a bare one leaves part of a password |
| A refusal names the scheme, the host and the kind of fault, and asks for percent-encoding | The parser's own message quotes the URL |
| The host is named only where one `@` with no `=` or `&` before it, or none, says where it begins, and only when it is shaped like a host | Otherwise what follows the `@` may be the password |
| The upgrade rehearsal reads the URL from the environment and hands it to its container through the environment | An argument is readable by every local user and written to the rehearsal's log |
| A URL the parser refuses is judged by the database package before any other parser reads it | Every other parser quotes what it could not read |
| Every configured address is shown through one redaction rule: the database server, the object store endpoint, the published directory, the deployment address, the chat server and the identity provider's issuer | Two rules with different reach let one forget the query string |
| Redaction replaces the password, every query value carrying a credential, and the fragment; in a deployment, directory, chat server or issuer address it replaces a user name standing alone too | A driver reads a password from the query and a presigned object store address carries its signature and session token there. Those four addresses carry no user, so a name there is a token |
| A refused address with no `//` after its scheme shows nothing up to its last `@`, and one the parser cannot read is not shown | `admin:hunter2@psirt.example.com` parses with the scheme `admin` |

## Limits

| Limit | Detail |
|---|---|
| A logged secret is invisible | Nothing breaks and no test fails, and the leak lives in a system nobody thinks of as holding secrets, so redaction is a rule at formatting rather than a habit |
