# Administration trail

The record of every administrative change, which writes leave a row, and the
secrets nothing records or logs.

Satisfies REQ-22, REQ-68.

## Contents

- [The administration trail](#the-administration-trail)
- [Secrets and logs](#secrets-and-logs)
- [Limits](#limits)

## The administration trail

An administrative change records who, what, before, after and when (REQ-22):
settings, role grants and withdrawals, assignment rules, end-of-life dates, the
minimum severity, credentials, accounts, teams, who is on a case, and the names
an issue answers to. The deadline policy, the minimum severity and end-of-life
dates each rewrite what the tool reports, so their record is evidence.

| Rule | Reason |
|---|---|
| Both values are kept, and absent is not empty | |
| A move is recorded from the value the write replaced, as that write answers it | A separate read lets two concurrent writers both record the original |
| Recorded in the request, where the actor is known | The walk catches a route that forgets (§ Recorded writes) |
| Every row names its actor: a person, configuration, a merge, or an upgrade; only a person's row names a person | |
| Configuration records only naming and unnaming administrators in `OPENPSIRT_BOOTSTRAP_ADMINS`, adding and removing group mappings in `OPENPSIRT_GROUP_ROLES`, and setting where roles come from to match; a start naming the same people records nothing | |
| A merge records only a rating claim it withdrew or an incident it cleared because another stood in its place in the same product | `design-docs/findings-issues.md` § Merged issues |
| An upgrade is the one to v0.5.0, recording only a key withdrawn because another holds its folded name, or a token withdrawn because another of its owner's does; no migration this tree carries writes one | |
| The record is written in the transaction making the change, and a failure to record fails the change with a refusal saying it was not made | A retry then changes nothing twice |
| What follows the change is outside it: deactivation ends sessions inside, and hands work back after it commits, bounded by what they held, never by the request | Ending sessions is what deactivation means |
| A grant and its withdrawal are recorded alike, minting a credential included | |
| A revocation that matched nothing leaves no row and is refused as not found: a grant, an estate grant, a removed group mapping, a team membership, a place on a case, a personal token, a pipeline key, a pinned identifier | Read as a withdrawal, it hands back work for a role never held |
| Never the secret, and never the whole address: what a credential may send, and a destination's host | For Slack and Teams the address is the credential |
| **What a change is about is composed from the names it resolved to** | History is read by stored identity, and a typed path segment is unbounded; an issue resolves through its first 191 runes |
| The recorder bounds what it writes to the column | A backstop: an overlong value would refuse the act |
| **It is read over a period, and leaves as a file**; asked for no period, it answers about everything | An access review covers a certificate's stretch |
| On screen it grows to two hundred rows, newest first, and past that says the file holds every one; a larger page is refused | |

### Recorded writes

Every write the server registers is one of two kinds, and the walk fails one
that is neither.

| Kind | Writes |
|---|---|
| **Leaves a row** | Anything changing what somebody may reach, what the deployment is set to, or what a later scan will mean: grants and group mappings, credentials minted and withdrawn, accounts, teams, assignment rules, support dates, the minimum severity, destinations, who is on a case, another name for an issue |
| **Leaves none, deliberately** | A triage decision and the argument around it, which is the decision record (REQ-22); an act already recorded with actor and moment on what it changed, such as editing a report, recording a message to or from its reporter, assigning it, or uploading an attachment; one person's own notifications, saved filters, mail and session; declaring what exists in the catalog; operating the queue. A declaration bringing back something retired, or filling in what a tag was cut from, leaves the row retiring or setting it would, in the same transaction |

| Rule | Reason |
|---|---|
| The second list carries a reason per route, never a count | Absorbing a route there instead of recording it is the failure the walk shows |
| The walk reads the operations the server registered, and its driving half exercises each trailed route and reads the row back | |

## Secrets and logs

Connection strings are redacted, and credentials and tokens are never written at
any level (REQ-68). A URL is redacted where it is formatted, never where it is
logged.

| Rule | Reason |
|---|---|
| A password parameter in the query is redacted pair by pair, as written | The query parser drops a pair it cannot decode |
| A server URL with an `@` in its path or a query parameter's name, a fragment, or no `//` after the scheme is refused; an `@` in a query parameter's value is accepted | A password with an unescaped `/`, `?` or `#` parses split where redaction does not look. A value's `@` is a user name a driver reads |
| Every error from opening a connection has each spelling of each credential taken out | A driver redacts user information only |
| A PostgreSQL connection string reaches the driver with each `@` in its query escaped | The driver's error masks up to the last `@` |
| A refusal names the scheme, the host and the kind of fault, and asks for percent-encoding | The parser's own message quotes the URL |
| The host is named only where one `@` with no `=` or `&` before it, or none, says where it begins, and only when it is shaped like a host | |
| The upgrade rehearsal reads the URL from the environment and passes it to its container through the environment | An argument is readable by every local user and logged |
| A URL the parser refuses is judged by the database package before any other parser reads it | Other parsers quote it |
| Every configured address is shown through one redaction rule: the database server, the object store endpoint, the published directory, the deployment address, the chat server and the identity provider's issuer | |
| Redaction replaces the password, every query value carrying a credential, and the fragment; in a deployment, directory, chat server or issuer address it replaces a lone user name too | A presigned object store address carries its signature and session token in the query. Those four addresses carry no user, so a name there is a token |
| A refused address with no `//` after its scheme shows nothing up to its last `@`, and one the parser cannot read is not shown | `admin:hunter2@psirt.example.com` parses with the scheme `admin` |

## Limits

| Limit | Detail |
|---|---|
| The trail records what the application does | A hand edit of the database leaves no row; the database is trusted (REQ-22) |
