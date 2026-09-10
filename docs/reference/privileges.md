# Privileges

Who may do what, and what each role means.

**What every individual endpoint requires is on the endpoint**, in the [API
reference](api.md): each operation states its scope, the roles that satisfy it,
and a note where a rule is not a role, and carries the same value as structured
data for anything reading the document (REQ-62). This page used to repeat all
of that as four tables of a hundred and sixty rows, which is the reference
again at lower resolution — nobody looking up one endpoint reads a table to
find it, and nobody reading about roles wants a list of paths.

Access is granted in advance or not at all: **no account is created by signing
in**. Somebody who authenticates and has no record is refused, so a role is
something an administrator gave a person before they arrived.

## The roles

A role is held **per product**, except administration, which is held for the
deployment.

| Role | What it allows |
|---|---|
| `public-read` | Read findings that have been disclosed |
| `private-read` | Read findings nobody has announced |
| `public-triage` | Argue about disclosed findings: decide, revise, withdraw, comment. Take work nobody owns, and hand back your own |
| `private-triage` | The same for findings nobody has announced, including recording one and moving its disclosure date |
| `approver` | Agree to somebody else's claim. A triager may also approve, and the proposer may never approve their own |
| `assigner` | Give work to somebody else, or take what they are holding |
| administrator | The deployment: people, roles, credentials, settings, and the catalog |

**Seeing is never changing.** A read role reaches no act, and every act is a
role of its own. That is why there are two read roles rather than one: what has
been announced and what has not are different populations, and a great many
people should see the first without seeing the second.

**`approver` and `assigner` grant no visibility of their own.** Each is a
capability bounded by what its holder may read, so granted alone it reaches
nothing — somebody who may agree to claims needs a read role as well, and a
deployment that grants only the capability has given somebody an empty tool.

**An administrator administers** (REQ-42). People, roles, credentials, settings
and the catalog. Reading and triaging are granted on a product like anybody
else's, and an administrator who wants them grants them to themselves. Holding
every product role there is does not amount to administration either — the two
do not imply each other in either direction. This is what makes a read-only
auditor expressible, and what keeps one account from proposing a decision and
approving it.

Two rules are not roles and cannot be granted:

- **Visibility narrows every answer.** An endpoint you may call still shows
 only what you may see, so two people calling the same endpoint get different
 answers rather than one of them getting an error.
- **The proposer of a claim may never approve it**, whoever they are, however
 much they hold.

## Reaching a name without reading the directory

Listing people is administration, and it stays that way: a directory of
everybody who works here is not something a role about findings should carry.
Two narrower questions are answered instead, each scoped to a product and
capped, and neither is that list (REQ-42):

- **Who can be mentioned** in a comment on a particular finding — people who
 can already read it.
- **Who can hold work** in a product — people who could open what they would be
 given, and the teams routed work there.

They are different projections on purpose. A team cannot be mentioned in prose
but is a perfectly good holder of work, and somebody who can read a finding is
not necessarily somebody it should be handed to.

## What a declaration is, and is not

Each operation *declares* what it asks of a caller, and the declaration is not
the check: the check is a line in the handler. Where somebody wrote a narrower
check than the operation declares, the two disagree, and the reference follows
the declaration. Six have disagreed, and every one was found by reading them
against each other rather than by anything failing.

Enforcing the declaration centrally instead was considered and refused. A
refusal's shape is part of the answer, and many of these deliberately report
"not there" rather than "not yours" — a check that ran before the handler would
answer the question the handler exists to avoid answering.

**Two kinds of rule, and each says which it is.** A gate refuses somebody
holding none of the roles. Where the reference says *what you hold decides what
comes back rather than whether you may ask*, the roles narrow the answer
instead: a stranger is answered, with nothing of theirs in it, and an empty list
is the correct answer rather than a check that was skipped.

**Every gate is swept.** A test walks the operations the server registers, and
asks each gated one as somebody who holds none of its roles; a 2xx fails it.
That is a floor rather than a proof the check is the right one, and the rest is
the authorization tests and review. It reads the operations rather than this
page, which is why this page can be prose.
