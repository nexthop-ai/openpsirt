# Privileges

The roles, and the reach of each.

Each endpoint's own requirement is on the endpoint, in the [API
reference](api.md): every operation states its scope, the roles that satisfy
it, and a note where a rule is not a role, and carries the same value as
structured data for anything reading the document (REQ-62). Repeated here as
four tables of a hundred and sixty rows, that is the reference again at lower
resolution — nobody looking up one endpoint reads a table to find it, and
nobody reading about roles wants a list of paths.

Access is granted in advance or not at all: no account is created for anybody
nothing authorized in advance. Somebody who authenticates and has no record is
refused, so a role is something an administrator gave a person before they
arrived.

Where a deployment derives roles from identity-provider groups, the mapping is
that advance grant, and a record is written on first arrival for somebody it
covers. Somebody in no mapped group is refused exactly as a stranger is, and
nothing is recorded for them.

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

Seeing is never changing. A read role reaches no act, and every act is a
role of its own. That is why there are two read roles rather than one: what has
been announced and what has not are different populations, and a great many
people should see the first without seeing the second.

`approver` and `assigner` grant no visibility of their own. Each is a
capability bounded by what its holder may read, so granted alone it reaches
nothing — somebody who may agree to claims needs a read role as well, and a
deployment that grants only the capability has given somebody an empty tool.

An administrator administers (REQ-42). People, roles, credentials, settings,
the catalog, and acts on the record itself — removing an attached file, and
supplying a third party's evidence about a product. Reading and triaging are
granted on a product like anybody else's, and an administrator who wants them
grants them to themselves. Holding
every product role there is does not amount to administration either — the two
do not imply each other in either direction. This is what makes a read-only
auditor expressible, and what keeps one account from proposing a decision and
approving it.

Two rules are not roles and cannot be granted:

- **Visibility** narrows every answer. An endpoint you may call still shows
 only what you may see, so two people calling the same endpoint get different
 answers rather than one of them getting an error.
- **Separation of duties**: the proposer of a claim may never approve it,
 whoever they are, however much they hold.

## Names without a directory

Listing people is administration, and it stays that way: a directory of
everybody who works here is not something a role about findings should carry.
Three narrower questions are answered instead, each narrowed by what the asker
may see and each bounded, and none of them is that list (REQ-42):

- **The mentionable** in a comment on a particular finding: people who can
 already read it. Scoped to the product, capped.
- **The holders of work** in a product: people who could open what they would
 be given, and the teams routed work there. Scoped to the product, capped.
- **The holdings you can see**: a name and how much, across the products your
 grants reach. Narrowed by subject in the data layer rather than by a product
 in the path, and bounded like every other list, worst first.

They are different projections on purpose. A team cannot be mentioned in prose
but is a perfectly good holder of work, somebody who can read a finding is not
necessarily somebody it should be handed to, and an overloaded person is a
question about work rather than about people.

## The reach of a declaration

Each operation *declares* what it asks of a caller. The part of that about the
caller alone runs; the part about the product is a line in the handler.

The scope — administrator, your own credential, any recognized credential,
none — is a fact about the subject and nothing else, so it is enforced from the
declaration before any handler runs. Left to the handler alone, an
administrator-only operation whose check somebody deletes still renders
"Requires: administrator", still carries the extension a client generator
reads, and answers anybody holding a credential.

A role on a product is different, because it needs the product resolved, and
that is where the handler's own refusal shape matters: many of these
deliberately report "not there" rather than "not yours", and a check running
before the handler would answer the question the handler exists to avoid
answering. That is why the *scope* half is enforced centrally and the *role*
half is not: enforcing both centrally is refused for that reason, and enforcing
neither leaves the ladder unverifiable.

Where somebody wrote a narrower check than the operation declares, the two
disagree, and the reference follows the declaration. Six have disagreed, and
every one was found by reading them against each other rather than by anything
failing.

Two kinds of rule, and each says which it is. A gate refuses somebody
holding none of the roles. Where the reference says *what you hold decides what
comes back rather than whether you may ask*, the roles narrow the answer
instead: a stranger is answered, with nothing of theirs in it, and an empty list
is the correct answer rather than a check that was skipped.

Every gate is swept, at every scope. A test walks the operations the server
registers and asks each gated one as somebody it excludes: for a role on a
product, somebody holding none of those roles; for an administrator gate,
somebody holding a role and not administering. A 2xx fails it.

It counts each of the two classes separately and refuses to pass on a class
that has emptied. Sweeping the first alone leaves the administrator gates
walked by nothing — the ones a mistake would be worst on.

A third class, for a role held on any product at all rather than on the one a
request names, has no operations: the only ones in it recorded a rating, and a
rating belongs to a product (REQ-29), so the scope went with the shape that
needed it.

That is a floor rather than a proof the check is the right one, and the rest is
the authorization tests and review. It reads the operations rather than this
page, which is why this page can be prose.
