# Text people write

Justifications, deferral reasons, comments and descriptions, and the point at
which typed text becomes markup.

Satisfies REQ-65, REQ-66, REQ-67, REQ-69.

## Contents

- [Policy and sanitizing](#policy-and-sanitizing)
- [Raw markup](#raw-markup)
- [Link schemes](#link-schemes)
- [Referring to an issue](#referring-to-an-issue)
- [Images and attachments](#images-and-attachments)
- [Representation](#representation)
- [Rendered and escaped text](#rendered-and-escaped-text)
- [Refusals](#refusals)
- [Code block language tags](#code-block-language-tags)
- [Bounds](#bounds)
- [Limits](#limits)

## Policy and sanitizing

Two controls, kept apart, and they run in two different places.

| | Runs | Covers |
|---|---|---|
| Policy | Once, on the server, at submission, before storage | What is permitted, which links survive, what each reference resolves to |
| Sanitizing | Wherever the text is rendered, which is not here | Text stored before a rule existed |

Policy needs data and authorization checks no client holds, so it is the
server's. Sanitizing travels with rendering, and **nothing on the server
renders**: the API returns the source as its only representation, and mail is
sent as plain text. The interface sanitizes what it renders, and an integrator
rendering this markdown sanitizes what they render.

A sanitizer was written here and never called. Its policy, its language
allowlist and its time bound sat behind an entry point no running code reached,
so a rule improved in it next year would change nothing for anybody — while this
document said it ran on every render, which is the shape a reviewer ticks. It is
gone, and what is written here is what happens.

What that costs, stated rather than glossed: text stored under an older
submission policy is served as source, so a rule written after it was stored is
applied by whoever renders it and by nobody else. For the interface that is the
interface's own sanitizer, which is current. For an integrator it is theirs,
which is why the API says so.

The source is stored; rendered markup never is. The same text reaches a
browser, an email and an export.

## Raw markup

Raw markup is **refused at submission**, naming the line it is on. Not dropped,
not escaped: a person told while they are still writing can fix it, and a tag
silently escaped is somebody who typed one thing and was shown another.

| Rule | Reason |
|---|---|
| Refused rather than allowlisted | An allowlist of permitted tags is a thing that can be wrong, and every interesting attack lives in the gap between what such a list permits and what a browser does. Nothing triage needs requires markup, so the category goes rather than being bounded |
| Refused rather than turned off at the parser | A parser that produced no markup nodes would leave nothing to report, and the point is to report it. This was described as parser configuration and was not: the option that reads that way is a *renderer* option, and nothing here renders |

There is no second pass. A sanitizer ran over the parser's output once, and it
was the only reader of the rendering this server no longer does — so what
stands between a payload and a reader is the check at submission, which is the
half the server owns. What renders is somebody else's, and each renderer has
its own tests over the same corpus.

## Link schemes

`http`, `https` and `mailto` survive, and two schemes of this deployment's own:
`attachment:` for a file held here and `issue:` for one vulnerability. Every
other scheme is dropped.

| Refused | Reason |
|---|---|
| `javascript:` | Script execution from a link |
| `data:` | Lets a link become a page this deployment appears to have served |
| A custom application scheme | Hands a privileged reader's click to a program on their machine |

Outbound links carry no referrer and no live opener.

A link to somewhere in this deployment survives. The browser's sanitizer decides
by **resolving** the destination against the page rather than matching it
against a pattern: `//somewhere.else/x` carries no scheme and is not relative, so
a browser resolves it against the page's protocol and fetches it from another
origin.

Every field a person types passes the submission policy, whether or not
anything renders it: an assessment's reasoning, the reason an embargo is
extended, the note on a closure by hand, the note on a build declared
unaffected, and the summary recorded with an issuance. So does an address
stored on its own — where work on a claim is happening, the address beside a
fix target — and the summary of a recorded flaw. A field that skips the policy
loses all three of its parts at once: the scheme check, the refusal of raw
markup, and the length bound.

**The check runs in the store, at the point the value is trimmed**, rather than
in the handler that happens to be the first caller. That is what makes the
policy hold for every path into the column, and a column written by two paths
is only as bounded as the laxer of the two.

Submission and sanitizing must agree on what survives. A link accepted at
submission and deleted by the sanitizer is a link when it is written and plain
text when it is read, with nothing reporting the difference.

## Referring to an issue

`issue:CVE-2026-1234` is one vulnerability, wherever this deployment has it
(REQ-65). An identifier and never an address, for the reason an attachment is
one: what a finding's address names — a product, a build, a component — is not
what somebody writing "the same root cause as CVE-2026-1234" means. They mean
the issue, and the issue has an address of its own.

| Rule | Reason |
|---|---|
| Written, never detected | A bare identifier in a sentence is text somebody wrote. Rewriting it into a link edits their prose, quotations and lists-of-examples included |
| A bare identifier keeps meaning what it already meant | It links to the record that defines it — the world's answer — and `issue:` links to ours. Two citations, both right, and taking the first over would silently retarget every identifier anybody has ever typed |
| The shape is checked, the existence is not | Whether we hold that issue is a question with a subject attached, and this policy has none. Somebody writing about a flaw nothing has scanned yet is writing something true, and refusing it would make the text argue with the scan schedule |
| A shape rather than a list of prefixes | CVE, GHSA and every vendor identifier a scan file carries are all a letter followed by letters, digits and separators. A list of the ones we have heard of would refuse a reference to an issue we already hold |
| Judged at submission, not only at render | The half that lists what a text refers to recognizes only an identifier, so a destination the scheme accepted and that half ignores is a dead link nothing reports — the same disagreement `attachment:../../secret` produced |
| Nothing resolves it server-side, and nothing needs to | An identifier **is** the address: our record of an issue is reached from the identifier alone, by anybody, with no lookup. That is what makes it unlike a mention, which needs the person table, or an attachment, which needs a token resolved to a file — the two REQ-65 is about. A reference to an issue nothing has scanned yet points at a page that says so, and becomes right when a scan arrives |

## Images and attachments

An image may reference a file attached here and nothing else. The restriction is
by scheme, not by address.

| Rule | |
|---|---|
| The only permitted image scheme is `attachment:` | A submission pointing anywhere else is told to attach the file |
| What follows the scheme must be a 32-hexadecimal-character identifier this deployment minted | Otherwise `attachment:../../secret` is accepted when written and resolves to nothing when read |
| The sanitizer permits the scheme | It cannot become a page or a script: no browser resolves it, and the interface turns it into a path against a file this deployment holds |

A remote image fires from the browser of everybody who reads the text, from
inside the network, reporting to whoever wrote it who is reading which finding
and when. On an undisclosed finding that is a disclosure channel. A file attached
here is fetched through a path that authorizes the reader — see
`DESIGN-attachments.md`.

## Representation

The API returns markdown, as the sole representation. There is no markup
representation and no parameter requesting one.

Markdown is what an integrating application can most easily lay out, and it reads
as plain text as it stands. HTML assumes a browser, which most callers of an
API-first tool are not.

Mail is plain text, so nothing renders there either. An HTML part is the case
that would need a renderer on the server, and it is not built.

Sanitizing travels with rendering, and every renderer is somebody else's: the
interface for a browser, an integrator for their own application. A rendering
that fails is the renderer's problem, since the source is authoritative.

## Rendered and escaped text

| Origin | Treatment |
|---|---|
| Typed into this tool | Passes the submission policy and is rendered as markdown |
| Supplied by a scan file | Shown as written, never rendered (REQ-66) |

Both live in the same column, so the origin decides. Rendering the column would
hand whoever wrote the scan file a formatting language aimed at the browsers of
the people holding the most access in this deployment.

Escaping, like sanitizing, happens where the text is put into a document —
which is the interface, not here. What the server guarantees is that the two
origins stay distinguishable, so a renderer can tell which it is holding.

## Refusals

A refusal carries the line, the offending text, and the reason. Every fault in
the submission is reported at once rather than one at a time.

## Code block language tags

The language tag after three backticks is input and lands in a class attribute.
It is allowlisted. An unrecognized language keeps the block and loses the label
rather than failing.

The allowlist is whoever renders. This server emits no markup, so the list it
held went with the renderer — and each reader keeps its own, over which what is
asserted is the rendered output: asking an allowlist directly proves only that
it agrees with itself.

## Bounds

Every field is capped at 64 KB. Nothing here renders, so the cap is the whole
of the bound: what was time-bounded was a rendering this server stopped doing.

The column holds what the cap admits, on every engine. Two of the four spell
plain text as a type topping out at 65,535 bytes, one byte short of the cap — so
a field of exactly the admitted size passed submission and failed the write on
those two, or was truncated without a word outside strict mode, which leaves an
approver agreeing to text that is not the text somebody wrote. The quick loop
never saw it, because the engine it runs on stores it happily.

The parse that remains is the one the submission check makes, over text already
inside that cap — so the cap is applied before any parsing starts and is what
bounds the work. The time bound that sat beside it bounded the *wait* rather
than the work, which is a distinction worth keeping in mind if rendering ever
comes back: a parse cannot be interrupted, so what such a bound buys is that
the request answers and releases its resources while the work runs on.

## Limits

- **A bare `scheme://` is treated as an address; a bare `word:` is not.** The
  second matches `parser.go:112` in a stack trace and `TODO: check this` in a
  sentence. Schemes that act rather than navigate are matched separately, since
  they carry no `//`.
- **A tag in the text is reported rather than silently dropped.** Raw markup is
  already off at the parser, so this changes nothing about safety; it tells the
  author why their tag will not appear.
- **An allowlist of permitted tags was rejected** in favor of refusing raw markup
  outright. Such a list is a thing that can be wrong, and the gap between what it
  permits and what a browser does is where the attacks live.
