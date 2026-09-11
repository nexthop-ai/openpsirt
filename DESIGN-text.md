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

Two controls, kept apart.

| | Runs | Covers |
|---|---|---|
| Policy | Once, on the server, at submission, before storage | What is permitted, which links survive, what each reference resolves to |
| Sanitizing | Every time the text is rendered | Text stored before a rule existed |

Both run. Policy needs data and authorization checks no client holds. Sanitizing
covers stored text, because a sanitizer improved next year does nothing for
markup already in the database.

The source is stored; rendered markup never is. The same text reaches a browser,
an email and an export.

## Raw markup

Raw markup is refused at the parser rather than stripped afterwards. The parser
drops a raw block and escapes an inline one. The assertion is that nothing
arrives as live markup, not which of the two mechanisms ran.

The sanitizer runs over the parser output regardless, and that is asserted
separately.

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

Every field rendered as markdown passes the submission policy, including an
address stored on its own — where work on a claim is happening, the address
beside a fix target — and the summary of a recorded flaw. A field that skips the
policy loses all three of its parts at once: the scheme check, the refusal of raw
markup, and the length bound.

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

The server renders for an email's HTML part, which has no client to render for
it. It does not render for a reader on the way out of the API.

Sanitizing travels with rendering: for the interface that is the browser, for an
email it is here. An integrator rendering this markdown sanitizes what they
render. A rendering that fails is the renderer's problem, since the source is
authoritative.

## Rendered and escaped text

| Origin | Treatment |
|---|---|
| Typed into this tool | Passes the submission policy and is rendered as markdown |
| Supplied by a scan file | Escaped and displayed as written, never rendered (REQ-66) |

Both live in the same column, so the origin decides. Rendering the column would
hand whoever wrote the scan file a formatting language aimed at the browsers of
the people holding the most access in this deployment.

## Refusals

A refusal carries the line, the offending text, and the reason. Every fault in
the submission is reported at once rather than one at a time.

## Code block language tags

The language tag after three backticks is input and lands in a class attribute.
It is allowlisted. An unrecognized language keeps the block and loses the label
rather than failing.

The allowlist is applied in one place, by the sanitizer, on the way out. What is
asserted is the rendered output, because asking the allowlist directly proves
only that it agrees with itself.

## Bounds

Every field is capped at 64 KB. Rendering is time-bounded.

**The column holds what the cap admits, on every engine.** Two of the four
spell plain text as a type topping out at 65,535 bytes, one byte short of the
cap — so a field of exactly the admitted size passed submission and failed the
write on those two, or was truncated without a word outside strict mode, which
leaves an approver agreeing to text that is not the text somebody wrote. The
quick loop never saw it, because the engine it runs on stores it happily.

The time bound bounds the wait, not the work: a parse cannot be interrupted, so
the work runs to completion with nobody reading the result. What the bound buys
is that the request answers and releases its resources. The cap on the work is
the length limit, applied before any parsing starts.

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
