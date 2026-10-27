# Text people write

Justifications, deferral reasons, comments and descriptions: the policy typed
text passes at submission, and where it is rendered.

Satisfies REQ-65, REQ-66, REQ-67, REQ-69.

## Contents

- [Policy and sanitizing](#policy-and-sanitizing)
- [Raw markup](#raw-markup)
- [Link schemes](#link-schemes)
- [Issue references](#issue-references)
- [Images and attachments](#images-and-attachments)
- [Representation](#representation)
- [Rendered and escaped text](#rendered-and-escaped-text)
- [Refusals](#refusals)
- [Code block language tags](#code-block-language-tags)
- [Bounds](#bounds)
- [Limits](#limits)

## Policy and sanitizing

Two controls, kept apart, running in two places (REQ-67).

| Control | Runs | Covers |
|---|---|---|
| Policy | Once, on the server, at submission, before storage | What is permitted, which links survive, what each reference resolves to |
| Sanitizing | Wherever the text is rendered, which is never this server | Text stored before a rule existed |

| Rule | Reason |
|---|---|
| Policy is the server's | It needs data and authorization checks no client holds |
| Sanitizing travels with rendering, and nothing on the server renders | The API returns the source as its only representation, and mail is plain text. The interface sanitizes what it renders; an integrator sanitizes what they render |
| Text stored under an older policy is served as source | A rule written after it was stored is applied by whoever renders it: the interface's current sanitizer, or an integrator's, which is why the API says so |
| The source is stored, never rendered markup | One text reaches a browser, an email and an export |
| Submission and sanitizing agree on what survives | A link accepted at submission and dropped by the sanitizer is a link when written and plain text when read, with nothing reporting it |

## Raw markup

Raw markup is refused at submission, naming the line it is on. It is never
dropped and never escaped: a person told while writing can fix it, and a tag
silently escaped shows them something other than what they typed.

| Rule | Reason |
|---|---|
| The category is refused, never allowlisted | An allowlist can be wrong, and attacks live in the gap between what it permits and what a browser does. Nothing triage needs requires markup |
| The parser reports it; it is not turned off at the parser | A parser producing no markup nodes leaves nothing to report. The option that reads as parser configuration is a renderer option, and nothing here renders |
| There is no second pass | The submission check is the server's half; each renderer is somebody else's and has its own tests over the same corpus |

## Link schemes

`http`, `https` and `mailto` survive, with two schemes of this deployment's
own: `attachment:` for a file held here and `issue:` for one vulnerability.
Every other scheme is dropped.

| Refused | Reason |
|---|---|
| `javascript:` | Script execution from a link |
| `data:` | A link becomes a page this deployment appears to have served |
| A custom application scheme | Hands a privileged reader's click to a program on their machine |

| Rule | Reason |
|---|---|
| One file of test data holds both lists: what submitted text may link to, and what a link leaving the deployment may name once the two local schemes are rewritten into paths | The submission check and the interface's renderer each keep a copy, and a test on each side compares it with the file, so a scheme accepted at submission and dropped on screen fails on the side not changed |
| The refusal sentence and the operation description naming the schemes are built from the submission check's list | |
| Outbound links carry no referrer and no live opener | |
| A destination is judged as a browser reads it, in every link form: inline, a reference definition, and an autolink in angle brackets | |
| Character references are decoded first | `&#106;avascript:` is `javascript:` to a browser |
| Leading and trailing control characters and spaces are removed, and every tab and newline wherever it sits | A browser's address parser does the same, so `/`, a tab, `/evil.example` is two separators |
| The scheme runs to the first colon, with any control character inside it ignored | `java&#9;script:` is `javascript:` to a browser |
| `attachment:` and `issue:` are refused unless written exactly so, in lower case, and the refusal names the spelling | A renderer resolves them as written, so `Attachment:` links to nothing, and the identifier after it may be well formed |
| An `attachment:` reference is the minted identifier, 32 lower-case hexadecimal characters; an `issue:` reference is a letter then 2 to 63 letters, digits, dots, dashes or underscores | The submission check accepts exactly what the interface's renderer links, so accepted text is never a dead link. The corpus holds references on both sides of each edge |
| A link to this deployment survives; the sanitizer decides by resolving the destination against the page, never by pattern | `//somewhere.else/x` carries no scheme and is not relative: a browser fetches it from another origin |

### Fields under the policy

Every field a person types passes the policy, whether or not anything renders
it.

| Field | Examples |
|---|---|
| Text | A decision's reasoning, an assessment's reasoning, the reason an embargo is extended, the note on a closure by hand, the note on a build declared unaffected, the summary recorded with an issuance, a recorded flaw's summary |
| An address stored alone | Where work on a decision is happening, the address beside a fix target |

| Rule | Reason |
|---|---|
| A field that skips the policy loses the scheme check, the refusal of raw markup and the length bound at once | |
| The check runs in the store, where the value is trimmed, never in the first handler that calls it | A column written by two paths is only as bounded as the laxer |
| Every route answering a refusal of the policy answers 422, with a detail per fault naming its line | A route falling through to its fault arm answers 500 for the caller's own writing, which tells them nothing to fix |

## Issue references

`issue:CVE-2026-1234` is one vulnerability, wherever this deployment has it
(REQ-65). It is an identifier, never an address: somebody writing "the same
root cause as CVE-2026-1234" means the issue, which has an address of its own,
and never a finding's product, build or component.

| Rule | Reason |
|---|---|
| Written, never detected | Rewriting a bare identifier into a link edits somebody's prose, quotations and lists of examples included |
| A bare identifier keeps linking to the record that defines it; `issue:` links to ours | Two citations, both right. Taking the first over would retarget every identifier anybody has typed |
| The shape is checked; existence is not | Whether we hold the issue is a question with a subject, and this policy has none. A flaw nothing has scanned yet is still true to write about |
| A shape, never a list of prefixes | CVE, GHSA and every vendor identifier a scan carries are a letter then letters, digits and separators; a list of known prefixes refuses issues already held |
| Judged at submission as well as at render | The half that lists what a text refers to recognizes only an identifier, so a destination the scheme accepted and that half ignores is a dead link nothing reports, as `attachment:../../secret` would be |
| Nothing resolves it on the server | The identifier is the address, reached by anybody with no lookup, unlike a mention, which needs the person table, or an attachment, which needs a token resolved to a file; those two are what REQ-65 resolves. A reference to an issue nothing has scanned points at a page saying so, and becomes right when a scan arrives |
| Nothing lists what a text refers to | There is no resolver to feed. Whoever renders the text finds the references in it |

## Images and attachments

An image may reference a file attached here and nothing else, by scheme.

| Rule | Reason |
|---|---|
| The only image scheme is `attachment:` | A submission pointing anywhere else is told to attach the file |
| What follows it is a 32-hexadecimal-character identifier this deployment minted | Otherwise `attachment:../../secret` is accepted when written and resolves to nothing when read |
| Every form the check accepts a reference in keeps the file: a link, an image, a reference definition and an autolink | The list of what a text refers to marks a file attached, and an unmarked file is deleted by the reaper while the text still points at it |
| The sanitizer permits the scheme | No browser resolves it, so it cannot become a page or a script; the interface turns it into a path to a file this deployment holds |
| A remote image is never allowed | It fires from every reader's browser, inside the network, telling its author who read which finding and when: a disclosure channel on an undisclosed finding |

A file attached here is fetched through a path that authorizes the reader
(`design-docs/attachments.md` § Fetch authorization).

## Representation

| Rule | Reason |
|---|---|
| The API returns markdown as its sole representation, with no parameter requesting markup | An integrating application lays markdown out easily and it reads as plain text; HTML assumes a browser, which most callers are not |
| Mail is plain text. An HTML part is not built | Mail carries only sentences the server composes and no typed text, so an HTML part would need no renderer |
| Every renderer is somebody else's: the interface for a browser, an integrator for their application | The source is authoritative, so a failed rendering is the renderer's |

## Rendered and escaped text

| Origin | Treatment |
|---|---|
| Typed into this tool | Passes the submission policy and is rendered as markdown |
| Supplied by a scan file | Shown as written, never rendered (REQ-66) |

| Rule | Reason |
|---|---|
| The origin decides, since both share a column | Rendering the column hands a scan file's author a formatting language aimed at the browsers of the people holding the most access |
| Escaping happens where text is put into a document, and the two origins stay distinguishable | The interface escapes what it shows, and a renderer can tell which it holds |
| The release note and the issue document, both served as markdown, escape every value that did not pass the policy as it is written (`design-docs/analytics.md`) | A renderer shows it as the text it is |
| A webhook's subject and text are escaped by the same rule, line by line (`design-docs/notifications.md`) | |

| Escaped | Where | Opens |
|---|---|---|
| A control character, a newline among them | Anywhere, as a space | A line and a block the string chose |
| `\` `` ` `` `*` `[` `]` `<` `~` `\|` | Anywhere | An escape, code, emphasis, a link or image, markup or an autolink, strikethrough, a table cell |
| `_` | Unless a letter or digit is on both sides | Emphasis |
| `&` | Before a letter or `#` | A character reference |
| `:` | Before `//` | A bare address, which a renderer that links addresses links |
| `.` | After `www` at the start of a word | The same, for an address with no scheme |
| `@` | Before a letter or digit | A mail link, and a mention in a renderer with accounts |
| Spaces | First in the string, dropped | A code block, which four of them open where the string opens a line |
| A run of up to six `#`, or a `-` or `+`, before a space or the end of the string; a `-` before another `-`; a `>` | First in the string | A heading, a list item, a rule or a quotation where the string opens a line, a list item's content included |
| `.` or `)` before a space or the end of the string | After up to nine leading digits | An ordered list item |
| The first `#` of a run after a space | Last in the string, trailing spaces aside | A closing sequence, which a heading drops |

A character is escaped where it can open syntax where it sits, and in the few
places it only might: `--rc1` is written `\--rc1`, because a line of three is a
rule. Nothing else is escaped, because both documents are also read as source,
where `1\.2\.3` for every version is noise.

## Refusals

A refusal carries the line, the offending text and the reason, and every fault
in a submission is reported at once.

| Case | Line named |
|---|---|
| A refused link | Where it is written, found from the link's own text onward |
| A destination written twice | Both lines. One shown in a fenced block above, or earlier in the same paragraph, is not the one named |
| A destination from a reference definition | The definition's line |
| A destination not appearing literally, spelled with a character reference | The first line of its block |
| A link with no text, and an autolink | Searched from the start of the block, so an earlier copy in the same paragraph is the one named |

## Code block language tags

The tag after three backticks lands in a class attribute, so it is allowlisted
(REQ-67). An unrecognized language keeps the block and loses the label.

| Rule | Reason |
|---|---|
| The allowlist belongs to whoever renders, and each reader keeps its own | This server emits no markup |
| A test asserts over the rendered output | Asking an allowlist directly proves only that it agrees with itself |

## Bounds

Every field is capped at 64 KB (REQ-69). Nothing here renders, so the cap is
the whole bound.

| Rule | Reason |
|---|---|
| The column holds what the cap admits, on every engine | Two engines spell plain text as a type topping out at 65,535 bytes, one short of the cap: a field of exactly the admitted size passes submission, then fails the write or, outside strict mode, is truncated without a word, leaving an approver agreeing to text nobody wrote. A test on one engine does not reach it |
| The cap is applied before any parsing | The one parse is the submission check's, so the cap bounds the work |
| No time bound | A parse cannot be interrupted, so a time bound limits the wait and never the work |

## Limits

| Rule | Reason |
|---|---|
| A code block is not highlighted | Grammar coverage costs bundle size, weighed against a real screen |
| A bare `scheme://` is an address; a bare `word:` is not | The second matches `parser.go:112` in a stack trace and `TODO: check this` in a sentence. Schemes that act rather than navigate carry no `//`, and are matched separately |
