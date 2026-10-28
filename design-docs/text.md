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

| Control | Runs | Covers |
|---|---|---|
| Policy | Once, on the server, at submission, before storage (REQ-67) | What is permitted, which links survive, what each reference resolves to |
| Sanitizing | Wherever the text is rendered, never on this server | Text stored before a rule existed |

| Rule | Reason |
|---|---|
| Policy is the server's | It needs data and authorization no client holds |
| Nothing on the server renders: the API returns source, and mail is plain text. The interface sanitizes what it renders, an integrator what they render | Sanitizing travels with rendering |
| Text stored under an older policy is served as source, so a later rule is the renderer's to apply, which the API says | |
| The source is stored, never rendered markup | One text reaches a browser, an email and an export |
| Submission and sanitizing agree on what survives | Otherwise a link written is plain text when read, and nothing reports it |

## Raw markup

Raw markup is refused at submission, naming its line: never dropped, never
escaped, so the writer fixes it and is never shown something else.

| Rule | Reason |
|---|---|
| The category is refused, never allowlisted | Attacks live in the gap between an allowlist and a browser, and triage needs no markup |
| The parser reports it; it is not switched off at the parser | A parser producing no markup nodes has nothing to report, and that option is the renderer's |
| There is no second pass on the server | Each renderer is somebody else's, tested over the same corpus |

## Link schemes

`http`, `https` and `mailto` survive, with this deployment's `attachment:` for
a file held here and `issue:` for one vulnerability. Every other scheme is
dropped.

| Refused | Reason |
|---|---|
| `javascript:` | Script from a link |
| `data:` | A page this deployment appears to have served |
| A custom application scheme | A privileged reader's click handed to a program on their machine |

| Rule | Reason |
|---|---|
| One test-data file holds what submitted text may link to and what an outbound link may name once the two local schemes become paths; the submission check and the interface's renderer each keep a copy a test compares with it | A scheme accepted at submission and dropped on screen fails on the side not changed |
| The refusal sentence and the operation description are built from the submission check's list | |
| Outbound links carry no referrer and no live opener | |
| A destination is judged as a browser reads it, inline, as a reference definition, and as an angle-bracket autolink | |
| Character references are decoded first | `&#106;avascript:` is `javascript:` |
| Leading and trailing control characters and spaces are removed, and every tab and newline anywhere | A browser does the same, so `/`, a tab, `/evil.example` is two separators |
| The scheme runs to the first colon, ignoring control characters inside it | `java&#9;script:` is `javascript:` |
| `attachment:` and `issue:` are refused unless written exactly so, in lower case, and the refusal names the spelling | `Attachment:` links to nothing though the identifier may be well formed |
| An `attachment:` reference is 32 lower-case hexadecimal characters; an `issue:` reference is a letter then 2 to 63 letters, digits, dots, dashes or underscores | Submission accepts exactly what the interface links, with corpus cases on both sides of each edge |
| A link to this deployment survives; the sanitizer resolves the destination against the page, never matches a pattern | `//somewhere.else/x` has no scheme and is not relative: it is another origin |

### Fields under the policy

Every typed field passes the policy, rendered or not.

| Field | Examples |
|---|---|
| Text | A decision's or an assessment's reasoning, the reason an embargo is extended, the note on a closure by hand or on a build declared unaffected, an issuance's summary, a recorded flaw's summary |
| An address stored alone | Where work on a decision happens, the address beside a fix target |

| Rule | Reason |
|---|---|
| A field skipping the policy loses the scheme check, the markup refusal and the length bound at once | |
| The check runs in the store, where the value is trimmed | A column written by two paths is as bounded as the laxer |
| A refusal of the policy answers 422, a detail per fault naming its line, on every route | Falling through to 500 tells the writer nothing to fix |

## Issue references

`issue:CVE-2026-1234` is one vulnerability wherever this deployment has it
(REQ-65): the issue, with an address of its own, never a finding's product,
build or component.

| Rule | Reason |
|---|---|
| Written, never detected | Linking bare identifiers edits somebody's prose |
| A bare identifier keeps linking to the record defining it; `issue:` links to ours | Two citations, both right |
| The shape is checked, existence is not | The policy has no subject, and an unscanned flaw is true to write about |
| A shape, never a list of prefixes | Every scanned identifier is a letter then letters, digits and separators |
| Judged at submission as well as at render | Otherwise an accepted destination the reference finder ignores is a dead link nothing reports |
| Nothing resolves it on the server | The identifier is the address; mentions and attachments are what REQ-65 resolves. An unscanned issue's page says so until a scan arrives |
| Nothing lists what a text refers to | No resolver needs it; a renderer finds the references in the text |

## Images and attachments

| Rule | Reason |
|---|---|
| An image's only scheme is `attachment:`, followed by an identifier this deployment minted | Anything else is told to attach the file; `attachment:../../secret` would resolve to nothing |
| Every form the check accepts a reference in keeps the file: link, image, reference definition, autolink | An unmarked file is reaped while text still points at it |
| The sanitizer permits the scheme | No browser resolves it; the interface turns it into a path to a held file |
| A remote image is never allowed | It reports to its author who read which finding and when, from inside the network |

A held file is fetched through a path that authorizes the reader
(`design-docs/attachments.md` § Fetch authorization).

## Representation

| Rule | Reason |
|---|---|
| The API returns markdown alone, with no parameter requesting markup | It lays out easily and reads as plain text; HTML assumes a browser |
| Mail is plain text; an HTML part is not built | Mail carries only sentences the server composes |
| Every renderer is somebody else's | The source is authoritative |

## Rendered and escaped text

| Origin | Treatment |
|---|---|
| Typed into this tool | Passes the policy, rendered as markdown |
| Supplied by a scan file | Shown as written, never rendered (REQ-66) |

| Rule | Reason |
|---|---|
| The origin decides, since both share a column | Otherwise a scan file's author formats text in the browsers of those with the most access |
| Escaping happens where text enters a document, and the origins stay distinguishable | |
| The release note and the issue document, served as markdown, escape every value that did not pass the policy (`design-docs/analytics-releases.md` § The release note, `design-docs/analytics-releases.md` § One issue across the estate) | |
| A webhook's subject and text are escaped line by line by the same rule (`design-docs/notifications-delivery.md` § Outbound HTTP) | |

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

A character is escaped where it opens syntax where it sits, and in the few
places it might: `--rc1` is `\--rc1`, since a line of three is a rule. Nowhere
else, because both documents are read as source, where `1\.2\.3` is noise.

## Refusals

A refusal carries the line, the offending text and the reason; every fault is
reported at once.

| Case | Line named |
|---|---|
| A refused link | Where it is written, searched from the link's own text |
| A destination written twice | Both lines; a copy in a fenced block above or earlier in the paragraph is not named |
| From a reference definition | The definition's line |
| Not appearing literally, spelled with a character reference | The first line of its block |
| A link with no text, and an autolink | Searched from the block's start, so an earlier copy in the paragraph is named |

## Code block language tags

The tag after three backticks reaches a class attribute, so it is allowlisted
(REQ-67); an unrecognized one keeps the block and drops the label.

| Rule | Reason |
|---|---|
| The allowlist is each renderer's own | This server emits no markup |
| Tests assert on rendered output | Asking an allowlist proves it agrees with itself |

## Bounds

Every field is capped at 64 KB (REQ-69), the whole bound, since nothing here
renders.

| Rule | Reason |
|---|---|
| The column holds what the cap admits, on every engine | Two engines' plain-text type tops out at 65,535 bytes: a field at the cap passes submission, then fails the write or is silently truncated outside strict mode. A one-engine test misses it |
| The cap applies before any parsing | It bounds the one parse, the submission check's |
| No time bound | A parse cannot be interrupted, so it would bound the wait and not the work |

## Limits

| Rule | Reason |
|---|---|
| A code block is not highlighted | Grammar coverage costs bundle size |
| A bare `scheme://` is an address; a bare `word:` is not | That matches `parser.go:112` and `TODO: check this`. Schemes that act carry no `//` and are matched separately |
