# Data model

What a scan is filed against: products, branches and tags, variants and builds,
and the names they are declared under.

Satisfies REQ-07, REQ-15, REQ-17, REQ-32, REQ-52, REQ-54.

## Contents

- [Vocabulary](#vocabulary)
- [Branches and tags](#branches-and-tags)
- [Release dates](#release-dates)
- [End of support](#end-of-support)
- [Variants and builds](#variants-and-builds)
- [Declaration before use](#declaration-before-use)
- [Names](#names)
- [Engine differences](#engine-differences)
- [Limits](#limits)

`design-docs/data-model-components.md` holds what a component is and how it is
identified; `design-docs/data-model-graph.md` holds the graph, its history and
occurrences.

## Vocabulary

A scan is filed against **(product, branch or tag, variant)**. All three are
declared before anything may name them.

| Word | Means |
|---|---|
| Product | A thing that ships |
| Branch or tag | A branch or a tag of that product |
| Variant | One of the ways the product is built |
| Build | One branch or tag built as one variant, and the pair a scan is filed against |
| Occurrence | A component and what directly pulled it in |
| Finding | One component at one occurrence in one build. Twelve occurrences is twelve findings (REQ-17) |
| Group | One issue at one component across every occurrence it sits at. The row the findings list returns, and the thing somebody decides about |
| Report | A problem somebody reported to us, and the record that it arrived. It exists before anybody has judged it, and points at an issue only once somebody has (`design-docs/findings-reports.md` § Reports) |

Every count is of findings or of groups: twenty-five thousand rows a scan
produces against four hundred things somebody looks at.

| Term | Usage |
|---|---|
| Build | The word in prose, in responses, on screens and in the schema |
| Release | Not a level of the hierarchy. The act of shipping, and the version a fix arrives in |
| Occurrence | Spelled `occurrences` everywhere, never "locations" |

| Verb | Means | Not |
|---|---|---|
| Approve | A second person agrees to a decision | Agree, as a state |
| Decided | A group whose every occurrence is answered by a standing decision | Agreed. The wire value is `agreed`, the one place the word appears for this |
| Withdraw | Taking back something recorded: a decision, an approval, a role | Revoke, retract, remove, cancel. Retiring a team or a rule is not a taking-back |
| Hand back | Returning work to nobody | Release, which would make that word mean a third thing |

## Branches and tags

Branches and tags share one table. A branch moves and a tag does not; both carry
a product, variants, findings, an end-of-life date and declaration before use. A
tag records the branch it was cut from, where known: release readiness compares
a branch against it, and a new line seeds its decisions from it.

| Rule | Reason |
|---|---|
| The parent can be filled in afterwards, by declaring the tag again with the branch named (REQ-15) | Without it, release readiness reports the branch never released |
| Naming a different branch is refused | A tag is one frozen point |
| Only a tag has a parent, and it is a branch of the same product; declaring and filling in ask the same check | |
| A listed tag names its parent even when the parent is retired | The parent is a fact about the tag |

## Release dates

When a release went out is a date of its own (REQ-54), because the day a tag was
declared here is an accident of administration: before the release, months
after, or while backfilling a year.

| Rule | Reason |
|---|---|
| The release-over-release chart orders and labels its points by it | A year entered in an afternoon otherwise plots as one day |
| It falls back to the declaration date where nobody has stated one | |
| It can be corrected; the parent fills in once and never moves | The date is a fact about the world somebody may have got wrong |

## End of support

A date, not a flag (REQ-15): it answers "what goes out of support next
quarter", takes effect without anybody remembering, and is how lifecycle
policies are published.

| Rule | Reason |
|---|---|
| Set on a release, or on a product for every release with no date of its own | |
| A release with no date inherits rather than copying | A copy stops following the product the next time it moves. A screen shows a release's date and whose it is |
| Reversible | |
| Absent is not past | |
| Nothing is deleted or hidden past the date | |
| The comparison is spelled once, in the catalog | The same fact decides both effects below and what a screen says |

| Effect | Detail |
|---|---|
| No deadline | A finding on a release out of support carries none, or the overdue figure fills with releases nobody will fix. `design-docs/triage-severity.md` § Minimum severity |
| Silence is expected | A build that stops being scanned is not reported as quiet (REQ-52). It is still listed with how long it has been. `design-docs/ingest.md` |

## Variants and builds

| | Definition |
|---|---|
| Variant | Declared once per product, name unique within it. A chip, an architecture, an operating system: a property of the product, unchanged by a new release |
| Build | One release built as one variant. Recorded on first use, because a scan saying this release was built as that variant reports a fact |

The build is what a scan is filed against, so one identifier runs from a scan
through its graph to a finding.

| Rule | Reason |
|---|---|
| The variant list is not restated per release | Retyped, `win`, `windows` and `win32` across three releases are three variants |
| A variant introduced later does not appear in earlier releases | Those have no build of it |
| Each variant records whether it is customer-facing, defaulting to yes | It feeds ranking (REQ-32), and an unclassified artifact ranks as though it ships |
| An administrator corrects customer-facing; a pipeline redeclaring the variant with the other value is refused | It moves what everybody is told to work on first |
| Two pipelines filing the first scan for one build at once produce one row | Two rows are two histories for one thing somebody ships |

### Catalog corrections

What a product, a release or a variant is called can be wrong. These rules hold
at all three levels unless a row says otherwise. Each correction is an
administrative act, recorded with who did it and what it held before.

| Rule | Reason |
|---|---|
| The matching name and the spelling shown move together | Both derive from one string |
| A name another variant of the product holds is refused, retired ones included | Declaring it again brings that variant back |
| A name is refused once a document naming it has been published | OpenVEX documents and advisory product trees identify builds and releases by these names, so a rename reads as a second document or a customer no longer affected. Issued documents are kept as the bytes sent |
| A product's name is refused where a group mapping names it, before or after | A mapping names its product (REQ-41); configuration changes first |
| A release is asked about the advisories that named it, by holding an issue they cover, never about its product | Asked of the product, one named release blocks every sibling |
| An issue taken off an advisory after an issuance still counts; one taken off before does not | The first was on the document readers hold |
| An issue taken off an advisory and put back keeps one row, with the interval it was last on | The pair is unique. When it was first on is lost, so an issuance from before it was taken off reads as not naming it, and a rename that document should refuse is allowed |
| A product's displayed name moves freely | Nothing is identified by it. A release and a variant have no displayed name apart from their name |
| Whether a variant reaches customers stays correctable | It is in no document and identifies nothing |
| Whether a release is a branch or a tag, and a tag's branch, do not move | They say what a release is |

### Catalog retirement

A product, a release and a variant are retired, never deleted. The row and
everything filed against it stay. Retiring differs from an end-of-support date:
the date ends support and hides nothing; retiring says the thing is not tracked
here. It is an administrative act, recorded with who did it and what it held before.

| Rule | Reason |
|---|---|
| It is offered nowhere | The product's variant list and every picker reading it stop naming it |
| A release still names a retired variant among what it was built as | Its findings are still open somewhere |
| No scan may be filed against it, and the refusal says to declare it again | What changes is a build script |
| Everything already filed against it still resolves by name | Its findings, decisions and published documents |
| Declaring it again brings it back, matching what it reaches as any redeclaration does | A pipeline declares on every build, and tidying a list must not break it |
| Retiring a product writes nothing onto its releases and variants | They leave every list through the product, and bringing it back is then one write |
| A retired product or release is named by nothing | A kept link opens a page saying it is retired |
| Retiring one already retired is refused | Two administrators at once would both record it |
| One conditional write, matching only a row in use, retires every kind of row kept after retirement | A catalog part, a team, a destination, a supplier, an assignment rule and a response window share the refusal above |

## Declaration before use

A scan naming something undeclared is refused, naming which part is missing:
product, branch or tag, or variant (REQ-07). Created on demand, a typo in a
branch name becomes a branch with its own findings while the real one looks
unscanned.

| Rule | Reason |
|---|---|
| Declaring what is there succeeds and changes nothing | Two CI pipelines arriving together is ordinary |
| A declaration losing to another writer reads what won and confirms it, once and no further | The unique index refuses one of two inserts; a row that keeps disappearing is no race |
| Declaring something else under a known name is refused | A tag redeclared as a branch, or a product with another display name, is a name changing meaning |
| A display name is compared trimmed, as stored | Surrounding space is not part of it |

## Names

| Rule | Reason |
|---|---|
| Bounded: no surrounding space, nothing empty, a length counted in characters that keeps a unique index inside every engine's key limit | The column holds characters |
| Unique within the parent: a product globally, a branch or tag and a variant within their product | |
| Capitals do not distinguish two names | Typed into build scripts, `sonic` against `SONiC` is a typo |
| The normalized form is stored for matching, the spelling written beside it and shown | A lower-case value compares alike under any collation on all four engines |
| An identity a sign-in provider hands over is compared exactly | Deciding two accounts are one person merges access nobody granted |
| A component name is stored, reported and linked in the producer's spelling, and matched on its stored fold where a person types it | The fold the assignment rules and search match on |
| Two components differing only in capitals are both what a typed name means | A lookup answers with the choices; a filter keeps both |
| The producer's spelling names the one spelled that way | Links are built from the stored name, so a link reaches its component |
| A clash in capitals alone, at one version, ecosystem and namespace, is reached only by its own spelling | The choices tell components apart by those three |

## Engine differences

Only column declarations differ; everything queried is portable.

| Declaration | Reason |
|---|---|
| Generated keys | Three spellings for one idea |
| Timestamps | One engine has no `DATETIME`; another's `TIMESTAMP` acquires an implicit default and an on-update clause |
| Booleans | One engine has no boolean type |
| Text lengths | A unique index needs a bounded width on some engines |

MySQL and MariaDB enforce a tag's reference to its parent branch during a bulk
delete, where PostgreSQL and SQLite do not, so clearing branches and tags
detaches the parent first.

## Limits

| Limit | Detail |
|---|---|
| Which product a build belongs to is asked in one place | Two walks of the same three tables drift |
