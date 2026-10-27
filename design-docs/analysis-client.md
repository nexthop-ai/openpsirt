# Upload client

`openpsirt-upload`, run in a pipeline beside the analyzer: what it reads, how
it writes paths, repositories and fingerprints, what it sends, and how it is
distributed.

Satisfies REQ-08.

## Contents

- [Upload client](#upload-client)
- [Formats read](#formats-read)
- [Paths](#paths)
- [Repositories](#repositories)
- [Fingerprints](#fingerprints)
- [Contents sent](#contents-sent)
- [Sending](#sending)
- [Distribution](#distribution)
- [Limits](#limits)

## Upload client

It reads the analyzer's output and the checkout, writes one SARIF run per
analyzer holding what the deployment cannot learn from the output alone, and
sends each as `design-docs/analysis.md` § The upload describes.

```
openpsirt-upload upload --product P --branch-or-tag B --variant V --series [TOOL=]NAME... \
  [--commit SHA] [--built TIME] [--snippets] [--salt-file FILE] \
  [--third-party PATH]... OUTPUT...
openpsirt-upload write --series [TOOL=]NAME... --output FILE OUTPUT...
```

`write` stores the document instead of sending it, so a pipeline sees exactly
what would leave.

## Formats read

| Format | Read as |
|---|---|
| clang `plist-multi-file` | One result per diagnostic: its issue hash as `clang/issueHash/v1`, its enclosing function as a logical location, its path as a code flow with each step's function, and each checker's documentation address. One document is one translation unit analyzed |
| cppcheck XML version 2 | One result per error. `error` and `warning` keep their level, `style`, `performance` and `portability` are notes, and `information` and `debug` are left out as describing cppcheck's own run. Its CWE as the tag `external/cwe/cwe-<n>`, its hash as `hash/v1`, the first location as the result's and the rest as related locations with their text |
| SARIF 2.1.0, from any tool | Forwarded, with artifact and rule references resolved to paths and identifiers, so nothing points into a list the client removes |
| Any of the three, gzipped | Decompressed first |

| Rule | Reason |
|---|---|
| A native format is read where the tool has one | clang's plist carries the issue hash, call path and enclosing function; its SARIF carries none |
| clang's plain `plist` is not what to send | It drops a diagnostic whose path crosses files |
| An HTML report and a directory of output are refused | Both carry source |
| One tool's outputs merge into one run | Rules merge by identifier, results and invocations concatenate, and per-unit counts add |
| Several tools' outputs are one upload per tool; `write` stores each in its own file, the tool's name before the extension, and one refused does not stop the others | A series is one tool |
| Several tools' output names each one's series, as `--series TOOL=NAME`; a bare `--series NAME` serves one tool | A series named once for all changes whenever a tool is added or dropped |
| `--rule`, `--rules-file`, `--tool-version`, `--exit-status` and `--units-analyzed` are refused for several tools' output | Each describes one tool |
| `--series TOOL=NAME` naming one tool twice is refused | Neither can be chosen without guessing |
| An output in none of the formats is refused, named, with the formats read | |

## Paths

Every path is written relative to the checkout, with `/`, under the starting
point `SRCROOT`, which the document leaves undefined, so the deployment places
it against the source root it is given (`design-docs/analysis-source.md`
§ Placement).

| Rule | Reason |
|---|---|
| A path arriving absolute, as a `file://` address, relative to the working directory, or under a defined starting point is resolved first; a chain of starting points is followed to sixteen steps | |
| A path naming no starting point is relative to the directory the client runs in | The working directory the output states is not read, so the client runs where the analyzer ran |
| A drive letter and a path on a drive compare without regard to case | Windows compares them so |
| A path's case is taken from the checkout's index, and left as written where two indexed paths differ only by case | A tool on a case-insensitive system writes the case it was asked for |
| A path is inside the checkout as written, or once the links along it and the checkout's own path are followed | git names the checkout with links followed, and a tool run through a link writes paths through it |
| A path outside the checkout is written as its `file://` address | The deployment drops and counts it |
| A path under a starting point the output never defines is left as written | Guessing its root places it wrongly |
| A region whose end is before its start loses its end | It states a line and no span |

## Repositories

| Rule | Reason |
|---|---|
| Every repository the checkout holds is listed, submodules at every depth | A result is placed by the innermost repository holding it |
| Each is a `versionControlProvenance` entry with its commit and directory, as a `mappedTo` under `SRCROOT` | A directory under another starting point chained to `SRCROOT` is not placed |
| The top repository's commit is `--commit`, or the commit checked out; the submodules' are the commits checked out | |
| A remote is written as a web address: `https`, no credentials, port or `.git`, an SSH or scp-style address made the host and path it names; a submodule's relative address resolves against its parent's remote | An SSH remote and an HTTPS identifier name one repository |
| A repository whose remote is a local path is left out | Nobody else can reach it |
| A submodule's path and name are read whole, spaces included | `.gitmodules` and `git submodule status` allow them |
| A repository with tracked changes is named in `openpsirt/changed` | Its results describe code no commit holds |

## Fingerprints

Each result carries `openpsirt/context/v1`, a content fingerprint of its line
(REQ-08).

| Rule | Reason |
|---|---|
| It is a SHA-256 of the line and one line either side, each trimmed and every inner run of white space one space, joined by line feeds; a line before the first or after the last is empty | A reindented or moved block keeps it, on any system's line endings |
| A carriage return ending a line is removed first | A Windows checkout's line endings are the checkout's |
| With `--salt-file`, it is an HMAC-SHA256 keyed on the file's trimmed contents | A short line cannot be recovered by hashing guesses |
| A salted run names its salt as `openpsirt/salt`: the first eight bytes of the salt's SHA-256, in lower-case hexadecimal | A changed salt changes every fingerprint, and the name says so |
| A salted run carries no fingerprint the tool wrote | A tool's own cannot be salted, and a short line is recovered from it |
| A file is read only inside the checkout, every link along its path followed, up to 16 MiB | A fingerprint or snippet reads nothing else off the build host |

## Contents sent

| Rule | Reason |
|---|---|
| No source text leaves unless `--snippets` is given | A run carries paths, lines and fingerprints |
| With `--snippets`, each location carries its lines and a context region two lines either side, each bounded at 4,096 bytes, carriage returns removed | |
| Whole-file contents, fixes, attachments, snippets and markdown messages in forwarded SARIF are removed and counted in what the client prints; a markdown message with no text takes the words its markdown shows, reduced as the deployment reduces one | |
| A snippet is removed from every location forwarded SARIF names: a result's own, its related places, flow steps and stack frames, a run's shared flow steps, and the places a notification names | Each is a region of source |
| A forwarded run's artifact list and starting points are removed | Every path is resolved before it is written |
| The run parameters are written as the deployment reads them (`design-docs/analysis.md` § Run parameters): `openpsirt/client`, `openpsirt/commit`, `openpsirt/series` or `automationDetails.id` where `--built` is given, the unit counts together or not at all, and an invocation from `--exit-status` | |
| `--compile-commands` gives the units expected as its entry count; for clang the units analyzed are the documents read; units expected for a tool counting none analyzed are not sent, and the client says so | |
| The rule set and third-party paths are sent as the upload's fields | The deployment reads them from the fields alone |

## Sending

| Rule | Reason |
|---|---|
| The document is gzipped and sent as the one `sarif` part, with the key as a bearer token | Output compresses several times, and the request bound is on the compressed size |
| The address is `--url` or `OPENPSIRT_URL`; the key is `OPENPSIRT_KEY` and nothing else | A key on a command line is in every process listing on the build host |
| A 503 is sent again after its `Retry-After`, and a request that reached nothing after a pause doubling each time, five attempts in all, no pause over two minutes | A matrix of builds finishing together each gets its turn |
| A redirect is not followed, and fails the step naming where it points | It would carry the bearer token wherever it points, plain HTTP included |
| The receipt is printed as returned, and a refusal fails the step with its words | A 202 says queued, and the counts are read from the run's receipt later |

## Distribution

| Rule | Reason |
|---|---|
| One binary, pure Go with cgo off, for Linux, macOS and Windows on amd64 and arm64 (`design-docs/packaging.md` § Release assets) | It runs where the analyzer runs |
| The archives are covered by the release's checksum file and its signature | As every other asset |
| No Authenticode signature and no notarization | A pipeline fetches the binary by command, which neither check stops. Downloaded through a browser on macOS or Windows, the system holds it until a person allows it |
| CI runs the client's tests on macOS and Windows when one of its sources moved (`design-docs/build.md` § CI jobs) | The fingerprints of one function under each line ending are pinned to hashes worked out by hand |

## Limits

| Limit | Detail |
|---|---|
| The client's macOS and Windows behavior is tested and not used | No pipeline here runs on either |
| A path naming no starting point is placed by the client against the directory it runs in, and by the deployment against the working directory the output states | One output sent both ways is placed differently when the analyzer ran outside the client's directory |
