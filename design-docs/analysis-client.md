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
analyzer with what the output alone lacks, and sends each as
`design-docs/analysis.md` § The upload describes.

```
openpsirt-upload upload --product P --branch-or-tag B --variant V --series [TOOL=]NAME... \
  [--commit SHA] [--built TIME] [--snippets] [--salt-file FILE] \
  [--third-party PATH]... OUTPUT...
openpsirt-upload write --series [TOOL=]NAME... --output FILE OUTPUT...
```

`write` stores what `upload` would send.

## Formats read

| Format | Read as |
|---|---|
| clang `plist-multi-file` | A result per diagnostic: issue hash as `clang/issueHash/v1`, enclosing function as a logical location, path as a code flow with each step's function, each checker's documentation address. A document is a translation unit |
| cppcheck XML version 2 | A result per error. `error` and `warning` keep their level; `style`, `performance`, `portability` are notes; `information` and `debug` are dropped. CWE as `external/cwe/cwe-<n>`, hash as `hash/v1`, first location the result's and the rest related, with text |
| SARIF 2.1.0 | Forwarded, artifact and rule references resolved to paths and identifiers |
| Any of them gzipped | Decompressed first |

| Rule | Reason |
|---|---|
| A native format is read where one exists | clang's SARIF lacks hash, path and function |
| clang's plain `plist` is not to be sent | It drops cross-file diagnostics |
| HTML reports and output directories are refused | They carry source |
| One tool's outputs merge into one run: rules by identifier, results and invocations concatenated, unit counts added | |
| Several tools are one upload each; `write` names each file by tool before the extension; one refused does not stop the rest | A series is one tool |
| Several tools need `--series TOOL=NAME` each; bare `--series NAME` serves one tool | A shared name changes when tools change |
| `--rule`, `--rules-file`, `--tool-version`, `--exit-status` and `--units-analyzed` are refused for several tools | Each describes one |
| One tool named twice in `--series` is refused | |
| An output in no format read is refused, named, listing the formats | |

## Paths

Every path is written relative to the checkout with `/`, under `SRCROOT`, left
undefined, so the deployment places it (`design-docs/analysis-source.md`
§ Placement).

| Rule | Reason |
|---|---|
| Absolute, `file://`, relative and defined-starting-point paths are resolved, chains followed to sixteen steps | |
| A path with no starting point is relative to the client's directory | The client runs where the analyzer ran |
| Drive letters and paths on a drive compare ignoring case | Windows |
| Case is taken from the checkout's index, except where two indexed paths differ only by case | Case-insensitive systems write what was asked |
| A path is inside the checkout as written or with links along it and the checkout's path followed | git resolves links; tools may not |
| A path outside the checkout is written as its `file://` address | The deployment drops it |
| A path under an undefined starting point is left as written | |
| A region ending before it starts loses its end | |

## Repositories

| Rule | Reason |
|---|---|
| Every repository in the checkout is listed, submodules at every depth, as `versionControlProvenance` with commit and a `mappedTo` under `SRCROOT` | Results place by innermost repository; another chained starting point is not placed |
| The top commit is `--commit` or the checked-out one; submodules' are checked out | |
| A remote is written `https`, without credentials, port or `.git`, SSH and scp forms turned into host and path, a relative submodule address resolved against its parent | |
| A local-path remote is left out | Nobody else can reach it |
| Submodule paths and names are read whole, spaces included | |
| A repository with tracked changes is named in `openpsirt/changed` | No commit holds that code |

## Fingerprints

Each result carries `openpsirt/context/v1`, a content fingerprint of its line
(REQ-08).

| Rule | Reason |
|---|---|
| SHA-256 of the line and one either side, each trimmed with inner white space collapsed, joined by line feeds; beyond the file is empty | Reindenting, moving and line endings keep it |
| A trailing carriage return is removed first | |
| With `--salt-file`, HMAC-SHA256 keyed on the trimmed file | A short line cannot be guessed back |
| A salted run names its salt as `openpsirt/salt`, the first eight bytes of its SHA-256 in lower-case hex, and carries no tool fingerprint | A rotation is visible; a tool's own cannot be salted |
| Files are read only inside the checkout, links followed, up to 16 MiB | Nothing else on the build host is read |

## Contents sent

| Rule | Reason |
|---|---|
| No source leaves without `--snippets` | |
| With it, each location carries its lines and two lines of context either side, each at most 4,096 bytes, carriage returns removed | |
| Forwarded SARIF loses whole-file contents, fixes, attachments, snippets and markdown messages, counted in the output; a markdown-only message is reduced as the deployment reduces one | |
| A snippet is removed from every location: result, related places, flow steps, stack frames, shared flow steps, notification places | |
| A forwarded run's artifact list and starting points are removed | Paths are already resolved |
| Run parameters are written as `design-docs/analysis.md` § Run parameters reads them: `openpsirt/client`, `openpsirt/commit`, `openpsirt/series` or `automationDetails.id` with `--built`, both unit counts or neither, an invocation from `--exit-status` | |
| `--compile-commands` gives units expected by entry count; clang's units analyzed are documents read; expected units for a tool counting none analyzed are withheld, saying so | |
| Rule set and third-party paths go as upload fields | |

## Sending

| Rule | Reason |
|---|---|
| Gzipped, as the one `sarif` part, key as bearer token | The request bound is on compressed size |
| Address from `--url` or `OPENPSIRT_URL`; key from `OPENPSIRT_KEY` only | A command-line key shows in process listings |
| A 503 retries after `Retry-After`; a request reaching nothing retries with doubling pauses, five attempts, pauses at most two minutes | |
| A redirect is not followed, failing the step with its target | It would carry the token |
| The receipt is printed as returned; a refusal fails the step with its words | 202 means queued |

## Distribution

| Rule | Reason |
|---|---|
| One pure Go binary, cgo off, for Linux, macOS and Windows on amd64 and arm64 (`design-docs/packaging.md` § Release assets) | |
| Covered by the release's checksum file and signature | |
| No Authenticode signature or notarization | A pipeline's command fetch passes neither check; a browser download waits for a person |
| CI runs its tests on macOS and Windows when its sources move (`design-docs/build.md` § CI jobs) | Fingerprints under each line ending are pinned to hand-computed hashes |

## Limits

| Limit | Detail |
|---|---|
| macOS and Windows behavior is tested and unused | No pipeline here runs on either |
| A path with no starting point is placed by the client against its own directory, by the deployment against the output's working directory | One output sent both ways places differently when they differ |
