# Code finding source

Where a code finding is: the component it is placed on, links into its
repository, the source kept beside it, its evidence, and code the product did
not write.

Satisfies REQ-17, REQ-42, REQ-43, REQ-66.

## Contents

- [Placement](#placement)
- [Source](#source)
- [Repository settings](#repository-settings)
- [Source links](#source-links)
- [Snippets](#snippets)
- [Rule documentation](#rule-documentation)
- [Evidence](#evidence)
- [Third-party code](#third-party-code)
- [Limits](#limits)

## Placement

A code finding is one component at one occurrence (REQ-17), on the build's
newest read inventory.

| Rule | Reason |
|---|---|
| A result is placed on the component built from the innermost run repository holding its path | Only the inventory says which component a directory became |
| A component is built from the repository its package identifier names: `github`, `gitlab` and `bitbucket` by namespace and name, any type by `vcs_url` | |
| Else from its first CycloneDX external reference of type `vcs` | sonic-buildimage states one so on `pkg:deb` packages |
| Else into the first component whose CPE names its owner as vendor and name as product, lower case, hyphen and underscore alike | `cpe:2.3:a:frrouting:frr` is `github.com/FRRouting/frr`; weakest, so last |
| Repositories compare as host, owner and name, lower case, without scheme, credentials, port, revision or `.git` | SSH and HTTPS spellings are one repository |
| A result in no inventory repository is placed on the build | Every build has a root |

## Source

Every place links into the repository's web view at the analyzed commit, with
source kept beside it where the product allows. The deployment builds the
address and never requests it; the reader's browser does.

## Repository settings

Stated per product through the API or the Repositories screen
(`design-docs/interface.md` § The repositories screen), each change in the
administrative trail.

| Setting | Holds |
|---|---|
| Hosts | A remote prefix, a web address, and a style: `github`, `gitlab`, `gitea` (Forgejo writes Gitea's), or `custom` with a file template and optional comparison template |
| Paths | A checkout prefix with any of: a repository and branch for links where an upload names none, whether source is kept, whether kept source is disclosed with a flaw |

| Rule | Reason |
|---|---|
| A web address is `https`, with no credential, query or fragment | |
| A custom template begins `{repo}/` and names only `{commit}`, `{path}`, `{start}`, `{end}`, or `{from}` and `{to}` | Otherwise it could open another host |
| A remote prefix may hold a path, naming a mirror; the longest prefix covers a remote, and the rest is the repository under its web address | `git.example.com/mirror/github/FRRouting/frr` opens at `https://github.com/FRRouting/frr` |
| A path's repository and branch come together or not at all | |
| A path naming no repository and nothing of source is refused | |
| At most 100 hosts and 2,000 paths | sonic-buildimage pins dozens of submodules |
| Remotes and prefixes compare normalized: lower-case host, no edge slashes | |

## Source links

| Rule | Reason |
|---|---|
| A path is in the run repository with the longest prefix holding it | `src/sonic-sairedis/SAI/inc/saiport.h` is `inc/saiport.h` in SAI, at SAI's commit |
| A relative remote resolves against its parent's remote; an SSH remote reads as its host and path | `.gitmodules` uses both |
| A remote is recorded and shown without credential or query | A token would reach every reader |
| A remote on no host the product names is unlinked text | Its host is the uploader's choice |
| A revision links only as a commit, 7 to 64 hexadecimal digits | A branch moves, and `?` or `#` would steer the link |
| Each segment is percent-encoded; an empty, `.` or `..` segment unlinks the place | |
| A finished address must be `https` on the web address's host, or the place is unlinked | The last check after substitution |
| A repository whose working tree differed from its commit is marked patched | The link shows the source before the patch |
| A path no run repository holds links to the product's branch for its longest prefix, marked approximate | The commit is unknown, and the branch has moved since |
| A place with no line opens the file; an end before the start is the start | |
| A code finding no longer open carries its repository's comparison between the newest build seeing it and the first not, or says both are one commit, unpatched | Unchanged code means no fix there, and a build-time patch is invisible to commits |

An unlinked place says why: no repository, no named host, no commit, or a path
leaving the repository.

## Snippets

| Rule | Reason |
|---|---|
| Source is kept under the longest prefix stating so, nowhere else, off by default | A private product may forbid its source elsewhere |
| The upload's own statement of public paths decides nothing | A pipeline could mislabel a private path |
| Decided on arrival for the result, every step and related place; nothing outside the checkout; source not kept is counted as discarded and the upload accepted | A changed setting reaches later uploads |
| A context region is preferred, with its starting line | It is wider |
| At most `analysis.max_snippet` bytes per place, 4 KiB by default, the most the upload client sends | |
| A snippet is answered and shown as text (REQ-66) | It is uploaded data |
| Source is disclosed with a flaw under the longest prefix stating so, off by default, stripped elsewhere | One published flaw does not publish a private product's source (`design-docs/analysis-flaws.md` § Disclosure inclusion) |

## Rule documentation

A rule's documentation address becomes a `documentation` reference on its issue
where it is `https`, on the default port, with no credential, on an analyzer
documentation host: LLVM, Cppcheck, CodeQL, GitHub documentation, SonarSource,
Semgrep, PMD, SpotBugs, Find Security Bugs, Bandit, Pylint, Ruff, ESLint,
Staticcheck, golangci-lint, Clippy, Microsoft Learn and PVS-Studio. Any other is
dropped, being the uploader's choice of where a reader goes.

## Evidence

`GET …/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}`
answers one code finding on one build.

| Part | Holds |
|---|---|
| Where | Rule, place, the analyzer's path and related places, each with link and source |
| Sightings | Last seen; for one no longer open, first not seen, by which run, with the comparison, and the run a person named as fixing it |
| Commits | Beside each of those builds, the commit of its own repository, or the checkout top's; nothing where not a commit |
| Decision | The live decision, agreed or waiting, where the reader may read it |

| Rule | Reason |
|---|---|
| The occurrence identity addresses it | A rule name holds a slash |
| Read through the Evidence consumer, analysis kind alone (`design-docs/kinds.md` § Consumers) | |
| Read in the data layer at the subject's visibilities; one nobody may read answers as an empty occurrence (REQ-42, REQ-43) | |
| The open finding answers, else the newest | |
| Links are built when read, from the newest run's repositories and the settings | A host change reaches every place |

## Third-party code

A run declares paths holding code the product did not write
(`design-docs/analysis.md` § Run parameters). Their code findings are triaged
as any other.

| Rule | Reason |
|---|---|
| A declared path is a prefix as a repository is, sharing one confirmed component (`design-docs/analysis-flaws.md` § Flaw record offer) | Vendored code has no repository |
| The innermost repository or declared path holding a file is its prefix | |
| Declared paths are recorded from the checkout top, and compared that way | `./src/vendor`, `src//vendor/` and `/src/vendor` are `src/vendor`; `..` stops at the top |
| A declared path holds itself and what is under it, exactly | `src/vendor/zlib` holds `src/vendor/zlib/inflate.c`, not `src/vendor/zlibx/a.c` |
| The newest run seeing the code finding declares it | |
| A list not reading as paths declares nothing | |
| Evidence, flaw record offer, queue row and queue file say third-party | Its flaw is reported upstream, whose advisory returns through the supplier paths (`design-docs/ingest-claims.md` § Supplier advisories) |
| It is still recorded as a flaw here | It ships until the upstream fix arrives |

## Limits

| Limit | Detail |
|---|---|
| A snippet records what the upload sent | A patched repository's snippet is patched source while its link is not |
| The documentation hosts are a list in the code | Others are dropped until listed |
