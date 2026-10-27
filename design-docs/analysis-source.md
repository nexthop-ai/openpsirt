# Code finding source

Where a code finding is: the component it is placed on, the links into its
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

A code finding is one component at one occurrence (REQ-17).

| Rule | Reason |
|---|---|
| A result in a repository the run names is placed on the build's component built from the innermost repository holding its path | The inventory is the only statement of which component a directory became |
| A component is built from a repository its package identifier names: the `github`, `gitlab` and `bitbucket` types by namespace and name, any type by a `vcs_url` qualifier | |
| A component whose identifier names no repository is built from the first CycloneDX external reference of type `vcs` its inventory states | A distribution package's identifier names none; sonic-buildimage states one this way on `pkg:deb` packages |
| A repository nothing else names is built into the first component whose platform enumeration names its owner as vendor and its name as product, compared in lower case with hyphen and underscore alike | `cpe:2.3:a:frrouting:frr` is `github.com/FRRouting/frr`. The enumeration is weaker, so read only where nothing else names one |
| Repository addresses compare as host, owner and name, in lower case, without scheme, credentials, port, revision or `.git` | An SSH remote and an HTTPS identifier name one repository |
| A result in no repository the inventory names is placed on the build itself | Every build has a root |
| The inventory placed against is the build's newest read | A run arriving first waits for it |

## Source

Every place a code finding names links into the repository's web view at the
analyzed commit, and carries the source kept beside it where the product keeps
source under its path. The deployment builds an address and never requests it;
the reader's browser does, signing in where the repository is private.

## Repository settings

An administrator states them per product, through the API or the product's
Repositories screen (`design-docs/interface.md` § The repositories screen), and
each change is in the administrative trail.

| Setting | Holds |
|---|---|
| Hosts | Each a remote prefix, a web address, and a style: `github`, `gitlab`, `gitea` (Forgejo writes Gitea's), or `custom` with a file template and an optional comparison template |
| Paths | Each a checkout prefix with any of: a repository and branch for links where an upload names none, whether source under it is kept, whether kept source is disclosed with a flaw |

| Rule | Reason |
|---|---|
| A web address is `https`, with no credential, query or fragment | A scheme is something a browser acts on |
| A custom template begins with `{repo}/` and names only `{commit}`, `{path}`, `{start}` and `{end}`, or `{from}` and `{to}` for a comparison | A template beginning elsewhere could open on another host |
| A remote prefix may hold a path, which names a mirror: the host with the longest prefix covers a remote, and the rest of the remote is the repository under its web address | `git.example.com/mirror/github/FRRouting/frr` opens at `https://github.com/FRRouting/frr` |
| A path's repository and branch are named together or not at all | One alone is no link |
| A path naming no repository and saying nothing of source is refused | It says nothing |
| A product states at most 100 hosts and 2,000 paths | sonic-buildimage pins dozens of submodules |
| Remotes and prefixes compare normalized: host in lower case, path with no leading or trailing slash | One repository written two ways is one entry |

## Source links

| Rule | Reason |
|---|---|
| A path is in the run's repository with the longest prefix holding it, and the rest is within that repository | `src/sonic-sairedis/SAI/inc/saiport.h` is `inc/saiport.h` in SAI, at SAI's commit |
| A relative remote resolves against the remote of the repository holding it, resolved the same way; an SSH remote reads as the host and path it names, with or without a user | `.gitmodules` uses both |
| A remote is recorded and shown with any credential and query taken out | It comes from the upload, and a token in it would reach every reader |
| A remote on no host the product names is shown as text, unlinked | Without the list, its host is the uploader's choice |
| A revision opens a link only where it is a commit, 7 to 64 hexadecimal digits | A branch moves, and `?` or `#` in it would steer the link |
| Each path segment is percent-encoded, and a segment empty, `.` or `..` leaves the place unlinked | `?`, `#` and traversal would steer the link |
| A finished address must open over `https` on the host the web address names, or the place is unlinked | The last check, after every template and substitution |
| A repository whose working tree differed from its commit when analyzed is marked patched | The link shows the source before the patch |
| A path no run repository holds links to the branch the product names for its longest prefix, marked approximate | The commit is unknown |
| A place with no line opens the file; an end before the start is the start | |
| A code finding the build no longer holds open carries a comparison of its repository between the build of the newest run that saw it and the first that did not, or says both name the same commit and neither was patched | A disappearance where the code did not change is no fix in that code, and a build-time patch is a change no commit shows |

Each unlinked place says why: no repository known, the repository on no named
host, the revision not a commit, or the path leaving the repository.

## Snippets

| Rule | Reason |
|---|---|
| Source is kept under a path where the longest prefix stating it says so, and nowhere no prefix states it | Off by default: a private product may not allow its source elsewhere, and may carry public upstreams that do |
| The upload's own statement of which paths are public decides nothing | A misconfigured pipeline could label a private path public |
| Source is decided as an upload arrives, for the result and every step and related place, and a place outside the checkout keeps none | A changed setting reaches the uploads after it |
| A context region's source is preferred to its region's, with the line it starts at | It is the wider |
| At most `analysis.max_snippet` bytes are kept per place, 4 KiB where nobody has said | A client sends a few lines either side |
| A snippet is answered and shown as text (REQ-66) | It is uploaded data |
| Source is disclosed with a flaw under a path where the longest prefix stating it says so, and stripped everywhere else | Off by default: a private product's source is not published because one flaw in it was (`design-docs/analysis-flaws.md` § Disclosure inclusion) |

## Rule documentation

A rule's documentation address is recorded as a `documentation` reference on
its issue where it is `https`, on the default port, with no credential, on a
host analyzers document rules on: the LLVM, Cppcheck, CodeQL, GitHub
documentation, SonarSource, Semgrep, PMD, SpotBugs, Find Security Bugs, Bandit,
Pylint, Ruff, ESLint, Staticcheck, golangci-lint, Clippy, Microsoft Learn and
PVS-Studio hosts. Any other address is dropped: it comes from the upload, so a
host outside the list is the uploader's choice of where a reader is sent.

## Evidence

`GET …/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}`
answers one code finding's evidence on one build.

| Part | Holds |
|---|---|
| Where it is | Its rule, its place, the analyzer's path to it and the related places, each with its link and source |
| Sightings | When it was last seen; for one no longer open, when it was first not seen, by which run, with the comparison above, and the run a person named as the build that fixed it |
| Commits | Beside each of those two builds, the commit of the code finding's own repository: the run's repository holding its path, or the top of the checkout where none does, nothing where that is not a commit |
| Decision | The live decision at the code finding, agreed to or waiting, where the reader may read one |

| Rule | Reason |
|---|---|
| The occurrence identity addresses a code finding | A rule's name holds a slash |
| It is read through the Evidence consumer, which includes the analysis kind alone (`design-docs/kinds.md` § Consumers) | Nothing of a code finding reaches a vulnerability consumer |
| It is read in the data layer at the visibilities the subject reads in the product, and one nobody may read answers as an occurrence holding nothing (REQ-42, REQ-43) | Another answer would say a code finding is there |
| The open code finding is answered, or the newest where none is open | A reappearance opens a new finding at the same occurrence |
| Every link is built when read, from the newest run's repositories and the product's settings | A change to the hosts reaches every place at once |

## Third-party code

A run declares the paths holding code the product did not write
(`design-docs/analysis.md` § Run parameters). A code finding under one is
triaged and confirmed as any other.

| Rule | Reason |
|---|---|
| A declared path is a prefix in its own right, as a repository is | Vendored code has no repository of its own; every file under it shares one prefix and one confirmed component (`design-docs/analysis-flaws.md` § Flaw record offer) |
| The innermost of the run's repositories and declared paths holding a file is its prefix | A repository nested in vendored code names its own component |
| A declared path is recorded from the top of the checkout, and a code finding's path compared in that form | `./src/vendor`, `src//vendor/` and `/src/vendor` are `src/vendor`, and `..` climbs no higher than the top |
| A declared path holds itself and every path under it, compared exactly | `src/vendor/zlib` holds `src/vendor/zlib/inflate.c` and not `src/vendor/zlibx/a.c`; paths are case-sensitive |
| The declaration read is the newest run's to see the code finding | It is the description the path was read against, as its repositories are |
| A list that does not read as paths declares nothing | The upload writes paths from the top of the checkout |
| The evidence, the flaw record offer, the queue's row and the queue's file say it is third-party | The person recording the flaw reports it upstream, whose advisory or VEX then reaches the product's builds (`design-docs/ingest-claims.md` § Supplier advisories) |
| A third-party code finding is still recorded as a flaw here | The flaw ships in the product's builds until the upstream's fix arrives |

## Limits

| Limit | Detail |
|---|---|
| A link reaches only the repositories a product names a host for | A repository on none is shown as its remote, as text |
| A snippet records what the upload sent | Nothing compares it with the repository, so a patched repository's snippet is the patched source while its link is the source before the patch |
| A link in a code finding no run repository holds is to a branch | It is marked approximate, and the branch has moved since the build whenever anybody pushed |
| The documentation hosts are a list in the code | An analyzer documenting rules elsewhere has its documentation dropped until the list names it |
