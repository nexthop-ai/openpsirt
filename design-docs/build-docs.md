# Documentation build

The published documentation site, its versioned sets, and the checks held over
every document: links, make commands, release versions, scanner pins and the
settings reference.

Satisfies REQ-63.

## Contents

- [Documentation](#documentation)
- [Link check](#link-check)
- [Release version](#release-version)
- [Scanner pins](#scanner-pins)
- [The settings reference](#the-settings-reference)
- [Limits](#limits)

## Documentation

Built with mkdocs-material, published to GitHub Pages, sets versioned by `mike`
(REQ-63).

| Set | Published by |
|---|---|
| `main` | Every push to `main` |
| Each release, by version | The release workflow, which moves `latest` to the newest release (`design-docs/packaging-release.md` § The release procedure) |

| Rule | Reason |
|---|---|
| The default is `latest` once a release carries it, and `main` until then | Unreleased documentation at the root describes a version nobody can install |
| Every push to `main` resets the default | A default another run moved is put back |

## Link check

A test in `internal/docs` fails on a link reaching nothing; a test in
`internal/build` fails on a make command no makefile defines.

| Rule | Reason |
|---|---|
| A fragment is checked against its page's own renderer | |
| Pages under `docs/` use the site's anchors: ASCII-decomposed, punctuation removed, each run of spaces and hyphens one hyphen | |
| Other documents use the forge's: punctuation but underscores removed, each space a hyphen | A dash-separated heading takes two hyphens there and one on the site |
| A link to a directory or another file kind is checked for existence, ignoring fragment, query or title | |
| Links in code fences and inline code are not read | |
| Make commands are read inline in backticks and on their own line in a fenced block, after a prompt or variables | Prose lines are not read, since "make the claim" starts a line too |

## Release version

A page names the release a reader deploys as `{{ release }}`, which the build
fills.

| Build | Version written in |
|---|---|
| A release tag | The tag's version, as `DOCS_RELEASE`; a candidate's pages name the candidate |
| `main` | The newest release tag reachable from the commit, candidates left out |
| The CI check and a local `make docs-site` | As for `main` |
| None resolves | The build fails |

| Rule | Reason |
|---|---|
| A version is `X.Y.Z` or `X.Y.Z-rc.N`, `v` optional; anything else in `DOCS_RELEASE` fails | |
| Site workflows check out full history | A shallow checkout has no tags |
| A test fails on a hand-written release version in `README.md`, `SECURITY.md` or `docs/` | |
| `README.md` names no version | The site does not build it |
| The compatibility notes say a database any release built is upgraded in place, and one a candidate built is recreated | A candidate's migration can change before release (`design-docs/database.md` § Migrations) |

| Not reported | Reason |
|---|---|
| The configuration page's `From vX.Y.Z` upgrade notes | Past releases are their subject |
| Four numeric parts, or a version running into a letter | An address, or a third party's version |
| Example versions the test lists per page | A third party's or a customer's |

## Scanner pins

| Placeholder | Filled with |
|---|---|
| `{{ scanner }}` | The scanner version the image carries |
| `{{ scanner_sha256_amd64 }}`, `{{ scanner_sha256_arm64 }}` | The checksum the image verifies each download against, so a host checks the same pin |

| Rule | Reason |
|---|---|
| The hook declares every placeholder; the build fails on an undeclared one and an unfilled declared one | |
| Each pin is read from the Dockerfile's scanner stage, exactly once | Other stages pin checksums the same way |
| A written-out scanner version is reported | It is release-shaped |
| `${{ … }}` in a pipeline example is not a placeholder | It follows a dollar sign and holds a dot |
| A test fails on an undeclared placeholder, a declared one no page writes, and a pin the stage holds other than once | |

## The settings reference

The configuration page lists every setting with its environment variable, file
key, meaning and default. A set value that cannot be read stops the process
naming the setting.

| Held by a test | Reason |
|---|---|
| Every variable the loader reads is on the page, and every one on the page is read | |
| Each file key sits in its variable's row, and no other key appears | A key read into the wrong setting shows |
| The settings table in code is what the loader reads | A missing name is settable from neither source |

## Limits

| Limit | Detail |
|---|---|
| `README.md` and `docs/index.md` are compared from their first section to the end of their deployment section, link targets aside | Neither can include the other |
