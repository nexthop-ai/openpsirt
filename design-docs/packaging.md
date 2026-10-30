# Packaging and deployment

The container image, what it carries and where it keeps data, how the process
starts and stops, and how a deployment is configured.

Satisfies REQ-01, REQ-04, REQ-76, REQ-83, the start-up behavior REQ-72
requires, and the storage REQ-78 needs.

## Contents

- [Image structure](#image-structure)
- [Base version](#base-version)
- [Bundled scanner](#bundled-scanner)
- [CVE record snapshot](#cve-record-snapshot)
- [Repository copies](#repository-copies)
- [Pod sizing](#pod-sizing)
- [CPU priority](#cpu-priority)
- [Image and archive checks](#image-and-archive-checks)
- [Starting and stopping](#starting-and-stopping)
- [Configuration sources](#configuration-sources)
- [Limits](#limits)

## Image structure

Multi-stage: the interface built with node, the binary with the module's Go
toolchain, the result run on Alpine.

| Part | Detail |
|---|---|
| Size | ~40 MB |
| User | Non-root, no login shell, no home directory |
| Extras | The vulnerability scanner; git, for patch-link branches; root certificates; timezone data |
| Healthcheck | Liveness only; readiness needs the database and belongs to the orchestrator |

| Rule | Reason |
|---|---|
| The interface is built inside the image | The Go build embeds a git-ignored directory and an API-only binary is a supported build, so a clean checkout, as CI builds, would ship no interface silently. Docker is then the image's only requirement |
| The binary is static, CGO off | Part of why the pure-Go SQLite driver was chosen |
| The base is Alpine | An operator debugging a deployment wants a shell |

## Base version

Every stage but third-party toolchain images starts from one pinned build
argument, because what a finding means depends on what was measured.

| Rule | Reason |
|---|---|
| Every base is named by digest and tag, and `make pins-check` refuses a tag alone, or no tag | A re-pushed tag would be compiled into a signed release. The check reads every `FROM` past its flags |
| The base's packages are upgraded at build time (REQ-04) | A tag's package set froze at publishing. When the base moved from 3.21 to 3.24, 22 findings were against its packages, 20 of them OpenSSL `3.5.7-r0` fixed in `3.5.8-r0`, two critical, all through Alpine's own advisories. Upgrading clears them, and every older base has the same shape |

## Bundled scanner

The deployment runs the scan itself, so the image carries the scanner.

| Rule | Reason |
|---|---|
| The scanner is pinned and its download checksummed | Which scanner build answered is part of a finding |
| Its vulnerability data is fetched at run time | Baked in, it is stale a day later |
| The chart mounts a volume for the data, its directory one chart value both image and chart read | The root filesystem is read-only |
| Every replica mounts the one claim, and the chart refuses at render an access mode it can see is too narrow | This is a Deployment, with no volume per pod |

| The data lives on | Detail |
|---|---|
| Scratch space for the pod's life | The default; downloaded and imported on every start |
| A claim the chart makes | Off unless asked, since a claim appearing on upgrade surprises |
| A claim made elsewhere | Named instead, winning over the chart's; naming both is refused |

## CVE record snapshot

The snapshot lives in its own directory inside the scanner's data directory
(`design-docs/ingest-scanner.md` § CVE records). The chart derives it from the scanner's
directory, after `extraEnv`, so the two share a volume. The first fetch makes the
directory.

## Repository copies

Patch-link branch labels keep repository copies (REQ-78), used as
`design-docs/findings-patch-branches.md` describes.

| Rule | Reason |
|---|---|
| git is the distribution's package, run as a child | |
| The chart mounts a writable path; the image makes the directory, owned by the unprivileged user | The root filesystem is read-only |
| Scratch space unless a claim is named, bounded a fifth above the quota unless set | A copy arriving adds to those kept, and scratch past its bound evicts the pod |
| The quota is written as a whole number | A values file reads it as a float, and the server refuses 5.36870912e+10 |
| The scratch bound's built-in quota is held to the binary's by `make pins-check` | A quota above the volume evicts the pod |
| The chart makes no claim; a claim named in values is mounted | The deployment chooses its storage |
| The excluded hosts, the quota and turning lookups on are chart values; on sets `OPENPSIRT_PATCH_BRANCHES` | They are the deployment's boundary, never an administrator's setting, and need the chart's memory limit and volume |
| One replica fetches and every replica serves the labels | Labels are in the database. A shared claim must be ReadWriteMany, which the chart cannot check on a claim it did not make |

## Pod sizing

The container runs the server and the scanner as its child under one cgroup
limit, and the kernel kills the larger on excess.

| Rule | Reason |
|---|---|
| The limit is sized for both | Sized for the server alone, a scan dies while the pod stays up |
| The server's share is the ingest budget, about 250 MB per document read (`design-docs/ingest.md`), rising with its bounds | |
| The scanner's share is unbounded and unmeasured here | |
| Importing the vulnerability database is the largest draw, on every start where the data is not kept | |
| A first copy of a large repository is the other large draw, noted beside the chart's limit | The kernel's stable tree: 1.3 GB fetched whole, 0.6 GB where the host sends commits alone. The operator documentation asks for 4 GiB before turning patch branches on for the first |
| Neither default is measured against the scanner | Its memory moves with each release |

## CPU priority

| Rule | Reason |
|---|---|
| The scanner and git start at niceness 10 | Requests are answered while a scan or fetch runs |
| They are born at it, lowered on the forking thread, and their children inherit it | Set after start, git's children could already run at full priority |
| Niceness orders processes within the pod alone | Requests and limits share CPU between pods |
| A priority that cannot be lowered is logged, and the program runs | The platform refused something needing no privilege |

## Image and archive checks

| Check | Detects |
|---|---|
| The image runs | An unstartable image |
| It is not running as root | A security context regression |
| The bundled scanner runs | A scanner that does not execute on this base |
| It serves the interface | An image without one, answering the page with a credential refusal |
| The archive's binary serves the interface | The same, for the archive |

| Rule | Reason |
|---|---|
| The checks run on a release as well as a change | A release image is rebuilt with an upgraded base, and its scanner can break |
| The archive is asked the image's question in the same words, on a free port with a throwaway database | |

## Starting and stopping

| Rule | Reason |
|---|---|
| Everything contacted before serving is under one deadline, each step logged first | A silent hang looks like a slow image pull |
| Migrating is outside the deadline, which restarts after it | A large schema change outlasts any start |
| With automatic migration on, the port opens after the database connects and before the schema is applied | Health checks are answered throughout: 873 s for the v0.9.0 upgrade on a production-shaped PostgreSQL database |
| Until the start completes, `/healthz` answers 200, `/readyz` 503, and every other path 503 with `Retry-After` | The API answers in the refusal shape, a browser gets a page, anything else "OpenPSIRT is upgrading its database". Nothing reads the database |
| The router replaces the upgrading answer in one step, last; background passes start after | A request reaches one or the other whole |
| With automatic migration off, the port opens after every start-up check | |
| Every refusal reading no database precedes the port | Sign-in providers and return address, stores, the interface, queue sizes against the scanner timeout, the signing key |
| A refusal after the port opened closes it and exits 1 | The administrators, group mappings, and a sign-in provider other than the one identities were bound under follow the migration |
| An address already held is refused as the port opens, before migrating | |
| A stop signal during the start ends it, exiting 0 | The migration or the wait for another's sees it through its context. PostgreSQL and SQLite roll back; MySQL and MariaDB leave the schema part changed (`design-docs/database-migrations.md` § Migrations that stop half way), and the next start reapplies it |
| An unknown subcommand is refused | A typo would start a server |
| Background loops run from one list; the mail sender is absent with no channel and the attachment sweeper with no store | |
| Every exit waits for the background work, a failure to serve included | Each pass fires at once, so an early return leaves them mid-query as the database closes |
| One setting bounds both halves of the shutdown grace, which exit alike | Different exit codes would report half an unfinished shutdown as finished |
| The chart stops every earlier pod before starting a new one | Below 1.0 an upgrade may reshape tables the old release reads (REQ-76), and a ReadWriteOnce claim must move |
| A rolling update is the operator's choice, scaling to zero by hand before a schema change | Nothing serves between old pods stopping and a new one ready |
| The commands are `serve`, the default, and `migrate`, each taking `--config` before or after its name | |

## Configuration sources

A deployment is configured by environment variables or a configuration file,
never both (REQ-83).

| Rule | Reason |
|---|---|
| The file is TOML, named by `--config` | A variable naming it would sit beside the file |
| An `OPENPSIRT_` variable beside a file is refused at startup, naming each, empty ones included | The harness's variables are refused too |
| Library and child-program variables stay in both modes: `PATH`, `HOME`, `TMPDIR`, `TZ`, certificate and proxy variables, `PG` variables, `AWS_` variables, every `GRYPE_` variable | |
| One table defines each setting's variable and file key, read by both sources | A test holds it to the loader and the page (`design-docs/build-docs.md` § The settings reference) |
| Keys are tables by area, nesting for parts | `database.url` is `url` under `[database]`; `signin.oidc.issuer` is `issuer` under `[signin.oidc]` |
| File values pass through the environment's loader, spelled as the environment would: whole numbers, `true` or `false`, comma-joined lists | One path for every default and refusal |
| A value of the wrong type is refused, never converted | |
| An unknown key is refused, naming it | |
| A list entry holding a comma is refused | It would split |
| A malformed file is refused naming the line | |
| A file others may read or write is refused, asking for 0600 | It holds the secrets |
| A file owned by anyone but the process's user or root is refused | Its owner can rewrite it; a mounted secret is root's |
| The file is opened once, and every check is on what was opened | A swap between check and read would go unchecked |
| A directory or pipe is refused by path before opening, and the opened file must be the checked one | A writerless pipe hangs the start |
| A refusal stopping the process names the key, even after startup | The process rewrites variable names to keys on the way out |
| A refusal answered to a request names the setting both ways | It cannot be rewritten. The advisory prefix and the publisher are the two |
| A pod configured by file sets `enableServiceLinks: false` | A Service named `openpsirt` gives pods `OPENPSIRT_` variables |
| The chart configures by environment | Secrets arrive as variable references |
| The image sets no deployment variable; the scanner is on `PATH` | |

## Limits

| Limit | Detail |
|---|---|
| Nothing moves the pinned base either | Past end of life it gets no backports. Dependabot watches `FROM` lines; the scanner and inventory tool, versions and checksums in build arguments, are watched by nobody |
| Two builds of one commit can differ | The base's packages are upgraded at build; the image's inventory records what shipped |
| The packaging gate has one implementation, the target CI runs | |
| Text written ahead of time names a setting by its variable | A log line, screen hint, API reference or history entry cannot know the source; the configuration page pairs variables with keys |
| Nothing is fetched at run time from a source only this project controls, or gated on a key it issues | A mirrored image is complete, as Apache 2.0 delivery requires (REQ-01) |
