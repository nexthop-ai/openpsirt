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

Multi-stage: the interface built with node, the binary built with the Go
toolchain the module declares, the result run on Alpine.

| Part | Detail |
|---|---|
| Size | ~40 MB |
| User | Non-root, no login shell, no home directory |
| Extras | The vulnerability scanner; git, for labeling patch links with branches; root certificates for outbound TLS to the ranking feeds and the scanner's data; timezone data |
| Healthcheck | Liveness only; readiness needs the database and belongs to the orchestrator |

| Rule | Reason |
|---|---|
| The interface is built inside the image, never taken from the build context | The Go build embeds a git-ignored directory and tolerates it empty, so an image from a clean checkout, as CI builds, would carry no interface and nothing would report it. It also limits the image's requirements to docker |
| The binary is fully static, with CGO off | Part of why the pure-Go SQLite driver was chosen |
| The base is Alpine | `scratch` or distroless would work; a self-hosted operator debugging a deployment wants a shell |

## Base version

Every stage that is not a third-party toolchain image starts from one build
argument, so the stages cannot drift. The version is pinned, because what a
finding means depends on what was measured.

| Rule | Reason |
|---|---|
| Every base image is named by digest as well as tag, and `make pins-check` refuses one named by tag alone | A tag is a name its owner can move, and a re-pushed one would be compiled into a release signed with this project's identity. The tag stays for a reader. The check reads every `FROM` past its flags, and a base with no tag, its `latest`, is refused the same way |
| The packages inside the base are upgraded at build time (REQ-04) | A base tag's package set froze when it was published, so pinning alone keeps shipping what was known vulnerable on that date. The day the base moved from 3.21 to 3.24: 22 findings against the distribution's packages, 20 of them OpenSSL `3.5.7-r0` fixed in `3.5.8-r0`, two critical, all matched through Alpine's own advisories |

## Bundled scanner

The deployment runs the scan itself, so an image without a scanner accepts
inventories it can never answer for.

| Rule | Reason |
|---|---|
| The scanner is pinned to a version and its download checksummed | Which build of a scanner answered is part of what a finding means |
| Its vulnerability data is fetched at run time | A database baked into an image is stale the day after publishing |
| The chart mounts a volume for the data, and the image and chart read its directory from one chart value | The data needs a writable path, and the root filesystem is read-only |
| Every replica mounts the one claim, and the chart refuses at render the access-mode pairing it can see | This is a Deployment, never a set with a volume per pod, so the access mode must allow as many nodes as replicas |

| The data lives on | Detail |
|---|---|
| Scratch space lasting as long as the pod | The default, so an install needs no storage. Downloaded and imported again on every start |
| A claim the chart makes | Off unless asked for; storage provisioned on an upgrade surprises an install that had none |
| A claim made elsewhere | Named instead, and wins over the chart's. Naming both is refused |

## CVE record snapshot

The CVE record snapshot is kept on the scanner's data volume, in a directory of
its own inside the scanner's (`design-docs/ingest.md` § CVE records). The chart
names it from the scanner's directory, after anything in `extraEnv`, so the two
cannot name different volumes. The first fetch makes the directory, so the image
makes nothing for it.

## Repository copies

Labeling a patch link with the branches holding its commit keeps copies of
repositories (REQ-78); `design-docs/findings-patch-branches.md` says how they are
used.

| Rule | Reason |
|---|---|
| git is the distribution's package, run as a child | Nothing of it is linked into the binary |
| The chart mounts a writable path for the copies, and the image makes the directory owned by the unprivileged user | The root filesystem is read-only |
| Scratch space unless a claim is named, bounded a fifth above the quota unless set | A copy arriving adds to those kept, and scratch past its bound gets the pod evicted. It holds nothing until the lookups are on |
| The quota is written as a whole number whatever the values file holds | A values file reads a whole number as a float, and the server refuses 5.36870912e+10 |
| The built-in quota the scratch space is sized for is the binary's own, held to it by `make pins-check` | Two copies in two languages drift, and a quota larger than the volume gets the pod evicted |
| The chart makes no claim for it; a claim named in values is mounted instead | A deployment turning this on chooses its storage |
| The excluded hosts, the quota, and turning the lookups on are chart values; turning them on sets `OPENPSIRT_PATCH_BRANCHES` | They are the deployment's boundary, and nothing works until the memory limit, volume and excluded hosts are set in the chart |
| One replica fetches, and every replica serves the labels | The labels are in the database and the copies on one replica's disk. A shared claim must be ReadWriteMany, which the chart cannot check on a claim it did not make |

## Pod sizing

The container holds two processes that use memory, the server and the scanner
it starts as a child. A cgroup limit covers both, and the kernel answers an
excess by killing the larger.

| Rule | Reason |
|---|---|
| The limit is sized for both processes | Sized for the server alone, a scan dies, and reads as a failed run while the pod stays up |
| The server's share is the ingest budget | About 250 MB for one document being read, set by `design-docs/ingest.md`, each bound configurable. Raising them raises the limit |
| The scanner's share is bounded by nothing here | It is somebody else's program, its report is bounded only once written, and what it needs is not measured |
| Importing the vulnerability database is the largest single draw | It happens on every start where the data is not kept, so keeping the data takes it off the common path |
| A first copy of a large repository is the other large draw, and the chart says so beside the limit | Off unless patch branches are on. The kernel's stable tree: 1.3 GB fetched whole from git.kernel.org, 0.6 GB where the host sends commits alone. Either can coincide with a scan, so the operator documentation asks for 4 GiB before turning it on |
| Neither default is measured against the scanner | Its memory moves with each release. Both follow the shape: two processes, one unmeasured, and a peak at start |

## CPU priority

| Rule | Reason |
|---|---|
| The scanner and git start at niceness 10 | Both are background work sharing the pod's CPU, so a request is answered while a scan or fetch runs |
| They are born at it, and what they start inherits it | The priority is lowered on the thread that forks them; set after start, git's own children could already run at the server's |
| Niceness orders the processes inside one pod | Sharing between pods is the pod's requests and limits |
| A priority that cannot be lowered is logged and the program runs anyway | Lowering one's own priority needs no privilege, so this is a platform refusing |

## Image and archive checks

The only places these claims are tested.

| Check | Detects |
|---|---|
| The image runs | An unstartable image |
| It is not running as root | A security context regression |
| The bundled scanner runs | A scanner binary that does not execute on this base |
| It serves the interface | An image built with no interface, which answers the page's path with a credential refusal |
| The archive's binary serves the interface | The same, in the form somebody runs by hand |

| Rule | Reason |
|---|---|
| The checks run against a release as well as a change | A release image is built from a fresh checkout with its base upgraded, so it differs from what a merge was gated on, and its scanner can break in between |
| The archive is asked the image's question in the same words, started on a free port with a throwaway database | The two cannot drift |

## Starting and stopping

| Rule | Reason |
|---|---|
| Everything contacted before the server serves is under one deadline, and each step logs what it is about to do | An endpoint accepting the connection and never answering otherwise holds the process with no log line, which looks like a slow image pull |
| Migrating is outside that deadline, which starts again once the schema is in place | A schema change on a large table takes longer than a deployment starts in |
| With automatic migration on, the port opens after the database connects and before the schema is applied | A platform's health check is answered throughout, so nothing ends the migration part way. 873 s for migration 43 on a production-shaped PostgreSQL database |
| Until the start completes, `/healthz` answers 200, `/readyz` 503, and every other path 503 with `Retry-After` | The API answers in the refusal shape, a browser gets a page, anything else the sentence "OpenPSIRT is upgrading its database". Nothing in it reads the database |
| The router replaces the upgrading answer in one step, after everything else in the start; the background passes start after the swap | A request reaches one or the other whole |
| With automatic migration off, the port opens after every start-up check | Nothing long is waited on |
| Every refusal reading no database comes before the port opens | Sign-in providers and their return address, the stores, the interface, the queue's sizes against the scanner's timeout, the signing key. A bad value is refused in seconds, before a migration |
| A refusal after the port opened closes it and exits 1 | The refusals reading the schema follow the migration: the administrators, the group mappings, a sign-in provider other than the one identities were bound under |
| An address somebody else holds is refused as the port opens, before the migration | A start that cannot serve spends no migration finding out |
| A stop signal during the start ends it and exits 0 | It reaches the migration, or a wait for another process's, through its context, and the stopped step's error is logged. PostgreSQL and SQLite roll the migration back; MySQL and MariaDB leave the schema part changed (`design-docs/database.md` § Migrations that stop half way). The next start applies it again |
| An unknown subcommand is refused | Ignored, a typo in a migration job starts a server against whatever schema is there |
| Background loops run beside the server from one list; the mail sender is absent where no channel is configured and the attachment sweeper where no store is | Every other pass runs whatever a deployment has, and the list shows what runs |
| Every exit waits for the background work, a failure to serve included | Each pass starts on a timer firing at once, so returning early leaves them mid-query as the database closes, and an orderly failure becomes failed scans and retried jobs |
| One setting bounds both halves of the shutdown grace, and both answer the same way | An overrun request exiting 1 and an overrun worker exiting 0 would tell a supervisor half an unfinished shutdown finished |
| The chart stops every pod of the earlier release before starting one of this one | Below 1.0 an upgrade may drop and reshape tables the earlier release reads (REQ-76). A ReadWriteOnce claim moves too, where a rolling update leaves the new pod waiting for the volume |
| A rolling update is the operator's choice | Nothing answers between the old pods stopping and a new one ready, and a failed upgrade leaves nothing serving. A deployment that must stay up chooses it, and scales to zero by hand before a schema-changing upgrade |
| The commands are `serve`, which is also what no command means, and `migrate`; each takes `--config` after its name as well as before | |

## Configuration sources

A deployment is configured by environment variables or by a configuration file,
never both (REQ-83).

| Rule | Reason |
|---|---|
| The file is TOML, named by `--config` on the command line | A variable naming it would be one of the deployment's own set beside the file |
| A variable whose name begins `OPENPSIRT_` beside a file is refused at startup, naming every one | Set but empty counts as set. The harness's own variables share the prefix and are refused the same way |
| Variables the deployment's libraries and children read stay in the environment in both modes | `PATH`, `HOME`, `TMPDIR`, `TZ`, the certificate and proxy variables, the PostgreSQL driver's `PG` variables, the object store client's `AWS_` variables, every `GRYPE_` variable. None is a setting of this deployment |
| Every setting has one environment name and one file key, defined together in one table both sources read through | A test holds the table to the loader and the configuration page (`design-docs/build-docs.md` § The settings reference) |
| A file's keys are tables by area and a key within, nesting where an area has parts | `database.url` is `url` under `[database]`; `signin.oidc.issuer` is `issuer` under `[signin.oidc]` |
| A file's values pass through the environment's loader, spelled as the environment would: a whole number, `true` or `false`, a list joined with commas | Every default, validation and refusal is one path |
| A value of the wrong type is refused, never converted | A quoted number or a switch written as a word is a mistake a typed format makes visible |
| An unknown key is refused, naming it | A misspelled key otherwise configures nothing silently |
| A list entry holding a comma is refused | The loader reads a list as the environment carries it, splitting the entry |
| A malformed file is refused naming the line | |
| A file anybody but its owner may read or write is refused, saying to set 0600 | It holds the database password and the sign-in and store secrets; a file somebody else can change is a configuration somebody else chose |
| A file owned by a user other than the process's own or root is refused | Its owner can rewrite it whatever its mode; a mounted secret is root's |
| The file is opened once, and every check is made on what was opened | Checked and read by path, a file swapped between the two is read unchecked |
| A directory or a pipe is refused by path before opening, and the file opened must be the one checked | Opening a pipe with no writer waits, holding the start with nothing logged |
| A refusal that stops the process names the key, never the variable, one made after startup began included | The process rewrites each variable's name in a refusal to its key on the way out |
| A refusal answered to a request names the setting both ways | It cannot be rewritten on the way out, and its relayed reader may use either source. The advisory prefix and the publisher are the two |
| A pod configured by file sets `enableServiceLinks: false` | Kubernetes gives a pod variables for every Service in its namespace, and a Service named `openpsirt` produces `OPENPSIRT_` ones, refused beside a file |
| The chart configures by environment | Its secrets arrive as references into variables, as a cluster does with a Secret |
| The image sets no variable of the deployment's own; the scanner is found on the image's `PATH` | A file would be refused beside it |

## Limits

| Limit | Detail |
|---|---|
| Pinning the base means nothing moves it either | Past a base's end of life its packages get no backports. Dependabot watches what a `FROM` line names, the base images and the Go toolchain; the scanner and the inventory tool, each a version and checksum in a build argument, are watched by nobody |
| Two builds of one commit can differ | The base's packages are upgraded at build time. The image carries an inventory of itself, so what shipped is recorded |
| The packaging gate has one implementation, the target CI runs | Written twice, in the makefile and the workflow, neither copy would be a superset |
| Pinned pairs are compared, never trusted | `design-docs/build-dependencies.md` § Pinned pairs lists them, and catches a build argument given two defaults |
| Text written ahead of time names a setting by its variable whatever the source | A log line, a screen hint, the API reference and a recorded history entry cannot know the source; the configuration page pairs each variable with its key |
| Nothing is fetched at run time from a source only this project controls, and nothing is gated on a key it issues | An operator mirroring the image has the whole thing, which Apache 2.0 delivery requires (REQ-01) |
