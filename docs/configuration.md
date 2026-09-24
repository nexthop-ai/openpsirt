# Configuration

Every setting comes from the environment, and every name starts with
`OPENPSIRT_`. Each one has a working default, so the process starts with
nothing set but a database — and a value that is set and cannot be read stops
the process with the variable named, rather than falling back to the default.
A switch spelled wrongly that silently reads as its opposite is worse than a
refusal to start.

A switch takes `true` or `false` (also `1`, `0`, `t`, `f`, in any case). A
duration is written as Go reads it: `30s`, `5m`, `12h`. A number is a positive
whole number; zero reads as unset everywhere, so it is refused rather than
taken.

## Features

What this deployment does beyond scanning and triage, and what turns each on.
Everything marked off does nothing until the thing in the last column is set.

| Feature | Default | Turned on by |
|---|---|---|
| [Scheduled rescanning](#scanning) | On, daily | `scanning.every` under Settings sets how often |
| [Vulnerability data updates](#an-air-gapped-install) | On | `GRYPE_DB_AUTO_UPDATE`; set it to `false` where the deployment cannot reach the network |
| [Upstream currency](#upstream-currency) | Off | `upstream.currency` under Settings |
| [Patch branches](#patch-branches) | Off | `OPENPSIRT_PATCH_BRANCHES`, or `patchBranches.enabled` in the chart. [What to set first](#enabling) |
| [Supplier advisories](#supplier-advisories) | Off | Naming a supplier under Settings |
| [Mail](#mail) | Off | `OPENPSIRT_MAIL_FROM` and `OPENPSIRT_MAIL_SERVER`, both |
| Webhooks | Off | Adding a destination under Settings |
| [Attachments](#attachment-storage) | Off | `OPENPSIRT_ATTACHMENT_BUCKET`, or `OPENPSIRT_ATTACHMENT_DIR` for a trial |
| [Advisory generation](#advisory-publication) | Off | `OPENPSIRT_PUBLISHER_NAME` and `OPENPSIRT_PUBLISHER_NAMESPACE`, both |
| [The published advisory directory](#the-published-advisory-directory) | Off | `OPENPSIRT_DIRECTORY_URL` and a bucket or directory to write to, with advisory generation on |

A sign-in method is not in this list because one is required: the process
refuses to start without one. [Sign-in](#sign-in) says which.

## Upgrading

A database built by v0.1.0 or v0.2.0 is upgraded in place, at startup or by
`openpsirt migrate up`. One built by v0.1.0 passes through the v0.2.0 upgrade on
the way. A database built by any build between releases is recreated.

Read the sections for the release you are coming from, and every section after
it: from v0.1.0, read all three.

### Every upgrade

| Step | |
|---|---|
| Back the database up | On MySQL and MariaDB an upgrade that fails part way leaves the schema half changed, and the backup is what recovers it |
| Stop every process of the earlier release | With the Helm chart, scale the deployment to zero first. The upgrade from v0.1.0 drops and reshapes tables v0.1.0 reads and writes, so a replica left serving fails on them |
| Deploy this release | It migrates at startup. With `autoMigrate: false`, run `openpsirt migrate up` first |

Going back is `openpsirt migrate down`, once for each release stepped back, run
with this build before the earlier one is deployed. v0.1.0 started against an
upgraded schema reports it current and cannot read it.

### From v0.1.0

| Change | What to do |
|---|---|
| `private-read` and `private-triage` reach undisclosed findings only. In v0.1.0 they reached disclosed findings too | Grant `public-read` or `public-triage` beside them, directly, in a group binding or in a token's holds, wherever somebody should keep the disclosed findings. Nothing is granted on upgrade |
| The setting `disclosure.extension-threshold` is `disclosure.movement-threshold` | Nothing. The value is carried across by the upgrade |

| After the upgrade from v0.1.0 | |
|---|---|
| An advisory v0.1.0 issued | Keeps the tracking identifier it was issued under. v0.1.0 did not keep the documents it issued, so a published directory leaves the advisory out until it is issued again |
| A reported flaw | Has a reference, minted as one recorded today would be |

### From v0.2.0

Also read after an upgrade from v0.1.0.

| Change | What to do |
|---|---|
| `OPENPSIRT_PATCH_EXCLUDED` is `OPENPSIRT_OUTBOUND_EXCLUDED`, and the chart's `patchBranches.excluded` is `outbound.excluded` | Move the list. The old name is refused at startup, and the chart refuses to render with the old key set |
| The excluded list also keeps supplier directories out, and a supplier is read from every host its description names | Set `outbound.excluded` wherever suppliers are configured |
| Patch branch lookups are turned on in the deployment's configuration. The `patch.branches` setting is gone | Set `patchBranches.enabled: true` in the chart, or `OPENPSIRT_PATCH_BRANCHES=true`. A deployment that had the setting on has the lookups off until then. [What to set first](#enabling) |

| After the upgrade from v0.2.0 | |
|---|---|
| A report | Sent in from outside |
| A flaw recorded here with a severity in force in its product | Rated at its first recording in that product. Its deadline counts from there, on the windows for flaws in our own product |
| A flaw recorded here with no severity in force | Not rated, and with no deadline |
| A flaw recorded with nobody named as reporting it | Found here. It has no disclosure date |
| A component | Has no license until a scan reads one from its inventory |

## Serving

| Variable | Meaning | Default |
|---|---|---|
| `OPENPSIRT_ADDR` | The `host:port` the HTTP server listens on | `:8080` |
| `OPENPSIRT_BASE_URL` | The address people arrive on, **written in full and with no path below it**: `https://psirt.example.com`. Behind a proxy that is not what the process thinks it is called, and a sign-in provider compares the address it sends people back to against what it was registered with, so it is stated rather than guessed. Required once a provider is configured | unset |
| `OPENPSIRT_PLAIN_HTTP` | Serve without TLS, which is what running locally looks like. It only loosens cookies: the session cookie is sent over plain HTTP, which it otherwise is not | `false` |
| `OPENPSIRT_SHUTDOWN_GRACE` | How long requests in flight get to finish on a stop signal, and then how long background work gets to finish after that | `15s` |
| `OPENPSIRT_STARTUP_TIMEOUT` | How long everything contacted before the server listens has to answer: the database, the schema, the administrators named here, and the attachment store. Past it the process stops and names what it was waiting on | `60s` |
| `OPENPSIRT_LOG_LEVEL` | `debug`, `info`, `warn` or `error` | `info` |
| `OPENPSIRT_LOG_FORMAT` | `text` or `json` | `text` |

The defaults above are the binary's. The chart sets a log format of `json`,
because a cluster's collector parses the logs; run the binary yourself and it
writes `text`.

## Database

| Variable | Meaning | Default |
|---|---|---|
| `OPENPSIRT_DATABASE_URL` | Which database and how to reach it: `postgres://user:password@host:5432/name`, `mysql://…`, `mariadb://…`, or `sqlite:///absolute/path.db`. SQLite is for development and a single-pod trial, never production. Encryption is negotiated but not required — see below. **Required** | unset |
| `OPENPSIRT_AUTO_MIGRATE` | Apply outstanding schema changes at startup, so deploying the binary is the whole upgrade. Turn it off to run `openpsirt migrate up` yourself, under different credentials, at a time you choose. With it off, a process whose database is behind the build refuses to start rather than serving against a schema it is ahead of, and `openpsirt migrate status` says where both stand. That compares version numbers, not schema content: below 1.0 a schema change edits what declares the thing rather than adding a migration beside it, so a database can be at the expected version and still hold what an earlier build created | `true` |
| `OPENPSIRT_DB_MAX_OPEN` | Most connections open at once | `25` |
| `OPENPSIRT_DB_MAX_IDLE` | Most connections kept open idle | `25` |
| `OPENPSIRT_DB_IDLE_TIMEOUT` | How long an idle connection is kept before it is closed. Shorter than anything between the process and the server would close it, so nothing closes one behind the process's back | `1m` |
| `OPENPSIRT_DB_CONN_LIFETIME` | How long a connection is used before it is replaced | `30m` |
| `OPENPSIRT_DB_REQUIRE_ENCRYPTION` | Refuse to start where the connection to the database is not encrypted. See below | `false` |

### Database connection encryption

The connection carries undisclosed findings, and by default it is encrypted
only where the server offers it. Opportunistic is not the same as certain: a
server that answers without TLS is accepted, and so is one whose certificate
nobody checked. Ask for certainty in the URL.

| Engine | Default | Ask for certainty with |
|---|---|---|
| PostgreSQL | `sslmode=prefer` — encrypted if the server offers it, no certificate checked | `?sslmode=verify-full`, with `sslrootcert` naming the authority |
| MySQL, MariaDB | `tls=preferred` — encrypted if the server offers it, no certificate checked | `?tls=true`, which verifies the certificate against the system roots |
| SQLite | No connection to encrypt | — |

Anything the URL says about the transport is left alone, so `tls=skip-verify`
or a `sslmode` of your own reaches the driver as written.

Say so where it is required. With `OPENPSIRT_DB_REQUIRE_ENCRYPTION` set,
the process asks the connection what it negotiated and refuses to start where
that is cleartext — naming the URL, without its password, and what to put in
it. Asking for encryption in the URL and being given none is a deployment that
believes it is encrypted and is not, and nothing else says otherwise: the
process logs the transport at every start, which is a line somebody has to
read.

| Where it is set | |
|---|---|
| The connection is encrypted | Nothing happens. The transport is logged as it always is |
| The connection is in cleartext | Refused at startup, naming the setting |
| The server will not say which | Refused. What this asks for is certainty, and "we could not find out" is not it |
| The database is SQLite | Refused. A file opened directly has no connection to encrypt, and quietly doing nothing is what a setting that changes nothing looks like |

## Scanning

| Variable | Meaning | Default |
|---|---|---|
| `OPENPSIRT_SCANNER_PATH` | Where the vulnerability scanner binary lives. Empty means whatever the environment resolves. The scanner is a requirement of a deployment rather than an option: the vulnerability data is produced here, not sent in | unset |
| `OPENPSIRT_SCANNER_TIMEOUT` | How long one scan may run before it is killed and recorded as a run that failed. Raise it where a large inventory legitimately takes longer: past it, every attempt is killed and the job is set aside once its attempts run out. It has to stay below `OPENPSIRT_QUEUE_MAX_HOLD`, the span a worker may hold one job for, and the process refuses to start where it does not | `30m` |
| `GRYPE_DB_CACHE_DIR` | Where the scanner keeps its vulnerability data. The image sets it; a deployment that moves it has to move it in both places, or the data lands on the read-only root filesystem where it cannot be written | `/var/cache/openpsirt/grype` |
| `GRYPE_DB_AUTO_UPDATE` | Whether the scanner fetches its own vulnerability data. Set it to `false` where the deployment cannot reach the network, and put the data there yourself — see below | `true` |

### An air-gapped install

The scanner's vulnerability data is not shipped in the image: it changes daily
and the image does not. A deployment that can reach the network downloads it
itself and nothing here needs doing.

One that cannot needs the data carried across, and carrying it is a build
target rather than a list of steps:

```
make scanner-db
```

It produces `dist/openpsirt-scanner-db-<date>.tar.gz` and its checksum, using
the scanner the image carries — the format is the scanner's, and a bundle
built by a different version is one that may not load. Before it says it
succeeded it runs that same scanner against the bundle with the network off
and auto-update refused, which is the configuration on the far side of the
gap: a bundle that merely exists is what the target refuses to produce.

On the far side, check the bundle before trusting it, unpack it into
`GRYPE_DB_CACHE_DIR`, and set `GRYPE_DB_AUTO_UPDATE=false`:

```
make scanner-db-verify BUNDLE=openpsirt-scanner-db-<date>.tar.gz
```

The verification is available there as well as here on purpose. "It built" and
"it loads where it has to" are different claims, and the second is the one that
matters where the bundle is all there is — in the one situation where trying it
out first is not available.

## Mail

Mail is how anything leaves the application. A deployment that sets none of
this tells nobody anything outside it, which is an ordinary way to run: the
notification area in the interface still works.

`MAIL_FROM` and `MAIL_SERVER` are both needed for mail to happen at all — a
server with nobody to send as is half a configuration, and either alone sends
nothing rather than failing at startup. Credentials are optional, and are
refused over a connection the server would not secure with STARTTLS.

| Variable | Meaning | Default |
|---|---|---|
| `OPENPSIRT_MAIL_FROM` | The address messages are sent as. Set it and the server together, or neither: half of the pair is refused at startup, because a server with nobody to send as sends nothing and would say nothing about it | unset |
| `OPENPSIRT_MAIL_SERVER` | The SMTP server as `host:port`, e.g. `smtp.example.com:587` | unset |
| `OPENPSIRT_MAIL_USERNAME` | Username, where the server wants one. Sent only after STARTTLS | unset |
| `OPENPSIRT_MAIL_PASSWORD` | Password for that username. Sent only after STARTTLS | unset |

Who gets what is not configuration: each person chooses in their own settings,
and the daily digest is off until somebody asks for it. A message about a
finding nobody has announced carries no detail — only that there is something,
and a link.

On the Helm chart these are the `mail` values, and the password goes in a
Secret the chart makes or one you name.

## Advisory publication

An advisory is a document about flaws in your own products, under an
identifier this deployment mints. It is generated from what the deployment
already holds and handed to you; nothing is sent anywhere. That you published
it is recorded when you say so, which is what lets the next document be a
revision.

Both a name and a namespace are needed for either to do anything. A CSAF
document requires a publisher, so with one missing no advisory is generated and
the refusal says which — rather than handing you a document that fails
validation after you have sent it.

| Variable | Meaning | Default |
|---|---|---|
| `OPENPSIRT_PUBLISHER_NAME` | The organization advisories say issued them. Set it and the namespace together, or neither | unset |
| `OPENPSIRT_PUBLISHER_NAMESPACE` | A URL identifying that organization, which is what a reader of a CSAF document matches on | unset |
| `OPENPSIRT_PUBLISHER_CATEGORY` | What the standard calls the kind of publisher: `coordinator`, `discoverer`, `other`, `translator`, `user` or `vendor`. A deployment publishing about its own product is a vendor. Anything else is refused at startup — the value reaches the document verbatim, so a typo produces advisories that fail validation wherever anybody takes them | `vendor` |
| `OPENPSIRT_ADVISORY_PREFIX` | What a minted advisory identifier opens with, before the year and a number within it — the half a reader recognizes the publisher by. A letter followed by up to nineteen letters, digits or hyphens, upper case; anything else is refused at startup. Unset, no advisory can be started and the refusal says so: an identifier traceable to no publisher is in every document that went out, where a refusal is fixed once | unset |

On the Helm chart these go through `extraEnv`, since a deployment that does not
publish needs none of them.

## The published advisory directory

Absent is ordinary: with none of this set, advisories are generated and handed
to you and nothing is written anywhere.

Set it and every advisory that has gone out is written as a static CSAF
provider directory — the documents in a folder per year, a list of them, a list
of changes, a ROLIE feed, a description of you as a provider, and a `.sha256`
beside each document. This application serves none of it. It writes files; your
web server serves them, at the address you give below.

| Variable | What it does | Default |
|---|---|---|
| `OPENPSIRT_DIRECTORY_URL` | The `https` address the directory is reachable at, which only you know. Every address the directory states about itself is built from it, and so is the address each advisory states for itself, so nothing is written without it. Refused at startup if it is not an `https` address | unset |
| `OPENPSIRT_DIRECTORY_BUCKET` | The bucket the files are written to. Empty means no object store | unset |
| `OPENPSIRT_DIRECTORY_ENDPOINT` | The address of a self-hosted store. A cloud provider needs none | unset |
| `OPENPSIRT_DIRECTORY_REGION` | The region, where the store wants one | unset |
| `OPENPSIRT_DIRECTORY_KEY` | Access key, where the environment supplies no role | unset |
| `OPENPSIRT_DIRECTORY_SECRET` | Its secret | unset |
| `OPENPSIRT_DIRECTORY_SESSION_TOKEN` | A session token, where the credentials are temporary ones | unset |
| `OPENPSIRT_DIRECTORY_PATH_STYLE` | Address the bucket in the path rather than the host, which is what a self-hosted store usually wants | set when an endpoint is |
| `OPENPSIRT_DIRECTORY_ALLOW_HTTP` | Accept a store endpoint that is not `https` and is not this machine | off |
| `OPENPSIRT_DIRECTORY_DIR` | A directory on this machine to write the files into instead. The bucket wins where both are set | unset |
| `OPENPSIRT_DIRECTORY_LIST` | Tell aggregators they may list you | on |
| `OPENPSIRT_DIRECTORY_MIRROR` | Tell aggregators they may mirror your documents | off |

A directory on this machine is a deployment here, unlike for attachments: a
web server reading the same disk is the ordinary way to serve static files.
One process writes it, so it wants a replica of its own and a volume of its
own — on the chart's defaults, two replicas with a read-only root filesystem,
the pass cannot create the directory at all, and on a shared volume the two
replicas write over one another. Run one replica with a volume mounted for it,
or use the object store.

Files are written readable by whoever serves them, and folders enterable. A
web server runs as its own user, and refused the lot it serves what looks like
a deployment that has published nothing.

Use a store of its own rather than the one attachments are in. Every file here
is served to anybody who asks, and every attachment is authorized before it is
handed over — one destination would have to be both.

Only a document that may travel is written. An advisory covering a flaw nobody
outside has been told about carries TLP:RED, and the directory is the freely
accessible half of the standard's distribution, so those are held back and
counted in the log line. Editorial state has nothing to do with it: a draft is
not published because it has not gone out, and a published document stays
published while it is being revised.

What is written is what went out, byte for byte. Issuing an advisory is what
puts a document in the directory, and editing one afterwards changes nothing
there until you record that the next revision went out.

Setting the address changes what advisories say, not only where they are put.
A document states the address it is published at, so one generated before you
set it states none and one generated after states it — and a document that has
already gone out keeps the bytes it went out as. Set the address before you
publish, rather than after.

Three things are yours to arrange, because they are your web server's rather
than this application's:

- **TLS, and no redirects.** The standard requires the first and asks against
  the second.
- **One of the three ways to be found**: `/.well-known/csaf/provider-metadata.json`
  under your main domain, a `CSAF` field in your `security.txt` pointing at the
  description, or the `csaf.data.security.<domain>` DNS record.
- **Directory listings**, if you want the manual navigation the standard asks
  for.
- **Read access to the files.** Nothing here sets an access policy on the
  object store, which is the right default and leaves readability yours: a
  bucket made with the usual defaults answers 403 to everybody while this
  writes into it successfully. Give whatever serves the address a policy that
  lets it read, or put a front end with credentials of its own in front.

Nothing is signed. Signatures and a public key are what the standard's trusted
provider role adds, and key material is configuration of a kind this deployment
does not yet take. The layout leaves room for it: a signature sits beside the
document under the same name, and the feed already names the file beside each
entry that answers for it.

## Supplier advisories

Off unless an administrator names a supplier, under Settings. Each is named
against one product, and what is read lands as evidence beside a finding — a
publisher's own judgment, never a decision taken here.

Requests go to the host the configured address names, and to every host the
publisher's description, its feeds and their entries name for listings,
documents and digests: https on port 443 only, a redirect refused rather than
followed, and an address inside this network or in
[`OPENPSIRT_OUTBOUND_EXCLUDED`](#outbound-exclusions) refused. So an egress rule
for this is every host a supplier publishes from, on 443.
SUSE's description is on `www.suse.com` and its directory on `ftp.suse.com`.

What leaves is the request itself. No component name, no build, no product,
nothing about what this deployment holds — the narrowing to what a product
ships happens here, after the document has arrived.

How often each supplier is read again is `scanning.every`, the same setting
that paces re-scans. Shortening it makes more requests to every configured
supplier as well as more scans here.

A new supplier is read from `scanning.supplier-history` days before it was
added, 365 unless set. A publisher's listing holds everything they have ever
issued, so this bounds how much of it is asked for: a year of Red Hat is about
97,000 documents and takes about seventeen days to read, and a year of a vendor
publishing a few hundred a year takes hours. To take an advisory published
earlier, upload it. A supplier withdrawn and added again resumes where it
stopped, no further back than the same window.

Each document is checked against the SHA-256 or SHA-512 file its publisher
serves beside it, and one that does not match is not read. A publisher serving
neither is read unchecked.


## Upstream currency

Off unless an administrator turns it on, under Settings. Everything a scan
needs arrives as a file somebody imported, so a deployment that cannot reach out
loses this answer and what a scan reports is unaffected.

What goes out is a component's name, to that ecosystem's public index, and
nothing else — no version, no build, no product. Most indexes take one request
per component; Maven Central takes two, the version list and the newest
release's project document, and nuget.org up to five, the registration and up
to four of its pages. For an open-source dependency that is public knowledge. For
something built here it is the name of a project, a team, or a product nobody
has announced, and a public index records every request made of it.

| Ecosystem | Host asked |
|---|---|
| Go | `proxy.golang.org` |
| npm | `registry.npmjs.org` |
| PyPI | `pypi.org` |
| Cargo | `crates.io` |
| Maven | `repo1.maven.org` |
| NuGet | `api.nuget.org` |

Nothing else is reached, and a redirect is not followed. A distribution
package is never asked about.

Where egress is restricted, allow the hosts for the ecosystems your builds
carry. An index that cannot be reached is asked once a pass and then left for
the rest of it, so the others are still asked; its components stay due, and
each pass logs the failure.

So names this deployment calls its own are never sent. Three sources, unioned:

| Source | What it yields |
|---|---|
| `OPENPSIRT_PUBLISHER_NAMESPACE` | The organization, spelled the three ways the ecosystems spell one: the host, the host reversed, which is what a Maven group is, and each label short of the top-level domain. A label naming a kind of registration or a forge rather than an organization is dropped, so `example.github.io` does not hold back everything under `github.com` |
| What each build declared itself to be | The account, scope or group that identifier is published under, where an inventory names one. Read from the scans rather than from here, so a product declared this morning is one whose name does not leave this afternoon |
| `OPENPSIRT_UPSTREAM_INTERNAL` | Whatever else you name, separated by commas |

| Variable | Meaning | Default |
|---|---|---|
| `OPENPSIRT_UPSTREAM_INTERNAL` | Names never sent to a public index, separated by commas, on top of the two derived sources above. Here rather than among the settings an administrator tunes, beside the namespace the default is derived from: asking upstream is a switch an administrator throws, and what leaves the deployment when it is on is a boundary you drew | unset |

A name matches each part of a package's own name, either exactly or followed by
`-`, `.` or `_`. A name without a dot also matches each dotted part, which is
how a Maven group holds an organization's name after its top-level domain. A
name carrying a dot also covers a host under it. So a
deployment publishing under `example.test` holds back:

| Identifier | On the label |
|---|---|
| `pkg:npm/@example/agent` | `example` |
| `pkg:golang/github.com/example-corp/thing` | `example` |
| `pkg:golang/test.example/lib` | `test.example`, the same organization spelled the way a module path spells it |
| `pkg:golang/go.example.test/team/agent` | `example.test`, which covers a host under it |
| `pkg:maven/test.example.tools/agent` | `test.example`, which is what a Maven group is |
| `pkg:nuget/Example.Agent` | `example` |

`pkg:npm/exampler` is left alone. Case does not decide.

This is a better default, not a control. A deployment that needs certainty
about what leaves it leaves the whole feature off, which is where it ships. It
is biased toward holding back: over-excluding loses an answer, which is visible
on the screen that would have shown it, and under-excluding sends a name to
somebody else's service, which is visible nowhere.

Turning it off again drops what was fetched. On a deployment that had
asking on before a name was held back, the version an index gave for that name
is removed the next time the pass reaches it, along with the summary and the
project address. All of it came from sending the name. Nothing else is
affected and no upgrade step is needed.

Read what it held back, and what no index knew. The report is at
`/v1/upstream/unanswered` and on the System screen. Held-back names say what
the default is costing; names no public index has heard of are private modules
and vendored forks, and they are the candidates to promote into
`OPENPSIRT_UPSTREAM_INTERNAL` so they stop being asked about at all.

## Outbound exclusions

Two fetches go to hosts somebody else chose: the repository a patch link names,
and the directory and documents a supplier's description names. Both refuse
loopback, private, link-local and shared address space regardless. An internal
service on a public address or behind a public name is kept out by this list
alone.

| Variable | Meaning | Default |
|---|---|---|
| `OPENPSIRT_OUTBOUND_EXCLUDED` | Hosts and networks nothing is fetched from, separated by commas. A name covers itself and every host under it; a network is written as `10.0.0.0/8` and covers every address a name resolves to inside it | unset |

```
OPENPSIRT_OUTBOUND_EXCLUDED=corp.example.com,internal.example.net,203.0.113.0/24
```

The chart sets it from `outbound.excluded`.

## Patch branches

A patch link to a commit is labeled with the branches of its repository that
contain the commit, on the finding it belongs to. A fix backported to five
branches arrives as five bare commit links, and the label is what says which
one applies to the branch you ship.

Off unless the deployment turns it on. It fetches a copy of each repository a
patch link names, from the host the link names, and asks the copy which
branches hold each commit. Progress, failures and the size of each copy are on
the System screen and at `/v1/patch-branches`.

| Variable | Meaning | Default |
|---|---|---|
| `OPENPSIRT_PATCH_BRANCHES` | Whether the lookups run. Read at startup, so changing it takes a restart | `false` |
| `OPENPSIRT_PATCH_DIR` | Where the copies are kept. It must be writable, which with a read-only root filesystem means a mounted volume | `/var/cache/openpsirt/repositories` |
| `OPENPSIRT_PATCH_QUOTA` | How many bytes the copies may hold together. The least recently used is removed to make room | `21474836480` (20 GB) |

### Enabling

| Step | Chart value | Why |
|---|---|---|
| Raise the memory limit to 4 GiB | `resources.limits.memory` | git runs inside the pod's limit beside the server and the scanner |
| List your internal domains and networks | `outbound.excluded` | A report chooses the host. See [Outbound exclusions](#outbound-exclusions) |
| Keep the copies on a volume | `patchBranches.existingClaim` | Scratch space loses them on every restart |
| Turn it on | `patchBranches.enabled: true` | Sets `OPENPSIRT_PATCH_BRANCHES` |

### Replicas

| | |
|---|---|
| One replica fetches at a time | A lease decides which |
| Every replica serves the labels | They are kept in the database |
| The copies are one replica's disk | A ReadWriteMany claim shared by every replica keeps one set. Only the replica holding the lease writes to it |
| A ReadWriteOnce claim with several replicas | The replicas on other nodes stay Pending. The chart cannot refuse this, because it cannot see the access mode of a claim it did not make |
| No claim | Each pod keeps its own scratch copy and fetches again when the lease moves to it |

Only https is used, redirects are not followed, and git runs with no
configuration, credentials or hooks from the environment.

### Sizing

The Linux kernel is the largest repository reports link to, and git.kernel.org
sends whole history:

| The kernel's stable tree | From git.kernel.org | From a host that sends commits alone |
|---|---|---|
| Copy on disk | 5.1 GB, and 116 MB of index | 1.1 GB, and 116 MB of index |
| First fetch | 15 minutes | 90 seconds |
| Memory at the peak of the first fetch | 1.3 GB | 0.6 GB |

Size the quota to hold the kernel and the other repositories your reports link
to, and the volume a fifth larger than the quota. The chart sizes its scratch
volume that way from `patchBranches.quota`; a claim of your own needs the same
room. A copy that alone outgrows the quota is abandoned and tried again a day
later.

git runs inside the same memory limit as the server and the scanner, and a
first kernel fetch can coincide with a scan. Raise the limit to 4 GiB before
turning this on where reports link to git.kernel.org. Where the limit is
exceeded, the kernel kills the largest process, the visit fails, and it is
retried a day later.

Keep the copies on a persistent volume. Scratch space loses them on every
restart, and the kernel is fetched again from the start.

## Sign-in

The process refuses to start until somebody can administer it, and naming
somebody grants a role — it does not let anybody in without signing in.

Configure at least one of the sign-in methods below, or nobody can reach it.
The Helm chart refuses to render an install with none; the binary does not
check, because a deployment being brought up in pieces is an ordinary state
for a process and not for an install.

| Variable | Meaning | Default |
|---|---|---|
| `OPENPSIRT_BOOTSTRAP_ADMINS` | Identities granted administration at every startup, comma-separated. Each is the plain username your provider or your trusted proxy reports — there is no prefix, and the same name down either path is the same person. Capitals do not matter: a name is folded as it is stored. **A name written `provider:username` is refused and the process stops**, naming what to write instead, because an accepted one becomes an administrator account nobody can sign in as. Applied every time rather than only the first, so it is the way back in for an operator who has locked themselves out: add yourself, restart | unset |
| `OPENPSIRT_SESSION_LIFETIME` | How long a sign-in lasts, where nothing has been set in the application. **An administrator's setting wins over this**, because the settings screen offers it and a value somebody sets there that nothing reads is worse than not offering it. A value here has to be a positive duration, and at most 30 days — group membership is read at sign-in and never again, so this is how long a role a group withdrew can still be held | 12 hours |

### An OpenID Connect provider

One sign-in provider is configured at a time. Setting both an issuer here and a
GitHub client id below stops the process, naming the two: an identity is a
username, and two providers issuing them independently cannot be told apart.

| Variable | Meaning | Default |
|---|---|---|
| `OPENPSIRT_OIDC_ISSUER` | The provider's issuer address. Empty means no provider. **Every endpoint the provider publishes must be on this host** — the authorization endpoint, the token endpoint and the keys endpoint — and the process refuses to start where one is not. Providers that publish their keys elsewhere, Google among them, are refused: a discovery document names the addresses this deployment will send people to, and it arrives over the network | unset |
| `OPENPSIRT_OIDC_NAME` | What the sign-in button calls it. It is also a path segment, so it must be made only of characters a URL path carries as written — no slashes and no spaces. The process refuses to start otherwise | `oidc` |
| `OPENPSIRT_OIDC_CLIENT_ID` | The client registered with the provider | unset |
| `OPENPSIRT_OIDC_CLIENT_SECRET` | Its secret | unset |
| `OPENPSIRT_OIDC_USERNAME_CLAIM` | Which claim carries the name an authorization is written for. **Required**, with no default — see below | none — the process refuses to start without it |
| `OPENPSIRT_OIDC_GROUPS_CLAIM` | The claim carrying group membership, if the provider asserts it | unset |

### The username claim

The claim is not the identity. The provider's subject is, and the first
sign-in pins it; from then on the subject decides and a rename is followed as
a label.

This claim does one job: match an authorization an administrator wrote for
somebody who has not arrived yet. That has to be a name a person can type, so
the subject itself cannot serve — nobody knows it in advance. The property it
needs is narrower than immutable:

> An end user must not be able to set it to a name an administrator might
> have authorized.

The exposure runs from the moment a grant is written until somebody redeems
it, which `signin.claim-window` also bounds.

| Provider | Usually | Check before you trust it |
|---|---|---|
| Okta | `preferred_username` — the Okta login, normally the address the directory assigned | Self-service profile editing must not cover the username or the primary email. It does not by default |
| Entra ID | `oid`, or `upn` where administrators want a name they recognize | `preferred_username` on Entra is not a good choice: it follows the mail nickname |
| Keycloak | A custom claim mapped to an administrator-managed attribute | If self-registration is on, `preferred_username` is a name the account holder chose, and is the case this refusal exists for |
| Anything else | Whatever the provider assigns rather than the person | Ask whether a user can edit it in the provider's own account settings |

`preferred_username` rides on the `profile` scope rather than `email`. The
scopes requested are `openid profile email` and are not configurable, so a
claim carried by any of the three is available.

A claim the provider does not send, or sends as something other than a string,
reads as absent. The sign-in then falls back to the address the provider says
it verified, and failing that to the subject — which matches no authorization
anybody typed, so the person is refused rather than admitted. A claim name
with a typo in it therefore reads as "this person was never granted access",
not as a configuration error, so check the name against the provider's own
token before deciding somebody's grant is missing.

### Sign-in without a provider

The trusted header below is the way in that does not depend on the provider,
and it is what a provider change goes through. A pinned identifier does not
refuse a proxy arrival, so everybody reaches what they already hold.

The provider is down and people must sign in.

1. Unset `OPENPSIRT_OIDC_ISSUER`. A provider that cannot be discovered stops
   the process at startup, so leaving it set means nothing starts at all.
2. Set `OPENPSIRT_TRUSTED_HEADER` and `OPENPSIRT_TRUSTED_SOURCES`. Both are
   needed; half a configuration stops the process.
3. Restart. Sign-in is by the name the proxy asserts.

The provider publishes an endpoint on another host. The process refuses to
start, naming the endpoint and the host. Pinning the fetch to the issuer does
not stop the document naming somewhere else inside itself, and an issuer naming
an authorization endpoint elsewhere turns every sign-in into a redirect of its
choosing. There is no way to allow it: the deployment reaches this provider
through a proxy that serves the whole of it from one host, or it signs in
through the trusted header instead.

The provider is changing. An identifier belongs to the provider that
issued it, and the same string names somebody else at another one, so a
deployment configured for a provider its bound identities do not name refuses
to start.

1. Point `OPENPSIRT_OIDC_ISSUER` back at the **old** provider, or configure the
   trusted header with no provider at all where the old one cannot be reached
   either. A binding is withdrawn while the provider that made it is still
   configured.
2. `DELETE /v1/people/{identity}/identifier` for each person. The
   authorization and the roles stay; only the pin goes.
3. Configure the new provider and restart. Each name is redeemed again by
   whoever next arrives holding it.

Doing it the other way round — configuring the new provider first — leaves a
process that will not start. The refusal names the old issuer and the steps, so
the way out is to put that value back and start at step 1.

What is compared is the **issuer**, not `OPENPSIRT_OIDC_NAME`. Renaming the
button changes nothing, and repointing the issuer while leaving the button
alone is caught.




### GitHub

| Variable | Meaning | Default |
|---|---|---|
| `OPENPSIRT_GITHUB_CLIENT_ID` | The OAuth application's client id. Empty means GitHub sign-in is off. Not to be set alongside `OPENPSIRT_OIDC_ISSUER` | unset |
| `OPENPSIRT_GITHUB_CLIENT_SECRET` | Its secret | unset |
| `OPENPSIRT_GITHUB_ORG` | Restrict sign-in to members of one organization, and read its teams as groups. Empty means anybody with a GitHub account, which is rarely what you want | unset |

### The trusted header

Both the header and the sources it is believed from are required together: a
header named with nothing to trust it from is either a mistake or the first
half of one, and the process stops rather than accept a header anybody can set.

| Variable | Meaning | Default |
|---|---|---|
| `OPENPSIRT_TRUSTED_HEADER` | The header an identity-aware proxy sets to say who somebody is | unset |
| `OPENPSIRT_TRUSTED_SOURCES` | Addresses or CIDR ranges the header is believed from, comma-separated. Anything else presenting it is ignored | unset |
| `OPENPSIRT_TRUSTED_GROUPS_HEADER` | Where that proxy reports group membership, if it does | unset |
| `OPENPSIRT_TRUSTED_GROUPS_DELIMITER` | What separates the names in it. Neither the header nor the separator is standardized, so both are named rather than guessed | `,` |

## Attachment storage

Absent is ordinary: with none of this set, attachments are off and everything
else works. An operator who wants none should not have to run a bucket.

`OPENPSIRT_ATTACHMENT_BUCKET` is what turns the object store on. The endpoint
is what a self-hosted store needs and a cloud one does not, and credentials are
optional — a deployment on a cloud provider gets a rotating role from its
environment rather than a key somebody stored.

| Variable | What it does | Default |
|---|---|---|
| `OPENPSIRT_ATTACHMENT_BUCKET` | The bucket files are kept in. Empty means attachments are off | unset |
| `OPENPSIRT_ATTACHMENT_ENDPOINT` | The address of a self-hosted store. A cloud provider needs none | unset |
| `OPENPSIRT_ATTACHMENT_REGION` | The region, where the store wants one | unset |
| `OPENPSIRT_ATTACHMENT_KEY` | Access key, where the environment supplies no role | unset |
| `OPENPSIRT_ATTACHMENT_SECRET` | Its secret | unset |
| `OPENPSIRT_ATTACHMENT_SESSION_TOKEN` | A session token, where the credentials are temporary ones | unset |
| `OPENPSIRT_ATTACHMENT_PATH_STYLE` | Address the bucket in the path rather than the host, which is what a self-hosted store usually wants. Follows the endpoint rather than having a default of its own | set when an endpoint is |
| `OPENPSIRT_ATTACHMENT_ALLOW_HTTP` | Accept an endpoint that is not `https` and is not this machine. Read what it costs below before setting it | off |
| `OPENPSIRT_ATTACHMENT_DIR` | A directory to keep files in instead, for running the tool without standing up an object store. One process and one disk, so never a production option; the bucket wins where both are set | unset |

An endpoint that is not `https` is refused, because a file is handed over as a
redirect to a signed address and that address is a bearer token: anybody on the
path between the browser and the store may spend it for the file it names.
Loopback is exempt, since nothing crosses a network.

`OPENPSIRT_ATTACHMENT_ALLOW_HTTP` accepts one anyway, for a store on a network
you are content to carry those addresses across. A deployment that sets it is
told so at every start rather than only where it was configured:

```
WARN attachment links cross the network in the clear endpoint=http://minio.internal:9000
```

This is not `OPENPSIRT_PLAIN_HTTP`, which is about serving this application
without TLS and loosens cookies. One is a file on the way out and the other a
session on the way in; a deployment can want either without the other.

## The work queue

Reading a scan and running a scanner are jobs in a queue held in the database.
Each bound below is what a deployment sizes; left unset, the built-in value
applies, and each takes effect at the next start rather than at once.

How deep the queue may get before uploads are refused is not here: it is a
setting an administrator changes on screen, because the refusal lands on a
build server and waiting for a restart is not a remedy.

| Variable | What it does | Default |
|---|---|---|
| `OPENPSIRT_QUEUE_MAX_ATTEMPTS` | How many times a job is tried before it is set aside with its last error | `5` |
| `OPENPSIRT_QUEUE_CLAIM_TIMEOUT` | How long a claim is honored with nothing heard from the worker holding it, after which another worker may take the job. It bounds a worker going silent, not how long a job may take | `30m` |
| `OPENPSIRT_QUEUE_HEARTBEAT` | How often a running job renews its claim. Well under the claim timeout, so several renewals may fail before the claim is at risk — a value that is not below it is refused at startup | `5m` |
| `OPENPSIRT_QUEUE_MAX_HOLD` | How long one claim may be renewed for altogether, after which the work is cancelled and the attempt recorded as a failure. It is what stops a worker wedged inside its work renewing for ever, and it has to stay above both the claim timeout and `OPENPSIRT_SCANNER_TIMEOUT`, which the process checks at startup | `2h` |
| `OPENPSIRT_QUEUE_BACKOFF` | How long a failed job waits before it is tried again, multiplied by the attempt | `30s` |

## Scan file limits

A scan file is somebody else's output arriving over a link this deployment does
not control, so it is read within bounds. These are the ceilings; each is
refused with a sentence naming what was exceeded rather than by failing
partway.

Leave one unset and it keeps the built-in value, so a deployment changing one
does not have to restate the rest.

The built-in values are set from what reading a document costs in memory, not
from how large a document looks. An edge holds about half a kilobyte of heap
while it is being read and a component about one and a third, so the defaults
below allow roughly 250 MB for one document. They are still several times the
largest producer we have. Raise them on a deployment with a bigger box and a
bigger inventory, and raise the container's memory limit with them.

That 250 MB is the server's share of the pod. The scanner runs as a second
process in the same container, so the memory limit covers both — see
[Memory and the scanner's database](#memory-and-the-scanners-database).

| Variable | What it does | Default |
|---|---|---|
| `OPENPSIRT_INGEST_MAX_BYTES` | How large a single document may be | 256 MB |
| `OPENPSIRT_INGEST_MAX_COMPONENTS` | How many components it may describe. About 1.3 KB of heap each while reading | 100,000 |
| `OPENPSIRT_INGEST_MAX_EDGES` | How many dependency edges it may declare. The component count does not bound this: a thousand components can declare a million edges between them. About 0.5 KB of heap each while reading | 250,000 |
| `OPENPSIRT_INGEST_MAX_FILES` | How many files a document may catalog. Not covered by the component count: a real scan catalogs forty-five to fifty-six files per package, so one bound cannot size both | 500,000 |
| `OPENPSIRT_INGEST_MAX_STATEMENTS` | How many claims a suppression document may make | 100,000 |
| `OPENPSIRT_INGEST_MAX_DEPTH` | How deeply it may nest | 64 |
| `OPENPSIRT_INGEST_MAX_DOCUMENTS` | How many suppression documents may arrive with one scan. Every bound above is per document, so without a ceiling on the count they are multiplied by a number nothing decides. The claim bound is spent across the documents rather than per document | 8 |

## Scanner output limits

The scanner's report is read in the same process, and its size is components ×
matches × references — the first of which a producer controls by uploading a
scan file. So it is bounded the way a scan file is, from the same budget, and
each bound left unset keeps the built-in value.

A report past its ceiling fails the run rather than being read in part: half a
report reads as a product that stopped having problems. Complaints past theirs
are dropped instead, because a scanner with a lot to say still scanned.

| Variable | What it does | Default |
|---|---|---|
| `OPENPSIRT_SCANNER_MAX_OUTPUT` | How large one report may be. The load-bearing bound: every count below is bounded by it | 256 MB |
| `OPENPSIRT_SCANNER_MAX_COMPLAINT` | How much of what a scanner said while running is kept | 1 MB |
| `OPENPSIRT_SCANNER_MAX_MATCHES` | How many matches one report may state. One match becomes as many findings as its component has places, so a scan's findings are an upper bound on its report's matches: the largest real image measured here produced 335,021 findings, and stated fewer matches than that | 500,000 |
| `OPENPSIRT_SCANNER_MAX_REFERENCES` | How many addresses one match may point at. Bounded separately because the two multiply | 1,000 |

## Memory and the scanner's database

The container runs two processes that use memory: the server, and the scanner
it starts as a child for every scan. One memory limit covers both, and an
excess is answered by the kernel killing the larger of the two — which is the
scanner. The scan is then recorded as a run that failed while the pod stays up,
so nothing in the failure points at the limit.

The chart ships:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 512Mi
  limits:
    memory: 2Gi
```

| What draws on it | |
|---|---|
| The server reading one scan document | About 250 MB at the built-in bounds. [Scan file limits](#scan-file-limits) sets it, and raising those raises this |
| The server reading one scanner report | Bounded by `OPENPSIRT_SCANNER_MAX_OUTPUT`. A read and a scan run in separate loops, so a pod can be doing both |
| The scanner itself | Not bounded by anything here. It is a separate program, and its report is bounded only once written |
| The scanner importing its vulnerability database | The largest single draw, and it happens on every start where the data is not kept |
| Fetching a repository for [patch branches](#patch-branches) | Off unless the deployment turns it on. Up to 1.3 GB for the first copy of the kernel from git.kernel.org |

Raise the limit for a bigger inventory, for raised scan-file bounds, or where
the database is imported on every start.

### Database persistence

The scanner fetches its data at runtime, because a database built into an image
is stale the day after that image is published. Where the data is not kept
across restarts it is downloaded and imported again on every start, and that
import is the largest thing the pod does with memory.

Keeping it takes the import off the common path. The chart will make the claim:

```yaml
scanner:
  persistence:
    enabled: true
    size: 10Gi
    storageClass: ""          # the cluster's default
    accessModes:
      - ReadWriteOnce
```

Every replica mounts the one claim, so the access mode has to allow as many
nodes as there are replicas. `ReadWriteOnce` binds to a single node: with more
than one replica, use `ReadWriteMany` on a storage class that offers it, name a
claim per replica set through `scanner.persistence.existingClaim`, or run one
replica. The chart refuses the combination it can see at render time rather
than leaving a replica Pending.

A claim you made yourself is named instead, and wins over the one the chart
would make:

```yaml
scanner:
  persistence:
    existingClaim: grype-db
```

Naming both is refused. The claim the chart makes is kept when the release is
uninstalled, because the data is re-downloadable and a claim is not worth
deleting by surprise.

### An exhausted limit

The scanner is killed by the kernel rather than exiting, so the run fails with
the signal in the message:

```
run /usr/local/bin/grype: signal: killed
```

The job is retried with backoff and set aside after `OPENPSIRT_QUEUE_MAX_ATTEMPTS`
attempts, so the symptom is scans that will not complete rather than a pod that
will not stay up. Where the pod itself is killed instead, a deployment without a
kept database restarts into the import that exhausted it.
