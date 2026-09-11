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

## Serving

| Variable | Meaning | Default |
|---|---|---|
| `OPENPSIRT_ADDR` | The `host:port` the HTTP server listens on | `:8080` |
| `OPENPSIRT_BASE_URL` | The address people arrive on. Behind a proxy that is not what the process thinks it is called, and a sign-in provider compares the address it sends people back to against what it was registered with, so it is stated rather than guessed. Required once a provider is configured | unset |
| `OPENPSIRT_PLAIN_HTTP` | Serve without TLS, which is what running locally looks like. It only loosens cookies: the session cookie is sent over plain HTTP, which it otherwise is not | `false` |
| `OPENPSIRT_SHUTDOWN_GRACE` | How long requests in flight get to finish on a stop signal, and then how long background work gets to finish after that | `15s` |
| `OPENPSIRT_LOG_LEVEL` | `debug`, `info`, `warn` or `error` | `info` |
| `OPENPSIRT_LOG_FORMAT` | `text` or `json` | `text` |

## Database

| Variable | Meaning | Default |
|---|---|---|
| `OPENPSIRT_DATABASE_URL` | Which database and how to reach it: `postgres://user:password@host:5432/name`, `mysql://…`, `mariadb://…`, or `sqlite:///absolute/path.db`. SQLite is for development and a single-pod trial, never production. **Required** | unset |
| `OPENPSIRT_AUTO_MIGRATE` | Apply outstanding schema changes at startup, so deploying the binary is the whole upgrade. Turn it off to run `openpsirt migrate up` yourself, under different credentials, at a time you choose | `true` |
| `OPENPSIRT_DB_MAX_OPEN` | Most connections open at once | `25` |
| `OPENPSIRT_DB_MAX_IDLE` | Most connections kept open idle | `25` |
| `OPENPSIRT_DB_IDLE_TIMEOUT` | How long an idle connection is kept before it is closed. Shorter than anything between the process and the server would close it, so nothing closes one behind the process's back | `1m` |
| `OPENPSIRT_DB_CONN_LIFETIME` | How long a connection is used before it is replaced | `30m` |

## Scanning

| Variable | Meaning | Default |
|---|---|---|
| `OPENPSIRT_SCANNER_PATH` | Where the vulnerability scanner binary lives. Empty means whatever the environment resolves. The scanner is a requirement of a deployment rather than an option: the vulnerability data is produced here, not sent in | unset |
| `GRYPE_DB_CACHE_DIR` | Where the scanner keeps its vulnerability data. The image sets it; a deployment that moves it has to move it in both places, or the data lands on the read-only root filesystem where it cannot be written | `/var/cache/openpsirt/grype` |
| `GRYPE_DB_AUTO_UPDATE` | Whether the scanner fetches its own vulnerability data. Set it to `false` where the deployment cannot reach the network, and put the data there yourself — see below | `true` |

### An install that cannot reach the network

The scanner's vulnerability data is not shipped in the image: it changes daily
and the image does not. A deployment that can reach the network downloads it
itself and nothing here needs doing.

One that cannot needs the data carried across, and carrying it is a build
target rather than a list of steps:

```
make scanner-db
```

It produces `dist/openpsirt-scanner-db-<date>.tar.gz` and its checksum, using
**the scanner the image carries** — the format is the scanner's, and a bundle
built by a different version is one that may not load. Before it says it
succeeded it runs that same scanner against the bundle **with the network off
and auto-update refused**, which is the configuration on the far side of the
gap: a bundle that merely exists is what the target refuses to produce.

On the far side, check the bundle before trusting it, unpack it into
`GRYPE_DB_CACHE_DIR`, and set `GRYPE_DB_AUTO_UPDATE=false`:

```
make scanner-db-verify BUNDLE=openpsirt-scanner-db-<date>.tar.gz
```

The verification is available there as well as here on purpose. "It built" and
"it loads where it has to" are different claims, and the second is the one an
air-gapped install depends on — in the one situation where trying it out first
is not available.

## Telling people

Mail is how anything leaves the application. A deployment that sets none of
this tells nobody anything outside it, which is an ordinary way to run: the
notification area in the interface still works.

`MAIL_FROM` and `MAIL_SERVER` are both needed for mail to happen at all — a
server with nobody to send as is half a configuration, and either alone sends
nothing rather than failing at startup. Credentials are optional, and are
refused over a connection the server would not secure with STARTTLS.

| Variable | Meaning | Default |
|---|---|---|
| `OPENPSIRT_MAIL_FROM` | The address messages are sent as. Set it and the server together, or neither | unset |
| `OPENPSIRT_MAIL_SERVER` | The SMTP server as `host:port`, e.g. `smtp.example.com:587` | unset |
| `OPENPSIRT_MAIL_USERNAME` | Username, where the server wants one. Sent only after STARTTLS | unset |
| `OPENPSIRT_MAIL_PASSWORD` | Password for that username. Sent only after STARTTLS | unset |

Who gets what is not configuration: each person chooses in their own settings,
and the daily digest is off until somebody asks for it. A message about a
finding nobody has announced carries no detail — only that there is something,
and a link.

On the Helm chart these are the `mail` values, and the password goes in a
Secret the chart makes or one you name.

## Publishing advisories

An advisory is a document about a flaw in your own product. It is generated
from what this deployment already holds and handed to you; nothing is sent
anywhere, and nothing records that you published it.

Both a name and a namespace are needed for either to do anything. A CSAF
document requires a publisher, so with one missing no advisory is generated and
the refusal says which — rather than handing you a document that fails
validation after you have sent it.

| Variable | Meaning | Default |
|---|---|---|
| `OPENPSIRT_PUBLISHER_NAME` | The organization advisories say issued them. Set it and the namespace together, or neither | unset |
| `OPENPSIRT_PUBLISHER_NAMESPACE` | A URL identifying that organization, which is what a reader of a CSAF document matches on | unset |
| `OPENPSIRT_PUBLISHER_CATEGORY` | What the standard calls the kind of publisher. A deployment publishing about its own product is a vendor | `vendor` |

On the Helm chart these go through `extraEnv`, since a deployment that does not
publish needs none of them.

## Who may sign in

The process refuses to start until somebody can administer it, and naming
somebody grants a role — it does not let anybody in without signing in.

Configure at least one of the sign-in methods below, or nobody can reach it.
**The Helm chart refuses to render an install with none; the binary does not
check**, because a deployment being brought up in pieces is an ordinary state
for a process and not for an install.

| Variable | Meaning | Default |
|---|---|---|
| `OPENPSIRT_BOOTSTRAP_ADMINS` | Identities granted administration at every startup, comma-separated. Each is the plain username your provider or your trusted proxy reports — there is no prefix, and the same name down either path is the same person. Capitals do not matter: a name is folded as it is stored. **A name written `provider:username` is refused and the process stops**, naming what to write instead, because an accepted one becomes an administrator account nobody can sign in as. Applied every time rather than only the first, so it is the way back in for an operator who has locked themselves out: add yourself, restart | unset |
| `OPENPSIRT_SESSION_LIFETIME` | How long a sign-in lasts, where nothing has been set in the application. **An administrator's setting wins over this**, because the settings screen offers it and a value somebody sets there that nothing reads is worse than not offering it. A value here has to be a positive duration | 12 hours |

### An OpenID Connect provider

One sign-in provider is configured at a time. Setting both an issuer here and a
GitHub client id below stops the process, naming the two: an identity is a
username, and two providers issuing them independently cannot be told apart.

| Variable | Meaning | Default |
|---|---|---|
| `OPENPSIRT_OIDC_ISSUER` | The provider's issuer address. Empty means no provider | unset |
| `OPENPSIRT_OIDC_NAME` | What the sign-in button calls it | `oidc` |
| `OPENPSIRT_OIDC_CLIENT_ID` | The client registered with the provider | unset |
| `OPENPSIRT_OIDC_CLIENT_SECRET` | Its secret | unset |
| `OPENPSIRT_OIDC_USERNAME_CLAIM` | The claim to take a person's identity from, when it is not the subject | unset |
| `OPENPSIRT_OIDC_GROUPS_CLAIM` | The claim carrying group membership, if the provider asserts it | unset |

### GitHub

| Variable | Meaning | Default |
|---|---|---|
| `OPENPSIRT_GITHUB_CLIENT_ID` | The OAuth application's client id. Empty means GitHub sign-in is off. Not to be set alongside `OPENPSIRT_OIDC_ISSUER` | unset |
| `OPENPSIRT_GITHUB_CLIENT_SECRET` | Its secret | unset |
| `OPENPSIRT_GITHUB_ORG` | Restrict sign-in to members of one organization, and read its teams as groups. Empty means anybody with a GitHub account, which is rarely what you want | unset |

### A proxy that says who somebody is

Both the header and the sources it is believed from are required together: a
header named with nothing to trust it from is either a mistake or the first
half of one, and the process stops rather than accept a header anybody can set.

| Variable | Meaning | Default |
|---|---|---|
| `OPENPSIRT_TRUSTED_HEADER` | The header an identity-aware proxy sets to say who somebody is | unset |
| `OPENPSIRT_TRUSTED_SOURCES` | Addresses or CIDR ranges the header is believed from, comma-separated. Anything else presenting it is ignored | unset |
| `OPENPSIRT_TRUSTED_GROUPS_HEADER` | Where that proxy reports group membership, if it does | unset |
| `OPENPSIRT_TRUSTED_GROUPS_DELIMITER` | What separates the names in it. Neither the header nor the separator is standardized, so both are named rather than guessed | `,` |

## Where files hanging off a finding are kept

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

    WARN attachment links cross the network in the clear endpoint=http://minio.internal:9000

This is not `OPENPSIRT_PLAIN_HTTP`, which is about serving this application
without TLS and loosens cookies. One is a file on the way out and the other a
session on the way in; a deployment can want either without the other.

## Reading a scan file

A scan file is somebody else's output arriving over a link this deployment does
not control, so it is read within bounds. These are the ceilings; each is
refused with a sentence naming what was exceeded rather than by failing
partway.

Leave one unset and it keeps the built-in value, so a deployment changing one
does not have to restate the rest.

The built-in values are set from what reading a document costs in memory, not
from how large a document looks. An edge holds about half a kilobyte of heap
while it is being read and a component about one and a third, so the defaults
below allow roughly 250 MB for one document — about half the memory limit the
chart ships with. They are still several times the largest producer we have.
Raise them on a deployment with a bigger box and a bigger inventory, and raise
the container's memory limit with them.

| Variable | What it does | Default |
|---|---|---|
| `OPENPSIRT_INGEST_MAX_BYTES` | How large a single document may be | 256 MB |
| `OPENPSIRT_INGEST_MAX_COMPONENTS` | How many components it may describe. About 1.3 KB of heap each while reading | 100,000 |
| `OPENPSIRT_INGEST_MAX_EDGES` | How many dependency edges it may declare. The component count does not bound this: a thousand components can declare a million edges between them. About 0.5 KB of heap each while reading | 250,000 |
| `OPENPSIRT_INGEST_MAX_FILES` | How many files a document may catalog. Not covered by the component count: a real scan catalogs forty-five to fifty-six files per package, so one bound cannot size both | 500,000 |
| `OPENPSIRT_INGEST_MAX_STATEMENTS` | How many claims a suppression document may make | 100,000 |
| `OPENPSIRT_INGEST_MAX_DEPTH` | How deeply it may nest | 64 |
