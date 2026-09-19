# Evaluation

Two ways, for two different questions. The published image answers "what does
this thing do"; the checkout answers "what does my change do".

## The published image

```
docker run -p 8080:8080 \
  -v "$PWD/openpsirt-data:/data" \
  -e OPENPSIRT_DATABASE_URL="sqlite:///data/openpsirt.db" \
  -e OPENPSIRT_ADDR="0.0.0.0:8080" \
  -e OPENPSIRT_PLAIN_HTTP=1 \
  -e OPENPSIRT_BOOTSTRAP_ADMINS="you" \
  -e OPENPSIRT_TRUSTED_HEADER="X-User" \
  -e OPENPSIRT_TRUSTED_SOURCES="172.16.0.0/12,10.0.0.0/8,fd00::/8" \
  ghcr.io/nexthop-ai/openpsirt:0.1.0
```

It creates its own schema on startup and serves the interface and the API on
one port. The Helm chart is published beside the image, as
`openpsirt-0.1.0.tgz` on the same release.

!!! warning "Not a small production deployment"
    Plain HTTP, and administration handed to whoever a header says they are.
    It is for looking at.

### Sign-in

Nothing creates an account and no path admits an unknown arrival, so a
deployment that cannot tell who is asking serves nobody. There are two ways to
tell it, and the command above uses the second.

| | |
|---|---|
| A sign-in provider | One OpenID Connect provider, or GitHub. Configured at startup, and needed for anybody to sign in through a browser normally |
| A trusted header | A reverse proxy authenticates and passes the username on. Honored only from addresses you name, because reaching the container directly bypasses the proxy |

A browser cannot set a header, so the command above gives you an API to
drive with `curl` rather than an interface to click:

```
curl -H "X-User: you" http://localhost:8080/v1/people
```

To browse it you need something in front that sets the header — which is what
the demo below stands up, and what a real deployment does with its ingress.

!!! note "Name the addresses the header arrives from, not the ones you expect"
    The source is whatever presents the request to the container, which on a
    dual-stack docker host is often an IPv6 address rather than the bridge
    range. A header from anywhere else is refused and logged, and the refusal
    says only "not authorized" — the log is where it says why.

## From a checkout

```
make demo                    # build, start, seed two products, print the address
make demo DEMO_HOST=yourbox  # if you browse by something other than localhost
```

Docker is all you need, plus `curl` and `xz` to read the compressed fixtures.
The image builds the interface and the binary inside itself and carries the
scanner, and it builds from your working tree — so what comes up is your
change.

It seeds two products: a real switch image, and OpenPSIRT itself, from the
inventory the image carries of what it ships, so the screens that compare
across products have something to compare.

### The two-person control

A judgment is proposed by one person and agreed to by another, and approving
your own is refused, so one person cannot demonstrate this. The demo opens a
door per person, and two browser windows are two people:

| Door | Arrives as | May |
|---|---|---|
| `http://localhost:8080` | an administrator | administer the deployment |
| `http://localhost:8081` | Ana | triage, and approve somebody else's |
| `http://localhost:8082` | Ben | triage, and approve somebody else's |

Change the cast with `DEMO_CAST`, which takes `port:name:roles` entries:

```
make demo DEMO_CAST="8091:ana:public-read,public-triage,approver \
                     8092:ben:public-read,public-triage,approver"
```

### The rest of the commands

| | |
|---|---|
| `make demo-status` | What it found, and every door |
| `make demo-down` | Stops it |
| `make demo-reset` | Starts over, keeping the scanner's vulnerability database, which is large and slow to fetch |
| `make demo-triage` | A few judgments once the scans have landed: a dismissal, a deferral and a backport proposed by one of the cast and agreed to by another, plus an upgrade carried by a team |
| `make demo-vex` | A VEX document attributed to a distribution, written from what the scans actually found |
| `make demo-flaw` | One flaw in what this deployment ships, recorded by hand and undisclosed |
| `make dev` | This machine's binary plus the interface's own dev server, for editing the interface and watching it reload |

- A demo where every figure reads zero demonstrates nothing. Without
  `demo-triage` the review queue, the record of judgments, how long triage is
  taking and what is planned are all empty, and the screens answering those
  questions look broken rather than idle. It records through the cast's own
  doors, because one person proposing and a second agreeing is the control the
  whole tool rests on.
- `demo-vex` is separate from the seed because the scans run in the background,
  and a document written before them would name issues this deployment does not
  have.
- `make dev` needs Go, node and a scanner installed locally, and it does not
  exercise the interface the binary embeds. `make demo` does.
- Everything the demo writes stays in a git-ignored directory in the checkout.
