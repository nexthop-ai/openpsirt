# Sign-in and sessions

Provider and trusted-header sign-in, how an arrival matches an authorization,
sessions, request forgery, and the headers every response carries.

Satisfies REQ-08, REQ-41, REQ-68, REQ-69.

## Contents

- [Provider sign-in](#provider-sign-in)
- [Outbound provider fetches](#outbound-provider-fetches)
- [Trusted-header sign-in](#trusted-header-sign-in)
- [Name and identifier](#name-and-identifier)
- [Mail addresses](#mail-addresses)
- [Session state](#session-state)
- [Sessions and request forgery](#sessions-and-request-forgery)
- [Sign-in return addresses](#sign-in-return-addresses)
- [Values a deployment mints](#values-a-deployment-mints)
- [Browser headers](#browser-headers)
- [Limits](#limits)

## Provider sign-in

Two adapters, one configured at a time: OpenID Connect, and plain OAuth 2.0 for
a forge that issues no identity token and publishes no discovery document.

| Rule | Reason |
|---|---|
| Configuring both stops the process, naming the two settings | An identity is a username (REQ-41), and two issuers make one name ambiguous |
| Configuring none is no fault | A reverse proxy authenticates instead |
| A broken sign-in configuration is refused at startup | |
| The forge's team listing is read to the end, up to twenty full pages, with one more asked for to tell a whole listing from a longer one; a listing full past the bound refuses the sign-in | It spans every organization; refusing beats silently withdrawing roles |
| The exchange happens here and the browser gets this deployment's session; a provider's token never reaches a page | It would be a second, unverified way to authenticate |
| The echoed value, the value tying the answer to this request and the proof-key secret stay with the browser where no script reads them | A server table of half-finished sign-ins has to be swept and anybody can fill it |

| Check | Prevents |
|---|---|
| The echoed value is compared **before** anything is exchanged | A callback of somebody else's making giving a signed-in person that somebody's session |
| The proof key is sent as a digest and kept as the secret it hashes | A code taken in flight being exchanged |
| The identity token must carry the value tying it to this sign-in | A token from another sign-in |
| An identity token naming no subject is refused | Matching by name alone |
| An identity with a NUL character in its subject, username, name, address or groups is refused | Two identities read as one; a NUL fails the statement on two engines |
| A provider's address is recorded only where the provider says it verified it; no address redeems an authorization | Mail about undisclosed work going wherever an account holder typed |
| The sealed value carries when it was minted, and a stale one is refused | The sealing key never rotates, and the browser holding the value may have planted it |

## Outbound provider fetches

Every fetch out of this process uses one client. For discovery, the key fetches,
the code exchange and forge calls it talks to the configured host alone, follows
no redirect, and connects to no address inside this network.

An address inside this network is loopback, private, link-local, multicast or
unspecified, or carrier-grade translation, "this network", benchmarking,
protocol assignments, reserved, IPv6 site-local, IPv4-compatible IPv6, or the
local-use NAT64 prefix. A well-known NAT64 or a 6to4 address is judged by the
IPv4 address inside it, against the built-in blocks and the administrator's
excluded networks alike.

| Rule | Reason |
|---|---|
| The endpoints a provider publishes are checked against the issuer's host when the adapter is built; a misdirecting provider stops the process | A document from the right host can name another |
| The address check runs after the name resolves and before the connection is made | A separate resolution can answer differently |
| Every refusal the client makes is told apart from a host that did not answer, and an internal or excluded address apart again | |
| The exchange re-resolves the issuer's name on every sign-in, under every control | It carries the client secret and the code |
| The return address is stated in configuration; a provider configured without it does not start | A request's host is whatever the caller claimed |
| Every request out carries one User-Agent, set where every request passes | |
| An address an administrator configured, a webhook or a chat server, uses the client without the address check: https only, no user in the address, no redirect | REQ-69 lets an operator's address reach anywhere |
| An upstream an administrator named uses the client pinned to its host | `design-docs/upstream.md` § Requests |
| An answer read back from a provider is bounded | An endless body exhausts memory |

## Trusted-header sign-in

A reverse proxy authenticates and passes the username on, alone or beside a
provider, where the asserted name is that name at the provider.

| Rule | Reason |
|---|---|
| Naming the header and naming the sources it is honored from are both required; a half-configuration stops the process | Reaching the container directly bypasses the proxy |
| Membership may come in a second header, with its name and separator configured | It extends no trust beyond the username header |
| The sources are also the proxies whose forwarded client the published documents rate-limit (`design-docs/publishing.md`) | Where it publishes, they may be named with no header and are read for that alone, and every address is still refused as a source |

## Name and identifier

An administrator authorizes a name; a provider reports a username and its own
identifier, and only the identifier is stable.

- The first successful sign-in pins the provider's identifier to the authorization waiting under that name.
- From then on the identifier decides, and the username is followed as a label.

A renamed holder is still recognized, and a newcomer under a released name is
refused.

### One identity, two arrival paths

An identity is a username, unqualified by the path it arrived on (REQ-41).

| Arrival | Matched by | Binds |
|---|---|---|
| The provider | Its identifier where one is bound; otherwise the name, which binds it | The identifier, at that sign-in |
| A trusted proxy | The name | Nothing |

| Rule | Reason |
|---|---|
| A proxy binds nothing, and the provider binds afterwards | Arrival order does not decide which path works |
| A bound identifier does not refuse a proxy arrival | Trusting the header already trusts it to claim anybody |
| Which path an arrival took is stated, never inferred from an empty identifier | |
| A username is folded as stored; an identifier is not (REQ-08) | A capitals mismatch leaves an authorization nobody redeems, or a second account under group-bound admission |
| An identifier is unbound by an administrator, never by a sign-in | Automatic unbinding would let whoever took a released name redeem it |

### Provider attribution

The issuer, never the button's label, is recorded beside each identifier, at
the same moment.

| Rule | Reason |
|---|---|
| Discovery asks for the issuer as written, and again as published where the two differ only by a trailing slash; any other difference is refused at startup | Providers differ on the slash |
| The issuer is recorded without a trailing slash | |
| An identifier is read only as its issuer meant it | One string names different people at two providers |
| An arrival naming no provider is refused | |
| A bound identity whose issuer is no longer configured stops the process | One provider at a time is a rule across time (REQ-41) |
| A row bound before the provider was recorded reads as the one configured now | |
| Unbinding clears the identifier and its provider together | |
| A match that could not be read is a fault on every way in, answered 500 and logged as an error | An outage must not read as a run of strangers |

### The way in without the provider

| Situation | What to do |
|---|---|
| The provider is down and people must sign in | Configure the trusted header with no provider |
| The provider is changing | Unbind each person, then configure the new provider; each authorization is redeemed again under its name. Unbinding is a control beside each pinned name on the Access screen and needs a signed-in administrator |
| The provider is changing and the old one cannot be reached | The same, through the trusted header, since an undiscoverable provider stops the process |

A provider its bound identities do not name refuses to start, and says how to
undo it.

### The redemption window

| Rule | Reason |
|---|---|
| An unredeemed authorization stops being redeemable, on every path a name arrives by | Matched by name alone, it waits for whoever holds the name |
| Authorizing somebody again restarts it, and so does unbinding them | A configured administrator, authorized at every start, keeps the way in |
| The window is written with the authorization, from the setting then; unbinding writes the configured window, read inside the act | A changed setting never extends what stands |
| Thirty days where nobody has said | |
| A group mapping adopts a recorded account only while its authorization is redeemable, never reopening the window | |
| A group mapping adopts only an authorization waiting under the name | Direct mode refuses the same arrival |
| A redeemed authorization is not held to it | |

### The username claim

| Rule | Reason |
|---|---|
| The operator states which OpenID Connect claim carries the username, or the process refuses to start | `preferred_username` is self-chosen on some providers and assigned on others |
| The claim must be one an end user cannot choose | |
| The subject cannot serve as the claim | An authorization is written before anybody arrives |
| A missing claim setting is refused before discovery, naming the setting | |
| A token without the claim is refused, and the log names the claim | No other value stands in |
| The issuer is read with surrounding spaces ignored | |
| The groups claim is named with surrounding spaces ignored, once | The claim checked at startup is the claim read |

## Mail addresses

A person's mail address is optional; without one they are told nothing outside
the application.

| Rule | Reason |
|---|---|
| An administrator sets it, and a sign-in provider fills in one nobody set, in either role-assignment mode | |
| Which source wrote it is kept; a provider refreshes only what a provider gave | An administrator's correction stays |
| A provider's address is taken only where the provider says it checked it; one forge is asked for its confirmed addresses | |
| Failing to record an address does not fail a sign-in | |

## Session state

What a sign-in remembers while the browser is at the provider stays in a cookie.

| Rule | Reason |
|---|---|
| **It is signed with this deployment's own key** | Unsigned, a planted state and verifier gives a victim the attacker's session |
| The key is stored and minted the first time it is wanted | Any replica finishes a sign-in, across a restart |
| The return address is checked on the way in and out | § Sign-in return addresses |
| When a person, session, personal token or pipeline key was last used is written only once the recorded time is an hour old, through one helper | A write per request makes the row the hottest, turns reads into writes, and conflicts at commit on a cluster |

## Sessions and request forgery

A session is stored, so any replica serves it and deleting the row cuts access.
It holds no roles, so a withdrawn role applies on the next request. The token is
stored hashed and the cookie is unreadable by script.

| Arriving by | Proof required |
|---|---|
| A session | A value bound to the session, which this deployment's pages read and echo |
| A proxy's header | Where the request came from |

| Rule | Reason |
|---|---|
| Origin is checked on both paths | It holds when the echoed value has leaked |
| Requests carrying a key or a token are exempt | Nothing sends those automatically |
| Safe methods are named as a list | A method nobody thought of is guarded |
| Both origins are compared as a browser serializes them: scheme and host lower case, no default port | `https://psirt.example.com:443` is the origin `https://psirt.example.com`; compared as written, the deployment's own writes are refused |

## Sign-in return addresses

A sign-in may carry the address it began at.

| Rule | Reason |
|---|---|
| The address is kept in the sign-in cookie | Nothing a provider echoes decides where somebody lands |
| It is kept only when it starts with a single `/`, does not start with `//` or `/\`, and parses with no scheme and no host | This is the whole of the defense |
| Checked on the way in and again on the way out | The browser may edit its cookie |
| A bad address is discarded, never refused | |

## Values a deployment mints

The key sealing sign-ins in flight is written by the deployment itself. A
session is a random secret resolved by its hash, so losing the key costs only
sign-ins in flight.

| Rule | Reason |
|---|---|
| Minted only where nothing holds one, and the answer is what is stored; the caller takes whichever key won | Two replicas starting together both mint |
| A stored key that is empty, short or not one this minted fails sign-in closed; removing the row lets the next sign-in mint afresh | An empty key is computable by anybody |

## Browser headers

Every response carries (REQ-69): no content-type sniffing, no framing by any
page, referrers kept to this origin, and a content security policy permitting
only the bundled interface's own scripts, styles and fonts, `data:` images, and
requests to itself. Inline styles are allowed, because the chart library writes
them.

| Rule | Reason |
|---|---|
| Set **before any handler**, on API answers as well as pages | They back up the markdown sanitizer |
| The page's own inline script, which applies the theme before first paint, is allowed by its hash and nothing wider | `'unsafe-inline'` allows a smuggled script too |
| The hash is taken from what is served | A hand-kept hash drifts |
| `base-uri` permits nothing and `form-action` permits this origin | Neither a `<base>` element nor a form action is a fetch |
| A download filename is made safe where the header is written | A product name may hold a quote or a carriage return |

## Limits

| Limit | Detail |
|---|---|
| Trusted-header sign-in has no stable identifier | The proxy is the authority |
| Proxies delivering identity in a signed token are not supported by the header path | A header read cannot verify a signature; such deployments configure a provider |
| Naming every address as a trusted source is refused | It reaches what naming none does. An IPv4-mapped range is held as its IPv4 range, so `::ffff:0:0/96` is refused with `0.0.0.0/0` |
