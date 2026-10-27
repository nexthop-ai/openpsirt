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

Two adapters, one configured at a time: OpenID Connect for an identity provider,
and plain OAuth 2.0 for a forge that issues no identity token and publishes no
discovery document, whose account is asked about.

| Rule | Reason |
|---|---|
| Configuring both stops the process, naming the two settings | An identity is a username (REQ-41), and two providers issuing usernames make one name either one person or two |
| Configuring none is no fault | A reverse proxy authenticates instead |
| A broken sign-in configuration is refused at startup | Whoever started it sees it, never the first person signing in |
| The forge's team listing is read to the end, up to twenty full pages, with one more asked for to tell a whole listing from a longer one; a listing full past the bound refuses the sign-in | The listing spans every organization the person belongs to. Refusing beats silently withdrawing roles from somebody in many teams |
| The exchange happens here and the browser gets this deployment's session; a provider's token never reaches a page | A browser holding one would be a second way to authenticate, verified by a second path |
| What survives the round trip, the echoed value, the value tying the answer to this request and the proof-key secret, stays with the browser where no script reads it | A table of half-finished sign-ins has to be swept and anybody can fill it |

| Check | Prevents |
|---|---|
| The echoed value is compared **before** anything is exchanged | A signed-in person handed a callback of somebody else's making getting that person's session |
| The proof key is sent as a digest and kept as the secret it hashes | An authorization code taken in flight being exchanged by whoever took it |
| The identity token must carry the value tying it to this sign-in | It belonging to another sign-in |
| An identity token naming no subject is refused | The deployment quietly matching by name alone |
| An identity with a NUL character in its subject, username, name, address or groups is refused | Dropping the character makes two identities one, and a NUL fails the statement on two engines |
| A provider's address is recorded only where the provider says it verified it | Mail about an undisclosed finding going wherever an account holder typed. No address redeems an authorization; the username claim alone does |
| The sealed value carries when it was minted, and a stale one is refused | The browser holding it may have planted it, and the sealing key never rotates, so a months-old sign-in would stay acceptable |

## Outbound provider fetches

Discovery, the key fetches after it, the code exchange and every forge call go
through one client that talks to the configured host alone, follows no redirect,
and connects to no address inside this network. Every fetch out of this process
uses the one client; a per-caller client forgets a control, and the library's
default has no timeout and follows ten redirects.

An address inside this network is loopback, private, link-local, multicast or
unspecified, or in a block the internet does not route: carrier-grade
translation, "this network", benchmarking, protocol assignments, reserved, IPv6
site-local, IPv4-compatible IPv6, and the local-use NAT64 prefix. An address in
the well-known NAT64 prefix, and a 6to4 address, is judged by the IPv4 address
inside it, against the built-in blocks and the administrator's excluded
networks alike.

| Rule | Reason |
|---|---|
| The endpoints a provider publishes are checked against the issuer's own host when the adapter is built; a provider that would misdirect stops the process | A document from the right host can name endpoints on another |
| The address check runs after the name resolves and before the connection is made | Earlier it sees a name; resolving separately leaves a window to resolve differently |
| Every refusal the client makes, at the dial or before it, is told apart from a host that did not answer, and an internal or excluded address apart again | What a name resolves to can change |
| The exchange, carrying the client secret and the code, re-resolves the issuer's name on every sign-in and is held to all of it | It is the fetch that matters most |
| The return address is stated in configuration, never taken from the request; a provider configured without it does not start | Otherwise it is whatever a caller claimed the host was |
| Every request out carries one User-Agent, set where every request passes | A receiver sees one name; a forgotten one sends the library's |
| An address an administrator configured, a webhook or a chat server, uses the same client without the address check: https only, no user in the address, no redirect | The operator typed it, and REQ-69 lets it reach wherever that is |
| An upstream an administrator named uses the same client pinned to its host, without the address check | Its documents name further addresses, and any on another host is refused before resolving (`design-docs/upstream.md` § Requests) |
| An answer read back from a provider is bounded | A profile is a few hundred bytes; an endless body allocates until the process dies |

## Trusted-header sign-in

A reverse proxy authenticates and passes the username on, with no provider or
beside one, where the name it asserts is the same person as that name at the
provider.

| Rule | Reason |
|---|---|
| Two deliberate acts: naming the header, and naming the sources it is honored from. A half-configuration stops the process | Reaching the container directly bypasses the proxy, so trusting the header unconditionally lets anybody be anybody, administrator included |
| Membership may come in a second header, with its name and separator configured | It extends no trust: whoever forges it could forge the username header. Neither is standardized |
| The sources are also the proxies whose forwarded client the published documents rate-limit (`design-docs/publishing.md`) | A deployment names its proxies once. Where it publishes, they may be named with no header and are read for that alone, and every address is still refused as a source |

## Name and identifier

An administrator authorizes a name; a provider reports a username and its own
identifier, and only the identifier is stable.

- The username is redeemed once: the first successful sign-in pins the provider's identifier to the authorization waiting under that name.
- From then on the identifier decides, and the username is followed as a label.

A username that moves fails closed: a renamed holder is still recognized, and a
newcomer registering the released name holds a different identifier and is
refused. Pinning at first use keeps authorization in advance, since nobody knows
an identifier before its holder arrives.

### One identity, two arrival paths

An identity is a username, unqualified by the path it arrived on (REQ-41).

| Arrival | Matched by | Binds |
|---|---|---|
| The provider | Its identifier where one is bound; otherwise the name, which binds it | The identifier, at that sign-in |
| A trusted proxy | The name | Nothing |

| Rule | Reason |
|---|---|
| A proxy binds nothing, and the provider binds afterwards | Whichever path somebody arrives by first, both keep working |
| A bound identifier does not refuse a proxy arrival | Trusting the header already grants whoever sets it the power to claim anybody |
| Which path an arrival took is stated, never inferred from an empty identifier | A boundary turning on a field left empty by accident fails quietly |
| A username is folded; an identifier is not | An administrator types the name and a provider reports it, and a mismatch in capitals leaves an authorization nobody redeems, or a second account under group-bound admission. Folded as stored, so no collation decides (REQ-08) |
| An identifier is unbound by an administrator, never by a sign-in | Changing provider leaves every pinned account refused, and clearing that automatically would let whoever took a released name redeem it |

### Provider attribution

The issuer is recorded beside each identifier it minted, at the same moment.
The issuer, never the button's label, because a provider change ordinarily
keeps the label.

| Rule | Reason |
|---|---|
| Discovery asks for the issuer as written, and again as published where the two differ only by a trailing slash; any other difference is refused at startup | The document is compared character for character, and providers differ on the slash |
| The issuer is recorded without a trailing slash | One provider whichever spelling is written |
| An identifier is read only as its issuer meant it | The same string names different people at two providers |
| An arrival naming no provider is refused | A binding with no issuer cannot be told from another provider's |
| A bound identity whose issuer is no longer configured stops the process | One provider at a time is a rule across time (REQ-41), and nothing at sign-in tells a reinterpreted identifier apart |
| A row bound before the provider was recorded reads as the one configured now | Nothing else is possible, and refusing would lock out a deployment that never changed provider |
| Unbinding clears the identifier and its provider together | A leftover provider reads as a binding nobody withdrew |
| A match that could not be read is a fault on every way in, answered 500 and logged as an error | Read as "not authorized", an outage turns everybody away and logs a run of strangers |

### The way in without the provider

| Situation | What to do |
|---|---|
| The provider is down and people must sign in | Configure the trusted header with no provider. A pinned identifier does not refuse a proxy arrival |
| The provider is changing | Unbind each person, then configure the new provider; each authorization is redeemed again under its name. Unbinding is a control beside each pinned name on the Access screen and needs a signed-in administrator |
| The provider is changing and the old one cannot be reached | The same, through the trusted header, since an undiscoverable provider stops the process |

| Rule | Reason |
|---|---|
| A provider its bound identities do not name refuses to start, and says how to undo it | The refusal is the only place anybody learns the bindings need withdrawing |
| The redemption window is charged on every path a name arrives by | On the proxy path a name alone decides who gets the roles |

### The redemption window

An unredeemed authorization is matched by name alone, so it lapses.

| Rule | Reason |
|---|---|
| An unredeemed authorization stops being redeemable, on every path | Left open, it waits for whoever turns up holding the name |
| Authorizing somebody again restarts it, and so does unbinding them | An administrator named in configuration is authorized again at every start, so never loses the way in |
| The window is written when the authorization is, from the setting in force then; unbinding writes the configured window, read inside the act | Changing the setting never extends what is standing |
| Thirty days where nobody has said | Long enough for a start date, a notice period or a holiday |
| A group mapping adopts a recorded account only while its authorization is redeemable, and never reopens the window | Adopting a lapsed one renews it for whoever holds the name |
| A group mapping adopts only an authorization waiting under the name | A holder whose name moved away left none, and the next holder is somebody new. Direct mode refuses the same arrival |
| A redeemed authorization is not held to it | The identifier decides from then on |

### The username claim

An OpenID Connect provider is told which claim carries the username, with no
default.

| Rule | Reason |
|---|---|
| The operator states the claim or the process refuses to start | Which claim end users cannot choose is a fact about the provider; `preferred_username` is self-chosen on some providers and assigned on others |
| The property required is that an end user cannot choose the value | Narrower than immutable: the subject is the identity, and a rename after binding is followed as a label |
| The subject cannot serve as the claim | An authorization is written before anybody arrives, for a name a person can type |
| A missing claim setting is refused before discovery, naming the setting | No provider needs to be reachable |
| A token without the claim is refused, and the log names the claim | A verified address or the subject in its place is a value the operator never chose |
| The issuer is read with surrounding spaces ignored | A file or template leaves them |
| The groups claim is named with surrounding spaces ignored, once | Whether a provider reports groups decides at startup whether mappings are accepted, so the claim checked is the claim read |

## Mail addresses

A person's mail address is optional; somebody without one is told nothing
outside the application and keeps the area inside it.

| Rule | Reason |
|---|---|
| An administrator sets it with the record, and a sign-in provider fills in one nobody set, in either role-assignment mode | A provider covers the ordinary case and nothing on the trusted-header path or before a first sign-in |
| Which source wrote it is kept; a provider refreshes only what a provider gave | An administrator's correction is never put back by the next sign-in |
| A provider's address is taken only where the provider says it checked it; one forge is asked for its confirmed addresses, never the public profile | An unchecked address is whatever the account holder typed |
| Failing to record an address does not fail a sign-in | |

## Session state

What a sign-in remembers while the browser is at the provider stays in a cookie
with the browser.

| Rule | Reason |
|---|---|
| **It is signed with this deployment's own key** | Unsigned, somebody able to write a cookie on this host plants their own state and verifier and the callback hands the victim a session for the attacker's account |
| The key is stored, never held in memory, and minted the first time it is wanted | A sign-in begun on one replica is finished by any, across a restart |
| The return address is checked on the way in and again on the way out | § Sign-in return addresses |

When a person, session, personal token or pipeline key was last used is written
only once the recorded time is an hour old, through one helper every resolver
calls. A write per request makes that row the hottest in the database, turns a
read into a write a follower cannot serve, and conflicts at commit on a
cluster. The date is what a credential review reads.

## Sessions and request forgery

A session is stored, so it works on any replica and deleting the row cuts access
at once. It holds no roles: what a request reaches is read when it asks, so a
withdrawn role takes effect on the next request. The token is stored hashed and
the cookie cannot be read by script.

A browser's credential arrives whoever caused the request, on both browser
paths.

| Arriving by | Proof required |
|---|---|
| A session | A value bound to the session, which this deployment's pages read and echo and another origin cannot read |
| A proxy's header | Where the request came from, since there is no session and a browser does not let a page misstate its origin |

| Rule | Reason |
|---|---|
| Origin is checked on both paths | It costs nothing and holds when the echoed value has leaked |
| Requests carrying a key or a token are exempt | Nothing sends those automatically |
| Safe methods are named as a list | A method nobody thought of is guarded |
| Both origins are compared as a browser serializes them: scheme and host lower case, no default port | A base address naming `https://psirt.example.com:443` is the origin a browser calls `https://psirt.example.com`; compared as written, every write from the deployment's own page is refused |

## Sign-in return addresses

A sign-in may carry the address it began at, so somebody whose session ended
lands back on their screen.

| Rule | Reason |
|---|---|
| The address is kept in the sign-in cookie | Nothing a provider echoes back decides where somebody lands |
| It is kept only when it starts with a single `/`, does not start with `//` or `/\`, and parses with no scheme and no host | Browsers read `//` and `/\` as protocol-relative. This is the whole of the defense |
| Checked on the way in and again on the way out | The browser may edit its cookie, and an address that left here is one this deployment sent |
| A bad address is discarded, never refused | A link somebody else wrote must not fail a sign-in |

## Values a deployment mints

Some settings are written by the deployment itself, chiefly the key sealing
sign-ins in flight. Sessions never depend on it: a session is a random secret
resolved by its hash, so losing this key costs only the sign-ins in flight.

| Rule | Reason |
|---|---|
| Minted only where nothing holds one, and the answer is what is stored | Two replicas starting together both mint; a plain set lets the second refuse every sign-in sealed with the first |
| The caller takes whichever key won | It wants the key everybody agrees on |
| A stored key that is empty, short or not one this minted fails sign-in closed; removing the row lets the next sign-in mint afresh | An empty key is one anybody can compute |

## Browser headers

Every response carries headers turning off what nothing here needs (REQ-69): no
content-type sniffing, no framing by any page, referrers kept to this origin,
and a content security policy permitting only what the bundled interface ships:
its own scripts, styles and fonts, `data:` images, and requests to itself. Inline
styles are allowed, because the chart library writes them.

| Rule | Reason |
|---|---|
| Set **before any handler**, on API answers as well as pages | A later route cannot lack them, and a JSON body opened in a browser is covered. They are the second line behind the markdown sanitizer |
| The page's own inline script, which applies the chosen theme before first paint, is allowed by its hash and nothing wider | `'unsafe-inline'` allows every inline script, one smuggled past the sanitizer included |
| The hash is taken from what is served | A hand-kept hash drifts when a build step touches the snippet, and the browser refuses it silently |
| `base-uri` permits nothing and `form-action` permits this origin | A `<base>` element rewrites every relative address without a fetch directive, and a form's action is not a fetch |
| A download filename is made safe where the header is written | A product's name may hold a quote or a carriage return. The check at the header covers every export, later ones included |

## Limits

| Limit | Detail |
|---|---|
| Trusted-header sign-in has no stable identifier | It asserts a username on every request, and the proxy is the authority |
| Proxies delivering identity in a signed token are not supported by the header path | A header read cannot verify a signature; such deployments configure a provider |
| Naming every address as a trusted source is refused | It reaches what naming none reaches. An IPv4-mapped range is held as its IPv4 range, so `::ffff:0:0/96` is refused with `0.0.0.0/0` |
