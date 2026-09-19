# Sending a build's inventory

What a build pipeline does, end to end. Everything here is one HTTP request;
there is no client to install and no agent to run.

The short version: **declare what you ship once, mint a key once, and post the
inventory on every build.**

## What has to exist first

A scan is filed against a product, a stream and a variant, and an upload naming
something undeclared is refused — the error says which part is missing. That is
deliberate: a typo in a pipeline would otherwise create a fourth product nobody
meant, and the first anybody would know is a screen with four of everything.

| | |
|---|---|
| **Product** | The thing you ship. `sonic` |
| **Stream** | A branch that keeps moving, or a tag that was built once. `main`, `v2.4.1` |
| **Variant** | How it was built. `broadcom`, `amd64`, `container` |

Declaring is three requests, and you make them once rather than per build.
Each is administration, so each needs an administrator — a pipeline's key
cannot declare anything.

Scripting these needs an `Origin` header. A write arriving with no session
of ours behind it is guarded against forgery by the origin it states, so a
request made from a shell through a trusted-header proxy is refused as "not
from a page this deployment served" until it says where it came from. Add
`-H "Origin: $OPENPSIRT"` to each of the three. Making them from the interface
needs nothing extra.

```bash
curl -X POST "$OPENPSIRT/v1/products" \
  -H 'Content-Type: application/json' \
  -d '{"name": "sonic", "display_name": "SONiC"}'

curl -X POST "$OPENPSIRT/v1/products/sonic/streams" \
  -H 'Content-Type: application/json' \
  -d '{"name": "main", "kind": "branch"}'

curl -X POST "$OPENPSIRT/v1/products/sonic/variants" \
  -H 'Content-Type: application/json' \
  -d '{"name": "broadcom", "customer_facing": true}'
```

A tag names the branch it was cut from, which is what release comparison reads:

```bash
curl -X POST "$OPENPSIRT/v1/products/sonic/streams" \
  -H 'Content-Type: application/json' \
  -d '{"name": "v2.4.1", "kind": "tag", "parent": "main"}'
```

## Minting a key

A pipeline authenticates with an API key, which is a credential rather than a
person: it may file scans and it holds none of a person's rights.

```bash
curl -X POST "$OPENPSIRT/v1/keys" \
  -H "Origin: $OPENPSIRT" \
  -H 'Content-Type: application/json' \
  -d '{"name": "sonic-ci", "product": "sonic"}'
```

A key is scoped to one product, which is required rather than optional, and
may be narrowed further to one stream and one variant. So a deployment shipping
three products has three keys, and a key that leaks reaches one of them.

The secret comes back once in `item.secret`, begins `opk_`, and is stored hashed — a credential
store that can hand back what it holds gives up every pipeline's key with a copy
of the database. Put it in your CI's secret store on the way past; there is no
second chance to read it.

Creating one needs a session, not another key: a credential cannot create
another, and one that could would outlive the person who made it.

Nothing further is granted. Declaring a product is administration and filing
against it is not, so a person holds nothing on a product until somebody grants
it — but a key carries the product it was made for, so a pipeline needs no
grant of its own.

## Sending the inventory

Your build already produces an SBOM. Send it.

```bash
curl -X POST \
  "$OPENPSIRT/v1/products/sonic/streams/main/variants/broadcom/scans" \
  -H "Authorization: Bearer $OPENPSIRT_KEY" \
  -F "inventory=@sbom.cdx.json"
```

| | |
|---|---|
| `inventory` | The SBOM. CycloneDX 1.x, SPDX 2.x or SPDX 3.x — the format is read from the document, not declared |
| `suppressions` | Optional, repeatable. OpenVEX documents stating what this build has already dealt with |

A 202 means accepted, not valid. The documents are parsed afterwards, so the
response says the upload arrived and nothing about whether it could be read.
That is the one thing to get right in a pipeline: a green step here is not a
green scan.

## Finding out what happened

Poll the scans for that build.

```bash
curl -H "Authorization: Bearer $OPENPSIRT_KEY" \
  "$OPENPSIRT/v1/products/sonic/streams/main/variants/broadcom/scans"
```

Each entry carries `state`, and where something went wrong, `failure` — in the
words the screen shows, so the person reading the failed step and the person
opening the interface are reading the same sentence.

```json
{"scan_id": 1, "state": "failed",
 "failure": "run grype: exec: \"grype\": executable file not found in $PATH",
 "components": 106, "placed": 106}
```

`components` against `placed` is worth watching: it is the difference between a
document describing a graph and one that is a list. One component placed
nowhere is ordinary; a document placing none of them produces findings that are
each correct and cannot answer "why is this here" about any of them.

Reading the inventory and scanning it are separate work with different rhythms:
an inventory is read once, and scanned again whenever the vulnerability data
moves. So a scan appearing is not the same as findings appearing.

## GitHub Actions

```yaml
- name: Send the inventory to OpenPSIRT
  env:
    OPENPSIRT: ${{ vars.OPENPSIRT_URL }}
    OPENPSIRT_KEY: ${{ secrets.OPENPSIRT_KEY }}
  run: |
    curl --fail-with-body -X POST \
      "$OPENPSIRT/v1/products/sonic/streams/main/variants/${{ matrix.variant }}/scans" \
      -H "Authorization: Bearer $OPENPSIRT_KEY" \
      -F "inventory=@sbom.cdx.json"
```

`--fail-with-body` rather than `--fail`, so a refusal prints why rather than
only failing the step.

## GitLab CI

```yaml
send-inventory:
  stage: .post
  image: curlimages/curl:latest
  script:
    - |
      curl --fail-with-body -X POST \
        "$OPENPSIRT/v1/products/sonic/streams/$CI_COMMIT_BRANCH/variants/broadcom/scans" \
        -H "Authorization: Bearer $OPENPSIRT_KEY" \
        -F "inventory=@sbom.cdx.json"
```

Naming the stream from `$CI_COMMIT_BRANCH` is the shape that bites: **the
stream has to have been declared.** A pipeline running on a branch nobody
declared is refused, every build, until somebody declares it — and the refusal
says which part is missing rather than making you guess:

```
404  product "sonic": stream "nobody-declared-this": not declared
```

## What a pipeline is not asked to do

| | |
|---|---|
| **No scanning** | The deployment scans what you send, on its own schedule, against the vulnerability data of the day. A release that is never rebuilt has the same components and a different answer next month |
| **No results in the build log** | Nothing is returned for a pipeline to print. A build log is readable by everybody with access to CI, and a pre-triage count is both sensitive and wrong |
| **No pass or fail** | There is no build gate. What a scan reports depends on what the vulnerability data knows that day rather than on what the commit changed, so the same commit would pass today and fail tomorrow — which is the property that makes a gate get switched off. A build that introduces a known-exploited critical tells somebody instead |
