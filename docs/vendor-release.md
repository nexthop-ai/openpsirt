# A vendor's release

A vendor publishes a release's SBOM and its VEX document. Loaded here, every
judgment the vendor published for that release is recorded as the vendor's,
with its reason. What the vendor did not publish, such as a CVE disclosed after
the release, is open here as it is there.

Matching the vendor's counts at one moment is not the aim. Both deployments
scan against the vulnerability data of the day, so the counts agree when the two
update on roughly the same schedule.

## The two documents

| Document | |
|---|---|
| The SBOM | The release's inventory, as the vendor built it. CycloneDX 1.x, SPDX 2.x or SPDX 3.x |
| The VEX document | The vendor's VEX for the same build. OpenVEX or CSAF VEX |

An OpenPSIRT deployment offers two VEX documents per build. Either loads here:
the vendor's own judgments, or those with what the vendor's suppliers state
about their own products, in the suppliers' names. The second carries more.

A VEX document uploaded on its own has to name the build the way the SBOM names
its root: the same package identifier, at the same version. A VEX document an
OpenPSIRT deployment generates does this.

## The release here

A release is filed against a product, a stream and a variant, declared once by
an administrator. A vendor's release is a tag: it was built once and does not
change. [Build pipelines](pipeline.md) § Prerequisites has the three requests,
and § The pipeline key the key an upload takes.

```bash
curl -X POST "$OPENPSIRT/v1/products/sonic/streams" \
  -H "Origin: $OPENPSIRT" \
  -H 'Content-Type: application/json' \
  -d '{"name": "202605.1", "kind": "tag"}'
```

## One upload

The SBOM and the VEX document go in one request.

```bash
curl -X POST \
  "$OPENPSIRT/v1/products/sonic/streams/202605.1/variants/broadcom/scans" \
  -H "Authorization: Bearer $OPENPSIRT_KEY" \
  -F "inventory=@sonic-202605.1.cdx.json" \
  -F "suppressions=@sonic-202605.1.openvex.json"
```

The release is scanned here after the upload is read, and the VEX statements
apply to what the scan finds.

## A VEX document on its own

A VEX document the vendor revises after the release is uploaded by an
administrator, on its own. A statement naming the build's root is the build's
claim whichever way it arrived, and the next scan applies it. A later document
from the same publisher sets aside what the earlier one said.

```bash
curl -X POST \
  "$OPENPSIRT/v1/products/sonic/vex-statements?publisher=Vendor" \
  -H "Origin: $OPENPSIRT" \
  -F "statements=@sonic-202605.1.openvex.json"
```

## Statement effects

A statement names a component, and usually a product it ships inside.

| The statement names | Sent with the SBOM | Uploaded on its own |
|---|---|---|
| The build's root as the product | The build's claim, across the whole build | The same |
| A component of the build as the product | The build's claim, beneath that component and nowhere else: "zlib inside curl 8.5.0" answers the zlib curl pulls in | That component's supplier's statement. Where it says `not_affected` it closes the findings beneath that component |
| A product the build does not contain, or none | The build's claim, across the whole build | Evidence on the finding, and a prefill for a decision |

| The build's claim says | The finding |
|---|---|
| `not_affected` | Stays open, is not work, and shows the vendor's reason |
| `fixed` | Closes as patched |
| `affected` | Stays work, and shows the vendor's workaround |
| `under_investigation` | Stays work, and shows that the vendor is looking |

The finding screen shows each claim under "Build says", with its status, its
justification and the vendor's words. Where the claim came from a VEX document
uploaded on its own, it names the publisher and the document.

## Workarounds

A vendor that will not fix a flaw publishes what to apply instead. Here those
findings stay work, because the flaw is in the release and the workaround is
yours to apply. The findings list's "Build says" filter, set to "Affected",
gathers them.

A will-not-fix the vendor gave no workaround for is not in the VEX document,
because the format requires an action on a statement that a flaw applies. It is
open here, as an undecided finding.
