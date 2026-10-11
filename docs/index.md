<picture>
 <source media="(prefers-color-scheme: dark)" srcset="assets/openpsirt-logo-wide-dark.svg">
 <img alt="OpenPSIRT" src="assets/openpsirt-logo-wide.svg" width="420">
</picture>

# OpenPSIRT

Product security incident response for the software you ship.

OpenPSIRT is the open-source workbench for a product security team. It turns
the SBOMs your builds already produce into a tracked, triaged, auditable record
of every vulnerability in every release, from the first scan to the published
advisory.

!!! note "Alpha"
    Below 1.0 the API and the schema carry no compatibility promise. A
    database built by a release is upgraded in place, or, where it is too
    old, through an earlier release first; a database built by a release
    candidate or any other earlier build is recreated.
    [Current state](built.md) says what is built and what is not.

## Product security in one place

Every build you ship already produces a software bill of materials. OpenPSIRT
puts it to work. It reads the SBOM from your pipeline, scans every product
against the same vulnerability data, and keeps the result as a living record
of what each release contains and what threatens it.

That record stays current without anyone tending it. Nightly scans carry
findings forward, so the work your team has done is still standing in the
morning. Shipped releases are rescanned too, so a vulnerability published
months after a release went out is still found in it. A fix is never marked
done by hand: OpenPSIRT confirms it when the next scan of each release stops
finding the issue.

## Triage at scale

A modern product image carries a staggering number of findings. One real image
we measure against carries 335,021 of them. Nobody can read that list, and
nobody has to.

Most findings are answered by a handful of upgrades, and OpenPSIRT shows you
the handful. Fix bundles group findings by the upgrade that closes them. On a
real image, 5,047 fixable findings collapse into 271 upgrades, and a single
kernel upgrade closes 917 of them. One decision answers a whole bundle, and the
next scan proves it landed. Binary packages built from the same source move
together, so curl and the libraries built beside it are one decision.

Backports stop being a puzzle. A kernel advisory often lists its fix as five
bare commits. OpenPSIRT reads the repository and tells you which commit is the
fix for 6.1, 6.6, 6.12, 6.16 and the mainline, so each maintained branch gets
the patch it needs.

Judgments travel with the code. A decision made on one release carries to every
other release, tag and variant that ships the same dependency chain, so the
same question is answered once. When a supplier states that its product is not
affected, every finding reached only through that product closes, and opens
again if the statement changes.

## Accuracy you can defend

Every number OpenPSIRT reports can be traced to the evidence behind it.

A finding is a component at a specific place in a specific build, so a judgment
holds exactly where it was made, and a judgment about risk lapses when the code
under it moves.
Identity is derived from content, never from identifiers a scan file happens
to carry, so the same component is recognized from one build to the next and
from one SBOM producer to another. Every finding records the scanner, its
version, its database and how the match was made.

Nothing disappears quietly. Every finding that closes says why: it was
upgraded, removed, patched, revised or superseded. One that vanishes with no
explanation is flagged, at any volume. A scanner match judged wrong stays
answered at every version, and an issue's own CVE record narrows what the
scanner claims. Versions are ranked only for ecosystems with a defined
ordering, so an upgrade recommendation is never a guess.

## Cyber Resilience Act readiness

The EU [Cyber Resilience Act](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)
makes vulnerability handling a legal duty for manufacturers of products with
digital elements sold in the EU. Its reporting obligations apply from 11 September
2026, and the rest from 11 December 2027.

OpenPSIRT gives you the records the regulation asks for. Each build's SBOM is
kept with its full dependency graph. Remediation runs on deadlines set by
policy, and every fix is verified by a scan. Reports from outside carry a
coordinated disclosure date. Fixed vulnerabilities are published as CSAF
advisories in a standard provider directory, and every build has its own VEX
document.

When a vulnerability in your product is actively exploited, the clock starts
the moment you know. OpenPSIRT records that moment, runs the notice windows you
declare for the early warning, the notification and the final report, alerts
you as each one opens and passes, and keeps a record of every notice you give.
Your counsel decides which obligations apply. OpenPSIRT holds the facts and the
clocks they run on.

## FIRST PSIRT Services Framework

The [FIRST PSIRT Services Framework](https://www.first.org/standards/frameworks/psirts/psirt_services_framework_v1.1)
is the shared description of what a product security team does. OpenPSIRT gives
that work a home.

Reports from finders are recorded the moment they reach you, judged with a
second person agreeing before any is rejected, and credited the way the finder
asked. Every
component of every product is watched for new vulnerabilities. Triage records
one outcome per finding, with its reasoning. Remediation is planned against the
releases it targets and confirmed by their scans. Disclosure runs on a
date, keeps an issue private until somebody discloses it, and marks an advisory
final once a second person agrees to it. Metrics on triage
time, deadlines and approvals show whether the team is keeping pace.

## Separation of duties

Security decisions deserve the same controls as code. Dismissing a finding
takes a written reason and a second person's approval, and nobody approves
their own. An approval is bound to the exact text it agreed to, so editing the
reason withdraws it. Every act lands in an append-only history, written in the
same transaction as the act itself.

Visibility is enforced in the data layer. A product somebody holds no role on
is invisible to them in every list, count, search and export. Public and
private work are granted separately, and a pipeline's credential can only
upload and read back its own uploads.

## Deployment

OpenPSIRT is open source under the Apache 2.0 license and runs on your own
infrastructure. It ships as a container image, a Helm chart, and Linux binaries
for amd64 and arm64. It runs on PostgreSQL, MySQL or MariaDB, with SQLite for
trials, and every change is tested on all four. Run as many replicas as you
need, with no leader and no shared filesystem.

It reads CycloneDX and SPDX, the formats your build tools already write. It
signs people in through OpenID Connect, GitHub or a trusted header. It runs
fully air-gapped, with the scanner and its data loaded from a bundle. Every
screen is built on a REST API described by an OpenAPI document, so anything
the interface does, your automation can do too.

## Next steps

[Evaluation](trying.md) stands one up to look at, and [Current state](built.md)
says what is built and what is not. To put it to work, [Build pipelines](pipeline.md)
shows a pipeline declaring its target and posting its SBOM, and
[A vendor's release](vendor-release.md) loads a vendor's SBOM and VEX document so
their judgments are recorded as theirs. [Configuration](configuration.md) lists
every setting, the [API reference](reference/api.md) every operation, and
[Privileges](reference/privileges.md) which role reaches which endpoint.

The reasoning behind every decision is in
[REQUIREMENTS.md](https://github.com/nexthop-ai/openpsirt/blob/main/REQUIREMENTS.md).
