# OpenPSIRT

Track vulnerabilities in the products you ship.

OpenPSIRT takes in the inventory a build produced, scans it for known
vulnerabilities, works out what changed release to release, and gives people
somewhere to triage what it finds and follow it through to a fix.

!!! note "Early development"
 There is no release yet. What is here describes the system as it is being
 built, and changes as it is.

## What it does

- **Takes in inventories** pushed by build pipelines, in CycloneDX or SPDX
 form, along with the suppressions the build carries patches for
- **Runs the scan here**, not in the build, so every product is measured
 against the same scanner and the same vulnerability data
- **Keeps the dependency graph**, so you can see why a vulnerable component is
 present and which part of the product pulled it in
- **Tracks change over time** per release, and works out why a finding
 disappeared rather than guessing
- **Carries triage decisions forward**, so a nightly scan does not reset the work
- **Rescans shipped releases**, so a vulnerability published after a release
 still gets found
- **Reports** on what was fixed between releases, what was dismissed and why,
 what is running out of time, and whether the team is keeping pace

## What it does not do

- Generate SBOMs — your build does that
- Work out what is in a product — the component list always comes from the build
- Build or deploy fixes
