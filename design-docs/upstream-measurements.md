# Upstream measurements

Benchmark runs behind the upstream rules. Each section names the rule it
justifies.

## Contents

- [A fork reading its upstream](#a-fork-reading-its-upstream)

## A fork reading its upstream

Justifies reading every hour and applying statements on every run
(`design-docs/upstream.md` § Settings, § Statements applied). The full-size
switch image shipped by the upstream and by a fork on PostgreSQL, every
component with a package identifier carrying one issue: 6,843 issues at
components. The upstream publishes, signed, that 76 of the distribution
packages' issues do not apply because the code is absent. The fork reads it
over TLS from a server on the same machine.

| Measured | |
|---|---|
| Documents read and recorded on the first read | 76, every one holding for anybody, each checked against its digest and its signature |
| The first read | 0.40 s |
| A read over nothing that moved | 18 ms: one request for the description and one for the feed, answered that nothing moved |
| The fork's run over its build | 0.58 s before it trusts the upstream, 0.60 s with the 76 statements standing |
| Findings that run closes | 508: the 76 issues at every occurrence the image ships them |
