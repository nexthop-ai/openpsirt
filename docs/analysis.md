# Analyzer results

A static analyzer's run over a build is sent with `openpsirt-analysis`, the
upload client published with every release. It reads the analyzer's own
output and the checkout, and sends one run per build. Each result is recorded
as an internal finding of the build, and the run's receipt counts what it
opened, saw again and no longer found.

Sending one needs the product, stream and variant declared and a pipeline key,
as [Build pipelines](pipeline.md) describes for an inventory. A run is applied
once its build's inventory has been read, so the two uploads may arrive in
either order.

## The client

Each release attaches `openpsirt-analysis_<version>_<system>_<arch>.tar.gz`
for Linux, macOS and Windows on amd64 and arm64, covered by `SHA256SUMS` and
its signature. Check them as the release notes show, then unpack the binary
onto the path.

| Command | Does |
|---|---|
| `openpsirt-analysis upload …` | Builds the run and sends it, printing the receipt |
| `openpsirt-analysis write --output FILE …` | Builds the run and stores it, to see what would be sent |
| `openpsirt-analysis version` | Prints the client's version |

## The analyzer's output

| Analyzer | Write |
|---|---|
| clang static analyzer | `-analyzer-output=plist-multi-file`, one document per translation unit. Plain `plist` drops any diagnostic whose path crosses files, and HTML is refused because it carries source |
| cppcheck | `--xml --xml-version=2` |
| Anything else | SARIF |

Output of several analyzers is sent as one upload per analyzer, each under a
series of its own, named once per analyzer as `--series TOOL=NAME`: for
example `--series clang=clang-sa --series cppcheck=cppcheck-all`. The tool is
the name its output gives it, in any case. `write` stores each analyzer's run
in a file of its own, the analyzer's name before the extension. `--rule`,
`--rules-file` and `--tool-version` each describe one analyzer, and are refused
for output of several.

## The upload

```bash
export OPENPSIRT_URL=https://openpsirt.example.com
export OPENPSIRT_KEY=…   # the pipeline key

openpsirt-analysis upload \
  --product sonic --stream main --variant broadcom \
  --series clang-sa \
  --built "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --compile-commands build/compile_commands.json \
  --exit-status "$status" \
  out/*.plist
```

Run it inside the checkout, or name the checkout with `--source-root`.

| Flag | |
|---|---|
| `--product`, `--stream`, `--variant` | The build the run is of |
| `--series` | Which analysis this is: the tool and its configuration, the same on every build. Each run is compared with the series' last. `TOOL=NAME` names one analyzer's, where the output is of several |
| `--built` | When the build was made, in RFC 3339. Without it, the run is dated when it arrives |
| `--commit` | The commit analyzed. The commit checked out where unset |
| `--units-expected`, `--units-analyzed` | How many translation units the run was meant to analyze, and did. Both or neither |
| `--compile-commands` | A compilation database, whose entries are the units expected. For clang, the units analyzed are the documents given |
| `--exit-status` | The analyzer's exit status. A run that exited non-zero is recorded and not compared |
| `--rule`, `--rules-file` | The rules enabled, so a rule that found nothing reads as checked |
| `--third-party` | A directory of code the product did not write, relative to the checkout. Repeatable |
| `--tool-version` | The analyzer's version, where its output does not state one |
| `--snippets` | Send the source lines of each location. Without it, no source leaves the pipeline |
| `--salt-file` | A file holding a secret that keys each result's fingerprint |
| `--url` | The deployment's address, where `OPENPSIRT_URL` is not set |

The key is read from `OPENPSIRT_KEY` and from nowhere else, so it never
appears on a command line.

A 503 is retried after the time the deployment asks for, and a request that
reached nothing is retried after a growing pause, five attempts in all.

### GitHub Actions

```yaml
- name: Send the analysis to OpenPSIRT
  env:
    OPENPSIRT_URL: ${{ vars.OPENPSIRT_URL }}
    OPENPSIRT_KEY: ${{ secrets.OPENPSIRT_KEY }}
  run: |
    openpsirt-analysis upload \
      --product sonic --stream main --variant ${{ matrix.variant }} \
      --series cppcheck --exit-status "${{ steps.cppcheck.outputs.status }}" \
      cppcheck.xml
```

## Contents sent

| | |
|---|---|
| Paths | Relative to the checkout, with `/`, in the case the checkout's index holds. A path outside the checkout is sent as it is and dropped by the deployment with its result |
| Repositories | Every repository the checkout holds, submodules included, with its commit and its remote as a web address. A repository with uncommitted changes is named as changed |
| Fingerprints | A hash of each result's line and the line either side, with white space and line endings normalized, so a result keeps its identity when the code around it moves. With `--salt-file` the hash is keyed, and the analyzer's own fingerprints are left out |
| Source | Nothing, unless `--snippets` is given. Whole-file contents and suggested fixes in an analyzer's SARIF are always removed |

`write` stores exactly the document `upload` would send.
