# Analyzer results

A static analyzer's run over a build is sent with `openpsirt-analysis`, the
upload client published with every release. It reads the analyzer's own
output and the checkout, and sends one run per analyzer per build. Each result
is recorded as an internal finding of the build, and the run's receipt counts
what it opened, saw again and no longer found.

Sending one needs the product, stream and variant declared and a pipeline key,
as [Build pipelines](pipeline.md) describes for an inventory. A run is applied
once its build's inventory has been read, so the two uploads may arrive in
either order.

## The client

Each release attaches `openpsirt-analysis_<version>_<system>_<arch>.tar.gz`
for Linux and macOS and `openpsirt-analysis_<version>_windows_<arch>.zip` for
Windows, on amd64 and arm64, each beside a CycloneDX inventory of its binary,
`openpsirt-analysis_<version>_<system>_<arch>.cdx.json`, and all covered by
`SHA256SUMS` and its signature, `SHA256SUMS.cosign.bundle`.

| System | `<system>_<arch>` | Program |
|---|---|---|
| Linux | `linux_amd64`, `linux_arm64` | `openpsirt-analysis` |
| macOS | `darwin_amd64`, `darwin_arm64` | `openpsirt-analysis` |
| Windows | `windows_amd64`, `windows_arm64` | `openpsirt-analysis.exe` |

An archive holds one directory, named as the archive is, with the program,
`LICENSE` and `NOTICE` in it.

```bash
base=https://github.com/nexthop-ai/openpsirt/releases/download/v{{ release }}
client=openpsirt-analysis_{{ release }}_linux_amd64
curl -fsSL -O "$base/$client.tar.gz" -O "$base/SHA256SUMS" -O "$base/SHA256SUMS.cosign.bundle"
cosign verify-blob \
  --bundle SHA256SUMS.cosign.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/nexthop-ai/openpsirt/.github/workflows/release.yml@refs/tags/v{{ release }} \
  SHA256SUMS
grep " $client.tar.gz\$" SHA256SUMS | shasum -a 256 -c
tar -xzf "$client.tar.gz"
export PATH="$PWD/$client:$PATH"
openpsirt-analysis version
```

The same lines install it on macOS, with `darwin` in the name. The pipeline
examples below check the checksum alone; a runner holding cosign checks the
signature first, as above.

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

Any of them may be gzipped.

Output of several analyzers is sent as one upload per analyzer, each under a
series of its own, named once per analyzer as `--series TOOL=NAME`: for
example `--series clang=clang-sa --series cppcheck=cppcheck-all`. The tool is
the name its output gives it, in any case. `write` stores each analyzer's run
in a file of its own, the analyzer's name before the extension.

### Dependency and secret scanners

This upload takes static analysis of the product's own code. Two kinds of
tool that write SARIF are sent elsewhere or not at all:

| Tool | Where its results go |
|---|---|
| A dependency scanner: govulncheck, cargo-audit, Trivy, Grype, OSV-Scanner, Snyk Open Source, OWASP Dependency-Check, npm audit, pip-audit, bundler-audit, Retire.js | Nowhere. A vulnerable dependency is found by matching the build's inventory, sent as [Build pipelines](pipeline.md) describes, and the same issue arriving here would be triaged twice |
| A secret scanner: gitleaks, TruffleHog, detect-secrets, ggshield, Secretlint, Nosey Parker, Kingfisher | Nowhere. Its results carry the secret itself, and this deployment does not store one |

A run from one of these is left out whole and named on the receipt, and an
upload holding nothing else is refused. A result whose rule is an advisory's
identifier, such as `CVE-2026-12345` or `GHSA-…`, is dropped and counted on the
receipt, whatever tool wrote it.

## The upload

```bash
export OPENPSIRT_URL=https://openpsirt.example.com
export OPENPSIRT_KEY=…   # the pipeline key

openpsirt-analysis upload \
  --product sonic --stream main --variant broadcom \
  --series clang-sa \
  --built "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --compile-commands build/compile_commands.json \
  out/*/*.plist
```

Run it inside the checkout, or name the checkout with `--source-root`.

| Flag | |
|---|---|
| `--product`, `--stream`, `--variant` | The build the run is of |
| `--series` | Which analysis this is: the tool and its configuration, the same on every build. Each run is compared with the series' last. `TOOL=NAME` names one analyzer's, where the output is of several |
| `--built` | When the build was made, in RFC 3339. Without it, the run is dated when it arrives |
| `--commit` | The commit analyzed. The commit checked out where unset |
| `--source-root` | The top of the checkout. The git working tree holding the current directory where unset |
| `--units-expected`, `--units-analyzed` | How many translation units the run was meant to analyze, and did. Both or neither: units expected for an analyzer that counts none analyzed are not sent, and the client says so |
| `--compile-commands` | A compilation database, whose entries are the units expected. For clang, the units analyzed are the documents given |
| `--exit-status` | The analyzer's exit status. A run that exited non-zero is recorded and not compared |
| `--rule`, `--rules-file` | The rules enabled, so a rule that found nothing reads as checked. `--rule` is repeatable; the file names one rule per line, and leaves out blank lines and lines opening with `#` |
| `--third-party` | A directory of code the product did not write, relative to the checkout. Repeatable |
| `--tool-version` | The analyzer's version, where its output does not state one |
| `--snippets` | Send the source lines of each location. Without it, no source leaves the pipeline |
| `--salt-file` | A file holding a secret that keys each result's fingerprint. Keep it fixed in the CI system's secret store and shared by every job sending a series: a new salt changes every fingerprint, and the next run is matched as a fingerprint change |
| `--url` | The deployment's address, where `OPENPSIRT_URL` is not set |
| `--output` | Where `write` stores the document |

`--exit-status`, `--units-analyzed`, `--tool-version`, `--rule` and
`--rules-file` each describe one analyzer, and are refused for the output of
several.

The key is read from `OPENPSIRT_KEY` and from nowhere else, so it never
appears on a command line.

A 503 is retried after the time the deployment asks for, and a request that
reached nothing is retried after a growing pause, five attempts in all. A
redirect is not followed: the step fails naming where it points, so the key
never reaches another address.

## Comparable runs

A run is compared with its series' last, and a result missing from it is
recorded as no longer found, only where the run states its coverage and
exited cleanly. A run that is not comparable is still recorded, and its
receipt says why. A result last reported by another tool version or rule set
stays open, and the receipt counts it as uncompared.

| Analyzer | Coverage stated by |
|---|---|
| clang | `--compile-commands`, with the units analyzed counted from the documents given |
| CodeQL | Its SARIF, which lists every rule of the queries it ran |
| Every other analyzer below | `--rules-file`, naming the rules its configuration enables. Its SARIF lists only the rules that fired |

| The analyzer exits non-zero | Exit status |
|---|---|
| Only when it failed | Passed with `--exit-status` |
| For a result it found, unless told otherwise | Told to exit zero on results, then passed |
| For a result and for a failure alike | Not passed |

CodeQL states its run successful even where every compilation failed. Its
SARIF names each file it expected to analyze and each file it extracted, and a
run that extracted none of the files it expected is not comparable.

## Pipelines

Each example installs the client, runs Ruff, and sends Ruff's SARIF. Any
recipe under [Recipes by language](#recipes-by-language) replaces the Ruff
lines. `OPENPSIRT_KEY` is held in the CI system's secret store.

### GitHub Actions

A matrix over Linux, macOS and Windows runners, each its own variant:

```yaml
jobs:
  analysis:
    strategy:
      matrix:
        include:
          - {os: ubuntu-latest, client: linux_amd64, variant: linux}
          - {os: macos-latest, client: darwin_arm64, variant: macos}
          - {os: windows-latest, client: windows_amd64, variant: windows}
    runs-on: ${{ matrix.os }}
    env:
      OPENPSIRT_URL: ${{ vars.OPENPSIRT_URL }}
      OPENPSIRT_KEY: ${{ secrets.OPENPSIRT_KEY }}
      BASE: https://github.com/nexthop-ai/openpsirt/releases/download/v{{ release }}
      CLIENT: openpsirt-analysis_{{ release }}_${{ matrix.client }}
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: '3.x'

      - name: Install the client
        if: runner.os != 'Windows'
        run: |
          curl -fsSL -O "$BASE/$CLIENT.tar.gz" -O "$BASE/SHA256SUMS"
          grep " $CLIENT.tar.gz\$" SHA256SUMS | shasum -a 256 -c
          tar -xzf "$CLIENT.tar.gz"
          echo "$PWD/$CLIENT" >> "$GITHUB_PATH"

      - name: Install the client
        if: runner.os == 'Windows'
        shell: pwsh
        run: |
          Invoke-WebRequest "$env:BASE/$env:CLIENT.zip" -OutFile "$env:CLIENT.zip"
          Invoke-WebRequest "$env:BASE/SHA256SUMS" -OutFile SHA256SUMS
          $want = ((Select-String -Path SHA256SUMS -SimpleMatch " $env:CLIENT.zip").Line -split '\s+')[0]
          if ((Get-FileHash "$env:CLIENT.zip" -Algorithm SHA256).Hash -ne $want) { throw "$env:CLIENT.zip does not match SHA256SUMS" }
          Expand-Archive "$env:CLIENT.zip" -DestinationPath .
          Add-Content $env:GITHUB_PATH "$PWD\$env:CLIENT"

      - name: Send the analysis to OpenPSIRT
        shell: bash
        run: |
          pip install ruff
          status=0
          ruff check --output-format sarif --output-file ruff.sarif --exit-zero . || status=$?
          openpsirt-analysis upload \
            --product sonic --stream main --variant ${{ matrix.variant }} \
            --series ruff --built "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            --rules-file .openpsirt/ruff.rules --exit-status "$status" \
            ruff.sarif
```

`shell: bash` runs the last step under Git Bash on Windows, so one step serves
all three runners.

### GitLab CI

One job per runner, each its own variant. The hosted macOS and Windows
runners are chosen by tag; the Windows runner runs PowerShell and takes no
`image`.

```yaml
variables:
  BASE: https://github.com/nexthop-ai/openpsirt/releases/download/v{{ release }}

.unix: &unix
  - curl -fsSL -O "$BASE/$CLIENT.tar.gz" -O "$BASE/SHA256SUMS"
  - grep " $CLIENT.tar.gz\$" SHA256SUMS | shasum -a 256 -c
  - tar -xzf "$CLIENT.tar.gz" && export PATH="$PWD/$CLIENT:$PATH"
  - python3 -m venv .venv && . .venv/bin/activate && pip install ruff
  - status=0; ruff check --output-format sarif --output-file ruff.sarif --exit-zero . || status=$?
  - >
    openpsirt-analysis upload
    --product sonic --stream "$CI_COMMIT_BRANCH" --variant "$VARIANT"
    --series ruff --built "$CI_PIPELINE_CREATED_AT"
    --rules-file .openpsirt/ruff.rules --exit-status "$status"
    ruff.sarif

analysis-linux:
  image: python:3
  variables: {CLIENT: "openpsirt-analysis_{{ release }}_linux_amd64", VARIANT: linux}
  script: *unix

analysis-macos:
  tags: [saas-macos-medium-m1]
  image: macos-26-xcode-26
  variables: {CLIENT: "openpsirt-analysis_{{ release }}_darwin_arm64", VARIANT: macos}
  script: *unix

analysis-windows:
  tags: [saas-windows-medium-amd64]
  variables: {CLIENT: "openpsirt-analysis_{{ release }}_windows_amd64", VARIANT: windows}
  script:
    - |
      Invoke-WebRequest "$env:BASE/$env:CLIENT.zip" -OutFile "$env:CLIENT.zip"
      Invoke-WebRequest "$env:BASE/SHA256SUMS" -OutFile SHA256SUMS
      $want = ((Select-String -Path SHA256SUMS -SimpleMatch " $env:CLIENT.zip").Line -split '\s+')[0]
      if ((Get-FileHash "$env:CLIENT.zip" -Algorithm SHA256).Hash -ne $want) { throw "$env:CLIENT.zip does not match SHA256SUMS" }
      Expand-Archive "$env:CLIENT.zip" -DestinationPath .
      $env:Path = "$PWD\$env:CLIENT;$env:Path"
      python -m pip install ruff
      python -m ruff check --output-format sarif --output-file ruff.sarif --exit-zero .
      $status = $LASTEXITCODE
      openpsirt-analysis upload `
        --product sonic --stream "$env:CI_COMMIT_BRANCH" --variant "$env:VARIANT" `
        --series ruff --built "$env:CI_PIPELINE_CREATED_AT" `
        --rules-file .openpsirt/ruff.rules --exit-status $status `
        ruff.sarif
```

`OPENPSIRT_URL` and `OPENPSIRT_KEY` are CI/CD variables, the key masked.
`CI_PIPELINE_CREATED_AT` is already RFC 3339. A stream named from
`CI_COMMIT_BRANCH` has to have been declared, as
[Build pipelines](pipeline.md) says.

### Jenkins

A matrix over agents labeled `linux`, `macos` and `windows`, each its own
variant:

```groovy
pipeline {
  agent none
  environment {
    OPENPSIRT_URL = 'https://openpsirt.example.com'
    OPENPSIRT_KEY = credentials('openpsirt-key')
    BASE = 'https://github.com/nexthop-ai/openpsirt/releases/download/v{{ release }}'
  }
  stages {
    stage('Analysis') {
      matrix {
        axes {
          axis {
            name 'VARIANT'
            values 'linux', 'macos', 'windows'
          }
        }
        agent { label "${VARIANT}" }
        stages {
          stage('Send') {
            steps {
              script {
                def client = [linux: 'linux_amd64', macos: 'darwin_arm64', windows: 'windows_amd64'][env.VARIANT]
                withEnv(["CLIENT=openpsirt-analysis_{{ release }}_${client}"]) {
                  if (isUnix()) {
                    sh '''
                      curl -fsSL -O "$BASE/$CLIENT.tar.gz" -O "$BASE/SHA256SUMS"
                      grep " $CLIENT.tar.gz\\$" SHA256SUMS | shasum -a 256 -c
                      tar -xzf "$CLIENT.tar.gz"
                      PATH="$PWD/$CLIENT:$PATH"
                      python3 -m venv .venv && . .venv/bin/activate && pip install ruff
                      status=0
                      ruff check --output-format sarif --output-file ruff.sarif --exit-zero . || status=$?
                      openpsirt-analysis upload \\
                        --product sonic --stream main --variant "$VARIANT" \\
                        --series ruff --built "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \\
                        --rules-file .openpsirt/ruff.rules --exit-status "$status" \\
                        ruff.sarif
                    '''
                  } else {
                    powershell '''
                      Invoke-WebRequest "$env:BASE/$env:CLIENT.zip" -OutFile "$env:CLIENT.zip"
                      Invoke-WebRequest "$env:BASE/SHA256SUMS" -OutFile SHA256SUMS
                      $want = ((Select-String -Path SHA256SUMS -SimpleMatch " $env:CLIENT.zip").Line -split '\\s+')[0]
                      if ((Get-FileHash "$env:CLIENT.zip" -Algorithm SHA256).Hash -ne $want) { throw "$env:CLIENT.zip does not match SHA256SUMS" }
                      Expand-Archive "$env:CLIENT.zip" -DestinationPath .
                      $env:Path = "$PWD\\$env:CLIENT;$env:Path"
                      python -m pip install ruff
                      python -m ruff check --output-format sarif --output-file ruff.sarif --exit-zero .
                      $status = $LASTEXITCODE
                      $built = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
                      openpsirt-analysis upload `
                        --product sonic --stream main --variant "$env:VARIANT" `
                        --series ruff --built $built `
                        --rules-file .openpsirt/ruff.rules --exit-status $status `
                        ruff.sarif
                    '''
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

`openpsirt-key` is a secret-text credential, and `credentials()` masks it in
the log. Groovy reads `\\` inside `'''` as one backslash, so the shell sees
`\$` and `\`, and PowerShell sees `\s+` and `\`. Each agent label names
the machines of one system; the macOS agents here are Apple silicon, and an
Intel one takes `darwin_amd64`.

### Azure Pipelines

A matrix over the hosted Linux, macOS and Windows images, each its own
variant. The hosted macOS image is Intel, so it takes the `darwin_amd64`
client.

```yaml
strategy:
  matrix:
    linux:
      image: ubuntu-latest
      client: linux_amd64
      variant: linux
    macos:
      image: macOS-latest
      client: darwin_amd64
      variant: macos
    windows:
      image: windows-latest
      client: windows_amd64
      variant: windows

pool:
  vmImage: $(image)

variables:
  BASE: https://github.com/nexthop-ai/openpsirt/releases/download/v{{ release }}
  CLIENT: openpsirt-analysis_{{ release }}_$(client)

steps:
  - checkout: self
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.x'

  - bash: |
      curl -fsSL -O "$BASE/$CLIENT.tar.gz" -O "$BASE/SHA256SUMS"
      grep " $CLIENT.tar.gz\$" SHA256SUMS | shasum -a 256 -c
      tar -xzf "$CLIENT.tar.gz"
      echo "##vso[task.prependpath]$PWD/$CLIENT"
    displayName: Install the client
    condition: ne(variables['Agent.OS'], 'Windows_NT')

  - pwsh: |
      Invoke-WebRequest "$env:BASE/$env:CLIENT.zip" -OutFile "$env:CLIENT.zip"
      Invoke-WebRequest "$env:BASE/SHA256SUMS" -OutFile SHA256SUMS
      $want = ((Select-String -Path SHA256SUMS -SimpleMatch " $env:CLIENT.zip").Line -split '\s+')[0]
      if ((Get-FileHash "$env:CLIENT.zip" -Algorithm SHA256).Hash -ne $want) { throw "$env:CLIENT.zip does not match SHA256SUMS" }
      Expand-Archive "$env:CLIENT.zip" -DestinationPath .
      Write-Host "##vso[task.prependpath]$PWD\$env:CLIENT"
    displayName: Install the client
    condition: eq(variables['Agent.OS'], 'Windows_NT')

  - bash: |
      pip install ruff
      status=0
      ruff check --output-format sarif --output-file ruff.sarif --exit-zero . || status=$?
      openpsirt-analysis upload \
        --product sonic --stream "$(Build.SourceBranchName)" --variant "$(variant)" \
        --series ruff --built "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --rules-file .openpsirt/ruff.rules --exit-status "$status" \
        ruff.sarif
    displayName: Send the analysis to OpenPSIRT
    env:
      OPENPSIRT_URL: $(OPENPSIRT_URL)
      OPENPSIRT_KEY: $(OPENPSIRT_KEY)
```

A secret variable reaches a script only through `env`, so the key is mapped
there. The last step runs under Git Bash on the Windows image, so one step
serves all three.

### GitHub code scanning

The analyzer's own SARIF also goes to GitHub code scanning, unchanged:

```yaml
permissions:
  security-events: write

steps:
  - uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: ruff.sarif
      category: ruff
```

## Uploads without the client

A producer writing complete SARIF posts it directly:

```bash
curl --fail-with-body --retry 5 -X POST \
  "$OPENPSIRT_URL/v1/products/sonic/streams/main/variants/broadcom/analyses" \
  -H "Authorization: Bearer $OPENPSIRT_KEY" \
  -F "sarif=@ruff.sarif" \
  -F "series=ruff" \
  -F "commit=$(git rev-parse HEAD)" \
  -F "built=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -F "tool-version=$(ruff --version | cut -d' ' -f2)" \
  -F "source-root=$PWD" \
  -F "exit-status=$status"
```

| Field | |
|---|---|
| `sarif` | Required, repeatable. SARIF of one analyzer, gzipped or not |
| `series` | Required, unless each run's `automationDetails.id` states it as `<series>/<built>` |
| `commit` | The commit analyzed, at the top of the checkout |
| `built` | When the build was made, in RFC 3339. Runs are ordered by it, and one more than five minutes ahead of the deployment's clock is refused |
| `tool-version` | The analyzer's version |
| `rules` | Repeatable. One rule enabled per field |
| `units-expected`, `units-analyzed` | Whole numbers, both or neither |
| `exit-status` | The analyzer's exit status, as a whole number |
| `source-root` | The checkout's absolute path on the build host. Every path is placed against it |
| `third-party` | Repeatable. A path, relative to the checkout, holding code the product did not write |

A value the SARIF states wins over the field.

| Answer | |
|---|---|
| 202 `queued` | Stored, and applied once the build's inventory has been read |
| 200 `already_held` | The same documents for the same series, build and build time |
| 422 | A document or a field could not be read; the detail names which |
| 409 | The product, stream or variant is retired |
| 503 | The deployment is busy. `curl --retry` sends it again after `Retry-After` |

A direct upload goes without what the client adds:

| Client addition | Without it |
|---|---|
| Repositories | Every result is placed on the build itself, rather than on the component built from the repository holding it |
| Content fingerprints | A result is matched on the analyzer's own fingerprint, or on its line, so moved code reads as a new result more often |
| Paths in the checkout index's case | A path is placed as the analyzer wrote it |
| Whole-file contents, fixes and attachments removed before sending | They leave the pipeline, and the deployment removes them on arrival |

Without the client's fingerprint, a result is matched on what its analyzer
wrote. Where that is only the rule, the path, the line and the message, a
result whose line moved is paired with the nearest result of the same rule and
message in its file, and its dismissal is asked to be affirmed again:

| Analyzer, uploaded plain | Matched on | When lines move above it |
|---|---|---|
| CodeQL | Its `primaryLocationLineHash` | It keeps its lead |
| cppcheck | Its `hash/v1`, with the path | It keeps its lead |
| clang 22 and later | Its issue hash, with the path | It keeps its lead |
| clang before 22 | The rule, path, line and message | It is paired by nearest line, and two results moving past each other can swap. Send its `plist-multi-file` output through the client, which carries the issue hash in every version and the enclosing function |
| clang-tidy | The rule, path, line and message | It is paired by nearest line, and two results moving past each other can swap. The client adds a content fingerprint |

## Recipes by language

Each recipe runs in the checkout with `OPENPSIRT_URL` and `OPENPSIRT_KEY`
set, the client on the path, and the build named once:

```bash
build=(--product sonic --stream main --variant broadcom --built "$(date -u +%Y-%m-%dT%H:%M:%SZ)")
```

A `.rules` file names the rules the analyzer's configuration enables, as
[Comparable runs](#comparable-runs) describes.

### Go

gosec exits non-zero for a result and for a failure alike, so its status is
not passed:

```bash
go install github.com/securego/gosec/v2/cmd/gosec@latest
gosec -no-fail -fmt sarif -out gosec.sarif ./...
openpsirt-analysis upload "${build[@]}" --series gosec \
  --rules-file .openpsirt/gosec.rules gosec.sarif
```

golangci-lint states no version in its SARIF, and names each result's rule by
its linter, so its rules file names the linters enabled:

```bash
curl -sSfL https://golangci-lint.run/install.sh | sh -s -- -b "$(go env GOPATH)/bin" "$GOLANGCI_LINT_VERSION"
status=0
golangci-lint run --output.sarif.path=golangci-lint.sarif --issues-exit-code=0 ./... || status=$?
openpsirt-analysis upload "${build[@]}" --series golangci-lint \
  --tool-version "$(golangci-lint version --short)" \
  --rules-file .openpsirt/golangci-lint.rules --exit-status "$status" \
  golangci-lint.sarif
```

### Python

Bandit writes SARIF with its `sarif` extra installed:

```bash
pip install "bandit[sarif]"
status=0
bandit -r . -f sarif -o bandit.sarif --exit-zero || status=$?
openpsirt-analysis upload "${build[@]}" --series bandit \
  --rules-file .openpsirt/bandit.rules --exit-status "$status" bandit.sarif
```

Ruff:

```bash
pip install ruff
status=0
ruff check --output-format sarif --output-file ruff.sarif --exit-zero . || status=$?
openpsirt-analysis upload "${build[@]}" --series ruff \
  --rules-file .openpsirt/ruff.rules --exit-status "$status" ruff.sarif
```

### JavaScript and TypeScript

ESLint, with the SARIF formatter. ESLint exits 1 for a result and 2 for a
failure, so 1 is sent as 0:

```bash
npm install --save-dev @microsoft/eslint-formatter-sarif
status=0
npx eslint . -f @microsoft/eslint-formatter-sarif -o eslint.sarif || status=$?
if [ "$status" -eq 1 ]; then status=0; fi
openpsirt-analysis upload "${build[@]}" --series eslint \
  --rules-file .openpsirt/eslint.rules --exit-status "$status" eslint.sarif
```

TypeScript is read by the parser the ESLint configuration names, and needs
nothing further here.

### Rust

clippy's diagnostics, converted by `clippy-sarif`. `--cap-lints warn` keeps a
denied lint from failing the run, so a non-zero status is a build that failed:

```bash
cargo install clippy-sarif
set -o pipefail
status=0
cargo clippy --message-format=json -- --cap-lints warn | clippy-sarif --output clippy.sarif || status=$?
openpsirt-analysis upload "${build[@]}" --series clippy \
  --tool-version "$(cargo clippy --version)" \
  --rules-file .openpsirt/clippy.rules --exit-status "$status" clippy.sarif
```

### Java

SpotBugs, through its Maven plugin:

```bash
status=0
mvn -B compile com.github.spotbugs:spotbugs-maven-plugin:spotbugs -Dspotbugs.sarifOutput=true || status=$?
openpsirt-analysis upload "${build[@]}" --series spotbugs \
  --rules-file .openpsirt/spotbugs.rules --exit-status "$status" \
  target/spotbugsSarif.json
```

The SARIF names its paths under the source directories SpotBugs was given,
which the client resolves into the checkout.

### C and C++

clang's analyzer over a compilation database, through `analyze-build`, from
clang's tools or `pip install scan-build`. The client reads the plist
documents, one per translation unit, so the units analyzed are counted:

```bash
cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
analyze-build --cdb build/compile_commands.json --plist-multi-file -o out
openpsirt-analysis upload "${build[@]}" --series clang-sa \
  --compile-commands build/compile_commands.json out/*/*.plist
```

`analyze-build` writes into a directory of its own under `-o`, named for the
time it ran.

cppcheck, as XML version 2, which the client reads:

```bash
status=0
cppcheck --project=build/compile_commands.json --enable=all \
  --xml --xml-version=2 --output-file=cppcheck.xml || status=$?
openpsirt-analysis upload "${build[@]}" --series cppcheck \
  --rules-file .openpsirt/cppcheck.rules --exit-status "$status" cppcheck.xml
```

Both in one command name each one's series, and leave out the flags that
describe one analyzer:

```bash
openpsirt-analysis upload "${build[@]}" \
  --series clang=clang-sa --series cppcheck=cppcheck \
  --compile-commands build/compile_commands.json \
  out/*/*.plist cppcheck.xml
```

### CodeQL

One database and one upload per language, each its own series. Output of
several CodeQL languages sent together is one tool's, and merges into one run:

```bash
curl -fsSL https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz | tar -xz
export PATH="$PWD/codeql:$PATH"

status=0
codeql database create db-go --language=go --build-mode=autobuild || status=$?
codeql database analyze db-go --format=sarif-latest --output=codeql-go.sarif || status=$?
openpsirt-analysis upload "${build[@]}" --series codeql-go \
  --exit-status "$status" codeql-go.sarif
```

| Language | `--language`, `--build-mode` |
|---|---|
| C and C++ | `cpp`, `autobuild`, or `manual` with `--command` naming the build |
| Go | `go`, `autobuild` |
| Java and Kotlin | `java`, `autobuild` or `none` |
| JavaScript and TypeScript | `javascript-typescript`, `none` |
| Python | `python`, `none` |

The queries are the language's default suite. CodeQL's SARIF lists every rule
of the suite, so its runs need no rules file.

## Contents sent

| | |
|---|---|
| Paths | Relative to the checkout, with `/`, in the case the checkout's index holds, whether the tool wrote it through a symbolic link or not. A path outside the checkout is sent as it is and dropped by the deployment with its result |
| Repositories | Every repository the checkout holds, submodules included, with its commit and its remote as a web address. A repository with uncommitted changes is named as changed |
| Fingerprints | A hash of each result's line and the line either side, with white space and line endings normalized, so a result keeps its identity when the code around it moves. With `--salt-file` the hash is keyed, and the analyzer's own fingerprints are left out. A salt can be rotated: the first run under a new one keeps each result's lead, and its dismissal, wherever the result is the only one of its rule, file, message without digits, function and call chain. Results sharing all of those are matched as any run's are, by function and then line, and their dismissals wait to be confirmed again |
| Source | Nothing, unless `--snippets` is given. Whole-file contents, attachments and suggested fixes in an analyzer's SARIF are always removed |

`write` stores exactly the document `upload` would send.
