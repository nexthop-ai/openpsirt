# Helm chart

The chart's probes, security context, network policy, render-time refusals and
secret sources.

Satisfies REQ-02, REQ-03, REQ-49, and the probe behavior REQ-72 requires.

## Contents

- [Chart probes](#chart-probes)
- [Platform health checks](#platform-health-checks)
- [Chart security context](#chart-security-context)
- [Network policy](#network-policy)
- [Render-time refusals](#render-time-refusals)
- [Secret sources](#secret-sources)
- [Limits](#limits)

## Chart probes

| Probe | Question | Path |
|---|---|---|
| Startup | The port has opened | `/healthz` |
| Liveness | The process is running | `/healthz` |
| Readiness | It can serve | `/readyz` |

| Rule | Reason |
|---|---|
| Liveness does not depend on the database | A restart cannot fix an unreachable database, and a probe failing on one adds a restart loop to the outage |
| The startup probe allows ten minutes by default | `/healthz` answers from the moment the port opens and throughout a migration (`design-docs/packaging.md` § Starting and stopping), so this bounds what precedes the port: connecting to the database and the refusals reading none, sign-in provider discovery and the store checks among them. The start-up deadline ends a hang there first |
| The image's own health check, which Docker acts on and Kubernetes ignores, runs `openpsirt health` | It reads the configuration the server reads and asks `/healthz` where `OPENPSIRT_ADDR` says the server listens, on loopback where that names every interface, never through a proxy |
| `openpsirt health` takes `--config` as every command does; the image's check passes none | A container configured by file replaces the check with one naming the file. Left alone, it reads the environment and asks port 8080 |

## Platform health checks

| Check | Path | Reason |
|---|---|---|
| Whether to keep the process | `/healthz` | It answers while the schema is applied; a check failing during a migration ends it part way, and the next process starts it over |
| Whether to send it traffic | `/readyz` | It answers only once the router serves, and while the database answers |

A load balancer whose one health check decides both, such as an AWS Application
Load Balancer in front of ECS, is pointed at `/healthz`. A process applying the
schema then receives traffic and answers with the upgrading response.

## Chart security context

| Rule | Reason |
|---|---|
| Non-root, read-only root filesystem, every capability dropped, the default seccomp profile, no service-account token | The application never talks to the Kubernetes API |
| `/tmp` is a size-limited `emptyDir`, sized for the uploads one server reads at once | `upload.max-concurrent` of the largest request a route takes: four of 512 MiB at the shipped values, which the shipped 3 GiB holds with room for other scratch |
| The pod's termination grace is twice the process's shutdown grace | The process drains requests for that long, then waits as long again for a worker mid-scan |
| A SQLite URL with more than one replica is refused at render | Every replica serves, reads and scans, coordinated through the database (REQ-03), and SQLite is a file in one pod. The chart sees only a URL in values; for one in an operator's Secret the process warns at startup that SQLite is not a production engine |
| A single-pod SQLite trial keeps its file under `/var/lib/openpsirt`, the one directory the chart mounts for a SQLite URL, on a bounded scratch volume or a named claim | A SQLite URL in values naming any other path, a directory beneath it included, is refused at render, since the process would crash-loop creating the file |
| A claim named for SQLite beside a URL held in a Secret is refused | The chart cannot read that URL and would mount nothing |
| No other install gets the volume | A server database keeps nothing on the pod |

## Network policy

Sign-in by a trusted header is believed by address alone, usually the pod
network every pod is on, so a trusted-header install renders a NetworkPolicy
admitting only the ingress controller.

| Rule | Reason |
|---|---|
| Rendered whenever a trusted header is named, unless turned off | Off, any pod can send the header to the Service and sign in as anybody, the bootstrap administrators included |
| Admits the ingress controller by namespace and pod labels, both configurable, and any further peers named | The defaults are ingress-nginx's labels. A host-network controller needs an address block, and a metrics scraper a namespace of its own |
| The controller's defaults apply only where neither label map is set, applied in the template | Helm merges an operator's map into a default map, which would keep ingress-nginx's labels beside another controller's and admit nobody |
| A controller named by its pods alone is refused at render | A pod selector alone selects the policy's own namespace, never the controller's, and pod labels matched in every namespace are labels anybody creating a pod can set, so that pod could assert the header |
| The controller's admission can be turned off, keeping the further peers | A host-network controller is named by address, and its labels admit nothing |
| Anything reaching the Service directly is refused unless named as a further peer | A pipeline uploading with a key from inside the cluster is one |
| The install notes warn about the header in every trusted-header install, with or without an ingress | An ingress is where the header's sources are widest |
| A policy is enforced only by a network plugin supporting it, and the kubelet's probes come from the node, which most plugins admit | |

## Render-time refusals

Each fails at render with a sentence naming the problem, because manifests that
cannot work fail later as a crash-looping pod.

| Refused | Reason |
|---|---|
| Both a managed Secret and a chart-created one for the database URL, or neither | There must be exactly one |
| No bootstrap admin | Nobody can administer the deployment |
| No sign-in provider | Naming a bootstrap admin grants a role and admits nobody |
| A provider with no base URL | A provider returns somebody to an address and compares it against its registration |
| A trusted header with no sources | Anybody can set it |
| A mail server with no sending address, an address with no server, or a password with no username | Half-configured mail comes up healthy and sends nothing (REQ-02). Mail is opt-in, so this costs a deployment wanting none nothing (REQ-49) |
| A sign-in provider with no client secret | The process refuses to start without one |
| An OIDC provider with no username claim | The same, with no default: what an authorization is redeemed against is the operator's question |
| A secret given both ways at once | The chart writes no Secret when one is named, so the values file's would be ignored silently |
| SQLite behind more than one replica | A second replica starts with an empty database of its own |
| A chart-made scanner cache claim every replica mounts and only one node can | The replicas elsewhere stay Pending, a deployment that never becomes ready |
| A scanner cache claim given both ways at once | The chart makes none when one is named |
| A network policy for a trusted header that admits nobody | It refuses the proxy setting the header, which is every sign-in |

| Rule | Reason |
|---|---|
| Each refusal is tested by asserting it fires, and the count examined is printed | A loop that checked nothing reads like one finding nothing wrong |
| A legal install resolves every `secretKeyRef` it renders against the Secrets the same install creates, read from the render | A hand-written list would give a new secret source no row and stay green on the defect |

## Secret sources

The database URL, both client secrets and the mail password answer one pair of
rules, differing only in the Secret's name and key.

| Value | Read from |
|---|---|
| Set in the values | A Secret the chart creates, under a key of the chart's own |
| A Secret the operator names | That Secret, under the key named beside it |
| Both | Refused at render; one would be ignored |
| Neither, for the mail password | Nothing; mail is opt-in and a server may want no credentials |
| Neither, for a sign-in provider | Refused at render; the process refuses to start without one |

| Rule | Reason |
|---|---|
| The operator's key name is read only where they also name the Secret | The chart's Secret holds the value under the chart's key, and asking for the operator's renders a pod that never starts |
| A Secret is written only while what reads it is configured; clearing a provider's issuer removes its Secret | One left behind holds a live credential nothing reads |
| The database URL always comes from a Secret, named or created from a value | The values file states that a password put there enters the release history. Mail credentials are in the chart for the same reason |
| Bootstrap admins are applied at every startup, and the install notes say so | They are the recovery path: lose administrative access, add yourself, upgrade |

## Limits

| Limit | Detail |
|---|---|
| A SQLite URL in an operator's own Secret is not checked against the replica count | The chart cannot read it; the process warns at startup |
| A ReadWriteOnce claim the chart did not make is not refused for shared repository copies | The chart cannot see its access mode |
