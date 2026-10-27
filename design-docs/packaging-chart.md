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

| Probe | Checks | Path |
|---|---|---|
| Startup | The port has opened | `/healthz` |
| Liveness | The process is running | `/healthz` |
| Readiness | It can serve | `/readyz` |

| Rule | Reason |
|---|---|
| Liveness ignores the database | A restart cannot fix it, and would add a restart loop to an outage |
| The startup probe allows ten minutes by default | `/healthz` answers from port opening through a migration (`design-docs/packaging.md` § Starting and stopping), so this bounds the database connection, the database-free refusals, provider discovery and store checks. The start-up deadline ends a hang first |
| The image's health check, used by Docker and ignored by Kubernetes, runs `openpsirt health` | It reads the server's configuration and asks `/healthz` where `OPENPSIRT_ADDR` listens, on loopback for every interface, never through a proxy |
| `openpsirt health` takes `--config`; the image's check passes none | A file-configured container replaces the check with one naming the file; otherwise it asks port 8080 |

## Platform health checks

| Check | Path | Reason |
|---|---|---|
| Keep the process | `/healthz` | It answers during a migration, which a failing check would cut short and restart |
| Send it traffic | `/readyz` | It answers once the router serves and while the database answers |

A load balancer with one check for both, such as an AWS Application Load
Balancer in front of ECS, uses `/healthz`, and a migrating process answers its
traffic with the upgrading response.

## Chart security context

| Rule | Reason |
|---|---|
| Non-root, read-only root filesystem, all capabilities dropped, default seccomp, no service-account token | The application never calls the Kubernetes API |
| `/tmp` is a size-limited `emptyDir` for one server's concurrent uploads | `upload.max-concurrent` of the largest request: four of 512 MiB at the shipped values, inside the shipped 3 GiB |
| Termination grace is twice the process's shutdown grace | Requests drain, then a mid-scan worker gets as long again |
| A SQLite URL with more than one replica is refused at render | Replicas coordinate through the database (REQ-03), and SQLite is one pod's file. |
| A SQLite trial keeps its file under `/var/lib/openpsirt`, mounted for a SQLite URL on bounded scratch or a named claim; another path in values, a subdirectory included, is refused at render | The process would crash-loop creating the file |
| A claim named for SQLite beside a URL held in a Secret is refused | The chart cannot read the URL and would mount nothing |
| No other install gets the volume | |

## Network policy

A trusted header is believed by source address, usually the whole pod network,
so a trusted-header install renders a NetworkPolicy admitting only the ingress
controller.

| Rule | Reason |
|---|---|
| Rendered whenever a trusted header is named, unless turned off | Off, any pod can sign in as anybody, bootstrap administrators included |
| Admits the controller by namespace and pod labels, both configurable, and further named peers | Defaults are ingress-nginx's labels. A host-network controller needs an address block; a metrics scraper its namespace |
| The controller defaults apply only where neither label map is set, in the template | Helm merges an operator's map into defaults, mixing two controllers' labels |
| A controller named by pod labels alone is refused at render; the policy renders only where trusted-header sign-in is on, so the refusal applies there alone | A pod selector alone matches the policy's own namespace, and pod labels across namespaces are settable by anyone creating a pod, who could then assert the header |
| The controller's admission can be turned off, keeping the further peers | A host-network controller is named by address |
| Direct traffic to the Service is refused unless from a further peer | Such as a pipeline uploading from inside the cluster |
| The install notes warn about the header in every trusted-header install | An ingress widens the header's sources |

## Render-time refusals

Each fails at render with a sentence naming the problem, instead of a
crash-looping pod.

| Refused | Reason |
|---|---|
| Both a managed and a chart-created Secret for the database URL, or neither | Exactly one |
| No bootstrap admin | Nobody can administer |
| No sign-in provider | A bootstrap admin admits nobody alone |
| A provider with no base URL | It returns somebody to an address its registration checks |
| A trusted header with no sources | Anybody could set it |
| A mail server with no sending address, an address with no server, or a password with no username | Half-configured mail sends nothing while healthy (REQ-02); mail is opt-in, so this costs nothing (REQ-49) |
| A provider with no client secret | The process would not start |
| An OIDC provider with no username claim | The same, with no default: only the operator knows the claim |
| A secret given both ways | The values file's would be silently ignored |
| SQLite behind more than one replica | A second replica gets an empty database |
| A chart-made scanner cache claim mounted by every replica that only one node can mount | The others stay Pending forever |
| A scanner cache claim given both ways | |
| A trusted-header network policy admitting nobody | It refuses the proxy, which is every sign-in |

| Rule | Reason |
|---|---|
| Each refusal is tested firing, and the count examined printed | A loop checking nothing reads like one finding nothing |
| A legal install resolves every `secretKeyRef` it renders against the Secrets it creates, read from the render | A hand-written list would miss a new secret source |

## Secret sources

The database URL, both client secrets and the mail password follow one rule
set.

| Value | Read from |
|---|---|
| Set in the values | A chart-created Secret, under the chart's key |
| A Secret the operator names | That Secret, under the key named beside it |
| Both | Refused at render |
| Neither, for the mail password | Nothing; a mail server may want no credentials |
| Neither, for a sign-in provider | Refused at render |

| Rule | Reason |
|---|---|
| The operator's key name is read only with the operator's Secret | In the chart's Secret it names a missing key, and the pod never starts |
| A Secret exists only while its reader is configured; clearing a provider's issuer removes it | A leftover holds a live credential |
| The database URL always comes from a Secret, named or chart-created; the values file warns a password there enters the release history | Mail credentials follow suit |
| Bootstrap admins are applied at every startup, as the install notes say | The recovery path: add yourself and upgrade |

## Limits

| Limit | Detail |
|---|---|
| A SQLite URL in an operator's Secret is not checked against the replica count | The chart cannot read it; the process warns at startup that SQLite is not a production engine |
| The network policy is enforced only by a plugin supporting it | Kubelet probes come from the node, which most plugins admit |
