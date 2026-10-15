# Copyright Nexthop Systems Inc.
# SPDX-License-Identifier: Apache-2.0

# The container image and the Helm chart, checked as what ships.

.PHONY: check-packaging

# Requires docker and helm. Skipped by "check" so that a machine without them
# can still run everything else.
# CHECK_IMAGE is what the packaging checks run against. Left at the default it
# is built here; CI passes the tag it has already built, so the same checks run
# in both places rather than being written twice and drifting.
CHECK_IMAGE ?= openpsirt:check

# Whether the two tools this needs are here, asked once rather than per line.
PACKAGING_TOOLS := $(shell command -v $(DOCKER) >/dev/null 2>&1 && \
                     command -v helm >/dev/null 2>&1 && echo yes)

check-packaging:
ifeq ($(PACKAGING_TOOLS),)
	@# Said rather than passed silently. The gate runs this now, so a machine
	@# without docker or helm must still be able to run the gate — and a skip
	@# that looks like a pass is what every other check here is written to
	@# avoid, which is why it names what it did not do.
	@echo "$(DOCKER) or helm is not installed, so the image and the chart are unchecked here."
	@echo "CI runs both on every push; install them to run these before one."
else
	@# Not quiet, for the reason dist-inventories is not: a build that fails
	@# without saying why is diagnosed by running it again differently.
	@if [ "$(CHECK_IMAGE)" = "openpsirt:check" ]; then \
	  $(DOCKER) build -t $(CHECK_IMAGE) .; \
	fi
	$(DOCKER) run --rm $(CHECK_IMAGE) -version
	@test "$$($(DOCKER) run --rm --entrypoint id $(CHECK_IMAGE) -u)" != "0" \
	  || { echo "image runs as root"; exit 1; }
	@$(DOCKER) run --rm --entrypoint /usr/local/bin/grype $(CHECK_IMAGE) version >/dev/null \
	  || { echo "image carries no working scanner, so it could ingest and never scan"; exit 1; }
	@# That the image serves the interface, not merely that it starts. The Go
	@# build embeds a git-ignored directory, so an image built from a clean
	@# checkout carried no interface at all and every other check here passed.
	@set -e; \
	  id=$$($(DOCKER) run -d --rm -p 127.0.0.1:0:8080 \
	         --tmpfs /tmp \
	         -e OPENPSIRT_DATABASE_URL="sqlite:///tmp/check.db" \
	         -e OPENPSIRT_ADDR="0.0.0.0:8080" \
	         -e OPENPSIRT_PLAIN_HTTP=1 \
	         -e OPENPSIRT_BOOTSTRAP_ADMINS=check \
	         $(CHECK_IMAGE)); \
	  trap '$(DOCKER) rm -f $$id >/dev/null 2>&1 || true' EXIT; \
	  port=$$($(DOCKER) port $$id 8080/tcp | head -1 | sed 's/.*://'); \
	  waited=0; \
	  until curl -fsS --noproxy '*' "http://127.0.0.1:$$port/readyz" >/dev/null 2>&1; do \
	    waited=$$((waited + 1)); \
	    [ $$waited -gt 60 ] && { echo "the image never became ready"; exit 1; }; \
	    sleep 1; \
	  done; \
	  curl -fsS --noproxy '*' "http://127.0.0.1:$$port/" | grep -qi '<!doctype html' \
	    || { echo "the image serves no interface: it was built without one"; exit 1; }
	helm lint deploy/helm/openpsirt --set database.url=postgres://u:p@h:5432/d \
	  --set auth.bootstrapAdmins='{admin}' --set auth.trustedHeader.name=X-Forwarded-User \
	  --set auth.trustedHeader.sources='{10.0.0.0/8}'
	helm template t deploy/helm/openpsirt --set database.existingSecret=s \
	  --set auth.bootstrapAdmins='{admin}' --set auth.baseURL=https://psirt.example.com \
	  --set auth.oidc.issuer=https://id.example.com --set auth.oidc.clientID=abc \
	  --set auth.oidc.clientSecret=shh --set auth.oidc.usernameClaim=sub >/dev/null
	@# An upgrade may reshape tables the earlier release reads, so by default
	@# no pod of it serves beside a pod of this one.
	@helm template t deploy/helm/openpsirt --set database.existingSecret=s \
	  --set auth.bootstrapAdmins='{admin}' --set auth.trustedHeader.name=X-User \
	  --set auth.trustedHeader.sources='{10.0.0.0/8}' -s templates/deployment.yaml \
	  | awk '/^  strategy:$$/ {s=1; next} s && /^    type: Recreate$$/ {found=1} /^  [^ ]/ {s=0} END {exit !found}' \
	  || { echo "the chart's Deployment does not stop the earlier release before starting this one"; exit 1; }
	@# Sign-in by a header believed from the pod network is sign-in any pod
	@# can assert, so such an install is fenced to its ingress controller.
	@helm template t deploy/helm/openpsirt --set database.existingSecret=s \
	  --set auth.bootstrapAdmins='{admin}' --set auth.trustedHeader.name=X-User \
	  --set auth.trustedHeader.sources='{10.0.0.0/8}' | grep -q '^kind: NetworkPolicy$$' \
	  || { echo "a trusted-header install renders no NetworkPolicy, so any pod can assert the header"; exit 1; }
	@# A rotated password the chart holds rolls the pods, the mail one included
	@# where it is the only one.
	@helm template t deploy/helm/openpsirt --set database.existingSecret=s \
	  --set auth.bootstrapAdmins='{admin}' --set auth.trustedHeader.name=X-User \
	  --set auth.trustedHeader.sources='{10.0.0.0/8}' --set mail.server=smtp:587 \
	  --set mail.from=psirt@example.com --set mail.username=u --set mail.password=shh \
	  -s templates/deployment.yaml | grep -q 'checksum/secrets:' \
	  || { echo "rotating the chart-held mail password would not roll the pods"; exit 1; }
	# An install that cannot reach a login is not an install, and mail that is
	# half configured is mail nobody gets. Each of these refuses at template
	# time rather than producing a deployment that starts, fails its own
	# administration check, and crash-loops with the reason in a log nobody is
	# watching yet — or one that comes up healthy and quietly tells nobody.
	@# Each case names the substring the chart's own fail must carry. Branching
	@# on the exit status alone with both streams discarded, any template error
	@# read as the refusal — so an unrelated fault reachable under one value
	@# combination looked exactly like the guard working, and the success line
	@# below printed anyway.
	@refusals=0; \
	for missing in \
	  "no database|needs a database|" \
	  "nobody can administer|set auth.bootstrapAdmins|--set database.existingSecret=s" \
	  "no way to sign in|configure a way to sign in|--set database.existingSecret=s --set auth.bootstrapAdmins={admin}" \
	  "no address to return to|set auth.baseURL|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.oidc.issuer=https://id.example.com" \
	  "a header anybody can set|set auth.trustedHeader.sources|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.trustedHeader.name=X-User" \
	  "half a mail configuration|set mail.server and mail.from together|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8} --set mail.server=smtp:587" \
	  "a password that is never sent|set mail.username|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8} --set mail.server=smtp:587 --set mail.from=psirt@example.com --set mail.password=shh" \
	  "a provider and no client secret|set auth.oidc.clientSecret|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.baseURL=https://p.example.com --set auth.oidc.issuer=https://id.example.com --set auth.oidc.clientID=abc" \
	  "a provider and no username claim|set auth.oidc.usernameClaim|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.baseURL=https://p.example.com --set auth.oidc.issuer=https://id.example.com --set auth.oidc.clientID=abc --set auth.oidc.clientSecret=shh" \
	  "a GitHub app and no client secret|set auth.github.clientSecret|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.baseURL=https://p.example.com --set auth.github.clientID=gh" \
	  "half a Zulip bot|set chat.zulip.site, chat.zulip.email and chat.zulip.key|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8} --set chat.zulip.site=https://chat.example.com" \
	  "a Slack token given twice|set chat.slack.token or chat.slack.existingSecret, not both|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8} --set chat.slack.token=xoxb-1 --set chat.slack.existingSecret=mine" \
	  "a Zulip key given twice|set chat.zulip.key or chat.zulip.existingSecret, not both|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8} --set chat.zulip.site=https://chat.example.com --set chat.zulip.email=bot@chat.example.com --set chat.zulip.key=k --set chat.zulip.existingSecret=mine" \
	  "a secret given twice|not both|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.baseURL=https://p.example.com --set auth.oidc.issuer=https://id.example.com --set auth.oidc.clientID=abc --set auth.oidc.usernameClaim=sub --set auth.oidc.clientSecret=shh --set auth.oidc.existingSecret=mine" \
	  "SQLite behind more than one replica|SQLite is one file on one pod|--set database.url=sqlite:///var/lib/openpsirt/openpsirt.db --set auth.bootstrapAdmins={admin} --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8}" \
	  "a scanner cache claim every replica mounts and only one can|no ReadWriteMany access mode|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8} --set scanner.persistence.enabled=true" \
	  "a scanner cache claim given twice|set scanner.persistence.enabled or scanner.persistence.existingClaim|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8} --set scanner.persistence.enabled=true --set scanner.persistence.existingClaim=mine" \
	  "a group role naming no group|names no group|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.baseURL=https://p.example.com --set auth.github.clientID=gh --set auth.github.clientSecret=shh --set auth.github.org=o --set auth.groupRoles[0].roles={admin}" \
	  "a group role granting nothing|names no roles|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.baseURL=https://p.example.com --set auth.github.clientID=gh --set auth.github.clientSecret=shh --set auth.github.org=o --set auth.groupRoles[0].group=g" \
	  "a group role naming no role|is not a role|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.baseURL=https://p.example.com --set auth.github.clientID=gh --set auth.github.clientSecret=shh --set auth.github.org=o --set auth.groupRoles[0].group=g --set auth.groupRoles[0].roles={owner}" \
	  "a group role with an empty product|names an empty product|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.baseURL=https://p.example.com --set auth.github.clientID=gh --set auth.github.clientSecret=shh --set auth.github.org=o --set auth.groupRoles[0].group=g --set auth.groupRoles[0].roles={public-read} --set auth.groupRoles[0].products={}" \
	  "administration held on a product|takes no products|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.baseURL=https://p.example.com --set auth.github.clientID=gh --set auth.github.clientSecret=shh --set auth.github.org=o --set auth.groupRoles[0].group=g --set auth.groupRoles[0].roles={admin} --set auth.groupRoles[0].products={router-os}" \
	  "group roles and nothing reporting groups|set a source of groups for auth.groupRoles|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.baseURL=https://p.example.com --set auth.github.clientID=gh --set auth.github.clientSecret=shh --set auth.groupRoles[0].group=g --set auth.groupRoles[0].roles={admin}" \
	  "SQLite where nothing is writable|SQLite outside /var/lib/openpsirt|--set database.url=sqlite:///data/openpsirt.db --set replicaCount=1 --set auth.bootstrapAdmins={admin} --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8}" \
	  "SQLite in a directory nothing creates|SQLite outside /var/lib/openpsirt|--set database.url=sqlite:///var/lib/openpsirt/trial/openpsirt.db --set replicaCount=1 --set auth.bootstrapAdmins={admin} --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8}" \
	  "SQLite climbing out of its directory|SQLite outside /var/lib/openpsirt|--set database.url=sqlite:///var/lib/openpsirt/../../tmp/x.db --set replicaCount=1 --set auth.bootstrapAdmins={admin} --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8}" \
	  "a SQLite claim nothing mounts|database.sqlite.existingClaim is set and database.url is not SQLite|--set database.existingSecret=s --set database.sqlite.existingClaim=mine --set auth.bootstrapAdmins={admin} --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8}" \
	  "a controller named by its pods alone|set networkPolicy.ingressController.namespaceLabels|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8} --set networkPolicy.ingressController.podLabels.app=router" \
	  "a trusted header fenced from everybody|set networkPolicy.ingressController or networkPolicy.from|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8} --set networkPolicy.ingressController.enabled=false"; do \
	  refusals=$$((refusals + 1)); \
	  what="$${missing%%|*}"; rest="$${missing#*|}"; \
	  expect="$${rest%%|*}"; args="$${rest#*|}"; \
	  out=$$(helm template t deploy/helm/openpsirt $$args 2>&1) && { \
	    echo "the chart accepted an install with $$what"; exit 1; }; \
	  case "$$out" in \
	    *"$$expect"*) ;; \
	    *) echo "the chart refused an install with $$what for the wrong reason:"; \
	       echo "$$out"; exit 1;; \
	  esac; \
	done; \
	  [ "$$refusals" -gt 0 ] || { echo "no refusal was examined, so this checked nothing"; exit 1; }; \
	  echo "  $$refusals installs the chart has to refuse, each for the reason it names"
	@echo "the chart refuses every install that could not be signed into or could not start, and every mail configuration that would send nothing"
	@# Helm merges a map an operator sets into a default map, so a policy
	@# holding its defaults in values.yaml would keep ingress-nginx's labels beside
	@# another controller's, and admit nobody while rendering cleanly.
	@set -e; out=$$(helm template t deploy/helm/openpsirt -s templates/networkpolicy.yaml \
	  --set database.existingSecret=s --set auth.bootstrapAdmins={admin} \
	  --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8} \
	  --set networkPolicy.ingressController.podLabels.app=router \
	  --set networkPolicy.ingressController.namespaceLabels.team=edge); \
	case "$$out" in *ingress-nginx*) echo "a controller's own labels were merged with ingress-nginx's:"; echo "$$out"; exit 1;; esac; \
	case "$$out" in *"app: router"*) ;; *) echo "a controller's own labels were not rendered:"; echo "$$out"; exit 1;; esac; \
	case "$$out" in *"team: edge"*) ;; *) echo "a controller's own namespace labels were not rendered:"; echo "$$out"; exit 1;; esac
	@echo "the network policy admits a controller by its own labels alone"
	@# The root filesystem is read-only, so a single-pod SQLite trial gets a
	@# writable directory for its file, and nothing else does.
	@set -e; out=$$(helm template t deploy/helm/openpsirt -s templates/deployment.yaml \
	  --set database.url=sqlite:///var/lib/openpsirt/openpsirt.db --set replicaCount=1 \
	  --set auth.bootstrapAdmins={admin} --set auth.trustedHeader.name=X-User \
	  --set auth.trustedHeader.sources={10.0.0.0/8}); \
	case "$$out" in *"mountPath: /var/lib/openpsirt"*) ;; *) echo "a SQLite trial has nowhere writable for its file:"; echo "$$out"; exit 1;; esac; \
	out=$$(helm template t deploy/helm/openpsirt -s templates/deployment.yaml \
	  --set database.existingSecret=s --set auth.bootstrapAdmins={admin} \
	  --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8}); \
	case "$$out" in *"/var/lib/openpsirt"*) echo "a server database was given a SQLite volume:"; echo "$$out"; exit 1;; esac
	@echo "a single-pod SQLite trial keeps its file on a volume of its own"
	@# A group or product name holding a character the variable separates on
	@# is carried encoded, so the process reads the name it was given.
	@out=$$(helm template t deploy/helm/openpsirt -s templates/deployment.yaml \
	  --set database.existingSecret=s --set auth.bootstrapAdmins={admin} \
	  --set auth.baseURL=https://p.example.com --set auth.github.clientID=gh \
	  --set auth.github.clientSecret=shh --set auth.github.org=o \
	  --set 'auth.groupRoles[0].group=sec@example.com' --set 'auth.groupRoles[0].roles={public-triage,approver}' \
	  --set 'auth.groupRoles[0].products={router-os,switch-os}'); \
	case "$$out" in *'value: "sec%40example.com=public-triage+approver@router-os,switch-os"'*) ;; \
	  *) echo "the group roles were not rendered as OPENPSIRT_GROUP_ROLES reads them:"; echo "$$out" | grep -A1 GROUP_ROLES; exit 1;; esac
	@echo "the group roles render encoded, as the process reads them"
	@# A group mapped to admin is somebody who can administer, so it stands in
	@# for a named administrator.
	@helm template t deploy/helm/openpsirt -s templates/deployment.yaml \
	  --set database.existingSecret=s --set auth.baseURL=https://p.example.com \
	  --set auth.github.clientID=gh --set auth.github.clientSecret=shh --set auth.github.org=o \
	  --set 'auth.groupRoles[0].group=leads' --set 'auth.groupRoles[0].roles={admin}' >/dev/null \
	  || { echo "an install whose only administrator is a group mapped to admin was refused"; exit 1; }
	@echo "a group mapped to admin stands in for a named administrator"
	@# The refusals above assert that an install the chart cannot serve fails
	@# at render. These assert the other half: that a legal one renders a
	@# reference something answers. A secretKeyRef naming a Secret nothing
	@# creates, or a key nothing writes, renders perfectly and leaves a pod
	@# that can never start — the same failure the refusals exist to prevent,
	@# one step later and with no message anybody reads.
	@#
	@# Read out of the render rather than compared against a list written
	@# here: a fifth secret source added later gets no row in a list and the
	@# check stays green on exactly the defect it is for. Every reference a
	@# legal install renders is resolved against the Secrets that same install
	@# creates, and the count of what was examined is printed, because a walk
	@# that found nothing looks like a walk that found nothing wrong.
	@#
	@# Every value is held by the chart in these, because a Secret the
	@# operator manages is not in the render and a reference to one cannot be
	@# resolved here. That arm is asserted below, against what they named.
	@set -e; base="--set auth.bootstrapAdmins={admin} --set auth.baseURL=https://psirt.example.com"; \
	refs=0; \
	for install in \
	  "a database URL the chart holds|--set database.url=postgres://u:p@h:5432/d --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8}" \
	  "an OIDC secret the chart holds|--set database.url=postgres://u:p@h:5432/d --set auth.oidc.issuer=https://id.example.com --set auth.oidc.clientID=abc --set auth.oidc.usernameClaim=sub --set auth.oidc.clientSecret=shh" \
	  "a GitHub secret the chart holds|--set database.url=postgres://u:p@h:5432/d --set auth.github.clientID=gh --set auth.github.clientSecret=shh" \
	  "a mail password the chart holds|--set database.url=postgres://u:p@h:5432/d --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8} --set mail.server=smtp:587 --set mail.from=psirt@example.com --set mail.username=u --set mail.password=shh" \
	  "chat credentials the chart holds|--set database.url=postgres://u:p@h:5432/d --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8} --set chat.slack.token=xoxb-1 --set chat.zulip.site=https://chat.example.com --set chat.zulip.email=bot@chat.example.com --set chat.zulip.key=k" \
	  "every secret the chart holds at once|--set database.url=postgres://u:p@h:5432/d --set auth.oidc.issuer=https://id.example.com --set auth.oidc.clientID=abc --set auth.oidc.usernameClaim=sub --set auth.oidc.clientSecret=shh --set mail.server=smtp:587 --set mail.from=psirt@example.com --set mail.username=u --set mail.password=shh"; do \
	  what="$${install%%|*}"; args="$${install#*|}"; \
	  out=$$(helm template t deploy/helm/openpsirt $$base $$args) \
	    || { echo "the chart refused $$what:"; echo "$$out"; exit 1; }; \
	  written=$$(printf '%s\n' "$$out" | awk '\
	    /^kind: Secret$$/ {secret=1; next} \
	    /^---/ {secret=0; holds=0; next} \
	    secret && /^  name:/ {name=$$2; next} \
	    secret && /^stringData:$$/ {holds=1; next} \
	    holds && /^  [A-Za-z0-9_-]+:/ {key=$$1; sub(":", "", key); print name "/" key}' | tr '\n' ' '); \
	  found=$$(printf '%s\n' "$$out" | awk '\
	    /secretKeyRef:/ {ref=1; next} \
	    ref && /name:/ {name=$$2; next} \
	    ref && /key:/ {print name "/" $$2; ref=0}'); \
	  [ -n "$$found" ] || { echo "$$what renders no secret reference at all"; exit 1; }; \
	  for one in $$found; do \
	    refs=$$((refs + 1)); \
	    case " $$written " in \
	      *" $$one "*) ;; \
	      *) echo "with $$what the chart asks for $$one and creates [$$written]"; exit 1 ;; \
	    esac; \
	  done; \
	done; \
	[ "$$refs" -gt 0 ] || { echo "no secret reference was examined, so this checked nothing"; exit 1; }; \
	echo "  $$refs secret references, every one of them answered by a Secret the same install writes"
	@# The operator's own Secret is the other arm, and cannot be resolved
	@# inside the render because it is theirs. What is asserted there is that
	@# the reference names what they named, rather than the chart's own key.
	@set -e; out=$$(helm template t deploy/helm/openpsirt \
	  --set database.existingSecret=s --set auth.bootstrapAdmins={admin} \
	  --set auth.baseURL=https://psirt.example.com \
	  --set auth.oidc.issuer=https://id.example.com --set auth.oidc.clientID=abc \
	  --set auth.oidc.usernameClaim=sub \
	  --set auth.oidc.existingSecret=mine --set auth.oidc.existingSecretKey=theirs); \
	  got=$$(printf '%s\n' "$$out" | awk '\
	    $$0 ~ "name: OPENPSIRT_OIDC_CLIENT_SECRET$$" {f=1; next} \
	    f && /secretKeyRef:/ {g=1; next} \
	    g && /name:/ {n=$$2; next} \
	    g && /key:/ {print n, $$2; exit}'); \
	  [ "$$got" = "mine theirs" ] \
	    || { echo "with a Secret the operator holds, the chart asks for [$$got]"; exit 1; }
	@echo "every secret the chart renders a reference to is one it creates, under the key it wrote"
endif
