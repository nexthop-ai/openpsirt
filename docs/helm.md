# Helm

The Helm chart is the supported deployment on Kubernetes. It runs the
container image, sets every setting through an `OPENPSIRT_` environment
variable, and refuses at render any install that could not start or could not
be signed into.

## Chart installation

The chart is published on each release beside the image, as
`openpsirt-{{ release }}.tgz`.

```sh
helm install openpsirt \
  https://github.com/nexthop-ai/openpsirt/releases/download/v{{ release }}/openpsirt-{{ release }}.tgz \
  --namespace openpsirt --create-namespace \
  -f values.yaml
```

`values.yaml` in the chart describes every value. The tables below say what an
install needs and which setting each value sets.

## Minimum values

| Value | Holds |
|---|---|
| `database.url` or `database.existingSecret` | The database. SQLite is for a single-pod trial, and the chart refuses it beside a second replica |
| `auth.baseURL` | The address people reach the deployment on, in full: `https://psirt.example.com`. Required once a provider is configured |
| `auth.oidc.issuer`, `auth.github.clientID` or `auth.trustedHeader.name` | One way to sign in |
| `auth.bootstrapAdmins` | Who administers the deployment. Granted at every start, so it is also the way back in |

```yaml
database:
  existingSecret: openpsirt-database
auth:
  baseURL: https://psirt.example.com
  bootstrapAdmins: [ana]
  github:
    clientID: Iv1.0123456789abcdef
    existingSecret: openpsirt-github
    org: example-corp
```

## Secrets

Each secret value is given one of two ways, never both.

| Form | Effect |
|---|---|
| The value itself: `database.url`, `auth.oidc.clientSecret`, `auth.github.clientSecret`, `mail.password`, `chat.slack.token`, `chat.zulip.key` | The chart writes it into a Secret of its own. A changed value rolls the pods |
| `existingSecret`, with `existingSecretKey` | The chart reads a Secret you manage, under that key |

`existingSecret` is the recommended form. A value in `values.yaml` is kept in
the release history and usually in version control.

| Secret | Default key |
|---|---|
| `database.existingSecret` | `database-url` |
| `auth.oidc.existingSecret` | `oidc-client-secret` |
| `auth.github.existingSecret` | `github-client-secret` |
| `mail.existingSecret` | `mail-password` |
| `chat.slack.existingSecret` | `slack-token` |
| `chat.zulip.existingSecret` | `zulip-key` |

## Sign-in

### GitHub

| Step | |
|---|---|
| Register an OAuth app in the organization | Its authorization callback URL is `<auth.baseURL>/v1/sign-in/github/callback`, such as `https://psirt.example.com/v1/sign-in/github/callback`. GitHub compares it exactly |
| Allow the app to read the organization | An organization that restricts third-party OAuth apps reports no teams to one it has not approved, and nobody then holds a role through a team |
| Set `auth.github.org` | Sign-in is limited to members of that organization, and their teams are read as groups |
| Map teams to roles in `auth.groupRoles` | A group is a team slug, matched exactly with its capitals: `kernel-security`, not `Kernel Security` |

```yaml
auth:
  baseURL: https://psirt.example.com
  bootstrapAdmins: [ana]
  github:
    clientID: Iv1.0123456789abcdef
    existingSecret: openpsirt-github
    org: example-corp
  groupRoles:
    - group: psirt-leads
      roles: [admin]
    - group: security-team
      roles: [private-triage, approver]
    - group: kernel-maintainers
      roles: [public-triage]
      products: [router-os, switch-os]
```

### OpenID Connect

The callback URL is
`<auth.baseURL>/v1/sign-in/<auth.oidc.name>/callback`, which is
`/v1/sign-in/oidc/callback` under the default name, and a group is a value of
the claim `auth.oidc.groupsClaim` names.

### Roles from groups

The chart renders `auth.groupRoles` as one variable:

```yaml
- name: OPENPSIRT_GROUP_ROLES
  value: "psirt-leads=admin; security-team=private-triage+approver; kernel-maintainers=public-triage@router-os,switch-os"
```

| Rule | |
|---|---|
| `products` absent | The roles are held on every product, including products declared later |
| `admin` and `audit` | Held over the deployment, so an entry granting either names no products |
| Any entry | Roles come from groups, and nothing in the running application changes the mapping. It changes with the release |
| A source of groups | `auth.github.org`, `auth.oidc.groupsClaim` or `auth.trustedHeader.groupsHeader`. The chart refuses `groupRoles` without one |

[Roles from groups](configuration.md#roles-from-groups) holds the whole of the
setting.

## Upgrades

| Value | Effect |
|---|---|
| `strategy` | `Recreate` by default, so every pod of the earlier release stops before a pod of this one starts |
| `autoMigrate` | `true` by default: the schema is upgraded at startup. With `false`, run `openpsirt migrate up` before the upgrade |

[Upgrading](configuration.md#upgrading) holds what each release needs.

## Values and variables

Each value sets the variable beside it. A setting with no value here is set
through `extraEnv`, which takes entries in the Kubernetes `env` form.

| Value | Variable | Described in |
|---|---|---|
| `database.url`, `database.existingSecret` | `OPENPSIRT_DATABASE_URL` | [Database](configuration.md#database) |
| `autoMigrate` | `OPENPSIRT_AUTO_MIGRATE` | [Database](configuration.md#database) |
| `auth.baseURL` | `OPENPSIRT_BASE_URL` | [Serving](configuration.md#serving) |
| `log.level` | `OPENPSIRT_LOG_LEVEL` | [Serving](configuration.md#serving) |
| `log.format` | `OPENPSIRT_LOG_FORMAT` | [Serving](configuration.md#serving) |
| `auth.bootstrapAdmins` | `OPENPSIRT_BOOTSTRAP_ADMINS` | [Sign-in](configuration.md#sign-in) |
| `auth.groupRoles` | `OPENPSIRT_GROUP_ROLES` | [Roles from groups](configuration.md#roles-from-groups) |
| `auth.oidc.name` | `OPENPSIRT_OIDC_NAME` | [An OpenID Connect provider](configuration.md#an-openid-connect-provider) |
| `auth.oidc.issuer` | `OPENPSIRT_OIDC_ISSUER` | [An OpenID Connect provider](configuration.md#an-openid-connect-provider) |
| `auth.oidc.clientID` | `OPENPSIRT_OIDC_CLIENT_ID` | [An OpenID Connect provider](configuration.md#an-openid-connect-provider) |
| `auth.oidc.clientSecret`, `auth.oidc.existingSecret` | `OPENPSIRT_OIDC_CLIENT_SECRET` | [An OpenID Connect provider](configuration.md#an-openid-connect-provider) |
| `auth.oidc.usernameClaim` | `OPENPSIRT_OIDC_USERNAME_CLAIM` | [An OpenID Connect provider](configuration.md#an-openid-connect-provider) |
| `auth.oidc.groupsClaim` | `OPENPSIRT_OIDC_GROUPS_CLAIM` | [An OpenID Connect provider](configuration.md#an-openid-connect-provider) |
| `auth.github.clientID` | `OPENPSIRT_GITHUB_CLIENT_ID` | [GitHub](configuration.md#github) |
| `auth.github.clientSecret`, `auth.github.existingSecret` | `OPENPSIRT_GITHUB_CLIENT_SECRET` | [GitHub](configuration.md#github) |
| `auth.github.org` | `OPENPSIRT_GITHUB_ORG` | [GitHub](configuration.md#github) |
| `auth.trustedHeader.name` | `OPENPSIRT_TRUSTED_HEADER` | [The trusted header](configuration.md#the-trusted-header) |
| `auth.trustedHeader.sources` | `OPENPSIRT_TRUSTED_SOURCES` | [The trusted header](configuration.md#the-trusted-header) |
| `auth.trustedHeader.groupsHeader` | `OPENPSIRT_TRUSTED_GROUPS_HEADER` | [The trusted header](configuration.md#the-trusted-header) |
| `auth.trustedHeader.groupsDelimiter` | `OPENPSIRT_TRUSTED_GROUPS_DELIMITER` | [The trusted header](configuration.md#the-trusted-header) |
| `outbound.excluded` | `OPENPSIRT_OUTBOUND_EXCLUDED` | [Outbound exclusions](configuration.md#outbound-exclusions) |
| `patchBranches.enabled` | `OPENPSIRT_PATCH_BRANCHES` | [Patch branches](configuration.md#patch-branches) |
| `patchBranches.quota` | `OPENPSIRT_PATCH_QUOTA` | [Patch branches](configuration.md#patch-branches) |
| `mail.server` | `OPENPSIRT_MAIL_SERVER` | [Mail](configuration.md#mail) |
| `mail.from` | `OPENPSIRT_MAIL_FROM` | [Mail](configuration.md#mail) |
| `mail.username` | `OPENPSIRT_MAIL_USERNAME` | [Mail](configuration.md#mail) |
| `mail.password`, `mail.existingSecret` | `OPENPSIRT_MAIL_PASSWORD` | [Mail](configuration.md#mail) |
| `chat.slack.token`, `chat.slack.existingSecret` | `OPENPSIRT_SLACK_TOKEN` | [Chat](configuration.md#chat) |
| `chat.zulip.site` | `OPENPSIRT_ZULIP_SITE` | [Chat](configuration.md#chat) |
| `chat.zulip.email` | `OPENPSIRT_ZULIP_EMAIL` | [Chat](configuration.md#chat) |
| `chat.zulip.key`, `chat.zulip.existingSecret` | `OPENPSIRT_ZULIP_KEY` | [Chat](configuration.md#chat) |
