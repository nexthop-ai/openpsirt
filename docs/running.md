# The binary on a host

The container image and the Helm chart are the supported deployment. The
release also carries the binary for Linux, amd64 and arm64, which runs the
same program on a host of your own. The interface is built into it.

A host running the binary needs four things beside it: the vulnerability
scanner, a database, a configuration file, and a reverse proxy for TLS.

## The release archive

Download three files from the release page,
`https://github.com/nexthop-ai/openpsirt/releases/tag/v{{ release }}`:

| File | Holds |
|---|---|
| `openpsirt_{{ release }}_linux_amd64.tar.gz`, or `_arm64` | The binary, with `LICENSE`, `NOTICE` and `README.md` |
| `SHA256SUMS` | The checksum of every file on the release |
| `SHA256SUMS.cosign.bundle` | The signature over `SHA256SUMS`, made by the release workflow |

Check the signature with cosign 3 or later, then the checksum, then install:

```
cosign verify-blob \
  --bundle SHA256SUMS.cosign.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/nexthop-ai/openpsirt/.github/workflows/release.yml@refs/tags/v{{ release }} \
  SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf openpsirt_{{ release }}_linux_amd64.tar.gz
sudo install -m 0755 openpsirt_{{ release }}_linux_amd64/openpsirt /usr/local/bin/openpsirt
openpsirt -version
```

The signature says the file came from this repository's release workflow at
that tag. `--ignore-missing` checks the files you downloaded and skips the rest.

## The scanner

The deployment runs the scan itself, with the scanner the image carries:
Grype {{ scanner }}. Install that version. A different one reads a different
database format and answers differently, so findings stop being comparable
with a deployment running the image.

```
curl -fsSLO https://github.com/anchore/grype/releases/download/v{{ scanner }}/grype_{{ scanner }}_linux_amd64.tar.gz
curl -fsSLO https://github.com/anchore/grype/releases/download/v{{ scanner }}/grype_{{ scanner }}_checksums.txt
sha256sum --ignore-missing -c grype_{{ scanner }}_checksums.txt
tar -xzf grype_{{ scanner }}_linux_amd64.tar.gz grype
sudo install -m 0755 grype /usr/local/bin/grype
```

The process finds it on `PATH`. `scanner.path` in the configuration file names
it anywhere else.

### Vulnerability data

| Where the host is | What to do |
|---|---|
| It reaches the network | Nothing. The scanner downloads its data into `GRYPE_DB_CACHE_DIR` on first use and keeps it current |
| It does not | Build the offline bundle with `make scanner-db` in a checkout of this release on a machine that does, carry the bundle and its `.sha256` across, check it with `sha256sum -c`, unpack it into `GRYPE_DB_CACHE_DIR`, and set `GRYPE_DB_AUTO_UPDATE=false` in the unit. [An air-gapped install](configuration.md#an-air-gapped-install) says what the bundle is checked for |

The `GRYPE_` variables are the scanner's own, so they go in the unit's
environment beside a configuration file.

## Layout

| Path | Holds | Owner and mode |
|---|---|---|
| `/usr/local/bin/openpsirt` | The binary | `root`, `0755` |
| `/usr/local/bin/grype` | The scanner | `root`, `0755` |
| `/etc/openpsirt/openpsirt.toml` | The configuration file | `openpsirt`, `0600`. Refused at startup when anybody else may read or write it |
| `/var/lib/openpsirt` | A SQLite database, and attachments where `attachments.dir` names a directory here | `openpsirt`, `0700` |
| `/var/cache/openpsirt/grype` | The scanner's vulnerability data | `openpsirt`, `0700` |
| `/var/cache/openpsirt/repositories` | Copies of repositories, where patch branch lookups are on | `openpsirt`, `0700` |

The process runs as its own unprivileged user:

```
sudo useradd --system --no-create-home --shell /usr/sbin/nologin openpsirt
sudo install -d -o root -g root -m 0755 /etc/openpsirt
sudo install -o openpsirt -g openpsirt -m 0600 /dev/null /etc/openpsirt/openpsirt.toml
```

SQLite is for a trial on one host. A deployment people rely on points
`database.url` at PostgreSQL, MySQL or MariaDB.

## The configuration file

Every setting, its key and its default is in [Configuration](configuration.md).
Behind a proxy on the same host:

```toml
[server]
address = "127.0.0.1:8080"
base_url = "https://psirt.example.com"

[database]
url = "postgres://openpsirt:secret@db.example.com:5432/openpsirt?sslmode=verify-full"

[signin]
bootstrap_admins = ["ana"]

[signin.oidc]
issuer = "https://id.example.com"
client_id = "openpsirt"
client_secret = "secret"
username_claim = "preferred_username"
```

| Key | Why |
|---|---|
| `server.address` on `127.0.0.1` | Only the proxy reaches the process. Reached directly, a request skips TLS and, with trusted-header sign-in, the proxy that authenticated it |
| `server.base_url` | The address people type. Sign-in providers send people back to it, links in notifications point at it, and a browser's write is refused when its origin is anything else |
| `server.plain_http` left unset | The session cookie is marked for HTTPS only. The browser is on HTTPS at the proxy, which is what the cookie needs |

No `OPENPSIRT_` variable is set anywhere the process can see it: one beside the
file is refused at startup, naming it.

## The service

```ini
[Unit]
Description=OpenPSIRT
Wants=network-online.target
After=network-online.target

[Service]
User=openpsirt
Group=openpsirt
ExecStart=/usr/local/bin/openpsirt serve --config /etc/openpsirt/openpsirt.toml
Environment=GRYPE_DB_CACHE_DIR=/var/cache/openpsirt/grype
StateDirectory=openpsirt
StateDirectoryMode=0700
CacheDirectory=openpsirt openpsirt/grype openpsirt/repositories
CacheDirectoryMode=0700
Restart=on-failure
TimeoutStopSec=45
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

| Line | Why |
|---|---|
| `StateDirectory`, `CacheDirectory` | systemd makes the directories in the layout above, owned by the service user, and leaves them writable under `ProtectSystem=strict` |
| `TimeoutStopSec=45` | On a stop the process gives requests in flight `server.shutdown_grace`, 15 seconds unless set, and then background work the same again. Raise both together |
| `Restart=on-failure` | A refusal at startup exits with status 1, naming what to fix, and `journalctl -u openpsirt` shows it |

Save it as `/etc/systemd/system/openpsirt.service`, then
`sudo systemctl daemon-reload && sudo systemctl enable --now openpsirt`.

## The reverse proxy

The binary serves plain HTTP. It has no TLS settings, and it marks its session
cookie for HTTPS only, so a browser signs in only through something serving
HTTPS in front of it. `server.plain_http` removes that marking, which is for
running on one machine and nothing else. A deployment people reach has a
reverse proxy terminating TLS.

| The proxy | Why |
|---|---|
| Terminates TLS, and redirects HTTP to HTTPS | The session cookie travels over HTTPS alone |
| Passes to `server.address` | `127.0.0.1:8080` in the examples |
| Passes the `Host` header through | Where `server.base_url` is unset, a browser's origin is compared with the `Host` the process receives. Set `server.base_url` to the address the proxy answers on, and the comparison is with that |
| Sends no forwarding headers the process needs | It reads no `X-Forwarded-For`, `X-Forwarded-Proto` or `Forwarded` header. The client address it sees is the proxy's, and `signin.trusted_header.sources` is matched against that address |
| Accepts a request body of twice `ingest.max_bytes` | One upload carries an inventory and its suppression documents: 512 MB at the defaults. Past the proxy's own limit the upload is refused by the proxy with a 413, before the process sees it, and nginx's default is 1 MB |
| Waits 300 seconds for a response | The process gives a request five minutes to arrive and five minutes to answer. An export of a large product, a CSV or VEX download, and a scan upload over a slow link run close to that |
| Does not buffer responses | Exports, the `.csv` and `.json` downloads, are written as they are read |

The configurations below were each checked by the server's own configuration
test, and by requests through the server to the binary.

### nginx

```nginx
server {
    listen 80;
    server_name psirt.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name psirt.example.com;

    ssl_certificate     /etc/ssl/psirt.example.com/fullchain.pem;
    ssl_certificate_key /etc/ssl/psirt.example.com/privkey.pem;

    # Twice ingest.max_bytes: one upload carries an inventory and its
    # suppression documents.
    client_max_body_size 512m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        # The server gives a request five minutes each way.
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        # Exports are written as they are read.
        proxy_buffering off;
        proxy_request_buffering off;
    }
}
```

### Apache httpd

With `mod_ssl`, `mod_proxy`, `mod_proxy_http` and `mod_rewrite` loaded.

```apache
<VirtualHost *:80>
    ServerName psirt.example.com
    RewriteEngine On
    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
</VirtualHost>

<VirtualHost *:443>
    ServerName psirt.example.com
    SSLEngine on
    SSLCertificateFile    /etc/ssl/psirt.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/ssl/psirt.example.com/privkey.pem

    # Twice ingest.max_bytes, in bytes.
    LimitRequestBody 536870912
    ProxyPreserveHost On
    ProxyTimeout 300
    ProxyPass        / http://127.0.0.1:8080/ flushpackets=on
    ProxyPassReverse / http://127.0.0.1:8080/
</VirtualHost>
```

`LimitRequestBody` is in bytes. `flushpackets=on` passes each part of an
export on as it arrives.

### Caddy

Caddy obtains the certificate, and redirects HTTP to HTTPS, by itself.

```
psirt.example.com {
	request_body {
		max_size 512MB
	}
	reverse_proxy 127.0.0.1:8080 {
		flush_interval -1
	}
}
```

## Trusted-header sign-in

The proxy authenticates each person, and tells the process who they are in a
header. [The trusted header](configuration.md#the-trusted-header) holds the
settings.

```toml
[signin.trusted_header]
name = "X-User"
sources = ["127.0.0.1/32"]
groups_header = "X-Groups"
```

!!! danger "Remove the header the client sent"
    The process believes the header from any request arriving from
    `signin.trusted_header.sources`, and every request through the proxy
    arrives from there. A proxy that passes on an `X-User` the client wrote
    lets anybody sign in as anybody, the administrators included. Remove
    the client's copy of both headers before setting them.

| The proxy | Why |
|---|---|
| Authenticates every request to the people's address | A request that reaches the process without passing authentication carries no identity |
| Removes any `X-User` and `X-Groups` the client sent, then sets them from who it authenticated | The process cannot tell a header the proxy wrote from one the client wrote |
| Is the only address in `signin.trusted_header.sources` | Anything else listed there can assert anybody |
| Serves build pipelines on an address of their own, removing both headers and authenticating nothing | A pipeline sends an API key and cannot sign in through a browser, and the process authenticates the key |

### nginx with oauth2-proxy

oauth2-proxy runs on port 4180 with `--reverse-proxy` and `--set-xauthrequest`,
which is what makes it answer with the user and groups headers read below.

```nginx
server {
    listen 80;
    server_name psirt.example.com api.psirt.example.com;
    return 301 https://$host$request_uri;
}

# People: every request is authenticated here first.
server {
    listen 443 ssl;
    server_name psirt.example.com;

    ssl_certificate     /etc/ssl/psirt.example.com/fullchain.pem;
    ssl_certificate_key /etc/ssl/psirt.example.com/privkey.pem;
    client_max_body_size 512m;

    # The authenticating service, here oauth2-proxy on port 4180.
    location /oauth2/ {
        proxy_pass http://127.0.0.1:4180;
        proxy_set_header Host $host;
        proxy_set_header X-Auth-Request-Redirect $request_uri;
    }
    location = /oauth2/auth {
        internal;
        proxy_pass http://127.0.0.1:4180;
        proxy_set_header Host $host;
        proxy_set_header Content-Length "";
        proxy_pass_request_body off;
    }

    location / {
        auth_request /oauth2/auth;
        error_page 401 = /oauth2/sign_in;
        auth_request_set $user   $upstream_http_x_auth_request_user;
        auth_request_set $groups $upstream_http_x_auth_request_groups;

        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        # Replaces whatever the client sent under these names.
        proxy_set_header X-User   $user;
        proxy_set_header X-Groups $groups;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        proxy_buffering off;
        proxy_request_buffering off;
    }
}

# Build pipelines, which send an API key and cannot sign in.
server {
    listen 443 ssl;
    server_name api.psirt.example.com;

    ssl_certificate     /etc/ssl/psirt.example.com/fullchain.pem;
    ssl_certificate_key /etc/ssl/psirt.example.com/privkey.pem;
    client_max_body_size 512m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        # An empty value removes the header: nobody signs in through here.
        proxy_set_header X-User   "";
        proxy_set_header X-Groups "";
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        proxy_buffering off;
        proxy_request_buffering off;
    }
}
```

`proxy_set_header` replaces a header of the same name from the client, and an
empty value removes it.

### Apache httpd

With `mod_headers` and an authentication module loaded as well.

```apache
<VirtualHost *:80>
    ServerName psirt.example.com
    ServerAlias api.psirt.example.com
    RewriteEngine On
    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
</VirtualHost>

# People: every request is authenticated here first.
<VirtualHost *:443>
    ServerName psirt.example.com
    SSLEngine on
    SSLCertificateFile    /etc/ssl/psirt.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/ssl/psirt.example.com/privkey.pem
    LimitRequestBody 536870912

    # Any module that authenticates and sets REMOTE_USER: mod_auth_openidc,
    # mod_auth_mellon, or Basic against a directory as here.
    <Location />
        AuthType Basic
        AuthName "OpenPSIRT"
        AuthBasicProvider file
        AuthUserFile /etc/apache2/openpsirt.htpasswd
        Require valid-user
    </Location>

    # Removed before anything else reads the request, then set from the
    # authenticated user.
    RequestHeader unset X-User early
    RequestHeader unset X-Groups early
    RequestHeader set X-User "expr=%{REMOTE_USER}"

    ProxyPreserveHost On
    ProxyTimeout 300
    ProxyPass        / http://127.0.0.1:8080/ flushpackets=on
    ProxyPassReverse / http://127.0.0.1:8080/
</VirtualHost>

# Build pipelines, which send an API key and cannot sign in.
<VirtualHost *:443>
    ServerName api.psirt.example.com
    SSLEngine on
    SSLCertificateFile    /etc/ssl/psirt.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/ssl/psirt.example.com/privkey.pem
    LimitRequestBody 536870912

    RequestHeader unset X-User early
    RequestHeader unset X-Groups early

    ProxyPreserveHost On
    ProxyTimeout 300
    ProxyPass        / http://127.0.0.1:8080/ flushpackets=on
    ProxyPassReverse / http://127.0.0.1:8080/
</VirtualHost>
```

`RequestHeader unset … early` removes the client's copy before authentication
runs, and `RequestHeader set` writes the authenticated user after it.

## Upgrading

Read [Upgrading](configuration.md#upgrading) for the release you are coming
from first.

1. Back the database up.
2. Stop the service: `sudo systemctl stop openpsirt`.
3. Install the new binary, checked as in [The release archive](#the-release-archive).
   Install the scanner at the version [The scanner](#the-scanner) names, where
   it has moved.
4. Where `database.auto_migrate` is `false`, migrate as the service user:
   `sudo -u openpsirt openpsirt migrate up --config /etc/openpsirt/openpsirt.toml`.
   Otherwise the process migrates as it starts.
5. Start the service: `sudo systemctl start openpsirt`.

`openpsirt migrate status --config /etc/openpsirt/openpsirt.toml` says which
schema version the database is at and which this build expects.
