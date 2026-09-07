# Waypoint

A self-hosted library of services and a small request desk for friends. Discover a game or app, request access where needed, discuss setup, and find your next steps. External accounts, media requests, and monitoring stay in their existing applications. An optional dedicated WireGuard gateway adds explicitly approved device network access.

Built in Go with SQLite, server-rendered HTML, and lightweight JavaScript. No Redis, Node runtime, cloud account, SMTP, service API credentials, or privileged container is required. Node/Playwright are used only by the isolated browser tests.

The optional [WireGuard/My Devices extension](docs/vpn.md) uses a separate gateway with container-scoped `NET_ADMIN`. It is disabled by default and never grants network access from portal membership or manual service records.

## Start locally

```sh
cp .env.example .env
docker compose build
docker compose run --rm portal migrate
docker compose run --rm portal admin create
docker compose up -d
```

Visit **http://localhost:8080**. Bootstrap prompts for an administrator username and a password of at least 12 characters. There are no default credentials or unauthenticated setup endpoints. Keep the password in your own password manager.

Optionally add example cards (no accounts, active grants, or real destinations):

```sh
docker compose run --rm portal seed-demo
```

The seed is explicit and idempotent and does not replace existing service settings. Example connection data uses `example.invalid` and is labeled as demonstration data. Normal startup never seeds anything. The WoW, Plex, Seerr, and Status actions remain disabled/unconfigured until you set their actual URLs.

The application is exposed on loopback only. A named volume persists the database, server sessions, CSRF key, and uploads. The image runs as UID/GID **65532**, drops capabilities, and has a read-only root filesystem. A bind mount, if substituted, must be writable by that UID; do not make data world-writable.

## Configure your community

1. Open **Administration → Settings** to choose branding. Public browsing is off by default. Turning it on exposes only content explicitly marked public.
2. Configure categories and services. Basic description/artwork follow discovery visibility; connection data and the setup guide have a separate audience. Category restrictions apply too. Save before using audience previews.
3. Add contextual links with explicit global, category, or service placement. An `access` audience always requires an associated service with a current portal access record. Parent restrictions cannot be overridden by a child link.
4. Configure the deployed **Waygate URL** under WoW, **Plex** and **Seerr** under Plex, and a user-facing **Status** board globally. `https://github.com/zeroward/waygate` is source reference only, never a deployed portal destination. No destination is fetched by the server.
5. Create an invitation from Members, copy its single-use link, and deliver it privately. Invitations reserve a username and create a member without service permissions. Optional service recommendations add a card label only and never bypass visibility or grant access. Optional contact emails are not verified and no email is sent.
6. Review requests. **Approved – Setup Pending does not grant access.** Perform setup in the appropriate external application, then fulfill the request with confirmation and non-secret next steps. The request update and portal access record commit together.
7. Use Access to record pre-existing access or update/revoke a portal record. Revocation, expiry, and member disablement create external-removal reminders. Complete those manually in the external system, then record completion here.

`public`, `member`, `access`, and `admin` mean public browsing, enabled signed-in members, members with a current recorded grant for the selected service, and administrators respectively. Administrators can inspect all configuration; preview uses the actual visibility policy with a simulated member/grant, without changing records.

Manual status is labeled with its update time. It is never a live health or player-count measurement. Service launch URIs must be configured explicitly; v1 allows `steam://` on service links with the game icon. Ordinary destinations use HTTP or HTTPS. Connection strings are copied exactly, not generated from host/port guesses.

## HTTPS and reverse proxies

For an optional Cloudflare Tunnel container, follow [the tunnel setup guide](docs/tunnel.md). Its Compose overlay works with the VPN overlay, uses a mounted token file, forces HTTPS cookies, and removes the portal host-port mapping. Set your Cloudflare hostname and publish the route to `http://portal:8080`. The WireGuard UDP endpoint remains separate.

For production, set:

```dotenv
APP_ENV=production
BASE_URL=https://portal.your-domain.example
TRUSTED_PROXIES=
```

Use your own real origin. Production refuses an HTTP base URL and sets Secure, HttpOnly, SameSite=Lax session cookies. Keep the Compose loopback bind when a host reverse proxy connects to `127.0.0.1:8080`. Terminate HTTPS at your chosen proxy, preserve the original Host, and set the original `X-Forwarded-For` chain. List only that proxy's source CIDRs in `TRUSTED_PROXIES`; otherwise forwarded client addresses are ignored. Forwarded identity headers are never authentication.

For a proxy in another container, deliberately attach it to the Compose network and route to `portal:8080`, or use the operator's chosen reachable bind. Do not use host networking or expose SQLite/uploads. The application does not modify your proxy, DNS, firewall, or external networks. Its health probe is `GET /healthz` and returns only `ok`.

Disable shared caching for application pages and `/media/`; the app sends `Cache-Control: private, no-store`. Only bundled `/static/` assets are public static files. Configure proxy logs to omit query strings and redact invitation/reset delivery URLs. Do not put tracking or analytics on authentication pages. The application itself does not log request URLs, bodies, token values, or passwords.

## Recovery

An enabled administrator can issue a one-hour single-use reset link from a member's editor. Issuing a replacement invalidates earlier links. Outstanding invitation/reset links can be revoked from Members. Password reset/change invalidates existing sessions.

For the sole administrator, use the local interactive command:

```sh
docker compose run --rm portal admin recover --username OWNER
```

This resets and re-enables an existing administrator, invalidates sessions and reset links, and records a local recovery audit event. It neither creates an external account nor restores revoked portal grants. Local filesystem/container administration is the recovery trust boundary. Password arguments and noninteractive password input are deliberately rejected.

## Back up, restore, and upgrade

Use a consistent backup of the **entire data volume**, including `waypoint.db`, any WAL/SHM files, `csrf.key`, and `uploads/`. The simplest small-instance procedure is a brief stop:

```sh
docker compose stop portal
# Use your container volume backup tool to archive the entire waypoint-data volume.
# In Docker Compose the actual volume name is normally <project>_waypoint-data.
docker compose start portal
```

An exact portable Docker backup/restore procedure is in [operations documentation](docs/operations.md). Do not copy only a live SQLite main file while writes or WAL are active. Protect backups as private account and discussion data. Restore the whole snapshot to an empty data volume while the application is stopped, preserve ownership, run `migrate`, and start. Test restores on an isolated instance.

Before upgrading: back up, stop the app, build the desired revision, run `docker compose run --rm portal migrate`, then `docker compose up -d`. Migrations are versioned and transactional. Startup refuses missing or newer schemas. Do not downgrade a binary against a newer database; restore the matching backup. Use a single application instance per SQLite volume.

## Development and verification

With Go 1.26 or newer installed:

```sh
go mod download
go run ./cmd/waypoint migrate
go run ./cmd/waypoint admin create
go run ./cmd/waypoint serve
make check
make test
make build
```

The default native data directory is `./data` and listen address is `127.0.0.1:8080`. `DATA_DIR`, `LISTEN_ADDR`, `APP_ENV`, `BASE_URL`, and `TRUSTED_PROXIES` configure runtime behavior. No service secrets belong in environment configuration.

Without Go installed:

```sh
docker build --target test .
docker compose --profile test run --rm --build browser-tests
```

The Go test target runs format checks, `go vet`, and `go test -race -count=1 ./...`. Production compilation occurs in the regular image build. Browser tests build a separate fixture binary under the `e2e` build tag, create a temporary database and random password, and exercise invitation → request → discussion → approval → fulfillment → My Access. They never connect to the operator's running portal or use its data. Screenshots/results are written to `test-results/`.

To exercise the production image bootstrap/recovery and restart behavior with disposable Docker resources:

```sh
python3 tests/container-smoke.py
```

For dependency vulnerability analysis:

```sh
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

See [implementation status](docs/implementation-status.md) for checks actually executed, [security](docs/security.md) for trust boundaries, and [roadmap](docs/roadmap.md) for deferred work.


With the optional VPN overlay, friends can use **My Devices → Add device & request connection**, then download a one-time ZIP after administrator approval and gateway confirmation. Import the included `.conf` in WireGuard; no private-key knowledge is needed. Lost packs require replacement and fresh approval. Existing public-key enrollment remains under Advanced. See [VPN setup, migration 3, and delivery-key backup instructions](docs/vpn.md). Keep the new `vpn-delivery` volume persistent and portal-only.
