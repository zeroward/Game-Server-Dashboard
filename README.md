# Waypoint

A self-hosted library of services and a small request desk for friends. Discover a game or app, request access where needed, discuss setup, and find your next steps. External accounts, media requests, and monitoring stay in their existing applications. An optional dedicated WireGuard gateway adds explicitly approved device network access.

Built in Go with SQLite, server-rendered HTML, and lightweight JavaScript. The default Docker stack includes the portal, a dedicated WireGuard gateway, and a Cloudflare Tunnel connector. Node/Playwright are used only for isolated browser tests.

## Start

1. For a new installation, copy `.env.example` to `.env`. For an existing installation, keep your file and add any missing required settings.
2. Set `TUNNEL_HOSTNAME` to the website hostname and `VPN_ENDPOINT` to the separately reachable WireGuard host and UDP port. Preserve any existing port override.
3. Follow [Cloudflare setup](docs/tunnel.md) to create the token file and point the public hostname to `http://portal:8080`. Review the gateway [network prerequisites](docs/vpn.md).
4. Start the full stack:

```sh
docker compose up -d --build
```

The portal initializes an empty database and applies pending migrations on every startup, before serving requests. Sidecars wait for portal health. You do not need a separate migration command.

For a fresh installation only, create your administrator:

```sh
docker compose exec portal /waypoint admin create
```

Bootstrap prompts for a username and password of at least 12 characters. There are no default credentials or unauthenticated setup endpoints. Existing installations retain their administrator. Then visit **https://your-configured-hostname**.

There are no overlay files to select. Keep the same Compose project/directory so the existing `waypoint-data`, `vpn-control`, `vpn-gateway`, and `vpn-delivery` volumes are retained. When updating an older checkout, drop the old `-f` arguments. The current configuration has no portal host-port mapping; HTTPS access goes through Cloudflare.

Only the gateway receives container-scoped `NET_ADMIN`. The portal and connector run as UID/GID **65532** with no capabilities and read-only root filesystems. No service receives the Docker socket, host networking, or privileged mode.

Optional example cards, without accounts, grants, or real destinations:

```sh
docker compose exec portal /waypoint seed-demo
```

The seed is explicit and idempotent. It never replaces existing settings or runs automatically.

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

The default stack derives HTTPS branding/links and Secure cookies from `TUNNEL_HOSTNAME`, trusts only the connector's static IP for forwarded client addresses, and publishes no portal web port. See [tunnel setup and verification](docs/tunnel.md).

Native development can still run the portal alone. Runtime `APP_ENV`, `BASE_URL`, and `TRUSTED_PROXIES` configure a separately managed proxy deployment; the supplied Compose file intentionally fixes production settings. Preserve the original Host and trust only your proxy's source CIDRs. Forwarded identity headers never authenticate users.

The health endpoint is `GET /healthz`; it returns only `ok` after startup migrations finish. Disable shared caching for application pages, media, and connection-pack downloads. Only bundled static assets may be publicly cached. Never log request bodies, cookies, token values, or private configurations.

## Recovery

An enabled administrator can issue a one-hour single-use reset link from a member's editor. Issuing a replacement invalidates earlier links. Outstanding invitation/reset links can be revoked from Members. Password reset/change invalidates existing sessions.

For the sole administrator, use the local interactive command:

```sh
docker compose exec portal /waypoint admin recover --username OWNER
```

This resets and re-enables an existing administrator, invalidates sessions and reset links, and records a local recovery audit event. It neither creates an external account nor restores revoked portal grants. Local filesystem/container administration is the recovery trust boundary. Password arguments and noninteractive password input are deliberately rejected.

## Back up, restore, and upgrade

Use a consistent backup of all four volumes. The **entire portal data volume** includes `waypoint.db`, any WAL/SHM files, `csrf.key`, and `uploads/`. The simplest small-instance procedure is a brief stop:

```sh
docker compose stop
# Archive waypoint-data, vpn-control, vpn-gateway, and vpn-delivery.
# Actual volume names normally start with <project>_.
docker compose up -d
```

An exact portable Docker backup/restore procedure is in [operations documentation](docs/operations.md). Do not copy only a live SQLite main file while writes or WAL are active. Protect backups as private account and discussion data. Restore the whole snapshot to an empty data volume while the application is stopped, preserve ownership, and start; startup applies any pending migrations. Test restores on an isolated instance.

Before upgrading, back up all four volumes consistently, then run `docker compose up -d --build`. Startup applies versioned migrations under a SQLite write lock. Failures roll back schema and ledger together and leave the portal unhealthy; unsupported newer schemas are refused. The explicit `migrate` command remains available for maintenance. Do not downgrade a binary against a newer database; restore the matching backup. Use a single application instance per SQLite volume.

## Development and verification

With Go 1.26 or newer installed:

```sh
go mod download
go run ./cmd/waypoint serve
# In another terminal after startup:
go run ./cmd/waypoint admin create
make check
make test
make build
```

The default native data directory is `./data` and listen address is `127.0.0.1:8080`. `DATA_DIR`, `LISTEN_ADDR`, `APP_ENV`, `BASE_URL`, and `TRUSTED_PROXIES` configure runtime behavior. No service secrets belong in environment configuration.

Without Go installed:

```sh
docker build --target test .
docker compose --env-file tests/compose.env --profile test run --rm --no-deps --build browser-tests
```

The Go test target runs format checks, `go vet`, and `go test -race -count=1 ./...`. Production compilation occurs in the regular image build. Browser tests build a separate fixture binary under the `e2e` build tag, create a temporary database and random password, and exercise invitation → request → discussion → approval → fulfillment → My Access. They never connect to the operator's running portal or use its data. Screenshots/results are written to `test-results/`.

To exercise the production image bootstrap/recovery and restart behavior with disposable Docker resources:

```sh
python3 tests/container-smoke.py --vpn
python3 tests/startup-smoke.py
python3 tests/tunnel-smoke.py
```

For dependency vulnerability analysis:

```sh
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

See [implementation status](docs/implementation-status.md) for checks actually executed, [security](docs/security.md) for trust boundaries, and [roadmap](docs/roadmap.md) for deferred work.


Friends can use **My Devices → Add device & request connection**, then download a one-time ZIP after administrator approval and gateway confirmation. Import the included `.conf` in WireGuard; no private-key knowledge is needed. Lost packs require replacement and fresh approval. Existing public-key enrollment remains under Advanced. See [VPN setup and delivery-key backup instructions](docs/vpn.md). Keep the new `vpn-delivery` volume persistent and portal-only.

### Secure login and email

Every account must set up a passkey or an authenticator on its next login. Existing sessions are signed out by the upgrade. Save the recovery codes shown during enrollment.

Configure SMTP in **Administration → email**, then use **Email invitation** in Members. SMTP is optional and disabled until configured; copied invitation links still work. Users verify their email in **Account security** to receive notifications.

Back up the new **portal-secrets** volume alongside your database. See [secure accounts and email](docs/accounts-email.md) for setup, recovery, delivery behavior, and hostname requirements.
