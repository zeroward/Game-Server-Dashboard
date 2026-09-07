# Operations and architecture

## Major choices

The workspace was empty and had no usable Git history or project instructions. Go was selected by the operator. The application is a modular monolith with SQLite and server-rendered templates; browser JavaScript provides copy feedback, previews, and menu behavior. Canonical full-page details avoid modal/history complexity. Built-in abstract artwork keeps the release self-contained and avoids unlicensed game imagery.

SCS provides server-side sessions; Argon2id provides password hashing; Gorilla CSRF protects mutations; Goldmark and Bluemonday render sanitized Markdown. SQL and server policies own authorization. No SPA payload contains raw service records. Templates and static assets are embedded in the Go binary; uploads remain in the persistent volume. Schema migration 1 installs the portal; migration 2 adds optional VPN device/network records and notification references. Migration 3 adds encrypted one-time device deliveries. All are transactional. Run migrate explicitly before upgrading startup. Future schema changes must add a new versioned migration and preserve historical records.

## Routes and contracts

- `/`: permitted catalog; `q`, `category`, and `tag` query parameters filter permitted content only.
- `/services/{slug}`: canonical details and service-aware request forms. `/services/{slug}/open` rechecks a configured direct-card destination.
- `/out/{id}`: authorized configured-link redirect, with no caller-supplied redirect destination.
- `/media/{id}`: authorized image response; `/static/` contains bundled public assets only.
- `/account/login`, `/account/redeem`, `/account/password`, `/account/logout`: local membership operations; mutations are POST plus CSRF.
- `/requests`, `/requests/{id}`, `/my-access`, `/notifications`: owner views, with explicit administrator access to request review.
- `/services/{slug}/requests` accepts bounded access/support form submissions. `/requests/{id}/{reply|note|transition}` accepts owner/admin actions with the displayed request version. No attachments.
- `/admin/{section}` provides configuration and queue forms; all mutations require an enabled administrator and CSRF.
- `/healthz`: minimal unauthenticated process health, with no version/database/service information.

There is no external integration API. Browser and direct HTTP requests go through the same authorization checks.

## State transitions

Access requests: Pending → Needs Information / Approved – Setup Pending / Denied / Cancelled; Needs Information → Pending on a member reply or administrator review, Approved – Setup Pending / Denied / Cancelled; Approved – Setup Pending → Needs Information / Fulfilled / Denied / Cancelled. Fulfilled, Denied, and Cancelled are terminal. Members can reply and cancel their own active requests. Only admins review and fulfill.

Support: Open → Waiting for Member / Resolved / Cancelled; Waiting for Member → Open on member reply or administrator action / Resolved / Cancelled. Resolved and Cancelled are terminal. Resolving does not grant access.

Missing information, denial, and waiting-for-member changes require member-visible explanations. Fulfillment requires a separate external-setup checkbox and non-secret next steps. UTC end dates expire at the start of the following UTC day; all stored timestamps are UTC. Admin announcement times are entered in UTC.

## Exact backup/restore example

The following uses a temporary ordinary container solely as an operator's volume-archive tool. It is not an application capability and does not mount the Docker socket inside a container.

Determine the volume name:

```sh
docker volume ls --filter label=com.docker.compose.volume=waypoint-data
```

Substitute that name for `PROJECT_waypoint-data`. Back up to a private operator directory:

```sh
mkdir -m 700 backups
docker compose stop portal
docker run --rm -v PROJECT_waypoint-data:/data:ro -v "$PWD/backups:/backup" alpine:3.22 tar -czf /backup/waypoint-backup.tar.gz -C /data .
docker compose start portal
chmod 600 backups/waypoint-backup.tar.gz
```

Restore to a **new empty volume**, with the old application stopped:

```sh
docker volume create waypoint-restored
docker run --rm -v waypoint-restored:/data -v "$PWD/backups:/backup:ro" alpine:3.22 tar -xzf /backup/waypoint-backup.tar.gz -C /data
```

Point a separate Compose project at this restored volume, retaining UID/GID 65532 ownership, and run `migrate` before startup. Verify account login, request history, uploaded artwork, and access expiry before substituting it for the original volume. Preserve the original until validation succeeds. Do not restore over a running database or use `docker compose down -v` against data you want to keep.

## Operational limits

Single instance, small group, and SQLite are deliberate. Request queues and catalog filtering use small-dataset queries; this is not designed for thousands of concurrent users. Notifications show the most recent 100 authorized entries; the admin audit view shows the latest 500, with older data retained in SQLite. Access history displays the latest 100 changes. No full-text search server, delivery service, monitoring agent, or external cleanup automation is needed.

Make regular backups and keep the Go toolchain/dependencies updated. Review the status checklist for the latest validation evidence. The browser fixture is built only with the `e2e` tag and is absent from the production image.

## Optional gateway operations

See [VPN deployment and recovery](vpn.md) for the explicit Compose overlay, separate control/key storage, network prerequisites, and outage semantics. Back up all four volumes (portal data, control, gateway, and portal-only delivery key) consistently and stop the gateway before restoring an old portal database so revoked grants cannot be resurrected. Default Compose remains a single unprivileged application; the gateway is never started implicitly.
