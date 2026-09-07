# Implementation status

Verified locally on 2026-09-07. Implemented features and executed checks are separated from deliberate future work.

## Implemented

- [x] Go/SQLite monolith; transactional initial migration; embedded templates/assets; persistent sessions/uploads/settings.
- [x] Dark responsive artwork catalog; category/tag search; canonical details; exact copy controls; fallbacks and focal points.
- [x] Service/category/link CRUD, publication/archive, ordering, featuring, service and audience previews, setup guides, bounded request forms.
- [x] Explicit global/category/service links; administrator-configured WoW/Plex/Seerr/Status destinations; restricted redirects and artwork.
- [x] Invitation-only accounts, hashed single-use invitations/resets, password change/logout, disablement/session invalidation, last-admin protection, local interactive recovery.
- [x] Server-side discovery/detail/parent/grant rules and time-based expiry; no-store personalized responses.
- [x] Access requests, immutable submitted snapshots, duplicate prevention, legal transitions, public discussions/private notes, transactional manual fulfillment.
- [x] My Requests, My Access, pre-existing access records, version-checked updates/revocation, audit history, external-removal reminders.
- [x] Support lifecycle without grants; scoped scheduled announcements; generic in-app notifications.
- [x] Decoded/re-encoded artwork uploads, sanitized Markdown, URL validation, CSRF, rate limits, safe production cookies.
- [x] Optional My Devices and dedicated WireGuard gateway; automatic one-time configuration packs and advanced client-generated public keys, explicit device/destination approvals, immutable reviewed rules, audit history, notifications, server-enforced TCP/UDP ACLs, expiry and revocation.
- [x] Non-root Docker image, loopback Compose bind, health endpoint, opt-in idempotent demo seed, setup/security/operations/roadmap documentation.

## Verification evidence

- [x] **35 Go tests** passed with `go test -race -count=1 ./...`; `go vet ./...` and formatting checks passed. Tests include invitation/reset expiry and reuse, concurrent redemption, ownership, all audiences, recommendation privacy, direct links, protected uploads/media, scoped search, CSRF/HTTPS origins, snapshots, fulfillment/revocation conflicts, rollback, expiry, notes/notifications, configuration CRUD, schedules, and restart persistence. Added tests cover migration from schema 1, device ownership, hidden offerings, control API authentication, rule validation, disabled-member revocation, expired-grant history, target version conflicts, failed-apply ordering, and offline peer expiry. Pack tests cover owner-only/CSRF delivery, concurrent one-time consumption, ciphertext tampering/context binding, encryption-key restart/recovery failure, migration from schema 2, rollback, replacement with fresh approval, and expired/revoked/hidden offerings.
- [x] `docker build --target test .` passed (format check, vet, and race tests).
- [x] Production Go compilation and `docker build -t waypoint:local .` passed. Runtime user is `65532:65532` with a private data directory; Compose configuration validates.
- [x] **14 Playwright scenarios** passed through `docker compose --profile test run --rm --build browser-tests`. The full invitation → request → discussion → approval → fulfillment → My Access flow is exercised. Axe WCAG A/AA checks passed on login, catalog, service, service editor, request, and mobile catalog. Device enrollment → network request → explicit approval → setup → revocation also passed, with Axe checks for device setup at desktop/mobile and network administration. Automatic enrollment → approval → ZIP download → replacement with fresh approval passed, including desktop/mobile Axe checks. Desktop 1440px and mobile 390px screenshots were inspected; keyboard navigation, clipboard success, and absence of browser JavaScript errors were checked.
- [x] `python3 tests/container-smoke.py` passed using a disposable volume/container: migration and seed idempotence, interactive bootstrap/recovery, non-root read-only runtime, health, login, cache headers, session/database persistence after restart, and recovery invalidation. Temporary containers and volumes are removed by the test.
- [x] Optional gateway production build passed; `compose.vpn.yaml` validates with a nonworking example endpoint. `python3 tests/container-smoke.py --vpn` passed: private control volume/socket authentication, actual gateway acknowledgment, explicitly approved peer installation, device persistence, and control socket reconnection after portal restart, alongside the bootstrap/recovery checks. The pack smoke test additionally verified encrypted pending delivery across restart, one-time ZIP consumption, and key compatibility against the actual gateway using WireGuard’s own public-key derivation.
- [x] Previously, `python3 tests/vpn-network.py` passed **8 real-network checks** in disposable Docker namespaces: per-peer IP/port restrictions despite malicious client AllowedIPs, explicit UDP approval, gateway/peer isolation, source spoof rejection, established-connection revocation, gateway restart, kernel expiry with the agent suspended and portal offline, and subsequent expired-peer removal. No host networking or host firewall commands are used. Packet tests were not rerun for the connection-pack change; gateway/firewall code is unchanged, and the updated real-gateway container smoke test passed.
- [x] Baseline `govulncheck` reported **zero reachable vulnerabilities** using Go 1.26.8 and the pinned dependency set. It also reports advisories for Gorilla CSRF's unused `TrustedOrigins` option (GO-2025-3884) and the unused OpenPGP package within x/crypto (GO-2026-5932). This application configures no TrustedOrigins allowlist and imports no OpenPGP code.

The baseline dependency scan predates the VPN extension; no Go dependencies were added, but that scan was not rerun for the new binary or the gateway OS packages.

Browser screenshots and its scenario report are generated under `test-results/` (ignored by Git and production builds). The browser fixture uses random temporary credentials and a temporary database, never operator data. Backup/restore procedures and HTTPS proxy setup are documented; no production reverse proxy or external service was changed or deployed during verification.

## Deliberately deferred / limitations

- [ ] QR packages, IPv6 tunnel policy, configurable pools/multiple gateways, and Tailscale management. Shipped optional gateway supports IPv4 only, reserves `10.77.0.0/24`, keeps 253 lifetime device addresses, and does not reuse keys/addresses.
- [ ] Repeat downloads, QR import, or automatic updates to previously downloaded packs. Pending delivery expires in 30 days; lost/interrupted downloads need replacement and fresh approval. Ciphertext deletion does not erase old WAL/backups.
- [ ] Immediate revocation while the gateway is disconnected from the portal. The selected outage policy keeps previously applied grants until their individual expiry; the UI shows unconfirmed removal.
- [ ] Host networking/firewall configuration and external application permission changes. Network ACLs apply only within the dedicated gateway.
- [ ] OIDC, outbound notifications, live status APIs, access bundles, calendars/polls/social features, attachments, and integrations with external permission systems.
- [ ] Verification of external entitlements or automated external removal. Admin confirmations are manual assertions.
- [ ] Automatic cleanup of unused artwork files. Unreferenced files remain protected and can be removed during operator maintenance.

Public branding is visible on login; public catalog access is opt-in. External artwork has the documented browser privacy tradeoff. No production deployment or external service changes were performed.
