# Security and trust boundaries

**Hiding a link does not secure its destination.** Every external application and gateway/firewall must enforce its own access rules. A member invitation, manual service request approval, or active portal record never changes LAN reachability or external permissions. Explicit device-network approval in the separate gateway is a separate operation.

Waypoint does not connect to AzerothCore databases, Waygate sessions, Plex/Seerr APIs, monitoring APIs, Docker sockets, identity providers, or external admin networks. It links to administrator-configured destinations. HTTP/HTTPS internal hostnames are intentional and are never fetched for previews, icons, metadata, or health checks.

## Authorization

- Every request resolves an enabled local account and session generation. Disabling, recovery, password changes, and role changes invalidate old generations. The last enabled administrator is protected in a database transaction.
- Discovery requires publication, non-archive status, category permission, and service discovery audience. Public browsing requires both the global opt-in and public content. Administrators have explicit administrative visibility.
- Connection/setup details use a separate audience. An access audience checks an active record whose expiry is still in the future and whose user is enabled, at request time. A periodic reconciliation task creates expiry audit events and follow-ups but never determines whether access is usable.
- Link visibility intersects its audience, parent category/service rules, and any associated service's discovery rules. Direct-link and outbound routes repeat these checks. Hidden content returns 404; member attempts to use administration return 403.
- View models are filtered before rendering. Search does not search restricted connection/setup text. Private notes have separate tables and queries and are not available through member request views or notifications.
- Historical requests preserve their original service label and submitted field snapshot. Unpublished/archived services do not expose current details or destinations through history. Access records retain the name at recording time.
- Protected artwork is outside the static directory and is served through the same discovery policy. Existing downloads cannot be recalled from a browser, but every later request rechecks permissions. Personalized HTML and artwork responses use no-store caching.

## Accounts and browser protections

Passwords use the maintained Argon2id library with random salts. Session management uses SCS and database storage. Session identifiers are opaque; authorization is never stored in an external application account. Sessions expire after seven days with a one-day idle timeout. Logout deletes the server-side session. Token renewal happens at login.

Invitation and recovery secrets use 256 bits from Go's cryptographic random source. Only their SHA-256 hashes are stored. Invitations expire in 48 hours; reset links in one hour. Redemption is transactional and single-use, cannot promote a member, and does not create service grants. Admins may see a newly issued delivery link once. Query strings are removed from the visible redemption URL by progressive enhancement; the form also works without JavaScript. Use private delivery and proxy log redaction.

Gorilla CSRF middleware protects all mutations, including login, logout, account redemption, and multipart upload. There are no GET state-changing endpoints. Secure cookies require production HTTPS. CSP forbids remote scripts, frames, executable objects, and inline scripts; inline styles support configured focal points/accent colors. Images may use explicit remote HTTP/HTTPS artwork URLs. Cross-origin referrers are suppressed; same-origin referrers preserve browser form-origin checks. No arbitrary `next` redirect parameter is accepted.

Authentication limits are stored in SQLite (20 attempts per source IP per 15 minutes). Request submissions allow 10 per member per hour; request updates allow 60 per member per hour. Logout remains available regardless of authentication throttling. Proxy client addresses are used only when the socket peer belongs to configured trusted CIDRs. Unknown forwarded identity headers are ignored.

## Input and storage

SQL uses bound parameters. Request transitions and fulfillment run in transactions and use expected-version checks. A partial unique index prevents active duplicate access requests. Access updates also check the displayed version; conflicting actions require reload. Support resolution never invokes access granting.

Markdown is rendered with raw HTML disabled and then sanitized. Description/guide images are removed; artwork must use the explicit image setting. URLs must be absolute HTTP/HTTPS without credentials/control characters. Only explicit `steam://` service actions with the game icon may use a game-launch scheme. No executable icon markup or ticket attachments are accepted.

Artwork validation checks format, byte limit (8 MiB), dimensions (20 megapixels), and full decoding before JPEG re-encoding. Supported sources are JPEG, PNG, and WebP; SVG/HTML uploads are rejected. Filenames are generated, metadata is discarded, and storage paths are never derived from user filenames. The bundled grain SVG is application-authored static artwork, not an upload. Deleted/replaced image files may remain as inaccessible orphans until an operator removes them during maintenance; they are never served without a matching authorized media record.

The SQLite database and backups contain personal contact information, password hashes, discussions, and session state; protect them with host filesystem controls and encrypted backups where appropriate. The application does not encrypt SQLite at rest. Do not use replies, notes, next steps, or announcements to distribute passwords, keys, or VPN configurations.

## Manual access and external removal

Approval means review is complete and setup is still pending. Fulfillment requires the administrator to attest to external setup and supply non-secret next steps. The portal cannot verify that assertion.

Revocation, expiry, and disablement stop restricted portal content immediately. They create follow-ups for separate external removal. Recording a follow-up complete is an administrator assertion, not automated verification. Re-enabling a member does not restore revoked records. A regrant does not silently dismiss an outstanding external-removal reminder; an administrator must reconcile it deliberately.

No production deployment, host DNS/firewall changes, external entitlement synchronization, or host networking is included. The dedicated WireGuard gateway manages only its own container network namespace. Read [the VPN trust boundary](vpn.md) before enabling it.

## Device-network approval

My Devices and network administration use the same enabled sessions, CSRF protection, no-store responses, and ownership checks as the portal. Changes are rate-limited to 40 per member per 15 minutes. Unique keys/addresses and a partial unique request index prevent concurrent duplicate enrollment/requests. Grants snapshot their reviewed destination and use expected versions for both request and target. Gateway policy excludes disabled users, revoked devices, expired grants, disabled targets, and unpublished/archived services. Destination permissions are separate from catalog visibility and manual access records. Expiry is enforced by timed kernel firewall sets even if the agent stops. Offline gateway revocations remain pending rather than being presented as completed.

The control API is available only over an authenticated Unix socket; it is not part of the browser HTTP listener and does not accept cookie or forwarded-header identity. It is intentionally outside browser CSRF middleware because it requires a volume-protected random bearer credential. The gateway never mounts the portal database, and the portal never mounts gateway private keys. Advanced enrollment retains private keys exclusively on the client. Automatic enrollment prepares one-time packs using a portal-only encryption key volume; see below. Raw command execution, uploaded profiles, general file access, external-account provisioning, and Tailscale management are not exposed.


## One-time device connection packs

Automatic enrollment atomically creates a unique X25519 device identity, encrypted pending delivery, and Pending connection request. Approval is still deliberate. Download requires the owner’s enabled current session, CSRF-protected POST, unexpired delivery, active approved peer/rules, visible service/category, and a fresh acknowledgment matching the gateway policy. Administrators cannot download another member’s pack. Download attempts are limited to ten per member per fifteen minutes.

Private bytes are AES-256-GCM encrypted with authenticated owner/device/public-key context and random nonces. The separate mode-0600 key is on the portal-only delivery volume, never the gateway or control volume. This protects a database-only exposure; the running portal and host remain trusted. The binary uses Go standard cryptographic libraries, not custom cryptographic primitives. Packs contain only a configuration and plain-text instructions, with safe generated filenames and no executable hooks.

Delivery generation/consumption is transactional: exactly one concurrent download receives bytes, and failed configuration validation preserves the pending delivery. Ciphertext is removed before sending, so an interrupted download cannot be resumed. Replacement requires confirmation, retires the old identity, and requests fresh approval; it never inherits network grants. Encrypted pending material expires after 30 days; expiry/revocation/disablement prevent delivery immediately, independently of cleanup. Deleted ciphertext may remain in WAL/backups. Protect backups and delivery keys; restore them consistently, and retire uncertain device deliveries before reopening a restored instance. An expiring download is not peer revocation.

Use HTTPS for remote delivery and disable shared caching/body logging at the proxy. No private bytes enter server-rendered HTML, sessions, notifications, audit targets, URLs, control messages, or plaintext storage. Downloaded files are credentials: friends should import them on one device and then remove the ZIP and extracted files. Do not submit them in support discussions. QR codes and repeat-download storage are deferred.

## Cloudflare Tunnel boundary

The default Compose stack runs a pinned non-root connector with no capabilities, a read-only root filesystem, and only its token-file mount. It shares a dedicated bridge with the portal; the portal trusts only its static /32 for forwarded client IPs. Compose forces production HTTPS cookies and removes the application host port. No forwarded identity headers become portal authentication. Cloudflare terminates HTTPS and can process portal content, including private VPN pack downloads. Keep token files, logs and the connector isolated, bypass shared caching, and preserve the original Host. See [setup and operational checks](tunnel.md).

## Automatic startup migrations

The portal opens no HTTP listener or control socket until pending migrations commit. The migration ledger is read after acquiring a SQLite write lock; schema and ledger changes roll back together on failure. Newer unsupported schemas are refused. Back up before upgrading, and restore a matching backup before downgrading. Bootstrap stays interactive and local; initialization never seeds demo users or grants.
