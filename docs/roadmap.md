# Roadmap

## Shipped WireGuard phase

My Devices, automatic one-time importable connection packs (with advanced client-generated public-key enrollment), explicit per-device network approval, destination/port ACLs, expiry, revocation, and a separate gateway are included in the default Compose stack. See [VPN documentation](vpn.md) and [verification status](implementation-status.md). No general LAN permission follows from membership or manual service-access records.

## Later VPN options

- QR import and optional browser-local key generation, if the additional device/browser support burden is justified. The shipped flow deliberately uses encrypted server generation, owner-only one-time delivery, a 30-day pending window, and fresh approval for replacements. **Expiring a download does not disable an installed VPN peer.** Per-device revocation/expiry remain separately enforced at the secured gateway. Repeat-download vaults are not shipped.
- Configurable address pools with safe allocation/reuse after confirmed removal, multiple gateways, and topology-aware IPv6 policy. The current implementation reserves a fixed IPv4 pool and never reuses historical addresses.
- Automated DNS/service endpoint discovery only after a separate trust and reapproval design; current endpoint rules are explicit IPs, not URL-derived guesses.
- Stronger short renewable leases as an optional outage policy. The chosen release retains approved access until its individual expiry while the portal is unavailable.
- Plain WireGuard peer management is distinct from Tailscale identity, enrollment, tailnet ACLs, key expiry, and device removal. Any Tailscale support needs a separate explicit design and permissions.

## Other possible extensions

- External identity/OIDC using an established provider, with deliberate local account linking and recovery rules. Never reuse WoW GM ranks or database credentials.
- Discord, ntfy, or web-push notifications (SMTP email is implemented) with minimal message content and the same authorization checks.
- Real read-only status integrations, explicitly identified as live and with timestamps/error states. Manual badges remain honest manual records.
- Access bundles with explicit per-service review and external setup responsibilities.
- Game-night calendars, polls, server wish lists, and lightweight social/community features.
- More allowlisted game launch schemes after URI behavior and safety tests.

Shared folders, BookStack, Forgejo, workspaces, Mumble, and PrivateBin already fit the ordinary card/link model. Do not deploy or recreate them inside Waypoint. No speculative plugin system is needed.
