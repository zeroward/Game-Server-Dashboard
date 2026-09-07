# Optional WireGuard gateway

Waypoint can enroll devices and explicitly approve IPv4 destinations through a dedicated WireGuard gateway. This is an opt-in extension; normal startup remains an unprivileged directory and manual request desk. It does not manage Waygate's gateway, Tailscale, external application accounts, or the host firewall.

## Operator setup

Use a Linux Docker host with kernel WireGuard and nftables support. The gateway uses its own Docker network namespace, drops all capabilities except `NET_ADMIN`, and needs neither host networking nor `/dev/net/tun`, `SYS_MODULE`, privileged mode, or the Docker socket. Its process runs as UID 0 / GID 65532 inside that namespace; the portal stays UID/GID 65532 with no capabilities. Rootless Docker is not supported for this optional gateway. Do not change either container to host networking or share its namespace with the portal.

The first version reserves **10.77.0.0/24**, gateway **10.77.0.1**, interface **wg0**, and egress interface **eth0**. Check for conflicts with the host LAN, other VPNs (including Waygate), Docker networks, and client networks before enabling. These fixed values are deliberately not a general topology editor. One gateway and one portal instance are supported. The pool has 253 lifetime device addresses; revoked addresses and keys are retained and never reassigned, preventing delayed policies from reaching a replacement device. Up to ten non-revoked devices per member are permitted.

Set these values in `.env`:

- `VPN_ENDPOINT`: your actual reachable WireGuard UDP hostname/IP and port, such as `vpn.example.invalid:51820` **only as a nonworking example**. No HTTP scheme. This is separate from `BASE_URL` and from ordinary service links.
- `VPN_BIND_IP`: defaults to `127.0.0.1`. Deliberately choose the host interface that should accept VPN UDP traffic, or keep loopback behind your chosen UDP forwarding arrangement.
- `VPN_UDP_PORT`: host-side UDP port, default 51820. The gateway listens on container port 51820. The endpoint must match your external forwarding configuration.

For an existing portal, back up its volume first and stop it during the schema upgrade:

```sh
docker compose stop portal
docker compose -f compose.yaml -f compose.vpn.yaml build
docker compose -f compose.yaml -f compose.vpn.yaml run --rm --no-deps portal migrate
docker compose -f compose.yaml -f compose.vpn.yaml up -d portal gateway
```

For a new installation, also run the interactive `portal admin create` command after migration. Never use a default password. The overlay initializes private control, gateway, and delivery-key volumes. It publishes only the deliberately configured UDP port in addition to the existing portal port. The application does not configure router forwarding, DNS, HTTPS, host routes, firewall exceptions, or external containers. The gateway's Docker bridge must be able to reach the approved destination addresses through the operator's existing routing. Only attach additional networks deliberately; the supplied topology expects destination traffic to leave `eth0`.

Open **Administration → network access**. The page must show a recent gateway confirmation before enrolling friends. A handshake is not a claim that an external application is configured or healthy.

## Friend and administrator workflow

1. The admin creates a destination associated with a catalog service: a member-visible label, canonical IPv4 CIDR, TCP/UDP protocol, ports/ranges, and enabled state. Use `/32` by default. A broader subnet deliberately allows every matching address within it; port range `1-65535` is an explicit broad exception.
2. In **My Devices**, the friend enters a device name, selects a service, and adds a short reason. **Add device & request connection** generates a unique device key and submits the request together. No key knowledge is needed. Only discoverable offerings are listed; pending requesters cannot see destination IPs/ports.
3. The admin reviews the device, exact destination and ports, checks the explicit confirmation, and chooses an expiry within one year. The expiry means **00:00 UTC at the beginning of that date**. Stale forms after destination edits are rejected.
4. The gateway polls the protected control socket every five seconds, applies the policy, and acknowledges its revision. My Devices offers **Download connection pack** only after a fresh acknowledgment matches the current policy. Refresh the page to see updates; this is not an external connectivity diagnostic.
5. The friend downloads the ZIP once, extracts it, installs the [official WireGuard app](https://www.wireguard.com/install/), and imports its `wp<device-id>.conf` file. The ZIP also includes a short setup guide. Turn on the tunnel and open the approved service. There are no keys to copy, scripts to run, or fields to edit. Delete downloaded ZIP/config files after import; use one pack per physical device.
6. The download is owner-only (admins cannot download another member's pack) and expires 30 days after enrollment. It is consumed transactionally before bytes are sent. Interrupted or lost downloads require **Replace connection pack**: confirm retirement of the old device, choose the service and give a reason. The replacement gets a new identity and **fresh approval**; old permissions are queued for removal at the gateway. Refresh after download to see its consumed state.
7. External services still require their own accounts, setup, and guides. Use the service's Get Help discussion for support; never paste keys or profiles there.

**Advanced: use your own public key** preserves client-generated enrollment for existing users and operators who prefer to keep private keys exclusively on the client. Create an empty tunnel locally, enroll its public key, request a connection, and enter the approved settings under **Set up this device**. Automatic packs are available when the portal has `VPN_DELIVERY_DIR`; the supplied VPN overlay mounts a dedicated volume at `/delivery`. Without it, only the advanced flow is enabled.

A downloaded pack cannot update itself when additional routes are approved. Request a replacement and fresh approval for the desired destination, or use the advanced WireGuard editor with administrator guidance. QR codes and repeat download vaults are not implemented. One-time delivery expires independently of network access: **an expired download does not disable a VPN peer**.

The network request lifecycle is Pending → Approved or Denied, then Approved → Revoked/Expired. Requests and device keys cannot be edited to silently change an approved identity. Revoke the old device and enroll a fresh key for replacement or key rotation. To renew an expired grant, submit a new destination request. Editing a destination affects subsequent approvals only; existing grants retain their approved address/port snapshot. Disabling a destination or unpublishing/archiving its service removes it from the gateway's desired policy. Re-enabling or republishing resumes still-approved, unexpired grants; revoke grants first if resumption is not intended. Disabling a member permanently revokes their devices and network grants; enabling the member again does not restore those devices.

## What the ACL enforces

The server assigns each public key exactly one `/32` tunnel source address. Clients cannot impersonate another device by editing that address. Each firewall grant matches source device, destination IP/CIDR, TCP or UDP, and destination ports. Return traffic requires an established connection and the same currently valid grant. There is no unconditional `ESTABLISHED` bypass after revocation. A shared IP/port behind an HTTP reverse proxy cannot be separated by hostname, URL path, or application account at this layer: enforce those restrictions in that proxy/application, or use distinct network endpoints. Ordinary catalog URLs never become firewall rules automatically.

Traffic from `wg0` to the gateway's own listeners is dropped. Forwarding only permits explicitly approved `wg0` → `eth0` flows and matching returns. Peer-to-peer forwarding, IPv6 forwarding, general Internet exit access, tunnel-subnet destinations, multicast, loopback, and link-local destinations are blocked. `/0` destinations are rejected. Configuring broad other ranges deliberately expands the reachable destinations and needs careful review. IPv6 outer WireGuard endpoints may depend on the operator's Docker UDP publication; this release's supported deployment and tunnel policy are IPv4. ICMP/ping and automatic diagnostic traffic are not permitted. The conservative MTU reduces fragmentation needs; no automated PMTU diagnostic is offered.

DNS is not automatically provided. To use an internal resolver, explicitly approve its IPv4 address on **both UDP and TCP port 53**, then configure that DNS address in the client's WireGuard application. The resolver must independently limit which private names it reveals. Supplying a hostname as a catalog link does not authorize DNS or fetch its addresses. Destination address changes need explicit operator edits and new approvals.

Rules use kernel nftables timed sets in both directions. Once installed, traffic stops at expiry even when the portal is down or the gateway agent has crashed. The agent also removes expired peers from WireGuard on its next local reconciliation. Thus a temporarily retained expired peer may still complete a WireGuard handshake, but cannot forward approved traffic. WireGuard handshakes and application access are separate facts. Kernel timeouts use elapsed time; keep host time synchronized, and avoid changing the clock manually during grants. Reconciliation converts stored UTC expiries into remaining time when rules are installed.

A policy update first installs a deny-all forwarding policy, synchronizes WireGuard peers, then atomically installs the new firewall table. Updates can briefly interrupt traffic; failures leave forwarding blocked once that deny policy is installed. Intent is durably saved before applying, so a received revocation cannot be lost by restarting between operations. During portal/control outages, the gateway retains the last valid policy **until its individual expiries**. New approvals and revocations cannot reach a disconnected gateway. For urgent removal during an outage, the operator must stop the dedicated gateway through their own trusted deployment tooling. Waypoint does not have a host-control or emergency shell feature.

## Control boundary, storage, and recovery

The optional portal listener is a Unix socket on the `vpn-control` volume, with no TCP management port. It accepts only authenticated `GET /v1/policy` and `POST /v1/applied` calls. Authentication uses a cryptographically random 256-bit bearer secret in a mode-0640 file and a mode-0660 socket in a portal-owned directory. The gateway mounts this volume read-only. Never mount it into unrelated containers, a reverse proxy, or a VPN client; possession permits reading/applying acknowledgments for network policy. Host root and the dedicated gateway remain trusted. A compromised portal administrator can approve destinations reachable by this gateway, which is why independent segmentation and application authorization remain necessary.

The protocol contains revision hashes, numeric identifiers, public keys, assigned addresses, and approved rule snapshots/expiries. It carries no usernames, discussion bodies, application credentials, or private keys. The gateway accepts typed bounded fields, rejects overlapping/duplicate peer identities and unsafe input, and never executes a shell or accepts arbitrary commands. Acknowledgments describe applied policy, not independent verification of external permissions. Kernel configuration changes by another privileged operator are outside this agent's ownership model; do not share `wg0` or its nftables table with other managers.

Back up four separate volumes with services stopped: portal data, `vpn-control`, `vpn-gateway`, and `vpn-delivery`. The gateway volume contains the server private key and last approved policy and must be protected as secret material. Use the archive procedure in `operations.md`, retaining ownership and permissions. Migration 2 adds device/network records; migration 3 adds encrypted delivery records and preserves existing users, devices, and grants. Startup refuses a mismatched schema.

Automatic enrollment uses Go's maintained X25519 implementation and AES-256-GCM with random nonces. The database stores only encrypted private bytes while a pack is pending, bound to the owner, device ID, and public key. The mode-0600 encryption key lives at `/delivery/delivery.key` on the **portal-only** `vpn-delivery` volume; the gateway and control protocol never receive client private keys. This separates a database-only backup from its decryption key, not the running portal process from its own key. Protect both volumes and backups; a compromised portal process can decrypt pending packs.

Successful delivery deletes the active ciphertext; expiry, device revocation/replacement, and member disablement also discard it. Database WAL pages and old backups can retain ciphertext, so this is not a claim of forensic erasure. Restore the matching delivery volume to preserve pending packs after restart or recovery. Startup fails closed if the key is missing while encrypted deliveries remain. Restoring old database/key backups can resurrect consumed deliveries: before reconnecting a restored instance, retire devices whose delivery history is uncertain and require fresh enrollment. HTTPS, authenticated sessions, CSRF, and no-store downloads protect delivery in transit; no tokenized download URLs or private keys in HTML, notifications, logs, or gateway requests are used.

Before restoring a portal backup, **stop the gateway**. An older backup could contain approvals that were subsequently revoked. Review and correct restored device/grant records before reconnecting it. Restore the gateway key if clients should retain their configured server public key; generating a new server key requires redistributing its public key to every client. Never start two gateways from the same key/data volume. To rotate the control secret, stop both services, replace the token with 32 cryptographically random bytes encoded as 64 hex characters while preserving mode/ownership, then restart both. Do not print it in logs or put it in URLs.

Disable this extension by stopping/removing the gateway with the VPN overlay **before** returning to the base Compose configuration. Removing a web link or `VPN_ENABLED` alone is not a network revocation: a still-running disconnected gateway retains prior grants until expiry. Keep its volume for history/recovery; never use `down -v` inadvertently.

## Tests

```sh
docker build --target test .
docker compose --profile test run --rm --build browser-tests
docker build -t waypoint:local .
python3 tests/container-smoke.py
python3 tests/container-smoke.py --vpn
docker build -f Dockerfile.gateway -t waypoint-gateway:local .
docker build -f tests/Dockerfile.vpn -t waypoint-vpn-test:local .
python3 tests/vpn-network.py
```

The browser fixture simulates gateway acknowledgments solely for UI tests; the VPN container smoke test uses a real gateway and checks generated-key compatibility with `wg pubkey`, encrypted pack persistence, and one-time delivery. The packet tests create and clean up dedicated Docker networks, containers, and a private volume. Only their containers receive `NET_ADMIN`; they never use host networking or host sysctl/firewall commands. They test actual WireGuard traffic including malicious client routes, source spoofing, TCP/UDP permissions, established-flow revocation, restart, and kernel expiry during agent suspension. The Python tooling is operator-side testing only and is absent from the production gateway image.

Reference: Waygate's [dev agent](https://github.com/zeroward/waygate/blob/dev/internal/wg/agent.go) inspired the separate reconciler. This implementation does not reuse its host networking, shared server-key files, realm-specific ports, or account integration. [WireGuard cryptokey routing](https://www.wireguard.com/#cryptokey-routing) explains source binding; the [nftables manual](https://netfilter.org/projects/nftables/manpage.html) documents timed sets and atomic batch updates.
