# Optional Cloudflare Tunnel

`compose.tunnel.yaml` adds a pinned, non-root `cloudflared` connector to the existing Compose project. It exposes the **Waypoint website** through your Cloudflare hostname using outbound connections. The overlay removes the portal's host-port mapping. Base Compose remains unchanged when the overlay is omitted.

The tunnel does not carry native WireGuard UDP traffic, publish every catalog destination, configure external accounts, or grant LAN access. Keep `VPN_ENDPOINT` and its UDP forwarding separate. Friends still use Waypoint invitations and approvals. This optional mode requires your own Cloudflare account and domain; local operation does not.

## Configure

Use Docker Compose **2.24.4 or later** (the overlay clears inherited ports with `!reset`). Keep the existing project directory/name to retain your database and VPN volumes. Back up before changing deployment configuration. The tunnel itself introduces no database migration.

1. In Cloudflare's dashboard, create a **remotely managed Cloudflare Tunnel** using the `cloudflared` connector.
2. Add a published application route for your hostname, pointing to **HTTP → `portal:8080`**. Use the hostname root, not a path prefix. Preserve the original Host header: leave HTTP Host Header override empty, or set it to that same public hostname. Do not use `localhost:8080`, which refers to the connector itself.
3. Add to your existing `.env`:

   ```dotenv
   TUNNEL_HOSTNAME=portal.your-domain.example
   TUNNEL_TOKEN_FILE=./secrets/cloudflare-token
   ```

   Replace the example with your real hostname, without `https://`, a port, or a path. The overlay forces production mode, derives an HTTPS `BASE_URL`, and trusts only the connector's exact Docker IP. Development `.env` values cannot turn off Secure cookies in this mode.
4. Save **only the tunnel token value**, not the Docker install command, in the ignored token file. For a normal rootful Linux Docker host:

   ```sh
   install -d -m 700 secrets
   install -m 600 /dev/null secrets/cloudflare-token
   nano secrets/cloudflare-token
   sudo chown 65532:65532 secrets/cloudflare-token
   ```

   Run `install` only when creating the file; it would truncate an existing token. Paste in the editor, save and close it before changing ownership. The read-only mount requires an existing file readable by UID 65532. The connector receives neither the database nor VPN/control/key volumes. Do not put tokens in `.env`, shell arguments, tickets, or source control. The secrets directory is excluded from Git and Docker builds. On SELinux hosts the dedicated bind file receives a private `Z` label. Rootless/user-remapped Docker requires file ownership matching your UID mapping.

The dedicated bridge defaults to `172.30.250.0/29`, connector `.2`, portal `.3`. Check for overlap with your LAN, VPN and Docker networks. If needed, change all three `.env` settings together: `TUNNEL_SUBNET`, `TUNNEL_CONNECTOR_IP`, and `TUNNEL_PORTAL_IP`. Only portal and cloudflared should join this bridge. The VPN gateway remains on its separate bridge and communicates over the protected control socket.

## Start

For an existing installation with VPN enabled:

```sh
docker compose -f compose.yaml -f compose.vpn.yaml -f compose.tunnel.yaml config -q
docker compose -f compose.yaml -f compose.vpn.yaml -f compose.tunnel.yaml up -d portal gateway cloudflared
```

Without VPN:

```sh
docker compose -f compose.yaml -f compose.tunnel.yaml config -q
docker compose -f compose.yaml -f compose.tunnel.yaml up -d portal cloudflared
```

For a fresh installation, build the portal, run `portal migrate`, and run interactive `portal admin create` with those same Compose flags before `up`. Existing installations retain their administrator and database. If upgrading from a pre-migration-3 binary, follow the usual backup/build/migration instructions first.

Visit **https://your-configured-hostname**. Local `http://localhost:8080` is unavailable with this overlay. Configure Cloudflare to redirect HTTP visitors to HTTPS. Bypass Cloudflare caching for this application's hostname, especially authentication, requests, notifications, media, and `/my-devices/*/pack`. Keep authentication pages free of injected analytics.

Cloudflare terminates browser HTTPS and is therefore a trusted processor of portal pages and downloaded VPN configurations. The connector-to-portal hop is HTTP confined to the same Docker bridge. The connector needs outbound DNS and Cloudflare connectivity on port 7844 over UDP or TCP. It opens no inbound web ports and changes no host firewall rules. Address any blocking egress policy outside Waypoint. Default transport can fall back from QUIC to HTTP/2. Avoid debug logging: it can include request headers and URLs.

## Verify and maintain

```sh
docker compose -f compose.yaml -f compose.vpn.yaml -f compose.tunnel.yaml ps
docker compose -f compose.yaml -f compose.vpn.yaml -f compose.tunnel.yaml logs --tail=50 cloudflared
```

Omit the VPN file when not using it. Connector health uses its private readiness endpoint, which succeeds only when connected to Cloudflare. It does not verify public DNS or application login. If the portal is unhealthy, check migrations and the hostname; for unreadable/invalid token errors, check file contents, ownership and permissions. A 502 commonly indicates an incorrect origin route; CSRF failures can indicate an incorrect Host override or visiting another hostname.

After activation, verify the real HTTPS hostname, invitation redemption, login/logout, a private page, and a connection-pack download. Confirm the portal has no host-port mapping. These real account/DNS checks cannot be performed with the offline test.

To rotate the token, obtain a replacement in Cloudflare, update the protected file with `sudoedit secrets/cloudflare-token`, and recreate only cloudflared with the same Compose flags. Rotate compromised tokens in Cloudflare, not merely in the local file. Upgrade the pinned image/tag and digest deliberately. Back up the token securely or plan to issue a new one; it is separate from portal data and the VPN delivery key.

To return to loopback access, first stop and remove cloudflared using the same Compose files. Recreate portal with only the base and optional VPN files. Merely omitting the overlay does not stop an existing connector. Do not use `down -v` on operator data.

## Tests

```sh
docker build --target test .
docker compose --profile test build browser-tests
python3 tests/tunnel-smoke.py
```

The smoke test uses a temporary project with an **internal, outbound-blocked network** and a random nonworking token. It validates base/tunnel/VPN merges, isolated mounts, absent web ports, actual non-root connector startup, honest offline readiness, Docker origin-name resolution, Secure cookies, and no-store headers. It removes only its own temporary resources. Go regression tests cover HTTPS → HTTP proxy login/logout/CSRF and exact proxy-IP trust. No Cloudflare account, DNS or real token is used.

References: [Cloudflare setup](https://developers.cloudflare.com/tunnel/setup/), [token-file and logging flags](https://developers.cloudflare.com/tunnel/advanced/run-parameters/), [origin Host settings](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/), [Compose merge/reset rules](https://docs.docker.com/reference/compose-file/merge/).
