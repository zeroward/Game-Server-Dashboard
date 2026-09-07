# Cloudflare Tunnel

The default `compose.yaml` runs the portal, WireGuard gateway, and pinned non-root Cloudflare connector together. Start the configured stack with `docker compose up -d --build`. No portal host port is published.
The tunnel does not carry native WireGuard UDP traffic, publish every catalog destination, configure external accounts, or grant LAN access. Keep `VPN_ENDPOINT` and its UDP forwarding separate. Friends still use Waypoint invitations and approvals. The default stack requires your Cloudflare account and domain. Native development can run the portal alone.

## Configure

Use a current Docker Compose v2 or newer. Keep the existing project directory/name to retain your database and VPN volumes. Back up before changing deployment configuration. Startup initializes the database and applies pending migrations automatically.

1. In Cloudflare's dashboard, create a **remotely managed Cloudflare Tunnel** using the `cloudflared` connector.
2. Add a published application route for your hostname, pointing to **HTTP → `portal:8080`**. Use the hostname root, not a path prefix. Preserve the original Host header: leave HTTP Host Header override empty, or set it to that same public hostname. Do not use `localhost:8080`, which refers to the connector itself.
3. Add to your existing `.env`:

   ```dotenv
   TUNNEL_HOSTNAME=portal.your-domain.example
   TUNNEL_TOKEN_FILE=./secrets/cloudflare-token
   ```

   Replace the example with your real hostname, without `https://`, a port, or a path. Compose forces production mode, derives an HTTPS `BASE_URL`, and trusts only the connector's exact Docker IP. Development `.env` values cannot turn off Secure cookies in the full-stack deployment.
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

```sh
docker compose config -q
docker compose up -d --build
```

For a fresh installation only, run `docker compose exec portal /waypoint admin create` after startup. Existing installations retain their administrator and database. Migrations run automatically before portal health becomes available. New sidecars wait for that health check.

Visit **https://your-configured-hostname**. Local `http://localhost:8080` is unavailable in the default stack. Configure Cloudflare to redirect HTTP visitors to HTTPS. Bypass Cloudflare caching for this application's hostname, especially authentication, requests, notifications, media, and `/my-devices/*/pack`. Keep authentication pages free of injected analytics.

Cloudflare terminates browser HTTPS and is therefore a trusted processor of portal pages and downloaded VPN configurations. The connector-to-portal hop is HTTP confined to the same Docker bridge. The connector needs outbound DNS and Cloudflare connectivity on port 7844 over UDP or TCP. It opens no inbound web ports and changes no host firewall rules. Address any blocking egress policy outside Waypoint. Default transport can fall back from QUIC to HTTP/2. Avoid debug logging: it can include request headers and URLs.

## Verify and maintain

```sh
docker compose ps
docker compose logs --tail=50 cloudflared
```

Connector health uses its private readiness endpoint, which succeeds only when connected to Cloudflare. It does not verify public DNS or application login. If the portal is unhealthy, check migrations and the hostname; for unreadable/invalid token errors, check file contents, ownership and permissions. A 502 commonly indicates an incorrect origin route; CSRF failures can indicate an incorrect Host override or visiting another hostname.

After activation, verify the real HTTPS hostname, invitation redemption, login/logout, a private page, and a connection-pack download. Confirm the portal has no host-port mapping. These real account/DNS checks cannot be performed with the offline test.

To rotate the token, obtain a replacement in Cloudflare, update the protected file with `sudoedit secrets/cloudflare-token`, and recreate only cloudflared with Compose. Rotate compromised tokens in Cloudflare, not merely in the local file. Upgrade the pinned image/tag and digest deliberately. Back up the token securely or plan to issue a new one; it is separate from portal data and the VPN delivery key.

To stop external website access, stop cloudflared explicitly with `docker compose stop cloudflared`. Changing a URL or removing configuration does not stop a running connector. Native development remains available for a local portal-only process. Do not use `down -v` on operator data.

## Tests

```sh
docker build --target test .
docker compose --env-file tests/compose.env --profile test build browser-tests
python3 tests/tunnel-smoke.py
```

The smoke test uses a temporary project with an **internal, outbound-blocked network** and a random nonworking token. It validates full-stack service and volume configuration, isolated mounts, absent web ports, actual non-root connector startup, honest offline readiness, fresh-volume automatic initialization, Docker origin-name resolution, Secure cookies, and no-store headers. It removes only its own temporary resources. The configured stack includes the real gateway, while Cloudflare egress remains blocked. Go regression tests cover HTTPS → HTTP proxy login/logout/CSRF and exact proxy-IP trust. No Cloudflare account, DNS or real token is used.

References: [Cloudflare setup](https://developers.cloudflare.com/tunnel/setup/), [token-file and logging flags](https://developers.cloudflare.com/tunnel/advanced/run-parameters/), [origin Host settings](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/), [Compose merge/reset rules](https://docs.docker.com/reference/compose-file/merge/).
