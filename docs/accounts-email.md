# Secure accounts and email

Every account, including the first administrator, must enroll a passkey or an authenticator before using Waypoint. Existing sessions are invalidated by the upgrade; existing users enter their password once and complete setup. There is no public signup. Invitations never grant service or network access.

## Sign-in and recovery

Passkeys sign in directly using a device screen lock or security key. Password sign-in requires a six-digit authenticator code if TOTP is enrolled. An account with only passkeys cannot sign in with just its password. Passkeys require HTTPS (localhost is supported for development) and are tied to the configured `BASE_URL` hostname. Use a hostname rather than an IP address for passkeys. Keep that hostname stable. Changing it requires re-enrollment using TOTP, recovery codes, or administrator assistance; changing proxy headers does not change the permitted origin.

Account menu → **Account security** manages authenticators, named passkeys, recovery codes, and email. Security changes require a recent passkey confirmation or password plus authenticator code. A passkey or TOTP must remain enrolled; recovery codes alone do not count as a normal login method.

Save the ten recovery codes when shown. They are displayed once and can be downloaded as a text file. Using one invalidates all existing factors, codes, and sessions and requires replacement enrollment. They are credentials: store them privately. Password-reset links do not remove MFA.

An administrator can open a member record, verify the member’s identity outside Waypoint, and explicitly reset lost login factors. This issues a single-use, one-hour setup link. The old password cannot unlock enrollment until that link is redeemed. Administrators cannot use this interface to reset their own factors.

For a sole administrator locked out, use the local terminal:

```sh
docker compose exec portal /waypoint admin recover --username YOUR_USERNAME
```

Enter the new password twice. Type `RESET` at the additional confirmation to remove lost factors; press Enter to preserve them. Local recovery restores enrollment and invalidates sessions. The operator with database/key-volume or local CLI access is trusted.

## SMTP setup

1. Sign in as an administrator and open **Administration → email**.
2. Enter the provider’s SMTP hostname and sender address, optionally its username/password. Select required STARTTLS (usually port 587) or implicit TLS (usually 465). Certificate verification is always enabled. Unauthenticated TLS relays are supported; plaintext production SMTP is not.
3. Enable delivery and save. Queue a test to an address you control, then refresh the delivery list.
4. Configure the sender domain’s SPF/DKIM/DMARC using your mail provider’s instructions. Waypoint does not modify DNS or operate a mail server.

SMTP passwords are encrypted and never echoed back. Leave the password blank to preserve it or explicitly clear it. Disabling SMTP pauses delivery; the portal remains usable. No SMTP provider credentials ship with the app.

In **Members**, choose **Email invitation** or **Email password reset**. Copy-link delivery remains available without SMTP. Email invitations expire in 48 hours; password resets in one hour. Failed queuing rolls back creation of the invitation/reset token.

Users verify their email separately through **Account security** before receiving update emails. Copied invitations do not prove mailbox ownership. Verification links expire in one hour, require the correct signed-in account and explicit confirmation, and work once. When changing addresses, the old address remains active until the new one is verified. Existing addresses are not automatically marked verified.

Routine request/access/device/admin-queue email notifications can be disabled in Account security. Security-change emails remain enabled for verified addresses. Email messages contain generic text and links to Waypoint, never ticket bodies, private notes, private service destinations, or VPN packs. SMTP providers can see email contents and invitation/reset links; choose a trusted provider.

## Delivery and operations

A transactional SQLite outbox records future notifications and explicit mail actions. No historical inbox items are mailed when SMTP is first enabled. The portal’s worker attempts a message every five seconds, with bounded connection timeouts and up to five attempts using exponential backoff. Admins can retry failed deliveries. Expired or consumed links and ineligible recipients are cancelled before sending.

“Accepted by SMTP server” is the strongest delivery claim available; it does not prove inbox delivery. A crash after SMTP acceptance but before recording success can cause a duplicate after restart. No delivery/read tracking or bounce ingestion is implemented. Delivery records show sanitized errors, not raw SMTP transcripts. Completed/cancelled encrypted message payloads are cleared. Failed pending messages remain encrypted for operator retry.

Compose automatically creates the non-root, portal-only `portal-secrets` volume mounted at `/secrets`. Its `account.key` encrypts TOTP secrets, SMTP credentials, and queued delivery links. It is separate from VPN keys and is not mounted into the gateway or Cloudflare connector. Native runs default to `DATA_DIR/secrets`, configurable with `ACCOUNT_SECRETS_DIR`.

**Back up the database and portal-secrets volume together**, as well as existing uploads/VPN volumes. Stop the portal for a consistent backup or use the documented SQLite backup procedure. Restore the matching key before starting. If encrypted data exists and the key is missing, startup fails rather than generating a replacement. The encryption protects a database-only copy; someone with both database and key can decrypt these fields. There is no automatic key rotation.

The automatic schema migration invalidates old sessions but preserves accounts, service access, requests, and existing VPN state. Startup remains `docker compose up -d --build`. No production email is sent by the automated tests.
