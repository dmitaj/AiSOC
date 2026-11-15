---
sidebar_position: 7
title: Microsoft 365 Audit
description: Tenant-wide Microsoft 365 audit events (Exchange, SharePoint, Teams, OneDrive, Azure AD) via the Office 365 Management Activity API.
---

# Microsoft 365 Audit

The M365 connector pulls **unified audit log events** from the Office 365 Management Activity API. This includes Exchange Online mailbox audit, SharePoint and OneDrive file activity, Teams chat and meeting events, Power Platform actions, and Azure AD sign-ins.

## What you get

| Content type | Examples |
|---|---|
| `Audit.Exchange` | Mailbox login, mail rule create, send-as |
| `Audit.SharePoint` | File access, sharing-link create, anonymous-link |
| `Audit.AzureActiveDirectory` | User sign-in, MFA disable, app consent |
| `Audit.General` | Teams meeting events, DLP matches, eDiscovery |
| `DLP.All` | Data loss prevention rule matches |

The connector subscribes to all five content types. Events are normalized with `source: m365` and `category` derived from the workload.

## Prerequisites

You can **reuse the Azure AD app from the [Entra connector](/docs/connectors/azure-entra)** — they share an auth model. If you do, just add the extra application permission below.

If creating fresh:

- An **Azure AD app registration** (App registration in Entra ID).
- A **client secret**.
- The application permission **`ActivityFeed.Read`** (and **`ActivityFeed.ReadDlp`** if you want DLP events) on the **Office 365 Management APIs** resource (not on Microsoft Graph).
- **Admin consent** granted on those permissions.
- Audit logging **must be enabled** in the tenant (`Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true`).

## Setup walkthrough

### 1. Add Management API permission

1. **Entra admin → App registrations → your app → API permissions**.
2. **Add a permission → Office 365 Management APIs → Application permissions**.
3. Select `ActivityFeed.Read` (and `ActivityFeed.ReadDlp` if needed).
4. Click **Grant admin consent for &lt;tenant&gt;**.

### 2. Confirm unified audit log is on

In a PowerShell session connected to Exchange Online:

```powershell
Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled
```

If `False`, run:

```powershell
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
```

### 3. Add the connector in AiSOC

1. **Connectors → Add connector → Microsoft 365 Audit**.
2. `tenant_id`, `client_id`, `client_secret` = same values as the Entra connector (or freshly minted).
3. **Test connection** → starts a subscription on `Audit.General` and immediately stops it; this is the cheapest verification call.
4. **Save**.

## Certificate authentication (recommended)

Instead of a client secret you can authenticate the app with a certificate. The private key never leaves AiSOC: it signs a short-lived assertion, and only that assertion is sent to Microsoft.

1. Create a self-signed certificate and key:

   ```bash
   openssl req -x509 -newkey rsa:2048 -sha256 -days 730 -nodes -subj "/CN=AiSOC M365 Audit Connector" -keyout aisoc.key -out aisoc.crt
   ```

2. In the Entra portal open **App registrations → your app → Certificates & secrets → Certificates → Upload certificate** and upload `aisoc.crt` (a `.cer`/`.crt`/`.pem` public certificate). Copy the **Thumbprint** shown next to it.
3. In AiSOC paste `cat aisoc.key aisoc.crt` into **Certificate PEM (private key)** (the PEM must contain the `PRIVATE KEY` block; including the `CERTIFICATE` block too lets AiSOC derive the thumbprint itself). If you omit the certificate block, fill **Certificate Thumbprint**. Leave **Client Secret** empty. If the key is encrypted, set **Private Key Password**.

Exactly one of secret or certificate must be configured; if both are set, the certificate is used. The key must be RSA. Existing secret-based instances keep working unchanged.

### Let AiSOC generate the certificate (auto-rotated)

Instead of running `openssl` yourself, click **Generate certificate** under **Certificate PEM (private key)** (in the add wizard, the edit dialog, or the OAuth panel's **Certificate** mode). AiSOC creates an RSA-2048 key and a self-signed SHA-256 certificate valid for 730 days. The private key stays in AiSOC, vault-encrypted; the console only receives the public certificate and shows its thumbprint, expiry and a **Download .cer** button.

1. Fill in **Tenant ID** (the OAuth panel asks for it next to the button) and, optionally, the app's **Application object ID** from its **Overview** page.
2. Click **Generate certificate**, then **Download .cer**.
3. Upload it in Entra admin center → **App registrations → your app → Certificates & secrets → Certificates**.
4. **Test connection** and **Save** as usual. Until you save, the generated key is held for 24 hours under a one-time id; an abandoned one simply expires. Pasting your own PEM remains available and is unaffected.

`GET /api/v1/connectors/{id}/certificate.cer` (or `GET /api/v1/oauth/app/{connector_type}/certificate.cer` for the OAuth app) downloads the current public certificate again. No endpoint ever returns the key.

**Auto-rotation.** Once a day the api service checks every certificate AiSOC generated; one that expires in less than **30 days** is rolled over through Microsoft Graph: AiSOC requests an app-only token with the current certificate, calls [`addKey`](https://learn.microsoft.com/graph/api/application-addkey) with a new certificate and a proof-of-possession token signed by the current key, confirms the new certificate can obtain a token (retrying for a few minutes while Entra replicates), switches to it, and then calls `removeKey` for the old certificate with a proof signed by the new key. An application needs no Graph permission to roll its own keys. The proof names the app by its **object id**: give it when generating, or AiSOC looks it up with `GET /applications(appId=…)`, which needs `Application.Read.All` (or `Directory.Read.All`). For the very first certificate you uploaded by hand, AiSOC can find its key id only through that same read; without it the old certificate is left in place and the connector card says so — delete it in the portal when convenient. Each successful rotation is written to the audit log (`connectors:certificate_rotate`).

If a rotation fails before the switch, AiSOC keeps the old certificate, shows the error on the connector card ("Last auto-rotation failed: …"), writes a `connectors:certificate_rotation_failed` audit entry and an `ms_cert_rotation.alarm` error log line, marks the connector unhealthy once fewer than 7 days remain, and retries the next day. The connector card and edit dialog show **Certificate expires YYYY-MM-DD · auto-rotates**; a pasted certificate shows **expires YYYY-MM-DD — rotate manually** and is never touched.

`addKey` can only be authorised by a certificate that is still valid. If every certificate on the app has expired (for example the api service was down for the whole 30-day window), AiSOC cannot recover on its own: generate a new certificate, upload the `.cer` manually and save.

### One-click OAuth with a certificate

The console's **Connect with Microsoft 365 Audit via OAuth** panel can use the same certificate. Under **Register OAuth app**, switch **Client secret | Certificate** to **Certificate**, enter the app's **Client ID**, and paste the PEM (private key, ideally followed by the certificate). The thumbprint field is only needed when the PEM has no `CERTIFICATE` block, and the password field only when the key is encrypted; the key is re-stored unencrypted inside the credential vault, so the password is never kept. The PEM is validated on save (an unreadable or non-RSA key, or a bad thumbprint, is rejected with a 422) and is never shown again — the panel only reports that a certificate is registered.

The authorization-code exchange and every background token refresh then authenticate with an RS256 `client_assertion` (`x5t`, plus `x5t#S256` when the certificate is present) instead of `client_secret`. The certificate option appears only for Microsoft identity platform apps (token endpoint on `login.microsoftonline.com` / `login.microsoft.com`); other OAuth providers accept a client secret only.

## Polling details

- Default interval: **300 seconds**.
- The connector calls `subscriptions/content` for each content type with `startTime`/`endTime` set to the last-poll window.
- Each content URL returned is then fetched and concatenated. The Management API delivers events with up to 60 minutes of latency, so don't be alarmed if events seem to lag.
- On first poll for a tenant, the connector ensures all five subscriptions are started (idempotent).

## Severity heuristics

The Management API does not provide severity, so AiSOC infers from `Operation`:

| Pattern | Severity |
|---|---|
| `Add member to role`, mailbox `Add-MailboxPermission`, `Set-Mailbox` with `ForwardingSmtpAddress` | `high` |
| `New-InboxRule` matching exfil patterns (forward to external, delete-on-receive) | `high` |
| Anonymous link create (`AnonymousLinkCreated`) on SharePoint | `medium` |
| MFA disable (`Disable Strong Authentication`) | `high` |
| Routine `MailItemsAccessed`, `FileAccessed` | dropped unless flagged by DLP |

## Troubleshooting

**`AAD: Tenant ... does not have a service principal for resource manage.office.com`** — the app has Microsoft Graph perms but not Office 365 Management API perms. Add `ActivityFeed.Read` on the **Office 365 Management APIs** resource specifically.

**Subscription started but `events_added: 0`** — Management API has up to 60 min latency on first events. Wait one full polling interval, then check again. Also confirm `UnifiedAuditLogIngestionEnabled` is `True`.

**`InvalidPropertyValueException: tenant ID has not been onboarded`** — you need to start a subscription via `POST /subscriptions/start?contentType=...` first. The connector does this automatically on first poll, so just wait one cycle.

## Related

- [Microsoft Entra ID](/docs/connectors/azure-entra) — sign-in/audit at the directory level. M365 audit gives you the workload-level depth.
- [Microsoft Defender (XDR)](/docs/connectors/azure-defender) — finished alerts. M365 audit gives you the raw events behind them.

<!-- BEGIN GENERATED FIELD REFERENCE -->

## Configuration reference

{/* Generated by scripts/generate_connector_docs.py from the connector's
    schema(). Edit the schema, not this table. */}

| Field | Label | Type | Required | Default | Notes |
|-------|-------|------|----------|---------|-------|
| `tenant_id` | Tenant ID | string | yes | — | — |
| `client_id` | Application (Client) ID | string | yes | — | — |
| `client_secret` | Client Secret | secret | no | — | **encrypted at rest** · Leave empty when using a certificate (recommended). Exactly one of secret or certificate is required. |
| `certificate_pem` | Certificate PEM (private key) | secret | no | — | **encrypted at rest** · Recommended over a client secret. Paste a PEM containing the PRIVATE KEY (and optionally the CERTIFICATE) for the certificate whose public .cer you uploaded under Entra portal > App registrations > your app > Certificates & secrets. |
| `certificate_thumbprint` | Certificate Thumbprint | string | no | — | SHA-1 thumbprint shown next to the certificate under App registrations > Certificates & secrets. Optional when the PEM above also contains the certificate. |
| `private_key_password` | Private Key Password | secret | no | — | **encrypted at rest** · Only if the private key in the PEM is encrypted. |

:::note Credential handling
`client_secret`, `certificate_pem`, `private_key_password` are encrypted at rest by the credential vault before the row is written, and decrypted only at poll time. The value is never logged and never returned by the API. See [credential vault](../operations/credentials.md).
:::

<!-- END GENERATED FIELD REFERENCE -->
