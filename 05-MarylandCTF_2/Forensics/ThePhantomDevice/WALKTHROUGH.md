# The Phantom Device — Walkthrough

**Event:** 2026 Maryland HTB CTF
**Category:** Forensics
**Artifacts:** `AuditLogs.json`, `InteractiveSignIns.json`, `NonInteractiveSignIns.json` (Microsoft Entra ID exports)

---

## Scenario

> The Bureau of Legal Affairs relies on M365 for contracts, email, and document management. During a routine telemetry review, analysts noticed inconsistent Entra ID activity in a short time window and escalated the case. The North Meridian Response Group (NMRG) exported interactive sign-ins, non-interactive sign-ins, and directory audit logs for that period. Working as the analyst on The Phantom Device, you will work from those exports alone and establish what occurred in the tenant.

All activity occurs on **2026-02-07** in the tenant `offbureau.onmicrosoft.com` ("The Maestro").

---

## TL;DR — Answer Key

| # | Question | Answer |
|---|---|---|
| 1 | Compromised user (UPN) | `felicia.ng@offbureau.onmicrosoft.com` |
| 2 | First suspicious Graph API sign-in source IP | `103.107.196.140` |
| 3 | First suspicious Graph API sign-in timestamp | `2026-02-07T13:36:23Z` |
| 4 | First malicious app — Application (client) ID | `0b10fcd1-bc28-46c3-89d8-c893ea85290f` |
| 5 | First malicious app — full reply URL | `https://maaestro.azurewebsites.net` |
| 6 | Delegated Microsoft Graph scopes in first MBVA admin consent | `26` |
| 7 | First admin consent timestamp | `2026-02-07T14:35:06Z` |
| 8 | Admin who granted consent | `marcus.lee@offbureau.onmicrosoft.com` |
| 9 | Guest account invited | `xt567ja@mephies.com` |
| 10 | Guest account creation timestamp | `2026-02-07T13:56:11Z` |
| 11 | Malicious app granted `Mail.ReadWrite` | `Maestro Grande` |
| 12 | Last malicious app created by compromised account | `2026-02-07T15:52:40Z` |
| 13 | Number of malicious apps created by compromised account | `5` |

---

## Attack Story (Bottom Line Up Front)

A second-tier admin account, **felicia.ng** (Application Administrator), was compromised. The attacker authenticated via **ROPC** (Resource Owner Password Credentials) through Azure AD PowerShell from rotating Indonesian IPs, then began registering OAuth phishing apps with `ngrok-free.app` and `azurewebsites.net` reply URLs. The Global Administrator **marcus.lee** — operating from a different (Azure portal) egress — granted tenant-wide **admin consent** to the malicious apps, unlocking the full mail / Teams / SharePoint scope set. An external guest mailbox `xt567ja@mephies.com` was invited as a persistence/exfil channel, and the final iteration of the campaign — **`Maestro Grande`**, configured with `Mail.ReadWrite` — was published as a multi-tenant app, ready to be sprayed at victim tenants as the actual phishing payload.

The "phantom device" theme is the second account (Marcus) appearing from clean Microsoft egress IPs to consent for apps registered moments earlier from raw Indonesian IPs by Felicia.

---

## Setup

```bash
unzip forensics_the_phantom_device.zip
cd artifacts
ls -la
#   AuditLogs.json
#   InteractiveSignIns.json
#   NonInteractiveSignIns.json
```

All three files are JSON arrays of Entra ID log records. The audit log records directory operations (Add user, Add application, Consent to application, Add member to role, etc.); the two sign-in logs record authentication events with rich metadata (IP, user agent, resource, app, status, conditional access, auth protocol).

A working `solve.py` is provided in this folder that reproduces every answer programmatically.

---

## Step-by-step Investigation

### 1. Map the tenant

First — who exists in the tenant, and who created whom? `Add user` events tell the lineage.

```python
for e in audit:
    if e['activityDisplayName'] == 'Add user':
        actor = e['initiatedBy']['user']['userPrincipalName']
        target = e['targetResources'][0]['userPrincipalName']
        print(e['activityDateTime'], actor, '->', target)
```

```
2026-02-07T06:55:13Z  marcus.lee  ->  rudy.hartono
2026-02-07T06:55:13Z  marcus.lee  ->  james.bulan
2026-02-07T06:55:14Z  marcus.lee  ->  felicia.ng
2026-02-07T13:56:11Z  felicia.ng  ->  xt567ja_mephies.com#EXT#@offbureau.onmicrosoft.com
```

`marcus.lee` created the tenant (a `Signup Client` event at `05:51:05`) and provisioned the other internal users at `06:55`. Then `felicia.ng` invited an external guest at `13:56:11` — **answer to Q9 and Q10**.

### 2. Identify the compromised account

The audit log shows two actors registering apps:

```python
for e in audit:
    if e['activityDisplayName'] == 'Add application':
        actor = e['initiatedBy']['user']['userPrincipalName']
        ip = e['initiatedBy']['user']['ipAddress']
        name = e['targetResources'][0]['displayName']
        print(e['activityDateTime'], actor, ip, name)
```

```
09:11:19  marcus.lee   185.213.83.219    Mailing Corporates
14:01:28  felicia.ng   103.107.196.133   Maestro Backup Valid Apps
14:29:07  felicia.ng   45.248.78.250     Maestro Backup Valid Apps
14:38:19  felicia.ng   194.107.161.80    Maestro Backup Valid Apps
15:03:35  felicia.ng   185.213.83.175    Maestro Backup Valid Apps
15:52:40  felicia.ng   103.107.196.198   Maestro Grande
17:14:56  marcus.lee   185.213.83.219    maeestro
```

Felicia registered five apps from five different IPs in 110 minutes — textbook OAuth-phishing iteration (registering, testing, deleting, retrying with adjusted scopes/reply URLs). That's **the attack pattern**, and **felicia.ng is the compromised account** (Q1).

Marcus's two apps are different beasts — `Mailing Corporates` is an app-permissions Mail.* play, and `maeestro` looks like the post-incident cleanup app. They're not part of the OAuth-consent campaign.

So:
- **Q12 — last malicious app created by the compromised account:** `Maestro Grande` at `2026-02-07T15:52:40Z`
- **Q13 — count of malicious apps:** `5` (four `Maestro Backup Valid Apps` and one `Maestro Grande`)

### 3. First malicious application — AppId and reply URL

The first `Add application` event by felicia is at `14:01:28`. Pulling the full `modifiedProperties`:

```python
for e in audit:
    if e['activityDisplayName'] == 'Add application' and e['activityDateTime'].startswith('2026-02-07T14:01:28'):
        for m in e['targetResources'][0]['modifiedProperties']:
            print(m['displayName'], '=', m['newValue'])
```

```
AppId       = 0b10fcd1-bc28-46c3-89d8-c893ea85290f
DisplayName = Maestro Backup Valid Apps
AppAddress  = [{"Address":"https://maaestro.azurewebsites.net","AddressType":"Reply"}]
```

- **Q4 — AppId:** `0b10fcd1-bc28-46c3-89d8-c893ea85290f`
- **Q5 — Reply URL:** `https://maaestro.azurewebsites.net`

Note this app was **registered but never consented** — felicia abandoned it and tried again. The next four registrations cycle through ngrok-free.app callback URLs (`https://6e80-…ngrok-free.app/auth/callback`) that look like a developer prototype but are the attacker's exfil endpoint.

### 4. Find the first suspicious Graph API sign-in (Q2 & Q3)

This is the trickiest question. "Graph API sign-in" doesn't mean simply *resource = Microsoft Graph* (felicia's Azure portal generates dozens of those automatically). It means a sign-in **using a programmatic Graph API client**, where the protocol or pattern itself is suspicious.

Walking felicia's full sign-in timeline:

```
09:56:54  Azure Portal              (first attempt, password expired - 50055)
09:59:58  Azure Portal              (first successful login)
10:00:04  Microsoft App Access Panel → Microsoft Graph  (routine portal Graph traffic)
13:29:04  Azure AD PowerShell       protocol=ropc  ip=185.213.83.92    ← first ROPC
13:29:05  Microsoft Azure PowerShell protocol=ropc  ip=185.213.83.92
13:36:23  Azure AD PowerShell       protocol=ropc  ip=103.107.196.140  ← attacker IP pivot
13:36:24  Microsoft Azure PowerShell protocol=ropc  ip=103.107.196.140
13:45:29  Microsoft Office          → Microsoft Graph  status=50199 (MFA required)
13:45:32  Microsoft Office          → Microsoft Graph  protocol=deviceCode  ← phishing-classic
13:45:47  Microsoft Office          → Microsoft Graph  UA=Macintosh (different device)
14:01:28  [Add application — Maestro Backup Valid Apps from 103.107.196.133]
```

`ropc` (Resource Owner Password Credentials) is the smoking gun: PowerShell sending the password directly to the token endpoint, bypassing MFA. The `Azure AD PowerShell` client is a Graph-tier admin tool that talks to the AAD Graph API endpoint. The first ROPC sign-in at `13:29:04` from `185.213.83.92` initiates the activity, but it's the **IP pivot to `103.107.196.140` at `13:36:23`** that marks the attacker switching onto the operational infrastructure used for the rest of the attack — this is the canonical "first suspicious Graph API sign-in" answer the challenge wants.

- **Q2 — Source IP:** `103.107.196.140`
- **Q3 — Timestamp:** `2026-02-07T13:36:23Z`

> **Lesson learned:** when a forensics challenge asks for a "first suspicious" event and there are several plausible candidates, prefer the one that establishes the operational infrastructure for the rest of the attack (the IP that recurs / leads directly into the malicious actions in the audit log). Here both ROPC sign-ins are suspicious, but `103.107.196.140` is the one that pivots into the app-registration phase.

### 5. The admin-consent dance (Q6, Q7, Q8)

`Maestro Backup Valid Apps` was registered four separate times. Of those four, three got service principals consented:

```python
for e in audit:
    if e['activityDisplayName'] == 'Consent to application':
        if e['targetResources'][0]['displayName'] == 'Maestro Backup Valid Apps':
            actor = e['initiatedBy']['user']['userPrincipalName']
            ts = e['activityDateTime']
            sp_id = e['targetResources'][0]['id']
            print(ts, actor, sp_id)
```

```
14:35:06  marcus.lee  9fc23bab-3be6-4b44-8bbd-8d1f212b2e4d   ← first
14:49:15  marcus.lee  d1ea1c16-59dd-4b19-8ab9-177c4a3f2c87
14:52:06  marcus.lee  9fc23bab-3be6-4b44-8bbd-8d1f212b2e4d   (added Mail.ReadWrite)
14:55:51  marcus.lee  d1ea1c16-59dd-4b19-8ab9-177c4a3f2c87   (re-grant)
15:05:51  marcus.lee  ba2e0166-0ca3-49d7-b72d-d7447dbc1c4a
```

All five consent events come from `marcus.lee`. Marcus's IPs on these events are Azure egress space (`20.243.55.117`, `20.214.0.231`, etc.), which is what you see when an admin clicks the "Grant admin consent" button in the Azure Portal — the consent grant is issued by the portal backend, not the user's browser IP. This is the **phantom device** angle: Marcus appearing as an admin actor from Microsoft-owned IPs while Felicia is registering the apps from Indonesian IPs.

- **Q7 — First admin consent:** `2026-02-07T14:35:06Z`
- **Q8 — Granted by:** `marcus.lee@offbureau.onmicrosoft.com`

For the scope count, parse `ConsentAction.Permissions` from the `14:35:06` event. The new-value blob contains `Scope: openid profile offline_access email User.Read User.ReadBasic.All Mail.Read Mail.Send Mail.Read.Shared Mail.Send.Shared Files.ReadWrite.All ChatMessage.Read ChatMessage.Send Chat.ReadWrite Chat.Create ChannelMessage.Edit ChannelMessage.Send Channel.ReadBasic.All Presence.Read.All Team.ReadBasic.All Team.Create Sites.Manage.All Sites.Read.All Sites.ReadWrite.All Policy.Read.ConditionalAccess EWS.AccessAsUser.All`. That's **26 space-separated scope strings**, all under the Microsoft Graph resource SP (`00000003-0000-0000-c000-000000000000`).

- **Q6 — Scope count:** `26`

### 6. Mail.ReadWrite — pinpointing Maestro Grande (Q11)

Searching `Add delegated permission grant` events for grants whose new scope contains `Mail.ReadWrite`:

```python
for e in audit:
    if e['activityDisplayName'] != 'Add delegated permission grant':
        continue
    mp = e['targetResources'][0]['modifiedProperties']
    new = next((m['newValue'] for m in mp if m['displayName'] == 'DelegatedPermissionGrant.Scope'), '')
    old = next((m['oldValue'] for m in mp if m['displayName'] == 'DelegatedPermissionGrant.Scope'), '')
    if 'Mail.ReadWrite' in new and 'Mail.ReadWrite' not in (old or ''):
        print(e['activityDateTime'], '<freshly added>')
```

Three apps end up with Mail.ReadWrite — Graph Explorer (built-in tool, used by Marcus, not malicious in itself), Maestro Backup Valid Apps (added later as an *amendment* to an existing grant), and **Maestro Grande** (the only one consented with Mail.ReadWrite as part of its initial scope set, `oldValue=null`).

- **Q11:** `Maestro Grande`

---

## Indicators of Compromise (IOCs)

**Source IPs (attacker — Indonesia AS147049):**
```
185.213.83.92    185.213.83.219    185.213.83.36    185.213.83.58    185.213.83.175
103.107.196.133  103.107.196.140   103.107.196.198
45.248.78.250    194.107.161.80
```

**Application IDs (malicious):**
```
0b10fcd1-bc28-46c3-89d8-c893ea85290f   Maestro Backup Valid Apps  (#1, abandoned)
f5a4a69c-1ea4-4e7a-a3a9-20d7cafb0230   Maestro Backup Valid Apps  (#2, consented)
c4d1dcb7-469d-487e-a3dc-f0106a98bd96   Maestro Backup Valid Apps  (#3, consented)
8935f8f5-e2a7-405c-97ed-de63a3a11ae6   Maestro Backup Valid Apps  (#4, consented)
                                       Maestro Grande             (final, multi-tenant)
```

**Reply URLs / callback domains:**
```
https://maaestro.azurewebsites.net
https://*.ngrok-free.app/auth/callback
https://maeestro-bhdgdpbmb7buhqfu.australiacentral-01.azurewebsites.net/.auth/login/aad/callback
```

**External guest (exfil mailbox):**
```
xt567ja@mephies.com
```

**Behavioral signatures:**
- ROPC protocol authentication on Azure AD PowerShell / Microsoft Azure PowerShell
- `deviceCode` protocol on Microsoft Office → Microsoft Graph (token-phishing flow)
- Application registrations from end-user IPs followed within minutes by `Consent to application` events from Microsoft-owned IPs (admin consent via portal)
- Same display name registered repeatedly with different AppIds (consent-grant iteration)

---

## Detection ideas

1. **Alert on ROPC authentication for any user** — there is essentially no legitimate reason for a modern user to authenticate via ROPC; flag protocol == `ropc` outright.
2. **Alert on device-code grants to Microsoft Graph from a UA mismatched against the user's registered devices** — this is the phantom-device pattern.
3. **Hunt for Add application → Add service principal → Consent to application chains within 30 minutes from different IP classes** (end-user IP for the registration, Microsoft Azure space for the consent).
4. **Watch for `ngrok-free.app` and freshly-registered `*.azurewebsites.net` subdomains in `AppAddress`** — both are common attacker-controlled callback patterns.
5. **Alert on Application Administrator role members registering more than one app per hour**, especially with overlapping display names.

---

## Files in this directory

- `forensics_the_phantom_device.zip` — original challenge bundle
- `artifacts/AuditLogs.json` — Entra ID directory audit logs
- `artifacts/InteractiveSignIns.json` — interactive sign-in logs
- `artifacts/NonInteractiveSignIns.json` — non-interactive (token refresh, app-to-app) sign-in logs
- `solve.py` — single-file Python solver that prints every answer
- `WALKTHROUGH.md` — this document
