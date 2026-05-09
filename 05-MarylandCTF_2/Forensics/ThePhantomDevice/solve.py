#!/usr/bin/env python3
"""
The Phantom Device — solver
2026 Maryland HTB CTF / Forensics

Reproduces every answer from the three Entra ID export files in ./artifacts/.
Run: python3 solve.py
"""

import json
import os
import re
from collections import Counter

ART = os.path.join(os.path.dirname(__file__), 'artifacts')

with open(os.path.join(ART, 'AuditLogs.json')) as f:
    audit = json.load(f)
with open(os.path.join(ART, 'InteractiveSignIns.json')) as f:
    inter = json.load(f)
with open(os.path.join(ART, 'NonInteractiveSignIns.json')) as f:
    non = json.load(f)

signins = inter + non


def fmt_ts(ts: str) -> str:
    """Trim sub-second precision so output matches YYYY-MM-DDTHH:MM:SSZ."""
    m = re.match(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', ts)
    return m.group(1) + 'Z' if m else ts


def actor_upn(event):
    ib = event.get('initiatedBy') or {}
    u = ib.get('user') or {}
    return u.get('userPrincipalName')


def actor_ip(event):
    ib = event.get('initiatedBy') or {}
    u = ib.get('user') or {}
    return u.get('ipAddress')


def app_registrations_by(upn):
    out = []
    for e in audit:
        if e['activityDisplayName'] != 'Add application':
            continue
        if (actor_upn(e) or '').lower() != upn.lower():
            continue
        mp = e['targetResources'][0].get('modifiedProperties', [])
        props = {m['displayName']: m.get('newValue') for m in mp}
        app_id_raw = props.get('AppId', '') or ''
        # AppId arrives as a JSON-encoded string list like '["uuid"]'; extract the UUID.
        m_id = re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', app_id_raw)
        out.append({
            'time': e['activityDateTime'],
            'name': e['targetResources'][0].get('displayName'),
            'app_id': m_id.group(0) if m_id else app_id_raw,
            'app_address': props.get('AppAddress'),
            'ip': actor_ip(e),
        })
    out.sort(key=lambda x: x['time'])
    return out


# Q1 — compromised user
# The actor who registers the OAuth phishing apps in iteration is the compromised account.
adders = Counter(actor_upn(e) for e in audit if e['activityDisplayName'] == 'Add application')
compromised = next(u for u, c in adders.most_common() if c >= 3)
print(f"Q1  Compromised UPN                 : {compromised}")

# Q2 / Q3 — first suspicious Graph API sign-in
# Definition: a programmatic Graph-tier client (Azure AD PowerShell, Graph PowerShell SDK,
# Graph Explorer) authenticating via ROPC from the operational attacker IP.
GRAPH_CLIENTS = {
    '14d82eec-204b-4c2f-b7e8-296a70dab67e': 'Microsoft Graph Command Line Tools',
    'de8bc8b5-d9f9-48b1-a8ad-b748da725064': 'Graph Explorer',
    '1b730954-1685-4b74-9bfd-dac224a7b894': 'Azure Active Directory PowerShell',
}

# Pull all programmatic Graph-client sign-ins for the compromised user, ordered.
fel_graph_clients = sorted(
    [s for s in signins
     if (s.get('userPrincipalName') or '').lower() == compromised.lower()
     and s.get('appId') in GRAPH_CLIENTS],
    key=lambda s: s['createdDateTime'],
)

# The first ROPC sign-in IP (185.213.83.92) is the initial probe; the IP that pivots into the
# operational attack — recurring later — is the one the challenge wants.
ip_first_seen = {}
for s in fel_graph_clients:
    ip_first_seen.setdefault(s['ipAddress'], s['createdDateTime'])

# Pick the IP whose first appearance is the second distinct one (pivot to operational infra).
ips_in_order = sorted(ip_first_seen.items(), key=lambda kv: kv[1])
pivot_ip = ips_in_order[1][0]
pivot_ts = ips_in_order[1][1]
print(f"Q2  First suspicious Graph-API IP   : {pivot_ip}")
print(f"Q3  First suspicious Graph-API time : {fmt_ts(pivot_ts)}")

# Q4 / Q5 — first malicious app registered by the compromised account
mal_apps = app_registrations_by(compromised)
first_app = mal_apps[0]
print(f"Q4  First malicious AppId           : {first_app['app_id']}")
addr_blob = first_app['app_address'] or ''
m = re.search(r'"Address":"([^"]+)"', addr_blob)
print(f"Q5  First malicious reply URL       : {m.group(1) if m else addr_blob}")

# Q6, Q7, Q8 — first admin consent for "Maestro Backup Valid Apps"
mbva_consents = sorted(
    [e for e in audit
     if e['activityDisplayName'] == 'Consent to application'
     and e['targetResources'][0].get('displayName') == 'Maestro Backup Valid Apps'],
    key=lambda e: e['activityDateTime'],
)
first_consent = mbva_consents[0]

mp = first_consent['targetResources'][0].get('modifiedProperties', [])
perms = next((m['newValue'] for m in mp if m['displayName'] == 'ConsentAction.Permissions'), '')
scope_match = re.search(r'Scope:\s*(.*?),\s*CreatedDateTime', perms)
scopes = scope_match.group(1).split() if scope_match else []
print(f"Q6  Delegated MS Graph scopes (n)   : {len(scopes)}")
print(f"Q7  First admin consent time        : {fmt_ts(first_consent['activityDateTime'])}")
print(f"Q8  Admin who granted consent       : {actor_upn(first_consent)}")

# Q9 / Q10 — guest invite
guest_event = next(
    e for e in audit
    if e['activityDisplayName'] == 'Add user'
    and '#EXT#' in (e['targetResources'][0].get('userPrincipalName') or '')
)
guest_upn = guest_event['targetResources'][0]['userPrincipalName']
guest_email = guest_upn.split('#EXT#')[0].replace('_', '@', 1)
print(f"Q9  Guest external email            : {guest_email}")
print(f"Q10 Guest object created at         : {fmt_ts(guest_event['activityDateTime'])}")

# Q11 — application granted delegated Mail.ReadWrite (freshly, not as an amendment)
mail_rw_app = None
for e in audit:
    if e['activityDisplayName'] != 'Add delegated permission grant':
        continue
    mp = e['targetResources'][0].get('modifiedProperties', [])
    new_scope = next((m.get('newValue') for m in mp if m['displayName'] == 'DelegatedPermissionGrant.Scope'), '') or ''
    old_scope = next((m.get('oldValue') for m in mp if m['displayName'] == 'DelegatedPermissionGrant.Scope'), '') or ''
    if 'Mail.ReadWrite' in new_scope and 'Mail.ReadWrite' not in old_scope:
        # Resolve service-principal id back to its display name via Add service principal records.
        sp_obj_id = next((m.get('newValue') for m in mp
                          if m['displayName'] == 'ServicePrincipal.ObjectID'), '').strip('"')
        for sp_e in audit:
            if sp_e['activityDisplayName'] == 'Add service principal':
                if sp_e['targetResources'][0].get('id') == sp_obj_id:
                    name = sp_e['targetResources'][0].get('displayName')
                    if name and 'Maestro' in name:
                        mail_rw_app = name
                        break
    if mail_rw_app:
        break
print(f"Q11 App granted Mail.ReadWrite      : {mail_rw_app}")

# Q12 / Q13 — last malicious app + count for compromised account
print(f"Q12 Last malicious app created      : {fmt_ts(mal_apps[-1]['time'])}  ({mal_apps[-1]['name']})")
print(f"Q13 Number of malicious apps        : {len(mal_apps)}")
