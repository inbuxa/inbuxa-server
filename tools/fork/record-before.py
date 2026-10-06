#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""
Record what must still be true after the cutover, from the server that is
about to be replaced.

    tools/fork/record-before.py --server https://mail.example.org \
        --admin 'admin@example.org:PASSWORD' --out ./before.json

Step 4 of `docs/spec/cutover-run.md`: write down what has to be true
afterwards, while the old server can still be asked. Step 10 then checks
against it. Skipping this turns "each mailbox holds what was recorded" into
"each mailbox holds something", which is not the same check and will not
catch a partial copy.

**This script only reads.** It reuses `record-compat.py`'s client, whose
`call` refuses any method that is not a `/get` or a `/query`, so it is safe
against the live server that the hand-off brief otherwise bars touching.

What it records from the administrator alone, needing nobody's password:

- every account: its name, address, aliases, description, roles, tenant,
  quota and **usedDiskQuota**, which is the number that moves if mail goes
  missing;
- every domain, and every tenant.

Exact per-mailbox message counts need the mailbox's own credentials, since
an administrator has reach over accounts but not always into them. Pass
`--as name:password` once per mailbox to record those too — worth it for a
handful of mailboxes, and it makes step 10 an equality rather than an
estimate.

Exit status: 0 recorded, 1 a server refusal or nothing to record, 2 usage.
"""

import argparse
import importlib.util
import json
import os
import pathlib
import sys
import urllib.request

# record-compat.py is not an importable name, and duplicating its client
# would duplicate the read-only guard that makes this safe to point at the
# live server. Load it by path instead.
_spec = importlib.util.spec_from_file_location(
    'record_compat', pathlib.Path(__file__).with_name('record-compat.py'))
_compat = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_compat)

Client, Refused, fail = _compat.Client, _compat.Refused, _compat.fail

ACCOUNT_PROPERTIES = [
    'id', 'name', 'description', 'emailAddress', 'aliases', 'roles',
    'domainId', 'memberTenantId', 'quotas', 'usedDiskQuota',
]


def record_accounts(admin, domains):
    """Every account the administrator can see, with what identifies it."""
    ids = admin.query_ids('Account')
    if not ids:
        return {}
    accounts = {}
    for account in admin.call('x:Account/get',
                              {'ids': ids, 'properties': ACCOUNT_PROPERTIES}).get('list', []):
        id = account.get('id')
        aliases = account.get('aliases') or {}
        accounts[id] = {
            'name': account.get('name'),
            'address': account.get('emailAddress'),
            'description': account.get('description'),
            'type': (account.get('roles') or {}).get('@type'),
            'domainId': account.get('domainId'),
            'memberTenantId': account.get('memberTenantId'),
            'usedDiskQuota': account.get('usedDiskQuota'),
            'quotas': account.get('quotas'),
            # Sorted and flattened: an alias moving position is not a change.
            # Resolved to the domain's name: an id is not what anyone
            # checks against at 2am.
            'aliases': sorted(
                '{}@{}'.format(
                    a.get('name'),
                    (domains.get(a.get('domainId')) or {}).get('name') or a.get('domainId'),
                )
                for a in (aliases.values() if isinstance(aliases, dict) else aliases)
                if a.get('enabled', True)
            ),
        }
    return accounts


def record_domains(admin):
    ids = admin.query_ids('Domain')
    if not ids:
        return {}
    return {
        d.get('id'): {'name': d.get('name'), 'memberTenantId': d.get('memberTenantId')}
        for d in admin.get('Domain', ids=ids)
    }


def record_tenants(admin):
    try:
        return {t.get('id'): {'name': t.get('name')} for t in admin.get('Tenant')}
    except Refused:
        # A server with no tenancy in use refuses rather than returning none.
        return {}


def record_mailbox(server, credentials, insecure):
    """Exact message count for one mailbox, signed in as that mailbox."""
    client = Client(server, credentials, insecure)
    if not client.authenticates():
        fail(f'{client.name} did not authenticate; --as wants name:password', code=1)
    # Its own account id, from the session, rather than guessing it.
    request = urllib.request.Request(
        f'{client.server}/jmap/session',
        headers={'Authorization': f'Basic {client.auth}'})
    with urllib.request.urlopen(request, context=client.ctx, timeout=30) as response:
        session = json.load(response)
    primary = session.get('primaryAccounts') or {}
    session_account = (primary.get('urn:ietf:params:jmap:mail')
                       or next(iter(session.get('accounts') or {}), None))
    if not session_account:
        fail(f'{client.name}: no account in its session', code=1)

    # Through call(), not _post(), so the read-only guard still applies.
    result = client.call('Email/query', {'accountId': session_account})
    return {'accountId': session_account, 'messages': len(result.get('ids', []))}


def main():
    parser = argparse.ArgumentParser(
        description='Record the pre-cutover state from the running server.')
    parser.add_argument('--server', required=True,
                        help='https://mail.example.org')
    parser.add_argument('--admin', required=True, metavar='NAME:PASSWORD',
                        help='an administrator with the run of the server')
    parser.add_argument('--as', dest='mailboxes', action='append', default=[],
                        metavar='NAME:PASSWORD',
                        help='a mailbox to count exactly; repeatable')
    parser.add_argument('--out', default='./before.json')
    parser.add_argument('--insecure', action='store_true',
                        help='accept a self-signed certificate')
    args = parser.parse_args()

    admin = Client(args.server, args.admin, args.insecure)
    if not admin.authenticates():
        fail(f'{admin.name} did not authenticate against {args.server}', code=1)

    try:
        domains = record_domains(admin)
        record = {
            'server': args.server.rstrip('/'),
            'domains': domains,
            'accounts': record_accounts(admin, domains),
            'tenants': record_tenants(admin),
            'mailboxes': {},
        }
        for credentials in args.mailboxes:
            name = credentials.split(':', 1)[0]
            record['mailboxes'][name] = record_mailbox(args.server, credentials, args.insecure)
    except Refused as refusal:
        fail(str(refusal), code=1)

    if not record['accounts']:
        fail('no accounts read; nothing to record', code=1)

    path = os.path.abspath(args.out)
    with open(path, 'w') as handle:
        json.dump(record, handle, indent=1, sort_keys=True)
    os.chmod(path, 0o600)

    print(f"recorded {len(record['accounts'])} account(s), "
          f"{len(record['domains'])} domain(s), "
          f"{len(record['tenants'])} tenant(s), "
          f"{len(record['mailboxes'])} counted mailbox(es)")
    for id, account in sorted(record['accounts'].items(), key=lambda kv: kv[1]['name'] or ''):
        quota = account['usedDiskQuota']
        aliases = (' aliases=' + ','.join(account['aliases'])) if account['aliases'] else ''
        print(f"  {account['name']:<16} {account['address'] or '':<28} "
              f"used={quota if quota is not None else '?'}{aliases}")
    for name, box in sorted(record['mailboxes'].items()):
        print(f"  {name:<16} messages={box['messages']}")
    print(f'wrote {path} (0600)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
