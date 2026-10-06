#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""
Record what the compat tests compare against, from the Enterprise server.

    tools/fork/record-compat.py --server https://mail.example.org \
        --admin 'admin@example.org:PASSWORD' --out ./compat \
        --tenant-admin 'tenant-admin@example.org:PASSWORD'

The eight `*_compat` tests check that INBUXA's data opens in the fork and
reads back as it did on the Enterprise server (docs/spec/SPEC.md §7). Three
of them need a recording of "as it did", which can only be made while the
Enterprise server is still running (docs/spec/compat-tests.md):

- `INBUXA_COMPAT_EXPECTED` (`expected.json`): tenants, their quotas and
  members, and what each tenant administrator can see.
- `INBUXA_COMPAT_MASKS` (`masks.json`): every masked address and its state.
- `INBUXA_COMPAT_ARCHIVED` (`archived.json`): every archived item, with all
  its properties, because `undelete_compat` compares every one it recorded.

**This script only reads.** It issues `/get` and `/query` and nothing else:
no `/set`, no task, no write of any kind, so it is safe against the live
server, which the hand-off brief otherwise bars touching. It is the one
thing that has to run there rather than on a copy.

`expected.json` holds the tenant administrators' passwords, because the test
signs in as each of them. Keep it as you would any password file; the script
writes it 0600.

Exit status: 0 recorded, 1 nothing to record or a server refusal, 2 usage.
"""

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

USING = [
    'urn:ietf:params:jmap:core',
    'urn:ietf:params:jmap:mail',
    'urn:ietf:params:jmap:principals',
    'urn:stalwart:jmap',
]


def fail(msg, code=2):
    print(f'record-compat: {msg}', file=sys.stderr)
    sys.exit(code)


# The permission each call needs, so a refusal says what to grant rather
# than only that something was refused.
PERMISSION = {
    'x:Tenant/get': 'sysTenantGet',
    'x:Account/query': 'sysAccountQuery',
    'x:Domain/query': 'sysDomainQuery',
    'x:MaskedEmail/get': 'sysMaskedEmailGet',
    'x:ArchivedItem/get': 'sysArchivedItemGet',
}


class Refused(Exception):
    """The server allowed the sign-in but not the call."""

    def __init__(self, who, method, error):
        self.who = who
        self.method = method
        self.error = error
        super().__init__(str(self))

    def __str__(self):
        detail = self.error.get('description') or json.dumps(self.error)[:120]
        # "not an owner of account X" is reach, not a permission: the
        # identity can see its own account and no further, and no permission
        # granted to it changes that. Saying "needs sysMaskedEmailGet" there
        # sends you to grant something that won't help.
        if 'owner' in detail.lower():
            return (f'{self.who} may not {self.method}: {detail}. '
                    f'That is reach, not a permission: this identity can only '
                    f'read its own account. Recording every account needs the '
                    f'administrator that has the run of the server; a tenant '
                    f'administrator belongs in --tenant-admin instead.')
        needed = PERMISSION.get(self.method)
        return (f'{self.who} may not {self.method}: {detail}'
                + (f' (needs {needed})' if needed else ''))


class Client:
    """One signed-in identity on the Enterprise server."""

    def __init__(self, server, credentials, insecure):
        if ':' not in credentials:
            fail(f'credentials must be name:password, not {credentials!r}')
        self.name, password = credentials.split(':', 1)
        self.server = server.rstrip('/')
        self.auth = base64.b64encode(f'{self.name}:{password}'.encode()).decode()
        self.ctx = ssl._create_unverified_context() if insecure else None

    def _post(self, url, body):
        request = urllib.request.Request(
            url, data=json.dumps(body).encode(), method='POST',
            headers={'Authorization': f'Basic {self.auth}',
                     'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, context=self.ctx, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors='replace')[:200]
            if error.code == 401:
                fail(f'{self.name} did not authenticate: {detail}', code=1)
            fail(f'{self.name}: HTTP {error.code} from {url}: {detail}', code=1)
        except urllib.error.URLError as error:
            self._unreachable(error)

    def authenticates(self):
        """Whether these credentials are accepted, without failing the run."""
        request = urllib.request.Request(
            f'{self.server}/jmap/session',
            headers={'Authorization': f'Basic {self.auth}'})
        try:
            with urllib.request.urlopen(request, context=self.ctx, timeout=30) as response:
                return response.status == 200
        except urllib.error.HTTPError as error:
            if error.code in (401, 403):
                return False
            fail(f'{self.name}: HTTP {error.code} from the session endpoint', code=1)
        except urllib.error.URLError as error:
            self._unreachable(error)

    def _unreachable(self, error):
        hint = ('. A self-signed certificate needs --insecure'
                if isinstance(error.reason, ssl.SSLError) else '')
        fail(f'cannot reach {self.server}: {error.reason}{hint}', code=1)

    def call(self, method, arguments):
        """One JMAP method call; returns its response object."""
        if not method.endswith(('/get', '/query')):
            fail(f'{method} is not a read; this script only reads')
        body = {'using': USING, 'methodCalls': [[method, arguments, '0']]}
        response = self._post(f'{self.server}/jmap', body)
        calls = response.get('methodResponses')
        if not calls:
            fail(f'{self.name}: no method response for {method}: '
                 f'{json.dumps(response)[:200]}', code=1)
        name, result, _ = calls[0]
        if name == 'error':
            raise Refused(self.name, method, result)
        return result

    def get(self, object_type, account_id=None, ids=None):
        arguments = {'ids': ids}
        if account_id is not None:
            arguments['accountId'] = account_id
        return self.call(f'x:{object_type}/get', arguments).get('list', [])

    def query_ids(self, object_type, filter=None, account_id=None):
        """
        Every matching id, following the query's pages.

        A server that caps a page would otherwise hand back a short list and
        the recording would quietly miss accounts. `total` is what says
        there are more; a server that doesn't send it gets one page, which
        is what it offered.
        """
        ids, seen = [], set()
        while True:
            arguments = {'filter': filter or {}, 'sort': [], 'position': len(ids)}
            if account_id is not None:
                arguments['accountId'] = account_id
            result = self.call(f'x:{object_type}/query', arguments)
            page = [id for id in result.get('ids', []) if id not in seen]
            if not page:
                return ids
            ids += page
            seen.update(page)
            total = result.get('total')
            if total is None or len(ids) >= total:
                return ids


def record_tenants(admin, tenant_admins):
    """Tenants, their quotas and members, and what each tenant admin sees."""
    tenants = {}
    for tenant in admin.get('Tenant'):
        id = tenant.get('id')
        if id is None:
            continue
        tenants[id] = {
            'name': tenant.get('name'),
            'quotas': tenant.get('quotas', {}),
            'members': sorted(admin.query_ids('Account', {'memberTenantId': id})),
        }
    admins = {}
    for client, password in tenant_admins:
        admins[client.name] = {
            'password': password,
            'accounts': sorted(client.query_ids('Account')),
            'domains': sorted(client.query_ids('Domain')),
        }
    return {'tenants': tenants, 'tenantAdmins': admins}


def record_masks(admin, account_ids):
    """Every masked address, as `masked_email_compat` reads them back."""
    masks = []
    for account_id in account_ids:
        for mask in admin.get('MaskedEmail', account_id=account_id):
            masks.append({
                'id': mask.get('id'),
                'accountId': account_id,
                'email': mask.get('email'),
                'enabled': mask.get('enabled'),
            })
    return masks


def record_archived(admin, account_ids):
    """
    Every archived item, whole.

    `undelete_compat` compares every property it finds in the recording
    against the stored object, so the object is kept as the server gives it,
    not trimmed. `accountId` is one of its properties, so the test can both
    address the item and compare it.
    """
    items = []
    for account_id in account_ids:
        for item in admin.get('ArchivedItem', account_id=account_id):
            item.setdefault('accountId', account_id)
            items.append(item)
    return items


def write(path, value, private=False):
    text = json.dumps(value, indent=2, sort_keys=True) + '\n'
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(text)
    os.chmod(path, 0o600 if private else 0o644)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--server', required=True,
                        help="the Enterprise server's base URL")
    parser.add_argument('--admin', required=True, metavar='NAME:PASSWORD',
                        help='a server-level administrator')
    parser.add_argument('--tenant-admin', action='append', default=[],
                        metavar='NAME:PASSWORD',
                        help='a tenant administrator, repeatable; each one is '
                             'signed in as itself to record what it sees')
    parser.add_argument('--out', required=True, help='directory for the three files')
    parser.add_argument('--insecure', action='store_true',
                        help="don't verify the server's certificate")
    args = parser.parse_args()

    admin = Client(args.server, args.admin, args.insecure)
    tenant_admins = [(Client(args.server, credentials, args.insecure),
                      credentials.split(':', 1)[1])
                     for credentials in args.tenant_admin]

    # Every identity first, before any work: a recording that stops on the
    # last tenant administrator has wasted a pass over every account, and
    # this runs against a server that may not be up for long.
    refused = [client.name for client in [admin] + [c for c, _ in tenant_admins]
               if not client.authenticates()]
    if refused:
        fail('these did not authenticate: ' + ', '.join(refused) + '.\n'
             'Basic authentication wants the account\'s name, which may not be\n'
             'its email address, and an account with two-factor or OAuth-only\n'
             'sign-in needs an app password instead of its own. Check one with:\n'
             "  curl -s -o /dev/null -w '%{http_code}\\n' -u 'NAME:PASSWORD' "
             f'{args.server.rstrip("/")}/jmap/session', code=1)

    os.makedirs(args.out, exist_ok=True)
    try:
        account_ids = admin.query_ids('Account')
    except Refused as refused:
        fail(f'{refused}\nWithout the accounts nothing else can be recorded.', code=1)
    if not account_ids:
        fail(f'{admin.name} sees no accounts: either the wrong server, or an '
             f'administrator without the run of it', code=1)

    # A section the server refuses costs that file, not the run: this passes
    # over a live server that may not be up again soon, so record what this
    # administrator is allowed to and say plainly what is missing.
    missing = []

    def section(name, record):
        try:
            return record()
        except Refused as refused:
            missing.append((name, refused))
            return None

    expected = section('expected.json', lambda: record_tenants(admin, tenant_admins))
    masks = section('masks.json', lambda: record_masks(admin, account_ids))
    archived = section('archived.json', lambda: record_archived(admin, account_ids))

    written = []
    if expected is not None:
        written.append(('INBUXA_COMPAT_EXPECTED',
                        write(os.path.join(args.out, 'expected.json'), expected, private=True),
                        f'{len(expected["tenants"])} tenants, '
                        f'{len(expected["tenantAdmins"])} tenant admins'))
    if masks is not None:
        written.append(('INBUXA_COMPAT_MASKS',
                        write(os.path.join(args.out, 'masks.json'), masks),
                        f'{len(masks)} masked addresses'))
    if archived is not None:
        written.append(('INBUXA_COMPAT_ARCHIVED',
                        write(os.path.join(args.out, 'archived.json'), archived),
                        f'{len(archived)} archived items'))

    print(f'Recorded from {args.server} as {admin.name}, across {len(account_ids)} accounts:')
    for variable, path, count in written:
        print(f'  {variable}={path}  ({count})')
    if expected is not None and not tenant_admins and expected['tenants']:
        print('\nNo --tenant-admin was given, so tenantAdmins is empty and '
              "tenant_compat checks only the tenants themselves.\n"
              'Pass each tenant administrator to check what it can see.',
              file=sys.stderr)
    if expected is not None:
        print('\nexpected.json holds those passwords; it is written 0600.', file=sys.stderr)
    if missing:
        print('\nNot recorded, and its test cannot run without it:', file=sys.stderr)
        for name, refused in missing:
            print(f'  {name}: {refused}', file=sys.stderr)
        print('Grant the permission and run again; what was written above stands.',
              file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
