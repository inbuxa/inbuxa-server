#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""Fill a fresh 0.16.27 server with a small, varied data set for the import fixture."""
import json, sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jmap import Jmap

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:18090"
A = json.load(open(os.path.join(os.environ["FIXTURE"], "admin.json")))
adm = Jmap(BASE, A["username"], A["secret"], ["urn:stalwart:jmap"])
PW = {"alice": "alice-fixture-pass-1", "bob": "bob-fixture-pass-2"}

domain = adm.call(("x:Domain/query", {}))[0]["ids"][0]

# Bootstrap makes an Ed25519 key, then an RSA one a moment later.
import time
for _ in range(60):
    if len(adm.call(("x:DkimSignature/query", {}))[0]["ids"]) >= 2:
        break
    time.sleep(1)
else:
    raise SystemExit("DKIM keys never appeared")

# A tenant with its own domain and one user (multi-tenancy is AGPL in 0.16).
r = adm.call(("x:Tenant/set", {"create": {"t": {"name": "acme"}}}))
tenant = adm.set_ok(r[0])["t"]["id"]
r = adm.call(("x:Domain/set", {"create": {"d": {"name": "acme.example.com", "memberTenantId": tenant}}}))
acme_domain = adm.set_ok(r[0])["d"]["id"]


def user(name, extra=None):
    u = {"@type": "User", "name": name, "domainId": domain, "description": f"{name.title()} Example",
         "credentials": {"0": {"@type": "Password", "secret": PW[name]}},
         "roles": {"@type": "User"}, "permissions": {"@type": "Inherit"}, "quotas": {},
         "aliases": {}, "memberGroupIds": {}, "encryptionAtRest": {"@type": "Disabled"}}
    u.update(extra or {})
    return u


existing = [x["id"] for x in adm.call(("x:Role/get", {"ids": None}))[0]["list"] if x.get("description") == "Helpdesk"]
r = [{"created": {"helpdesk": {"id": existing[0]}}}] if existing else adm.call(
    ("x:Role/set", {"create": {"helpdesk": {
        "description": "Helpdesk", "roleIds": {},
        "enabledPermissions": {"sysAccountGet": True, "sysAccountQuery": True, "sysQueuedMessageGet": True},
        "disabledPermissions": {}}}}),
)
role = adm.set_ok(r[0])["helpdesk"]["id"]
user_role = next(x["id"] for x in adm.call(("x:Role/get", {"ids": None}))[0]["list"] if x.get("description") == "User")
r = adm.call(("x:Account/set", {"create": {"sales": {
    "@type": "Group", "name": "sales", "domainId": domain, "description": "Sales team",
    "roles": {"@type": "Default"}, "permissions": {"@type": "Inherit"}, "quotas": {}, "aliases": {}}}}))
group = adm.set_ok(r[0])["sales"]["id"]
r = adm.call(("x:Account/set", {"create": {
    "alice": user("alice", {"memberGroupIds": {group: True},
                            "aliases": {"0": {"name": "a.example", "domainId": domain, "enabled": True,
                                              "description": None}},
                            "roles": {"@type": "Custom", "roleIds": {user_role: True, role: True}}}),
    "bob": user("bob", {"memberGroupIds": {group: True}, "quotas": {"maxDiskQuota": 50_000_000}}),
}}))
ids = adm.set_ok(r[0])
r = adm.call(("x:Account/set", {"create": {"carol": {
    "@type": "User", "name": "carol", "domainId": acme_domain, "description": "Carol Acme",
    "memberTenantId": tenant, "credentials": {"0": {"@type": "Password", "secret": "carol-fixture-pass-3"}},
    "roles": {"@type": "User"}, "permissions": {"@type": "Inherit"}, "quotas": {}, "aliases": {},
    "memberGroupIds": {}, "encryptionAtRest": {"@type": "Disabled"}}}}))
adm.set_ok(r[0])
print("accounts", {k: v["id"] for k, v in ids.items()}, "group", group, "role", role)

MSGS = [
    ("Quarterly numbers", "carol@example.net", "alice@example.org", "<q1@example.net>", None,
     "Here are the numbers for the quarter.", ["$seen"], "Inbox"),
    ("Re: Quarterly numbers", "alice@example.org", "carol@example.net", "<q2@example.org>", "<q1@example.net>",
     "Thanks, looks good.", ["$seen", "$answered"], "Inbox"),
    ("Project kickoff", "dave@example.net", "alice@example.org", "<k1@example.net>", None,
     "Kickoff is Monday at 10.", ["$flagged"], "Projects"),
    ("Invoice attached", "billing@example.net", "alice@example.org", "<i1@example.net>", None,
     None, [], "Inbox"),
]


def rfc822(subject, frm, to, mid, reply, body, attach):
    head = (f"From: {frm}\r\nTo: {to}\r\nSubject: {subject}\r\nMessage-ID: {mid}\r\n"
            f"Date: Mon, 26 Oct 2026 09:00:00 +0000\r\nMIME-Version: 1.0\r\n")
    if reply:
        head += f"In-Reply-To: {reply}\r\nReferences: {reply}\r\n"
    if not attach:
        return (head + "Content-Type: text/plain; charset=utf-8\r\n\r\n" + body + "\r\n").encode()
    return (head + 'Content-Type: multipart/mixed; boundary="b1"\r\n\r\n--b1\r\n'
            "Content-Type: text/plain; charset=utf-8\r\n\r\nInvoice for October.\r\n--b1\r\n"
            'Content-Type: application/pdf; name="invoice.pdf"\r\nContent-Disposition: attachment; '
            'filename="invoice.pdf"\r\nContent-Transfer-Encoding: base64\r\n\r\n'
            "JVBERi0xLjQKJcOkw7zDtsOfCjEgMCBvYmoKPDw+PgplbmRvYmoKdHJhaWxlcgo8PD4+CiUlRU9GCg==\r\n"
            "--b1--\r\n").encode()


def fill(name):
    j = Jmap(BASE, f"{name}@example.org", PW[name])
    acct = j.account_id()
    boxes = {m["name"]: m["id"] for m in j.call(("Mailbox/get", {"accountId": acct, "ids": None}))[0]["list"]}
    r = j.call(("Mailbox/set", {"accountId": acct, "create": {"p": {"name": "Projects"}}}))
    boxes["Projects"] = j.set_ok(r[0])["p"]["id"]
    r = j.call(("Mailbox/set", {"accountId": acct, "create": {"c": {"name": "2026", "parentId": boxes["Projects"]}}}))
    boxes["2026"] = j.set_ok(r[0])["c"]["id"]
    imports = {}
    for i, (subj, frm, to, mid, reply, body, kw, box) in enumerate(MSGS):
        blob = j.upload(rfc822(subj, frm, to, mid, reply, body, body is None), "message/rfc822")
        imports[str(i)] = {"blobId": blob, "mailboxIds": {boxes[box]: True},
                           "keywords": {k: True for k in kw}, "receivedAt": f"2026-10-26T09:0{i}:00Z"}
    j.set_ok(j.call(("Email/import", {"accountId": acct, "emails": imports}))[0])

    cals = j.call(("Calendar/get", {"accountId": acct, "ids": None}))[0]["list"]
    r = j.call(("CalendarEvent/set", {"accountId": acct, "create": {"e": {
        "calendarIds": {cals[0]["id"]: True}, "@type": "Event", "title": "Team standup",
        "start": "2026-11-02T09:30:00", "timeZone": "America/Phoenix", "duration": "PT15M",
        "recurrenceRule": {"@type": "RecurrenceRule", "frequency": "weekly", "byDay": [{"@type": "NDay", "day": "mo"}]}}}}))
    j.set_ok(r[0])
    books = j.call(("AddressBook/get", {"accountId": acct, "ids": None}))[0]["list"]
    r = j.call(("ContactCard/set", {"accountId": acct, "create": {"c": {
        "addressBookIds": {books[0]["id"]: True}, "@type": "Card", "version": "1.0", "kind": "individual",
        "name": {"@type": "Name", "full": "Carol Client"},
        "emails": {"e1": {"@type": "EmailAddress", "address": "carol@example.net"}}}}}))
    j.set_ok(r[0])

    script = ('require ["fileinto", "vnd.stalwart.expressions"];\r\n'
              'let "who" "envelope.from";\r\n'
              'if header :contains "subject" "kickoff" { fileinto "Projects"; }\r\n').encode()
    blob = j.upload(script, "application/sieve")
    r = j.call(("SieveScript/set", {"accountId": acct, "create": {"s": {"name": "filters", "blobId": blob}},
                                     "onSuccessActivateScript": "#s"}))
    j.set_ok(r[0])
    r = j.call(("VacationResponse/set", {"accountId": acct, "update": {"singleton": {
        "isEnabled": False, "subject": "Away", "textBody": "Back on Monday."}}}))
    j.set_ok(r[0], "updated")
    return j, acct, boxes


alice, a_acct, a_boxes = fill("alice")
bob, b_acct, b_boxes = fill("bob")

# bob shares his Projects folder with alice, read-only
principals = bob.call(("Principal/query", {"accountId": b_acct, "filter": {"email": "alice@example.org"}}))[0]["ids"]
r = bob.call(("Mailbox/set", {"accountId": b_acct, "update": {b_boxes["Projects"]: {
    "shareWith": {principals[0]: {"mayReadItems": True}}}}}))
bob.set_ok(r[0], "updated")
print("populated")
