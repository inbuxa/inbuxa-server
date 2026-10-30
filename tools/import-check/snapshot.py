#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""Print a server's fixture data as id-free JSON, so a 0.16.27 source and an
inbuxa target can be compared field by field."""
import json, sys, urllib.request, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jmap import Jmap

BASE = sys.argv[1]
A = json.load(open(os.path.join(os.environ["FIXTURE"], "admin.json")))
PW = {"alice": "alice-fixture-pass-1", "bob": "bob-fixture-pass-2", "carol": "carol-fixture-pass-3"}
DOMAIN = {"carol": "acme.example.com"}
REGISTRY_CAPS = ["urn:stalwart:jmap", "urn:inbuxa:jmap:registry"]


def admin_client():
    # The registry capability changed name; ask the session which one it has.
    probe = Jmap(BASE, A["username"], A["secret"])
    caps = [c for c in REGISTRY_CAPS if c in probe.session["capabilities"]]
    return Jmap(BASE, A["username"], A["secret"], caps)


def admin_view():
    j = admin_client()
    r = j.call(("x:Domain/get", {"ids": None}), ("x:Account/get", {"ids": None}),
               ("x:Role/get", {"ids": None}), ("x:DkimSignature/get", {"ids": None}))
    domains = {d["id"]: d["name"] for d in r[0]["list"]}
    names = {a["id"]: a["name"] for a in r[1]["list"]}
    roles = {x["id"]: x.get("description") for x in r[2]["list"]}
    accounts = {}
    for a in r[1]["list"]:
        role = a.get("roles") or {}
        accounts[a["name"]] = {
            "type": a["@type"], "description": a.get("description"),
            "domain": domains.get(a.get("domainId")), "tenant": a.get("memberTenantId") is not None,
            "aliases": sorted(f'{x["name"]}@{domains.get(x["domainId"])}' for x in (a.get("aliases") or {}).values()),
            "groups": sorted(names.get(g, g) for g in (a.get("memberGroupIds") or {})),
            "quotas": a.get("quotas") or {},
            "roles": [role.get("@type")] + sorted(roles.get(i, i) for i in (role.get("roleIds") or {})),
        }
    role_perms = {x["description"]: {"enabled": sorted(k for k, v in (x.get("enabledPermissions") or {}).items() if v),
                                     "disabled": sorted(k for k, v in (x.get("disabledPermissions") or {}).items() if v),
                                     "inherits": sorted(roles.get(i, i) for i in (x.get("roleIds") or {}))}
                  for x in r[2]["list"]}
    dkim = sorted(f'{domains.get(d.get("domainId"), "?")} {d["@type"]}' for d in r[3]["list"])
    r = j.call(("x:Tenant/get", {"ids": None}), ("x:Application/get", {"ids": None}))
    tenants = {t["id"]: t["name"] for t in r[0]["list"]}
    apps = sorted(f'{x.get("description")} enabled={x.get("enabled")} {x.get("resourceUrl")}' for x in r[1]["list"])
    return {"domains": sorted(domains.values()), "accounts": accounts, "roles": role_perms, "dkim": dkim,
            "tenants": sorted(t["name"] for t in r[0]["list"]), "applications": apps}


def user_view(name):
    j = Jmap(BASE, f"{name}@{DOMAIN.get(name, 'example.org')}", PW[name])
    acct = j.account_id()
    r = j.call(("Mailbox/get", {"accountId": acct, "ids": None}))
    boxes = {m["id"]: m for m in r[0]["list"]}

    def path(mid):
        m = boxes[mid]
        return (path(m["parentId"]) + "/" if m.get("parentId") else "") + m["name"]

    mailboxes = {path(m["id"]): {"role": m.get("role"), "total": m["totalEmails"], "unread": m["unreadEmails"]}
                 for m in boxes.values()}
    r = j.call(("Email/query", {"accountId": acct}),
               ("Email/get", {"accountId": acct, "#ids": {"resultOf": "0", "name": "Email/query", "path": "/ids"},
                              "properties": ["subject", "mailboxIds", "keywords", "threadId", "hasAttachment",
                                             "size", "receivedAt", "messageId"]}))
    threads = {}
    for e in r[1]["list"]:
        threads.setdefault(e["threadId"], []).append(e["subject"])
    emails = sorted(({"subject": e["subject"], "mailboxes": sorted(path(b) for b in e["mailboxIds"]),
                      "keywords": sorted(k for k in e["keywords"] if not k.startswith("$has")),
                      "thread": sorted(threads[e["threadId"]]), "hasAttachment": e["hasAttachment"],
                      "size": e["size"], "receivedAt": e["receivedAt"], "messageId": e["messageId"]}
                     for e in r[1]["list"]), key=lambda e: e["subject"])
    r = j.call(("CalendarEvent/get", {"accountId": acct, "ids": None}),
               ("ContactCard/get", {"accountId": acct, "ids": None}),
               ("SieveScript/get", {"accountId": acct, "ids": None}),
               ("VacationResponse/get", {"accountId": acct, "ids": ["singleton"]}))
    events = sorted([{"title": e.get("title"), "start": e.get("start"), "timeZone": e.get("timeZone"),
                      "duration": e.get("duration"), "rrule": (e.get("recurrenceRule") or {}).get("frequency")}
                     for e in r[0]["list"]], key=lambda e: e["title"] or "")
    cards = sorted([{"name": (c.get("name") or {}).get("full"),
                     "emails": sorted(x["address"] for x in (c.get("emails") or {}).values())}
                    for c in r[1]["list"]], key=lambda c: c["name"] or "")
    sieve = []
    for s in r[2]["list"]:
        url = j.session["downloadUrl"].replace("{accountId}", acct).replace("{blobId}", s["blobId"]) \
            .replace("{name}", "s").replace("{type}", "application/sieve")
        url = j.local(url)
        req = urllib.request.Request(url, headers=j.auth)
        sieve.append({"name": s["name"], "isActive": s["isActive"],
                      "content": urllib.request.urlopen(req).read().decode()})
    v = r[3]["list"][0]
    vacation = {k: v.get(k) for k in ("isEnabled", "subject", "textBody")}
    shared = sorted(a["name"] for k, a in j.session["accounts"].items() if k != acct)
    return {"mailboxes": mailboxes, "emails": emails, "events": events, "contacts": cards,
            "sieve": sorted(sieve, key=lambda s: s["name"]), "vacation": vacation, "sharedAccounts": shared}


print(json.dumps({"admin": admin_view(), "alice": user_view("alice"), "bob": user_view("bob"),
                  "carol": user_view("carol")},
                 indent=2, sort_keys=True))
