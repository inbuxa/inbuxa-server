#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""What happens on the imported store after the move: delivery through the
imported Sieve filter, search over imported mail, and re-saving a filter that
uses a pre-rename extension name."""
import json, smtplib, sys, time, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jmap import Jmap

BASE = sys.argv[1]
alice = Jmap(BASE, "alice@example.org", "alice-fixture-pass-1")
acct = alice.account_id()

failed = []


def ok(label, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + label + (f": {detail}" if detail and not cond else ""))
    if not cond:
        failed.append(label)

# 1. Delivery: the imported filter files "kickoff" mail into Projects.
with smtplib.SMTP("127.0.0.1", 18025, timeout=300) as s:
    s.sendmail("dave@example.net", ["alice@example.org"],
               b"From: dave@example.net\r\nTo: alice@example.org\r\nSubject: Second kickoff\r\n"
               b"Message-ID: <k2@example.net>\r\n\r\nAgain.\r\n")
found = []
for _ in range(30):
    r = alice.call(("Email/query", {"accountId": acct, "filter": {"subject": "Second kickoff"}}),
                   ("Email/get", {"accountId": acct, "#ids": {"resultOf": "0", "name": "Email/query", "path": "/ids"},
                                  "properties": ["mailboxIds"]}),
                   ("Mailbox/get", {"accountId": acct, "ids": None, "properties": ["name"]}))
    found = r[1]["list"]
    if found:
        break
    time.sleep(1)
names = {m["id"]: m["name"] for m in r[2]["list"]}
ok("delivery after import", bool(found))
ok("imported filter ran", bool(found) and [names[b] for b in found[0]["mailboxIds"]] == ["Projects"],
   found and [names[b] for b in found[0]["mailboxIds"]])

# 2. Search over imported mail, once the queued reindex has run.
hits = []
# Each account's reindex is spread over the first five minutes after start.
for _ in range(400):
    hits = alice.call(("Email/query", {"accountId": acct, "filter": {"text": "quarterly"}}))[0]["ids"]
    if len(hits) >= 2:
        break
    time.sleep(1)
ok("search finds imported mail", len(hits) >= 2, f"{len(hits)} of 2 found")

# 3. Re-saving the imported filter, which says vnd.stalwart.expressions.
s = alice.call(("SieveScript/get", {"accountId": acct, "ids": None}))[0]["list"]
script = next(x for x in s if x["name"] == "filters")
blob = alice.upload(b'require ["fileinto", "vnd.stalwart.expressions"];\r\nlet "who" "envelope.from";\r\n'
                    b'if header :contains "subject" "kickoff" { fileinto "Projects"; }\r\n', "application/sieve")
r = alice.call(("SieveScript/set", {"accountId": acct, "update": {script["id"]: {"blobId": blob}}}))[0]
ok("re-saving a pre-rename filter", not r.get("notUpdated"), r.get("notUpdated"))

# 4. The 0.16 web interface left in the registry.
A = json.load(open(os.path.join(os.environ["FIXTURE"], "admin.json")))
adm = Jmap(BASE, A["username"], A["secret"], ["urn:inbuxa:jmap:registry"])
apps = adm.call(("x:Application/get", {"ids": None}))[0]["list"]
print("INFO applications:", [(a.get("description"), a.get("enabled"), a.get("resourceUrl")) for a in apps])
sys.exit(1 if failed else 0)
