#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs
# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 1: build the "old" install from nothing and record what must survive.

Upstream stalwart 0.16.22 stands in for the Enterprise install: bootstrapped,
then given a domain, three accounts with known passwords, an alias, a tenant
with its own administrator, and mail that arrived from outside and mail sent
from inside. Writes before.json — the fingerprint phase 2 compares against.

Starts by destroying anything from an earlier run, so it is repeatable.
"""
import imaplib, json, os, subprocess, sys, time
from email.message import EmailMessage
import smtplib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib

HERE = os.path.dirname(os.path.abspath(__file__))
ADMIN_PW = "cutover-rehearsal-pw"
PEOPLE = {"alice": "alice-pw-7f21", "bob": "bob-pw-93c4", "carol": "carol-pw-15ab"}
TENANT_ADMIN_PW = "tadmin-pw-4b81"
TENANT_USER_PW = "tuser-pw-9e02"


def fresh():
    lib.stop("old")
    lib.stop("new")
    subprocess.run(["rm", "-rf", lib.BASE], check=False)
    for w in ("old", "new"):
        for sub in ("etc", "data"):
            os.makedirs(f"{lib.INSTALLS[w]['dir']}/{sub}", exist_ok=True)
    with open(f"{lib.INSTALLS['old']['dir']}/env", "w") as f:
        f.write(f"STALWART_RECOVERY_ADMIN=admin:{ADMIN_PW}\n")
        f.write(f"STALWART_PUBLIC_URL=http://127.0.0.1:{lib.HTTP}\n")


def main():
    print("== phase 1: the old install (upstream stalwart 0.16.22)")
    fresh()

    print("  booting into bootstrap mode ...")
    if not lib.start("old"):
        sys.exit("old install did not come up:\n" + lib.logs("old"))

    got = lib.one("admin", ADMIN_PW, "x:Bootstrap/get", {"ids": None})
    sid = got[1]["list"][0]["id"]
    res = lib.one("admin", ADMIN_PW, "x:Bootstrap/set", {"update": {sid: {
        "serverHostname": lib.HOSTNAME, "defaultDomain": lib.DOMAIN,
        "requestTlsCertificate": False}}})
    upd = res[1].get("updated", {}).get(sid)
    if not upd:
        sys.exit("bootstrap failed: " + json.dumps(res)[:500])
    user, pw = upd["username"], upd["secret"]
    print("  bootstrapped:", user)

    # Bootstrap mode only ends on the next start, and the recovery admin
    # stops authenticating once there is a real administrator.
    print("  restarting, holding the mail ports ...")
    lib.stop("old")
    if not lib.start("old"):
        sys.exit("old install did not come back up:\n" + lib.logs("old"))

    ids = lib.one(user, pw, "x:Account/query", {"filter": {"name": "admin"}})[1].get("ids", [])
    lib.one(user, pw, "x:Account/set", {"update": {ids[0]: {
        "credentials": {"0": {"@type": "Password", "secret": ADMIN_PW}}}}})
    pw = ADMIN_PW

    def create(kind, obj):
        r = lib.one(user, pw, f"x:{kind}/set", {"create": {"n": obj}})
        c = r[1].get("created", {}).get("n")
        if not c:
            sys.exit(f"create {kind} failed: {json.dumps(r)[:400]}")
        return c["id"]

    domain = lib.one(user, pw, "x:Domain/query", {})[1]["ids"][0]

    accounts = {}
    for name, secret in PEOPLE.items():
        obj = {"@type": "User", "name": name, "domainId": domain,
               "description": f"{name.title()} Example",
               "credentials": {"0": {"@type": "Password", "secret": secret}}}
        if name == "alice":
            obj["aliases"] = {"0": {"name": "sales", "domainId": domain, "enabled": True,
                                    "description": "Sales"}}
        accounts[name] = create("Account", obj)
    print("  accounts:", accounts)

    # A tenant, with membership set after create (it is refused on create,
    # and does not come down from the domain). Without memberTenantId an
    # account is server-wide and a tenant "admin" is a server administrator.
    tenant = create("Tenant", {"name": "Acme"})
    tdomain = create("Domain", {"name": f"acme.{lib.DOMAIN}", "memberTenantId": tenant,
                                "certificateManagement": {"@type": "Manual"},
                                "dnsManagement": {"@type": "Manual"}})
    tadmin = create("Account", {"@type": "User", "name": "tadmin", "domainId": tdomain,
                                "roles": {"@type": "Admin"},
                                "credentials": {"0": {"@type": "Password", "secret": TENANT_ADMIN_PW}}})
    tuser = create("Account", {"@type": "User", "name": "tuser", "domainId": tdomain,
                               "credentials": {"0": {"@type": "Password", "secret": TENANT_USER_PW}}})
    for acct in (tadmin, tuser):
        lib.one(user, pw, "x:Account/set", {"update": {acct: {"memberTenantId": tenant}}})
    print(f"  tenant={tenant} domain={tdomain} admin={tadmin} user={tuser}")

    ctx = lib.tls_context()
    for rcpt, subject in ((f"alice@{lib.DOMAIN}", "from the outside world"),
                          (f"sales@{lib.DOMAIN}", "to the alias"),
                          (f"bob@{lib.DOMAIN}", "second delivery")):
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = "sender@elsewhere.test", rcpt, subject
        msg.set_content("rehearsal body")
        with smtplib.SMTP("127.0.0.1", lib.SMTP, timeout=30) as s:
            s.send_message(msg)

    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = f"alice@{lib.DOMAIN}", f"bob@{lib.DOMAIN}", "from inside"
    msg.set_content("sent before the cutover")
    with smtplib.SMTP_SSL("127.0.0.1", lib.SUBMISSIONS, context=ctx, timeout=30) as s:
        s.login(f"alice@{lib.DOMAIN}", PEOPLE["alice"])
        s.send_message(msg)

    print("  waiting for delivery ...")
    time.sleep(8)

    before = {"admin": user, "domain": domain, "accounts": accounts,
              "tenant": {"id": tenant, "domain": tdomain, "admin": tadmin, "user": tuser},
              "mail": {}, "tenantView": tenant_view(user, pw)}
    for name, secret in PEOPLE.items():
        before["mail"][name] = mailbox(f"{name}@{lib.DOMAIN}", secret, accounts[name])
        # IMAP's INBOX is not JMAP's whole account — the spam filter files
        # some of this mail elsewhere. Record both, so phase 2 compares each
        # against itself rather than against the other.
        before["mail"][name]["inbox"] = imap_count(f"{name}@{lib.DOMAIN}", secret)
        print(f"  {name}: {before['mail'][name]['count']} message(s) "
              f"(INBOX {before['mail'][name]['inbox']}) {before['mail'][name]['subjects']}")

    json.dump(before, open(f"{HERE}/before.json", "w"), indent=1)
    print("  wrote before.json")


def imap_count(addr, secret):
    """Messages in INBOX over IMAP, or -1 if the sign-in itself failed."""
    try:
        with imaplib.IMAP4_SSL("127.0.0.1", lib.IMAPS, ssl_context=lib.tls_context()) as m:
            m.login(addr, secret)
            typ, data = m.select("INBOX")
            return int(data[0]) if typ == "OK" else -1
    except Exception:
        return -1


def mailbox(addr, secret, account_id):
    q = lib.jmap(addr, secret, [["Email/query", {"accountId": account_id}, "0"]])
    ids = q[0][1].get("ids", [])
    subs = []
    if ids:
        g = lib.jmap(addr, secret, [["Email/get", {"accountId": account_id, "ids": ids,
                                                   "properties": ["subject"]}, "0"]])
        subs = sorted(e.get("subject") or "" for e in g[0][1]["list"])
    return {"count": len(ids), "subjects": subs}


def tenant_view(server_user, server_pw):
    """What the tenant administrator can see, recorded from the old server."""
    ta = f"tadmin@acme.{lib.DOMAIN}"

    def ids_of(method, args=None):
        r = lib.one(ta, TENANT_ADMIN_PW, method, args or {})
        if r[0] == "error":
            return {"error": r[1].get("type")}
        body = r[1]
        if "ids" in body:
            return sorted(body["ids"])
        if "list" in body:
            return sorted(x["id"] for x in body["list"])
        return {"unexpected": list(body.keys())}

    view = {
        "accounts": ids_of("x:Account/query"),
        "domains": ids_of("x:Domain/query"),
        "tenants": ids_of("x:Tenant/get", {"ids": None}),
        "listeners": ids_of("x:NetworkListener/get", {"ids": None}),
        "serverAccounts": sorted(lib.one(server_user, server_pw,
                                         "x:Account/query", {})[1]["ids"]),
    }
    print("  tenant admin sees accounts:", view["accounts"], "domains:", view["domains"])
    print("  tenant admin listeners:", view["listeners"])
    print("  server admin sees accounts:", view["serverAccounts"])
    return view


if __name__ == "__main__":
    main()
