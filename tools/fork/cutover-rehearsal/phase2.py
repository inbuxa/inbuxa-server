#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 2: the cutover sequence of docs/spec/cutover.md, then its checks.

Side by side: the old install is stopped and left untouched, its store is
copied, and the fork is started on the copy. Then every check under "Before
letting mail flow" that this harness can make, each one reported as what it
proves rather than as a green line.
"""
import imaplib, json, os, shutil, socket, ssl, subprocess, sys, time
from email.message import EmailMessage
import smtplib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib

HERE = os.path.dirname(os.path.abspath(__file__))
ADMIN_PW = "cutover-rehearsal-pw"
PEOPLE = {"alice": "alice-pw-7f21", "bob": "bob-pw-93c4", "carol": "carol-pw-15ab"}
TENANT_ADMIN_PW = "tadmin-pw-4b81"


def port_open(port):
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) == 0


def main():
    before = json.load(open(f"{HERE}/before.json"))
    old_dir = lib.INSTALLS["old"]["dir"]
    new_dir = lib.INSTALLS["new"]["dir"]

    print("== phase 2: the cutover sequence\n")

    print("-- step 2: stop the old install, and make sure it cannot come back")
    lib.stop("old")
    time.sleep(2)
    lib.check(not port_open(lib.SMTP), "port 25 released by the old install")
    lib.check(not port_open(lib.HTTP), "http port released by the old install")
    gone = lib.docker("ps", "-a", "--filter", "name=cutover-old", "--format", "{{.Names}}",
                      check_rc=False).stdout.strip()
    lib.check(gone == "", "the old install cannot restart onto the ports",
              "container removed; the systemd `disable` step has no analogue here")

    print("\n-- step 3: copy the store (a copy, never a move)")
    t0 = time.time()
    shutil.rmtree(f"{new_dir}/data", ignore_errors=True)
    shutil.rmtree(f"{new_dir}/etc", ignore_errors=True)
    shutil.copytree(f"{old_dir}/data", f"{new_dir}/data")
    shutil.copytree(f"{old_dir}/etc", f"{new_dir}/etc")
    copied = time.time() - t0
    size = subprocess.run(["du", "-sb", f"{new_dir}/data"], capture_output=True,
                          text=True).stdout.split()[0]
    lib.check(os.path.isdir(f"{old_dir}/data"), "the original store is still there — the rollback")
    print(f"     copied {int(size)/1e6:.1f} MB in {copied:.1f}s")

    # The env file travels too, still using the STALWART_* names, which is
    # what the host will look like on the day.
    shutil.copy(f"{old_dir}/env", f"{new_dir}/env")

    print("\n-- steps 4-5: start the fork on the copy, and read the log before opening the ports")
    if not lib.start("new"):
        print(lib.logs("new"))
        sys.exit("the fork did not come up on the copied store")
    log = lib.logs("new", "200")
    lib.check(True, "the fork started on a store the old build wrote")

    version = subprocess.run([f"{lib.ROOT}/target/debug/inbuxa", "--version"],
                             capture_output=True, text=True).stdout.strip()
    lib.check(version == "2026.9.18 (Stalwart 0.16.22)",
              "the version string names the upstream base the data belongs to", version)

    fallback = [l for l in log.splitlines() if "STALWART_" in l or "deprecated" in l.lower()]
    lib.check(True, f"boot warnings about STALWART_* names: {len(fallback)} line(s)",
              "SPEC 2.5 — see below" if fallback else "none emitted")
    licence = [l for l in log.splitlines() if "licen" in l.lower()]
    lib.check(not licence, "no complaint about the Enterprise licence object",
              licence[0][:120] if licence else "")
    errors = [l for l in log.splitlines() if "ERROR" in l]
    lib.check(not errors, "no errors in the fork's startup log",
              errors[0][:160] if errors else "")

    print("\n-- step 7: before letting mail flow")
    admin = before["admin"]

    served = lib.one(admin, ADMIN_PW, "x:Account/query", {})[1]["ids"]
    lib.check(sorted(served) == before["tenantView"]["serverAccounts"],
              "every account is present, and the administrator signs in with its old password")

    for name, secret in PEOPLE.items():
        addr = f"{name}@{lib.DOMAIN}"
        try:
            s = lib.session(addr, secret)
            ok = bool(s.get("accounts"))
        except Exception as e:
            ok = False
        lib.check(ok, f"{name} signs in over JMAP with the password it had")

    for name, secret in PEOPLE.items():
        addr = f"{name}@{lib.DOMAIN}"
        got = mailbox(addr, secret, before["accounts"][name])
        want = before["mail"][name]
        same = got["count"] == want["count"] and got["subjects"] == want["subjects"]
        lib.check(same, f"{name}'s mail is exactly as it was",
                  f"{got['count']} vs {want['count']}")

    # IMAP, which nothing in the compat suite exercises.
    ctx = lib.tls_context()
    for name, secret in PEOPLE.items():
        try:
            with imaplib.IMAP4_SSL("127.0.0.1", lib.IMAPS, ssl_context=ctx) as m:
                m.login(f"{name}@{lib.DOMAIN}", secret)
                typ, data = m.select("INBOX")
                count = int(data[0]) if typ == "OK" else -1
            ok = count == before["mail"][name]["inbox"]
        except Exception as e:
            ok, count = False, str(e)[:60]
        lib.check(ok, f"{name} signs in over IMAP and sees the same INBOX as before",
                  f"{count} vs {before['mail'][name]['inbox']}")

    tv = tenant_view()
    lib.check(tv["accounts"] == before["tenantView"]["accounts"],
              "the tenant administrator sees exactly its own accounts, as before",
              f"{tv['accounts']} vs {before['tenantView']['accounts']}")
    lib.check(tv["domains"] == before["tenantView"]["domains"],
              "the tenant administrator sees exactly its own domains, as before")
    lib.check(tv["listeners"] == before["tenantView"]["listeners"],
              "the tenant administrator still cannot read listeners", str(tv["listeners"]))

    print("\n-- step 8: let mail flow")
    msg = EmailMessage()
    msg["From"] = "sender@elsewhere.test"
    msg["To"] = f"sales@{lib.DOMAIN}"
    msg["Subject"] = "after the cutover, to the alias"
    msg.set_content("delivered by the fork")
    try:
        with smtplib.SMTP("127.0.0.1", lib.SMTP, timeout=30) as s:
            s.send_message(msg)
        sent_in = True
    except Exception as e:
        sent_in = False
        print("    inbound send failed:", e)
    lib.check(sent_in, "a message from outside is accepted on port 25")

    msg = EmailMessage()
    msg["From"] = f"bob@{lib.DOMAIN}"
    msg["To"] = f"carol@{lib.DOMAIN}"
    msg["Subject"] = "after the cutover, from inside"
    msg.set_content("sent by the fork")
    try:
        with smtplib.SMTP_SSL("127.0.0.1", lib.SUBMISSIONS, context=ctx, timeout=30) as s:
            s.login(f"bob@{lib.DOMAIN}", PEOPLE["bob"])
            s.send_message(msg)
        sent_out = True
    except Exception as e:
        sent_out = False
        print("    submission failed:", e)
    lib.check(sent_out, "an authenticated submission is accepted on port 465")

    time.sleep(8)
    alice = mailbox(f"alice@{lib.DOMAIN}", PEOPLE["alice"], before["accounts"]["alice"])
    lib.check("after the cutover, to the alias" in alice["subjects"],
              "the alias still delivers after the move")
    carol = mailbox(f"carol@{lib.DOMAIN}", PEOPLE["carol"], before["accounts"]["carol"])
    lib.check("after the cutover, from inside" in carol["subjects"],
              "mail sent from inside is delivered by the fork")

    q = lib.one(admin, ADMIN_PW, "x:QueuedMessage/query", {})
    depth = len(q[1].get("ids", [])) if q[0] != "error" else "unreadable"
    lib.check(q[0] != "error" and len(q[1].get("ids", [])) == 0,
              "the queue is empty — nothing stuck behind the move", f"depth {depth}")

    json.dump({"log_fallback_lines": fallback, "version": version},
              open(f"{HERE}/phase2_notes.json", "w"), indent=1)

    ok = lib.summary("phase 2")
    if fallback:
        print("\n  STALWART_* fallback warnings observed:")
        for l in fallback[:6]:
            print("   ", l.strip()[:150])
    sys.exit(0 if ok else 1)


def mailbox(addr, secret, account_id):
    q = lib.jmap(addr, secret, [["Email/query", {"accountId": account_id}, "0"]])
    ids = q[0][1].get("ids", [])
    subs = []
    if ids:
        g = lib.jmap(addr, secret, [["Email/get", {"accountId": account_id, "ids": ids,
                                                   "properties": ["subject"]}, "0"]])
        subs = sorted(e.get("subject") or "" for e in g[0][1]["list"])
    return {"count": len(ids), "subjects": subs}


def tenant_view():
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

    return {"accounts": ids_of("x:Account/query"), "domains": ids_of("x:Domain/query"),
            "listeners": ids_of("x:NetworkListener/get", {"ids": None})}


if __name__ == "__main__":
    main()
