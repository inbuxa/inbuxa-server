#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 3: the rollback, and the question cutover.md leaves open.

Rollback, as the plan describes it: stop the fork, bring the old install back
on its untouched store. What it costs is whatever the fork accepted while it
served — this measures that rather than asserting it.

Then the open question: point the old build at the store the fork has been
writing to. cutover.md says this has never been checked and is worth an hour
beforehand rather than an argument at 2am.
"""
import json, os, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib

HERE = os.path.dirname(os.path.abspath(__file__))
ADMIN_PW = "cutover-rehearsal-pw"
PEOPLE = {"alice": "alice-pw-7f21", "bob": "bob-pw-93c4", "carol": "carol-pw-15ab"}


def mailbox(addr, secret, account_id):
    q = lib.jmap(addr, secret, [["Email/query", {"accountId": account_id}, "0"]])
    ids = q[0][1].get("ids", [])
    subs = []
    if ids:
        g = lib.jmap(addr, secret, [["Email/get", {"accountId": account_id, "ids": ids,
                                                   "properties": ["subject"]}, "0"]])
        subs = sorted(e.get("subject") or "" for e in g[0][1]["list"])
    return {"count": len(ids), "subjects": subs}


def main():
    before = json.load(open(f"{HERE}/before.json"))
    admin = before["admin"]

    print("== phase 3: the rollback\n")

    # What the fork accepted while it served. This is the cost.
    after_fork = {n: mailbox(f"{n}@{lib.DOMAIN}", s, before["accounts"][n])
                  for n, s in PEOPLE.items()}
    gained = {n: after_fork[n]["count"] - before["mail"][n]["count"] for n in PEOPLE}
    print("  messages the fork accepted that the old store never saw:", gained)

    print("\n-- stop the fork, bring the old install back")
    t0 = time.time()
    lib.stop("new")
    if not lib.start("old"):
        print(lib.logs("old"))
        sys.exit("the old install did not come back")
    elapsed = time.time() - t0
    lib.check(True, f"rolled back in {elapsed:.1f}s", "stop the fork, start the old unit")

    served = lib.one(admin, ADMIN_PW, "x:Account/query", {})[1]["ids"]
    lib.check(sorted(served) == before["tenantView"]["serverAccounts"],
              "every account is back, on the untouched store")

    for name, secret in PEOPLE.items():
        got = mailbox(f"{name}@{lib.DOMAIN}", secret, before["accounts"][name])
        want = before["mail"][name]
        lib.check(got["count"] == want["count"] and got["subjects"] == want["subjects"],
                  f"{name}'s mail is exactly the pre-cutover state",
                  f"{got['count']} vs {want['count']}")

    lost = sum(v for v in gained.values() if v > 0)
    lib.check(True, f"the rollback leaves {lost} message(s) behind in the fork's store",
              "the documented cost — the two stores diverge from the moment the fork starts")

    print("\n== the open question: can the old build read a store the fork has written?\n")
    lib.stop("old")
    time.sleep(2)

    spec = lib.INSTALLS["new"]
    name = "cutover-reverse"
    lib.docker("rm", "-f", name, check_rc=False)
    lib.docker(
        "run", "-d", "--name", name,
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--cap-add", "NET_BIND_SERVICE",
        "--entrypoint", "/usr/local/bin/stalwart",
        "-v", f"{lib.ROOT}/target/debug/stalwart:/usr/local/bin/stalwart:ro",
        "-v", f"{spec['dir']}/etc:/etc/stalwart",
        "-v", f"{spec['dir']}/data:/var/lib/stalwart",
        "-p", f"127.0.0.1:{lib.HTTP}:8080",
        "--env-file", f"{spec['dir']}/env",
        lib.IMAGE, "--config", "/etc/stalwart/config.json",
    )
    up = lib.wait_http(90)
    log = (lib.docker("logs", "--tail", "120", name, check_rc=False).stdout or "") + \
          (lib.docker("logs", "--tail", "120", name, check_rc=False).stderr or "")
    lib.check(up, "the old build boots on a store the fork has written")

    if up:
        try:
            ids = sorted(lib.one(admin, ADMIN_PW, "x:Account/query", {})[1]["ids"])
            lib.check(ids == before["tenantView"]["serverAccounts"],
                      "the old build reads back every account from the fork's store",
                      f"{len(ids)} accounts")
        except Exception as e:
            lib.check(False, "the old build reads back every account from the fork's store",
                      str(e)[:120])
        try:
            got = mailbox(f"bob@{lib.DOMAIN}", PEOPLE["bob"], before["accounts"]["bob"])
            lib.check(got["count"] >= before["mail"]["bob"]["count"],
                      "the old build reads mail the fork delivered", str(got["subjects"]))
        except Exception as e:
            lib.check(False, "the old build reads mail the fork delivered", str(e)[:120])
    errs = [l for l in log.splitlines() if "ERROR" in l]
    lib.check(not errs, "no errors from the old build on the fork's store",
              errs[0][:160] if errs else "")

    lib.docker("rm", "-f", name, check_rc=False)
    ok = lib.summary("phase 3")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
