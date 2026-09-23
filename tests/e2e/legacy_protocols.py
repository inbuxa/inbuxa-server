#!/usr/bin/env python3
"""Local end-to-end check of the legacy-protocols switch.

Run it with `python3 tests/e2e/legacy_protocols.py` after
`cargo build -p inbuxa`. Needs Docker. Working state goes under target/e2e.

Boots the debug binary, turns the switch off, and checks that the IMAP and
POP3 ports really stop accepting while SMTP, submission and JMAP keep going.
Then turns it back on and checks the ports come back.

This is the part unit tests cannot reach: whether a socket actually closes on
a running server (LP-2), and whether a listener put back actually binds again
(LP-5). Acceptance tests 15, 17 and 18.

It also checks the second lock (LP-6): while the switch is off, sign-in over
submission -- locked open -- is refused with the spec's words, with the right
password and with a wrong one, and refusals never add up to a disconnect
(LP-11). And that a normal IMAP sign-in works with the switch on, before and
after. And that while it is off, no listener the switch would close can be
created, or made by an update (LP-4, test 4), and nothing advertises what is
closed: autoconfig, autodiscover and PACC offer no IMAP, POP3 or submission,
and the suggested zone marks their SRV names not offered (LP-7, test 5).
Every change of the switch, and every refused sign-in, is an event in the
server's log (LP-8, test 14; LP-6).

Then a tenant's own switch (LP-9 to LP-14a): a tenant administrator turns it
off for its tenant, which refuses sign-in on the tenant's domains -- real
address or made-up, right password or wrong -- in the organization's words,
leaves every other domain alone, and stops client configuration offering
legacy servers for those domains. It reaches only its own tenant's switch,
and can't turn it back on while the server has legacy protocols off
(acceptance tests 6 to 10, 14). Throughout, the JMAP session tells each
account which way its switches point (test 13), and the impact panel's
list names who signed in over what: every account at server scope, only the
tenant's own at tenant scope, rewritten at most once an hour (LP-15).

Passwords are generated into files under target/e2e and never printed.
Everything is removed afterwards unless KEEP=1.
"""
import base64, json, os, secrets, shutil, socket, ssl, subprocess, sys, time, urllib.request, urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DIR = f"{ROOT}/target/e2e"
NAME = "inbuxa-legacy"
HTTP = "http://127.0.0.1:18080"
# port -> how to tell a live server from Docker's proxy. Publishing a port
# makes the host side accept connections whether or not anything is listening
# inside the container, so a bare connect proves nothing: each port has to be
# made to speak.
PORTS = {"imap": 18993, "pop3": 18995, "submissions": 18465, "smtp": 18025}
TLS_PORTS = {18993, 18995, 18465}
SMTP_REFUSAL = ("535 5.7.0 This server allows only inbuxa webmail and JMAP apps. "
                "This mail app can't send.")
INBUXA = "urn:inbuxa:jmap"
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def secret_file(name, value=None):
    path = f"{DIR}/secrets/{name}"
    if value is None:
        value = secrets.token_urlsafe(24)
    with open(path, "w") as f:
        f.write(value)
    os.chmod(path, 0o600)
    return value


def docker(*args, check_rc=True):
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check_rc)


def start(env_file=None):
    args = ["run", "-d", "--name", NAME, "--user", f"{os.getuid()}:{os.getgid()}",
            "--entrypoint", "/usr/local/bin/inbuxa",
            "-v", f"{ROOT}/target/debug/inbuxa:/usr/local/bin/inbuxa:ro",
            "-v", f"{DIR}/etc-legacy:/etc/inbuxa", "-v", f"{DIR}/data-legacy:/var/lib/inbuxa",
            "-p", "127.0.0.1:18080:8080",
            "-p", f"127.0.0.1:{PORTS['submissions']}:465",
            "-p", f"127.0.0.1:{PORTS['imap']}:993",
            "-p", f"127.0.0.1:{PORTS['pop3']}:995",
            "-p", f"127.0.0.1:{PORTS['smtp']}:25"]
    if env_file:
        args += ["--env-file", env_file]
    args += ["stalwartlabs/stalwart:v0.16.22", "--config", "/etc/inbuxa/config.json"]
    docker(*args)
    for _ in range(120):
        try:
            urllib.request.urlopen(f"{HTTP}/.well-known/jmap", timeout=2)
        except urllib.error.HTTPError:
            return
        except Exception:
            time.sleep(1)
            continue
        return
    sys.exit("server didn't come up: " + docker("logs", "--tail", "40", NAME, check_rc=False).stderr)


def stop():
    docker("rm", "-f", NAME, check_rc=False)


def jmap(user, password, calls, using=("urn:ietf:params:jmap:core", "urn:inbuxa:jmap:registry", INBUXA)):
    body = json.dumps({"using": list(using), "methodCalls": calls}).encode()
    req = urllib.request.Request(f"{HTTP}/jmap/", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode())
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)["methodResponses"]


def one(user, password, method, args):
    return jmap(user, password, [[method, args, "0"]])[0]


def session(user, password):
    req = urllib.request.Request(f"{HTTP}/jmap/session")
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode())
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def accepts(port, timeout=5):
    """Whether a server is really answering on this port.

    Docker's published port accepts and then closes when nothing is listening
    in the container, so connecting is not enough. A TLS port must complete a
    handshake; a plain one must send its greeting.
    """
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as raw:
            if port in TLS_PORTS:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(raw):
                    return True
            raw.settimeout(timeout)
            return bool(raw.recv(1))
    except (OSError, ssl.SSLError):
        return False


def tls(port, timeout=10):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=timeout))


def lines(sock):
    """Yields reply lines, CRLF stripped."""
    buf = b""
    while True:
        while b"\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                return
            buf += chunk
        line, buf = buf.split(b"\r\n", 1)
        yield line.decode(errors="replace")


def imap_login(port, user, password):
    """The tagged reply to LOGIN, over implicit TLS."""
    with tls(port) as sock:
        read = lines(sock)
        next(read)  # greeting
        quote = lambda v: '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
        sock.sendall(f"a1 LOGIN {quote(user)} {quote(password)}\r\n".encode())
        for line in read:
            if line.startswith("a1 "):
                return line[3:]
    return ""


def smtp_auths(port, user, passwords):
    """The reply to AUTH PLAIN for each password in turn, on one connection.
    A reply of "" means the server hung up."""
    # Every connection reaches the server from Docker's gateway, one IP, and
    # the stock inbound throttle takes five a second from it. The port checks
    # just before can use those up, so wait the second out.
    time.sleep(1.1)
    replies = []
    with tls(port) as sock:
        read = lines(sock)
        next(read)  # greeting
        sock.sendall(b"EHLO e2e.test\r\n")
        for line in read:
            if line[3:4] == " ":
                break
        for password in passwords:
            token = base64.b64encode(f"\0{user}\0{password}".encode()).decode()
            try:
                sock.sendall(f"AUTH PLAIN {token}\r\n".encode())
                replies.append(next(read, ""))
            except OSError:
                replies.append("")
    return replies


def advertised(admin, admin_pw):
    """What each client-configuration answer and the suggested zone offer."""
    with urllib.request.urlopen(f"{HTTP}/mail/config-v1.1.xml?emailaddress=a@legacy.test",
                                timeout=30) as resp:
        autoconfig = resp.read().decode()
    body = ('<?xml version="1.0" encoding="utf-8"?><Autodiscover xmlns="http://schemas.'
            'microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request>'
            '<EMailAddress>a@legacy.test</EMailAddress><AcceptableResponseSchema>http://'
            'schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a'
            '</AcceptableResponseSchema></Request></Autodiscover>').encode()
    req = urllib.request.Request(f"{HTTP}/autodiscover/autodiscover.xml", data=body, method="POST")
    req.add_header("Content-Type", "text/xml")
    with urllib.request.urlopen(req, timeout=30) as resp:
        autodiscover = resp.read().decode()
    with urllib.request.urlopen(f"{HTTP}/.well-known/user-agent-configuration.json",
                                timeout=30) as resp:
        pacc = json.load(resp).get("protocols", {})
    got = one(admin, admin_pw, "x:Domain/get", {"ids": None, "properties": ["name", "dnsZoneFile"]})
    zone = next((d.get("dnsZoneFile") or "" for d in got[1].get("list", [])
                 if d.get("name") == "legacy.test"), "")
    srv = {}
    for line in zone.splitlines():
        fields = line.split()
        if "SRV" in fields and fields[0].startswith("_"):
            srv[fields[0].split(".")[0] + "." + fields[0].split(".")[1]] = fields[-1]
    return {
        "autoconfig": {t for t in ("imap", "pop3", "smtp") if f'type="{t}"' in autoconfig},
        "autodiscover": {t for t in ("IMAP", "POP3", "SMTP") if f"<Type>{t}</Type>" in autodiscover},
        "pacc": {t for t in ("imap", "pop3", "smtp", "managesieve") if t in pacc},
        "jmap": "jmap" in pacc,
        "srv": srv,
    }


def events(name):
    """The server's log lines for one event, from its stdout tracer. The log
    is the container's, so it starts afresh at every restart."""
    out = docker("logs", NAME, check_rc=False)
    return [l for l in (out.stdout + out.stderr).splitlines() if f"({name})" in l]


def pop3_login(port, user, password):
    """The reply to PASS, over implicit TLS."""
    with tls(port) as sock:
        read = lines(sock)
        next(read)  # greeting
        sock.sendall(f"USER {user}\r\n".encode())
        next(read)
        sock.sendall(f"PASS {password}\r\n".encode())
        return next(read, "")


def created(res, key, what):
    obj = (res[1].get("created") or {}).get(key)
    if not obj:
        sys.exit(f"creating {what} failed: " + json.dumps(res[1])[:600])
    return obj["id"]


def tenant_checks(admin, admin_pw, account):
    """LP-9 to LP-14a, on a tenant with its own domain, user and admin."""
    t = created(one(admin, admin_pw, "x:Tenant/set", {"create": {"t": {"name": "legacy-t"}}}),
                "t", "tenant")
    t2 = created(one(admin, admin_pw, "x:Tenant/set", {"create": {"t": {"name": "legacy-t2"}}}),
                 "t", "second tenant")
    domain = created(one(admin, admin_pw, "x:Domain/set", {"create": {"d": {
        "name": "t.legacy.test", "isEnabled": True, "memberTenantId": t,
        "certificateManagement": {"@type": "Manual"}, "dnsManagement": {"@type": "Manual"},
        "dkimManagement": {"@type": "Manual"}}}}), "d", "tenant domain")
    user_pw = secret_file("legacy-tenant-user")
    tadmin_pw = secret_file("legacy-tenant-admin")
    def user(name, password, extra=None):
        body = {"@type": "User", "name": name, "domainId": domain,
                "credentials": {"0": {"@type": "Password", "secret": password}}}
        body.update(extra or {})
        return created(one(admin, admin_pw, "x:Account/set", {"create": {"a": body}}),
                       "a", f"account {name}")
    user("u", user_pw)
    user("tadmin", tadmin_pw, {"roles": {"@type": "Admin"}})
    tu, ta = "u@t.legacy.test", "tadmin@t.legacy.test"

    tsess = session(ta, tadmin_pw)
    tacct = tsess["primaryAccounts"].get(INBUXA) or list(tsess["accounts"])[0]
    tget = lambda ids=None: one(ta, tadmin_pw, "inbuxa:TenantProtocolPolicy/get",
                                {"accountId": tacct, "ids": ids})
    tset = lambda value: one(ta, tadmin_pw, "inbuxa:TenantProtocolPolicy/set",
                             {"accountId": tacct, "update": {t: {"legacyProtocols": value}}})

    check(session_flag(tu, user_pw) == "enabled",
          "the session says enabled for the tenant's user while both switches are on (test 13)")
    imap_login(PORTS["imap"], tu, user_pw)
    got = tget()
    recent = got[1]["list"][0].get("recentLegacyUse", [])
    names = {(r["name"], r["protocol"]) for r in recent}
    check((tu, "imap") in names and not any(n == admin for n, _ in names),
          "the tenant's panel lists its own user's IMAP sign-in and nobody outside it (LP-15, MT-1)")
    if (tu, "imap") not in names:
        print("     recent:", recent)

    # Before: the tenant's user signs in, and its domain is offered IMAP.
    check(imap_login(PORTS["imap"], tu, user_pw).startswith("OK"),
          "a tenant's user signs in over IMAP with the tenant's switch on")
    got = tget()
    mine = [p["id"] for p in got[1].get("list", [])]
    check(got[0] == "inbuxa:TenantProtocolPolicy/get" and mine == [t],
          "a tenant admin's /get answers with its own tenant's switch only (test 10)")
    if mine != [t]:
        print("     reply:", json.dumps(got)[:400])
    got = tget([t2])
    check(got[1].get("notFound") == [t2], "another tenant's switch is not found (test 10, MT-1)")
    res = one(ta, tadmin_pw, "inbuxa:TenantProtocolPolicy/set",
              {"accountId": tacct, "update": {t2: {"legacyProtocols": "disabled"}}})
    check(t2 in (res[1].get("notUpdated") or {}), "nor can it be changed (test 10)")

    # The tenant admin turns it off for its tenant (LP-9).
    res = tset("disabled")
    check(t in (res[1].get("updated") or {}), "a tenant admin turns legacy protocols off (LP-9)")
    if t not in (res[1].get("updated") or {}):
        print("     reply:", json.dumps(res)[:400])
    check(events_matching("security.legacy-protocols-changed", 'policy = "tenant"',
                          'value = "disabled"'),
          "and it is an event, scope tenant (LP-14, test 14)")

    check(session_flag(tu, user_pw) == "disabled",
          "the session says disabled for the tenant's user once its tenant turns it off (test 13)")
    check(session_flag(admin, admin_pw) == "enabled",
          "and still enabled for an account outside the tenant (test 13)")

    # Refused on the tenant's domain, every way in the same words (tests 6-8).
    imap_no = ("NO [ALERT] Your organization allows only inbuxa webmail and JMAP apps. "
               "This mail app can't sign in.")
    check(imap_login(PORTS["imap"], tu, user_pw) == imap_no,
          "the tenant's user is refused over IMAP with the right password (test 6)")
    check(imap_login(PORTS["imap"], tu, "wrong") == imap_no, "and with a wrong one (test 6)")
    check(imap_login(PORTS["imap"], "nobody@t.legacy.test", "x") == imap_no,
          "and a made-up address on the domain gets the same (test 7)")
    check(pop3_login(PORTS["pop3"], tu, user_pw) ==
          "-ERR [AUTH] Your organization allows only inbuxa webmail and JMAP apps. "
          "This mail app can't sign in.", "POP3 refuses in its own form (test 8)")
    check(smtp_auths(PORTS["submissions"], tu, [user_pw])[0] ==
          "535 5.7.0 Your organization allows only inbuxa webmail and JMAP apps. "
          "This mail app can't send.", "submission refuses in its own form (test 8)")
    check(imap_login(PORTS["imap"], admin, admin_pw).startswith("OK"),
          "an account on another domain signs in over IMAP normally (test 6)")
    check(session(tu, user_pw).get("accounts"), "the tenant's user still has JMAP (test 8)")
    check(not events("auth.failed"), "no refusal counted as a failed sign-in (LP-11)")

    # Client configuration for the tenant's domain only (LP-14a).
    with urllib.request.urlopen(f"{HTTP}/mail/config-v1.1.xml?emailaddress={tu}", timeout=30) as r:
        tenant_cfg = r.read().decode()
    with urllib.request.urlopen(f"{HTTP}/mail/config-v1.1.xml?emailaddress={admin}", timeout=30) as r:
        other_cfg = r.read().decode()
    check('type="imap"' not in tenant_cfg and 'type="imap"' in other_cfg,
          "autoconfig offers no IMAP for the tenant's domain, and still does elsewhere (LP-14a)")

    # Server off means off for everyone: the tenant can't turn it back on (test 9).
    one(admin, admin_pw, "inbuxa:ProtocolPolicy/set",
        {"accountId": account, "update": {"singleton": {"legacyProtocols": "disabled"}}})
    check(session_flag(admin, admin_pw) == "disabled",
          "with the server off, the session says disabled for everyone (test 13)")
    res = tset("enabled")
    refused = (res[1].get("notUpdated") or {}).get(t) or {}
    check(refused.get("type") == "forbidden"
          and "inbuxa:ProtocolPolicy" in (refused.get("description") or ""),
          "with the server off, the tenant can't turn them back on (LP-9, test 9)")
    one(admin, admin_pw, "inbuxa:ProtocolPolicy/set",
        {"accountId": account, "update": {"singleton": {"legacyProtocols": "enabled"}}})
    check(settle(PORTS["imap"], True), "IMAP is back after the server switch returns")

    # And back on, the tenant's user signs in again.
    res = tset("enabled")
    check(t in (res[1].get("updated") or {}), "with the server on, the tenant turns them back on")
    check(imap_login(PORTS["imap"], tu, user_pw).startswith("OK"),
          "and its user signs in over IMAP again")
    check(session_flag(tu, user_pw) == "enabled", "and its session says enabled again (test 13)")

    # A deleted tenant's switch goes with it, so a tenant that later gets the
    # same id doesn't start with legacy protocols off.
    sget = lambda ids: one(admin, admin_pw, "inbuxa:TenantProtocolPolicy/get",
                           {"accountId": account, "ids": ids})
    one(admin, admin_pw, "inbuxa:TenantProtocolPolicy/set",
        {"accountId": account, "update": {t2: {"legacyProtocols": "disabled"}}})
    check(sget([t2])[1]["list"][0]["legacyProtocols"] == "disabled",
          "a server admin turns another tenant's switch off")
    res = one(admin, admin_pw, "x:Tenant/set", {"destroy": [t2]})
    check(t2 in (res[1].get("destroyed") or []), "that tenant can be deleted")
    t3 = created(one(admin, admin_pw, "x:Tenant/set", {"create": {"t": {"name": "legacy-t3"}}}),
                 "t", "third tenant")
    if t3 == t2:
        check(sget([t3])[1]["list"][0]["legacyProtocols"] == "enabled",
              "a new tenant with the deleted one's id starts with legacy protocols on")
    else:
        print(f"     (the registry gave the new tenant a fresh id, {t3} not {t2}: reuse not observable)")


def session_flag(user, password):
    """legacyProtocols from the account's urn:inbuxa:jmap capability."""
    sess = session(user, password)
    acct = sess["primaryAccounts"].get(INBUXA) or list(sess["accounts"])[0]
    return sess["accounts"][acct]["accountCapabilities"].get(INBUXA, {}).get("legacyProtocols")


def events_matching(name, *parts):
    return any(all(p in line for p in parts) for line in events(name))


def settle(port, want, tries=30):
    """Wait for a port to reach the wanted state, so the check is not a race."""
    for _ in range(tries):
        if accepts(port) == want:
            return True
        time.sleep(0.5)
    return False


def main():
    stop()
    # Start from nothing. A half-bootstrapped data directory left by an
    # earlier run is no longer in bootstrap mode, and the recovery admin
    # stops authenticating the moment a real admin exists.
    for sub in ("etc-legacy", "data-legacy"):
        shutil.rmtree(f"{DIR}/{sub}", ignore_errors=True)
    for sub in ("etc-legacy", "data-legacy", "secrets"):
        os.makedirs(f"{DIR}/{sub}", exist_ok=True)
    os.chmod(f"{DIR}/secrets", 0o700)
    stop()

    # First boot, with a recovery admin from an env file.
    recovery = secret_file("legacy-recovery")
    env_file = f"{DIR}/secrets/legacy-env"
    with open(env_file, "w") as f:
        f.write(f"INBUXA_RECOVERY_ADMIN=admin:{recovery}\n")
    os.chmod(env_file, 0o600)
    start(env_file)

    got = one("admin", recovery, "x:Bootstrap/get", {"ids": None})
    singleton = got[1]["list"][0]["id"]
    res = one("admin", recovery, "x:Bootstrap/set", {"update": {singleton: {
        "serverHostname": "mail.legacy.test", "defaultDomain": "legacy.test",
        "requestTlsCertificate": False}}})
    updated = res[1].get("updated", {}).get(singleton)
    check(bool(updated), "bootstrap completed")
    if not updated:
        sys.exit(json.dumps(res))
    admin, admin_pw = updated["username"], secret_file("legacy-admin", updated["secret"])

    stop()
    start()

    # A tracer to stdout, so the events can be read back from the container's
    # log. It takes effect from the next start.
    res = one(admin, admin_pw, "x:Tracer/set", {"create": {"t": {
        "@type": "Stdout", "level": "info", "buffered": False, "ansi": False}}})
    if not (res[1].get("created") or {}).get("t"):
        sys.exit("tracer create failed: " + json.dumps(res))
    stop()
    start()

    sess = session(admin, admin_pw)
    account = sess["primaryAccounts"].get(INBUXA) or list(sess["accounts"])[0]
    policy_get = {"accountId": account, "ids": None}
    policy_set = lambda update: {"accountId": account, "update": {"singleton": update}}

    # The ports we expect a default install to be accepting on.
    check(accepts(PORTS["imap"]), "IMAP accepts before the switch")
    check(accepts(PORTS["pop3"]), "POP3 accepts before the switch")
    check(accepts(PORTS["submissions"]), "submission accepts before the switch")
    check(accepts(PORTS["smtp"]), "inbound SMTP accepts before the switch")

    # What is advertised with the switch on -- the control for LP-7.
    before = advertised(admin, admin_pw)
    print("     advertised before:", {k: sorted(v) if isinstance(v, set) else v
                                      for k, v in before.items() if k != "srv"})
    check(before["autoconfig"] and before["autodiscover"],
          "autoconfig and autodiscover offer mail apps a server with the switch on")
    check(before["srv"].get("_imaps._tcp", ".") != ".",
          "the suggested zone offers IMAP with the switch on")

    # A normal sign-in works with the switch on -- the control for LP-6.
    check(imap_login(PORTS["imap"], admin, admin_pw).startswith("OK"),
          "IMAP sign-in works with the switch on")
    check(smtp_auths(PORTS["submissions"], admin, [admin_pw])[0].startswith("235"),
          "submission sign-in works with the switch on")

    # The impact panel (LP-15): the sign-ins above are on it, once each.
    got = one(admin, admin_pw, "inbuxa:ProtocolPolicy/get",
              {"accountId": account, "ids": None, "properties": ["recentLegacyUse"]})
    recent = got[1]["list"][0].get("recentLegacyUse", [])
    mine = {r["protocol"]: r for r in recent if r["name"] == admin}
    check(set(mine) == {"imap", "submission"} and all(r["lastUsedAt"] > 0 for r in mine.values()),
          "the panel lists the admin's IMAP and submission sign-ins, and when (LP-15)")
    if set(mine) != {"imap", "submission"}:
        print("     recent:", recent)
    imap_login(PORTS["imap"], admin, admin_pw)
    got = one(admin, admin_pw, "inbuxa:ProtocolPolicy/get",
              {"accountId": account, "ids": None, "properties": ["recentLegacyUse"]})
    again = {r["protocol"]: r for r in got[1]["list"][0].get("recentLegacyUse", []) if r["name"] == admin}
    check(again.get("imap", {}).get("lastUsedAt") == mine.get("imap", {}).get("lastUsedAt"),
          "a second sign-in within the hour isn't written again (LP-15)")

    # What the screen reads: the locked set and what would close (LP-16, LP-21).
    got = one(admin, admin_pw, "inbuxa:ProtocolPolicy/get", policy_get)
    if got[0] != "inbuxa:ProtocolPolicy/get":
        sys.exit("ProtocolPolicy/get failed: " + json.dumps(got))
    policy = got[1]["list"][0]
    check(policy["legacyProtocols"] == "enabled", "switch starts enabled")
    check(set(policy["lockedProtocols"]) >= {"smtp", "http"},
          "SMTP and JMAP report as locked (LP-21)")
    would = {l["id"] for l in policy["wouldClose"]}
    print("     wouldClose:", sorted(would))
    check(would, "wouldClose names the listeners that would close (LP-16)")

    # Turn it off, and ask for submission to close too: the lock must overrule.
    res = one(admin, admin_pw, "inbuxa:ProtocolPolicy/set",
              policy_set({"legacyProtocols": "disabled", "closeSubmission": True}))
    if not res[1].get("updated"):
        sys.exit("ProtocolPolicy/set failed: " + json.dumps(res))
    overruled = res[1]["updated"].get("singleton")
    check(overruled is not None and overruled.get("closeSubmission") is False,
          "closeSubmission overruled to false and reported (LP-21, test 18)")

    # The ports themselves (LP-1, LP-2, LP-3, test 15).
    check(settle(PORTS["imap"], False), "IMAP stopped accepting")
    check(settle(PORTS["pop3"], False), "POP3 stopped accepting")
    check(accepts(PORTS["smtp"]), "inbound SMTP still accepts (LP-3)")
    check(accepts(PORTS["submissions"]), "submission still accepts, being locked (LP-21)")

    # JMAP still works, which is the whole point of locking it.
    got = one(admin, admin_pw, "inbuxa:ProtocolPolicy/get", policy_get)
    check(got[0] == "inbuxa:ProtocolPolicy/get", "JMAP still works while the switch is off")
    policy = got[1]["list"][0]
    check(policy["legacyProtocols"] == "disabled", "switch reads back disabled")
    saved = {l["id"] for l in policy["savedListeners"]}
    print("     savedListeners:", sorted(saved))
    check(saved, "the closed listeners were saved (LP-1)")

    # The second lock (LP-6). Submission stays open, being locked, so sign-in
    # over it is refused instead -- right password or wrong, the same words,
    # and never enough of them to be thrown off (LP-11, test 2, test 18).
    replies = smtp_auths(PORTS["submissions"], admin, [admin_pw] + ["wrong"] * 6)
    check(replies[0] == SMTP_REFUSAL, "submission refuses the right password (LP-6)")
    check(all(r == SMTP_REFUSAL for r in replies[1:]),
          "submission refuses wrong passwords the same way, and doesn't hang up (LP-11)")
    if not all(r == SMTP_REFUSAL for r in replies):
        print("     replies:", replies)

    # Nothing advertises what is closed (LP-7, test 5).
    during = advertised(admin, admin_pw)
    check(not during["autoconfig"], "autoconfig offers no IMAP, POP3 or submission (LP-7)")
    check(not during["autodiscover"], "autodiscover offers no IMAP, POP3 or submission (LP-7)")
    check(not during["pacc"] and during["jmap"], "PACC offers JMAP and nothing legacy (LP-7)")
    names = ("_imap._tcp", "_imaps._tcp", "_pop3._tcp", "_pop3s._tcp",
             "_submission._tcp", "_submissions._tcp")
    offered = {n: t for n, t in during["srv"].items() if n in names and t != "."}
    check(not offered and "_imaps._tcp" in during["srv"],
          "the suggested zone marks the legacy SRV names not offered, target . (LP-7)")
    if offered or "_imaps._tcp" not in during["srv"]:
        print("     srv:", during["srv"])

    # No listener the switch would close can be added while it is off (LP-4,
    # test 4), and the refusal names the policy.
    res = one(admin, admin_pw, "x:NetworkListener/set", {"create": {"m": {
        "name": "imap-new", "protocol": "imap", "bind": {"0.0.0.0:1993": True},
        "tlsImplicit": True}}})
    refused = (res[1].get("notCreated") or {}).get("m") or {}
    check(refused.get("type") == "invalidProperties"
          and "protocol" in (refused.get("properties") or [])
          and "inbuxa:ProtocolPolicy" in (refused.get("description") or ""),
          "creating an IMAP listener is refused, naming the policy (LP-4)")
    if not refused:
        print("     reply:", json.dumps(res[1])[:300])

    # What the switch never closes can still be added; turning it into a
    # listener the switch would close is refused like creating one.
    res = one(admin, admin_pw, "x:NetworkListener/set", {"create": {"s": {
        "name": "submission-extra", "protocol": "smtp", "bind": {"0.0.0.0:2587": True}}}})
    extra = (res[1].get("created") or {}).get("s", {}).get("id")
    check(extra is not None, "an SMTP listener can still be created, being locked (LP-4, LP-21)")
    if extra:
        res = one(admin, admin_pw, "x:NetworkListener/set",
                  {"update": {extra: {"protocol": "imap"}}})
        refused = (res[1].get("notUpdated") or {}).get(extra) or {}
        check(refused.get("type") == "invalidProperties",
              "turning it into an IMAP listener is refused (LP-4)")
        one(admin, admin_pw, "x:NetworkListener/set", {"destroy": [extra]})

    # The change was reported (LP-8, test 14), with who made it and what closed.
    changed = events("security.legacy-protocols-changed")
    check(len(changed) == 1 and 'value = "disabled"' in changed[0]
          and 'policy = "server"' in changed[0] and 'details = "closed"' in changed[0]
          and '"imaps"' in changed[0] and "accountId = " in changed[0],
          "turning it off is one event: scope, new value, who, listeners closed (LP-8)")
    if len(changed) != 1:
        print("     events:", changed)
    # Asking for what already holds is not a change.
    one(admin, admin_pw, "inbuxa:ProtocolPolicy/set", policy_set({"legacyProtocols": "disabled"}))
    check(len(events("security.legacy-protocols-changed")) == 1,
          "setting it off again when it is off raises no event (LP-8)")
    # Every refused sign-in is an event too, and none is a failed sign-in.
    refused = events("auth.legacy-protocol-refused")
    check(len(refused) == 7 and all('source = "submission"' in l for l in refused),
          "each refused sign-in is an auth.legacy-protocol-refused event (LP-6)")
    check(not events("auth.failed") and not events("auth.too-many-attempts"),
          "and none is logged as a failed sign-in (LP-11)")

    # A restart must not reopen them: the objects are gone, not just the sockets.
    stop()
    start()
    check(settle(PORTS["imap"], False), "IMAP still closed after a restart")
    check(accepts(PORTS["smtp"]), "inbound SMTP still accepts after a restart")

    # Turn it back on: the listeners come back and bind again (LP-5).
    res = one(admin, admin_pw, "inbuxa:ProtocolPolicy/set",
              policy_set({"legacyProtocols": "enabled"}))
    if "updated" not in res[1]:
        sys.exit("ProtocolPolicy/set back on failed: " + json.dumps(res))
    check(settle(PORTS["imap"], True), "IMAP accepts again without a restart (LP-5)")
    check(settle(PORTS["pop3"], True), "POP3 accepts again without a restart (LP-5)")

    got = one(admin, admin_pw, "inbuxa:ProtocolPolicy/get", policy_get)
    policy = got[1]["list"][0]
    check(policy["legacyProtocols"] == "enabled", "switch reads back enabled")
    check(not policy["savedListeners"], "savedListeners is empty again (LP-5)")
    changed = events("security.legacy-protocols-changed")
    check(len(changed) == 1 and 'value = "enabled"' in changed[0]
          and 'details = "reopened"' in changed[0] and '"imaps"' in changed[0],
          "turning it back on is one event, naming the listeners reopened (LP-8)")

    after = advertised(admin, admin_pw)
    check(after["autoconfig"] == before["autoconfig"] and after["srv"] == before["srv"],
          "autoconfig and the suggested zone offer them again once back on")

    # A tenant's own switch (LP-9 to LP-14a).
    tenant_checks(admin, admin_pw, account)

    # And sign-in works again, with no restart.
    check(imap_login(PORTS["imap"], admin, admin_pw).startswith("OK"),
          "IMAP sign-in works again once the switch is back on")
    check(smtp_auths(PORTS["submissions"], admin, [admin_pw])[0].startswith("235"),
          "submission sign-in works again once the switch is back on")

    print()
    if failures:
        print(f"{len(failures)} FAILED:")
        for f in failures:
            print("  - " + f)
    else:
        print("all checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    rc = 1
    try:
        rc = main()
    finally:
        if not os.environ.get("KEEP"):
            stop()
    sys.exit(rc)
