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
created, or made by an update (LP-4, test 4).

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
SMTP_REFUSAL = ("535 5.7.0 This server allows only INBUXA webmail and JMAP apps. "
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


def jmap(user, password, calls, using=("urn:ietf:params:jmap:core", "urn:stalwart:jmap", INBUXA)):
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

    sess = session(admin, admin_pw)
    account = sess["primaryAccounts"].get(INBUXA) or list(sess["accounts"])[0]
    policy_get = {"accountId": account, "ids": None}
    policy_set = lambda update: {"accountId": account, "update": {"singleton": update}}

    # The ports we expect a default install to be accepting on.
    check(accepts(PORTS["imap"]), "IMAP accepts before the switch")
    check(accepts(PORTS["pop3"]), "POP3 accepts before the switch")
    check(accepts(PORTS["submissions"]), "submission accepts before the switch")
    check(accepts(PORTS["smtp"]), "inbound SMTP accepts before the switch")

    # A normal sign-in works with the switch on -- the control for LP-6.
    check(imap_login(PORTS["imap"], admin, admin_pw).startswith("OK"),
          "IMAP sign-in works with the switch on")
    check(smtp_auths(PORTS["submissions"], admin, [admin_pw])[0].startswith("235"),
          "submission sign-in works with the switch on")

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
