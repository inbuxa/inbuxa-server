#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
#
# Migrations against a server image (docs/spec/features/migrations.md), on
# demand: the image's own inbuxa-migrate moves two accounts in from a
# Dovecot, and the server restarts in the middle of the move.
#
#   python3 tests/resources/migrations/live-image-test.py IMAGE
#
# IMAGE is a server image with migrations, such as one built from this
# tree with `docker buildx build --load -t inbuxa-server:test .`. Needs
# Docker and python3, nothing else; everything it starts is removed at the
# end. Steps:
#
#   1. Dovecot with a@ (3 messages) and b@ (2, plus a Bulk folder big
#      enough to take a while), and a master login.
#   2. The server, started once in recovery mode for a domain and an
#      administrator, then normally.
#   3. A migration of both, creating their accounts, one at a time.
#   4. Preview. Then move, and restart the server once a@ is done: the run
#      is interrupted, and the secret is gone with the restart.
#   5. Move again with the secret: it carries on, and both mailboxes are
#      whole, nothing twice.
#   6. The passwords sign a@ and b@ in. A message sent to a@ at the old
#      server comes over with the final pass.
#   7. Close: the work directory goes.

import base64
import imaplib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DOVECOT = os.path.join(HERE, "dovecot-source")
MASTER_SECRET = "m4ster-e2e"  # dovecot-source/masters
BULK = 2000
RUN = f"inbuxa-mig-live-{os.getpid()}"


def docker(*args, check=True):
    out = subprocess.run(["docker", *args], capture_output=True, text=True)
    if check and out.returncode != 0:
        raise SystemExit(f"docker {' '.join(args[:3])}…: {out.stderr.strip()}")
    return out.stdout.strip()


def step(text):
    print(f"--- {text}", flush=True)


class Server:
    def __init__(self, image, port, config):
        self.image, self.port, self.config = image, port, config
        self.base = f"http://127.0.0.1:{port}"
        self.name = f"{RUN}-server"

    def start(self, env):
        docker("rm", "-f", self.name, check=False)
        args = ["run", "-d", "--name", self.name, "--network", RUN,
                "-v", f"{RUN}-data:/var/lib/inbuxa",
                "-v", f"{self.config}:/etc/inbuxa/config.json:ro",
                "-p", f"127.0.0.1:{self.port}:8080",
                "-e", f"INBUXA_PUBLIC_URL={self.base}"]
        for key, value in env.items():
            args += ["-e", f"{key}={value}"]
        docker(*args, self.image)

    def wait(self, auth):
        deadline = time.time() + 180
        while time.time() < deadline:
            try:
                return self.request("/jmap/session", auth)
            except (urllib.error.URLError, ConnectionError, OSError):
                time.sleep(1)
        raise SystemExit("the server didn't come up:\n" + docker("logs", "--tail", "40", self.name, check=False))

    def request(self, path, auth, body=None, raw=False):
        req = urllib.request.Request(
            self.base + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": auth, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
        return data if raw else json.loads(data)


def basic(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


class Jmap:
    USING = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail",
             "urn:inbuxa:jmap", "urn:inbuxa:jmap:registry"]

    def __init__(self, server, user, password):
        self.server, self.auth = server, basic(user, password)
        self.session = server.wait(self.auth)
        accounts = self.session["accounts"]
        registry = [a for a, v in accounts.items() if "urn:inbuxa:jmap:registry" in v.get("accountCapabilities", {})]
        self.account = registry[0] if registry else self.session["primaryAccounts"]["urn:ietf:params:jmap:mail"]

    def call(self, method, args):
        args = {"accountId": self.account, **args}
        out = self.server.request("/jmap", self.auth, {"using": self.USING, "methodCalls": [[method, args, "0"]]})
        name, result, _ = out["methodResponses"][0]
        if name != method:
            raise SystemExit(f"{method}: {result}")
        return result


def check(ok, what):
    if not ok:
        raise SystemExit(f"FAILED: {what}")
    print(f"ok  {what}", flush=True)


def migration(admin, mid):
    return admin.call("inbuxa:Migration/get", {"ids": [mid]})["list"][0]


def act(admin, mid, action, secret=None):
    patch = {"action": action, **({"secret": secret} if secret else {})}
    return admin.call("inbuxa:Migration/set", {"update": {mid: patch}})


def settled(admin, mid, timeout=600):
    deadline = time.time() + timeout
    while time.time() < deadline:
        m = migration(admin, mid)
        if m["status"] != "running":
            return m
        time.sleep(1)
    raise SystemExit(f"the run didn't end: {migration(admin, mid)}")


def mailbox_counts(server, email, password):
    user = Jmap(server, email, password)
    out = server.request("/jmap", user.auth, {"using": Jmap.USING, "methodCalls": [
        ["Mailbox/get", {"accountId": user.account, "properties": ["name", "totalEmails"]}, "0"]]})
    return {m["name"]: m["totalEmails"] for m in out["methodResponses"][0][1]["list"] if m["totalEmails"]}


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: live-image-test.py IMAGE")
    image = sys.argv[1]
    work = tempfile.mkdtemp(prefix="inbuxa-mig-live-")
    config = os.path.join(work, "config.json")
    with open(config, "w") as f:
        f.write('{"@type":"RocksDb","path":"/var/lib/inbuxa"}')
    os.chmod(config, 0o644)
    try:
        run(image, config)
        print("\nPASSED")
    finally:
        for name in ("server", "dovecot"):
            docker("rm", "-f", f"{RUN}-{name}", check=False)
        docker("volume", "rm", "-f", f"{RUN}-data", check=False)
        docker("network", "rm", RUN, check=False)


def run(image, config):
    step("Dovecot")
    docker("network", "create", RUN)
    docker("build", "-q", "-t", "inbuxa-e2e-dovecot", DOVECOT)
    docker("run", "-d", "--name", f"{RUN}-dovecot", "--network", RUN, "--network-alias", "dovecot",
           "-p", "127.0.0.1::143", "inbuxa-e2e-dovecot")
    imap_port = int(docker("port", f"{RUN}-dovecot", "143/tcp").splitlines()[0].rsplit(":", 1)[1])
    subprocess.run([sys.executable, os.path.join(DOVECOT, "seed.py"), str(imap_port), "--bulk", str(BULK)],
                   check=True)

    step("the server, in recovery mode")
    port = int(subprocess.run([sys.executable, "-c", "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1])"],
                              capture_output=True, text=True).stdout)
    server = Server(image, port, config)
    recovery_pw, admin_pw = secrets.token_urlsafe(18), secrets.token_urlsafe(18)
    server.start({"INBUXA_RECOVERY_MODE": "1", "INBUXA_RECOVERY_ADMIN": f"admin:{recovery_pw}"})
    recovery = Jmap(server, "admin", recovery_pw)
    domain = recovery.call("x:Domain/set", {"create": {"d": {"name": "example.com"}}})["created"]["d"]["id"]
    created = recovery.call("x:Account/set", {"create": {"boss": {
        "@type": "User", "name": "boss", "domainId": domain,
        "credentials": {"0": {"@type": "Password", "secret": admin_pw}},
        "roles": {"@type": "Admin"}}}})
    check(bool(created.get("created", {}).get("boss")), "an administrator")

    step("the server, normally")
    normal = {"INBUXA_HTTP_BASIC_AUTH": "all"}
    server.start(normal)
    admin = Jmap(server, "boss@example.com", admin_pw)
    created = admin.call("inbuxa:Migration/set", {"create": {"m": {
        "description": "Live test", "sourceKind": "imap",
        "source": {"url": "imap://dovecot:143", "login": "{email}*master", "cleartext": True},
        "accounts": ["a@example.org", "b@example.org"], "createAccounts": True, "parallel": 1}}})
    mid = created["created"]["m"]["id"]

    step("preview")
    act(admin, mid, "preview", MASTER_SECRET)
    m = settled(admin, mid)
    check(m["result"] == "done" and not m["moved"], f"preview done, nothing moved ({m['result']})")
    version = docker("exec", server.name, "/usr/local/bin/inbuxa-migrate", "--version")
    check(version.startswith("inbuxa-migrate "), f"the image carries {version}")

    step("move, and a restart in the middle")
    act(admin, mid, "move")
    deadline = time.time() + 300
    while time.time() < deadline:
        m = migration(admin, mid)
        if m["status"] != "running" or m["progress"]["finished"] >= 1:
            break
        time.sleep(0.3)
    check(m["status"] == "running" and m["progress"]["finished"] == 1,
          f"a@ moved, b@ still moving ({m['progress']})")
    docker("restart", server.name)
    admin = Jmap(server, "boss@example.com", admin_pw)
    m = migration(admin, mid)
    check(m["status"] == "idle" and m["result"] == "interrupted", f"the restart cut the run off ({m.get('result')})")
    refused = act(admin, mid, "move")
    check("secret" in json.dumps(refused.get("notUpdated", {})), "the secret went with the restart")

    step("move again: it carries on")
    act(admin, mid, "move", MASTER_SECRET)
    m = settled(admin, mid)
    check(m["result"] == "done" and m["moved"], f"move done ({m['result']}, {m.get('error')})")
    report = docker("exec", server.name, "sh", "-c", f"cat /var/lib/inbuxa/migrations/*/work/report.csv")
    check("a@example.org,export,done earlier" in report, "a@ wasn't moved again")
    check("b@example.org,export,done," in report, "b@ was carried on to the end")

    step("the new accounts")
    blob = act(admin, mid, "passwords")["updated"][mid]["passwordsBlobId"]
    url = admin.session["downloadUrl"].replace("{accountId}", admin.account).replace("{blobId}", blob) \
        .replace("{name}", "p.csv").replace("{type}", "text/csv")
    csv = server.request(url[len(server.base):], admin.auth, raw=True).decode()
    passwords = dict(line.split(",", 1) for line in csv.strip().splitlines()[1:])
    check(sorted(passwords) == ["a@example.org", "b@example.org"], "a password for each")
    a = mailbox_counts(server, "a@example.org", passwords["a@example.org"])
    b = mailbox_counts(server, "b@example.org", passwords["b@example.org"])
    check(a == {"Inbox": 3}, f"a@ whole: {a}")
    check(b == {"Inbox": 1, "Projects": 1, "Bulk": BULK}, f"b@ whole, nothing twice: {b}")

    step("final pass")
    old = imaplib.IMAP4("127.0.0.1", int(docker("port", f"{RUN}-dovecot", "143/tcp").splitlines()[0].rsplit(":", 1)[1]))
    old.login("a@example.org*master", MASTER_SECRET)
    old.append("INBOX", None, None, b"From: late@example.net\r\nSubject: Late\r\nMessage-ID: <late@example.net>\r\n"
               b"Date: Tue, 5 Mar 2024 09:00:00 +0000\r\n\r\nLate\r\n")
    old.logout()
    act(admin, mid, "finalPass")
    m = settled(admin, mid)
    check(m["result"] == "done", f"final pass done ({m['result']})")
    a = mailbox_counts(server, "a@example.org", passwords["a@example.org"])
    check(a == {"Inbox": 4}, f"the late message came over: {a}")

    step("close")
    act(admin, mid, "close")
    left = docker("exec", server.name, "sh", "-c", "ls -A /var/lib/inbuxa/migrations")
    check(left == "", "the work directory is gone")


if __name__ == "__main__":
    main()
