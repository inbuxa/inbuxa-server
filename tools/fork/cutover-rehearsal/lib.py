#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared helpers for the synthetic cutover rehearsal.

Two containers stand in for the two installs of docs/spec/cutover.md:

  old  upstream stalwart 0.16.22 (target/debug/stalwart) — the Enterprise
       install that is running today
  new  the fork (target/debug/inbuxa) — what it is cut over to

Both run unprivileged with CAP_NET_BIND_SERVICE so the mail ports are bound
the way the systemd unit binds them, not as root. Nothing here touches
INBUXA's production server; the data is created here and thrown away.
"""
import base64, json, os, secrets, smtplib, ssl, subprocess, sys, time, urllib.error, urllib.request

ROOT = "/run/media/john/PROJECTS/inbuxa-server"
BASE = f"{ROOT}/target/cutover"
IMAGE = "stalwartlabs/stalwart:v0.16.22"

# Host ports. The two installs are side by side, as the plan requires, so
# they cannot share: only one holds the mail ports at a time.
HTTP = 12080
SMTP = 12025
SUBMISSIONS = 12465
IMAPS = 12993

DOMAIN = "cutover.test"
HOSTNAME = f"mail.{DOMAIN}"

INSTALLS = {
    "old": {"container": "cutover-old", "binary": "stalwart", "dir": f"{BASE}/old"},
    "new": {"container": "cutover-new", "binary": "inbuxa", "dir": f"{BASE}/new"},
}


def docker(*args, check_rc=True):
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check_rc)


def run(*args, check_rc=True):
    return subprocess.run(args, capture_output=True, text=True, check=check_rc)


def start(which, hold_mail_ports=True, extra_env=None):
    """Start one install. Only one may hold the mail ports at a time."""
    spec = INSTALLS[which]
    env_file = f"{spec['dir']}/env"
    args = [
        "run", "-d", "--name", spec["container"],
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--cap-add", "NET_BIND_SERVICE",
        "--entrypoint", f"/usr/local/bin/{spec['binary']}",
        "-v", f"{ROOT}/target/debug/{spec['binary']}:/usr/local/bin/{spec['binary']}:ro",
        "-v", f"{spec['dir']}/etc:/etc/stalwart",
        "-v", f"{spec['dir']}/data:/var/lib/stalwart",
        "-p", f"127.0.0.1:{HTTP}:8080",
    ]
    if hold_mail_ports:
        args += ["-p", f"127.0.0.1:{SMTP}:25",
                 "-p", f"127.0.0.1:{SUBMISSIONS}:465",
                 "-p", f"127.0.0.1:{IMAPS}:993"]
    if os.path.exists(env_file):
        args += ["--env-file", env_file]
    for k, v in (extra_env or {}).items():
        args += ["-e", f"{k}={v}"]
    args += [IMAGE, "--config", "/etc/stalwart/config.json"]
    docker(*args)
    return wait_http()


def wait_http(seconds=180):
    for _ in range(seconds):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{HTTP}/.well-known/jmap", timeout=2)
        except urllib.error.HTTPError:
            return True
        except Exception:
            time.sleep(1)
            continue
        return True
    return False


def stop(which):
    docker("rm", "-f", INSTALLS[which]["container"], check_rc=False)


def logs(which, tail="40"):
    r = docker("logs", "--tail", tail, INSTALLS[which]["container"], check_rc=False)
    return (r.stdout or "") + (r.stderr or "")


def jmap(user, pw, calls, using=("urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail",
                                 "urn:stalwart:jmap")):
    body = json.dumps({"using": list(using), "methodCalls": calls}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{HTTP}/jmap/", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode())
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)["methodResponses"]


def one(user, pw, method, args):
    return jmap(user, pw, [[method, args, "0"]])[0]


def session(user, pw):
    req = urllib.request.Request(f"http://127.0.0.1:{HTTP}/jmap/session")
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode())
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def tls_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


results = []


def check(cond, what, detail=""):
    results.append((bool(cond), what, detail))
    print(("  ok   " if cond else "  FAIL ") + what + (f"  [{detail}]" if detail else ""),
          flush=True)
    return bool(cond)


def summary(title):
    bad = [w for ok, w, _ in results if not ok]
    print(f"\n=== {title}: {len(results) - len(bad)}/{len(results)} passed", flush=True)
    for w in bad:
        print("    FAILED: " + w, flush=True)
    return not bad
