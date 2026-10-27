#!/usr/bin/env python3
"""Local end-to-end check that INBUXA_PRIVATE_TLDS lets a network that runs
its own DNS use its own top-level domain.

Run it with `python3 tests/e2e/private_tlds.py` after
`cargo build -p inbuxa`. Needs Docker. Working state goes under target/e2e.

Domains are only accepted when their suffix is public or one of a few
reserved private ones (test, internal, lan, home, ...). This boots the debug
binary and checks that:
- without the variable, the setup wizard refuses a domain under `.myownlab`;
- with INBUXA_PRIVATE_TLDS=myownlab, the wizard accepts it;
- after setup, a second domain and an account under `.myownlab` can be created,
  and that account signs in;
- once the variable is gone again, a new `.myownlab` domain is refused.

Passwords are generated into files under target/e2e and never printed.
Everything is removed afterwards unless KEEP=1.
"""

import base64, json, os, secrets, shutil, subprocess, sys, time, urllib.error, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DIR = f"{ROOT}/target/e2e"
NAME = "inbuxa-private-tlds"
PORT = 18197
HTTP = f"http://127.0.0.1:{PORT}"
# Another build to check, such as one from before the change.
BINARY = os.environ.get("INBUXA_BINARY", f"{ROOT}/target/debug/inbuxa")

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


def start(env=None):
    env_file = f"{DIR}/secrets/tlds-env"
    with open(env_file, "w") as f:
        for key, value in (env or {}).items():
            f.write(f"{key}={value}\n")
    os.chmod(env_file, 0o600)
    docker("run", "-d", "--name", NAME, "--user", f"{os.getuid()}:{os.getgid()}",
           "--entrypoint", "/usr/local/bin/inbuxa",
           "-v", f"{BINARY}:/usr/local/bin/inbuxa:ro",
           "-v", f"{DIR}/etc-tlds:/etc/inbuxa", "-v", f"{DIR}/data-tlds:/var/lib/inbuxa",
           "-p", f"127.0.0.1:{PORT}:8080",
           # A debug build's workers need more than the default stack.
           "-e", "RUST_MIN_STACK=16777216",
           # Signing in with a password over JMAP keeps the script short.
           "-e", "INBUXA_HTTP_BASIC_AUTH=all",
           "--env-file", env_file,
           "stalwartlabs/stalwart:v0.16.22", "--config", "/etc/inbuxa/config.json")
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


def restart(env=None):
    stop()
    start(env)


def jmap(user, password, calls):
    body = json.dumps({"using": ["urn:ietf:params:jmap:core", "urn:inbuxa:jmap:registry"],
                       "methodCalls": calls}).encode()
    req = urllib.request.Request(f"{HTTP}/jmap/", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode())
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)["methodResponses"]


def one(user, password, method, args):
    return jmap(user, password, [[method, args, "0"]])[0]


def signs_in(user, password):
    req = urllib.request.Request(f"{HTTP}/jmap/session")
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status == 200
    except urllib.error.HTTPError:
        return False


def bootstrap(recovery):
    got = one("admin", recovery, "x:Bootstrap/get", {"ids": None})
    singleton = got[1]["list"][0]["id"]
    res = one("admin", recovery, "x:Bootstrap/set", {"update": {singleton: {
        "defaultHostname": "mail.home.myownlab", "defaultDomain": "home.myownlab",
        "requestTlsCertificate": False}}})
    return res[1].get("updated", {}).get(singleton), res[1].get("notUpdated", {}).get(singleton)


def create_domain(admin, admin_pw, name):
    res = one(admin, admin_pw, "x:Domain/set", {"create": {"d": {
        "name": name, "enable": True,
        "certificateManagement": {"@type": "Manual"}, "dnsManagement": {"@type": "Manual"},
        "dkimManagement": {"@type": "Manual"}}}})
    return (res[1].get("created") or {}).get("d", {}).get("id"), res[1].get("notCreated")


def main():
    stop()
    for sub in ("etc-tlds", "data-tlds"):
        shutil.rmtree(f"{DIR}/{sub}", ignore_errors=True)
    for sub in ("etc-tlds", "data-tlds", "secrets"):
        os.makedirs(f"{DIR}/{sub}", exist_ok=True)
    os.chmod(f"{DIR}/secrets", 0o700)

    recovery = secret_file("tlds-recovery")
    start({"INBUXA_RECOVERY_ADMIN": f"admin:{recovery}"})
    updated, refused = bootstrap(recovery)
    check(not updated and bool(refused),
          f"without the variable, the wizard refuses home.myownlab ({(refused or {}).get('description')})")

    private = {"INBUXA_PRIVATE_TLDS": "myownlab"}
    restart({"INBUXA_RECOVERY_ADMIN": f"admin:{recovery}", **private})
    updated, refused = bootstrap(recovery)
    check(bool(updated), "with INBUXA_PRIVATE_TLDS=myownlab, the wizard accepts home.myownlab")
    if not updated:
        sys.exit(json.dumps(refused))
    admin, admin_pw = updated["username"], secret_file("tlds-admin", updated["secret"])

    restart(private)
    check(signs_in(admin, admin_pw), f"the permanent administrator signs in ({admin.split('@')[-1]})")
    domain, refused = create_domain(admin, admin_pw, "lab.myownlab")
    check(bool(domain), f"a second domain, lab.myownlab, is created ({refused})")
    if domain:
        user_pw = secret_file("tlds-user")
        res = one(admin, admin_pw, "x:Account/set", {"create": {"a": {
            "@type": "User", "name": "pat", "domainId": domain,
            "credentials": {"0": {"@type": "Password", "secret": user_pw}}}}})
        check(bool((res[1].get("created") or {}).get("a")),
              f"an account on lab.myownlab is created ({res[1].get('notCreated')})")
        check(signs_in("pat@lab.myownlab", user_pw), "pat@lab.myownlab signs in")

    restart()
    domain, refused = create_domain(admin, admin_pw, "other.myownlab")
    check(not domain, "once the variable is gone, a new .myownlab domain is refused")


try:
    main()
finally:
    if os.environ.get("KEEP") != "1":
        stop()
        for sub in ("etc-tlds", "data-tlds"):
            shutil.rmtree(f"{DIR}/{sub}", ignore_errors=True)

if failures:
    sys.exit(f"{len(failures)} check(s) failed")
print("all checks passed")
