#!/usr/bin/env python3
"""Local end-to-end check that an administrator gets no OAuth client bypass
outside bootstrap and recovery mode (contract C-5).

Run it with `python3 tests/e2e/client_override.py` after
`cargo build -p inbuxa`. Needs Docker. Working state goes under target/e2e.

Administrators hold OAuthClientOverride. Upstream lets it skip the client and
redirect URI checks everywhere, so a link naming a made-up client and an
attacker's redirect URI would hand an administrator's code to the attacker.
This boots the debug binary and checks that:
- in bootstrap mode, the recovery administrator still signs in through an
  unregistered client, as the setup wizard needs;
- after setup, an administrator gets no code for an unregistered client, nor
  for a registered one with a redirect URI it didn't register, while the
  registered client and URI still work end to end;
- a device code an administrator approves for an unregistered client can't be
  exchanged for a token;
- in recovery mode, the bypass is back for the recovery administrator.

Passwords are generated into files under target/e2e and never printed.
Everything is removed afterwards unless KEEP=1.
"""

import base64, hashlib, json, os, secrets, shutil, subprocess, sys, time, urllib.error, urllib.parse, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DIR = f"{ROOT}/target/e2e"
NAME = "inbuxa-client-override"
PORT = 18195
HTTP = f"http://127.0.0.1:{PORT}"
ADMIN_URL = "http://admin.override.test"
REDIRECT = f"{ADMIN_URL}/oauth/callback"
EVIL = "https://evil.example/cb"
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
    env_file = f"{DIR}/secrets/override-env"
    with open(env_file, "w") as f:
        for key, value in (env or {}).items():
            f.write(f"{key}={value}\n")
    os.chmod(env_file, 0o600)
    docker("run", "-d", "--name", NAME, "--user", f"{os.getuid()}:{os.getgid()}",
           "--entrypoint", "/usr/local/bin/inbuxa",
           "-v", f"{BINARY}:/usr/local/bin/inbuxa:ro",
           "-v", f"{DIR}/etc-override:/etc/inbuxa", "-v", f"{DIR}/data-override:/var/lib/inbuxa",
           "-p", f"127.0.0.1:{PORT}:8080",
           # A debug build's workers need more than the default stack.
           "-e", "RUST_MIN_STACK=16777216",
           # Registers inbuxa-admin, the one client this server knows (C-6).
           "-e", f"INBUXA_ADMIN_URL={ADMIN_URL}",
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


def request(path, method="GET", body=None, content_type=None, authorization=None):
    req = urllib.request.Request(f"{HTTP}{path}", data=body, method=method)
    if content_type:
        req.add_header("Content-Type", content_type)
    if authorization:
        req.add_header("Authorization", authorization)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()


def jmap(user, password, calls):
    body = json.dumps({"using": ["urn:ietf:params:jmap:core", "urn:inbuxa:jmap:registry"],
                       "methodCalls": calls}).encode()
    auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
    status, raw = request("/jmap/", "POST", body, "application/json", auth)
    if status != 200:
        sys.exit(f"JMAP call failed: {status}")
    return json.loads(raw)["methodResponses"]


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def sign_in(user, password, client_id, redirect_uri, challenge):
    """The sign-in page's request: what an authorization link leads to."""
    status, raw = request("/api/auth", "POST", json.dumps({
        "type": "authCode", "accountName": user, "accountSecret": password,
        "clientId": client_id, "redirectUri": redirect_uri,
        "codeChallenge": challenge, "codeChallengeMethod": "S256"}).encode(), "application/json")
    return json.loads(raw) if status == 200 else {"type": status}


def exchange(client_id, code, redirect_uri, verifier):
    status, raw = request("/auth/token", "POST", urllib.parse.urlencode({
        "grant_type": "authorization_code", "client_id": client_id, "code": code,
        "redirect_uri": redirect_uri, "code_verifier": verifier}).encode(),
        "application/x-www-form-urlencoded")
    return status, json.loads(raw or b"{}")


def phished(user, password, client_id, redirect_uri):
    """Whether a link naming this client and redirect URI ends in a token."""
    verifier, challenge = pkce()
    answer = sign_in(user, password, client_id, redirect_uri, challenge)
    if answer.get("type") != "authenticated":
        return False, answer.get("type")
    status, body = exchange(client_id, answer["client_code"], redirect_uri, verifier)
    return status == 200 and "access_token" in body, f"code issued, exchange {status}"


def main():
    stop()
    for sub in ("etc-override", "data-override"):
        shutil.rmtree(f"{DIR}/{sub}", ignore_errors=True)
    for sub in ("etc-override", "data-override", "secrets"):
        os.makedirs(f"{DIR}/{sub}", exist_ok=True)
    os.chmod(f"{DIR}/secrets", 0o700)

    # Bootstrap mode: the recovery administrator keeps the bypass.
    recovery = secret_file("override-recovery")
    start({"INBUXA_RECOVERY_ADMIN": f"admin:{recovery}"})
    got, how = phished("admin", recovery, "setup-wizard", EVIL)
    check(got, f"bootstrap mode: the recovery administrator signs in through an unregistered client ({how})")

    got = jmap("admin", recovery, [["x:Bootstrap/get", {"ids": None}, "0"]])
    singleton = got[0][1]["list"][0]["id"]
    res = jmap("admin", recovery, [["x:Bootstrap/set", {"update": {singleton: {
        "serverHostname": "mail.override.test", "defaultDomain": "override.test",
        "requestTlsCertificate": False}}}, "0"]])
    updated = res[0][1].get("updated", {}).get(singleton)
    check(bool(updated), "bootstrap completed")
    if not updated:
        sys.exit(json.dumps(res))
    admin, admin_pw = updated["username"], secret_file("override-admin", updated["secret"])

    # After setup: no bypass for an administrator.
    restart()
    got, how = phished(admin, admin_pw, "inbuxa-admin", REDIRECT)
    check(got, f"the registered client and redirect URI still sign an administrator in ({how})")
    got, how = phished(admin, admin_pw, "evil-client", EVIL)
    check(not got, f"an unregistered client gets nothing for an administrator ({how})")
    got, how = phished(admin, admin_pw, "inbuxa-admin", EVIL)
    check(not got, f"a registered client with a foreign redirect URI gets nothing ({how})")

    # Device flow: the administrator approves a code a made-up client asked for.
    status, raw = request("/auth/device", "POST", b"client_id=evil-device", "application/x-www-form-urlencoded")
    device = json.loads(raw) if status == 200 else {}
    check("device_code" in device, f"a device code is issued to anyone ({status})")
    if "device_code" in device:
        status, raw = request("/api/auth", "POST", json.dumps({
            "type": "authDevice", "accountName": admin, "accountSecret": admin_pw,
            "code": device["user_code"]}).encode(), "application/json")
        print("     approval:", json.loads(raw).get("type") if status == 200 else status)
        status, raw = request("/auth/token", "POST", urllib.parse.urlencode({
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": "evil-device", "device_code": device["device_code"]}).encode(),
            "application/x-www-form-urlencoded")
        body = json.loads(raw or b"{}")
        check("access_token" not in body,
              f"but an administrator's approval can't be exchanged for a token ({status}, {body.get('error')})")

    # Recovery mode: the bypass is back, for the recovery administrator.
    restart({"INBUXA_RECOVERY_MODE": "1", "INBUXA_RECOVERY_ADMIN": f"admin:{recovery}"})
    got, how = phished("admin", recovery, "recovery-tool", EVIL)
    check(got, f"recovery mode: the recovery administrator signs in through an unregistered client ({how})")

    if os.environ.get("KEEP") != "1":
        stop()
        for sub in ("etc-override", "data-override"):
            shutil.rmtree(f"{DIR}/{sub}", ignore_errors=True)
        for name in ("override-recovery", "override-admin", "override-env"):
            try:
                os.remove(f"{DIR}/secrets/{name}")
            except FileNotFoundError:
                pass

    print()
    if failures:
        print(f"{len(failures)} failed")
        sys.exit(1)
    print("all passed")


if __name__ == "__main__":
    main()
