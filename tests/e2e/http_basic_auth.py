#!/usr/bin/env python3
"""Local end-to-end check of contract C-23: outside DAV, HTTP sign-in is a
token, never a password.

Run it with `python3 tests/e2e/http_basic_auth.py` after
`cargo build -p inbuxa`. Needs Docker. Working state goes under target/e2e.

Boots the debug binary and checks that:
- in bootstrap mode, Basic works on JMAP (as permissive CORS does, C-16);
- after setup, Basic is refused on JMAP, the API, userinfo and introspection,
  with a 401 that offers only Bearer, and the password isn't checked;
- DAV still takes Basic, and its 401 still offers it;
- a token from the sign-in endpoint (`/api/auth`, the password in the body)
  and the token endpoint works on JMAP: the path the front ends use, and the
  one inbuxa-webmail's password check relies on;
- INBUXA_HTTP_BASIC_AUTH=all puts Basic back everywhere, an unknown value
  keeps the default with a warning, and recovery mode accepts Basic.

Passwords are generated into files under target/e2e and never printed.
Everything is removed afterwards unless KEEP=1.
"""

import base64, hashlib, json, os, secrets, shutil, subprocess, sys, time, urllib.error, urllib.parse, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DIR = f"{ROOT}/target/e2e"
NAME = "inbuxa-basic-auth"
PORT = 18180
HTTP = f"http://127.0.0.1:{PORT}"
ADMIN_URL = "http://admin.basic.test"
REDIRECT = f"{ADMIN_URL}/oauth/callback"
WEBMAIL_URL = "http://webmail.basic.test"
WEBMAIL_REDIRECT = f"{WEBMAIL_URL}/api/auth/callback"

failures = []
WEBMAIL_SECRET = secrets.token_urlsafe(24)


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
    args = ["run", "-d", "--name", NAME, "--user", f"{os.getuid()}:{os.getgid()}",
            "--entrypoint", "/usr/local/bin/inbuxa",
            "-v", f"{ROOT}/target/debug/inbuxa:/usr/local/bin/inbuxa:ro",
            "-v", f"{DIR}/etc-basic:/etc/inbuxa", "-v", f"{DIR}/data-basic:/var/lib/inbuxa",
            "-p", f"127.0.0.1:{PORT}:8080",
            # A debug build's workers need more than the default stack.
            "-e", "RUST_MIN_STACK=16777216",
            # Registers inbuxa-admin and inbuxa-webmail (C-6).
            "-e", f"INBUXA_ADMIN_URL={ADMIN_URL}", "-e", f"INBUXA_WEBMAIL_URL={WEBMAIL_URL}"]
    env_file = f"{DIR}/secrets/basic-env"
    with open(env_file, "w") as f:
        f.write(f"INBUXA_WEBMAIL_CLIENT_SECRET={WEBMAIL_SECRET}\n")
        for key, value in (env or {}).items():
            f.write(f"{key}={value}\n")
    os.chmod(env_file, 0o600)
    args += ["--env-file", env_file, "stalwartlabs/stalwart:v0.16.22", "--config", "/etc/inbuxa/config.json"]
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


def restart(env=None):
    stop()
    start(env)


def basic(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def request(path, authorization=None, method="GET", body=None, content_type=None, headers=None):
    """(status, headers, body) for a request, whatever the status."""
    req = urllib.request.Request(f"{HTTP}{path}", data=body, method=method)
    if authorization:
        req.add_header("Authorization", authorization)
    if content_type:
        req.add_header("Content-Type", content_type)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.headers, err.read()


def challenges(headers):
    return sorted(value.split(" ", 1)[0] for value in headers.get_all("WWW-Authenticate") or [])


def jmap(authorization, calls):
    body = json.dumps({"using": ["urn:ietf:params:jmap:core", "urn:inbuxa:jmap:registry"],
                       "methodCalls": calls}).encode()
    status, _, raw = request("/jmap/", authorization, "POST", body, "application/json")
    if status != 200:
        sys.exit(f"JMAP call failed: {status}")
    return json.loads(raw)["methodResponses"]


def sign_in(user, password, client_id, redirect_uri, verifier):
    """What the sign-in endpoint answers, the password in the request body."""
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    status, _, raw = request("/api/auth", method="POST", content_type="application/json", body=json.dumps({
        "type": "authCode", "accountName": user, "accountSecret": password,
        "clientId": client_id, "redirectUri": redirect_uri,
        "codeChallenge": challenge, "codeChallengeMethod": "S256"}).encode())
    return json.loads(raw) if status == 200 else {"type": status}


def token(user, password):
    """An access token the way a front end gets one: the sign-in endpoint, then
    the token endpoint, with PKCE."""
    verifier = secrets.token_urlsafe(48)
    answer = sign_in(user, password, "inbuxa-admin", REDIRECT, verifier)
    if answer.get("type") != "authenticated":
        return None, answer.get("type") or status
    status, _, raw = request("/auth/token", method="POST", content_type="application/x-www-form-urlencoded",
                             body=urllib.parse.urlencode({
                                 "grant_type": "authorization_code", "client_id": "inbuxa-admin",
                                 "code": answer["client_code"], "redirect_uri": REDIRECT,
                                 "code_verifier": verifier}).encode())
    if status != 200:
        return None, status
    return json.loads(raw)["access_token"], "authenticated"


def propfind(path, authorization):
    return request(path, authorization, "PROPFIND", b'<?xml version="1.0"?><propfind xmlns="DAV:"><prop><resourcetype/></prop></propfind>',
                   "application/xml", {"Depth": "0"})


def main():
    stop()
    for sub in ("etc-basic", "data-basic"):
        shutil.rmtree(f"{DIR}/{sub}", ignore_errors=True)
    for sub in ("etc-basic", "data-basic", "secrets"):
        os.makedirs(f"{DIR}/{sub}", exist_ok=True)
    os.chmod(f"{DIR}/secrets", 0o700)

    # Bootstrap mode: Basic works on JMAP, as it must for the setup wizard.
    recovery = secret_file("basic-recovery")
    start({"INBUXA_RECOVERY_ADMIN": f"admin:{recovery}"})
    status, _, _ = request("/jmap/session", basic("admin", recovery))
    check(status == 200, "bootstrap mode: Basic works on JMAP")
    got = jmap(basic("admin", recovery), [["x:Bootstrap/get", {"ids": None}, "0"]])
    singleton = got[0][1]["list"][0]["id"]
    res = jmap(basic("admin", recovery), [["x:Bootstrap/set", {"update": {singleton: {
        "serverHostname": "mail.basic.test", "defaultDomain": "basic.test",
        "requestTlsCertificate": False}}}, "0"]])
    updated = res[0][1].get("updated", {}).get(singleton)
    check(bool(updated), "bootstrap completed")
    if not updated:
        sys.exit(json.dumps(res))
    admin, admin_pw = updated["username"], secret_file("basic-admin", updated["secret"])

    # After setup, the default: Basic on DAV only. What follows needs a
    # tracer to stdout, to read warnings back, and a user account for the
    # webmail's password check. Both are made with a token, since Basic no
    # longer reaches JMAP.
    restart()
    admin_token, how = token(admin, admin_pw)
    if not admin_token:
        sys.exit(f"no token for the administrator: {how}")
    domain = jmap(f"Bearer {admin_token}", [["x:Domain/get", {"ids": None}, "0"]])[0][1]["list"][0]["id"]
    user, user_pw = "u@basic.test", secret_file("basic-user")
    res = jmap(f"Bearer {admin_token}", [
        ["x:Tracer/set", {"create": {"t": {"@type": "Stdout", "level": "info", "buffered": False, "ansi": False}}}, "0"],
        ["x:Account/set", {"create": {"a": {"@type": "User", "name": "u", "domainId": domain,
                                            "credentials": {"0": {"@type": "Password", "secret": user_pw}}}}}, "1"]])
    if not (res[0][1].get("created") or {}).get("t") or not (res[1][1].get("created") or {}).get("a"):
        sys.exit("setup failed: " + json.dumps(res))
    restart()
    right, wrong = basic(admin, admin_pw), basic(admin, "not-the-password")
    status, headers, _ = request("/jmap/session", right)
    check(status == 401, "Basic with the right password is refused on /jmap/session")
    check(challenges(headers) == ["Bearer"], f"that 401 offers only Bearer ({challenges(headers)})")
    status, _, _ = request("/jmap/", right, "POST", b'{"using":[],"methodCalls":[]}', "application/json")
    check(status == 401, "Basic is refused on a JMAP API call")
    status, headers, _ = request("/jmap/", None, "POST", b'{"using":[],"methodCalls":[]}', "application/json")
    check(status == 401 and challenges(headers) == ["Bearer"],
          f"an unauthenticated JMAP call's 401 offers only Bearer ({challenges(headers)})")
    for path in ("/api/account", "/auth/userinfo"):
        status, headers, _ = request(path, right)
        check(status == 401 and challenges(headers) == ["Bearer"], f"Basic is refused on {path}")
    status, _, _ = request("/auth/introspect", right, "POST", b"token=x", "application/x-www-form-urlencoded")
    check(status == 401, "Basic is refused on /auth/introspect")

    # Refused before the password is looked at, so the answer is the same
    # either way and can't be used to guess one.
    status_right, headers_right, body_right = request("/jmap/session", right)
    status_wrong, headers_wrong, body_wrong = request("/jmap/session", wrong)
    check((status_wrong, challenges(headers_wrong), body_wrong) == (status_right, challenges(headers_right), body_right),
          "a wrong password over Basic gets exactly the same answer as the right one")

    # DAV keeps Basic.
    status, _, _ = propfind(f"/dav/card/{admin}/", right)
    check(status == 207, f"Basic works on CardDAV ({status})")
    status, _, _ = propfind(f"/dav/cal/{admin}/", right)
    check(status == 207, f"Basic works on CalDAV ({status})")
    status, headers, _ = propfind(f"/dav/card/{admin}/", None)
    check(status == 401 and "Basic" in challenges(headers),
          f"DAV's 401 still offers Basic ({challenges(headers)})")

    # The front ends' path: the sign-in endpoint and a token.
    access, how = token(admin, admin_pw)
    check(access is not None, f"the sign-in endpoint takes the password in its body ({how})")
    _, how_wrong = token(admin, "not-the-password")
    check(how_wrong == "failure", f"and says failure for a wrong one ({how_wrong})")
    if access:
        status, _, _ = request("/jmap/session", f"Bearer {access}")
        check(status == 200, "a token works on /jmap/session")
        status, _, _ = request("/api/account", f"Bearer {access}")
        check(status == 200, f"a token works on /api/account ({status})")

    # inbuxa-webmail's password check before an app password: its own client,
    # its registered redirect URI, a verifier it throws away.
    for password, want in ((user_pw, "authenticated"), ("not-the-password", "failure")):
        got = sign_in(user, password, "ihasmail-inbuxa", WEBMAIL_REDIRECT, secrets.token_urlsafe(48))
        check(got.get("type") == want, f"the webmail's password check answers {want} ({got.get('type')})")
    got = sign_in(user, user_pw, "ihasmail-inbuxa", "https://evil.example/cb", secrets.token_urlsafe(48))
    check(got.get("type") != "authenticated", f"but not to a redirect URI it didn't register ({got.get('type')})")

    # The operator's switch.
    restart({"INBUXA_HTTP_BASIC_AUTH": "all"})
    status, _, _ = request("/jmap/session", right)
    check(status == 200, "INBUXA_HTTP_BASIC_AUTH=all: Basic works on JMAP again")
    status, headers, _ = request("/jmap/", None, "POST", b'{"using":[],"methodCalls":[]}', "application/json")
    check("Basic" in challenges(headers), f"and JMAP's 401 offers it again ({challenges(headers)})")

    restart({"INBUXA_HTTP_BASIC_AUTH": "sometimes"})
    status, _, _ = request("/jmap/session", right)
    check(status == 401, "an unknown INBUXA_HTTP_BASIC_AUTH keeps Basic refused")
    logs = docker("logs", NAME, check_rc=False)
    check("INBUXA_HTTP_BASIC_AUTH" in logs.stdout + logs.stderr, "and says so in the log")

    restart({"INBUXA_HTTP_BASIC_AUTH": "dav"})
    status, _, _ = request("/jmap/session", right)
    check(status == 401, "INBUXA_HTTP_BASIC_AUTH=dav is the default")

    # Recovery mode accepts Basic, for the recovery administrator.
    restart({"INBUXA_RECOVERY_MODE": "1", "INBUXA_RECOVERY_ADMIN": f"admin:{recovery}"})
    status, _, _ = request("/jmap/session", basic("admin", recovery))
    check(status == 200, "recovery mode: Basic works on JMAP")

    if os.environ.get("KEEP") != "1":
        stop()
        for sub in ("etc-basic", "data-basic"):
            shutil.rmtree(f"{DIR}/{sub}", ignore_errors=True)
        for name in ("basic-recovery", "basic-admin", "basic-user", "basic-env"):
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
