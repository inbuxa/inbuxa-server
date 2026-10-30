#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""Tiny stdlib JMAP client for the 0.16.27 import fixture rig."""
import base64, json, urllib.request, urllib.error

CAPS = [
    "urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail",
    "urn:ietf:params:jmap:submission", "urn:ietf:params:jmap:sieve",
    "urn:ietf:params:jmap:calendars", "urn:ietf:params:jmap:contacts",
    "urn:ietf:params:jmap:principals", "urn:ietf:params:jmap:vacationresponse",
]


class Jmap:
    def __init__(self, base, user, password, extra_caps=()):
        self.base, self.user = base.rstrip("/"), user
        tok = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.auth = {"Authorization": f"Basic {tok}"}
        self.caps = list(CAPS) + list(extra_caps)
        self._session = None

    def _req(self, method, path, body=None, ctype="application/json"):
        url = path if path.startswith("http") else self.base + path
        data = body if isinstance(body, (bytes, type(None))) else json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={**self.auth, "Content-Type": ctype})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"{method} {path}: HTTP {e.code}: {e.read()[:500]!r}")
        return json.loads(raw) if raw else None

    @property
    def session(self):
        if self._session is None:
            self._session = self._req("GET", "/jmap/session")
        return self._session

    def account_id(self, cap="urn:ietf:params:jmap:mail"):
        return self.session["primaryAccounts"].get(cap) or next(iter(self.session["accounts"]))

    def call(self, *calls):
        out = self._req("POST", "/jmap/", {"using": self.caps, "methodCalls": [
            [name, args, str(i)] for i, (name, args) in enumerate(calls)]})
        res = []
        for name, args, _ in out["methodResponses"]:
            if name == "error":
                raise RuntimeError(f"JMAP error: {json.dumps(args)[:800]}")
            res.append(args)
        return res

    def set_ok(self, resp, key="created"):
        bad = {k: v for k, v in resp.items() if k.startswith("not") and v}
        if bad:
            raise RuntimeError(f"set failed: {json.dumps(bad)[:1200]}")
        return resp.get(key) or {}

    def upload(self, data, ctype="application/octet-stream", account=None):
        account = account or self.account_id()
        url = self.local(self.session["uploadUrl"].replace("{accountId}", account))
        return self._req("POST", url, data, ctype)["blobId"]

    def local(self, url):
        # The session names the public hostname; the rig is on loopback.
        import urllib.parse
        u = urllib.parse.urlsplit(url)
        return self.base + urllib.parse.urlunsplit(("", "", u.path, u.query, ""))
