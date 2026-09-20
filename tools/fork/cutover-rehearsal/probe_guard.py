#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs
# SPDX-License-Identifier: AGPL-3.0-only
"""What actually stops the fork opening the original store by mistake.

cutover.md step 3 says "a copy, not a move", and the rehearsal showed why:
one open by the fork adds its column family and the Enterprise build can
never start on that store again. So the question is what prevents the
mistake, mechanically, rather than by being careful at 1am.

Three probes, in order, the last of which destroys the fixture:

  A  the old server is running      — does RocksDB's own lock refuse?
  B  stopped, store mounted read-only — does the fork refuse harmlessly?
  C  stopped, writable               — the accident, confirmed end to end

Run phase1.py first; this uses the install it leaves behind.
"""
import os, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib

OLD = lib.INSTALLS["old"]["dir"]
PROBE = "cutover-probe"


def try_fork_on(path, read_only=False, label=""):
    """Point the fork at `path` and report how it fails, or that it didn't."""
    lib.docker("rm", "-f", PROBE, check_rc=False)
    mount = f"{path}/data:/var/lib/stalwart" + (":ro" if read_only else "")
    lib.docker(
        "run", "-d", "--name", PROBE,
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--entrypoint", "/usr/local/bin/inbuxa",
        "-v", f"{lib.ROOT}/target/debug/inbuxa:/usr/local/bin/inbuxa:ro",
        "-v", f"{path}/etc:/etc/stalwart" + (":ro" if read_only else ""),
        "-v", mount,
        lib.IMAGE, "--config", "/etc/stalwart/config.json",
        check_rc=False,
    )
    time.sleep(8)
    state = lib.docker("inspect", "-f", "{{.State.Status}} exit={{.State.ExitCode}}",
                       PROBE, check_rc=False).stdout.strip()
    log = lib.docker("logs", "--tail", "40", PROBE, check_rc=False)
    text = (log.stdout or "") + (log.stderr or "")
    lib.docker("rm", "-f", PROBE, check_rc=False)
    first = next((l.strip() for l in text.splitlines()
                  if "failed" in l.lower() or "error" in l.lower()), "")
    print(f"  {label}: {state}")
    if first:
        print(f"    {first[:170]}")
    return state, text


def upstream_can_open(path):
    """Whether upstream 0.16.22 still starts on this store — the rollback."""
    name = "cutover-upstream-check"
    lib.docker("rm", "-f", name, check_rc=False)
    lib.docker(
        "run", "-d", "--name", name,
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--entrypoint", "/usr/local/bin/stalwart",
        "-v", f"{lib.ROOT}/target/debug/stalwart:/usr/local/bin/stalwart:ro",
        "-v", f"{path}/etc:/etc/stalwart",
        "-v", f"{path}/data:/var/lib/stalwart",
        lib.IMAGE, "--config", "/etc/stalwart/config.json",
        check_rc=False,
    )
    time.sleep(10)
    status = lib.docker("inspect", "-f", "{{.State.Status}}", name, check_rc=False).stdout.strip()
    log = lib.docker("logs", "--tail", "20", name, check_rc=False)
    text = (log.stdout or "") + (log.stderr or "")
    lib.docker("rm", "-f", name, check_rc=False)
    return status == "running", text


def main():
    print("== probe A: the old server is running\n")
    if not lib.wait_http(5):
        print("  the old install is not up — run phase1.py first")
        sys.exit(2)
    state, text = try_fork_on(OLD, label="fork pointed at the live store")
    locked = "lock" in text.lower() or "LOCK" in text
    lib.check(state.startswith("exited"),
              "the fork refuses to open a store another process holds")
    lib.check(locked, "it is RocksDB's lock that refuses it",
              "so the running server is itself the guard")

    print("\n== probe B: stopped, but the store is read-only\n")
    lib.stop("old")
    time.sleep(2)
    state, text = try_fork_on(OLD, read_only=True, label="fork pointed at a read-only store")
    lib.check(state.startswith("exited"), "the fork refuses a read-only store")
    ok, _ = upstream_can_open(OLD)
    lib.check(ok, "upstream still starts on it — the rollback is intact",
              "a read-only original survives being pointed at")

    print("\n== probe C: stopped and writable — the accident\n")
    state, text = try_fork_on(OLD, label="fork pointed at the writable original")
    ok, _ = upstream_can_open(OLD)
    lib.check(not ok, "upstream can no longer start — the rollback is gone",
              "one open was enough" if not ok else "unexpectedly survived")

    lib.summary("probe")
    print("\nThe fixture is now poisoned by design; re-run phase1.py to rebuild it.")


if __name__ == "__main__":
    main()
