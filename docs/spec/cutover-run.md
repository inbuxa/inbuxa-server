# The run

Status: 2026-09-19. The sheet for INBUXA's own cutover, to be followed at
the terminal.

`cutover.md` is why; this is what to type. Where they disagree, this page is
wrong — it is the general plan cut down to one small install, and anything
surprising belongs back there.

## This install

Eight mailboxes, two people and a printer (John, 2026-09-19). That scale
decides three things the general plan leaves open:

- **The store is small, so the copy is seconds.** `cutover.md` step 3's
  two-pass rsync exists for a store large enough that copying it dominates
  the window. Here it is complexity with nothing to buy, and a simpler
  sequence at 2am is worth more. One `cp -a` inside the window.
- **"Every account still works" is a five-minute check**, not a programme.
  Two people sign in; the printer sends one scan.
- **A reboot inside the window is affordable**, which is the only honest way
  to prove the old unit stays down. See step 9.

Fill these in before starting, rather than looking them up mid-window:

| | |
|---|---|
| Fork prefix | `______` (its config and unit; **not** under `/opt/stalwart`) |
| Fork store | `/var/lib/inbuxa` |
| Old webmail container | `______` |
| Administrator | `______` |
| Printer account, port, auth | `______` |

## Before the window — nothing stopped, no rush

1. **The artifact exists and says the right thing.**

   ```sh
   inbuxa --version      # 2026.9.18 (Stalwart 0.16.22)
   ```

   Built `--release`, on this machine's glibc or in the image that will run
   it. A debug binary is not what serves this.

2. **The service user exists**, because the copy is chowned to it in step 5
   and the unit runs as it.

   ```sh
   id inbuxa || useradd -r -s /usr/sbin/nologin inbuxa
   ```

3. **The config and unit are written and point at the fork's own paths.**
   Nothing either of them names may be inside `/opt/stalwart`: it is a
   reference from here on and will eventually go
   (`cutover.md`, "Retiring the old install"). The unit keeps
   `AmbientCapabilities=CAP_NET_BIND_SERVICE`, which is what lets an
   unprivileged process hold port 25.

4. **Write down what has to be true afterwards**, while the old server can
   still be asked: each mailbox and its message count, the two people's
   addresses, the aliases, and what the printer sends as.

## The window

5. **Stop the old server, and make sure it cannot come back.**

   ```sh
   systemctl stop stalwart
   systemctl disable stalwart
   systemctl mask stalwart          # stronger: cannot start even as a dependency
   systemctl is-enabled stalwart    # expect: masked
   docker stop <old-webmail>
   ```

   Wait for the process to have actually exited, not just for `stop` to
   return.

6. **Copy the store and the config**, and hand them to the user the fork
   runs as.

   ```sh
   cp -a /opt/stalwart/data /var/lib/inbuxa
   chown -R inbuxa:inbuxa /var/lib/inbuxa
   ```

   A copy, never a move. `cp -a` preserves ownership, so the chown is not
   optional — without it the fork cannot write its own store.

7. **Make the original unwritable, before the fork is started.**

   ```sh
   chattr +i /opt/stalwart/data
   ```

   Until step 5 the old server's own RocksDB lock was the only thing
   stopping anything else opening that store, and stopping it took that
   away. One open by the fork adds its column family and the Enterprise
   build never starts on it again — the rollback would be gone, with no way
   back (`cutover.md`, "Answered"). This is the line that protects it.

8. **Start the fork, and read the log before anything else.**

   ```sh
   systemctl enable --now inbuxa
   journalctl -u inbuxa -n 50 --no-pager
   ```

   Expect deprecation warnings naming any `STALWART_*` settings to rename,
   and a note that `INBUXA_RECOVERY_ADMIN` is ignored on a configured server
   — both are normal. Anything at ERROR is not.

9. **Reboot the host.**

   The only honest proof that the fork comes up on boot and the old unit
   does not. It costs a few minutes here and nothing else does the job:
   `is-enabled` says what is configured, a reboot says what happens.

   ```sh
   reboot
   # then
   systemctl is-active inbuxa     # active
   systemctl is-enabled stalwart  # masked
   ```

## Before letting mail flow

10. Work down this list. It is short because the install is.

    - `inbuxa --version` names the right base.
    - Every listener is up, and the certificate served on 443 and 993 is the
      real one, not a self-signed fallback.
    - **Both people** sign in, with the passwords they already had, over
      IMAP and through the front ends. Nothing in this move touches
      credentials — they are in the store that was copied — so a failure
      here is the copy or the front ends, not the account.
    - Each mailbox holds what step 4 recorded.
    - A message from outside arrives. A message from inside leaves.
    - Aliases still deliver.
    - The queue is draining and the task queue has no new permanent
      failures.
    - Nothing is listening on the old ports but the fork.

11. **The printer.** Send a scan through it.

    It is the one user that cannot tell you it is broken. Scan-to-email
    boxes carry a hardcoded credential, an old TLS stack, and often plain
    auth on 25 or 587 without STARTTLS — the kind of client a stricter
    default quietly starts refusing. The two humans will phone; the printer
    will simply stop, and it will be a fortnight before anyone asks where
    their document went.

    Do this before calling the cutover done, not after.

## Rollback

Minutes, and no restore, because the old install and its store are
untouched.

```sh
systemctl disable --now inbuxa
chattr -i /opt/stalwart/data     # FIRST — step 7 blocks the old build too
systemctl unmask stalwart
systemctl enable --now stalwart
docker start <old-webmail>
```

**The `chattr -i` comes first.** The guard of step 7 stops the Enterprise
build opening that store exactly as it stops the fork; skipping it fails the
rollback with what looks like a permissions problem, at the worst possible
moment.

**What it costs** is everything the fork accepted while it served — mail
delivered to the fork's store is not in the old one. That is free between
step 8 and step 10, and stops being free the moment mail flows. Decide
early and deliberately.

**What it never is:** pointing the old build at the fork's store. That is
not a recovery path and cannot be made into one.

## Afterwards

- **Do not delete `/opt/stalwart`.** It stays, shut down, masked and
  read-only, until it is deliberately retired (`cutover.md`). It costs a
  stopped unit and some disk.
- **Watch for the first certificate renewal.** The one failure that says
  nothing for ninety days and then takes the service down. Forcing a
  renewal answers it in a day instead.
- **Point a stock ihasmail at the fork** and note what it can no longer do,
  each difference being either a regression against upstream's contract or a
  feature that now expects INBUXA's own front ends (`cutover.md`).
- **Time every phase and keep the numbers.** This run is the first run of
  the migration tool (`migration.md`), and what it measures here is what
  that tool will advertise. A small server's migration should be minutes;
  the figure published should be one measured here, against a stated store
  size and account count.
