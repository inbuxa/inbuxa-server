# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
#
# python3 seed.py PORT [--bulk N]: a@example.org gets three messages in
# INBOX, b@example.org one in INBOX and one in Projects. --bulk adds N more
# to b@'s Bulk folder, so a run over it lasts long enough to interrupt.

import imaplib, sys, time
port = int(sys.argv[1])
bulk = int(sys.argv[sys.argv.index("--bulk") + 1]) if "--bulk" in sys.argv else 0
def msg(n, subject):
    return (f"From: old@example.net\r\nTo: x@example.org\r\nSubject: {subject}\r\n"
            f"Message-ID: <e2e-{n}@example.net>\r\nDate: Mon, 4 Mar 2024 09:00:00 +0000\r\n\r\nHi {n}\r\n").encode()
for _ in range(50):
    try:
        imaplib.IMAP4("127.0.0.1", port).logout(); break
    except OSError:
        time.sleep(0.2)
a = imaplib.IMAP4("127.0.0.1", port); a.login("a@example.org", "pass-a")
for n in range(1, 4):
    a.append("INBOX", r"(\Seen)" if n == 1 else None, None, msg(f"a{n}", f"A message {n}"))
a.logout()
b = imaplib.IMAP4("127.0.0.1", port); b.login("b@example.org", "pass-b")
b.create("Projects")
b.append("INBOX", None, None, msg("b1", "B inbox"))
b.append("Projects", r"(\Flagged)", None, msg("b2", "B project"))
if bulk:
    b.create("Bulk")
    for n in range(1, bulk + 1):
        b.append("Bulk", None, None, msg(f"bulk{n}", f"Bulk {n}"))
b.logout()
print("seeded")
