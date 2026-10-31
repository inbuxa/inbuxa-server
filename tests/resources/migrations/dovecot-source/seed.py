# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only

import imaplib, sys, time
port = int(sys.argv[1])
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
b.logout()
print("seeded")
