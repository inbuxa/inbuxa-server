#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""Run the 0.16.27 setup wizard over JMAP and save the administrator it creates."""
import sys, json, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jmap import Jmap
j = Jmap(sys.argv[1], "admin", os.environ["BOOT_PASSWORD"], ["urn:stalwart:jmap"])
r = j.call(("x:Bootstrap/set", {"update": {"singleton": {
    "serverHostname": "mail.example.org", "defaultDomain": "example.org",
    "requestTlsCertificate": False, "generateDkimKeys": True,
    "tracer": {"@type": "Stdout", "enable": True, "level": "info", "ansi": False,
               "multiline": False, "lossy": False, "events": {}, "eventsPolicy": "exclude"}}}}))
json.dump(j.set_ok(r[0], "updated")["singleton"], open(os.path.join(os.environ["FIXTURE"], "admin.json"), "w"), indent=2)
