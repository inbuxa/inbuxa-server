# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for tools/release/version.py: python3 -m unittest discover -s tools/release/tests"""
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("version", os.path.join(HERE, "..", "version.py"))
version = importlib.util.module_from_spec(spec)
spec.loader.exec_module(version)


class Display(unittest.TestCase):
    # The same cases as crates/utils/proc-macros/src/version.rs: the server
    # and the workflows must name a version the same way.
    def test_shown(self):
        for cargo, shown in [
            ("27.1.0", "27.1"),
            ("27.1.3", "27.1.3"),
            ("27.1.0-rc.1", "27.1-rc.1"),
            ("27.7.0-rc.12", "27.7-rc.12"),
            ("28.1.10", "28.1.10"),
        ]:
            self.assertEqual(version.display(cargo), shown, cargo)

    def test_refused(self):
        for cargo in ["27.1", "27.1.0.1", "27.1.1-rc.1", "27.1.0-rc.0", "27.1.0-beta.1",
                      "27.01.0", "2026.10.28.1", "2026.11.2", "27.13.0", ""]:
            with self.assertRaises(ValueError, msg=cargo):
                version.display(cargo)

    def test_image_tags(self):
        self.assertEqual(version.image_tags("27.1.0-rc.2"), ["27.1-rc.2", "27.1-rc"])
        self.assertEqual(version.image_tags("27.1.0"), ["27.1", "latest"])
        self.assertEqual(version.image_tags("27.1.4"), ["27.1.4", "27.1", "latest"])

    def test_weekly(self):
        self.assertIsNone(version.next_patch("27.1.0-rc.3"))
        self.assertEqual(version.next_patch("27.1.0"), "27.1.1")
        self.assertEqual(version.next_patch("27.1.9"), "27.1.10")


class SetVersion(unittest.TestCase):
    """--set on a copy of this repository's Cargo.toml, Cargo.lock and member
    manifests: a round trip gives the files back unchanged, and Cargo accepts
    the bumped lockfile as it is."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        src = version.ROOT
        shutil.copy(src / "Cargo.toml", self.tmp / "Cargo.toml")
        shutil.copy(src / "Cargo.lock", self.tmp / "Cargo.lock")
        for member in version.tomllib.loads((src / "Cargo.toml").read_text())["workspace"]["members"]:
            (self.tmp / member).mkdir(parents=True, exist_ok=True)
            shutil.copy(src / member / "Cargo.toml", self.tmp / member / "Cargo.toml")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def write(self, files):
        for path, text in files.items():
            path.write_text(text)

    def test_round_trip(self):
        before = {p: (self.tmp / p).read_text() for p in ("Cargo.toml", "Cargo.lock")}
        old = version.cargo_version(self.tmp)
        self.write(version.set_version("27.7.0-rc.4", self.tmp))
        self.assertEqual(version.cargo_version(self.tmp), "27.7.0-rc.4")
        lock = (self.tmp / "Cargo.lock").read_text()
        self.assertEqual(lock.count('version = "27.7.0-rc.4"'), len(version.members(self.tmp)))
        self.write(version.set_version(old, self.tmp))
        for p, text in before.items():
            self.assertEqual((self.tmp / p).read_text(), text, p)

    def test_refuses_a_bad_version(self):
        with self.assertRaises(ValueError):
            version.set_version("2026.11.2", self.tmp)

    @unittest.skipUnless(shutil.which("cargo"), "no cargo here")
    def test_cargo_accepts_it(self):
        # In the real tree, since cargo needs every member's sources.
        root = version.ROOT
        files = version.set_version("27.1.0-rc.9", root)
        saved = {p: p.read_text() for p in files}
        try:
            self.write(files)
            run = subprocess.run(["cargo", "metadata", "--locked", "--offline",
                                  "--format-version", "1"], cwd=root, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
        finally:
            self.write(saved)


if __name__ == "__main__":
    unittest.main()
