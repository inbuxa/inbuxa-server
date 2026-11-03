# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for tools/fork/docs-only.py: python3 -m unittest discover -s tools/fork/tests"""
import contextlib
import importlib.util
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("docs_only", os.path.join(HERE, "..", "docs-only.py"))
docs_only = importlib.util.module_from_spec(spec)
spec.loader.exec_module(docs_only)


class Paths(unittest.TestCase):
    def test_documentation(self):
        for paths in (["README.md"], ["CHANGELOG.md", "docs/spec/SPEC.md"], ["docs/img/a.png"]):
            self.assertTrue(docs_only.is_docs_only(paths), paths)

    def test_not_documentation(self):
        for paths in (
            [],
            ["Cargo.toml"],
            ["README.md", "crates/main/src/main.rs"],
            ["vendor/calcard/README.md"],
            ["crates/main/README.md"],
            [".github/workflows/ci.yml"],
            ["docs"],
            ["README.md\nsrc/main.rs"],
        ):
            self.assertFalse(docs_only.is_docs_only(paths), paths)


class Branches(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name)
        self.git("init", "-q", "-b", "main")
        self.commit({"README.md": "one\n", "src.rs": "fn main() {}\n"})
        self.git("branch", "base")
        self.git("switch", "-q", "-c", "work")

    def git(self, *args):
        subprocess.run(
            [
                "git",
                "-c", "user.name=t",
                "-c", "user.email=t@example.org",
                "-c", "commit.gpgsign=false",
                *args,
            ],
            cwd=self.repo,
            check=True,
            capture_output=True,
        )

    def commit(self, files):
        for name, text in files.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "change")

    def answer(self, ref="refs/heads/work", base="base"):
        with contextlib.redirect_stdout(io.StringIO()):
            return docs_only.answer(ref, base, self.repo)

    def test_docs_commit_is_docs_only(self):
        self.commit({"README.md": "two\n", "docs/a.md": "a\n"})
        self.assertTrue(self.answer())

    def test_code_commit_builds(self):
        self.commit({"src.rs": "fn main() { }\n"})
        self.assertFalse(self.answer())

    def test_docs_commit_on_top_of_code_still_builds(self):
        self.commit({"src.rs": "fn main() { }\n"})
        self.commit({"README.md": "two\n"})
        self.assertFalse(self.answer())

    def test_nothing_changed_builds(self):
        self.assertFalse(self.answer())

    def test_moving_code_into_docs_builds(self):
        self.git("mv", "src.rs", "docs-src.rs")
        (self.repo / "docs").mkdir()
        self.git("mv", "docs-src.rs", "docs/src.rs")
        self.git("commit", "-q", "-m", "move")
        self.assertFalse(self.answer())

    def test_code_landing_on_main_since_the_branch_left_it_does_not_count(self):
        self.commit({"README.md": "two\n"})
        self.git("switch", "-q", "base")
        self.commit({"src.rs": "fn main() { }\n"})
        self.git("switch", "-q", "work")
        self.assertTrue(self.answer())

    def test_main_always_builds(self):
        self.commit({"README.md": "two\n"})
        self.assertFalse(self.answer("refs/heads/main"))

    def test_git_failing_builds(self):
        self.commit({"README.md": "two\n"})
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(self.answer(base="no-such-ref"))


if __name__ == "__main__":
    unittest.main()
