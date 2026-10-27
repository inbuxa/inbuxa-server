# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for tools/fork/strip.py: python3 -m unittest discover tools/fork/tests"""
import importlib.util
import os
import pathlib
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('strip', os.path.join(HERE, '..', 'strip.py'))
strip = importlib.util.module_from_spec(spec)
spec.loader.exec_module(strip)

MULTILINE = """use std::sync::Arc;

#[cfg(all(
    test,
    feature = "postgres",
))]
#[rustfmt::skip]
#[path = "../../missing/contention_tests.rs"]
mod contention_tests;

pub struct Batch {
    pub ops: Vec<u8>,
}
"""


class RemoveDanglingMods(unittest.TestCase):
    def strip_file(self, text):
        with tempfile.TemporaryDirectory() as d:
            src = pathlib.Path(d, 'src')
            src.mkdir()
            path = src / 'lib.rs'
            path.write_text(text, encoding='utf-8')
            removed = strip.remove_dangling_mods(pathlib.Path(d))
            return path.read_text(encoding='utf-8'), removed

    def test_multiline_attribute_goes_with_its_mod(self):
        out, removed = self.strip_file(MULTILINE)
        self.assertNotIn('cfg(all(', out)
        self.assertNotIn('feature = "postgres"', out)
        self.assertIn('pub struct Batch {', out)
        self.assertEqual(len(removed), 1)
        self.assertEqual(removed[0]['lines'][0], '#[cfg(all(')

    def test_single_line_attributes_still_removed(self):
        out, _ = self.strip_file('#[cfg(test)]\nmod tests;\n\nfn kept() {}\n')
        self.assertEqual(out, '\nfn kept() {}\n')

    def test_previous_item_is_untouched(self):
        out, _ = self.strip_file('const LIMIT: [u8; 2] = [0, 1];\nmod gone;\n')
        self.assertEqual(out, 'const LIMIT: [u8; 2] = [0, 1];\n')

    def test_existing_module_kept(self):
        with tempfile.TemporaryDirectory() as d:
            src = pathlib.Path(d, 'src')
            src.mkdir()
            (src / 'here.rs').write_text('', encoding='utf-8')
            (src / 'lib.rs').write_text('#[cfg(all(\n    test,\n))]\nmod here;\n', encoding='utf-8')
            self.assertEqual(strip.remove_dangling_mods(pathlib.Path(d)), [])


if __name__ == '__main__':
    unittest.main()
