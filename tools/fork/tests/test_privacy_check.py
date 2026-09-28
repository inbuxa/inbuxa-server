# SPDX-FileCopyrightText: 2026 Coffey Labs
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for tools/fork/privacy-check.py: python3 -m unittest discover tools/fork/tests"""
import gzip
import importlib.util
import json
import os
import tempfile
import tomllib
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('privacy_check', os.path.join(HERE, '..', 'privacy-check.py'))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

VOCAB = """
[vocabulary]
categories = ["identifier", "contact", "network", "content", "metadata", "credential"]
whose = ["holder", "correspondent", "administrator"]
where = ["data-store", "blob-store", "search-store", "in-memory-store", "memory", "log-file", "external"]
scope = ["tenant", "server"]
retention = ["unbounded", "object-life", "receiver"]
"""

GOOD = VOCAB + """
[object."x:Widget"]
default = "none"
whose = ["holder"]
where = ["data-store"]
scope = "tenant"
retention = { setting = "x:Widget.keepFor" }
[object."x:Widget".properties]
owner = ["identifier"]

[object."inbuxa:Gadget"]
file = "inbuxa_gadget.rs"
default = "none"
[object."inbuxa:Gadget".properties]
remoteIp = ["network"]

[source."widget-log"]
categories = ["network"]
where = ["log-file"]
scope = "server"
retention = "unbounded"
enabled_by = ["x:Widget.enable", "inbuxa:Gadget.remoteIp"]
leaves_host = false
written_by = ["crates/widget.rs"]
"""


def make_tree(fields):
    root = tempfile.mkdtemp()
    os.makedirs(os.path.join(root, 'resources/schema'))
    with gzip.open(os.path.join(root, check.SCHEMA), 'wt') as f:
        json.dump({'fields': fields}, f)
    os.makedirs(os.path.join(root, check.OBJECTS_DIR))
    with open(os.path.join(root, check.OBJECTS_DIR, 'inbuxa_gadget.rs'), 'w') as f:
        f.write('Property::RemoteIp => "remoteIp",\nProperty::Id => "id",\n')
    os.makedirs(os.path.join(root, 'crates/jmap-proto/src/request'), exist_ok=True)
    with open(os.path.join(root, check.METHODS), 'w') as f:
        f.write('"inbuxa:Gadget" => MethodObject::Gadget,\n')
    with open(os.path.join(root, 'crates/widget.rs'), 'w') as f:
        f.write('')
    return root


def prop(type_, fmt=None):
    t = {'type': type_}
    if fmt:
        t['format'] = fmt
    return {'type': t}


FIELDS = {
    'x:Widget': {'properties': {
        'owner': prop('string', 'emailAddress'),
        'enable': prop('boolean'),
        'keepFor': prop('number', 'duration'),
        'label': prop('string', 'string'),
    }},
}


class PrivacyCheck(unittest.TestCase):
    def run_check(self, catalog, fields=FIELDS):
        return check.findings(make_tree(fields), tomllib.loads(catalog))

    def test_the_repository_passes(self):
        with open(os.path.join(check.ROOT, check.CATALOG), 'rb') as f:
            catalog = tomllib.load(f)
        self.assertEqual(check.findings(check.ROOT, catalog), [])

    def test_a_consistent_catalog_passes(self):
        self.assertEqual(self.run_check(GOOD), [])

    def test_an_unclassified_object_fails(self):
        fields = dict(FIELDS, **{'x:Sprocket': {'properties': {'size': prop('number', 'size')}}})
        found = self.run_check(GOOD, fields)
        self.assertEqual(found, ['x:Sprocket: schema object has no catalog entry'])

    def test_an_address_hidden_behind_the_default_fails(self):
        fields = {'x:Widget': {'properties': dict(FIELDS['x:Widget']['properties'],
                                                  contactEmail=prop('string', 'emailAddress'))}}
        found = self.run_check(GOOD, fields)
        self.assertEqual(found, ['x:Widget.contactEmail: typed as identifier but not listed'])

    def test_a_secret_in_a_set_or_object_counts(self):
        fields = {'x:Widget': {'properties': dict(
            FIELDS['x:Widget']['properties'],
            ips={'type': {'type': 'set', 'class': {'type': 'string', 'format': 'ipNetwork'}}},
            key={'type': {'type': 'object', 'objectName': 'x:SecretKey'}},
        )}}
        found = self.run_check(GOOD, fields)
        self.assertIn('x:Widget.ips: typed as network but not listed', found)
        self.assertIn('x:Widget.key: typed as credential but not listed', found)

    def test_a_stale_property_fails(self):
        found = self.run_check(GOOD.replace('owner = ["identifier"]', 'owner = ["identifier"]\ngone = ["content"]'))
        self.assertEqual(found, ['x:Widget.gone: no such property (stale)'])

    def test_a_stale_object_fails(self):
        found = self.run_check(GOOD + '\n[object."x:Removed"]\ndefault = "none"\n')
        self.assertEqual(found, ['x:Removed: no such schema object (stale)'])

    def test_a_stale_setting_fails(self):
        found = self.run_check(GOOD.replace('x:Widget.keepFor', 'x:Widget.keepForever'))
        self.assertEqual(found, ['x:Widget: setting x:Widget.keepForever names no property of x:Widget'])

    def test_a_stale_code_path_fails(self):
        found = self.run_check(GOOD.replace('crates/widget.rs', 'crates/gone.rs'))
        self.assertEqual(found, ['source "widget-log": written_by crates/gone.rs doesn\'t exist (stale)'])

    def test_an_unlisted_inbuxa_object_fails(self):
        catalog = VOCAB + """
[object."x:Widget"]
default = "none"
[object."x:Widget".properties]
owner = ["identifier"]
"""
        found = self.run_check(catalog)
        self.assertEqual(found, ['inbuxa:Gadget: inbuxa object has no catalog entry'])

    def test_words_outside_the_vocabulary_fail(self):
        found = self.run_check(GOOD.replace('owner = ["identifier"]', 'owner = ["personal"]'))
        self.assertEqual(found, ['x:Widget.owner: "personal" is not in vocabulary.categories'])

    def test_unlisted_prints_a_starting_entry(self):
        fields = dict(FIELDS, **{'x:Sprocket': {'properties': {'mail': prop('string', 'emailAddress')}}})
        lines = check.unlisted(make_tree(fields), tomllib.loads(GOOD))
        self.assertIn('[object."x:Sprocket"]', lines)
        self.assertIn('mail = ["identifier"]', lines)


class StripReport(unittest.TestCase):
    def test_an_import_reports_what_is_new_and_unclassified(self):
        import pathlib
        strip_spec = importlib.util.spec_from_file_location('strip', os.path.join(HERE, '..', 'strip.py'))
        strip = importlib.util.module_from_spec(strip_spec)
        strip_spec.loader.exec_module(strip)
        with gzip.open(os.path.join(check.ROOT, check.SCHEMA)) as f:
            upstream = json.load(f)
        upstream['fields']['x:NewThing'] = {'properties': {}}
        upstream['fields']['x:UserAccount']['properties']['backupEmail'] = prop('string', 'emailAddress')
        tree = pathlib.Path(tempfile.mkdtemp())
        (tree / 'resources/schema').mkdir(parents=True)
        with gzip.open(tree / 'resources/schema/schema.json.gz', 'wt') as f:
            json.dump(upstream, f)
        self.assertEqual(strip.privacy_flags(tree), {
            'objects': ['x:NewThing'],
            'fields': ['x:UserAccount.backupEmail (identifier)'],
        })


if __name__ == '__main__':
    unittest.main()
