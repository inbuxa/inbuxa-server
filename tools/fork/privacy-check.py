#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""
Fail when the personal-data catalog and the code disagree.

    tools/fork/privacy-check.py              # check; exit 1 on any finding
    tools/fork/privacy-check.py --unlisted   # print catalog entries for what's missing

The catalog (`resources/privacy/catalog.toml`, spec
`docs/spec/features/personal-data-catalog.md`) says, for every object and
source, what personal data it can hold. An upstream import can bring objects
and fields nobody has classified, and a refactor can leave the catalog naming
things that are gone; either way the catalog stops being true without anyone
noticing, so this runs in CI on every push and pull request. It fails when:

  1. an object in the schema's `fields`, or one of inbuxa's own JMAP objects,
     has no catalog entry;
  2. a property the schema types as an email address, an IP address or
     network, or a secret is covered only by its object's `default` -- it
     must be listed, so a new personal field can't hide behind a default;
  3. an entry names an object, property, setting or code path that doesn't
     exist (stale);
  4. an entry uses a word outside the catalog's own vocabulary.

When it fails on a new object or field, classify it: `--unlisted` prints a
starting entry for each, typed from the schema alone. Read the property's
description before trusting it.
"""
import argparse
import gzip
import json
import os
import re
import sys
import tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCHEMA = 'resources/schema/schema.json.gz'
CATALOG = 'resources/privacy/catalog.toml'
OBJECTS_DIR = 'crates/jmap-proto/src/object'
METHODS = 'crates/jmap-proto/src/request/method.rs'

SENSITIVE_FORMATS = {
    'emailAddress': 'identifier',
    'ipAddress': 'network',
    'ipNetwork': 'network',
    'secret': 'credential',
    'secretText': 'credential',
}
INBUXA_OBJECT = re.compile(r'"(inbuxa:[A-Z][A-Za-z]*)"')
PROPERTY_NAME = re.compile(r'=> "([a-z][A-Za-z0-9]*)"')


def sensitive(type_):
    """The category a property's schema type alone implies, or None."""
    fmt = type_.get('format') or (type_.get('class') or {}).get('format')
    if fmt in SENSITIVE_FORMATS:
        return SENSITIVE_FORMATS[fmt]
    name = type_.get('objectName') or (type_.get('class') or {}).get('objectName') or ''
    if name.startswith(('x:SecretKey', 'x:SecretText')) or name == 'x:HttpAuth':
        return 'credential'
    return None


def load_schema(root):
    with gzip.open(os.path.join(root, SCHEMA)) as f:
        return json.load(f)['fields']


def load_inbuxa_objects(root):
    """inbuxa's own objects, from the method names jmap-proto parses."""
    with open(os.path.join(root, METHODS), encoding='utf-8') as f:
        return set(INBUXA_OBJECT.findall(f.read()))


def inbuxa_properties(root, file_name):
    """The property names a jmap-proto object file maps, or None if it's gone."""
    path = os.path.join(root, OBJECTS_DIR, file_name)
    if not os.path.isfile(path):
        return None
    with open(path, encoding='utf-8') as f:
        return set(PROPERTY_NAME.findall(f.read()))


def findings(root, catalog):
    """Everything wrong with `catalog` against the tree at `root`."""
    fields = load_schema(root)
    inbuxa = load_inbuxa_objects(root)
    vocab = catalog.get('vocabulary', {})
    objects = catalog.get('object', {})
    sources = catalog.get('source', {})
    out = []
    inbuxa_props = {}

    def vocabulary(where, key, values):
        allowed = set(vocab.get(key, []))
        for value in values if isinstance(values, list) else [values]:
            if value not in allowed:
                out.append(f'{where}: "{value}" is not in vocabulary.{key}')

    def setting_exists(where, setting):
        obj, _, prop = setting.partition('.')
        if obj in fields:
            if prop not in fields[obj].get('properties', {}):
                out.append(f'{where}: setting {setting} names no property of {obj}')
        elif obj in inbuxa:
            props = inbuxa_props.get(obj)
            if props is not None and prop not in props:
                out.append(f'{where}: setting {setting} names no property of {obj}')
        else:
            out.append(f'{where}: setting {setting} names no object')

    def common(where, entry):
        for key in ('whose', 'where', 'scope'):
            if key in entry:
                vocabulary(where, key, entry[key])
        retention = entry.get('retention')
        if isinstance(retention, dict):
            setting_exists(where, retention.get('setting', ''))
        elif retention is not None:
            vocabulary(where, 'retention', retention)
        for key in ('enabled_by', 'captures'):
            for setting in entry.get(key, []):
                setting_exists(where, setting)

    # inbuxa objects' properties first, so settings can name them
    for name, entry in objects.items():
        if name.startswith('inbuxa:'):
            inbuxa_props[name] = inbuxa_properties(root, entry.get('file', ''))

    # 1: nothing unlisted
    for name in sorted(fields):
        if name not in objects:
            out.append(f'{name}: schema object has no catalog entry')
    for name in sorted(inbuxa):
        if name not in objects:
            out.append(f'{name}: inbuxa object has no catalog entry')

    for name, entry in sorted(objects.items()):
        props = entry.get('properties', {})
        if name.startswith('inbuxa:'):
            known = inbuxa_props.get(name)
            if name not in inbuxa:
                out.append(f'{name}: no such inbuxa object (stale)')
            if known is None:
                out.append(f'{name}: file "{entry.get("file", "")}" not found in {OBJECTS_DIR}')
                known = set()
        elif name in fields:
            known = set(fields[name].get('properties', {}))
        else:
            out.append(f'{name}: no such schema object (stale)')
            continue
        if entry.get('default') != 'none':
            out.append(f'{name}: default must be "none"')
        for prop, categories in props.items():
            if prop not in known:
                out.append(f'{name}.{prop}: no such property (stale)')
            vocabulary(f'{name}.{prop}', 'categories', categories)
        common(name, entry)
        # 2: typed-sensitive properties are listed
        if name in fields:
            for prop, spec in fields[name].get('properties', {}).items():
                if prop not in props and sensitive(spec['type']):
                    out.append(f'{name}.{prop}: typed as {sensitive(spec["type"])} but not listed')

    for name, entry in sorted(sources.items()):
        where = f'source "{name}"'
        vocabulary(where, 'categories', entry.get('categories', []))
        common(where, entry)
        if 'leaves_host' not in entry:
            out.append(f'{where}: leaves_host is missing')
        for path in entry.get('written_by', []):
            if not os.path.exists(os.path.join(root, path)):
                out.append(f'{where}: written_by {path} doesn\'t exist (stale)')
    return out


def unlisted(root, catalog):
    """Starting catalog entries for unlisted objects and properties."""
    fields = load_schema(root)
    objects = catalog.get('object', {})
    lines = []
    for name in sorted(fields):
        entry = objects.get(name)
        listed = (entry or {}).get('properties', {})
        missing = {
            p: sensitive(spec['type'])
            for p, spec in fields[name].get('properties', {}).items()
            if p not in listed and sensitive(spec['type'])
        }
        if entry is None or missing:
            lines.append(f'[object.{json.dumps(name)}]' if entry is None else f'# add to {name}:')
            if entry is None:
                lines.append('default = "none"')
            if missing:
                if entry is None:
                    lines.append(f'[object.{json.dumps(name)}.properties]')
                for prop, category in sorted(missing.items()):
                    lines.append(f'{prop} = ["{category}"]')
            lines.append('')
    return lines


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    parser.add_argument('--unlisted', action='store_true', help='print entries for what is missing')
    parser.add_argument('--root', default=ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    with open(os.path.join(args.root, CATALOG), 'rb') as f:
        catalog = tomllib.load(f)
    if args.unlisted:
        print('\n'.join(unlisted(args.root, catalog)))
        return 0
    found = findings(args.root, catalog)
    if found:
        print(f'privacy check: {len(found)} finding(s) in {CATALOG}:')
        for line in found:
            print(f'  {line}')
        print('Classify new objects and fields (--unlisted helps); remove what no longer exists.')
        return 1
    print(f'privacy check: clean ({len(catalog.get("object", {}))} objects, '
          f'{len(catalog.get("source", {}))} sources).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
