#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tell INBUXA Admin what each expression field accepts.

Every expression field in the registry has a context: the constants it may
evaluate to (DKIM verification: relaxed, strict or disable) and the variables
its conditions may read (sender_domain, local_port...). The server enforces
both, but the schema it serves the admin describes every expression field as
only an `x:Expression` object, so the admin can offer nothing better than a
free-text box.

This reads those contexts from the generated registry code and writes them
into the served schema, on each expression field's type:

    "type": {"type": "object", "objectName": "x:Expression",
             "expression": {"constants": ["relaxed", "strict", "disable"],
                            "variables": ["sender", "sender_domain", ...]}}

The registry code is the source, so re-run this after anything that
regenerates it (an upstream import, a new expression field). `--check` exits 1
when the schema is out of date; CI runs it.
"""

import argparse
import base64
import gzip
import hashlib
import json
import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]
REGISTRY = root / 'crates' / 'registry' / 'src' / 'schema'
SCHEMA = root / 'resources' / 'schema' / 'schema.json.gz'
SCHEMA_HASH = root / 'resources' / 'schema' / 'schema.json.sha256'


def names(enum, text):
    """Variant → wire name, from the `Enum::Variant => "name"` arms."""
    return dict(re.findall(rf'{enum}::(\w+) => "([^"]+)"', text))


def lists(text):
    """Every `pub static NAME: &[ExpressionConstant|Variable] = &[...]`."""
    out = {}
    for name, kind, body in re.findall(
        r'pub static (\w+): &\[(ExpressionConstant|ExpressionVariable)\] = &\[(.*?)\];', text, re.S
    ):
        out[name] = (kind, re.findall(rf'{kind}::(\w+)', body))
    return out


def contexts(text):
    """(struct, Property variant, variables list name, constants list name) per context."""
    out = []
    for block in re.finditer(r'(?m)^impl (\w+) \{(.*?)^\}', text, re.S):
        struct, body = block.group(1), block.group(2)
        for ctx in re.finditer(r'ExpressionContext \{(.*?)\n\s*\}\n', body, re.S):
            fields = ctx.group(1)
            prop = re.search(r'property: Property::(\w+),', fields)
            var = re.search(r'allowed_variables: (&\[\]|\w+),', fields)
            const = re.search(r'allowed_constants: (&\[\]|\w+),', fields)
            if prop and var and const:
                out.append((struct, prop.group(1), var.group(1), const.group(1)))
    return out


def build():
    enums = (REGISTRY / 'enums.rs').read_text(encoding='utf-8')
    enums_impl = (REGISTRY / 'enums_impl.rs').read_text(encoding='utf-8')
    props = names('Property', (REGISTRY / 'properties_impl.rs').read_text(encoding='utf-8'))
    const_names = names('ExpressionConstant', enums_impl)
    var_names = names('ExpressionVariable', enums_impl)
    known = lists(enums)

    def resolve(ref, kind, wire):
        if ref == '&[]':
            return []
        found = known.get(ref)
        if not found or found[0] != kind:
            raise SystemExit(f'expr-schema: no {kind} list named {ref}')
        return [wire[v] for v in found[1]]

    table = {}
    for struct, prop, var, const in contexts((REGISTRY / 'structs_impl.rs').read_text(encoding='utf-8')):
        table[(f'x:{struct}', props[prop])] = {
            'constants': resolve(const, 'ExpressionConstant', const_names),
            'variables': resolve(var, 'ExpressionVariable', var_names),
        }
    return table


def apply(schema, table):
    """Write the table into the schema; returns the (object, field) pairs it couldn't place."""
    missing = []
    for (obj, field), expr in sorted(table.items()):
        target = schema['fields'].get(obj, {}).get('properties', {}).get(field)
        if target is None or target['type'].get('objectName') != 'x:Expression':
            missing.append(f'{obj}.{field}')
            continue
        target['type']['expression'] = expr
    return missing


def encode(schema):
    text = json.dumps(schema, ensure_ascii=False, separators=(',', ':'))
    out = gzip.compress(text.encode('utf-8'), compresslevel=9, mtime=0)
    digest = base64.urlsafe_b64encode(hashlib.sha256(out).digest()).decode().rstrip('=')
    return out, digest


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--check', action='store_true', help='exit 1 if the schema is out of date')
    args = parser.parse_args()

    before = SCHEMA.read_bytes()
    schema = json.loads(gzip.decompress(before))
    table = build()
    missing = apply(schema, table)
    if missing:
        print('expr-schema: expression contexts with no matching schema field:', file=sys.stderr)
        for m in missing:
            print(f'  {m}', file=sys.stderr)
        return 1

    current = json.loads(gzip.decompress(before))
    if current == schema:
        print(f'expr-schema: {len(table)} expression fields, schema up to date')
        return 0
    if args.check:
        print('expr-schema: schema is out of date; run tools/fork/expr-schema.py', file=sys.stderr)
        return 1
    out, digest = encode(schema)
    SCHEMA.write_bytes(out)
    SCHEMA_HASH.write_text(digest, encoding='utf-8')
    print(f'expr-schema: wrote {len(table)} expression fields into {SCHEMA.relative_to(root)}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
