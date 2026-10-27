#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""
Recover per-field special cases from generated reference files.

    python3 tools/extract_tables.py REF_structs_impl.rs [OLD_structs_impl.rs] SCHEMA.json.gz

Prints Python literals for special_cases.py: STRING_VALIDATORS,
VALIDATE_MAX_FIRST, VALIDATE_IF_NOT_EMPTY and EXPRESSION_CONTEXTS. Facts from
the first file win; the optional second file (an older, unstripped snapshot)
fills in fields the first one does not show (Enterprise fields). Only fields
that exist in SCHEMA are kept.
"""
import gzip
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import generate as G  # noqa: E402

BLOCK = re.compile(r"^impl(?:<[^>]*>)? (?:([\w:<>']+) for )?(\w+) \{\n(.*?)^\}\n", re.S | re.M)


def facts(path, s, idents):
    text = Path(path).read_text()
    vals, maxfirst, ifne, ctx, u64 = {}, set(), set(), {}, {}
    for m in BLOCK.finditer(text):
        trait, ty, body = m.group(1) or '', m.group(2), m.group(3)
        sch = 'x:' + ty
        fmap = idents.get(sch)
        if not fmap:
            continue
        if trait == 'RegistryJsonPropertyPatch':
            flat = re.sub(r'\s+', ' ', body)
            for a in re.finditer(r'Some\((?:property @ )?Property::(\w+)\) => (.*?)(?=Some\((?:property @ )?Property::\w+\) =>|_ =>)', flat):
                f = fmap.get(a.group(1))
                if f:
                    vals[(sch, f)] = re.findall(r'StringValidator::(\w+)', a.group(2))
        if trait in ('ObjectImpl', '') and 'fn validate' in body:
            v = body.split('fn validate', 1)[1].split('\n    }\n', 1)[0]
            for mm in re.finditer(r'max_value\(\s*Property::(\w+)[^;]*;\s*\}\s*if \*value < ', v):
                f = fmap.get(mm.group(1))
                if f:
                    maxfirst.add((sch, f))
            for mm in re.finditer(r'let value = &self\.(\w+);\s*if !value\.match_\.is_empty\(\)', v):
                f = next((n for p, n in fmap.items() if G.snake(n) == mm.group(1)), None)
                if f:
                    ifne.add((sch, f))
        if trait == 'Default':
            for mm in re.finditer(r'^\s+(\w+): (?:Some\()?(\d+)(u64)?\b', body, re.M):
                f = next((n for p, n in fmap.items() if G.snake(n) == mm.group(1)), None)
                if f:
                    u64[(sch, f)] = bool(mm.group(3))
        if trait == '':
            for mm in re.finditer(r'expr: &self\.(\w+),.*?property: Property::(\w+),\s*'
                                  r'allowed_variables: ([\w&\[\]]+),\s*allowed_constants: ([\w&\[\]]+),', body, re.S):
                f = fmap.get(mm.group(2))
                if f:
                    v, c = mm.group(3), mm.group(4)
                    ctx[(sch, f)] = (None if v == '&[]' else v, None if c == '&[]' else c)
    return vals, maxfirst, ifne, ctx, u64


def main():
    args = sys.argv[1:]
    schema_path = args.pop()
    d = json.loads(gzip.decompress(Path(schema_path).read_bytes()))
    idents = {sch: {G.pascal(n): n for n in f['properties']} for sch, f in d['fields'].items()}
    results = [facts(p, None, idents) for p in args]
    vals, maxfirst, ifne, ctx, u64 = {}, set(), set(), {}, {}
    for i, (v, mf, ne, c, u) in enumerate(results):
        for k, x in u.items():
            u64.setdefault(k, x)
        for k, x in v.items():
            if k not in vals:
                vals[k] = x
        # Validation facts of later files only for fields the first file lacks.
        first_fields = set(results[0][0]) if i else set()
        maxfirst |= {k for k in mf if k not in first_fields}
        ifne |= {k for k in ne if k not in first_fields}
        for k, x in c.items():
            ctx.setdefault(k, x)
    # Validators: keep only those the derived rule does not already give.
    print('STRING_VALIDATORS = {')
    for (sch, f), v in sorted(vals.items()):
        t = d['fields'][sch]['properties'][f]
        ty = t['type']
        while ty['type'] == 'set':
            ty = ty['class']
        derived = ['Email'] if (ty['type'] == 'string' and ty.get('format') == 'emailAddress'
                                and t['update'] != 'serverSet') else []
        if v != derived:
            print(f'    ({sch!r}, {f!r}): {v!r},')
    print('}')
    sized = sorted(k for k, x in u64.items()
                   if x and d['fields'][k[0]]['properties'][k[1]]['type'].get('format') == 'size')
    print('SIZE_DEFAULT_SUFFIX =', sized)
    print('VALIDATE_MAX_FIRST =', sorted(maxfirst))
    print('VALIDATE_IF_NOT_EMPTY =', sorted(ifne))
    print('EXPRESSION_CONTEXTS = {')
    for k, v in sorted(ctx.items()):
        print(f'    {k!r}: {v!r},')
    print('}')


if __name__ == '__main__':
    main()
