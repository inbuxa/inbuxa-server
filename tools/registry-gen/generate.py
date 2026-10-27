#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""
Generate INBUXA's registry code from the public schema file.

    python3 generate.py --edition agpl --out out/
    python3 generate.py --edition full --out out/

Reads resources/schema/schema.json.gz (and, for the agpl edition,
resources/schema/schema_oss.json.gz, which is what tells open enum variants
from Enterprise ones) and writes:

    crates/registry/src/schema/{enums,enums_impl,properties,properties_impl,
                                structs,structs_impl}.rs

Everything the schema does not carry (field declaration order, index
definitions, expression contexts, and so on) lives in special_cases.py.

The output is formatted with `rustfmt --edition 2024` (rustfmt 1.x), which
must be on PATH. In the agpl edition, Enterprise content is first emitted
between marker comments, formatted together with the open code, and then
removed line by line; this is the same process that produced the reference
files, so the layout artifacts it leaves behind come out identical.
"""

import argparse
import gzip
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import special_cases as SC  # noqa: E402

HEADER = """/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

// This file is auto-generated. Do not edit directly.

"""

# The full edition is ours: it carries the fork's notice line as well.
MODIFIED = """ *
 * Modified by Coffey Labs in 2026 for INBUXA.
"""

# Marker comments around Enterprise-only lines (agpl edition only).
MARK_BEGIN = '// @@ENTERPRISE-BEGIN'
MARK_END = '// @@ENTERPRISE-END'

CFG_ENT = '#[cfg(feature = "enterprise")]'
CFG_NOT_ENT = '#[cfg(not(feature = "enterprise"))]'


# ---------------------------------------------------------------------------
# Naming
# ---------------------------------------------------------------------------

def variant_ident(name):
    """Schema enum value / variant name -> Rust identifier."""
    name = SC.IDENT_SOURCE_NAMES.get(name, name)
    name = name.replace('+', 'Plus')
    name = re.sub(r'(?<=GMT)-(?=\d)', 'Minus', name)
    parts = [p for p in re.split(r'[^A-Za-z0-9]+', name) if p]
    ident = ''.join(p[0].upper() + p[1:] for p in parts)
    if ident[:1].isdigit():
        ident = 'V' + ident
    return ident


RUST_KEYWORDS = set('''as async await break const continue crate dyn else enum extern false fn
for if impl in let loop match mod move mut pub ref return self static struct super trait true
type unsafe use where while abstract become box do final macro override priv typeof unsized
virtual yield try gen'''.split())


def snake(name):
    """camelCase property name -> snake_case Rust field name."""
    s = re.sub(r'([A-Z])', r'_\1', name).lower()
    return s + '_' if s in RUST_KEYWORDS else s


def pascal(name):
    """camelCase property name -> PascalCase `Property` variant."""
    name = name.lstrip('@')
    return SC.PROPERTY_IDENTS.get(name, name[:1].upper() + name[1:])


def strip_x(name):
    return name[2:] if name.startswith('x:') else name


# ---------------------------------------------------------------------------
# Schema model
# ---------------------------------------------------------------------------

def load_gz_json(path):
    return json.loads(gzip.decompress(Path(path).read_bytes()))


class Schema:
    def __init__(self, full, oss, edition):
        self.d = full
        self.oss = oss
        self.edition = edition
        self.agpl = edition == 'agpl'

    # ---- Enterprise classification (agpl only) ----
    def ent_enum(self, name):
        return self.oss is not None and name not in self.oss['enums']

    def oss_variant_names(self, enum):
        names = [v['name'] for v in self.oss['enums'][enum]]
        return {SC.OSS_NAME_RENAMES.get(n, n) for n in names}

    def ent_variant(self, enum, name):
        if self.oss is None:
            return False
        if enum not in self.oss['enums']:
            return True
        return name not in self.oss_variant_names(enum)

    def ent_schema(self, name):
        return self.oss is not None and name not in self.oss['schemas']

    def ent_object(self, name):
        return self.oss is not None and name not in self.oss['objects']

    def prepare(self):
        d = self.d
        # x: schemas, alphabetical (schema.json order)
        self.schemas = [k for k in d['schemas'] if k.startswith('x:')]
        self.fields = {}
        for s in self.schemas:
            if s not in d['fields']:
                continue
            props = d['fields'][s]['properties']
            order = SC.FIELD_ORDER.get(s)
            if order is None:
                order = list(props)
                print(f'warning: {s} has no FIELD_ORDER entry; using schema order', file=sys.stderr)
            missing = [p for p in props if p not in order]
            if missing:
                print(f'warning: {s}: {missing} not in FIELD_ORDER; appended', file=sys.stderr)
                order = list(order) + missing
            defaults = d['fields'][s].get('defaults', {})
            virtual = SC.VIRTUAL_FIELDS.get(s, [])
            self.fields[s] = [Field(self, s, n, props[n], defaults, n in virtual)
                              for n in order if n in props]
        # Property ids: first sighting, walking schemas alphabetically.
        self.prop_ids = {'@type': 0, 'id': 1, 'text': 2}
        for s in sorted(self.fields):
            for f in self.fields[s]:
                self.prop_ids.setdefault(f.name, len(self.prop_ids))
        # Properties used only by Enterprise fields.
        used_open = {'@type', 'id', 'text'}
        for s, fs in self.fields.items():
            if self.ent_schema(s):
                continue
            for f in fs:
                if not f.ent:
                    used_open.add(f.name)
        self.ent_props = {n for n in self.prop_ids if n not in used_open}
        # Registry objects: x: objects and singletons, alphabetical.
        self.objects = [k for k, v in d['objects'].items()
                        if k.startswith('x:') and v['type'] in ('object', 'singleton')]

    def schema_fields(self, s, include_ent=None):
        """Fields of a schema for this edition (all fields in full mode)."""
        return self.fields.get(s, [])

    def ent_field(self, schema, field):
        if self.oss is None:
            return False
        if self.d['fields'][schema]['properties'][field].get('enterprise'):
            return True
        of = self.oss['fields'].get(schema)
        return of is None or field not in of['properties']


class Field:
    def __init__(self, schema, sname, name, prop, defaults, virtual):
        self.s = schema
        self.schema = sname
        self.name = name
        self.prop = prop
        self.t = prop['type']
        self.update = prop['update']
        self.virtual = virtual
        self.has_default = name in defaults
        self.default = defaults.get(name)
        self.ent = schema.ent_field(sname, name)
        self.rust = snake(name)
        self.pident = pascal(name)
        self.nullable = bool(self.t.get('nullable'))


# ---------------------------------------------------------------------------
# Line buffer with Enterprise regions
# ---------------------------------------------------------------------------

class Out:
    def __init__(self, schema):
        self.s = schema
        self.lines = []

    def __call__(self, *lines):
        for l in lines:
            self.lines.extend(l.split('\n'))

    def ent(self, lines):
        """Lines that only exist in the Enterprise build."""
        if isinstance(lines, str):
            lines = lines.split('\n')
        if self.s.agpl:
            self.lines.append(MARK_BEGIN)
            self.lines.extend(lines)
            self.lines.append(MARK_END)
        else:
            self.lines.extend(lines)

    def agpl_only(self, lines):
        """Lines that only exist in the open build (cfg(not(enterprise)) remnants)."""
        if isinstance(lines, str):
            lines = lines.split('\n')
        if self.s.agpl:
            self.lines.extend(lines)

    def text(self):
        return '\n'.join(self.lines) + '\n'


def strip_enterprise(text):
    out, depth = [], 0
    for line in text.split('\n'):
        if MARK_BEGIN in line:
            depth += 1
            continue
        if MARK_END in line:
            depth -= 1
            continue
        if not depth:
            out.append(line)
    return '\n'.join(out)


def rustfmt(text):
    r = subprocess.run(['rustfmt', '--edition', '2024', '--emit', 'stdout'],
                       input=text, capture_output=True, text=True, cwd='/')
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
        raise SystemExit('rustfmt failed')
    return r.stdout


def finish(schema, body, fmt=True):
    header = HEADER
    if not schema.agpl:
        header = header.replace(' */\n', MODIFIED + ' */\n', 1)
    text = header + body
    if os.environ.get('REGISTRY_GEN_RAW'):
        Path(os.environ['REGISTRY_GEN_RAW']).write_text(text)
    if fmt:
        text = rustfmt(text)
    if schema.agpl:
        text = strip_enterprise(text).rstrip('\n') + '\n'
    return text


# ---------------------------------------------------------------------------
# enums.rs / enums_impl.rs
# ---------------------------------------------------------------------------

def generated_enums(s):
    for name in s.d['enums']:
        if name in SC.EXTERNAL_ENUMS:
            continue
        yield name
    # Variant enums schema.json lost to a name clash (see VARIANT_ENUM_NAMES).
    yield from SC.VARIANT_ENUM_NAMES.values()


def enum_variants(s, name):
    """[(ident, schema name, id, enterprise)] in schema order; id = list index."""
    for sch, ename in SC.VARIANT_ENUM_NAMES.items():
        if ename == name:
            ent = s.agpl and s.ent_schema(sch)
            return [(variant_ident(v['name']), v['name'], i, ent)
                    for i, v in enumerate(s.d['schemas'][sch]['variants'])]
    return [(variant_ident(v['name']), v['name'], i, s.ent_variant(name, v['name']))
            for i, v in enumerate(s.d['enums'][name])]


def enum_is_ent(s, name):
    for sch, ename in SC.VARIANT_ENUM_NAMES.items():
        if ename == name:
            return s.agpl and s.ent_schema(sch)
    return s.agpl and s.ent_enum(name)


def gen_enums(s):
    o = Out(s)
    first = True
    for name in generated_enums(s):
        vs = enum_variants(s, name)
        item = ['#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]',
                '#[repr(u16)]', f'pub enum {name} {{']
        body = []
        first_open = next((i for i, v in enumerate(vs) if not v[3]), 0) if s.agpl else 0
        for i, (ident, _, vid, ent) in enumerate(vs):
            if s.agpl and ent:
                attr = ['#[cfg_attr(feature = "enterprise", default)]'] if i == 0 else []
                body.append(('ent', attr + [f'{ident} = {vid},']))
            else:
                if i == 0:
                    attr = ['#[default]']
                elif s.agpl and i == first_open:
                    attr = ['#[cfg_attr(not(feature = "enterprise"), default)]']
                else:
                    attr = []
                body.append(('open', attr + [f'{ident} = {vid},']))
        if enum_is_ent(s, name):
            o.ent(item + flatten(body) + ['}', ''])
            continue
        if not first:
            pass
        o(*item)
        emit_body(o, body)
        o('}', '')
        first = False
    for name, ty, values in SC.EXPRESSION_STATICS:
        o(f'pub static {name}: &[{ty}] = &[')
        for v in values:
            o(f'    {ty}::{v},')
        o('];', '')
    return finish(s, o.text().rstrip('\n') + '\n')


def flatten(body):
    out = []
    for _, lines in body:
        out.extend(lines)
    return out


def emit_body(o, body):
    for kind, lines in body:
        if kind == 'ent':
            o.ent(lines)
        else:
            o(*lines)


def gen_enums_impl(s):
    o = Out(s)
    o('use crate::schema::prelude::*;', '')
    for name in generated_enums(s):
        emit_enum_impl(o, s, name, enum_variants(s, name), enum_is_ent(s, name),
                       name in SC.ENUMS_WITH_ALL)
    return finish(s, o.text().rstrip('\n') + '\n')


def emit_enum_impl(o, s, name, vs, whole_ent=False, with_all=False):
    """EnumImpl + serde impls. vs = [(ident, json name, id, enterprise)]."""
    has_ent = s.agpl and any(v[3] for v in vs)
    start = len(o.lines)
    o(f'impl EnumImpl for {name} {{')

    def parse_fn(variants, cfg):
        # rustfmt may leave the macro body alone, so indent it as final.
        lines = ([f'    {cfg}'] if cfg else []) + [
            '    fn parse(value: &str) -> Option<Self> {',
            '        hashify::map! {',
            '            value.as_bytes(),',
            f'            {name},']
        for ident, sname, _, _ in variants:
            lines.append(f'            b"{sname}" => {name}::{ident},')
        lines += ['        }', '        .copied()', '    }']
        return lines

    def arm(text, ent):
        if ent and not whole_ent:
            o.ent([text])
        elif not ent or s.agpl or True:
            o(text)

    if has_ent and not whole_ent:
        o(*parse_fn([v for v in vs if not v[3]], CFG_NOT_ENT))
        o.ent(parse_fn(vs, CFG_ENT))
    else:
        o(*parse_fn(vs, None))
    o('', 'fn as_str(&self) -> &\'static str {', '    match self {')
    for ident, sname, _, ent in vs:
        arm(f'{name}::{ident} => "{sname}",', ent)
    o('    }', '}', '')
    o('fn to_id(&self) -> u16 {', '    *self as u16', '}', '')
    o('fn from_id(id: u16) -> Option<Self> {', '    match id {')
    for ident, sname, vid, ent in vs:
        arm(f'{vid} => Some({name}::{ident}),', ent)
    o('        _ => None,', '    }', '}', '')
    o(f'const COUNT: usize = {max(v[2] for v in vs) + 1};', '}', '')
    if with_all:
        o(f'impl {name} {{', f'    pub const ALL: &[{name}] = &[')
        for ident, sname, vid, ent in vs:
            arm(f'{name}::{ident},', ent)
        o('    ];', '}', '')
    o(f'impl serde::Serialize for {name} {{',
      '    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>',
      '    where',
      '        S: serde::Serializer,',
      '    {',
      '        serializer.serialize_str(self.as_str())',
      '    }',
      '}', '',
      f'impl<\'de> serde::Deserialize<\'de> for {name} {{',
      '    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>',
      '    where',
      '        D: serde::Deserializer<\'de>,',
      '    {',
      '        let s = Cow::<str>::deserialize(deserializer)?;',
      '        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))',
      '    }',
      '}', '')
    if whole_ent:
        block = o.lines[start:]
        del o.lines[start:]
        o.ent(block)


# ---------------------------------------------------------------------------
# properties.rs / properties_impl.rs
# ---------------------------------------------------------------------------

def object_variants(s):
    return [(strip_x(n), strip_x(n), i, s.agpl and s.ent_object(n)) for i, n in enumerate(s.objects)]


def property_variants(s):
    vs = [(pascal(n), n, i, s.agpl and n in s.ent_props) for n, i in s.prop_ids.items()]
    return sorted(vs, key=lambda v: (v[1] != '@type', v[0]))


def gen_properties(s):
    o = Out(s)
    o('use crate::schema::prelude::*;')
    o('#[derive(Debug, Clone, Serialize, PartialEq, Eq)]', '#[serde(untagged)]',
      'pub enum ObjectInner {')
    for ident, _, _, ent in object_variants(s):
        line = f'{ident}(Box<{ident}>),'
        o.ent([line]) if ent else o(line)
    o('}', '')
    o('#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]', '#[repr(u16)]', 'pub enum ObjectType {')
    for ident, _, i, ent in object_variants(s):
        line = f'{ident} = {i},'
        o.ent([line]) if ent else o(line)
    o('}', '')
    o('#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]', '#[repr(u16)]', 'pub enum Property {')
    for ident, _, i, ent in property_variants(s):
        line = f'{ident} = {i},'
        o.ent([line]) if ent else o(line)
    o('}')
    return finish(s, o.text())


# ---------------------------------------------------------------------------
# Rust types
# ---------------------------------------------------------------------------

STRING_FORMAT_TYPES = {
    'ipAddress': 'IpAddr',
    'ipNetwork': 'IpAddrOrMask',
    'socketAddress': 'SocketAddr',
}
NUMBER_FORMAT_TYPES = {
    'duration': 'Duration',
    'unsignedInteger': 'u64',
    'size': 'u64',
    'integer': 'i64',
    'float': 'Float',
}


def enum_type(name):
    return SC.EXTERNAL_ENUMS.get(name) or name


def base_type(t):
    """Rust type of a schema type, ignoring nullability."""
    k = t['type']
    if k == 'string':
        return STRING_FORMAT_TYPES.get(t.get('format'), 'String')
    if k == 'number':
        return NUMBER_FORMAT_TYPES[t['format']]
    if k == 'boolean':
        return 'bool'
    if k == 'utcDateTime':
        return 'UTCDateTime'
    if k == 'enum':
        return enum_type(t['enumName'])
    if k == 'object':
        return strip_x(t['objectName'])
    if k == 'objectId':
        return 'Id'
    if k == 'blobId':
        return 'BlobId'
    if k == 'objectList':
        return f"List<{strip_x(t['objectName'])}>"
    if k == 'set':
        return f"Map<{base_type(t['class'])}>"
    if k == 'map':
        return f"VecMap<{base_type(t['keyClass'])}, {base_type(t['valueClass'])}>"
    raise ValueError(t)


def rust_type(f):
    ty = SC.RUST_TYPE_OVERRIDES.get((f.schema, f.name)) or base_type(f.t)
    return f'Option<{ty}>' if f.nullable else ty


def schema_kind(s, name):
    return s.d['schemas'][name]['type']


def variants(s, name):
    """[(ident, json name, payload schema or None, enterprise)]"""
    out = []
    enum = None
    for v in s.d['schemas'][name]['variants']:
        out.append((variant_ident(v['name']), v['name'], v.get('schemaName'),
                    s.agpl and v.get('schemaName') is not None and s.ent_schema(v['schemaName'])))
    return out


def variant_enum(name):
    """Name of the enum listing a multi-variant schema's variants."""
    return SC.VARIANT_ENUM_NAMES.get(name, strip_x(name) + 'Type')


def edition_schemas(s):
    """x: schemas to generate, alphabetical, with their Enterprise flag."""
    return [(n, s.agpl and s.ent_schema(n)) for n in s.schemas]


# ---------------------------------------------------------------------------
# structs.rs
# ---------------------------------------------------------------------------

def gen_structs(s):
    o = Out(s)
    o('use crate::schema::prelude::*;')
    for name, ent in edition_schemas(s):
        lines = ['#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]']
        rn = strip_x(name)
        body = []
        if schema_kind(s, name) == 'multiple':
            lines += ['#[serde(tag = "@type")]', f'pub enum {rn} {{']
            for ident, jname, payload, vent in variants(s, name):
                line = f'{ident}({strip_x(payload)}),' if payload else f'{ident},'
                body.append(('ent' if vent else 'open', [line]))
        else:
            lines += ['#[serde(default)]', f'pub struct {rn} {{']
            for f in s.fields[name]:
                if f.virtual:
                    continue
                fl = []
                if f.rust != f.name:
                    fl.append(f'#[serde(rename = "{f.name}")]')
                fl.append(f'pub {f.rust}: {rust_type(f)},')
                body.append(('ent' if f.ent else 'open', fl))
        if ent:
            o.ent(lines + flatten(body) + ['}', ''])
        else:
            o(*lines)
            emit_body(o, body)
            o('}', '')
    return finish(s, o.text().rstrip('\n') + '\n')


# ---------------------------------------------------------------------------
# Field helpers shared by structs_impl.rs and properties_impl.rs
# ---------------------------------------------------------------------------

def kind_of(t):
    k = t['type']
    if k == 'string':
        return {'ipAddress': 'ip', 'ipNetwork': 'ipmask', 'socketAddress': 'socket'}.get(
            t.get('format'), 'string')
    if k == 'number':
        return {'duration': 'duration', 'unsignedInteger': 'u64', 'size': 'u64',
                'integer': 'i64', 'float': 'float'}[t['format']]
    return {'boolean': 'bool', 'utcDateTime': 'datetime', 'enum': 'enum', 'object': 'object',
            'objectId': 'id', 'blobId': 'blob', 'objectList': 'list', 'set': 'set',
            'map': 'map'}[k]


def fkind(f):
    ov = SC.RUST_TYPE_OVERRIDES.get((f.schema, f.name))
    if ov == 'Id':
        return 'id'
    return kind_of(f.t)


def is_expr(t):
    return t['type'] == 'object' and t.get('objectName') == 'x:Expression'


def is_secret(f):
    return (f.t.get('format') in ('secret', 'secretText')
            or (f.schema, f.name) in SC.MASKED_FIELDS)


def parse_duration(v):
    """Schema duration default -> milliseconds."""
    if isinstance(v, (int, float)):
        return int(v)
    m = re.fullmatch(r'(\d+)\s*(ms|s|m|h|d|w)?', v.strip())
    if not m:
        raise ValueError(v)
    n = int(m.group(1))
    return n * {'ms': 1, None: 1, 's': 1000, 'm': 60000, 'h': 3600000,
                'd': 86400000, 'w': 604800000}[m.group(2)]


def rust_str(v):
    v = SC.STRING_LITERAL_RENAMES.get(v, v)
    return '"' + v.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n') + '"'


def float_lit(v):
    r = repr(float(v))
    return r


def num_literal(t, v, f=None):
    k = kind_of(t)
    if k == 'duration':
        return f'Duration::from_millis({parse_duration(v)})'
    if k == 'float':
        return f'Float::new({float_lit(v)}f64)'
    if k == 'i64':
        return f'{int(v)}i64'
    if k == 'u64':
        if t.get('format') == 'size' and (f is None or
                                          (f.schema, f.name) not in SC.SIZE_DEFAULT_SUFFIX):
            return f'{int(v)}'
        return f'{int(v)}u64'
    raise ValueError(t)


def schema_struct_fields(s, name):
    """Stored (non-virtual) fields of a single schema, in declaration order."""
    return [f for f in s.fields[name] if not f.virtual]


def default_expr(s, f, t=None, value=None):
    """Rust expression for a field's default (None -> Default::default())."""
    t = t or f.t
    if value is None:
        if not f.has_default:
            return None
        value = f.default
    k = kind_of(t)
    nullable = t.get('nullable')
    inner = value_literal(s, t, value, f)
    if inner is None:
        return None
    return f'Some({inner})' if nullable else inner


def value_literal(s, t, v, f=None):
    k = kind_of(t)
    if k == 'string':
        if v is None:
            return None
        return f'{rust_str(v)}.to_string()'
    if k in ('ip', 'ipmask', 'socket'):
        return f'{base_type(t)}::from_str({rust_str(v)}).unwrap()'
    if k in ('u64', 'i64', 'float', 'duration'):
        return num_literal(t, v, f)
    if k == 'bool':
        return 'true' if v else 'false'
    if k == 'enum':
        return f"{enum_type(t['enumName'])}::{variant_ident(v)}"
    if k == 'set':
        keys = set_default_order(f, v)
        if t['class']['type'] == 'enum' and t['class']['enumName'] in s.d['enums']:
            order = [e['name'] for e in s.d['enums'][t['class']['enumName']]]
            keys = sorted(keys, key=lambda x: order.index(x) if x in order else len(order))
        items = [value_literal(s, t['class'], x) for x in keys]
        return f"Map::new(vec![{', '.join(items)}])"
    if k == 'object':
        return object_literal(s, t['objectName'], v)
    if k == 'list':
        # objectList defaults are JSON objects keyed by position ("0", "1", ...).
        vals = [v[k] for k in sorted(v, key=int)] if isinstance(v, dict) else v
        items = [object_literal(s, t['objectName'], x) for x in vals]
        return f"List::from_iter([{', '.join(items)}])"
    if k == 'map':
        items = [f"({value_literal(s, t['keyClass'], key)}, {value_literal(s, t['valueClass'], val)})"
                 for key, val in v.items()]
        return f"VecMap::from_iter([{', '.join(items)}])"
    raise ValueError((t, v))


def set_default_order(f, v):
    keys = list(v) if isinstance(v, dict) else list(v)
    if f is not None:
        order = SC.SET_DEFAULT_ORDER.get((f.schema, f.name))
        if order:
            return order
    return keys


def object_literal(s, oname, v):
    name = strip_x(oname)
    if oname == 'x:Expression':
        return expression_literal(v)
    sch = s.d['schemas'][oname]
    if sch['type'] == 'multiple':
        vname = v['@type']
        var = next(x for x in sch['variants'] if x['name'] == vname)
        ident = variant_ident(vname)
        if not var.get('schemaName'):
            return f'{name}::{ident}'
        rest = {k: x for k, x in v.items() if k != '@type'}
        if not rest:
            return f'{name}::{ident}(Default::default())'
        return f"{name}::{ident}({struct_literal(s, var['schemaName'], rest)})"
    return struct_literal(s, oname, v)


def struct_literal(s, sname, v):
    fields = schema_struct_fields(s, sname)
    parts = []
    for f in fields:
        if f.name in v:
            parts.append(f'{f.rust}: {default_expr(s, f, value=v[f.name])}')
    if len(parts) < len(fields):
        parts.append('..Default::default()')
    return f"{strip_x(sname)} {{ {', '.join(parts)} }}"


def expression_literal(v):
    """Expression default: else_ first, then match_ when the key is present."""
    if isinstance(v, str):
        v = {'default': v}
    parts = []
    e = v.get('else', v.get('default'))
    if e is not None:
        parts.append(f'else_: {rust_str(e)}.to_string()')
    if 'match' in v:
        ms = ', '.join(f"ExpressionMatch {{ if_: {rust_str(m['if'])}.to_string(), "
                       f"then: {rust_str(m['then'])}.to_string() }}" for m in v['match'])
        parts.append(f'match_: List::from_iter([{ms}])')
    else:
        parts.append('..Default::default()')
    return f"Expression {{ {', '.join(parts)} }}"


# ---------------------------------------------------------------------------
# Derived model shared by structs_impl.rs and properties_impl.rs
# ---------------------------------------------------------------------------

def type_children(t):
    """Schema names referenced by a field type (objects, lists, sets, maps)."""
    k = t['type']
    if k in ('object', 'objectList'):
        return [t['objectName']]
    out = []
    for c in ('class', 'keyClass', 'valueClass'):
        if c in t:
            out += type_children(t[c])
    return out


class Model:
    """Facts computed over the full schema (Enterprise included)."""

    def __init__(self, s):
        self.s = s
        d = s.d
        self.object_set = set(s.objects)
        self.perms = {v['name'] for v in d['enums']['Permission']}
        # Types reachable from stored objects get a Pickle impl.
        self.pickled = set()
        stack = [o for o in s.objects if o not in SC.NOT_STORED_OBJECTS]
        while stack:
            n = stack.pop()
            if n in self.pickled or n not in d['schemas']:
                continue
            self.pickled.add(n)
            stack.extend(self.children(n))
        # Types with an index function (fixed point).
        self.indexable = set()
        changed = True
        while changed:
            changed = False
            for n in s.schemas:
                if n not in self.indexable and self._indexable(n):
                    self.indexable.add(n)
                    changed = True
        # Types with expression contexts (fixed point over multi variants).
        self.has_ctx = {n for n in s.schemas if schema_kind(s, n) == 'single'
                        and any(self.ctx_of(f) for f in schema_struct_fields(s, n))}
        changed = True
        while changed:
            changed = False
            for n in s.schemas:
                if n in self.has_ctx or schema_kind(s, n) != 'multiple':
                    continue
                if any(v[2] in self.has_ctx for v in variants(s, n) if v[2]):
                    self.has_ctx.add(n)
                    changed = True

    def children(self, n):
        sch = self.s.d['schemas'][n]
        if sch['type'] == 'multiple':
            return [v['schemaName'] for v in sch['variants'] if v.get('schemaName')]
        out = []
        for f in schema_struct_fields(self.s, n):
            out += type_children(f.t)
        return out

    def _indexable(self, n):
        s = self.s
        # Only stored types are indexed (an object's own index fn always exists).
        if n not in self.pickled:
            return False
        if schema_kind(s, n) == 'multiple':
            if n in SC.TYPE_INDEXED_OBJECTS:
                return True
            return any(v[2] in self.indexable for v in variants(s, n) if v[2])
        for f in schema_struct_fields(s, n):
            if index_ops(f) or fk_target(f) or self.nested_index(f):
                return True
        return False

    def nested_index(self, f):
        k = kind_of(f.t)
        if k in ('object', 'list'):
            return f.t['objectName'] in self.indexable
        if k == 'map':
            vc = f.t['valueClass']
            return vc['type'] == 'object' and vc['objectName'] in self.indexable
        return False

    def ctx_of(self, f):
        if not is_expr(f.t):
            return None
        return SC.EXPRESSION_CONTEXTS.get((f.schema, f.name))

    def object_flags(self, n):
        s = self.s
        obj = s.d['objects'][n]
        flags = []
        singleton = obj['type'] == 'singleton'
        if singleton:
            flags.append('OBJ_SINGLETON')
        var_fields = self.variant_field_names(n)
        if var_fields and all('accountId' in fs for fs in var_fields):
            flags.append('OBJ_FILTER_ACCOUNT')
        if any('memberTenantId' in fs for fs in var_fields):
            flags.append('OBJ_FILTER_TENANT')
        if n in SC.SEQ_ID_OBJECTS:
            flags.append('OBJ_SEQ_ID')
        if n in SC.NOT_STORED_OBJECTS:
            flags.append('OBJ_NOT_STORED')
        prefix = obj['permissionPrefix']
        ops = ['Get', 'Update'] if singleton else ['Get', 'Create', 'Update', 'Destroy', 'Query']
        for op in ['Get', 'Create', 'Update', 'Destroy', 'Query']:
            if op in ops and prefix + op not in self.perms:
                flags.append('OBJ_NO_' + op.upper())
        return ' | '.join(flags) or '0'

    def variant_field_names(self, n):
        s = self.s
        if schema_kind(s, n) == 'multiple':
            return [{f.name for f in s.fields.get(v[2], [])} if v[2] else set()
                    for v in variants(s, n)]
        return [{f.name for f in s.fields.get(n, [])}]


def index_ops(f):
    return SC.INDEX_OPS.get(f.schema, {}).get(f.name, [])


def fk_target(f):
    """(ObjectType ident, view filter or None) for objectId fields."""
    t = f.t
    while t['type'] == 'set':
        t = t['class']
    if t['type'] != 'objectId':
        return None
    obj = strip_x(t['objectName'])
    if '/' in obj:
        base, view = obj.split('/', 1)
        return base, f'Some({base}Type::{variant_ident(view)}.to_id())'
    return obj, 'None'


def is_set(f):
    return f.t['type'] == 'set'


# ---------------------------------------------------------------------------
# structs_impl.rs
# ---------------------------------------------------------------------------

def P(f):
    return f'Property::{f.pident}'


def scalar_checks(f, t, prop):
    """Validation lines for one value (`value: &T`)."""
    k = kind_of(t)
    ov = SC.RUST_TYPE_OVERRIDES.get((f.schema, f.name))
    if ov == 'Id':
        k = 'id'
    elif ov and ov.startswith('Map<u64'):
        return []
    lines = []
    if k == 'string':
        lines += ['if value.is_empty() {', f'    errors.push(ValidationError::required({prop}));', '}']
        if 'maxLength' in t:
            n = t['maxLength']
            lines += [f'if value.len() > {n} {{',
                      f'    errors.push(ValidationError::max_length({prop}, {n}));', '}']
    elif k == 'blob':
        lines += ['if value.is_empty() {', f'    errors.push(ValidationError::required({prop}));', '}']
    elif k == 'id' and ov != 'Id':
        lines += ['if !value.is_valid() {', f'    errors.push(ValidationError::required({prop}));', '}']
    elif k in ('datetime', 'ip', 'ipmask', 'socket', 'id'):
        lines += ['if !value.is_valid() {', f'    errors.push(ValidationError::invalid({prop}, value));', '}']
    elif k in ('u64', 'i64', 'float', 'duration'):
        if k == 'duration' and ('min' in t or 'max' in t):
            lines += ['if !value.is_valid() {', f'    errors.push(ValidationError::invalid({prop}, value));', '}']
        bounds = [('min', '<', 'min_value'), ('max', '>', 'max_value')]
        if (f.schema, f.name) in SC.VALIDATE_MAX_FIRST:
            bounds.reverse()
        for key, op, fn in bounds:
            if key in t:
                lit, push = bound_literals(t, t[key])
                lines += [f'if *value {op} {lit} {{',
                          f'    errors.push(ValidationError::{fn}({prop}, {push}));', '}']
    elif k == 'object':
        if (f.schema, f.name) in SC.VALIDATE_IF_NOT_EMPTY:
            lines += ['if !value.match_.is_empty() || !value.else_.is_empty() {',
                      '    value.validate(errors);', '}']
        else:
            lines += ['value.validate(errors);']
    return lines


def bound_literals(t, v):
    k = kind_of(t)
    if k == 'duration':
        ms = parse_duration(v)
        return f'Duration::from_millis({ms})', f'{ms}'
    if k == 'float':
        return f'Float::new({float_lit(v)})', f'{int(v)}' if float(v).is_integer() else f'{v}'
    if k == 'i64':
        return f'({int(v)})', f'{int(v)}'
    return f'{int(v)}', f'{int(v)}'


def validate_lines(f):
    t = f.t
    k = kind_of(t)
    prop = P(f)
    if k == 'set':
        inner = scalar_checks(f, t['class'], prop)
        lines = (['for value in value.iter() {'] + indent(inner) + ['}']) if inner else []
        if 'minItems' in t:
            n = t['minItems']
            lines += [f'if value.len() < {n} {{', f'    errors.push(ValidationError::min_items({prop}, {n}));', '}']
    elif k in ('list', 'map'):
        inner_t = ({'type': 'object', 'objectName': t['objectName']} if k == 'list'
                   else t['valueClass'])
        inner = scalar_checks(f, inner_t, prop)
        lines = (['for value in value.values() {'] + indent(inner) + ['}']) if inner else []
        if 'minItems' in t:
            n = t['minItems']
            lines += [f'if value.len() < {n} {{', f'    errors.push(ValidationError::min_items({prop}, {n}));', '}']
    else:
        lines = scalar_checks(f, t, prop)
    if not lines:
        return []
    if f.nullable:
        return [f'if let Some(value) = &self.{f.rust} {{'] + indent(lines) + ['}']
    return [f'let value = &self.{f.rust};'] + lines


def indent(lines, n=1):
    return [('    ' * n + l) if l else l for l in lines]


def index_lines(m, f):
    out = []
    fk = fk_target(f)
    if fk:
        obj, view = fk
        if is_set(f):
            out += [f'for id in self.{f.rust}.iter() {{',
                    f'    i.foreign_key(ObjectType::{obj}, Some(*id), {view});', '}']
        elif f.nullable:
            out += [f'i.foreign_key(ObjectType::{obj}, self.{f.rust}, {view});']
        else:
            out += [f'i.foreign_key(ObjectType::{obj}, self.{f.rust}.into(), {view});']
    for op in index_ops(f):
        kind = op[0]
        if kind == 'composite':
            _, cprop, how, other = op
            arg = (f'IndexValue::U32(self.{other}.document_id())' if how == 'docid'
                   else f'&self.{other}')
            out += [f'i.unique_global_composite(Property::{cprop}, &self.{f.rust}, {arg});']
            continue
        call = f'i.{kind}(Property::{op[1]}, '
        if is_set(f):
            out += [f'for value in self.{f.rust}.iter() {{', f'    {call}value);', '}']
        elif f.nullable:
            out += [f'if let Some(value) = &self.{f.rust} {{', f'    {call}value);', '}']
        else:
            out += [f'{call}&self.{f.rust});']
    if m.nested_index(f):
        k = kind_of(f.t)
        if k == 'object':
            if f.nullable:
                out += [f'if let Some(value) = &self.{f.rust} {{', '    value.index(i);', '}']
            else:
                out += [f'self.{f.rust}.index(i);']
        else:
            out += [f'for item in self.{f.rust}.values() {{', '    item.index(i);', '}']
    return out


def emit_fields(o, s, fields, fn):
    """Emit fn(f) lines for each field, Enterprise fields wrapped."""
    any_open = False
    for f in fields:
        lines = fn(f)
        if not lines:
            continue
        if f.ent:
            o.ent(lines)
        else:
            any_open = True
            o(*lines)
    return any_open


def has_lines(fields, fn, ent=None):
    return any(fn(f) for f in fields if ent is None or f.ent == ent)


def emit_validate_fn(o, s, fields):
    if not any(validate_lines(f) for f in fields):
        o('fn validate(&self, _: &mut Vec<ValidationError>) -> bool {', '    true', '}')
        return
    o('fn validate(&self, errors: &mut Vec<ValidationError>) -> bool {', '    let neb = errors.len();')
    emit_fields(o, s, fields, validate_lines)
    o('    errors.len() == neb', '}')


def emit_index_fn(o, m, s, fields, pub=False):
    fn = lambda f: index_lines(m, f)
    open_ = has_lines(fields, fn, False)
    ent = has_lines(fields, fn, True)
    if not open_ and not ent:
        o("fn index<'x>(&'x self, _: &mut IndexBuilder<'x>) {}")
        return
    if not open_ and s.agpl:
        o('#[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]')
    o("fn index<'x>(&'x self, i: &mut IndexBuilder<'x>) {")
    emit_fields(o, s, fields, fn)
    o('}')


def emit_trailing_ent(o, s, name):
    if name in SC.TRAILING_ENTERPRISE_ITEM and s.agpl:
        o('')
        o.ent([])


def emit_single(o, m, s, name):
    rn = strip_x(name)
    fields = schema_struct_fields(s, name)
    allf = s.fields[name]
    is_obj = name in m.object_set
    # 1. ObjectImpl / inherent validate (+ index)
    if is_obj:
        o(f'impl ObjectImpl for {rn} {{',
          f'    const FLAGS: u64 = {m.object_flags(name)};',
          '    const VERSION: u8 = 0;',
          f'    const OBJECT: ObjectType = ObjectType::{rn};', '')
        emit_validate_fn(o, s, fields)
        o('')
        emit_index_fn(o, m, s, fields)
    else:
        o(f'impl {rn} {{')
        emit_validate_fn(o, s, fields)
        if name in m.indexable:
            o('')
            emit_index_fn(o, m, s, fields)
    emit_trailing_ent(o, s, name)
    o('}', '')
    # 2. Expression contexts
    ctxf = [f for f in fields if m.ctx_of(f)]
    if ctxf:
        o(f'impl {rn} {{')
        for f in ctxf:
            vars_, consts = m.ctx_of(f)
            d = default_expr(s, f)
            lines = [f'pub fn ctx_{f.rust}(&self) -> ExpressionContext<\'_> {{',
                     '    ExpressionContext {',
                     f'        expr: &self.{f.rust},',
                     f'        default: {"Some(" + d + ")" if d else "None"},',
                     f'        property: {P(f)},',
                     f'        allowed_variables: {vars_ or "&[]"},',
                     f'        allowed_constants: {consts or "&[]"},',
                     '    }', '}', '']
            o.ent(lines) if f.ent else o(*lines)
        calls = []
        o('pub fn expression_ctxs(&self) -> Vec<ExpressionContext<\'_>> {')
        if any(f.ent for f in ctxf) and s.agpl:
            # vec![] with Enterprise entries (formatted vertically).
            o('    vec![')
            for f in ctxf:
                line = f'        self.ctx_{f.rust}(),'
                o.ent([line]) if f.ent else o(line)
            o('    ]')
        else:
            o('    vec![' + ', '.join(f'self.ctx_{f.rust}()' for f in ctxf) + ']')
        o('}', '}', '')
    # 3. Pickle
    if name in m.pickled:
        emit_pickle_single(o, m, s, name, fields, is_obj)
    # 4. Default
    o(f'impl Default for {rn} {{', '    fn default() -> Self {', '        Self {')
    for f in fields:
        d = (SC.DEFAULT_OVERRIDES.get((f.schema, f.name), {}).get('default')
             or default_expr(s, f)
             or ('false' if fkind(f) == 'bool' and not f.nullable else 'Default::default()'))
        # Indented as final: rustfmt leaves a struct literal alone when one
        # of its lines (a long string default) cannot be made to fit.
        line = f'            {f.rust}: {d},'
        o.ent([line]) if f.ent else o(line)
    o('        }', '    }', '}', '')
    # 5. IntoValue
    o(f'impl IntoValue for {rn} {{',
      "    fn into_value(self) -> JmapValue<'static> {",
      '        self.into_value_with(ValueOptions::default())', '    }', '',
      "    fn into_value_with(self, opts: ValueOptions) -> JmapValue<'static> {",
      f'        let mut map = jmap_tools::Map::with_capacity({len(fields) + 2});')
    for f in fields:
        val = f'self.{f.rust}.into_value_with(opts)'
        if is_secret(f):
            val = (f'if opts.include_secrets {{ {val} }} else '
                   '{ JmapValue::Str(MASKED_PASSWORD.into()) }')
        line = f'map.insert_unchecked({P(f)}, {val});'
        if is_secret(f) and f.nullable:
            line = f'if self.{f.rust}.is_some() {{ {line} }}'
        o.ent([line]) if f.ent else o(line)
    o('        JmapValue::Object(map)', '    }', '}', '')
    # 6. Patch
    o(f'impl RegistryJsonPropertyPatch for {rn} {{',
      "    fn patch_property<'x>(&mut self, mut pointer: JsonPointerPatch<'_>, value: JmapValue<'x>) -> PatchResult<'x> {",
      '        match pointer.next_property() {')
    for f in allf:
        line = patch_arm(f)
        o.ent([line]) if f.ent else o(line)
    o('            Some(Property::Type) => Ok(MaybeUnpatched::Unpatched { property: Property::Type, value }),',
      '            _ => Err(PatchError::new(pointer, "Invalid property")),',
      '        }', '    }', '}', '')


def string_validators(f):
    v = SC.STRING_VALIDATORS.get((f.schema, f.name))
    if v is not None:
        return v
    t = f.t
    while t['type'] == 'set':
        t = t['class']
    if t['type'] == 'string' and t.get('format') == 'emailAddress' and f.update != 'serverSet':
        return ['Email']
    return []


def patch_arm(f):
    arm = f'Some({P(f)})'
    if f.update == 'serverSet':
        return f'{arm} => pointer.assert_server_set(),'
    if f.virtual:
        return f'Some(property @ {P(f)}) => Ok(MaybeUnpatched::Unpatched {{ property, value }}),'
    ptr = 'pointer'
    if f.update == 'immutable':
        ptr += '.assert_read_only()?'
    if f.name == 'accountId':
        ptr += '.assert_can_set_account()?'
    if f.name == 'memberTenantId':
        # inbuxa: MT, only a caller allowed to move objects between tenants
        ptr += '.assert_can_set_tenant()?'
    vs = string_validators(f)
    if vs:
        ptr += '.with_validators(&[' + ', '.join(f'StringValidator::{v}' for v in vs) + '])'
    return f'{arm} => self.{f.rust}.patch({ptr}, value),'


def emit_pickle_single(o, m, s, name, fields, is_obj):
    rn = strip_x(name)
    flagged = [f for f in fields if f.nullable or kind_of(f.t) == 'bool']
    flag_no = {f.name: i for i, f in enumerate(flagged)}
    o(f'impl Pickle for {rn} {{', '    fn pickle(&self, out: &mut Vec<u8>) {')
    if flagged:
        if s.agpl and all(f.ent for f in flagged):
            o('#[cfg_attr(not(feature = "enterprise"), allow(unused_mut))]')
        o('let mut bitmap = 0u64;')
        for f in flagged:
            cond = f'self.{f.rust}' if not f.nullable else f'self.{f.rust}.is_some()'
            lines = [f'if {cond} {{', f'    bitmap |= 1 << {flag_no[f.name]};', '}']
            o.ent(lines) if f.ent else o(*lines)
    o(f'let block = crate::pickle::begin_block(out, {len(fields)}, {len(flagged)}, '
      f'{"bitmap" if flagged else "0"});')
    for f in fields:
        if kind_of(f.t) == 'bool' and not f.nullable:
            continue
        if f.nullable:
            lines = [f'if let Some(value) = &self.{f.rust} {{', '    value.pickle(out);', '}']
        else:
            lines = [f'self.{f.rust}.pickle(out);']
        if f.ent:
            if s.agpl and not f.nullable:
                o.agpl_only([CFG_NOT_ENT, '{',
                             '    let block = crate::pickle::begin_block(out, 0, 0, 0);',
                             '    crate::pickle::end_block(out, block);', '}'])
            o.ent(lines)
        else:
            o(*lines)
    o('crate::pickle::end_block(out, block);', '}', '')
    o("fn unpickle(stream: &mut crate::pickle::PickledStream<'_>) -> Option<Self> {")
    if is_obj:
        o('if stream.version() > Self::VERSION {', '    return None;', '}')
    o('let block = stream.open_block()?;')
    for i, f in enumerate(fields):
        d = (SC.DEFAULT_OVERRIDES.get((f.schema, f.name), {}).get('unpickle')
             or default_expr(s, f) or 'Default::default()')
        ty = rust_type(f)
        if kind_of(f.t) == 'bool' and not f.nullable:
            if not f.has_default:
                d = 'false'
            lines = [f'let field{i}: {ty} = if block.has({i}) {{ block.flag({flag_no[f.name]}) }} else {{ {d} }};']
        elif f.nullable:
            lines = [f'let field{i}: {ty} = if block.has({i}) {{',
                     f'    if block.flag({flag_no[f.name]}) {{ Some(Pickle::unpickle(stream)?) }} else {{ None }}',
                     f'}} else {{ {d} }};']
        else:
            lines = [f'let field{i}: {ty} = if block.has({i}) {{ Pickle::unpickle(stream)? }} else {{ {d} }};']
        if f.ent:
            if s.agpl and not f.nullable and kind_of(f.t) != 'bool':
                o.agpl_only([CFG_NOT_ENT, f'if block.has({i}) {{',
                             '    let block = stream.open_block()?;',
                             '    stream.close_block(block);', '}'])
            o.ent(lines)
        else:
            o(*lines)
    o('stream.close_block(block);', 'Some(Self {')
    for i, f in enumerate(fields):
        line = f'{f.rust}: field{i},'
        o.ent([line]) if f.ent else o(line)
    o('})', '}', '}', '')


def emit_multi(o, m, s, name):
    rn = strip_x(name)
    vs = variants(s, name)
    is_obj = name in m.object_set

    def arms(fn):
        for idx, (ident, jname, payload, vent) in enumerate(vs):
            lines = fn(idx, ident, jname, payload)
            if lines is None:
                continue
            o.ent(lines) if vent else o(*lines)

    # 1. ObjectImpl / validate
    if is_obj:
        o(f'impl ObjectImpl for {rn} {{',
          f'    const FLAGS: u64 = {m.object_flags(name)};',
          '    const VERSION: u8 = 0;',
          f'    const OBJECT: ObjectType = ObjectType::{rn};', '')
    else:
        o(f'impl {rn} {{')
    # a type whose variants carry no payload never reads these parameters
    # (full edition only: no open type is like that)
    unit_only = not any(p for _, _, p, _ in vs)
    errors_arg, opts_arg = ('_errors', '_opts') if unit_only else ('errors', 'opts')
    o(f'fn validate(&self, {errors_arg}: &mut Vec<ValidationError>) -> bool {{', 'match self {')
    arms(lambda i, v, j, p: [f'{rn}::{v}(inner) => inner.validate(errors),'] if p
         else [f'{rn}::{v} => true,'])
    o('}', '}')
    if is_obj or name in m.indexable:
        o('')
        if name in m.indexable:
            typed = name in SC.TYPE_INDEXED_OBJECTS
            o("fn index<'x>(&'x self, i: &mut IndexBuilder<'x>) {", 'match self {')

            def ix(i, v, j, p):
                body = [f'i.typ({i});'] if typed else []
                if p and p in m.indexable:
                    body.append('object.index(i);')
                    return [f'{rn}::{v}(object) => {{'] + body + ['}']
                pat = f'{rn}::{v}(_)' if p else f'{rn}::{v}'
                return [f'{pat} => {{'] + body + ['}']
            arms(ix)
            o('}', '}')
        else:
            o("fn index<'x>(&'x self, _: &mut IndexBuilder<'x>) {}")
    emit_trailing_ent(o, s, name)
    o('}', '')
    # 2. Default
    ident, jname, payload, vent = vs[0]
    o(f'impl Default for {rn} {{', '    fn default() -> Self {',
      f'        {rn}::{ident}(Default::default())' if payload else f'        {rn}::{ident}',
      '    }', '}', '')
    # 3. Pickle
    if name in m.pickled:
        o(f'impl Pickle for {rn} {{', '    fn pickle(&self, out: &mut Vec<u8>) {', 'match self {')
        arms(lambda i, v, j, p: [f'{rn}::{v}(inner) => {{', f'{i}u16.pickle(out);', 'inner.pickle(out);', '}']
             if p else [f'{rn}::{v} => {{', f'{i}u16.pickle(out);', '}'])
        o('}', '}', '')
        o("fn unpickle(stream: &mut crate::pickle::PickledStream<'_>) -> Option<Self> {")
        if is_obj:
            o('if stream.version() > Self::VERSION {', '    return None;', '}')
        o('match u16::unpickle(stream)? {')
        arms(lambda i, v, j, p: [f'{i} => Pickle::unpickle(stream).map({rn}::{v}),'] if p
             else [f'{i} => Some({rn}::{v}),'])
        o('_ => None,', '}', '}', '}', '')
    # 4. IntoValue
    o(f'impl IntoValue for {rn} {{',
      "    fn into_value(self) -> JmapValue<'static> {",
      '        self.into_value_with(ValueOptions::default())', '    }', '',
      f"    fn into_value_with(self, {opts_arg}: ValueOptions) -> JmapValue<'static> {{", 'match self {')
    arms(lambda i, v, j, p: [f'{rn}::{v}(obj) => {{', 'let mut obj = obj.into_value_with(opts);',
                             f'obj.as_object_mut().unwrap().insert_unchecked(Property::Type, JmapValue::Str("{j}".into()));',
                             'obj', '}'] if p else
         [f'{rn}::{v} => {{', 'let mut obj = jmap_tools::Map::new();',
          f'obj.insert_unchecked(Property::Type, JmapValue::Str("{j}".into()));',
          'JmapValue::Object(obj)', '}'])
    o('}', '}', '}', '')
    # 5. Patch
    o(f'impl RegistryJsonPatch for {rn} {{',
      "    fn patch<'x>(&mut self, pointer: JsonPointerPatch<'_>, value: JmapValue<'x>) -> PatchResult<'x> {",
      'if !pointer.has_next() {', 'match object_type(&pointer, &value)? {')
    ve = variant_enum(name)
    arms(lambda i, v, j, p: [f'{ve}::{v} => *self = {rn}::{v}(Default::default()),'] if p
         else [f'{ve}::{v} => *self = {rn}::{v},'])
    o('}', '}', 'match self {')
    arms(lambda i, v, j, p: [f'{rn}::{v}(inner) => inner.patch(pointer, value),'] if p
         else [f'{rn}::{v} => pointer.assert_eof(),'])
    o('}', '}', '}', '')
    # 6. object_type (+ expression contexts)
    o(f'impl {rn} {{', f'pub fn object_type(&self) -> {ve} {{', 'match self {')
    arms(lambda i, v, j, p: [f'{rn}::{v}(_) => {ve}::{v},'] if p
         else [f'{rn}::{v} => {ve}::{v},'])
    o('}', '}')
    if name in m.has_ctx:
        o('', "pub fn expression_ctxs(&self) -> Vec<ExpressionContext<'_>> {", 'match self {')
        arms(lambda i, v, j, p: [f'{rn}::{v}(obj) => obj.expression_ctxs(),']
             if p and p in m.has_ctx else None)
        if any(not (v[2] and v[2] in m.has_ctx) for v in vs):
            o('_ => vec![],')
        o('}', '}')
    o('}', '')


def gen_structs_impl(s):
    m = Model(s)
    o = Out(s)
    o('use crate::schema::prelude::*;', '')
    for name, ent in edition_schemas(s):
        start = len(o.lines)
        if schema_kind(s, name) == 'multiple':
            emit_multi(o, m, s, name)
        else:
            emit_single(o, m, s, name)
        if ent:
            block = o.lines[start:]
            del o.lines[start:]
            o.ent(block)
    return finish(s, o.text().rstrip('\n') + '\n')


# ---------------------------------------------------------------------------
# properties_impl.rs
# ---------------------------------------------------------------------------

INDEX_VALUE_TYPES = {'string': 'Keyword', 'id': 'Id', 'ip': 'IpMask', 'ipmask': 'IpMask',
                     'enum': 'Enum', 'u64': 'Number', 'i64': 'Number', 'float': 'Number',
                     'duration': 'Number', 'bool': 'Boolean', 'datetime': 'Number'}


def index_value_type(f):
    t = f.t
    while t['type'] == 'set':
        t = t['class']
    k = kind_of(t)
    if SC.RUST_TYPE_OVERRIDES.get((f.schema, f.name)) == 'Id':
        k = 'id'
    return INDEX_VALUE_TYPES[k]


def index_schemas(m, name, ent=False, seen=None):
    """[(Property ident, IndexSchemaType, IndexSchemaValueType, enterprise)]"""
    s = m.s
    seen = set() if seen is None else seen
    if name in seen:
        return []
    seen = seen | {name}
    out = []
    if schema_kind(s, name) == 'multiple':
        if name in SC.TYPE_INDEXED_OBJECTS:
            out.append(('Type', 'Search', 'Enum', ent))
        for v in variants(s, name):
            if v[2] and v[2] in m.indexable:
                out += index_schemas(m, v[2], ent or v[3], seen)
        return out
    for f in schema_struct_fields(s, name):
        fe = ent or f.ent
        for op in index_ops(f):
            if op[0] == 'text':
                out.append((op[1], 'Search', 'Text', fe))
            elif op[0] in ('search', 'unique'):
                vt = index_value_type(f)
                # Enum-valued field indexes are not queryable (only @type is).
                if vt != 'Enum':
                    out.append((op[1], op[0].capitalize(), vt, fe))
        if m.nested_index(f):
            k = kind_of(f.t)
            child = f.t['objectName'] if k in ('object', 'list') else f.t['valueClass']['objectName']
            out += index_schemas(m, child, fe, seen)
    return out


def emit_arms(o, s, rows):
    """rows: [(lines, enterprise)]"""
    for lines, ent in rows:
        if isinstance(lines, str):
            lines = [lines]
        o.ent(lines) if ent else o(*lines)


def emit_id_accessors(o, s, objs, json_name, rust_name):
    """`{rust_name}()` and `set_{rust_name}()` on ObjectInner, for every object
    (or variant) that has the Id field `json_name`."""
    acc_rows, set_rows = [], []
    for n, r, e in objs:
        if schema_kind(s, n) == 'multiple':
            vs = [v for v in variants(s, n) if v[2] and
                  any(f.name == json_name for f in schema_struct_fields(s, v[2]))]
            if not vs:
                continue
            get = [([f'ObjectInner::{r}(inner) => match inner.as_ref() {{'], False)]
            st = [([f'ObjectInner::{r}(inner) => match inner.as_mut() {{'], False)]
            for ident, _, payload, vent in vs:
                af = next(f for f in schema_struct_fields(s, payload) if f.name == json_name)
                get.append(([f'{r}::{ident}(obj) => ' + (f'obj.{rust_name},' if af.nullable else f'Some(obj.{rust_name}),')], vent))
                st.append(([f'{r}::{ident}(obj) => obj.{rust_name} = ' + ('Some(id),' if af.nullable else 'id,')], vent))
            every = len(vs) == len(variants(s, n))
            get.append(((['_ => None,'] if not every else []) + ['},'], False))
            st.append(((['_ => {}'] if not every else []) + ['},'], False))
            if e:
                acc_rows.append(([l for ls, _ in get for l in ls], True))
                set_rows.append(([l for ls, _ in st for l in ls], True))
            else:
                acc_rows += get
                set_rows += st
        else:
            af = next((f for f in schema_struct_fields(s, n) if f.name == json_name), None)
            if af is None:
                continue
            acc_rows.append((f'ObjectInner::{r}(obj) => ' + (f'obj.{rust_name},' if af.nullable else f'Some(obj.{rust_name}),'), e or af.ent))
            set_rows.append((f'ObjectInner::{r}(obj) => obj.{rust_name} = ' + ('Some(id),' if af.nullable else 'id,'), e or af.ent))
    o(f'pub fn {rust_name}(&self) -> Option<Id> {{', 'match self {')
    emit_arms(o, s, acc_rows)
    o('_ => None,', '}', '}', '')
    o(f'pub fn set_{rust_name}(&mut self, id: Id) {{', 'match self {')
    emit_arms(o, s, set_rows)
    o('_ => {}', '}', '}', '')


def gen_properties_impl(s):
    m = Model(s)
    o = Out(s)
    o('use crate::schema::prelude::*;', '')
    emit_enum_impl(o, s, 'ObjectType', object_variants(s))
    emit_enum_impl(o, s, 'Property', property_variants(s))
    objs = [(n, strip_x(n), s.agpl and s.ent_object(n)) for n in s.objects]
    json_of = {pascal(n): n for n in s.prop_ids}
    json_of['Type'] = '@type'

    def perm(n, op):
        prefix = s.d['objects'][n]['permissionPrefix']
        name = prefix + op
        return f'Permission::{variant_ident(name)}' if name in m.perms else None

    # impl ObjectType
    o('impl ObjectType {', 'pub fn flags(&self) -> u64 {', 'match self {')
    emit_arms(o, s, [(f'ObjectType::{r} => {r}::FLAGS,', e) for n, r, e in objs])
    o('}', '}', '')
    o('pub fn indexes(&self) -> Vec<IndexSchema> {', 'match self {')
    for n, r, e in objs:
        # Objects that are not stored have nothing to query by.
        rows = [] if n in SC.NOT_STORED_OBJECTS else index_schemas(m, n)
        uniq, seen = [], {}
        for row in rows:
            key = row[:3]
            if key in seen:
                if not row[3] and uniq[seen[key]][3]:
                    uniq[seen[key]] = row
                continue
            seen[key] = len(uniq)
            uniq.append(row)
        if not uniq:
            continue
        uniq.sort(key=lambda x: (x[0] != 'Text', json_of.get(x[0], x[0])))
        lines = [f'ObjectType::{r} => vec![']
        body = [(f'IndexSchema::new(Property::{p}, IndexSchemaType::{st}, IndexSchemaValueType::{vt}),',
                 ent) for p, st, vt, ent in uniq]
        if e:
            o.ent(lines + [b for b, _ in body] + ['],'])
        else:
            o(*lines)
            emit_arms(o, s, body)
            o('],')
    o('_ => vec![],', '}', '}', '')
    for fn, op, fallback, wildcard in (('get_permission', 'Get', None, False),
                                       ('query_permission', 'Query', None, True),
                                       ('create_permission', 'Create', 'Update', False),
                                       ('update_permission', 'Update', None, False),
                                       ('destroy_permission', 'Destroy', 'Update', False)):
        o(f'pub fn {fn}(&self) -> Permission {{', 'match self {')
        rows = []
        for n, r, e in objs:
            # Singletons are created and destroyed by updating them.
            singleton = s.d['objects'][n]['type'] == 'singleton'
            p = perm(n, op) or (fallback and singleton and perm(n, fallback))
            if p:
                rows.append((f'ObjectType::{r} => {p},', e))
            elif not wildcard:
                rows.append((f'ObjectType::{r} => unreachable!(),', e))
        emit_arms(o, s, rows)
        if wildcard:
            o('_ => unreachable!(),')
        o('}', '}', '')
    o('}', '')

    # impl ObjectInner
    o('impl ObjectInner {')
    # accountId everywhere; memberTenantId (inbuxa: MT) in the full edition only,
    # the agpl edition has no such fields.
    for json_name, rust_name in (('accountId', 'account_id'), ('memberTenantId', 'member_tenant_id')):
        if json_name == 'memberTenantId' and s.agpl:
            continue
        emit_id_accessors(o, s, objs, json_name, rust_name)
    o('pub fn to_pickled_vec(&self) -> Vec<u8> {', 'match &self {')
    emit_arms(o, s, [(f'ObjectInner::{r}(obj) => obj.to_pickled_vec(),' if n not in SC.NOT_STORED_OBJECTS
                      else f'ObjectInner::{r}(_) => unimplemented!("{r} is not stored"),', e)
                     for n, r, e in objs])
    o('}', '}', '')
    o("pub fn unpickle(object: ObjectType, stream: &mut crate::pickle::PickledStream<'_>) -> Option<Self> {",
      'match object {')
    emit_arms(o, s, [(f'ObjectType::{r} => Pickle::unpickle(stream).map(|obj| ObjectInner::{r}(Box::new(obj))),'
                      if n not in SC.NOT_STORED_OBJECTS
                      else f'ObjectType::{r} => unimplemented!("{r} is not stored"),', e)
                     for n, r, e in objs])
    o('}', '}', '')
    o("pub fn deserialize<'de, D>(object: ObjectType, deserializer: D) -> Result<Self, D::Error>",
      'where', "D: serde::Deserializer<'de>,", '{', 'match object {')
    emit_arms(o, s, [(f'ObjectType::{r} => {r}::deserialize(deserializer).map(|obj| ObjectInner::{r}(Box::new(obj))),', e)
                     for n, r, e in objs])
    o('}', '}', '')
    o("pub fn expression_ctxs(&self) -> Option<Vec<ExpressionContext<'_>>> {", 'match &self {')
    emit_arms(o, s, [(f'ObjectInner::{r}(obj) => Some(obj.expression_ctxs()),', e)
                     for n, r, e in objs if n in m.has_ctx])
    o('_ => None,', '}', '}', '}', '')

    # impl Object
    o('impl Object {', 'pub fn flags(&self) -> u64 {', 'match &self.inner {')
    emit_arms(o, s, [(f'ObjectInner::{r}(_) => {r}::FLAGS,', e) for n, r, e in objs])
    o('}', '}', '', 'pub fn object_type(&self) -> ObjectType {', 'match &self.inner {')
    emit_arms(o, s, [(f'ObjectInner::{r}(_) => ObjectType::{r},', e) for n, r, e in objs])
    o('}', '}', '', "pub fn object_variant(&self) -> Option<&'static str> {", 'match &self.inner {')
    emit_arms(o, s, [(f'ObjectInner::{r}(obj) => Some(obj.object_type().as_str()),', e)
                     for n, r, e in objs if schema_kind(s, n) == 'multiple'])
    o('_ => None,', '}', '}', '')
    o('pub fn validate(&self, errors: &mut Vec<ValidationError>) -> bool {', 'match &self.inner {')
    emit_arms(o, s, [(f'ObjectInner::{r}(obj) => obj.validate(errors),', e) for n, r, e in objs])
    o('}', '}', '')
    o("pub fn index<'x>(&'x self, i: &mut IndexBuilder<'x>) {", 'match &self.inner {')
    emit_arms(o, s, [(f'ObjectInner::{r}(obj) => obj.index(i),', e) for n, r, e in objs])
    o('}', '}', '')
    o("pub fn patch<'x>(&mut self, pointer: JsonPointerPatch<'_>, value: JmapValue<'x>) -> PatchResult<'x> {",
      'match &mut self.inner {')
    emit_arms(o, s, [(f'ObjectInner::{r}(obj) => obj.patch(pointer, value),', e) for n, r, e in objs])
    o('}', '}', '}', '')
    o('impl IntoValue for Object {',
      "fn into_value(self) -> JmapValue<'static> {",
      'self.into_value_with(ValueOptions::default())', '}', '',
      "fn into_value_with(self, opts: ValueOptions) -> JmapValue<'static> {", 'match self.inner {')
    emit_arms(o, s, [(f'ObjectInner::{r}(obj) => (*obj).into_value_with(opts),', e) for n, r, e in objs])
    o('}', '}', '}', '')
    o('impl From<ObjectType> for ObjectInner {', 'fn from(obj: ObjectType) -> Self {', 'match obj {')
    emit_arms(o, s, [(f'ObjectType::{r} => ObjectInner::{r}(Box::default()),', e) for n, r, e in objs])
    o('}', '}', '}', '')
    for n, r, e in objs:
        lines = [f'impl From<{r}> for ObjectInner {{', f'fn from(value: {r}) -> Self {{',
                 f'ObjectInner::{r}(Box::new(value))', '}', '}', '',
                 f'impl From<Object> for {r} {{', 'fn from(obj: Object) -> Self {', 'match obj.inner {',
                 f'ObjectInner::{r}(obj) => *obj,', '_ => unreachable!(),', '}', '}', '}', '']
        o.ent(lines) if e else o(*lines)
    return finish(s, o.text().rstrip('\n') + '\n')


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

OUTPUTS = {
    'crates/registry/src/schema/enums.rs': 'gen_enums',
    'crates/registry/src/schema/enums_impl.rs': 'gen_enums_impl',
    'crates/registry/src/schema/properties.rs': 'gen_properties',
    'crates/registry/src/schema/properties_impl.rs': 'gen_properties_impl',
    'crates/registry/src/schema/structs.rs': 'gen_structs',
    'crates/registry/src/schema/structs_impl.rs': 'gen_structs_impl',
}
# crates/http/src/form/mod.rs is not generated: it is the hand-written
# contact-form HTTP handler (no "auto-generated" line, nothing from the schema).


def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().split('\n')[0])
    ap.add_argument('--edition', choices=('agpl', 'full'), required=True)
    ap.add_argument('--schema', default='resources/schema/schema.json.gz',
                    help='upstream schema (gzip JSON)')
    ap.add_argument('--oss-schema', default=None,
                    help='upstream open-source schema (gzip JSON); defaults to '
                         'schema_oss.json.gz next to --schema; required for agpl')
    ap.add_argument('--out', required=True, help='output root directory')
    ap.add_argument('--only', action='append', default=[],
                    help='generate only outputs whose path contains this text')
    args = ap.parse_args()

    full = load_gz_json(args.schema)
    oss = None
    if args.edition == 'agpl':
        oss_path = args.oss_schema or str(Path(args.schema).with_name('schema_oss.json.gz'))
        oss = load_gz_json(oss_path)
    s = Schema(full, oss, args.edition)
    s.prepare()
    for rel, fn in OUTPUTS.items():
        if args.only and not any(x in rel for x in args.only):
            continue
        text = globals()[fn](s)
        path = Path(args.out) / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        print(f'{rel}: {text.count(chr(10))} lines')


if __name__ == '__main__':
    main()
