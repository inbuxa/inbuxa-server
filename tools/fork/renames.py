#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""
The upstream name where it's an identifier, and its replacement.

    tools/fork/renames.py DIR      # apply to a tree; prints what changed

Clients, users and operators meet the upstream name in a few places that
aren't notices: wire-protocol names (the JMAP registry capability, WebDAV
state tokens, Sieve extensions), the web interface's OAuth client id, store keys an
operator sees as blob names, and configuration defaults (SQL database and
user, the log file prefix). docs/spec/SPEC.md §2.4 renames them all.

strip.py applies this to every upstream import, so each release arrives
already renamed and those lines never conflict in the merge. `main` was
renamed with it once, on 2026-09-22. Don't run it on `main` again: code
written since that names the old spelling on purpose (the migrations that
retire it) would be renamed too. Those strings are listed in
name-allowlist.txt instead.

Names nobody sees keep upstream's spelling: the OAuth key-derivation contexts
and the hashed application prefix. Renaming them would only destroy state.
Copyright notices and prose (`.md`, `.txt`) are never touched.
"""
import gzip
import hashlib
import base64
import re
import sys
from pathlib import Path

# Plain substrings, in code and data: (old, new, the roots it applies under).
TEXT_RENAMES = [
    # Upstream's JMAP capability for its registry (`x:`) objects. Not plain
    # `urn:inbuxa:jmap`, which is the fork's own capability (contract C-1);
    # listed before the general prefix below so it wins.
    ('urn:stalwart:jmap', 'urn:inbuxa:jmap:registry', None),
    ('urn:stalwart:', 'urn:inbuxa:', None),
    ('vnd.stalwart.', 'vnd.inbuxa.', None),
    ('(vnd.stalwart)', '(vnd.inbuxa)', None),
    ('stalwart-webui', 'inbuxa-webui', None),
    ('STALWART_SPAM_', 'INBUXA_SPAM_', None),
    # Configuration defaults, as upstream's generated registry code spells
    # them. Server code only: the tests use the same spelling for fixtures
    # that must match their containers and identity provider (database users,
    # passwords, an OIDC audience), and name their databases explicitly.
    ('"stalwart".to_string()', '"inbuxa".to_string()', ('crates',)),
    ('"/var/log/stalwart', '"/var/log/inbuxa', ('crates',)),
    # The spam filter rules ship with the server (common::manager::spam_rules);
    # upstream's default of fetching its latest from GitHub becomes unset.
    ('spam_filter_rules_url: Some("https://github.com/stalwartlabs/spam-filter/releases/latest/download/spam-filter-rules.json.gz".to_string()),',
     'spam_filter_rules_url: None,', ('crates',)),
]
ROOTS = ('crates', 'tests', 'resources')
SKIP_SUFFIXES = {'.md', '.txt'}
TEXT_SUFFIXES = {'.rs', '.toml', '.py', '.sh', '.json', '.yml', '.yaml', '.js', '.ts', '.html', '.sieve', '.sql'}
COPYRIGHT = re.compile(r'(?i)(?:SPDX-FileCopyrightText:|\bcopyright\b|©)')

# The JSON Schema the server serves to INBUXA Admin, and its checksum.
SCHEMA = Path('resources/schema/schema.json.gz')
SCHEMA_HASH = Path('resources/schema/schema.json.sha256')
SCHEMA_RENAMES = [
    ('"stalwart"', '"inbuxa"'),
    ('vnd.stalwart', 'vnd.inbuxa'),
    # Sieve extension labels, "(vnd.stalwart)" until upstream v0.16.24.
    ('(Stalwart)"', '(vnd.inbuxa)"'),
    # The bundled spam rules: no default URL, and say what empty means.
    ('"spamFilterRulesUrl":"https://github.com/stalwartlabs/spam-filter/releases/latest/download/spam-filter-rules.json.gz",', ''),
    ('"URL to download spam filter rules from"',
     '"URL to download spam filter rules from. Empty uses the rules bundled with the server."'),
]


def rename_line(line, root):
    """Returns (new line, [(old, new, count)]) for a line of a file under `root`."""
    if COPYRIGHT.search(line):
        return line, []
    done = []
    for old, new, roots in TEXT_RENAMES:
        if roots is not None and root not in roots:
            continue
        if old in line:
            done.append((old, new, line.count(old)))
            line = line.replace(old, new)
    return line, done


def schema_bytes(gz):
    """The renamed schema, gzipped deterministically, and its checksum."""
    text = gzip.decompress(gz).decode('utf-8')
    for old, new in SCHEMA_RENAMES:
        text = text.replace(old, new)
    out = gzip.compress(text.encode('utf-8'), compresslevel=9, mtime=0)
    digest = base64.urlsafe_b64encode(hashlib.sha256(out).digest()).decode().rstrip('=')
    return out, digest


def apply(tree):
    """Apply every rename under `tree`; returns {"old → new": {file: count}}."""
    tree = Path(tree)
    done = {}

    def note(old, new, rel, count):
        done.setdefault(f'{old} → {new}', {})
        done[f'{old} → {new}'][rel] = done[f'{old} → {new}'].get(rel, 0) + count

    for root in ROOTS:
        base = tree / root
        if not base.is_dir():
            continue
        for path in sorted(base.rglob('*')):
            if not path.is_file() or path.suffix in SKIP_SUFFIXES:
                continue
            if path.suffix not in TEXT_SUFFIXES and not path.name.startswith('Dockerfile'):
                continue
            try:
                lines = path.read_text(encoding='utf-8').split('\n')
            except UnicodeDecodeError:
                continue
            changed = False
            rel = str(path.relative_to(tree))
            for n, line in enumerate(lines):
                new_line, subs = rename_line(line, root)
                for old, new, count in subs:
                    note(old, new, rel, count)
                if subs:
                    lines[n] = new_line
                    changed = True
            if changed:
                path.write_text('\n'.join(lines), encoding='utf-8')

    schema = tree / SCHEMA
    if schema.is_file():
        before = schema.read_bytes()
        text = gzip.decompress(before).decode('utf-8')
        counts = {old: text.count(old) for old, _ in SCHEMA_RENAMES}
        out, digest = schema_bytes(before)
        if any(counts.values()):
            schema.write_bytes(out)
            (tree / SCHEMA_HASH).write_text(digest, encoding='utf-8')
            for old, new in SCHEMA_RENAMES:
                if counts[old]:
                    note(old, new, str(SCHEMA), counts[old])
    return {k: dict(sorted(v.items())) for k, v in sorted(done.items())}


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(__doc__.split('\n\n')[1])
    for sub, files in apply(sys.argv[1]).items():
        print(f'{sub}: ' + ', '.join(f'{f} ({n})' for f, n in files.items()))
