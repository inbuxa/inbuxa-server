#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coffey Labs
# SPDX-License-Identifier: AGPL-3.0-only
"""
Produce an Enterprise-free snapshot of an upstream Stalwart release.

    tools/fork/strip.py --upstream PATH/TO/stalwart --ref v0.16.22 --out DIR

What it does, in order (docs/spec/SPEC.md §2.2):

1. Exports the tree at `--ref` with `git archive`. The snapshot never carries
   upstream's git history, because that history contains the Enterprise code.
2. Checks every Enterprise snippet is well-formed *before* stripping. Upstream's
   remover swallows an unterminated snippet to the end of the file without a
   word, so a malformed marker fails the run here instead.
3. Runs upstream's own remover, `resources/scripts/ossify.py` from the same
   ref, over every directory that holds Rust.
4. Removes `mod` declarations left pointing at deleted Enterprise files, then
   turns the `enterprise` Cargo feature off wherever it's switched on: in build
   scripts' `--features "..."` lists (Dockerfiles, CI), and in manifests: a
   crate's `default` list, and dependency `features` lists. Definitions of the
   feature are left alone. They're inert once nothing turns them on, and
   leaving them keeps each sync's diff small.
5. Verifies the result independently of `ossify.py`: no license header or
   snippet anywhere in the tree, in any file type, may name `LicenseRef-SEL`
   without `AGPL-3.0-only` alongside it, and no Cargo manifest may still turn
   `enterprise` on.
6. Writes `STRIP-REPORT.json` and `STRIP-REPORT.md` beside the tree: what was
   removed, what was edited, what upstream's schema flags as Enterprise, and
   how many `enterprise` feature gates and edition checks remain in shared
   code for the rebuilt features to replace.
7. Lists the third-party code left in the stripped tree, as upstream's
   comments mark it (another copyright holder or license, or "ported from"
   and the like), and names any file THIRD-PARTY.md doesn't cover yet. That's
   a report, not a failure: the notice goes in THIRD-PARTY.md with the merge.
8. Renames the upstream name where it's an identifier clients, users or
   operators meet (renames.py beside this script), so a re-import arrives
   purged and merges without conflicts on those lines. Copyright notices
   and prose are never touched.
9. Compiles the result (`cargo check --workspace --all-targets`). A file
   that survived the strip but calls code that didn't -- a dual-licensed test
   of an Enterprise feature, say -- fails here, on the `upstream` branch,
   instead of in the merge. Imports the strip left unused are reported, not
   failed. `--no-build-check` skips it.

Only license markers and Cargo manifests are read for meaning. The code inside
an Enterprise file or snippet is never printed, reported or kept, which is what
lets anyone run this outside the clean room (docs/spec/SPEC.md §3).

Exit status: 0 clean, 1 verification failed, 2 usage or environment error.
"""

import argparse
import gzip
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from renames import apply as rename_upstream_names  # noqa: E402

SEL = 'LicenseRef-SEL'
AGPL = 'AGPL-3.0-only'
# A license identifier as it appears in a comment header, in any comment style.
IDENT = re.compile(r'^\s*(?://+|/?\*+|#+|--|<!--)?\s*SPDX-License-Identifier:\s*(.+?)\s*(?:\*/|-->)?\s*$')
# Matched anywhere on the line, as upstream's remover matches them: an end
# marker is often a trailing comment on the snippet's last code line, as in
# `} // SPDX-SnippetEnd`.
SNIP_BEGIN = re.compile(r'//\s*SPDX-SnippetBegin\b')
SNIP_END = re.compile(r'//\s*SPDX-SnippetEnd\b')
TEXT_SUFFIXES = {
    '.rs', '.toml', '.md', '.txt', '.py', '.sh', '.json', '.yml', '.yaml', '.js',
    '.ts', '.html', '.css', '.sieve', '.sql', '.lua', '.hcl', '.cfg', '.conf', '',
}


def is_text(path):
    """Files worth scanning: known text suffixes, plus every `Dockerfile*` whatever its suffix."""
    return path.is_file() and (path.suffix in TEXT_SUFFIXES or path.name.startswith('Dockerfile'))


def fail(msg, code=2):
    print(f'strip: {msg}', file=sys.stderr)
    sys.exit(code)


def is_sel_only(expression):
    return SEL in expression and AGPL not in expression


def export(upstream, ref, out):
    """`git archive` the ref into `out`; returns the resolved commit."""
    try:
        sha = subprocess.run(['git', '-C', upstream, 'rev-parse', '--verify', f'{ref}^{{commit}}'],
                             check=True, capture_output=True, text=True).stdout.strip()
    except subprocess.CalledProcessError:
        fail(f'{ref!r} is not a commit in {upstream}. Fetch it first, e.g. '
             f'`git -C {upstream} fetch --depth 1 origin tag {ref}`')
    out.mkdir(parents=True)
    with tempfile.TemporaryFile() as tar:
        subprocess.run(['git', '-C', upstream, 'archive', '--format=tar', sha], check=True, stdout=tar)
        tar.seek(0)
        with tarfile.open(fileobj=tar) as t:
            t.extractall(out, filter='data')
    return sha


def rust_roots(tree):
    """Top-level directories that contain Rust, so ossify.py sees all of it."""
    return sorted({p.relative_to(tree).parts[0] for p in tree.rglob('*.rs')})


def check_snippets_wellformed(tree):
    """Every SnippetBegin has an End before the next Begin, and every snippet declares a license."""
    problems = []
    for path in tree.rglob('*.rs'):
        lines = path.read_text(encoding='utf-8', errors='replace').split('\n')
        open_at = None
        for n, line in enumerate(lines, 1):
            if SNIP_BEGIN.search(line):
                if open_at is not None:
                    problems.append(f'{path.relative_to(tree)}:{open_at}: snippet begins again at line {n} before ending')
                open_at = n
            elif SNIP_END.search(line):
                if open_at is None:
                    problems.append(f'{path.relative_to(tree)}:{n}: snippet ends without beginning')
                open_at = None
        if open_at is not None:
            problems.append(f'{path.relative_to(tree)}:{open_at}: snippet never ends')
    return problems


def sel_inventory(tree):
    """Before stripping: which files are SEL-only, and how many SEL snippets each file holds."""
    whole, snippets = [], {}
    for path in tree.rglob('*.rs'):
        rel = str(path.relative_to(tree))
        lines = path.read_text(encoding='utf-8', errors='replace').split('\n')
        header = next((IDENT.match(l).group(1) for l in lines[:12] if IDENT.match(l)), None)
        if header and is_sel_only(header):
            whole.append(rel)
            continue
        count, i = 0, 0
        while i < len(lines):
            if SNIP_BEGIN.search(lines[i]):
                j = i
                while j < len(lines) and not SNIP_END.search(lines[j]):
                    j += 1
                block = lines[i:j + 1]
                if any((m := IDENT.match(l)) and is_sel_only(m.group(1)) for l in block[:6]):
                    count += 1
                i = j
            i += 1
        if count:
            snippets[rel] = count
    return sorted(whole), dict(sorted(snippets.items()))


def run_ossify(tree, roots):
    script = tree / 'resources' / 'scripts' / 'ossify.py'
    if not script.is_file():
        fail('upstream has no resources/scripts/ossify.py at this ref; stripping needs it')
    log = []
    for root in roots:
        r = subprocess.run([sys.executable, str(script), str(tree / root)], capture_output=True, text=True)
        log.append(f'$ ossify.py {root}\n{r.stdout}{r.stderr}')
        if r.returncode != 0:
            fail(f'ossify.py failed on {root}:\n{r.stdout}{r.stderr}')
    return '\n'.join(log)


def deactivate_enterprise(tree):
    """Remove every activation of the `enterprise` feature from Cargo manifests."""
    edits = []
    entry = re.compile(r'"(?:[A-Za-z0-9_-]+/)?enterprise"\s*,?\s*')
    for manifest in sorted(tree.rglob('Cargo.toml')):
        text = manifest.read_text(encoding='utf-8')
        new_lines = []
        for n, line in enumerate(text.split('\n'), 1):
            code = line.split('#', 1)[0]
            key = code.split('=', 1)[0].strip() if '=' in code else ''
            activates = (
                key == 'default'
                or re.search(r'\bfeatures\s*=\s*\[', code) is not None
            )
            if activates and entry.search(code):
                cleaned = entry.sub('', line)
                cleaned = re.sub(r',\s*\]', ']', cleaned)
                edits.append({'file': str(manifest.relative_to(tree)), 'line': n,
                              'before': line.strip(), 'after': cleaned.strip()})
                line = cleaned
            new_lines.append(line)
        new = '\n'.join(new_lines)
        if new != text:
            manifest.write_text(new, encoding='utf-8')
    return edits


FEATURE_ARG = re.compile(r'(--features(?:\s+|=)")([^"]*)(")')


def deactivate_enterprise_in_scripts(tree):
    """
    Remove `enterprise` from `--features "..."` lists in build scripts.

    Upstream's Dockerfiles and CI pass the feature on the cargo command line,
    which the manifest edits don't reach. Left in, the image and release
    builds fail on a feature whose code is gone.
    """
    edits = []
    for path in sorted(tree.rglob('*')):
        if path.name == 'Cargo.toml' or not is_text(path):
            continue
        try:
            text = path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            continue
        if '--features' not in text or 'enterprise' not in text:
            continue
        lines = text.split('\n')
        changed = False
        for n, line in enumerate(lines):
            def drop(m):
                kept = [f for f in m.group(2).split() if f != 'enterprise' and not f.endswith('/enterprise')]
                return m.group(1) + ' '.join(kept) + m.group(3)
            new = FEATURE_ARG.sub(drop, line)
            if new != line:
                edits.append({'file': str(path.relative_to(tree)), 'line': n + 1,
                              'before': line.strip(), 'after': new.strip()})
                lines[n] = new
                changed = True
        if changed:
            path.write_text('\n'.join(lines), encoding='utf-8')
    return edits


def remove_dangling_mods(tree):
    """
    Remove `mod x;` declarations whose file ossify.py deleted.

    An Enterprise-only file can be declared from shared code just outside the
    snippet that ossify.py removes, so the declaration survives and points at
    nothing. Only shared (AGPL) code is read here, and only for `mod` lines. A
    declaration goes with the attribute lines directly above it, e.g. its
    `#[cfg(...)]`.
    """
    decl = re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;\s*(?://.*)?$')
    removed = []
    for path in sorted(tree.rglob('*.rs')):
        base = path.parent if path.name in ('mod.rs', 'lib.rs', 'main.rs') else path.parent / path.stem
        lines = path.read_text(encoding='utf-8').split('\n')
        keep = []
        for n, line in enumerate(lines, 1):
            m = decl.match(line)
            if m and not (base / f'{m.group(1)}.rs').is_file() and not (base / m.group(1) / 'mod.rs').is_file():
                dropped = [line]
                while keep and keep[-1].strip().startswith('#['):
                    dropped.insert(0, keep.pop())
                removed.append({'file': str(path.relative_to(tree)), 'line': n, 'module': m.group(1),
                                'lines': [l.strip() for l in dropped]})
                continue
            keep.append(line)
        if len(keep) != len(lines):
            path.write_text('\n'.join(keep), encoding='utf-8')
    return removed


def verify(tree):
    """Independent of ossify.py. Returns a list of problems; empty means clean."""
    problems = []
    for path in tree.rglob('*'):
        if not is_text(path):
            continue
        rel = path.relative_to(tree)
        if rel.parts[0] == 'LICENSES':
            continue  # the license texts themselves, not code under them
        try:
            lines = path.read_text(encoding='utf-8').split('\n')
        except UnicodeDecodeError:
            continue
        for n, line in enumerate(lines, 1):
            m = IDENT.match(line)
            if m and is_sel_only(m.group(1)):
                problems.append(f'{rel}:{n}: Enterprise-only license marker survived')
    for path in tree.rglob('*'):
        if path.name == 'Cargo.toml' or not is_text(path):
            continue
        try:
            text = path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            continue
        for n, line in enumerate(text.split('\n'), 1):
            for m in FEATURE_ARG.finditer(line):
                if any(f == 'enterprise' or f.endswith('/enterprise') for f in m.group(2).split()):
                    problems.append(f'{path.relative_to(tree)}:{n}: build script still passes the enterprise feature')
    for manifest in tree.rglob('Cargo.toml'):
        for n, line in enumerate(manifest.read_text(encoding='utf-8').split('\n'), 1):
            code = line.split('#', 1)[0]
            key = code.split('=', 1)[0].strip() if '=' in code else ''
            if (key == 'default' or re.search(r'\bfeatures\s*=\s*\[', code)) and re.search(r'"(?:[\w-]+/)?enterprise"', code):
                problems.append(f'{manifest.relative_to(tree)}:{n}: enterprise feature still switched on')
    return problems


# Third-party code as upstream marks it, in comments only: a license
# identifier other than upstream's own, a copyright line naming anyone but
# Stalwart Labs, or a note that code came from somewhere else.
COMMENT = re.compile(r'^\s*(?://+!?|/?\*+|#+|--|<!--)\s*(.*?)\s*(?:\*/|-->)?\s*$')
COPYRIGHT = re.compile(r'(?i)(?:SPDX-FileCopyrightText:|\bcopyright\b|©)')
ORIGIN = re.compile(r'(?i)\b(?:(?:ported|derived|adapted|taken|copied|borrowed)\s+from|credits?\b\s*:|inspired\s+by'
                    r'|licen[cs]e(?:d)?\s*(?:under|:)|\w+\s+licen[cs]ed\b|^from\s+https?://)')
OWN = ('Stalwart Labs',)
OWN_LICENSES = {AGPL, f'{AGPL} OR {SEL}'}


def third_party(tree):
    """
    Every comment line in the stripped tree that points at someone else's code.

    Runs after stripping, so only shared (AGPL) code is read. Each hit is a
    notice the fork passes on when it distributes, so it's matched against
    THIRD-PARTY.md, and a file that isn't listed there yet is reported as new.
    """
    hits = {}
    for path in sorted(tree.rglob('*')):
        if not is_text(path):
            continue
        rel = path.relative_to(tree)
        if rel.parts[0] == 'LICENSES' or path.suffix in ('.md', '.txt', '.json'):
            continue  # license texts, prose and data, not code
        try:
            lines = path.read_text(encoding='utf-8').split('\n')
        except UnicodeDecodeError:
            continue
        for n, line in enumerate(lines, 1):
            ident = IDENT.match(line)
            if ident:
                if ident.group(1) not in OWN_LICENSES and SEL not in ident.group(1):
                    hits.setdefault(str(rel), []).append({'line': n, 'text': f'SPDX-License-Identifier: {ident.group(1)}'})
                continue
            m = COMMENT.match(line)
            if not m or any(o in m.group(1) for o in OWN):
                continue
            if COPYRIGHT.search(m.group(1)) or ORIGIN.search(m.group(1)):
                hits.setdefault(str(rel), []).append({'line': n, 'text': m.group(1)[:160]})
    return hits


def unlisted(hits):
    """Files with third-party notices that THIRD-PARTY.md doesn't name yet."""
    notices = Path(__file__).resolve().parents[2] / 'THIRD-PARTY.md'
    listed = set(re.findall(r'`([^`\s]+?)(?::\d+)?`', notices.read_text(encoding='utf-8'))) if notices.is_file() else set()
    return sorted(f for f in hits if f not in listed)


def schema_flags(tree):
    path = tree / 'resources' / 'schema' / 'schema.json.gz'
    if not path.is_file():
        return None
    d = json.loads(gzip.decompress(path.read_bytes()))
    objects = sorted(k for k, v in d.get('objects', {}).items() if v.get('enterprise'))
    fields = sorted(
        f'{obj}.{name}'
        for obj, spec in d.get('fields', {}).items() if isinstance(spec, dict)
        for name, prop in spec.get('properties', {}).items()
        if isinstance(prop, dict) and prop.get('enterprise')
    )
    return {'objects': objects, 'fields': fields}


def remaining_hooks(tree):
    gates, checks = {}, {}
    for path in tree.rglob('*.rs'):
        text = path.read_text(encoding='utf-8', errors='replace')
        rel = str(path.relative_to(tree))
        g = len(re.findall(r'feature\s*=\s*"enterprise"', text))
        c = text.count('is_enterprise_edition()')
        if g:
            gates[rel] = g
        if c:
            checks[rel] = c
    return dict(sorted(gates.items())), dict(sorted(checks.items()))


BUILD_KNOWN = Path(__file__).resolve().parent / 'build-check-known.txt'


def known_build_failures():
    """Files expected not to compile in a stripped tree (build-check-known.txt)."""
    if not BUILD_KNOWN.is_file():
        return set()
    return {l.strip() for l in BUILD_KNOWN.read_text(encoding='utf-8').split('\n')
            if l.strip() and not l.lstrip().startswith('#')}


def build_check(tree, target_dir):
    """
    `cargo check` the stripped tree. Returns (errors, unused): each error is
    {file, line, message} from a compiler diagnostic, grouped by the file it
    points at; unused lists the imports reported unused.

    Only compiler diagnostics are read, and they point at the shared code
    that failed, never at the removed code.
    """
    cmd = ['cargo', 'check', '--workspace', '--all-targets', '--locked', '--message-format=json',
           '--target-dir', str(target_dir)]
    r = subprocess.run(cmd, cwd=tree, capture_output=True, text=True)
    errors, unused = [], []
    for line in r.stdout.splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get('reason') != 'compiler-message':
            continue
        d = msg['message']
        span = next((s for s in d.get('spans', []) if s.get('is_primary')), None)
        where = {'file': span['file_name'], 'line': span['line_start']} if span else {'file': '?', 'line': 0}
        if d.get('level') == 'error':
            errors.append({**where, 'message': d.get('message', '')})
        elif (d.get('code') or {}).get('code') == 'unused_imports':
            unused.append({**where, 'message': d.get('message', '')})
    if r.returncode != 0 and not errors:
        errors.append({'file': '?', 'line': 0, 'message': (r.stderr.strip().splitlines() or ['cargo check failed'])[-1]})
    dedup = lambda items: [dict(t) for t in sorted({tuple(sorted(i.items())) for i in items}, key=lambda t: (dict(t)['file'], dict(t)['line']))]
    return dedup(errors), dedup(unused)


def write_report(out_dir, report):
    (out_dir / 'STRIP-REPORT.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    r = report
    md = [
        f'# Strip report: upstream {r["ref"]} ({r["commit"][:12]})',
        '',
        f'- Enterprise-only files removed or emptied: **{len(r["removed_files"])}**',
        f'- Enterprise-only snippets removed: **{sum(r["removed_snippets"].values())}** in {len(r["removed_snippets"])} files',
        f'- Cargo edits turning `enterprise` off: **{len(r["cargo_edits"])}**',
        f'- Dangling module declarations removed: **{len(r["dangling_mods"])}**',
        f'- Verification: **{"clean" if not r["problems"] else f"{len(r["problems"])} problems"}**',
        f'- Left for the rebuilt features to replace: {sum(r["feature_gates"].values())} `enterprise` feature gates '
        f'in {len(r["feature_gates"])} files; {sum(r["edition_checks"].values())} `is_enterprise_edition()` checks '
        f'in {len(r["edition_checks"])} files',
        f'- Third-party code: {len(r["third_party"])} files, **{len(r["third_party_unlisted"])}** not in THIRD-PARTY.md',
        f'- Renamed identifiers: {sum(sum(f.values()) for f in r["renames"].values())} in '
        f'{len({p for f in r["renames"].values() for p in f})} files',
        '- Build check: ' + ('skipped' if r['build'] is None else
                             f'**{"clean" if not r["build"]["errors"] else f"{len(r["build"]["errors"])} errors"}**, '
                             f'{len(r["build"]["expected"])} expected errors in '
                             f'{len({e["file"] for e in r["build"]["expected"]})} rebuilt-feature tests, '
                             f'{len(r["build"]["unused"])} imports left unused'),
    ]
    if r['schema']:
        md.append(f'- Upstream schema flags {len(r["schema"]["objects"])} objects and {len(r["schema"]["fields"])} fields as Enterprise')
    md += ['', '## Removed files', ''] + [f'- `{f}`' for f in r['removed_files']]
    md += ['', '## Removed snippets', ''] + [f'- `{f}`: {n}' for f, n in r['removed_snippets'].items()]
    md += ['', '## Dangling module declarations removed', ''] + [f'- `{d["file"]}:{d["line"]}`: `mod {d["module"]}` ({" / ".join(d["lines"])})' for d in r['dangling_mods']]
    md += ['', '## Cargo edits', ''] + [f'- `{e["file"]}:{e["line"]}`: `{e["before"]}` → `{e["after"]}`' for e in r['cargo_edits']]
    if r['schema']:
        md += ['', '## Flagged Enterprise in upstream\'s schema', '', '**Objects:** ' + ', '.join(f'`{o}`' for o in r['schema']['objects']),
               '', '**Fields:** ' + ', '.join(f'`{f}`' for f in r['schema']['fields'])]
    md += ['', '## Third-party code', '',
           'Comments in the stripped tree that name another copyright holder, another license, or a source the '
           'code came from. Files marked **new** aren\'t in THIRD-PARTY.md yet.', '']
    for f, found in r['third_party'].items():
        md.append(f'- `{f}`{" **new**" if f in r["third_party_unlisted"] else ""}')
        md += [f'  - {h["line"]}: {h["text"]}' for h in found]
    md += ['', '## Renamed identifiers', '']
    for sub, files in r['renames'].items():
        md.append(f'- `{sub}`: ' + ', '.join(f'`{f}` ({n})' for f, n in files.items()))
    if r['build'] is not None:
        md += ['', '## Build check', '',
               'Errors mean shared code calls something the strip removed: usually a dual-licensed file that only '
               'serves an Enterprise feature. Drop or rework it in the merge into `main`, never on `upstream`.', '']
        md += [f'- error `{e["file"]}:{e["line"]}`: {e["message"]}' for e in r['build']['errors']]
        md += [f'- unused `{u["file"]}:{u["line"]}`: {u["message"]}' for u in r['build']['unused']]
        md += ['', 'Expected: upstream\'s tests of features the fork rebuilt on `main` '
               '(tools/fork/build-check-known.txt).', '']
        md += [f'- `{e["file"]}:{e["line"]}`: {e["message"]}' for e in r['build']['expected']]
        md += [f'- `{f}` now compiles: take it off the known list' for f in r['build']['known_clean']]
    if r['problems']:
        md += ['', '## Problems', ''] + [f'- {p}' for p in r['problems']]
    (out_dir / 'STRIP-REPORT.md').write_text('\n'.join(md) + '\n', encoding='utf-8')


def main():
    ap = argparse.ArgumentParser(description='Produce an Enterprise-free snapshot of an upstream Stalwart release.')
    ap.add_argument('--upstream', required=True, type=Path, help='a git clone of upstream Stalwart')
    ap.add_argument('--ref', required=True, help='tag, branch or commit to snapshot, e.g. v0.16.22')
    ap.add_argument('--out', required=True, type=Path, help='new directory; the tree goes in OUT/tree')
    ap.add_argument('--target-dir', type=Path, default=Path(__file__).resolve().parents[2] / 'target' / 'strip-check',
                    help="cargo's target dir for the build check (default: this repo's target/strip-check, "
                         'which keeps the dependency build warm between imports)')
    ap.add_argument('--no-build-check', action='store_true', help='skip compiling the stripped tree')
    args = ap.parse_args()

    if args.out.exists():
        fail(f'{args.out} already exists; choose a new directory')
    tree = args.out / 'tree'
    commit = export(args.upstream, args.ref, tree)

    malformed = check_snippets_wellformed(tree)
    if malformed:
        write_report(args.out, {'ref': args.ref, 'commit': commit, 'removed_files': [], 'removed_snippets': {},
                                'cargo_edits': [], 'dangling_mods': [], 'problems': malformed, 'feature_gates': {}, 'edition_checks': {},
                                'schema': None, 'third_party': {}, 'third_party_unlisted': [],
                                'renames': {}, 'build': None, 'ossify_log': ''})
        print('\n'.join(malformed), file=sys.stderr)
        fail('malformed snippet markers; nothing stripped', code=1)

    removed_files, removed_snippets = sel_inventory(tree)
    log = run_ossify(tree, rust_roots(tree))
    edits = deactivate_enterprise(tree) + deactivate_enterprise_in_scripts(tree)
    dangling = remove_dangling_mods(tree)
    renames = rename_upstream_names(tree)
    problems = verify(tree)
    gates, checks = remaining_hooks(tree)
    others = third_party(tree)
    new_others = unlisted(others)
    build = None
    if not args.no_build_check and not problems:
        print('strip: compiling the stripped tree (cargo check)...', file=sys.stderr)
        errors, unused = build_check(tree, args.target_dir)
        known = known_build_failures()
        expected = [e for e in errors if e['file'] in known]
        errors = [e for e in errors if e['file'] not in known]
        build = {'errors': errors, 'expected': expected, 'unused': unused,
                 'known_clean': sorted(known - {e['file'] for e in expected})}
        problems += [f'{e["file"]}:{e["line"]}: does not compile: {e["message"]}' for e in errors]

    report = {
        'ref': args.ref, 'commit': commit,
        'removed_files': removed_files, 'removed_snippets': removed_snippets,
        'cargo_edits': edits, 'dangling_mods': dangling, 'problems': problems,
        'feature_gates': gates, 'edition_checks': checks,
        'schema': schema_flags(tree), 'third_party': others, 'third_party_unlisted': new_others,
        'renames': renames, 'build': build, 'ossify_log': log,
    }
    write_report(args.out, report)
    print(f'{args.ref} ({commit[:12]}): removed {len(removed_files)} files and '
          f'{sum(removed_snippets.values())} snippets, {len(dangling)} dangling mods, {len(edits)} Cargo edits, '
          f'{"verified clean" if not problems else f"{len(problems)} PROBLEMS"}'
          f'{f", {len(new_others)} files of third-party code not in THIRD-PARTY.md" if new_others else ""}. Report: {args.out}/STRIP-REPORT.md')
    sys.exit(1 if problems else 0)


if __name__ == '__main__':
    main()
