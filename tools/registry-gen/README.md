<!--
SPDX-FileCopyrightText: 2026 Coffey Labs LLC
SPDX-License-Identifier: AGPL-3.0-only
-->

# inbuxa registry generator

`generate.py` writes the six generated files in
`crates/registry/src/schema/` from `resources/schema/schema.json.gz`. It needs
Python 3.12+ (standard library only) and `rustfmt` 1.x on `PATH`.

To change a registry object, edit `schema.json.gz` (and `special_cases.py` for
anything the schema doesn't carry), then regenerate from the repository root:

```
python3 tools/registry-gen/generate.py --edition full \
    --schema resources/schema/schema.json.gz --out .
```

The tree is built from the **full** edition. The **agpl** edition reproduces
upstream's open files, which is how the rules below were checked:

```
REF=<strip.py OUT>/tree tools/registry-gen/run.sh   # diff agpl output against REF
```

Options: `--oss-schema` (default: `schema_oss.json.gz` next to `--schema`;
the agpl edition needs it), `--only TEXT` (only outputs whose path contains
TEXT; you can repeat it).

Outputs, under `--out`:

| file (`crates/registry/src/schema/`) | agpl lines | diff vs d1e48ba | full lines |
|---|---|---|---|
| enums.rs | 3955 | 0 | 4198 |
| enums_impl.rs | 15283 | 0 | 16580 |
| properties.rs | 1178 | 0 | 1275 |
| properties_impl.rs | 7293 | 0 | 8011 |
| structs.rs | 5286 | 0 | 6114 |
| structs_impl.rs | 60074 | 0 | 69933 |

`crates/http/src/form/mod.rs` is not generated. It is the hand-written
contact-form HTTP handler. It has no "auto-generated" line and takes nothing
from the schema.

## Files

- `generate.py`: the generator. It holds every rule that can be derived from the schema.
- `special_cases.py`: every fact the schema does not carry, one commented
  table per kind, numbered sections 1 to 8. The generator reads nothing else.
- `tools/extract_tables.py`: recovers the per-field tables (string
  validators, check order, expression contexts, size-literal spelling) from
  generated reference files.
- `run.sh`: regenerates the agpl edition and prints `diff | wc -l` per file.

## Editions

Upstream produced the open files in three steps: it ran its generator in full,
formatted the result, and then ran `resources/scripts/ossify.py`, which deletes
every `SPDX-SnippetBegin`…`SnippetEnd` region line by line. This generator
mirrors that:

1. Enterprise lines are emitted between private markers
   (`// @@ENTERPRISE-BEGIN` / `END`, nestable).
2. The whole file is formatted with `rustfmt --edition 2024`.
3. **agpl**: the marked regions are deleted, and trailing blank lines are
   trimmed. This reproduces upstream's layout artifacts exactly:
   `vec![\n ],`, empty `fn index(..) {\n }` bodies, blank lines before a
   closing `}`. **full**: no markers, and none of the open build's
   `cfg(not(feature = "enterprise"))` stand-ins.

"Enterprise" means one of the following:

- the item is flagged `enterprise` in schema.json;
- the object or schema is missing from `schema_oss.json.gz`;
- the enum variant is missing from the open enum.

Enum variants carry no flag in schema.json, so the open schema is required.
Its `vnd.stalwart.*` names map to `vnd.inbuxa.*`.

The full edition was type-checked by copying the reference tree, swapping in
the six files, and running `cargo check -p registry --offline`. All generated
code checks. The only errors are 3 non-exhaustive `match`es in the
hand-written `utils/task.rs`, where ossify removed the Enterprise `Task` arms.
There are 2 warnings, from `SpamAiWebSearch`, which has a single unit
variant.

## Schema-to-code rules (derived)

- **Enum ids**: Rust discriminant = position in schema.json's list, checked
  for all 152 enums (Permission included). `COUNT` = full length. `#[default]`
  goes on the first variant. If that variant is Enterprise, the agpl build
  puts `cfg_attr(not(enterprise), default)` on the first open one.
  Identifiers: `+`→`Plus`, `-`→`Minus` only in `GMT-n`, split on
  non-alphanumerics, capitalize each part, prefix `V` before a digit.
- **Property ids**: `@type`=0, `id`=1, `text`=2. Every other property is
  numbered at its first sighting, walking x: schemas alphabetically and their
  fields in declaration order (virtual fields included). This reproduces all
  937 open ids and fills the 75 gaps exactly. The `Property` enum is sorted by
  identifier, with `Type` first.
- **Types**:
  - string → `String` (ip/network/socket formats → `IpAddr`, `IpAddrOrMask`,
    `SocketAddr`)
  - duration → `Duration`
  - unsignedInteger and size → `u64`; integer → `i64`; float → `Float`
  - objectId → `Id`; blobId → `BlobId`
  - set → `Map<T>`; objectList → `List<T>`; map → `VecMap<K, V>`
  - nullable → `Option<T>`
  - Rust keywords get a trailing `_`.
  - Serde renames appear whenever snake_case differs from the JSON name.
- **Defaults**:
  - Built from schema.json `defaults`: durations in ms, `Nu64` / `Ni64` /
    `Float::new(x)`, strings `.to_string()`, IP types `::from_str(..).unwrap()`.
  - Enum sets are in enum order; objectList defaults are keyed `"0"`, `"1"`, ….
  - Nested literals end in `..Default::default()` when partial.
  - Expression defaults: `else_` first, then `match_` when the key is present.
  - Plain bools without a default become `false`.
  - The fork's `/var/log/stalwart/` rename also applies to literals.
- **validate**:
  - Strings and blobs: `is_empty` → `required`. `Id`: `!is_valid` → `required`.
  - Date-times, IPs, sockets, ids from overrides, and durations with bounds:
    `invalid`.
  - Numeric bounds become `min_value` / `max_value` (i64 compares in
    parentheses).
  - `maxLength` → `max_length`; sets get `min_items` after the element loop.
  - Nested objects call `validate`. Sets loop with `iter()`, lists and maps
    with `values()`.
  - A type with no checks gets `fn validate(&self, _) -> bool { true }`.
- **Patch**:
  - serverSet → `assert_server_set()`.
  - Virtual field → returned as `Unpatched`.
  - immutable → `assert_read_only()?`; `accountId` adds
    `assert_can_set_account()?`.
  - emailAddress → `StringValidator::Email`.
  - Arms follow declaration order, then `@type`, then the error arm.
- **IntoValue**: capacity = stored fields (Enterprise included) + 2. The
  formats `secret` and `secretText` are masked unless `include_secrets`. An
  optional secret is inserted only when set.
- **Pickle** (types reachable from a stored object):
  - `begin_block(out, fields, flags, bitmap)`. Fields are numbered in
    declaration order of the stored fields, Enterprise included.
  - Every `Option` and `bool` takes the next flag bit. Bools travel only as
    flags.
  - Readers fall back to the default when `!block.has(n)`.
  - Objects check `stream.version()`.
  - Multi-variant types write a `u16` variant index (full numbering), then the
    payload.
  - In agpl, an Enterprise field that is neither Option nor bool leaves an
    empty block, and the reader skips it. Upstream does this even for the
    `u64` `Cache.tenants`.
  - When every flagged field is Enterprise, `let mut bitmap` gets
    `allow(unused_mut)`.
- **Index**:
  - Per field: a foreign key first for every objectId (sets loop,
    `x:Account/Group` views pass the variant id), then the table's ops, then
    recursion into nested types that index.
  - Only types reachable from stored objects index (Bootstrap's subtree does
    not).
  - An index that is empty in the open build but not in the full one keeps `i`
    and gets `allow(unused_variables)`.
  - `indexes()` lists text/search/unique ops: Text first, then by JSON name.
    Foreign keys, global and composite ops, enum-valued fields and
    not-stored objects are excluded.
- **Object flags**:
  - `SINGLETON` comes from the object type.
  - `FILTER_ACCOUNT`: every variant has `accountId`.
  - `FILTER_TENANT`: some variant has `memberTenantId`.
  - `NO_GET`/`CREATE`/`UPDATE`/`DESTROY`/`QUERY`: the `Permission` enum lacks
    `<prefix><Op>`. Singletons are only checked for Get and Update.
  - Permission getters fall back to Update for a singleton's create and
    destroy. Otherwise, a missing permission gives `unreachable!()`.

## Special cases (special_cases.py)

| table | entries | what it says |
|---|---|---|
| FIELD_ORDER | 329 schemas | field declaration order (schema.json is alphabetical) |
| VIRTUAL_FIELDS | 30 | properties that are patchable or listed but not stored |
| STRING_VALIDATORS | 333 | patch validators beyond `Email` (not predictable from format) |
| EXPRESSION_CONTEXTS | 122 | allowed variable and constant statics per Expression field |
| EXPRESSION_STATICS | 21 | the statics themselves (enums.rs) |
| INDEX_OPS | 107 schemas | text/search/unique/composite index entries |
| VALIDATE_MAX_FIRST | 47 | bound checks emitted max-before-min |
| VALIDATE_IF_NOT_EMPTY | 2 | Expressions validated only when set |
| SIZE_DEFAULT_SUFFIX | 26 | size defaults spelled `Nu64`, not `N` |
| SET_DEFAULT_ORDER | 3 | string-set defaults in source order |
| TRAILING_ENTERPRISE_ITEM | 56 | first impl ends with an Enterprise-only item (blank line left) |
| SEQ_ID_OBJECTS / NOT_STORED_OBJECTS | 7 / 11 | object flags |
| RUST_TYPE_OVERRIDES | 7 | `credentialId`/`documentId` → `Id`, `policyIdentifiers` → `Map<u64>` |
| MASKED_FIELDS | 2 | `otpUrl` masked like a secret |
| DEFAULT_OVERRIDES | 1 | `SpamSettings.spamFilterRulesUrl`: `None`, but unpickles to the download URL |
| EXTERNAL_ENUMS, IDENT_SOURCE_NAMES, OSS_NAME_RENAMES, ENUMS_WITH_ALL, TYPE_INDEXED_OBJECTS, STRING_LITERAL_RENAMES | small | naming and renames |
| VARIANT_ENUM_NAMES | 1 | full only: `x:Metric`'s variant enum clashes with `trc::MetricType`, renamed `MetricVariantType` (our name) |

## Enterprise placement and confidence

The open reference shows Enterprise fields only as gaps, so placement uses
these sources:

- Gaps in pickle field numbers, flag bits and Property ids.
- `#[cfg(not(enterprise))]` placeholders.
- 0.16.27 ordering (snapshot ad1330f).
- For schemas new in 1.0, form order.

Confidence by case:

- **High**: single Enterprise fields in open schemas, such as
  `memberTenantId`. Pickle gaps and id gaps pin them.
- **Good**: multi-field gaps. 0.16 order is consistent with every gap, flag
  and id.
- **Medium-high**: Enterprise-only schemas that already existed in 0.16.
- **Low**: AiModel\*, SpamAi\*, and fields new in 1.0, such as
  MaskedEmail.emailPrefix/emailDomain, Trace.from/size/timestamp/to,
  MetricCount/MetricSum.nodeId and Tenant.usedDiskQuota. Their order comes
  from forms plus id constraints, and their validators, index ops and
  contexts fall back to the derived rules. `SpamAiProperties.condition` has no
  context.

Full-edition guesses:

- `Archived*.status` is treated as virtual, as in 0.16.
- The content of the 56 trailing Enterprise items is unknown, so the full
  edition omits them.

Compatibility note: the agpl reader skips a non-option Enterprise field by
reading it as an empty block. It never skips an Enterprise `Option`. Records
that a full build wrote therefore misalign in the agpl build in two cases:

- an Enterprise `Option` that is `Some`, in front of open fields (for
  example `Domain.logo` or `DataRetention.archive*`);
- a non-option Enterprise field that is not itself a block (`Cache.tenants`,
  a `u64`).

The full edition reads and writes them correctly.
