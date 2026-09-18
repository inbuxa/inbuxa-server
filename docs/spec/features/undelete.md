# Feature spec: undelete

Status: draft, 2026-09-18. Feature 3 in SPEC.md §4.

## Provenance

Written for the clean room (SPEC.md §3). Sources, and nothing else:

| Source | License | Used for |
|---|---|---|
| Stalwart's registry schema: `x:ArchivedItem` and its five variants, `x:TaskRestoreArchivedItem`, `x:DataRetention`, the related enums and permissions, upstream `d9dee0a` | AGPL-3.0-only OR LicenseRef-SEL, taken under the AGPL | The stored records, field meanings, statuses, the restore task, the settings |
| Stalwart documentation: "Storage overview" (Un-deleting emails), the ArchivedItem and DataRetention object references, "Tasks" (Restore archived item) | Unlicensed public documentation: facts used, prose not copied | What counts as deleted, who can recover, how restore is asked for, the retention switch |
| RFC 8620, RFC 8621 | IETF | JMAP semantics; `Email` and mailbox behavior on restore |
| Probes of INBUXA's live Enterprise server, 2026-09-18 (Stalwart 0.16.22) | Observation | Everything under "Observed" |

No Enterprise-only file or snippet was used. The drafting session writes specs
only. Gaps are settled by observation or marked **Decision**, never filled
from memory of upstream code.

## What it is

When something is deleted for good (an email emptied from Trash, a file, a
calendar event, a contact, a Sieve script), the server keeps a copy for a set
period instead of destroying it at once. Within that period the user, or an
administrator, can bring it back. After it, the copy is destroyed.

This covers the mistakes that hurt most: emptying Trash, a filter that
deleted the wrong thing, a client that expunged a folder, a deleted script.
It isn't a backup (it doesn't protect against losing the server) and it
isn't a legal hold (a user can still destroy their own copies, see
UD-12).

Upstream ships this only in its Enterprise Edition. inbuxa-server ships it to
everybody. Off by default, as upstream, and switched on by a single duration.

## Data model

Unchanged from upstream, so existing archives open as they are (SPEC.md §7).

### Settings, on `x:DataRetention`

| Field | Meaning |
|---|---|
| `archiveDeletedItemsFor` | Duration. How long a deleted item is kept. Unset: nothing is kept, deletion is immediate. This is the only switch |
| `archiveDeletedAccountsFor` | Duration. How long a deleted account is kept. Unset: accounts are destroyed at once |

The clean-up that finally destroys expired copies runs on the existing
`dataCleanupSchedule` and `blobCleanupSchedule` of the same object.

### The record, `x:ArchivedItem`

One object with five variants, chosen by `@type`:

| Variant | Its own fields |
|---|---|
| `Email` | `from`, `subject`, `receivedAt`, `size` (read-only) |
| `FileNode` | `name`, `createdAt` |
| `CalendarEvent` | `title`, `startTime`, `createdAt` |
| `ContactCard` | `name`, `createdAt` |
| `SieveScript` | `name`, `content`, `createdAt` |

Every variant also has `accountId` (the owner), `archivedAt`,
`archivedUntil` (when it's destroyed if not restored), `blobId` (the kept
copy) and `status`, which is `archived` (kept, restorable) or
`requestRestore` (restore asked for).

Permissions: `sysArchivedItemGet`, `sysArchivedItemQuery`,
`sysArchivedItemCreate`, `sysArchivedItemUpdate`, `sysArchivedItemDestroy`,
and `taskRestoreArchivedItem`.

### The restore task, `x:TaskRestoreArchivedItem`

Task type `RestoreArchivedItem`, carrying the `accountId`, the
`archivedItemType`, the `blobId`, the original `createdAt`, the
`archivedUntil` deadline, and the task's own `status` and `due`.

## Required behavior

### What gets kept

- **UD-1.** With `archiveDeletedItemsFor` set, a copy is kept whenever an item
  of one of the five kinds is permanently removed from an account, whatever
  removed it. **Decision**, a deliberate extension: upstream defines all five
  kinds but archives only email. A contact, calendar event, file and Sieve
  script destroyed over JMAP produced no record (observed 2). inbuxa-server
  archives all five:
  - **Email:** JMAP `Email/set` destroy, IMAP `EXPUNGE` and
    `UID EXPUNGE`, POP3 `DELE` then `QUIT`, the automatic emptying of Trash
    and Junk (`expungeTrashAfter`), and a Sieve action that removes a stored
    message.
  - **Files:** `FileNode` destroy, over JMAP or WebDAV.
  - **Calendar events and contacts:** destroy over JMAP, CalDAV or CardDAV.
  - **Sieve scripts:** destroy over JMAP or ManageSieve.
- **UD-2.** Moving to Trash isn't deletion, and keeps nothing: the item still
  exists. Only the permanent removal is archived.
- **UD-3.** Mail rejected or discarded before delivery (spam refused at SMTP,
  a Sieve `discard` of incoming mail) was never stored, and isn't kept.
  **Decision**: an item that never reached the account can't be undeleted.
  Confirm against upstream (to observe, 2).
- **UD-4.** The copy is whole: for email, the full message as stored, with its
  mailboxes and keywords recorded so restore can put them back (UD-8). The
  archived record shows only the summary fields above.
- **UD-5.** `archivedUntil` is `archivedAt` plus the retention in force when
  the item was archived. Changing the setting later doesn't move existing
  deadlines. **Decision**: a shorter setting must never silently destroy what
  a user was told they could still recover.
- **UD-6.** Switching archiving off (unsetting the duration) stops new copies.
  Copies already kept stay until their own `archivedUntil`.
- **UD-6a.** A change to either retention setting takes effect at once.
  **Decision**, a fix: upstream applies it only after a settings reload
  (observed 1). Until then, deletions are destroyed as if archiving were off,
  while the setting reads as on.

### Recovering

- **UD-7.** A user sees and restores its own archived items. An administrator
  with the permissions sees and restores any account's it manages. In a
  tenant, a tenant administrator only its tenant's (multi-tenancy MT-1).
  Whether ordinary users hold these permissions by default is to observe, 4.
- **UD-8.** Restore is asked for by setting `status: requestRestore` on the
  item, over `x:ArchivedItem/set`. The server creates a `RestoreArchivedItem`
  task for it, and the task:
  - **Email:** puts the message back in the mailboxes it was in when deleted,
    if they still exist. If none do, it goes to the Inbox. **Decision** on
    Trash: a message deleted *from* Trash is restored to Trash only if Trash is
    all it was in. Otherwise it goes to the other mailboxes it was in. Keywords
    come back as they were, `$seen` included. It rejoins its thread.
  - **Files:** back to their original folder if it exists, else the root, with
    a `(restored)` suffix if the name is taken.
  - **Calendar events and contacts:** back to their original calendar or
    address book if it exists, else the default.
  - **Sieve scripts:** back as an inactive script, suffixed if the name is
    taken. A restored script never activates itself.
  **Decision**, a deliberate improvement: upstream restores every message
  to the Inbox, whatever mailboxes it was in (Trash included), with all
  keywords dropped (`$seen` and `$flagged` gone), under a new id and a new
  thread. It keeps only `receivedAt` (observed 5). That makes a restore look
  like new, unread mail, and loses the user's filing.
- **UD-9.** Once restored, the archived record is removed, as upstream
  (observed 5). The restored item is a new item with a new id, and JMAP
  `/changes` reports it as created.
- **UD-10.** A restore still counts against quota. It's refused if it would
  take the account, or its tenant, past a limit. The item stays archived, and
  the task records why.
- **UD-11.** Restoring is idempotent: asking twice, or asking while a restore
  task is already running, restores once.

### Destroying

- **UD-12.** A user may permanently destroy its own archived items early
  (`x:ArchivedItem/set` destroy), as upstream allows (observed 8). "Delete
  means delete" must stay possible for the person whose data it is. Undelete protects against
  accidents, not against the user. An operator who needs retention against
  users' wishes needs a legal-hold feature, which this isn't.
- **UD-13.** Past `archivedUntil`, the scheduled clean-up destroys the record
  and its copy. Nothing expired is restorable, even if clean-up hasn't run yet.

### Storage

- **UD-14.** Archived copies don't count toward the account's or tenant's
  quota while archived, as upstream (observed 7). Counting them would make deleting mail to
  free space fail. They do count in server storage reporting, and ihasmail's
  admin dashboard shows the archive's total size per account.

### Deleted accounts

- **UD-15.** With `archiveDeletedAccountsFor` set, destroying an account keeps
  the whole account (mail, files, calendars, contacts, scripts, settings) for
  that period. The account can't sign in or receive mail while deleted.
  Mail to it is refused as for an unknown address.
- **UD-16.** Its name and addresses stay reserved while it's kept, so nobody
  else can take them and receive its mail. **Decision**, a fix: upstream
  doesn't reserve them. A new account with the deleted one's name was created
  at once, while the old one's data was still waiting to be destroyed
  (observed 6).
- **UD-17.** A server-level administrator (or a tenant administrator, for its
  tenant) can restore a kept account within the period. It comes back as it
  was, with the same id and a new password to be set. **Decision**, an
  addition: upstream offers no restore. A deleted account disappears from the
  account list at once, and only a pending `DestroyAccount` task, due at the
  end of the period, shows it's still held (observed 6).

## Interfaces

- **Existing, unchanged:** `x:ArchivedItem/get`, `/query`, `/set` (update
  `status`; destroy); the task and settings objects; the permission names.
  Upstream's `/query` accepts no filter at all, and its `/get` omits `status`
  and `accountId` even when asked (observed 8). inbuxa-server returns every
  property it lists.
- **New, Decision:** `x:ArchivedItem/changes`; `/query` filters on `@type`
  and `archivedAt` ranges, and text over the summary fields, so ihasmail can
  offer "deleted in the last week" and search. Kept deleted accounts listed
  and restored through `x:Account` (shape settled with UD-17 once observed).

## ihasmail

These go in the INBUXA fork of ihasmail, not public ihasmail, which stays
Stalwart-facing (SPEC.md §5).

- **Recently deleted**, a view in Mail (and in Files, Calendar and Contacts
  for their kinds). It lists what's restorable, newest first, with how long is
  left, searchable, with **Restore** and **Delete forever**. Visible only when
  the server has archiving on.
- **After emptying Trash:** the confirmation says how long the mail stays
  recoverable, when archiving is on.
- **Administration:** an account's archive on its panel (count, size, restore
  on the user's behalf). Deleted accounts in the accounts list, marked, with
  **Restore** until their deadline. The retention settings in the storage
  settings.
- Every string this adds is new translation work for ihasmail's nine
  languages.

## Acceptance tests

1. Archiving off: an emptied message is gone, and there's no archived record.
2. Archiving 30 days: `Email/set` destroy, IMAP expunge, POP3 delete, and
   automatic Trash emptying each produce one archived `Email` record, with
   `archivedUntil` 30 days out (UD-1, UD-5).
3. Moving to Trash produces no record (UD-2).
4. Restoring a message deleted from two labels puts it back in both, with its
   keywords and thread (UD-8).
5. Restoring when its mailboxes are gone lands it in Inbox (UD-8).
6. File, event, contact and script each restore to the right place, and a
   restored script is inactive (UD-8).
7. The restored item has a new id, and the record is gone (UD-9).
8. Restoring past the account's quota is refused, and the item stays archived
   (UD-10).
9. Double restore restores once (UD-11).
10. The user destroys an archived item: it's gone for good (UD-12).
11. Retention lowered from 30 to 7 days: existing deadlines don't move
    (UD-5).
12. Past `archivedUntil`: not restorable, and gone after clean-up (UD-13).
13. Archive size doesn't count toward quota (UD-14).
14. Deleted account: can't sign in, mail refused, name reserved, restorable
    by an admin with its data intact (UD-15 to UD-17).
15. A user can't see another user's archive. A tenant admin sees only its
    tenant's (UD-7).
16. **(compat)** Archived items already held at INBUXA read back unchanged
    through `x:ArchivedItem` after cutover, and restore.

## Observed

Settled on 2026-09-18 against INBUXA's live Enterprise server (Stalwart
0.16.22). With the operator's approval, both retention settings were set to 1
day, made effective with a settings reload at 16:57:09 UTC, and restored to
their recorded values (unset) with a second reload at 17:01:50 UTC. The probes
ran as the throwaway ordinary account and a temporary admin. Everything the
probes created was deleted afterwards. The one exception is a deleted probe
account whose scheduled destroy task, due 2026-09-19 17:01 UTC, removes its one
message. Deletions by other users during those 4 minutes 41 seconds are kept
until their own 1-day deadline, then destroyed. No upstream code was read.

1. **Before, and switching on.** Archiving was off (both settings unset) and
   INBUXA held no archived items, so nothing needs carrying over at cutover.
   Setting the duration over JMAP read back as set, but deletions weren't
   archived, not even after an account purge task, until a `ReloadSettings`
   action. After that, archiving was immediate.
2. **What produced a record.** Email destroyed over JMAP, email destroyed from
   Trash over JMAP, and email expunged over IMAP each produced one `Email`
   record within seconds. A contact card, calendar event, file and Sieve script
   destroyed over JMAP produced none. Automatic Trash emptying, POP3 and Sieve
   `discard` weren't tested.
3. **The record.** `@type`, `from`, `subject`, `receivedAt`, `size`,
   `archivedAt`, `archivedUntil` (`archivedAt` plus the retention), `blobId`,
   `id`.
4. **Permissions.** The ordinary account holds all five `sysArchivedItem*`
   permissions, but not `taskRestoreArchivedItem`. It didn't need that one to
   restore.
5. **Restore.** Setting `status: requestRestore` restored within 10 seconds.
   A message that had been in Inbox and a second mailbox, flagged and read, came
   back in Inbox only, with no keywords, a new id and a new thread.
   `receivedAt` was kept. A message deleted from Trash also came back to Inbox.
   The archived record was removed on restore.
6. **Deleted accounts.** Destroying an account made sign-in fail (401) at
   once. The account left the list and `get` (`notFound`). Mail to it was
   refused `550 5.1.2 Mailbox does not exist.` A `DestroyAccount` task was
   scheduled for the end of the period, carrying the id, name and domain. No
   archived item appeared, and no restore path was visible. A new account with
   the same name was created successfully straight away. With retention off, a
   destroyed account left no task: it was deleted immediately.
7. **Quota.** The account's usage stayed at 185 bytes with three messages
   archived, and rose to 2,303 once two were restored.
8. **API.** `x:ArchivedItem/changes` is an unknown method. `/query` rejected
   every filter tried, `accountId` included, as `unsupportedFilter`. `/get`
   omitted `status` and `accountId` even when named in `properties`. The user
   could destroy its own archived item.

Not settled: automatic Trash and Junk emptying, POP3 deletion, Sieve
`discard`; whether a pending `DestroyAccount` task can be cancelled to keep an
account; and why the test account's usage read 486 bytes after cleanup
against 185 before (probably deletions not yet subtracted, not archiving).
None blocks the spec.
