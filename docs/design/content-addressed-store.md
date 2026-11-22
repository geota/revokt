<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The content-addressed store

Not normative; milestone 0.3. The design for #229, from the 2026-11-16 design audit (B-F8, accepted by the maintainer
that day), written against spec revision 61 and `main` at `08cf785`. Until the implementation issue edits §6.5, the
spec wins. Its three questions were answered on 2026-11-22 (section 13): keep `previous` (Q1, the lead), keep seed
rule (b)'s adopt scan (Q2, the maintainer; section 6.1), and run in memory when the store cannot be used (Q3, the
maintainer; section 10).

## 1. Summary

The store has three kinds of key under `<dataset>/<channel>/`:

- `blobs/<sha256>`: every attachment, full or delta, under the SHA-256 its signed record gives;
- `generations/<sha256>`: one file per generation, holding the verified records and the signature that verified
  them, under the SHA-256 of the file's own bytes;
- `current`, the pointer, and `updater.json`: the only keys whose bytes ever change.

An install writes its new blobs, then its generation file, then the pointer. Writing the pointer is the one step
that makes a generation live. `index.bin` is not stored: it is rebuilt from the records whenever a generation loads.
Prune keeps the generation files the pointer names and the blobs they name, and deletes the rest. The store no
longer holds a C2SP directory image. `GenerationFiles` still is one, in memory, and a test helper writes it to a
directory for the upki engine.

The point of the design: **every key except `current`, `updater.json` and `store.version` is named by the hash of its
bytes**. A write to such a key can only write the bytes its name already promises, so nothing on disk is ever
rewritten into something else. A half-written generation cannot be mistaken for a whole one, and an unchanged delta is
reused because its name matches. Most of today's directory rules go away: held directories, reopening, "holds another
generation", same-`<ts>` comparison and orphan completion.

The store's lifecycle modes (read-only instances, promotion to writer, and the storage fallback) are deferred until
a user needs them (section 10, Q3).

## 2. Layout

Keys follow §3's rule (segments of `[A-Za-z0-9._-]{1,96}`); dataset and channel are lowercase enum names, as today.

| Key | Content | Written | Mutable |
|---|---|---|---|
| `store.version` | `1` | once, first | no (a later layout bumps it, §6.5) |
| `<d>/<c>/blobs/<sha256>` | one attachment's bytes, re-hashed against the key on every read | before its generation file | no: content-addressed by the signed hash |
| `<d>/<c>/generations/<sha256>` | the generation file (section 3), re-hashed against the key on every read | after its blobs, before the pointer | no: content-addressed by its own hash |
| `<d>/<c>/current` | the pointer (section 4) | last write of an install | yes, atomic replace |
| `<d>/<c>/updater.json` | unchanged from §6.5 | after the pointer | yes, atomic replace |

There is no generation directory, no `meta.json`, no stored `index.bin` and no file named after an attachment. The
derived names of §6.5 (a filename of at most 32 bytes kept, a longer one shortened to 15 characters, `-` and a hash)
stay. They are the file names inside `index.bin` and `GenerationFiles`, computed at load from the records. Two
attachments that map to one name still fail the generation before any body is fetched.

## 3. The generation file

A JSON object in the engine's canonical encoding, read strictly (no unknown member, none twice), as the pointer is
today:

```
{
  "generationVersion": 1,
  "dataset": "CRLITE",
  "channel": "DEFAULT",
  "freshness": "RECORD_LAST_MODIFIED",          // or SEED_SIGNED_TIME for a seed's generation
  "signature": "<hex of the raw r || s pair>",
  "signerLeafSha256": "<hex>",
  "records": { "data": [ … ], "last_modified": "<ts>" }
}
```

- **`records`** is the verified collection payload: the whole collection, every channel's records sorted by id,
  tombstones removed, which is what the signature covers. Its canonical serialisation is exactly today's
  `records.json` and the seed's `records.json`. That works because canonical JSON is deterministic and the
  engine's JSON refuses non-integers (#254), so a round trip gives back the signed bytes. A `_since` changeset is
  merged over it, as over `records.json` today.
- **Derived at load, not stored:** the placed filters and their names (`placeFilters`/`buildIndex` over `records`
  and the channel), each blob's hash (the record's `attachment.hash`), `generationId` (`"<ts>/<last placed record
  id>"`), `sourceTimestampMillis` and the changeset timestamp (`last_modified`), and `format` (the full filter's
  encoding, read from its blob). Today `meta.json` stores each of these beside `records.json`, and §6.5's seed rule
  (b) has to check that the two agree. With nothing stored twice, nothing can disagree.
- **Dropped:** `collection`, which nothing reads; `metaVersion` (now `generationVersion`).
- **Kept for re-verification:** `signature` and `signerLeafSha256`, as today's `meta.json` keeps them. An ordinary
  load does not read them (the store is trusted at the OS level, §6.5). Seed rule (b)'s adopt scan reads them when
  it re-verifies a stored generation (section 6.1).
- **Name:** the SHA-256 of the file's bytes, 64 lowercase hex characters. The same inputs give the same bytes and
  the same name, so writing a generation that is already stored writes nothing new. A re-signed collection with the
  same `<ts>` gives a different file under a different name.
- **Size cap:** the configured `maxJsonBytes` (§4 limits, which can only be raised) plus 64 KiB for the envelope.
  The cap is derived from the configuration, not fixed at `MAX_JSON_BYTES`. It is checked **before the write** as
  well as at every read. A merged `_since` collection can grow past any one served body, and checking at write means
  the install never stores a file its own load-back would refuse. An install over the cap fails before step 3 with
  a store failure and a warning; the outcome and code are the implementation's to pick, under #222's vocabulary. A
  whole collection that large could not be fetched without a cursor either, so refusing it is consistent.
- **Read:** checked against the cap, then re-hashed against its key before it is parsed, so a flipped byte fails
  the read and never becomes a different generation. The JSON allocation budget of §6.5 applies. It is a new decoder
  of bytes from disk, so it gets a Jazzer target (AGENTS.md §12).

## 4. The pointer

`{"live": "<sha256>", "previous": "<sha256>"}`, read strictly as today, with `previous` optional. Each value names a
generation file. `previous` is kept (Q1).

The #245 comment on #229 asked for an integrity check on the pointer, so that a flipped bit in a name reads as
`Malformed` instead of as a valid pointer to the wrong generation. Content-addressed names give that check: a
damaged value either fails the strict parse, or names a key that no stored file hashes to. Such a key is absent, or
its bytes fail the re-hash. A wrong valid generation would need a SHA-256 collision. So the pointer needs no
checksum of its own, and section 7's fail-closed rule handles a pointer that names a generation that does not load.

**The residual: a whole pointer that is valid but stale.** Hash names catch damage inside a name. They cannot catch
a `current` that is intact but old: one restored from a backup, or one whose last write a storage acknowledged and
then lost. Such a pointer names an older stored generation that still loads, so the engine serves older data,
missing the later deltas, until the next install. A checksum on `current` would not catch this either, since the
stale pointer's checksum is valid. The rollback floor bounds it: while a generation is live, the floor is
max(watermark, the live `<ts>`) (§7.1), and `updater.json` keeps the higher watermark unless it is stale too. The
next sync installs anything newer.

`previous` follows today's rule, restated over generation files (#249, #242). It is the first candidate that is
not the new `live` and that loads (section 6): the generation the engine served before the install, then the old
`live`, then the old `previous`. A flip beside a malformed pointer has only the served generation as a candidate.

## 5. Install order

The §6.5 sequence, with the directory steps replaced:

1. **Bodies**, one at a time: for each placed attachment, if `blobs/<hash>` exists and re-hashes, it is reused
   (`REUSED`); otherwise the body is fetched (or read from the seed archive), hashed against its signed record and
   written, and the body is dropped. A stored blob that does not re-hash is rewritten with the verified bytes
   (`REWRITTEN`, `storeFailures++`), as today for full filters. Deltas now get the same rule, so #201's re-hash
   before reuse covers every attachment.
2. **`index.bin`** is built from the records and the blobs (≤ 1 MiB, §3.2), then **the format check** runs.
3. **The generation file** is written to `generations/<H>`. If that key exists and re-hashes, it is not written
   again.
4. **Load it back** exactly as `start()` would (section 6), then `engine.prepare(files)` → `engine.activate` →
   publish the snapshot (`generationEpoch++`).
5. **Flip the pointer**: `current` ← `{live: H, previous: …}`.
6. **Write `updater.json`.**
7. **Prune** (section 7), only after an `INSTALLED` **sync** install whose pointer read `Found` before the install.
   It is skipped after a flip that healed a malformed pointer (#256), and after **every seed load at `start()`**,
   rule (a) or (b), whatever the pointer reads back as afterwards (section 7).

**A failed install deletes nothing.** Its new blobs, and its generation file if step 3 ran, are not named by the
pointer. The next attempt reuses them by name (the same changeset retried under backoff is the usual case), and the
next prune deletes whatever stays unnamed. This replaces today's "on a failed `prepare()` or `activate()` the loader
deletes the directory it was given".

**A flip that failed after activation** leaves the engine serving `H` while the pointer names the old generation.
The retry finds the generation file and every blob already stored, so it is a flip and an `updater.json` write.
The loader remembers the served generation's name `H` beside the snapshot, because a hash name can no longer be
derived from `generationId` and `<ts>` as `liveDirectory()` does today. When the engine already serves `H`, the
retry may skip `prepare`/`activate`; whether it does is an implementation detail of the rewrite.

## 6. Load

One function, used by `start()`'s recovery chain and by step 4 of every install. To load `H`:

1. read `generations/<H>`, check the size cap, re-hash it against `H`, parse it, and check `dataset` and `channel`
   (a channel mismatch is no generation, as today);
2. schema-check `records` for the channel (`CrliteSchema.check`, capped at `MAX_CHANGESET_RECORDS`), then place
   the filters (the install's `placeFilters`);
3. read each placed filter's blob and re-hash it against its record;
4. rebuild `index.bin` with `buildIndex` and build `GenerationFiles` under the derived names.

Any failure is a failed load, counted once (`storeFailures++`). The §6.5 chain at `start()` is unchanged:
`live` → `previous` → seed → nothing. The delta base of a `_since` sync is the live generation's `records`. The delta
parent, derived today from the pointed `meta.json`, comes from the same file.

What a load returns, the `GenerationFiles` handed to `prepare` and the `records` used as a delta base, is always
byte-equal to a generation file and blobs this code wrote from verified data. Step 1's re-hash and step 3's re-hash
are what make that true. Without step 1, a flipped byte inside `records` that still parses (a delta's `channel`
value, say) would make `placeFilters` drop that delta silently, and the engine would serve without its revocations.
Section 14 pins both re-hashes down.

### 6.1 Seed rule (b)'s adopt scan

The maintainer kept the adopt scan (Q2). When the seed load finds no trustworthy pointer, it scans the store for a
complete generation newer than the seed, re-verifies it, and adopts it instead of installing the seed. No
trustworthy pointer means `current` is absent, malformed, or names a `live` that does not load. The rest of rule (b)
stays as §6.5 states it. Under content addressing:

- **A complete generation on disk** is a key under `<d>/<c>/generations/` whose last segment is 64 lowercase hex
  characters and that loads under section 6, steps 1 to 4. That means:
  - the file fits the cap and re-hashes to its name;
  - it parses strictly, with this dataset and channel and a `generationVersion` this binary reads;
  - its `records` pass the schema check and place;
  - every placed filter's blob is present and re-hashes to its record's `attachment.hash`;
  - `buildIndex` succeeds within 1 MiB.

  Today's rule (b) also checks that the index names exactly the placed records, that the timestamps agree with
  `records.json`, and that each file re-hashes to its record. Those checks now hold by construction, because the
  index, the names and the hashes are all derived from `records` at load and nothing stored can disagree with them.
- **It re-verifies** when it is complete and the signature check passes, unchanged from today (`SeedLoader.verifies`):
  when `signerLeafSha256` is the SHA-256 of the seed's verified leaf, `signature` must verify over the canonical
  serialisation of `records` (`ContentSignature.verifyRawPayload`). A generation signed by another leaf is trusted
  at the OS level, as today and as §6.5 trusts every stored generation.
- **The scan:**
  1. List `names()` under `generations/`.
  2. Run section 6's step 1 on each file: cap, re-hash, parse. That reads only the small file, and gives its `<ts>`
     (`records.last_modified`).
  3. The candidates are the files newer than the seed's `<ts>` and not older than the generation the engine serves
     (#235's floor, so an adopt never rolls back what is served).
  4. Order them newest first, with ties broken by name so the choice is deterministic. Two files with one `<ts>` are
     the same collection signed twice.
  5. Run steps 2 to 4 and the signature check from the newest down, and stop at the first that re-verifies.
- **Counting:** each file that fails step 1 counts one store failure (only damage can produce one, since writes are
  atomic), and so does each candidate that then fails to re-verify. A file older than the seed is not counted.
- **Cost:** step 1 reads every generation file, and the full check runs on at most the files that fail before the
  first one that passes. Under I7 the store holds at most `live`, `previous`, one interrupted install's file, and any
  newer file section 7 keeps, so the scan reads about three small files and re-hashes one generation's blobs.
- **Adopt**, as today:
  1. Write `updater.json`: the record read, an absent or malformed one replaced, with its watermark raised to the
     adopted `<ts>`.
  2. Flip `current` to `{live: H}`. As today's `Pointer(adopted, null)`, it names no `previous`.

  Nothing else is written, and nothing is pruned. Writing the watermark first means a failed flip leaves an honest
  failure, and the next load adopts again. Keeping the scan also keeps the floor: B would have lowered the watermark
  to the seed's `<ts>` with a newer verified generation still on disk (S13, S14), and A raises it to that generation.
- **Otherwise**, unchanged: a generation the engine serves that is newer than the seed is kept, and the seed is
  skipped. Failing that, the seed installs through section 5's steps 1 to 6, with no prune.

  Today's three same-name cases (the seed's own directory installed as it stands, completed again with only its
  rotted files re-staged, or completed from the seed) become the ordinary install. The seed's generation file has its
  own name. A stored copy that re-hashes is reused, a rotted blob is rewritten from the verified seed (`REWRITTEN`),
  and a missing one is written.

  One small difference: a stored *sync* generation with the seed's own `<ts>` used to share the seed's directory name
  and could be installed as it stood. It now has a different file, because `freshness` and perhaps the signature
  differ. It is not adopted, since adopting needs a strictly newer `<ts>`. The seed installs its own file and reuses
  every blob, so `DataState.fromSeed` is reported truthfully.

## 7. Prune

Prune keeps every generation file the pointer names and every blob those files name, and deletes every other key
under `generations/` and `blobs/`. `current`, `updater.json` and `store.version` stay. Three rules make it fail closed:

- **It deletes nothing unless it can read what it keeps.** The pointer must read `Found` and read back as the
  install's `live`, and every generation it names must load as far as section 6's step 2: the file re-hashes and
  parses, and its records place. A pointer that is absent or malformed, a named file that is absent or does not
  re-hash, and a `generationVersion` too new for this binary each mean nothing is deleted, with a store failure and
  a warning. A blob that fails its re-hash does not stop prune: the bytes are bad, but the name is still known and
  kept, and the next install rewrites it.
- **It never deletes newer verified data.** A generation file newer than the new `live` that passes section 6's
  steps 1 and 2 is kept with every blob it names. This is today's rule (a) guard ("never prunes past a complete
  directory newer than the seed"), extended to every prune. Such a file exists only when an install was
  interrupted between its generation-file write and its flip and an older generation installed afterwards, which
  the rollback floor allows only with no generation loaded (S13). The next install that passes it makes it garbage.
- **It deletes generation files before blobs**, the reverse of the write order. While deletes stay in order, every
  generation file on disk names only blobs that are on disk too.

**When it runs:** only as the last step of an `INSTALLED` sync install whose pointer read `Found` before the
install (section 5, step 7). That includes the air-gapped refresh, where `sync()` installs a replaced seed (§4). It
never runs:

- **after a heal flip** (#256), since the damaged pointer may have named any generation;
- **after any seed load at `start()`**, rule (a) or (b). The pre-flip read is what decides. Once the seed's flip
  lands, an absent pointer, or a `live` that did not load, reads back as a `Found` pointer naming the seed, so the
  read-back check alone cannot tell a (b) load from a healthy one. This keeps #235's "a (b) load never prunes or
  deletes", which #256 and the 2026-11-15 "an absent pointer deletes nothing" rest on. It also subsumes rule (a)'s
  guard;
- **at `start()`** otherwise either. At start, the only unnamed keys are what an interrupted install left: blobs the
  next sync would reuse, and perhaps a generation file it would reuse too. Pruning them would throw away a fetched
  6 MB full filter just before the sync that needs it.

Neither reference prunes at startup or after a dump import: upki deletes after a successful plan, and Firefox after a
successful timer sync (section 12). Garbage is therefore bounded until the next successful sync install: one
interrupted install's keys, plus the generation a seed load at `start()` replaced.

## 8. Crash consistency

`RevoktStorage.write` replaces a key atomically and is durable before it returns (§3: fsync the file, rename, fsync
the parent). Each step below is one key. A crash at any point, including inside a write, leaves one of these states:

| Crash after | On disk | `start()` loads | Next sync |
|---|---|---|---|
| any blob writes of step 1, or inside one | the old store plus some new blobs; a key inside a write is whole or absent, and the temp file is invisible to `names()` | the old `live`, untouched | the same changeset reuses every blob already written; nothing is fetched twice |
| a `REWRITTEN` blob | that blob's key now holds the bytes its name promises | the old `live`; if it named that blob, the blob is repaired | as above |
| the generation file (step 3), before the flip | the new generation whole but unnamed | the old `live` | the same changeset rebuilds the same bytes and the same name, so it finds the file and flips; a newer one leaves it for the next prune; there is no orphan loop (#205) because a name cannot hold another generation |
| the flip (step 5), before `updater.json` | `current` names the new generation, and every key it needs was durable before the flip | the new generation | `UNCHANGED` against the pointed generation rewrites `updater.json`, the §6.5 repair kept; the floor is max(watermark, the live `<ts>`), so the stale watermark reopens no rollback (§7.1) |
| some of prune's deletes | some unnamed keys gone | the new generation; nothing named was in the delete set | the next prune deletes the rest |

**Why `start()` always finds a whole generation, or falls back to the one before.** Three properties hold together:

1. **Immutable names.** A write to a blob or generation key writes the bytes whose SHA-256 is the key's name. Data
   under a name never changes. The only exception is a rotted blob, which gets its true bytes back.
2. **The pointer is written last, and only to a generation that loaded.** `current` is written after the generation
   file and every blob it names have returned from `write()`, so they are durable, and after this process has loaded
   that generation back (step 4).
3. **Only prune deletes.** It runs only after a sync install whose pointer read `Found` before the flip. It deletes
   only what the pointer, read back after the flip, does not name, never a newer generation that loads, and nothing at
   all when the pointer or a generation it names does not load.

So whenever `current` reads, it names a generation whose file and blobs are all on disk. Only damage (bit rot, or
outside writes to an OS-trusted directory) breaks that, and then the load fails over: `live` → `previous` → seed,
each counted.

**Deletes need no durability.** `RevoktStorage.delete` does not promise to be durable, and with this design it does
not need to. A crash can bring a deleted key back, or keep some of prune's deletes and lose others. A key that comes
back is one the pointer does not name, so it is garbage until the next prune. The worst case is a lost
generation-file delete beside a landed blob delete. That leaves an unnamed generation file whose blobs are missing,
which nothing loads. The adopt scan reads it only when it is newer than the seed, and then it fails at step 3 and
counts one store failure (section 6.1).

**Durability of keys that are reused rather than written.** Property 2 holds for keys this install wrote. A key it
reuses is a different case. `write()` fsyncs the parent directory after the rename. If process A renamed
`generations/H` or a blob into place and was killed before that fsync, process B can find the key, reuse it and flip
`current`. A power loss can then keep `current` and lose the directory entry; whether it does depends on the
filesystem (ext4's shared journal usually keeps it, f2fs need not). The first install has the same gap for the
`blobs/` and `generations/` directories it creates.

`start()` still only falls back (`live` → `previous`), and the floor is unchanged. To make property 2 hold anyway,
`JvmStorage` will:

- fsync every store directory (`<d>/<c>/`, `blobs/`, `generations/`) once, when it opens the store under the lock;
- fsync the parent of every directory it creates.

That belongs in the §3 `JvmStorage` notes, and #287 states it. The model test cannot reach write durability, so #287
covers it with a `JvmStorage`-level test, or at least a review item (section 14).

**Temp files.** A crash inside `JvmStorage.write` leaves a temp file, which `names()` excludes, so prune never sees
it. `JvmStorage` should delete its own temp files when it opens a directory under the lock. That is part of the
`JvmStorage` work, not of this layout.

## 9. The prune/install race

- **Inside one process.** One loader dispatcher, with parallelism one, runs every install, the seed load and prune.
  Prune is the last step of an `INSTALLED` sync install and never runs anywhere else (section 7). So no prune can fall
  between an install's first blob write and its flip, the window in which its blobs and generation file are not
  named yet. A blob found `REUSED` in step 1 cannot disappear before the flip either.
- **What the engine serves.** The engine never reads the store after `prepare`: the filters are decoded into memory,
  and §6.4 says no mmap. So deleting a served generation's keys cannot break serving. The served generation is still
  the first `previous` candidate (#249), so it survives for recovery. A disk-backed `GenerationFiles`, which §4
  allows later, would make prune protect the served generation explicitly. The implementation issue keeps a test
  that fails if that assumption changes.
- **Across processes.** The store lock is taken in `start()` and held to `close()`. With read-only instances
  deferred, only the lock holder reads or writes the store, so no other process can see a prune halfway. An instance
  that cannot take the lock runs in memory and never touches the store (Q3, section 10). If read-only instances come
  back, a reader reads `current`, then a generation file, then its blobs, while the writer may prune in between.
  Today's rule still covers it: a reader that finds a key missing re-reads `current` once. Because `previous` is kept
  (Q1), a reader is safe across one install, which is what upki gets by keeping the old manifest's files
  (section 12).

## 10. The lifecycle modes are deferred

Read-only instances, promotion to writer, and the storage fallback with its retry and migration
([readiness-and-store-modes.md](readiness-and-store-modes.md)) are deferred until a user needs them. Readiness, in the
same note, stays at 0.3. Three entry points lead into those modes today: `lock()` throws `StoreLockedException`;
`STORE_UNREADABLE` (the ownership check, or Android's credential-encrypted directory before the first unlock); and
`STORE_NEWER_LAYOUT` under `NewerLayout.IN_MEMORY`.

**Each entry point now runs the instance on `RevoktStorage.inMemory()` for the life of the process** (the
maintainer's answer to Q3). It logs the warning (`STORE_LOCKED`, `STORE_UNREADABLE` or `STORE_NEWER_LAYOUT`),
releases the lock if it holds it, and deregisters the identity, as §6.5 already does for `STORE_NEWER_LAYOUT`. It
never retries the configured storage, never promotes itself and never migrates. The seed installs in memory, and a
sync fetches in full. `RevoktState.storageFallback` stays true for the process, so the state still says the
instance is not persisting. `NewerLayout.REBUILD` (Android) is unchanged: there, a newer layout is rebuilt, not run
in memory.

**What drops:** `RevoktState.readOnly`, `READONLY_POLL_INTERVAL`, promotion, the storage retry and the per-field
`updater.json` merge on migration, the reader rules (section 9), and `SyncOutcome.STORE_LOCKED` as a recurring
outcome. `STORE_LOCKED` stays as the start warning; whether the `SyncOutcome` value goes or stays growable and unused
is the implementation's call, under #222.

**Residuals of running in memory**, which the README and #287 state:

- nothing persists, so at every start the floor is the seed's: each such process accepts any signed changeset newer
  than its seed, the first-install rollback window on every start;
- every such process fetches in full;
- a permanent `STORE_UNREADABLE` (wrong ownership) degrades to this mode on every start with only a warning;
- a direct-boot instance stays in memory until its process restarts. The README's direct-boot note says so, and
  recommends `AndroidStorage.deviceProtected`.

## 11. Today's layout is dropped, not migrated

Nothing is released. 0.2 runs the store only over `RevoktStorage.inMemory()`; spec §11 lists durability,
`store.version`, crash recovery and the lock under 0.3. `JvmStorage` is not built yet (`main` has no
`object JvmStorage`). So no store in today's layout exists anywhere except in a process's memory and in the tests.
The implementation replaces the layout outright. `store.version` stays `1` and means this layout. No migration code
is written, and the §6.5 rule for a lower or missing version stays for the next layout change. The tests over
today's layout are rewritten, not kept beside the new ones.

## 12. The references, choice by choice

upki is rustls/upki at `9821cce` (v1.0.1, the pin). Firefox is `mozilla-firefox/firefox` at `cac25a6`
(`cac25a6fa321b0051932359b84c4e2fe3caabdc5`), read 2026-11-22: RSC = `services/settings/RemoteSettingsClient.sys.mjs`,
DB = `services/settings/Database.sys.mjs`, ATT = `services/settings/Attachments.sys.mjs`, RSS =
`security/manager/ssl/RemoteSecuritySettings.sys.mjs`, CS = `security/manager/ssl/cert_storage/src/lib.rs`. All
`src`. Firefox's CRLite filters do not go through the Remote Settings attachment cache: RSS downloads them with
`downloadAsBytes` (RSS:613) and hands them to cert_storage. So the CRLite rows compare with cert_storage, and the
attachment cache appears where its rule differs.

| Choice | upki | Firefox | revokt | Fit |
|---|---|---|---|---|
| Attachments stored and reused by hash | One flat directory, files named by filename; each file is re-hashed against the manifest every fetch and skipped on a match (`fetch.rs:202-212`) | cert_storage keeps `crlite.filter` and each delta under its attachment filename in `security_state/` (CS:485-549); RSS re-hashes the file on disk against the record (`isFilterOnDisk`, RSS:559-576) and reads it instead of downloading on a match (RSS:680-725). The attachment cache is keyed by record id (ATT:437-447) | `blobs/<signed sha256>`; reuse is the name matching and the bytes re-hashing | Aligned on behaviour (reuse on a hash match, fetch again on a mismatch); the hash as the name is revokt's own |
| A generation is one unit holding records and signature | `manifest.json`, written by temp file and rename (`fetch.rs:377-390, 429-447`) | Records, timestamp and metadata (the signature) commit in one IndexedDB transaction (DB:105-187) | One generation file | Aligned: one manifest unit per state |
| One atomic switch | The manifest is written last, but filters are replaced under their names before it (`fetch.rs:150-152, 312`), so a crash leaves files of two states; `atomic_write` is a temp file and `persist` with no fsync (`fetch.rs:430-447`), and a body lands under its final name before it is hashed (`fetch.rs:312-320`), so a mismatch leaves a wrong-hash file under a manifest name until the next run | The IndexedDB transaction is atomic; cert_storage is not: it deletes the old filters before writing the new full with `std::fs::write` (CS:494-514) | The pointer write | Stricter than both (DIVERGENCES T1, kept) |
| `index.bin` derived, not stored | Built at fetch (`fetch.rs:337-376`) and read from disk at load (`index.rs:69-80`) | No index: cert_storage loads `crlite.filter` and every `*.delta` it finds (CS:521-534, 1107-1136), each filter carrying its own coverage | Rebuilt at every load by the one `buildIndex` | Like Firefox; unlike upki, which persists it |
| Re-hash at load | None at load | The attachment cache re-hashes on every read (ATT:614-633); cert_storage hashes at load (CS:143-144) but compares only at the next sync | Every blob and the generation file, against their names | Like the attachment cache; stricter than upki and cert_storage |
| What prune keeps | Files the new or the old manifest names; deletes other `*.filter`/`*.delta` after the index and manifest are saved (`fetch.rs:177-232`) | Attachments whose record still exists, after a successful timer sync (RSC:848-860, DB:334-399); cert_storage drops the old filters when a new full installs (CS:494-511) | The pointer's `live` and `previous`, any newer generation that loads, and their blobs, after an `INSTALLED` sync install; never after a seed load or a heal | Close to upki (new plus old); like both on timing (after a successful sync only) |
| Prune at startup | No | No | No (today: yes) | Aligned once dropped |
| A failed install's files | Stay; the next run re-hashes and reuses them | Stay in the attachment cache until prune | Stay until the next prune | Aligned |
| Integrity of the switch | No pointer | No pointer | Hash-named targets; no checksum on `current` | revokt's own (#245's input) |
| Records stored as decoded JSON | (no signed records) | Stored as objects and re-serialised to canonical JSON to verify (RSC:620-638, 1233-1247) | `records` member, re-serialised canonically | Like Firefox; the seed keeps raw bytes because it is verified before it is decoded |
| No trusted local state | No pointer; loads whatever `index.bin` is on disk (`index.rs:69-80`) | Falls back to the packaged dump when local data does not verify, then syncs again (RSC:1292-1300; ATT's `fallbackToDump`); no scan | Seed rule (b): adopt the newest complete, re-verified generation newer than the seed, else the seed (section 6.1) | revokt's own (kept, Q2): it keeps the watermark of the newest verified data where both references fall back to older data |
| Lock against a second process | None; two fetchers on one directory race | (memory) the profile lock refuses a second process on one profile | The second instance runs in memory for the process, with a warning (Q3) | Between the two: it never touches the store, as Firefox's second process does not, but it keeps running |

## 13. Questions and answers

Answered on 2026-11-22. The options and references stay here as the record.

**Q1. Keep `previous` in the pointer?** **Answer (lead): keep it, as #249 decided.**
- **A, keep it** (the current spec, and #249 as decided). It costs one small generation file plus the deltas the
  two generations do not share. It gives a recovery generation fresher than the seed and a one-install window for a
  future read-only reader, and it keeps `qualifies` and the served-first candidate rule.
- **B, drop it.** The pointer names `live` only. Recovery is `live` → seed, and prune keeps one generation.
- **References:**
  - **upki** keeps the previous manifest's files for one more fetch (`fetch.rs:214-218`), for readers in flight, but
    never loads them.
  - **Firefox** keeps nothing on disk: cert_storage deletes the old filters (CS:494-511), and the Remote Settings
    client restores the previous records from memory only when new data fails to verify (RSC:1271-1283).
- **Where the answer lands:** section 4 (the candidate rule), 7 (what prune keeps) and 9 (the reader window).

**Q2. Keep §6.5 seed-load rule (b)'s adopt scan?** **Answer (maintainer): keep it.** Section 6.1 designs it under
content addressing: what "complete" means, how the scan re-verifies a candidate, its order, counting, cost and adopt.
- **A, keep it**, scanning `generations/*`.
- **B, drop it.** The seed installs, the flip heals the pointer, and the next sync reinstalls the newest data from
  the blobs still on disk.
- **References:**
  - **upki** has no pointer and loads whatever `index.bin` is there.
  - **Firefox** falls back to the packaged dump when local data does not verify, then syncs again (RSC:1292-1300;
    ATT's `fallbackToDump`). Neither scans.
- **What A buys over B:** keeping the scan avoids the rollback window the review found in B (r289's Q2-B risk):
  - The floor: with a lost or malformed pointer, B installs the seed with nothing loaded. S13 and S14 then lower the
    watermark to the seed's `<ts>` while a newer verified generation is still on disk, and a network attacker can
    replay any Mozilla-signed changeset between the two. For a bundled seed that gap can be weeks. Firefox has the
    same exposure after a dump import; A raises the watermark to the adopted generation instead.
  - An instance that is offline at that start serves the newer stored data.
- **The no-prune rule:** a (b) load never prunes whatever the answer (section 7). The reviewer's B1 showed that the
  no-prune rule does not depend on the scan.

**Q3. With the lifecycle modes deferred, what does an instance do when it cannot use the store?**
**Answer (maintainer): run in memory for the process, with the warning and no retry** (section 10).
- **A, `start()` throws.**
- **B, run on `RevoktStorage.inMemory()` for the life of the process**, with the warning (chosen).
- **C, keep read-only instances.** That contradicts the accepted deferral.
- **References:**
  - **Firefox** refuses a second process on a locked profile (memory, not checked in source).
  - **upki** takes no lock, so two fetchers on one directory race.
- **Why B:** TLS keeps working with seed data, and the instance never touches the store, so there is no
  cross-process race. `STORE_NEWER_LAYOUT` under `IN_MEMORY` already behaves this way ("never retried", §6.5).
- **Accepted costs** (r289's Q3-B risks, accepted with the answer): every in-memory process floors at its seed's
  watermark, so the first-install rollback window opens on every start, and every in-memory process fetches in
  full. Section 10 lists these with the other residuals: a permanent `STORE_UNREADABLE` that only warns, and
  direct boot.

## 14. The fault-injection test (#214) over the rewrite

The model test (`StoreModel`, `StoreModelTest`, `StoreModelFuzzTest`, from #245) is the rewrite's safety net. Most of
its harness does not depend on the layout and stays: `Choices`, the counting storage with an n-th-operation throw and
stop, the scripted server, restarts, the trail. The layout-aware parts are rewritten in the same PR as the store,
and the model must pass at its default seed budget before review.

- **Invariants, restated:**
  - **I1:** what the pointer names as `live` or `previous`, and the generation the snapshot holds live, loads under
    section 6 unless damage hit it. Damage is forgotten once the code rewrites or deletes the damaged key.
  - **I2:** no generation file the pointer names, and no blob such a file names, is deleted, or overwritten with
    other bytes. Beside a pointer that does not read, or that names a generation that does not load, nothing under
    `generations/` or `blobs/` is deleted at all. A seed load at `start()` and a heal flip delete nothing either.
    The generation the engine held when a sync began survives that sync, as `live` or `previous` when the sync's
    flip landed (#242, #249).

    "Pointed to" is the last pointer the code wrote. **Today's exception for damage that leaves `current` readable
    (#246, `StoreModel.kt:70-75`: "a checksum would close it, #229") is dropped.** Under hash names, a damaged but
    readable `current` names an absent key, so keeping the exception would hide exactly the regression #245 asked
    about.
  - **I3** (`updater.json` only from a read that returned, #209; the watermark never backwards) and **I5** (the
    rollback floor) are unchanged.
  - **I4** (recovery within `RECOVERY` clean syncs) is unchanged. It gains a check: once faults stop, a sync over a
    store that still holds every blob fetches no attachment.
- **New invariants:**
  - **I6, immutable names:** every write to a key under `blobs/` or `generations/` writes bytes whose SHA-256 is the
    key's name.
  - **I7, bounded garbage:** after an `INSTALLED` sync that pruned, the store holds exactly `store.version`,
    `current`, `updater.json`, the generation files the pointer names, any newer generation that loads (section 7),
    and their blobs.
  - **I8, delete order:** a generation file on disk names only blobs on disk, unless damage or a lost delete hit
    them.
  - **I9, load fidelity:** whatever a load returns (the `GenerationFiles` handed to `prepare`, the delta base, and
    the generation a seed load adopts) is byte-equal to a generation file and blobs this code wrote from verified
    data. The model checks this against its own record of every write. Damaged bytes must make the load fail, never
    yield something else.
  - **I10, adopt:** a seed load beside a lost or malformed pointer adopts the newest stored generation newer than
    the seed, when one re-verifies. It never adopts one that is damaged, not newer than the seed, or older than the
    served generation, and it fetches no attachment.
- **Damage generators:**
  - a flipped byte or a truncation in a generation file;
  - a flip inside `records` that keeps the file parseable (a delta's `channel` value, B2's case), which only the
    re-hash catches;
  - a flipped hex digit in the pointer's `live` or `previous`, which names an absent key;
  - damage to a blob that `live` and `previous` share;
  - a deleted `current`;
  - a `generationVersion` too new.

  Today's `meta.json` and directory generators go.
- **Lost deletes:** the stop gains a variant that drops an arbitrary subset of a stopped sync's deletes, not only
  every delete after the stop, which is a prefix. It exercises section 8's worst case (a lost generation-file delete
  beside a landed blob delete) and I8's "lost delete" clause. Lost *write* durability (section 8) is out of the
  model's reach. #287 covers it with a `JvmStorage` test, or at least a review item.
- **Fault range:** the drawn operation range ("22 to 71 measured" today) is measured again, since an install now
  does far fewer writes.
- **Mutants the test must kill within its default budget**, shown in the PR's Tests section as working-method
  mutation and aimed again by the reviewer:
  - prune with an absent or malformed pointer;
  - prune when a named generation file does not load;
  - prune after a seed load at `start()`, rule (a) or (b) (B1);
  - prune of a newer generation file that loads;
  - prune that keeps only `live`'s blobs while `previous` is kept;
  - the flip moved before the generation-file write;
  - a load without the generation-file re-hash (I9; B2);
  - a load without the blob re-hash (I9);
  - a blob reused without its re-hash;
  - an adopt without the signature check when the leaf is the seed's;
  - an adopt of a candidate not newer than the seed;
  - a prune at the start of an install;
  - blobs deleted before generation files;
  - #209 reintroduced.

  #205's orphan loop and #207's fail-open bootstrap no longer have a code path that could reintroduce them. The test
  keeps their scenarios: an orphan generation served again, and damage beside a malformed pointer.

## 15. What the implementation changes

- **Spec:**
  - §6.5: the layout bullets, the install order, prune and when it runs, crash recovery, the rules beside a
    malformed pointer (they shrink to "prune deletes nothing"), the seed-load rule (rule (b) restated as section
    6.1, no prune after any seed load at `start()`), and the generation file's cap derived from `maxJsonBytes`;
  - §3: the `RevoktStorage` and `JvmStorage` notes. A lock collision and an unreadable store run in memory for the
    process (Q3); `JvmStorage` fsyncs every store directory at open and the parent of each directory it creates
    (section 8); temp files are swept at open;
  - §4: `RevoktState.readOnly` and `storageFallback`, `STORE_LOCKED`, and `resetState`'s read-only clause;
  - §5.1's references to the modes;
  - the `test-plan.md` rows for the store and seed tests;
  - `docs/spec/changes/<n>.md` for the implementation issue.
- **Decisions this supersedes or moots** (DECISIONS.md gets one entry when the implementation lands):
  - moot:
    - #200, the same-`<ts>` re-sign reuse: a re-signed generation is a new file;
    - #205, an orphan completed afresh, and its rounds 3 and 4 (`reopen` fails closed): there is nothing to reopen;
    - #236 and #242, held directories beside a malformed pointer: nothing is rewritten, and prune deletes nothing;
  - widened: #201, re-hash a stored delta before reuse, now covers every blob;
  - kept and restated: #235 and its follow-ups (the adopt rule, Q2: section 6.1; "a (b) load never prunes or
    deletes", now every seed load at `start()`);
  - kept: #249 (served first, Q1), #256 (no prune after a heal flip), #209 and #224 (unchanged);
  - per Q3: the read-only and storage-fallback parts of `readiness-and-store-modes.md` are deferred.
  - DIVERGENCES T1 is restated (blobs, a generation file and a pointer), and T2 shrinks.
- **Code:**
  - `engine/store/`: `StoreLayout` is rewritten around `blob`/`putBlob`, `writeGeneration`, `load`, `pointer`/`point`,
    `updater` and `prune`; `GenerationMeta`/`MetaJson` give way to the generation file's codec, with a Jazzer target;
    `GenerationNames.directory` and `isDirectory` go, and `derive` stays;
  - `update/Install.kt`: `claim`, `directory`, `sameGeneration`, `reopen` and the failure-path delete go, and the
    loader keeps the served generation's `H`;
  - `update/CrliteSync.kt`: the `Bodies` staging goes, and the delta base comes from the generation file;
  - `seed/SeedLoader.kt`: the adopt scan over `generations/*` (section 6.1); `verifies` keeps only the signature
    check beyond the load; the same-name reopen and re-stage paths go; no prune after a seed load;
  - the start path: the three entry points run on `inMemory()` with the warning and no retry (section 10);
  - a `@RevoktTestingApi` test helper writes `GenerationFiles` to a directory, the inverse of
    `JvmGenerationFiles.fromDirectory`, for the upki engine and the corpus tests.

## 16. Costs to measure in the implementation

- **Load decodes every filter twice:** `buildIndex` decodes each placed filter to read its coverage, then `prepare`
  decodes it again. Today a stored generation's load decodes once (it reads the stored `index.bin`). The
  implementation PR measures `start()` against §6.4's load columns and reports the numbers. If it is over, two
  fallbacks exist: a coverage-only clubcard read, which is a new decoder in the MPL port and needs its own fuzz
  target; or storing `index.bin` as a blob that the generation file names, as upki persists it. Either is a
  follow-up, not part of this design.
- **More hashing at load:** today only the full filter's blob is re-hashed at load (`readGeneration`). Now every
  delta is too, which is about 12.6 MB more on `default` at 52 deltas (§6.4's measured column less the 6 MB full).
- **Fewer writes per install:** a daily delta install writes its new deltas, one generation file and the pointer.
  Today it writes every delta again, plus `index.bin`, `records.json` and `meta.json`, each fsynced.
