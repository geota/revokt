<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The content-addressed store

Not normative; milestone 0.3. The design for #229, from the 2026-11-16 design audit (B-F8, accepted by the maintainer
that day), written against spec revision 61 and `main` at `08cf785`. Until the implementation issue edits §6.5, the
spec wins. Questions waiting for the lead are marked **Q1** to **Q3** (section 13); the text says where each answer
changes it.

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
- **Kept for re-verification:** `signature` and `signerLeafSha256`, as today's `meta.json` keeps them. Nothing reads
  them at load (the store is trusted at the OS level, §6.5). Seed rule (b) reads them when it re-verifies a stored
  generation; if Q2 drops the adopt scan, nothing reads them, and they stay as the signature the issue asks the
  generation to hold.
- **Name:** the SHA-256 of the file's bytes, 64 lowercase hex characters. The same inputs give the same bytes and
  the same name, so writing a generation that is already stored writes nothing new. A re-signed collection with the
  same `<ts>` gives a different file under a different name.
- **Read:** capped at `MAX_JSON_BYTES` + 64 KiB before it is parsed (it holds one `records` payload and a small
  envelope), and re-hashed against its key before it is parsed, so a flipped byte fails the read and never becomes
  a different generation. The JSON allocation budget of §6.5 applies. It is a new decoder of bytes from disk, so it
  gets a Jazzer target (AGENTS.md §12).

## 4. The pointer

`{"live": "<sha256>", "previous": "<sha256>"}`, read strictly as today, with `previous` optional. Each value names a
generation file. (If Q1 drops `previous`, the pointer is `{"live": "<sha256>"}`.)

The #245 comment on #229 asked for an integrity check on the pointer, so that a flipped bit in a name reads as
`Malformed` instead of as a valid pointer to the wrong generation. Content-addressed names give that check: a
damaged value either fails the strict parse, or names a key that no stored file hashes to. Such a key is absent, or
its bytes fail the re-hash. A wrong valid generation would need a SHA-256 collision. So the pointer needs no
checksum of its own, and section 7's fail-closed rule handles a pointer that names a generation that does not load.

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
7. **Prune** (section 7), after every `INSTALLED` install except one whose flip healed a malformed pointer (#256).

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
2. place the filters from `records` and the channel (the install's `placeFilters`);
3. read each placed filter's blob and re-hash it against its record;
4. rebuild `index.bin` with `buildIndex` and build `GenerationFiles` under the derived names.

Any failure is a failed load, counted once (`storeFailures++`). The §6.5 chain at `start()` is unchanged:
`live` → `previous` → seed → nothing. The delta base of a `_since` sync is the live generation's `records`. The delta
parent, derived today from the pointed `meta.json`, comes from the same file.

## 7. Prune

Prune keeps every generation file the pointer names and every blob those files name, and deletes every other key
under `generations/` and `blobs/`. `current`, `updater.json` and `store.version` stay. Two rules make it fail closed:

- **It deletes nothing unless it can read what it keeps.** The pointer must read `Found` and read back as the
  install's `live`, and every generation it names must load as far as section 6's step 2: the file re-hashes and
  parses, and its records place. A pointer that is absent or malformed, a named file that is absent or does not
  re-hash, and a `generationVersion` too new for this binary each mean nothing is deleted, with a store failure and
  a warning. A blob that fails its re-hash does not stop prune: the bytes are bad, but the name is still known and
  kept, and the next install rewrites it.
- **It deletes generation files before blobs**, the reverse of the write order. While deletes stay in order, every
  generation file on disk names only blobs that are on disk too.

**When it runs:** only as the last step of an `INSTALLED` install (section 5, step 7). It no longer runs at `start()`.
At start, the only unnamed keys are what an interrupted install left: blobs that the next sync would reuse, and
perhaps a generation file it would reuse too. Pruning them at start would throw away a fetched 6 MB full filter just
before the sync that needs it. Neither reference prunes at startup: upki deletes after a successful plan, and Firefox
after a successful sync (section 12). Garbage is therefore bounded by one interrupted install's blobs until the next
successful install.

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
3. **Only prune deletes**, only what the pointer, read back after the flip, does not name, and nothing at all when
   the pointer or a generation it names does not load.

So whenever `current` reads, it names a generation whose file and blobs are all on disk. Only damage (bit rot, or
outside writes to an OS-trusted directory) breaks that, and then the load fails over: `live` → `previous` → seed,
each counted.

**Deletes need no durability.** `RevoktStorage.delete` does not promise to be durable, and with this design it does
not need to. A crash can bring a deleted key back, or keep some of prune's deletes and lose others. A key that comes
back is one the pointer does not name, so it is garbage until the next prune. The worst case is a lost
generation-file delete beside a landed blob delete. That leaves an unnamed generation file whose blobs are missing,
which nothing loads; only Q2's adopt scan would read it, and the scan re-hashes every blob anyway.

**Temp files.** A crash inside `JvmStorage.write` leaves a temp file, which `names()` excludes, so prune never sees
it. `JvmStorage` should delete its own temp files when it opens a directory under the lock. That is part of the
`JvmStorage` work, not of this layout.

## 9. The prune/install race

- **Inside one process.** One loader dispatcher, with parallelism one, runs every install, the seed load and prune.
  Prune is the last step of an `INSTALLED` install and never runs anywhere else (section 7). So no prune can fall
  between an install's first blob write and its flip, the window in which its blobs and generation file are not
  named yet. A blob found `REUSED` in step 1 cannot disappear before the flip either.
- **What the engine serves.** The engine never reads the store after `prepare`: the filters are decoded into memory,
  and §6.4 says no mmap. So deleting a served generation's keys cannot break serving. The served generation is still
  the first `previous` candidate (#249), so it survives for recovery. A disk-backed `GenerationFiles`, which §4
  allows later, would make prune protect the served generation explicitly. The implementation issue keeps a test
  that fails if that assumption changes.
- **Across processes.** The store lock is taken in `start()` and held to `close()`. With read-only instances
  deferred, only the lock holder reads or writes the store, so no other process can see a prune halfway. Q3 settles
  what an instance that cannot take the lock does instead. If read-only instances come back, a reader reads
  `current`, then a generation file, then its blobs, while the writer may prune in between. Today's rule still
  covers it: a reader that finds a key missing re-reads `current` once. With `previous` kept (Q1), a reader is safe
  across one install, which is what upki gets by keeping the old manifest's files (section 12).

## 10. The lifecycle modes are deferred

Read-only instances, promotion to writer, and the storage fallback with its retry and migration
([readiness-and-store-modes.md](readiness-and-store-modes.md)) are deferred until a user needs them. Readiness, in the
same note, stays at 0.3. Three entry points lead into those modes today: `lock()` throws `StoreLockedException`;
`STORE_UNREADABLE` (the ownership check, or Android's credential-encrypted directory before the first unlock); and
`STORE_NEWER_LAYOUT` under `NewerLayout.IN_MEMORY`. Q3 asks what each does once the modes are gone. What drops with
them: `RevoktState.readOnly`, `READONLY_POLL_INTERVAL`, promotion, `SyncOutcome.STORE_LOCKED` as a recurring outcome,
the per-field `updater.json` merge on migration, and the reader rules (section 9).

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
| One atomic switch | The manifest is written last, but filters are overwritten in place by name before it (`fetch.rs:150-152, 312`), so a crash leaves files of two states | The IndexedDB transaction is atomic; cert_storage is not: it deletes the old filters before writing the new full with `std::fs::write` (CS:494-514) | The pointer write | Stricter than both (DIVERGENCES T1, kept) |
| `index.bin` derived, not stored | Built at fetch (`fetch.rs:337-376`) and read from disk at load (`index.rs:69-80`) | No index: cert_storage loads `crlite.filter` and every `*.delta` it finds (CS:521-534, 1107-1136), each filter carrying its own coverage | Rebuilt at every load by the one `buildIndex` | Like Firefox; unlike upki, which persists it |
| Re-hash at load | None at load | The attachment cache re-hashes on every read (ATT:614-633); cert_storage hashes at load (CS:143-144) but compares only at the next sync | Every blob and the generation file, against their names | Like the attachment cache; stricter than upki and cert_storage |
| What prune keeps | Files the new or the old manifest names; deletes other `*.filter`/`*.delta` after the index and manifest are saved (`fetch.rs:177-232`) | Attachments whose record still exists, after a successful timer sync (RSC:848-860, DB:334-399); cert_storage drops the old filters when a new full installs (CS:494-511) | The pointer's `live` and `previous` and their blobs, after an `INSTALLED` install | Close to upki (new plus old); like both on timing (after success only) |
| Prune at startup | No | No | No (today: yes) | Aligned once dropped |
| A failed install's files | Stay; the next run re-hashes and reuses them | Stay in the attachment cache until prune | Stay until the next prune | Aligned |
| Integrity of the switch | No pointer | No pointer | Hash-named targets; no checksum on `current` | revokt's own (#245's input) |
| Records stored as decoded JSON | (no signed records) | Stored as objects and re-serialised to canonical JSON to verify (RSC:620-638, 1233-1247) | `records` member, re-serialised canonically | Like Firefox; the seed keeps raw bytes because it is verified before it is decoded |
| Lock against a second process | None | (memory) the profile lock refuses a second process on one profile | Q3 | Q3 |

## 13. Questions for the lead

**Q1. Keep `previous` in the pointer?**
- **A, keep it** (the current spec, and #249 as decided). It costs one small generation file plus the deltas the
  two generations do not share. It gives a recovery generation fresher than the seed, a one-install window for a
  future read-only reader, and keeps `qualifies` and the served-first candidate rule.
- **B, drop it.** The pointer names `live` only. Recovery is `live` → seed, and prune keeps one generation. The
  candidate rule, `qualifies`, and #249's case go away.
- **upki** keeps the previous manifest's files for one more fetch (`fetch.rs:214-218`), for readers in flight, but
  never loads them. **Firefox** keeps nothing on disk: cert_storage deletes the old filters (CS:494-511), and the
  Remote Settings client restores the previous records from memory only when new data fails to verify
  (RSC:1271-1283).
- **Recommendation: A.** Under content addressing it is almost free, it matches upki's retention, and the decided
  rules stay.

**Q2. Keep §6.5 seed-load rule (b)'s adopt scan?** Today, with no trustworthy pointer (absent, malformed, or a
`live` that does not load), the seed load scans complete directories newer than the seed, re-verifies them, and
adopts the newest by flipping the pointer to it (#235, the 2026-11-19 third review).
- **A, keep it**, scanning `generations/*`: each a small file, parsed, its blobs re-hashed, and its signature
  checked when its leaf is the seed's.
- **B, drop it.** The seed installs (or the generation the engine serves is kept, as today), the flip heals the
  pointer, and nothing is pruned in that load. The next sync installs the newest data and fetches only the
  changeset, because every blob is still on disk and is reused by name.
- **upki** has no pointer and loads whatever `index.bin` is there. **Firefox** falls back to the packaged dump when
  local data does not verify, then syncs again (RSC:1292-1300; ATT's `fallbackToDump`). Neither scans.
- **What B costs:** an instance that is offline at that start serves the seed instead of a newer stored generation
  until a sync succeeds. It does not cost a download.
- **Recommendation: B.** It matches both references, removes the scan, the adopt re-verification and the same-name
  rewrite rules, and content addressing makes the re-sync cheap. If B, `signerLeafSha256` and `signature` have no
  reader at load (section 3).

**Q3. With the lifecycle modes deferred, what does an instance do when it cannot use the store?** This covers the
three entry points of section 10: `StoreLockedException`, `STORE_UNREADABLE`, and `STORE_NEWER_LAYOUT` under
`IN_MEMORY`.
- **A, `start()` throws** (`StoreLockedException`, or the diagnostic as an `S` `ERROR`).
- **B, run on `RevoktStorage.inMemory()` for the life of the process**, with the warning (`STORE_LOCKED`,
  `STORE_UNREADABLE` or `STORE_NEWER_LAYOUT`). No retry, no promotion and no migration; the seed installs in memory,
  and a sync fetches in full.
- **C, keep read-only instances.** That contradicts the accepted deferral, so it is listed only for completeness.
- **Firefox** refuses a second process on a locked profile (memory, not checked in source). **upki** takes no lock,
  so two fetchers on one directory race.
- **Recommendation: B.** TLS keeps working with seed data, and the instance never touches the store, so there is no
  cross-process race. It is the deferred fallback without its retry and migration, and `STORE_NEWER_LAYOUT` under
  `IN_MEMORY` already behaves this way ("never retried", §6.5). A would make an Android app's second process (a
  `:remote` service, say) or a parallel JVM test fail `start()`. A direct-boot instance under B stays in memory until
  the process restarts, which the README documents. `SyncOutcome.STORE_LOCKED` then has no use and can go, or stay
  growable and unused; that is the implementation's call, under #222's single failure vocabulary.

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
    `generations/` or `blobs/` is deleted at all. The generation the engine held when a sync began survives that
    sync, as `live` or `previous` when the sync's flip landed (#242, #249).
  - **I3** (`updater.json` only from a read that returned, #209; the watermark never backwards) and **I5** (the
    rollback floor) are unchanged.
  - **I4** (recovery within `RECOVERY` clean syncs) is unchanged. It gains a check: once faults stop, a sync over a
    store that still holds every blob fetches no attachment.
- **New invariants:**
  - **I6, immutable names:** every write to a key under `blobs/` or `generations/` writes bytes whose SHA-256 is the
    key's name.
  - **I7, bounded garbage:** after an `INSTALLED` sync that pruned, the store holds exactly `store.version`,
    `current`, `updater.json`, the generation files the pointer names and their blobs.
  - **I8, delete order:** a generation file on disk names only blobs on disk, unless damage or a lost delete hit
    them.
- **Damage generators:** a flipped byte or a truncation in a generation file (the re-hash must catch it); a flipped
  hex digit in the pointer's `live` or `previous` (it names an absent key); damage to a blob that `live` and
  `previous` share; a deleted `current`; a `generationVersion` too new. Today's `meta.json` and directory generators
  go.
- **Fault range:** the drawn operation range ("22 to 71 measured" today) is measured again, since an install now
  does far fewer writes.
- **Mutants the test must kill within its default budget**, shown in the PR's Tests section as working-method
  mutation and aimed again by the reviewer:
  - prune with an absent or malformed pointer;
  - prune when a named generation file does not load;
  - prune that keeps only `live`'s blobs while `previous` is kept;
  - the flip moved before the generation-file write;
  - a blob reused without its re-hash;
  - a prune at the start of an install;
  - blobs deleted before generation files;
  - #209 reintroduced.

  #205's orphan loop and #207's fail-open bootstrap no longer have a code path that could reintroduce them. The test
  keeps their scenarios: an orphan generation served again, and damage beside a malformed pointer.

## 15. What the implementation changes

- **Spec:**
  - §6.5: the layout bullets, the install order, prune and when it runs, crash recovery, the rules beside a
    malformed pointer (they shrink to "prune deletes nothing"), and the seed-load rule (per Q2);
  - §3: the `RevoktStorage` and `JvmStorage` notes on read-only instances and the lock (per Q3);
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
  - per Q2: #235 and its follow-ups (the adopt rule);
  - kept: #249 (served first, per Q1), #256 (no prune after a heal flip), #209 and #224 (unchanged).
  - DIVERGENCES T1 is restated (blobs, a generation file and a pointer), and T2 shrinks.
- **Code:**
  - `engine/store/`: `StoreLayout` is rewritten around `blob`/`putBlob`, `writeGeneration`, `load`, `pointer`/`point`,
    `updater` and `prune`; `GenerationMeta`/`MetaJson` give way to the generation file's codec, with a Jazzer target;
    `GenerationNames.directory` and `isDirectory` go, and `derive` stays;
  - `update/Install.kt`: `claim`, `directory`, `sameGeneration`, `reopen` and the failure-path delete go, and the
    loader keeps the served generation's `H`;
  - `update/CrliteSync.kt`: the `Bodies` staging goes, and the delta base comes from the generation file;
  - `seed/SeedLoader.kt`: per Q2;
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
