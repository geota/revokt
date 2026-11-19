<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Readiness, read-only mode and the storage fallback

Not normative. Moved out of the spec's §5.1 at revision 59 (#216), as it stood at revision 58; milestone: 0.3. A note is promoted into the spec when its milestone starts, and edited there.

**Readiness.** One future per `Revokt`, `dataReady`, **completed normally by the loader scheduler
at `dataDeadline = flipToStarted + awaitData` if still pending** (monotonic `TimeSource`; no `orTimeout`,
which is API 31+) and never completed exceptionally. It is internal to the handshake path; the
public `awaitReady()`/`readyFuture()` wait for `RevoktState.ready` with no deadline. Waiting
overloads wait for it only under `needsData` (flow step 0); step 0 does not run under `OFF`;
`OBSERVE` waits exactly as `ENFORCE` does. There is no snapshot future: the anchor snapshot is built
before a trust manager can go past step 1 ("Anchor snapshot" below). The loader's deadline-completion task
runs on the single-parallelism loader dispatcher, which performs only verify, decode, install and
anchor rebuilds; fetches run on `ioDispatcher`, buffered under the per-kind caps, and hand the body
to the loader, so a slow download never delays the deadline; the `get(timeout)` bound still covers
an in-flight install. `InterruptedException` restores the flag and throws
`CertificateException("interrupted")` with no verdict.

**Read-only mode.** A read-only instance **never writes to the store**: no blob, directory, pointer,
`updater.json`, prune or `store.version` write. Its seed and system cache, when the seed-vs-stored
rule selects them, are installed into the engine and published **in memory only**
(`DataState.fromSeed`, `installed` report them). Every `READONLY_POLL_INTERVAL` and on each `sync()`
the loader re-reads the pointer, re-applies the seed-vs-stored and class rules against the pointed
generation (a lower-class or older pointed generation never displaces the in-memory seed), reloads
when the pointer changed, and retries `storage.lock()` (its bounded ≤ 1 s try); on success it **promotes
itself to writer** (`readOnly = false`) and re-runs the loader start task as owner: the seed-vs-stored
rule is applied again with writes enabled, so an in-memory seed newer than the pointed generation is
now written and pointed, then a sync is scheduled. Until
then `sync()` returns `SyncOutcome.STORE_LOCKED` and `resetState()` throws `IllegalStateException`.

**Storage fallback** (`RevoktState.storageFallback`, `STORE_UNREADABLE` from an ownership failure or a
credential-encrypted directory before the first unlock, or `STORE_NEWER_LAYOUT` under
`NewerLayout.IN_MEMORY`): the instance runs on `inMemory()`, releases the store lock and deregisters
the identity; on every `READONLY_POLL_INTERVAL` tick and on each `sync()` the loader retries the
configured storage (the same bounded checks `start()` ran; never for `STORE_NEWER_LAYOUT`, which cannot
become readable); when it succeeds the loader registers (a registry collision, another instance now owning the
directory, keeps the fallback, logged at `WARN`; a fallback instance keeps syncing in memory, it does not
defer to the owner), locks (`StoreLockedException` → the instance becomes
**read-only** over that directory instead: `readOnly = true`, `storageFallback = false`, the in-memory
generation stays published until the pointed generation displaces it under the read-only rules, and
`sync()` returns `STORE_LOCKED` from then on), runs the owner start task against it with the in-memory
generation as one more candidate under the ordinary rules (it displaces a stored generation only when
its trust class is not lower and it is newer, exactly as a seed would; a `MIRROR` never displaces a
stored `SIGNED`), merges `updater.json` per field (watermark = max; cursor and
`lastVerified*` from the generation that ends up installed; `backoffUntilMillis` = max; `consecutiveFailures`
and per-source `lastAttemptAtMillis` from the newer record; `seedInstalledAtMillis` from whichever seed
install is live; `datasetLastAttemptAtMillis` = max, so an in-memory attempt that opened the `STALE` gate
is never undone by an older disk record) and clears `storageFallback` and the `STORE_UNREADABLE` warning
that caused it (a `STORE_NEWER_LAYOUT` fallback is never retried, so that warning stays), so a direct-boot process
migrates to disk after unlock instead of staying in memory for its lifetime.
