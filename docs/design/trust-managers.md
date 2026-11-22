<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Trust managers per delegate and their caches

Not normative. Moved out of the spec's §5.1 at revision 59 (#216), as it stood at revision 58; milestone: 0.3. A note is promoted into the spec when its milestone starts, and edited there.

**Trust managers per delegate.** Creation, lookup and the cap check run under **one lock** (this path
runs once per client build): drain the `ReferenceQueue`, purge entries whose trust-manager reference
has cleared, count live referents, and either return the existing instance (matched by `===` on the
delegate) or create one, evicting every entry whose `WeakReference.get()` is null, and throwing `IllegalStateException("<n>
live trust managers; close clients or reuse delegates")` only when live referents still reach
`maxTrustManagers`. In `STARTED` the anchor snapshot is built **inside this lock**, before
the instance is registered against the cap and the `ReferenceQueue`: a concurrent `trustManager(d)`
for the same delegate waits on the lock and then returns the built instance or, after a failed
build, retries the build itself (failures are not memoised); a failed build registers nothing,
consumes no cap slot and leaves no `sslContext` memo entry; a `trustManager(d)` or `sslContext(d)`
that arrives while `start()` holds the lock blocks for `start()`'s lock-held part (the
pre-start builds, bounded by `maxTrustManagers + 1` index builds and on an Android cold process
the NSC directory read, tens to hundreds of ms, plus the store lock's bounded ≤ 1 s try and the
pointer, `meta.json` and seed-header reads; the sole-seed synchronous decode runs with the lock
released, lifecycle paragraph), so a consumer that wires on the main thread creates its trust managers before
`start()` or wires after `start()` returned; `RevoktState` updates and listener dispatch
happen after the lock is released; the delegate's `getAcceptedIssuers()` runs under the lock and
must not call back into `Revokt`: the factory lock is not reentrant for `trustManager(d)`, a call
from the thread holding it throws `IllegalStateException("re-entrant trustManager() from a delegate")`. `start()` runs its whole synchronous part and flips the lifecycle
to `STARTED` under this same lock, `close()` flips to `CLOSED` under it, and `trustManager(d)` reads
the lifecycle under it, so every instance is built by exactly one of `start()`, the post-gap builds for
trust managers created during the sole-seed decode, wiring, the fetcher snapshot's per-sync retry on the
loader (which takes this lock), and none falls between (the JVM join of the loader task runs after the lock is released). The `ReferenceQueue` is registered on the **trust-manager** reference
(the trust manager holds its delegate strongly, so the delegate reference can never clear first).
Loader and refresh tasks hold a `WeakReference` to the trust manager, `get()` it each tick and reach
the delegate through it. `sslContext(delegate, keyManagers)` is memoised by bucket on identity hashes
but matched by `delegate === e.delegate && km.size == e.km.size && km.indices.all { km[i] === e.km[i] }`;
`null` and empty arrays are distinct keys; **contexts are held through `WeakReference`** (an
`SSLContext` strongly holds its trust managers, so a strong memo would pin every instance; the
client's own context keeps it alive); the `ReferenceQueue` is drained on every factory call and on
every loader and refresh tick (on those ticks under a `tryLock` that skips when contended, so the
loader never blocks on the factory lock); all contexts are dropped on `close()`.

- **Caches**, per trust manager, LRU-bounded (a synchronized access-ordered `LinkedHashMap` or a
  striped LRU; touched from concurrent handshake threads): the path cache holds `Found`, `NotFound`,
  `Budget` and the fallback result alike. **A path-cache entry is exactly**: `status`, `source`,
  `noIssuerReason`, `walkerReason`, `parseReason`, `keyabilityClause`, `terminalKind`,
  `usedFallback`, the step-6 `FallbackReason` (null when no `FallbackNotUsed` was reported; revision 50), `pathsFound`, the reported path as (source, index) pairs for walker entries or, for
  `PLATFORM` entries, the leaf-issuer SPKI hash, the anchor hash and the path length (a
  Conscrypt-completed chain can contain certificates from neither source), `reportedPathSha256s`,
  `issuerSpkiSha256s`, `candidatesDropped`, `anchorSha256`, the walk's `WalkStats` and `unsupportedOids`
  (the overload that produced it is **not** recorded; the 3-arg retry decision lives in the separate acceptance memo, flow step 1),
  plus the leaf's DER, `serial` and `scts` (never the other presented certificates, which would let a
  server park `PATH_CACHE_ENTRIES × MAX_PRESENTED_BYTES` in the cache); on a hit the `Finding.Path` is
  the stored one with `cacheHit = true` and `anchorSnapshotId` from the key, step 7 runs without
  re-parsing, and an exemption's `PresentedChain` is rebuilt from the live `chain` argument of that
  call; `PLATFORM` results are keyed with the host; nothing is cached when `decide` threw or step 6's `build` threw,
  and a verdict built on a thrown `build` is not put in the verdict cache either (flow step 3a, revision 50). The
  verdict cache key includes `generationEpoch` (internal; a `Long` incremented on any install and whenever a dataset leaves `pending` without a generation at the end of the start task, so a verdict cached as a pending-allow is never served once `NO_DATA` should fire), `policyEpoch` and `shadowPolicyEpoch` (the §4 setters) and
  the anchor snapshot id. Events are emitted only on verdict-cache misses. On a walker reason of
  `NO_CANDIDATE` or `UNANCHORED` (read before any `PLATFORM_ONLY` promotion) a rate-limited
  `refreshAnchors()` is scheduled (`ANCHOR_REFRESH_MIN_INTERVAL`; never while a rebuild is in
  flight); the triggering verdict stands; the next call re-walks under the new snapshot id. `canonicalSubject`
  is total (a `X500Principal` constructor failure yields null and raw-only matching) and is cached on
  each `Cert`, presented and store, so the relation test never allocates twice per pair.
