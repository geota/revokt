<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# revokt test plan

Normative: the §9 tiers, the fixture rows and their ids, §9.1 (fuzzing and the walker properties) and §9.2 (the differential parser oracle). Moved out of `revokt-spec.md` at revision 59 (#216), with the section numbers kept, so a citation of §9.x still points here. `./gradlew specStatus` reads the fixture lists from this file.

## 9. Correctness and testing

Tiered CI: **every PR** runs unit tests, committed fixtures, corpus replay, the purity compile, BCV,
the POM license assertion, the `Rule`/precedence tests and a Maven consumer build, all offline and
JDK-only; **nightly and release branches** run the oracle, fuzzing, emulators and minified-build
tests; **live checks** are informational.

**M1**
- **End-to-end oracle**: `rust-query-crlite` and `clubcard-crlite` driven with tens of thousands of
  PEM chains from CT (where `rust-query-crlite` takes SCTs from `x509-parser`, its pair set gets the same
  per-extension ∅ expectation as D2 for an inner identifier other than `0x04`, and the §9.2 read for a primitive
  `[3]`; a chain whose leaf `x509-parser` rejects is counted and excluded, not compared; the 0.1 oracle issue verifies its SCT
  path); the 10⁶-key comparison as a second tier; `index.bin` byte comparison (against `upki`'s `Index::write` over the same filters and file names, which revokt's writer reproduces; #86's golden);
  canonical JSON against `canonical_json`, with three declared differences: duplicate keys, which revokt rejects; every non-integer number `canonical_json` accepts, which revokt refuses (`RECORDS`); and the 60 recorded inputs both refuse, `canonical_json` with "number out of range" (any other oracle error beside a non-integer number fails); a `deleted` of `1e-400` is a tombstone, removed by `merge` (zero is lexical, where Python's `float()` underflows to `0.0`).
- **Cross-engine suite** (0.2): chain corpus × generations against both `RevocationEngine`s under
  the §3.2 equivalence classes; the `CrliteQuery` is extracted once by revokt's parser and handed to
  both engines, so no input is abstained; any `REVOKED`/`NOT_REVOKED` disagreement and any class
  disagreement fails the job.
- **Content-signature fixtures** (0.2 gates, except the item tagged [0.3], which needs the §6.5 store; revision 49) with mutations; incremental fixtures; a seed with an expired signer
  leaf must load; a seed 25 h ahead of local now loads with `clockBehind = true`, `ageMillis = 0`, `CLOCK_BEHIND` on `RevoktState.warnings`, the watermark at its signed timestamp; a changeset 2 h ahead of that seed then installs with `clockBehind = true`, `lastVerifiedAtMillis` advanced, watermark and cursor unchanged, and the next poll of the same changeset is `UNCHANGED`; after the local clock is advanced 30 h the next changeset installs normally, `clockBehind = false`, `CLOCK_BEHIND` gone, the watermark advanced; [0.3] a restart with the clock still behind republishes `clockBehind = true` from the stored generation; a signed changeset with `last_modified` 25 h ahead of local now against a live generation that is not `clockBehind` → `CLOCK_SKEW`, watermark unchanged, the next poll installs once the timestamp is within `clockSkew`; the same against a dataset with no generation → installs with `clockBehind`, watermark and cursor unchanged; a `mode` other than `p384ecdsa` rejected (stage `SIGNATURE`); a seed with a 70 MiB declared attachment → `SEED_UNREADABLE` before inflation; a seed with an `attachments/../x` entry, a second `records.json` entry, an extra `notes.txt` entry, an entry that differs from an expected name only in letter case (`RECORDS.JSON`, or an attachment's name with one letter's case changed) beside or instead of the expected entry, a central-directory name that differs from its local header's, a first entry other than `seed.json`, or no entry for an attachment `buildIndex` places in the generation → `SEED_UNREADABLE`, no attachment inflated and nothing installed (revision 52); a changeset whose attachment filenames are 33 and 64 characters → installs, with the generation's names the 32-character derived names; two attachment filenames that map to one name → `FAILED`, `INDEX_INCONSISTENT`, stage `INDEX`, no body fetched; (revision 56) a channel with two full filters, or none → `FAILED`, `INDEX_INCONSISTENT`, stage `INDEX`, the previous generation still live, and `SEED_UNREADABLE` for a seed; a delta whose `parent` names no record → placed by its time and installed; a full record without `parent` → loads, and a delta without one → `SYNC_SCHEMA_REJECTED`; a changeset signed by a P-256 leaf (a 64-byte raw pair) → verifies; a changeset whose first `signatures` entry fails and whose second verifies → installs; one with 5 entries, or
  whose every entry lacks `mode` → `FAILED`, stage `SIGNATURE`; two entries sharing one `x5u` URL → that URL fetched once; one whose `metadata` holds only `signature`, or an empty `signatures` → `FAILED`, stage `SIGNATURE`; an entry with no `mode` is skipped; (revision 57, #198) an entry whose `x5u` or `signature` is `""` is skipped like a missing one;
  `signatures` of `[null, a valid entry]` → `FAILED`, stage `SIGNATURE`, and `[a valid entry, null]` → installs; a first entry whose
  `x5u` fetch fails (404) and a second that verifies → installs; a lone entry whose `x5u` fetch fails → `FAILED`, stage
  `X5U`; a lone entry whose `x5u` body has no `CERTIFICATE` block, or whose chain fails, or whose signature verifier
  answers `UNSUPPORTED`, or whose records share an `id` → `FAILED`, stage `SIGNATURE`; a `_since` delta signed over the
  merged records → verifies over the merge, which is what installs, and fails over the delta's `changes` alone; a
  v3 filter with `approx_m` of 2^32, or a rank of 256 → `FAILED`; signature
  over records with a tombstone merged vs not merged.
- **Data-path fixtures** ((a), (b), (d) and (g) less its `BLOCKED_BY_SELF` items and its fetcher items tagged [0.3] are 0.2 gates; those items and (e), (f), (h) need the store, lifecycle machine or the 0.3 fetcher modules and are 0.3 gates): (a) changeset older than the watermark beyond the window →
  `ROLLBACK_REFUSED`, within the window but lower max coverage → `ROLLBACK_REFUSED`, within the window
  with equal coverage → installs; **newer timestamp with lower coverage → installs and advances the
  watermark**; a refused rollback leaves `consecutiveFailures` and `lastVerified*` unchanged;
  `Backoff: 100000000` → next poll ≤ 24 h and `backoffUntilMillis ≤ now + 24 h`; (revision 56, #131) a `CLOCK_SKEW` and
  a `STORE_FAILED` sync each advance `consecutiveFailures`, the first feed failure waiting 15 min, the second 30 min and
  the sixth capped at 6 h, while `ROLLBACK_REFUSED`, `BACKOFF` and `DEFERRED` leave the count unchanged; after three
  failures an `INSTALLED` poll, a clock-behind install, a 304 and a timestamp-match `UNCHANGED` each reset it to 0; a
  200 with `Backoff: 600` → `backoffUntilMillis = now + 600 s`; a success without the header clears `backoffUntilMillis`; a
  `FAILED` with `Retry-After: 60` waits 60 s although its computed backoff is 15 min; (revision 56, #190) an absent or
  malformed `updater.json` beside a live generation, then a changeset older than that generation by more than
  `rollbackWindow` → `ROLLBACK_REFUSED`;
  a live generation that is `clockBehind` far in the future, then a changeset newer than the stored watermark
  but older than that generation → installs (the feed does not freeze); (b)
  coverage `high` beyond `last_modified + clockSkew` → `FAILED`, stage `INDEX`; (d) x5u mutations: wrong leaf SAN, missing codeSigning EKU, root not pinned, non-CA
  certificate as intermediate, name-chaining break, `pathLenConstraint` violation, keyUsage without
  `keyCertSign`, an x5u URL on a non-allowlisted host, an x5u over 64 KiB, expired intermediate or
  leaf at live fetch → `CLOCK_SKEW` (stage `X5U`), expired leaf in seed → loads (revision 57: each `FAILED` x5u mutation in this row is at stage
  `SIGNATURE`, except the non-allowlisted host and the over-cap body, which are fetch failures at stage `X5U`); a pinned SPKI as a non-terminal
  link → loads with the path truncated there; the pinned terminal expired, or wrapped in a
  self-signed certificate with another subject → loads; (revision 54, each in the leaf and in the intermediate where both apply) a
  non-minimal length in the outer structure, a TLV after the SPKI, a second SEQUENCE inside `[3]`, bytes after an
  `extnValue`, an indefinite-length TBS or outer `signatureAlgorithm`, a constructed unique ID, a `UTCTime` without
  seconds, a time with a fraction or an offset, a year before 1970, notBefore after notAfter, a `critical` BOOLEAN of
  `01` and a signature BIT STRING with unused bits → `FAILED` (`PARSE`); (revision 55) trailing bytes inside an
  extension value revokt reads, a BOOLEAN `cA` of `01`, a non-minimal length inside basicConstraints, keyUsage,
  extKeyUsage, subjectAltName or nameConstraints, an empty keyUsage BIT STRING (`03 00`) or one with no named-bit byte (`03 01 00`), an empty extKeyUsage
  SEQUENCE (`30 00`), an extKeyUsage with a non-OID element, and a SAN with an unknown GeneralName tag → `EXTENSION`
  (the SAN case not `SAN`); a GeneralizedTime before 2050
  (Mozilla's intermediate's `20150317000000Z`), an explicitly encoded v1 version, an explicit FALSE `critical` or `cA`,
  an empty Extensions SEQUENCE, a zero or negative serial and a keyUsage with a non-minimal named-bit encoding →
  loads; a serial with a redundant leading `00` or `FF`, or an empty serial (`02 00`), → `PARSE`; a version INTEGER
  of 4 → `PARSE`, a version of 3, which is v4 → loads, and an implicit v1 with `[3]` → loads; an issuer with no RDN → `NAME`;
  an outer `signatureAlgorithm` that differs from the TBS one → `ALGORITHM`, and one that differs only by a NULL
  against an absent parameter → loads; an EC key with explicit curve parameters, a compressed point or a point one
  byte short, an `rsaEncryption` key with absent parameters or with NULL parameters that
  have content, a modulus with a redundant leading `00`, and an SPKI BIT
  STRING with unused bits → `ALGORITHM`; an ECDSA signature AlgorithmIdentifier with NULL parameters → loads; an
  extension OID twice, critical or not and understood or not → `EXTENSION`; an empty subjectAltName value →
  `EXTENSION`, and an empty critical `id-pkix-ocsp-nocheck` → loads; a `pathLenConstraint` of 128 → `EXTENSION`; an
  unknown critical extension → `EXTENSION`, and the same extension not critical → loads; a critical
  certificatePolicies → loads; a critical Netscape certificate type with basicConstraints and extKeyUsage → loads,
  without extKeyUsage → `EXTENSION`, and with an empty value → `EXTENSION`, while an empty non-critical Netscape certificate type → loads; (revision 55) a leaf whose embedded SCT
  list `extnValue` is an OCTET STRING followed by a byte, or is not an OCTET STRING → `EXTENSION`, and a well-formed
  one → loads; an intermediate with the TLS feature extension over a leaf without it, or with
  another value → `EXTENSION`, and the same value on both → loads; a terminal with the TLS feature over an
  intermediate without it → loads; a leaf with `cA = TRUE` → `LEAF_CA`; a
  malformed leaf basicConstraints or keyUsage → `EXTENSION`; a leaf extKeyUsage of codeSigning and
  `id-kp-OCSPSigning` → `EKU`; an intermediate extKeyUsage without codeSigning, or of anyExtendedKeyUsage alone →
  `EKU`, an intermediate with no extKeyUsage → loads, and a terminal extKeyUsage without codeSigning → loads; a PSS
  link whose salt is not the hash length, whose MGF1 hash differs from the message hash, whose hash is SHA-224, that
  encodes `trailerField` explicitly, or whose hash parameters are absent → `ALGORITHM`; an `id-RSASSA-PSS` key on a
  link → `ALGORITHM`; a chain whose only pinned SPKI is the leaf's → `NOT_PINNED`; the pinned terminal with a
  non-minimal length → loads; Mozilla's committed chain → loads, its intermediate's non-critical nameConstraints
  (`content-signature.mozilla.org` and `.content-signature.mozilla.org`) passing for the leaf; nameConstraints on the
  intermediate, critical or not: a permitted `""` → loads, an excluded `""` → `NAME_CONSTRAINTS`, a permitted
  `.onecrl.content-signature.mozilla.org` → `NAME_CONSTRAINTS` (a leading dot covers subdomains only), a permitted
  `ignature.mozilla.org` (a suffix off a label boundary) → `NAME_CONSTRAINTS`, a permitted
  `CONTENT-SIGNATURE.MOZILLA.ORG` → loads, an excluded `mozilla.org` → `NAME_CONSTRAINTS`, a permitted rfc822Name
  subtree alone → loads, a leaf outside the permitted subtree → `NAME_CONSTRAINTS`, an encoded `minimum` →
  `EXTENSION`, a wildcard or absolute base → `EXTENSION`, an empty NameConstraints → `EXTENSION`, and a directoryName
  subtree → `EXTENSION`; (e) store: power loss simulated after the pointer flip with a zero-length filter → start
  falls to `previous`, `storeFailures = 1`; a crash before `meta.json` leaves an incomplete directory
  that prune deletes; a non-empty store with a lower `store.version` → rebuilt from seed, `STORE_MIGRATED`, `storeFailures = 0`; with a higher `store.version` under `JvmStorage` → no file written, the lock released, `storageFallback = true` with `STORE_NEWER_LAYOUT`, and the worker-style `sync()` still installs in memory; under `AndroidStorage` → rebuilt from seed with `STORE_NEWER_LAYOUT`; an instance on the ownership fallback whose directory is chowned during the session → migrates within one `READONLY_POLL_INTERVAL`, `storageFallback = false`, the in-memory generation on disk; an empty
  directory → `storeFailures = 0`; a `meta.json` without its signed members, or without `records.json` beside it → no generation; a `meta.json` with the
  other channel → no generation; a `current` with an unknown or a duplicate member → malformed, so the generation its
  damaged `previous` member named is held, and a fresh loader's heal flip beside it prunes nothing, while the next
  install over the healed pointer prunes; a pointed generation without `records.json` → no `previous`, counted; two instances on one directory in one process → the second throws;
  a second JVM process on a held lock → read-only start within 1 s, `sync()` → `STORE_LOCKED`, the
  directory listing is byte-identical before and after its start even with a newer seed configured
  (served in memory, `fromSeed = true`), it observes the first process's install within
  `READONLY_POLL_INTERVAL`, and after the owner closes it acquires the lock within one interval and
  its next `sync()` installs; `close()` then a new instance on the same directory in the same process
  starts as owner; a directory owned by another uid or group-writable on POSIX → `STORE_UNREADABLE`
  and no file written for the session; two consecutive syncs whose `engine.prepare()` throws → `live`
  and `previous` still load, `storeFailures = 2` (sync-time `prepare()` throws count), both syncs `FAILED` with stage `PREPARE`, the two failed directories deleted; stored
  generation equal to the seed → no verification, `names()` unchanged; a changeset of 257 records after channel filtering or a 17 MiB declared filter → rejected before any
  body fetch; a channel whose
  coverage would make the built `index.bin` over 1 MiB → `FAILED`, `INDEX_INCONSISTENT`, stage `INDEX`, no
  generation directory written (a built index is always an even size, so not 1 MiB + 1 byte); (f) seed: `seedFormat` above supported → ignored with a warning; channel mismatch →
  `start()` throws on both platforms; a stored generation not older than the seed beside a valid pointer
  → seed skipped, nothing written; a mutated shipped `index.bin` → `SEED_UNREADABLE`; the seed-load
  rule's (b) (§6.5): a malformed or absent pointer beside a newer complete generation that re-verifies →
  adopted, `updater.json` written first, the pointer healed; one that does not re-verify → not adopted,
  counted once, kept, and the seed installed; never adopted below the generation the engine serves;
  the seed's own complete directory → installed as it stands, rotted → completed again with only its
  rotted files re-staged and, when the load fails, left incomplete, never deleted; the directory the engine
  serves never rewritten; a throwing `updater.json` or pointer read → `STORE_FAILED`, nothing written;
  a seed archive over 256 MiB, or a source that never ends → `SEED_UNREADABLE`, no store failure; (g) fetcher: the feed host's own
  chain revoked in the stored generation → `BLOCKED_BY_SELF` within the 24 h hold, `blockedSource`, `blockedChainSha256` and `blockedLeafSerial` set,
  `updateBlockedBySelf = true` (after the hold see below);
  a signed `intermediates` changeset served on the `cert-revocations` URL → `FAILED`,
  `SYNC_SCHEMA_REJECTED`, cursor, watermark and `lastVerified*` unchanged; a Remote Settings 3xx → `FAILED`; a gzip
  body inflating past its cap → `FAILED` before the cap is exceeded; a signed attachment whose size
  exceeds `MAX_FILTER_BYTES` → `FAILED` with `CAP_NEAR_LIMIT`, nothing advanced, not fetched; a signed revocation of the Remote Settings host → `BLOCKED_BY_SELF`; the same hit chain delivered to the public `fetcherTrustManager` by a consumer client → rejected, `feedHostBlock` not written, `updateBlockedBySelf` unchanged, while the same chain on the source's internal instance during its fetch → `BLOCKED_BY_SELF`; two sources with a factory that returns one client built over the first source's `tls` for both → the second source's hit chain, handshaking outside any fetch of the first source, writes nothing; a sync 23 h after the first block (across a process restart) is still `BLOCKED_BY_SELF`; one at 25 h installs with `feedHostRevoked = true` and `FEED_HOST_REVOKED` on `RevoktState.warnings`; a test engine whose `formats` is `{V4}` with the v3 seed and no fetching source → `start()` throws `SEED_UNREADABLE` in the sole-seed `ENFORCE` configuration (V `FORMAT_UNSUPPORTED` cannot fire first, there is no fetching source); a fetch answered 401 or 407 → `FAILED` with `httpStatus` set, on the JDK fetcher; [0.3] the same on the Android and OkHttp fetchers; the JDK fetcher against a server whose certificate lacks the host's SAN → `FAILED` (endpoint identification); [0.3] the same on the Android fetcher;
  (h) lifecycle: `close()` with a live client under `STRICT` → subsequent handshakes succeed on the
  platform verdict, `evaluations` frozen, no events; `close()` before ready → `readyFuture()` fails with
  `IllegalStateException`; `ready` is false in `CREATED` even with `requiredDatasets` empty; a
  `trustManager(d)` instance created before `start()` has its snapshot when `start()` returns on both platforms, and
  its first handshake waits for data only, under `needsData`, up to the flip to `STARTED` + `awaitData` (on the
  JVM `start()` has already joined the loader up to `awaitData`, so the handshake wait is what
  remains of it); `trustManager(d)` in `STARTED` with `d.getAcceptedIssuers()` throwing, and with it
  returning an empty array → `IllegalStateException`, `trustManagerCount` unchanged, `sslContext(d)`
  propagates it, a later call with a good delegate succeeds (JVM, and Android instrumented with a
  custom delegate); both platforms, a trust manager created in `CREATED` over an empty or throwing
  delegate → `start()` throws `IllegalStateException`, lifecycle stays `CREATED`, the store lock is
  not held and a second `Revokt` on the same directory starts as owner; `start()` over three
  pre-start instances whose second delegate throws once → the first `start()` throws, the second
  succeeds and all three report a snapshot; `trustManager(d)` racing `start()` → built by exactly
  one of the two, never left without a snapshot; a read-only instance (lock held by another
  process) has `fetcherTrustManager.status().anchorCount > 0` when a fetching source is configured
  (the build precedes the lock); a seed-only configuration with an empty default trust store →
  `start()` succeeds, and the same configuration after `revokt.trustManager` was read before `start()` → `start()` throws `IllegalStateException`; `revokt.evaluator.evaluate(...)` in `CREATED` and after `close()` → `IllegalStateException`; Android instrumented on API 26: `close()` with a pending `readyFuture()`, a pending `syncAsync()` and a `resetStateAsync()` → every future completes exceptionally, no `NoSuchMethodError`; `limits { maxTrustManagers = 2 }` → the third distinct delegate throws, and after the second client is dropped and collected the third succeeds without waiting for the `ReferenceQueue`; the `STARTING` racers: a second `start()` entering during the sole-seed decode returns after the first completes and throws iff the first threw, with one `prepare` call on the engine; `close()` entering during the decode → the prepared generation is closed, never activated, the store lock released, lifecycle `CLOSED`, `engine.close()` called once after the decode thread returned; a gap trust manager whose delegate throws → `start()` throws after `activate`, the stored generation is complete, and the retry loads it on the loader without a second seed verification; `refreshAnchors()` succeeds → `anchorSnapshotId` advances on that trust
  manager and the next handshake for a previously cached chain misses both caches, `pathCacheHits`
  unchanged; `resetState()` → `anchorSnapshotId` unchanged on every live trust manager, the next
  handshake is a verdict-cache miss (`generationEpoch`) and a path-cache hit; Android instrumented,
  wired on the main thread under `StrictMode.detectDiskReads().penaltyDeath()` → no violation on a
  cold process (the `start()` warm-up), after a trust-store change (the guarded delegate call) and
  with a Conscrypt `TrustManagerImpl` over `AndroidCAStore` as delegate;
  `resetState()` on a seeded `DEFAULT` instance → the next handshake is served by the seed, never
  `NO_DATA`; two listeners registered before the first handshake each receive every event in sequence order; an enqueue racing a drain's
  flag clear is still delivered without a further handshake.
- **Verifier**: OID harvest; key-OID gaps; PSS parameters (each `INVALID`: a SHA-1 message hash, the all-default
  parameters included; a SHA-256 message hash with MGF1 over SHA-1, which the JDK verifies; a mask generation
  function other than `id-mgf1`; each `UNSUPPORTED` instead under a provider without `id-RSASSA-PSS`); raw-to-DER
  edge cases; an off-curve point
  on a supported OID → `INVALID`; [0.2, #172] ECDSA range (revision 54), on P-256, P-384 and P-521 (the brainpool cases under BC
  were dropped in revision 56 with #175: the check reads n from the key's curve, and BC's path is tested with
  `revokt-bc`): r or s of 0, of n and of n + 1 → `INVALID` before `Signature` is
  called; an ECDSA signature on a curve the probe marks unsupported → `UNSUPPORTED`, whatever its r and s; r = s = 0, the CVE-2022-21449 form, → `INVALID` against a stub provider that answers `VERIFIED` to every
  signature, so the row tests revokt's check and not the JDK's; an `ECDSA-Sig-Value` with trailing bytes, a negative
  INTEGER, a redundant leading `00`, a non-minimal length or a missing s → `INVALID`; a key whose curve order cannot be
  read → `INVALID`; a valid signature rewritten to its high s (n − s) → `VERIFIED`; a throwing provider → `INVALID` plus `VerifierError`; PQ chain matrix.
- **Parser corpus** and the §9.2 differential parser oracle; **Android instrumented** (API 26, 31,
  34, 36) including the PKIX fallback (the jvmMain `PkixPathBuilderFallback` through ojluni, JVM-tested in 0.2), the
  null-host extension-call probe and the §9.2 corpus replay against the
  platform `CertificateFactory` (a 0.3 gate; pinned system-image revisions, Conscrypt APEX version logged); **live checks**; **benchmarks** on a physical ARM device including
  verifications per honest handshake.
- **Walker fixtures**, schema `id | presented (ordered) | snapshot | preload | verifier.unsupported |
  expected Walk (asserted only in the walker-only harness, revokt-engine's test set; every other path asserts the Finding.Path columns, and revokt-testing's recorded fixtures carry the Walk column as a string) | expected PathStatus / NoIssuerReason / WalkEnd | expected Path fields | verdict
  relation to the honest chain`, on every platform path (JVM walker, JVM walker with the fallback
  disabled in the walker-only harness, Android CT-gap path, Android plain delegate, `Revokt.evaluate`; a row whose
  outcome depends on the fallback states its fallback-disabled expectation, decision step 6, revision 49; every row
  whose step-5 walk ends `NotFound` or `Budget` with `usedFallback = false` asserts exactly one `FallbackNotUsed` with
  step 6's reason, revision 50: `DISABLED` on the disabled path, where a row's "fallback skipped" is
  `FallbackNotUsed(DISABLED)`; else `SKIPPED` above `FALLBACK_MAX_PRESENTED`, as in a row's "fallback skipped"; else
  `FAILED`. **A row's leaf stays within the keyability profile (K1 to K8) unless the row tests `PRODUCER_UNKEYABLE`**
  (revision 56, the maintainer's decision). A row cut at step 3 never walks and carries none: the `PARSE_FAILED` leaf, the 70-certificate chain, and
  the rows over `MAX_PRESENTED` on every trust-manager path and `Revokt.evaluate`, as the step-3 note below says):
  (a) random-key fake issuer; (b) ECDSA-recovered second key; (c) RSA duplicate-signature key;
  (d) recovered-key fake with an unsupported own signature, terminating at a real anchor; (e) 8, 16
  and 63 distinct-key related junk ahead of the real one → `Found`, verdict equals honest; (f)
  cross-signed chain with both roots in the snapshot → first path in M1, both on exhaustive re-walk;
  (g) chain omitting the intermediate → walker-harness `NO_ISSUER(NO_CANDIDATE)`; on trust-manager bindings `PLATFORM_ONLY` with `walkerReason = NO_CANDIDATE`; on Android with a warm intermediate index and a host, `Found(PLATFORM)` via step 4; (h) self-signed non-anchor and an
  A↔B loop; (i) 65 related junk at the leaf → `Budget(RELATED_BUDGET)`, `candidatesExplored = 64`,
  fallback skipped (chain too long), `PATH_BUDGET_EXCEEDED`; (j) ML-DSA anchor on a JDK without ML-DSA →
  `NO_ISSUER(UNSUPPORTED_ALGORITHM)` in the walker-only harness and `Evaluator.evaluate`; on a trust-manager binding a chain the
  platform accepted is `NO_ISSUER(PLATFORM_ONLY)` with the same `UnsupportedAlgorithm` finding (revision 57); (j2) brainpool anchor on SunEC (walker harness) → `NO_ISSUER(ALL_CANDIDATES_INVALID)`, no `UnsupportedAlgorithm` (the curve OID is the candidate's); (k) same-key decoy with a garbage
  signature first, decoy issuer name equal to the root's → `Found`, `verifications = 4`,
  `candidatesExplored = 5` (the store anchor and the real intermediate are both tried under the
  decoy's garbage signature before the leaf loop reaches the real intermediate by memo hit; re-derived
  under the `keyFamily` ordering of `related()`: unchanged, every candidate shares the family);
  (k2) the same with the decoy carrying an EC key under an RSA-signed leaf → the RSA store candidates
  are tried first, `verifications = 3`;
  (l) public cross-certificate to a retired non-anchor root first → `Found`; (m) sound path then 62
  related junk → `Found`; (n) unsupported candidate on a dead branch with a supported path found →
  `outcomeDepended = false`; (o) a second certified key verifying the leaf via an attacker-owned
  constrained sub-CA → both keys in `issuerSpkiSha256s`, `REVOKED`; (p) PrintableString/UTF8String
  issuer-name mismatch → `Found` via canonical ordering; (q) depth-9 bridge → `Found`; (r) TBS/outer
  signature OID mismatch → `Found` with the finding, and a NULL-vs-absent pair → `Found` with no finding;
  **(s1)** (o) plus 62 related junk ahead of the honest key (64 related in total) → `Found`, `pathsFound = 2`,
  `REVOKED`; **(s2)** (o) plus 63 junk (65 related) → `Budget(RELATED_BUDGET)`, `Rejected` with `rule ∈ {REVOKED,
  PATH_BUDGET_EXCEEDED}`, and `REVOKED ⇔ honestKey ∈ issuerSpkiSha256s`; **(t)** (o) plus 80 junk → same expectation as (s2); **(i), (e) with 63 junk, (s1), (s2), (t), (y) and (y2) present more than `MAX_PRESENTED` certificates (65 to 68, revision 56 adding (e), (s1) and (y2), which test the walker's 64-related-candidate edge) and are walker-harness only; on every trust-manager path and `Revokt.evaluate` they are cut at step 3: `Budget(EXPLORATION_BUDGET)`, `endDepth = 0`, `PATH_BUDGET_EXCEEDED`, no CRLite query and no `FallbackNotUsed`, as (ag) asserts**;
  (u) `getAcceptedIssuers()` throws during `refreshAnchors()` → the current snapshot is kept, `anchorSnapshotId` unchanged, the walk proceeds under it (the wiring and `start()` throw cases are lifecycle fixtures, (h));
  (v) honest chain against a 200-anchor snapshot → `verifications ≤ 4`, `COMPLETE`; (v2) the same
  with a retired-root cross-certificate presented → `≤ 4`; (w) dense cross-certified mesh (6 roots,
  12 cross-certs) → `Found`, reported path `leaf → I → anchor`; (x) self-signed anchor as server
  certificate → `Found([leaf])`, key = the leaf's own; **(y)** honest chain leaf → I1 → I2 → root with the root in the snapshot and 65 presented
  certificates whose subject equals I2's name and whose keys do **not** verify I1 (one `INVALID` exploration each), placed before I2 →
  `Budget(RELATED_BUDGET)` at `endDepth = 2` (sub-leaf cap propagates), fallback skipped,
  `PATH_BUDGET_EXCEEDED`; **(y3)** (M2) leaf whose issuer I has one certificate under OneCRL-listed anchor A and another under a retired root present only in the preload → paths `leaf → I_A → A` (ANCHOR, hit) and `leaf → I_B` (PRELOAD); `ONECRL` fires (the PRELOAD path is not a clean alternative); **(y2)** the same chain with the junk carrying the root's name and the
  root in the snapshot → `Found`, `verifications = 3` (leaf/I1, I1/I2, I2/root; the junk is never explored because the store root sorts first at I2, which pins store-first ordering); **(z)** `NotFound` where only
  an unrelated presented certificate has an unsupported key OID → `NO_ISSUER(UNANCHORED)`, no
  `UnsupportedAlgorithm`; (aa) root-issued leaf with the root also presented → `pathsFound = 1`;
  (ab) `PARSE_FAILED` leaf with no CRLite generation → `rules = {PARSE_FAILED, NO_DATA}`, `rule = NO_DATA`;
  (ac) **walker-harness only, custom canonicaliser** (on both default delegates every honest issuer
  is related, since `X500Principal`'s canonical form hex-encodes TeletexString and both platforms
  chain by it): issuer unrelated by encoding, the TeletexString difference on the issuer certificate's subject, not
  on the leaf's issuer field (K5), the leaf carrying a keyIdentifier AKI that matches no candidate, not the
  issuer-and-serial form (K8; revision 56, the maintainer's decision), and four unrelated junk ahead → `Found`
  through the unrelated loop, `REVOKED`; (ad) **walker-harness only**: leaf,
  honest issuer unrelated by encoding, six same-name mutually cross-signing junk certificates ahead →
  `Budget(EXPLORATION_BUDGET)`, `candidatesExplored = 1024`, `usedFallback = true`,
  `PATH_BUDGET_EXCEEDED`, `rule = REVOKED`, honest key last in `issuerSpkiSha256s`; with the fallback disabled the
  same walk → `PATH_BUDGET_EXCEEDED`, `usedFallback = false`, `FallbackNotUsed(DISABLED)`, the honest key (which only the fallback reaches) not in
  `issuerSpkiSha256s`, so `rule = PATH_BUDGET_EXCEEDED`; (ae) platform
  accepts, walker `UNANCHORED` and fallback fails → `NO_ISSUER(PLATFORM_ONLY)`,
  `walkerReason = UNANCHORED`, `FallbackNotUsed(FAILED)`; (af) 9 presented certificates with a link the walker cannot reproduce
  (custom delegate) → fallback skipped, `PATH_BUDGET_EXCEEDED`; with the fallback disabled → `PATH_BUDGET_EXCEEDED`
  as well, `usedFallback = false`, `FallbackNotUsed(DISABLED)`; (ag) 70 presented certificates →
  `Budget(EXPLORATION_BUDGET)` without a walk, no `FallbackNotUsed`; (ah) `VERIFICATION_BUDGET`: 12 presented certificates
  of distinct RSA duplicate-signature keys each verifying the leaf and recursing into a
  32-certificate dead-end subtree → `Budget(VERIFICATION_BUDGET)`, `verifications = 256`; (ai) a
  17-certificate honest path (16 non-terminal plus the anchor) → `Found`; an 18-certificate one →
  dead end; (aj) **walker-harness only, platform canonicaliser** (revision 48, #98): no related path at the leaf (the
  leaf's issuer neither presented nor in the snapshot); two unrelated presented certificates U1 and U2 whose keys both
  verify the leaf, each certified by a snapshot anchor, in both orders, with and without a related candidate ahead that
  verifies the leaf but is unanchored → `Found`, `leafKeys = {U1, U2}` and `unrelatedExploredAtLeaf = 2` in every
  case; with the CRLite stub revoking U2 only, `rule = REVOKED` in both orders. **Revision 57** (#196 and #197, the
  maintainer's decisions; in the first four rows the fallback finds no path, and the label is the same with it failed,
  `FallbackNotUsed(FAILED)`, or disabled, `FallbackNotUsed(DISABLED)`): (ak) the relabel: `[L]` →
  `NO_ISSUER(NO_CANDIDATE)`; `[L, D]`, where D is named like the leaf's issuer, verifies the leaf under a recovered key and signs itself with a probe-listed OID under an issuer no
  candidate matches → `NO_ISSUER(UNSUPPORTED_ALGORITHM)`, `walkerReason = UNANCHORED`; `[L, J]`, where J is the same but verifies
  nothing → `NO_ISSUER(UNSUPPORTED_ALGORITHM)`, `walkerReason = ALL_CANDIDATES_INVALID`; under `STRICT` all three are `Rejected`, and
  a `NO_ISSUER` exemption exempts all three alike; on trust-manager bindings and `Revokt.evaluate` all
  three are `NO_ISSUER(PLATFORM_ONLY)`, each with the walker's reason in `walkerReason` and D's or J's OID in an
  `UnsupportedAlgorithm(outcomeDepended = false)` finding, and `STRICT` plus `exempt(NO_ISSUER, hostSuffixIn(…) and
  platformOnly())` accepts each; (al) the leaf deferral: a leaf L2 whose own signature OID is probe-listed, presented
  alone → `NO_ISSUER(NO_CANDIDATE)`, no `UnsupportedAlgorithm`; `[L2, I]` → `NO_ISSUER(UNSUPPORTED_ALGORITHM)`, `walkerReason =
  ALL_CANDIDATES_INVALID`; on the bindings both `NO_ISSUER(PLATFORM_ONLY)`; (am) a related store anchor that signs
  itself with a probe-listed OID and does not verify the leaf → `NO_ISSUER(ALL_CANDIDATES_INVALID)`, its OID not
  recorded; (an) a presented certificate unrelated to the leaf that verifies it and signs itself with a probe-listed
  OID → its OID recorded, `Walk.NotFound(NO_CANDIDATE)` from the walk and `NO_ISSUER(UNSUPPORTED_ALGORITHM)` from `decide`; (ao) the
  candidate order: an issuer that is itself a self-signed snapshot anchor P, presented beside its cross-certificate
  under another anchor in both orders → reported path `[L, P]` and `anchorIn([P])` exempts in both; two cross-signed
  intermediates under two different anchors → the reported path follows the presented order, as Firefox's does;
  (ap) 64 snapshot anchors named like the leaf's issuer ahead of the presented issuer → `Budget(RELATED_BUDGET)` at
  `endDepth = 1` with no partial path, `PATH_BUDGET_EXCEEDED`, `usedFallback = true` and only the fallback's key
  evaluated; with the fallback disabled, `usedFallback = false`, `FallbackNotUsed(DISABLED)` and no key evaluated;
  (aq) a non-anchor issuer must be a CA: leaf → I → R with I having no basicConstraints, `cA` omitted, `cA` explicitly
  FALSE, a `cA` of `01`, or two basicConstraints → `NotFound(ALL_CANDIDATES_INVALID)`, `verifications = 0`,
  `candidatesExplored = 1`. Three cases use an end-entity certificate E under the real root, named like I: E's key
  verifies the leaf and `[L, E, I]` is presented → `Found` through I alone, `verifications = 2`,
  `candidatesExplored = 3`; `[L, E]` → `ALL_CANDIDATES_INVALID`; E signs itself with a probe-listed OID → the OID is
  still recorded. The attack the check closes: `[L, C, F]`, where F is an end-entity certificate under the real root
  and C, named like I, is a CA certificate for a recovered key that F's key signed → `NotFound(UNANCHORED)`,
  `verifications = 1`, `candidatesExplored = 3` (without the check it is `Found([L, C, F, R])`, with C's key the only
  leaf-issuer key); `[L, C2, F]`, the same with C2's issuer name not matching F's subject, so that only the unrelated
  loop reaches F → `NotFound(UNANCHORED)`, `verifications = 1`, `unrelatedExploredAtLeaf = 1`; leaf → I1 → I2 → R
  with I2 not a CA → `UNANCHORED`, `verifications = 1`, `candidatesExplored = 3`; a v3 anchor without
  basicConstraints still terminates → `Found`.
  Fixtures run with the cross-call memo cleared; (aa) presents the root's exact bytes;
  (z) has a related candidate that verifies but is unanchored; stuffing fixtures present their junk.
- **Trust-manager invariants**: never accept what the platform rejected (the 3-arg overload's null-host retry only after a socket or engine overload accepted the chain and host); under `DEFAULT` never
  reject on a step-2 failure alone except `PATH_BUDGET_EXCEEDED`; at most one event per (connection, verdict-cache TTL window) on Android
  OkHttp (the chain cleaner runs lazily, §5.1 flow step 1); at most two platform validations per 3-arg call, the second only the null-host retry; a direct 3-arg call for a chain and host no socket or engine overload accepted gets no retry; a plain delegate on the JVM throws `IllegalArgumentException` at wiring; an empty or throwing anchor set throws `IllegalStateException`
  at wiring (`STARTED`) or from `start()` (instances created in `CREATED`) on both platforms and
  consumes no cap slot; the cap throws at `maxTrustManagers + 1` live instances and instances are collected when their
  client is dropped; a trust manager that can go past flow step 1 has a snapshot (`fetcherTrustManager` without one never goes past flow step 1); `enforcement = ENFORCE` after the start task found the sole seed unreadable → `IllegalStateException` `NO_DATA_AT_FLIP`, enforcement unchanged; two concurrent
  `trustManager(d)` calls return the same instance.
- **API rows** (revision 56; 0.2 gates unless tagged): `Exemptions.and`/`or` as CEL: `broken or true`, `true or
  broken` → exempt, no finding; `false and broken`, `broken and false` → not exempt, no finding; `broken and true` →
  not exempt plus one `EngineError(EXEMPTION)`; `broken or broken` → the left operand's error recorded once; a fatal
  error from either side propagates; `hostIn(["Foo.Example."])` matches the host `foo.example` and not
  `foo.example.com`; `hostIn` or `hostSuffixIn` with `""`, `"."`, `".x"`, `"*.x"` or `"bücher.de"` →
  `IllegalArgumentException`; a request host of `"."` → no host, matching nothing; `EvaluationRequest.Builder.build()`
  with an empty `presented` or an empty `verifiedPath`, a `verifiedPath` of more than `MAX_DEPTH + 1` certificates, or a
  `verifiedPath` whose first certificate is not byte-equal to `presented[0]` → `IllegalArgumentException` (revision
  57); a one-certificate `verifiedPath` whose leaf is a snapshot anchor outside the keyability profile → `FOUND` under
  its own key, `anchorSnapshotId` the entry snapshot's; the same leaf when it is not an anchor →
  `PARSE_FAILED(PRODUCER_UNKEYABLE)`, never queried; a longer `verifiedPath` → `anchorSnapshotId = 0`, an anchor at its
  head gated like any leaf; `STRICT.newBuilder().build().newBuilder()` keeps `STRICT`'s preset; `rollbackWindowMillis(-1)` and
  `clockSkew(Duration.ofSeconds(Long.MAX_VALUE))` → `IllegalArgumentException`; a policy that is an `ERROR` under
  `validate(ENFORCE)` has only `WARNING`s under `validate(OFF)`; a `PresentedChain` whose second certificate does not
  parse → `size = 2`, `parsed(1) = false`, `der(1)` its bytes and its other fields empty; two `Verdict`s that differ
  only in `elapsedNanos` or `generationEpoch`, and two `SyncResult`s that differ only in `cause`, are equal;
  `validate()` with `ioDispatcher = Dispatchers.Unconfined` → V `IO_DISPATCHER_UNCONFINED`, a `WARNING` under both
  enforcements, and none for `Dispatchers.IO`; `RevoktLoggers.jul()` logs `DEBUG` at `FINE`, `INFO` at `INFO`, `WARN` at `WARNING` and `ERROR` at `SEVERE`;
  `MozillaRemoteSettings.Builder.build()` with an `x5uHosts` entry, or either side of a rewrite, of `1.2.3.4`, `a.0x7f`,
  `host.`, a 64-character label, a 254-character name, `host:443`, `user@host`,
  `host/x`, `host?x`, `host#x`, `[::1]` or a non-ASCII name → `IllegalArgumentException`, while an upper-case entry
  builds; an x5u URL on
  `Content-Signature-2.cdn.mozilla.net` against the default allowlist → `FAILED`; [#141] a delta poll's changeset URL carries
  `_since=<cursor>` bare and `If-None-Match: "<cursor>"`, and before #141 a sync with a stored cursor sends neither
  (revision 57); decision steps 7 and 8 (#133): a key answered `ENGINE_ERROR`
  while another is `REVOKED` → `Finding.Crlite(ENGINE_ERROR)` for it and no `EngineError(ENGINE)`; a boundary throw
  after one exemption ran → that exemption stands, no later one runs, rules = those fired plus `ENGINE_ERROR`; a
  required dataset the snapshot lacks → `dataStates` entry with `generationId` null and `NO_DATA`; a throwing clock →
  `ENGINE_ERROR(BOUNDARY)`, `NOT_WALKED`, `ageMillis` null, no `STALE`, `NO_DATA` still computed, no exemption; an
  engine whose `query` throws on the second key → `ENGINE_ERROR(BOUNDARY)` with `engineName` null, the first key's
  finding kept and no third query.
- **`Rule` model tests** (tagged by milestone: **0.1** the enum, preset tables, golden fixture, the `revokt-engine` jvmMain `Rule → BasicReason` map and precedence; **0.2** everything that needs `evaluate` alone; **0.3** exceptions, caches, counters, the shadow policy, listeners and the Java compile; revision 49 moved the parts of [0.2] items that need 0.3 machinery to [0.3]): [0.1] both preset tables are total over `Rule.entries`, the two status-map ranges are subsets of it, the `Rule → BasicReason` map is total, and the `RevoktStatus` and `RevoktEvent` rule-keyed maps are zero-filled over `Rule.entries`; `entries == entries.sortedBy { ruleClass }`; the golden growability fixture diff is
  additive; the `PathStatus → Rule` and `CrliteQueryResult → Rule` tables; `parseFailed` zero-filled over `ParseReason.entries`; [0.2] `Verdict.rule` is the
  first fired non-exempted `REJECT` rule; a leaf failing K6 →
  `PARSE_FAILED(PRODUCER_UNKEYABLE)` with `keyabilityClause = TIME` and `crlite == null`, and an issuer candidate
  outside the profile not dropped; per-dataset
  `NO_DATA` and `STALE` with a fresh CRLite and a 30-day-old OneCRL generation (M2) fire nothing;
  `DEFAULT.newBuilder().rule(STALE, REJECT)` with 4-day-old data → `Accepted`, `DataState.stale`,
  `rules` empty; the same with `rejectStaleAfter(CRLITE, 3 d)` on a generation that is not `fromSeed` (or, when `fromSeed`, after a sync attempt has completed since the seed install: persisted `datasetLastAttemptAtMillis ≥ seedInstalledAtMillis`) → `Rejected(STALE)`, and with `exempt(STALE, anchorIn(privateCa))` a chain under that anchor → `Accepted` with `Finding.Exempted(STALE)`;
  `dataStates[CRLITE].rules == {STALE}`; a `NO_SCTS` chain under `DEFAULT` → `Accepted`;
  `requiredDatasets = {CRLITE}`, no generation after the start task completed (`pending == false`), and a walker that throws → `Rejected(NO_DATA)` with
  `rules == {ENGINE_ERROR, NO_DATA}`; the golden fixture accepts the `ALLOW → REJECT` flip exactly
  once per rule and preset and rejects a second; [0.3] the parts of former [0.2] items that need 0.3
  machinery (revision 49): `parseFailed.values.sum() == fired[PARSE_FAILED]`; `rejects` sums equal rejection counts; the K6 leaf
  above on a path-cache hit → the same `PARSE_FAILED(PRODUCER_UNKEYABLE)` clause; a `shadowPolicy = STRICT` under
  `DEFAULT`/`ENFORCE` with a `NO_SCTS` chain → `Accepted`, `shadowVerdict` is `Rejected(NO_SCTS)`,
  `shadowWouldRejects[NO_SCTS] == 1`, `rejects` unchanged, one event; `RevoktCertificateException.cause.reason` equals
  the declared reason for every rule (`REVOKED` for `REVOKED`, `UNDETERMINED_REVOCATION_STATUS` for `NO_DATA`, …); `Rejected.getRule()`
  is non-null from Java; every preset passes `validate(ENFORCE)` with no `ERROR` at every release
  (including the M3/M4 one-minor `ALLOW` rows); ENFORCE with a revoked chain twice within the
  verdict-cache TTL → two exceptions, `rejects[REVOKED] == 2`, one event; a Java consumer compile that builds a policy with `staleness` and
  `rejectStaleAfter(Dataset, Duration)`, reads `verdict.getRule()`, implements `Exemption` as a
  lambda over `ExemptionContext` and `RevoktListener` with only `onVerdict`.

### 9.1 Fuzzing requirement

Mandatory for every component that parses bytes it did not produce; measured by coverage and bug
yield. **Targets**: v3/v4 filter decoders (differential against `clubcard-crlite`); `index.bin`
round trip; JSON and canonical JSON (differential against `canonical_json`); the TBS/DER parser and
SCT list (§9.2); DER ECDSA conversion and `AlgorithmIdentifier`/PSS parameters; seed archive and x5u
PEM; the path walker (below); [M2] CRX3, zip, `crl-set`, OneCRL, preload DER; [M3] precert TBS, log
list. **Harness**: Jazzer `@FuzzTest` methods with a static `fuzzerTestOneInput` wrapper;
`-Xmx256m -rss_limit_mb=1024 -timeout=10` (the §9.2 parser target overrides with `-timeout=1`); `-max_len` = each target's cap + 1 (filters:
`MAX_FILTER_BYTES + 1`); allocation budgets in each decoder; differential oracles in-process through
the `revokt-oracle` Rust cdylib and the Panama shim; the Go producer oracle runs **out of process**
(the CLI, batched over a pipe: one base64 DER per line in; one line per input out, `OK <serial-hex> <spki-sha256-hex> <ct|lax|zc>` or `REJECT <error>` (an empty line, the encoding of an empty input, is answered `REJECT`), with `##` terminating a batch, so the Go CLI and the Kotlin driver are written independently) during fuzzing, since a third set of signal handlers beside the JVM's
and libFuzzer's is not safe in-process. **Tiers**: PR = committed-corpus
replay as unit tests, JDK only; nightly = ClusterFuzzLite batch matrix, one job per target; OSS-Fuzz
once the project has users. **Findings**: any exception other than the declared result, any
allocation above budget, any timeout, any difference between implementations outside a declared
equivalence class, any non-idempotent round trip. **Acceptance**: no open continuous-tier crash at
release; Kover branch coverage of each parser package not regressed, 90 % as the target; committed
corpus capped at a few MB, overflow in a corpus repository.

**Walker fuzzer** (a 0.2 deliverable: it compiles against `Walk`, `CandidateIndex` and `reconstruct`, which exist from 0.2; the generator, `SymVerifier` and the reference walker are 0.1). Crypto is replaced by `SymVerifier(ok: Set<Pair<CertId, KeyId>>, unsupported:
Set<Oid>)`, which implements `SignatureVerifier.verify(sigAlg, spki, message, signature)` over bytes with `KeyId = SHA-256(spki)` and `CertId = SHA-256(message)` (the TBS); the generator emits real DER and writes the key id into the SPKI BIT STRING under a private-arc key OID, and `unsupported` is matched against `tbsSigOid`/`keyOid`/`curveOid` exactly as the startup probe does, so recovered and duplicate-signature keys are free to generate. Generator (every certificate carries a critical basicConstraints `cA = TRUE` except the leaf and
`EndEntityIssuer`'s end-entity certificate, so the relatedness invariant covers CAs only): an honest
world (1–200 anchors, some with unsupported OIDs; chain depth 0–9, depth = the number of intermediates; cross-signs only between
snapshot roots), then **world mutations** (`NameEncoding`, `AlgMismatch`, `UnsupportedOwnSig` on
honest certificates, `DropIntermediate`) and **attacker mutations** (`Recover(child)` with a fresh key
in `ok`, optionally `CertifiedBy(anchor)`; `SameKeyDecoy`; `CrossCertToNonAnchor`; `Stuff(n ≤ 300,
related)`; `SelfSignedNonAnchor`; `Loop`; `Permute`; `Duplicate`; `EndEntityIssuer(child, certifiedBy, unrelated)`, a recovered key
in an end-entity certificate issued by a snapshot anchor, named like the child's issuer or, with `unrelated`, a fresh
name only the unrelated loop reaches, which leaves the result unchanged and is the one generated certificate that
verifies a child without being related to it; `DepthPad`, junk certificates off the honest path that never lengthen it, so P3 is not tripped by a dead end). **Oracle**: a
**relation-aware, uncapped reference walker** (a non-anchor candidate must be a CA as the JDK reads it; at every node: related candidates, plus unrelated
presented certificates only when no related path exists, at the leaf collecting every unrelated issuer's key as §5.1 does; depth ≤ `MAX_DEPTH`; no other limits; the fuzzer runs both walkers with the platform canonicaliser, so the leaf-level custom-canonicaliser clause is inert for P2/P6 and is covered by the walker-harness fixtures instead) →
`refKeys`; a CRLite stub mapping the honest key to `REVOKED` in half the runs and every other key to `NOT_ENROLLED` (so `rules` is predictable under `Recover(CertifiedBy)`); a fake
`PathBuilderFallback` equal to the reference. Properties:
- **P1 soundness**: every returned path's links are in `ok` and not unsupported; terminal bytes in the snapshot.
- **P2 completeness**: `Found ⇒ leafKeys == refKeys`; `NotFound ⇒ refKeys == ∅`; `Budget ⇒ partialLeafKeys ⊆ refKeys`.
- **P3 never-improve** (attacker mutations only, under `DEFAULT`, with the CRLite stub always
  holding data): honest `Rejected ⇒` mutated `Rejected` with `rule ∈ {REVOKED, PATH_BUDGET_EXCEEDED}`;
  if no limit was hit, `(mutated is Rejected, mutated.rule) == (honest is Rejected, honest.rule)`.
- **P4 order-independence**: `PathStatus` and `leafKeys` invariant under `Permute` when neither
  order produced `Budget`; `Budget` in one order ⇒ `Budget` or `Found` with `leafKeys == refKeys` in the other.
- **P5 budgets**: counters ≤ limits; `Budget ⇒` a limit at its value at `endDepth` (for
  `RELATED_BUDGET`, `endDepth == 1 ⇒ relatedExploredAtLeaf == 64`; revision 57: not the converse, since a leaf can
  explore exactly 64 related candidates and the cut come at a deeper node) and the fallback invoked at most
  once; `verifications` never exceeds `MAX_VERIFICATIONS`.
- **P6 honest cost**: unmutated world, whose generator never emits two anchors with the same
  subject name, ⇒ `verifications ≤ depth + 1`.
- **P7 no throw**: no attacker mutation produces `ENGINE_ERROR`, run with the real `X500Principal`
  canonicaliser and a verifier that throws on a configurable candidate.
- **P8 honest acceptance** (goal 3's core guarantee): an unmutated world, or one with only
  `NameEncoding`/`AlgMismatch`, ⇒ `Found` with `PathStatus.FOUND`, never `Budget`, and
  `Rejected ⇔ the CRLite stub maps the honest key to REVOKED`; `UnsupportedOwnSig` on a non-anchor certificate ⇒
  `NO_ISSUER(UNSUPPORTED_ALGORITHM)`, never `PATH_BUDGET_EXCEEDED` (an anchor's self-signature is never verified, so the mutation is applied to non-anchors only); `DropIntermediate` ⇒ `NO_ISSUER(NO_CANDIDATE)`
  (a world mutation under P3: the platform's acceptance of such a chain is the §5.2 residual,
  outside the fuzzer's model).
Rounds 1–2 are `Recover` + P3; round 2's OID case is `UnsupportedOwnSig` + P1; round 3 is
`SameKeyDecoy`/`CrossCertToNonAnchor` + `Permute` + P4; round 4 is `Recover(CertifiedBy)` + `Stuff` +
P3. Run under Jazzer with the mutation list as the structured input, plus the committed corpus.

### 9.2 Differential parser oracle

**Why it is load-bearing.** Every certificate the trust manager parses has already been accepted by
the platform: presented chain, platform-built chain, anchors and preloads all arrive as platform
`X509Certificate`s and are re-read through `getEncoded()` (SunJSSE returns the stored bytes;
Conscrypt returns `i2d_X509` of the parsed object). **The read fallback**: on the JDK, a certificate whose
`getEncoded()` is `ParseFailed(STRUCTURE)` is read once more through the **platform canon**, `SEQUENCE {
getTBSCertificate(), the signature AlgorithmIdentifier TLV located in it, BIT STRING { 00, getSignature() } }` with
minimal new headers and the padding bits cleared, as `getSignature()` returns them. The locator reads one-octet
identifiers and definite lengths of at most four octets: after the TBS header it skips a first element with
identifier `A0`, then one element, and takes the next if its identifier is `30`. The producer's parse needs at least
that much there (an optional `[0]`, an INTEGER, a SEQUENCE; ct-go, its `lax` retry and zcrypto reject indefinite
lengths and lengths of 2^31 or more, Appendix A). The platform canon is the bytes the JDK verifies the signature
over, so a valid signature makes it what the CA signed, however the presented encoding was altered (#49). That covers
the path the platform verified and, since the walker verifies over the same `Cert.tbs` and `Cert.sig`, every
certificate on a link the walker verified; an anchor is read as the JDK's own view of it. Where the
AlgorithmIdentifier cannot be located, `encoded` stays `getEncoded()`: a leaf is `PARSE_FAILED(STRUCTURE)` and a
candidate is dropped, and a getter that throws has the same outcome and is counted `unavailable` (below). The
platform canon is defined as its own `canon(encoded)`, and the replay asserts that the reference view, where it
locates it, yields the same. A certificate so read carries no `AlgorithmIdMismatch` finding unless its TBS
AlgorithmIdentifier is not minimal DER. Where the bytes read stand for the certificate, and where `getEncoded()`
still does, is §5.3's. Conscrypt needs no fallback: its TLV parse is strict DER (no indefinite or non-minimal lengths).
`PARSE_FAILED` on the leaf allows in `DEFAULT` and an unparseable candidate is dropped (decision, §10 item 8). Two
failure classes matter: (i) a certificate the platform accepts and revokt rejects is unchecked (a leaf) or invisible
as an issuer (a dropped candidate ends the walk `NO_ISSUER`, which allows in `DEFAULT` for every leaf under that CA),
and a leaf revokt parses but cannot show producer-keyable is a sub-case, unchecked but never mis-answered (the D8
gap); (ii) a certificate from which revokt extracts **different bytes** than Mozilla's producer used to form the key
(`SHA-256(SHA-256(issuer SPKI TLV) ‖ serial content bytes)`) or different SCT timestamps queries the wrong key or the
wrong coverage, which can hide a revocation or, for a key outside the filter's universe, return an arbitrary answer.
The oracle bounds both.

**Parser contract under test.** One minimal parse of `Certificate` → `tbsCertificate` producing
`rawSerial` (INTEGER content bytes as encoded, sign and leading zeros preserved), `rawSpki` (complete
TLV), `rawSubject`, `rawIssuer` (complete Name TLVs), SKI/AKI, TBS `signature` and outer
`signatureAlgorithm` TLVs, the extension table (OID, critical, value bytes, offsets), and the SCT
pairs `(logId, timestamp)` as the **union** over every extension with OID `1.3.6.1.4.1.11129.2.4.2`
whose list parses under the SCT-list rule here. The rule follows `x509-parser` 0.18.1's `parse_ct_signed_certificate_timestamp_list` (oracle 3a; Appendix A pins it) except at the inner identifier.

- **Inner header.** The extension value must begin with the identifier octet `0x04` (universal, primitive `OCTET STRING`) and a definite length. The length is either short form, or long form `0x81`–`0xFE` followed by that many length octets, with leading zero octets allowed and the value below 2^64 and not past the end of the extension value; `0x80` and `0xFF` fail the list.
- **Divergence from 3a.** 3a also accepts tag number 4 in any class and in multi-octet form (asn1-rs checks the tag number only). That wider acceptance is the recorded D3 divergence class `3A_HEADER_LAX`. D2 expects no pairs from such an extension, so revokt yielding none is still asserted, never skipped. webpki yields none either, and Firefox rejects the certificate (D3, revision 46).
- **Items.** The inner content begins with a `u16` list length that must fit the content. Items are read only within that declared region. Each is a `u16`-prefixed item, whose length must fit the region, of: any version byte, 32-byte log id, u64 timestamp, `u16`-prefixed extensions, hash and signature algorithm bytes, `u16`-prefixed signature (a zero-length signature is accepted).
- **Ignored bytes.** Bytes after the inner `OCTET STRING`, after the declared region and inside an item after its signature are ignored and never parsed as items.
- **Partial lists.** The list keeps every item before the first item that fails to parse; a later item of length 0 ends the list like any failing item. It fails when its first item fails, which includes an empty list and a first item of length 0. A list that fails contributes nothing.

`NO_SCTS` iff the union is empty (the union is monotone under "one covered SCT
suffices" and SCTs never enter the key).

**Trailing elements are tolerated at least where the JDK's `X509CertInfo` tolerates them**; ct-go ignores extra elements at the end of a SEQUENCE, and every ignored element puts the leaf outside the keyability profile (K2; oracle 4 records what the producer does, D8). The JDK behaviour was probed on JDK 21 (Appendix A), and each case below is a D7 entry:
- **After `subjectPublicKeyInfo` in `tbsCertificate`,** the remaining elements are read in turn:
  - the next is `issuerUniqueID` if it is context tag 1 in either form (its content is not inspected);
  - then `subjectUniqueID` if it is context tag 2 in either form (likewise);
  - then `extensions` if it is a constructed context tag 3.

  The first element that does not fit ends the read. It must be a well-formed TLV; it and everything after it are ignored, and the bytes after it are not parsed and need not be TLVs. After `extensions`, the remaining bytes are ignored unparsed.
- **Inside `[3]`,** the bytes after the `Extensions` SEQUENCE are ignored unparsed.
- **Inside an `Extension`,** the bytes after `extnValue` are ignored unparsed.

- **Inside `[0]` the parse stays strict:** nothing may follow the version INTEGER, and anything there is `STRUCTURE`. The JDK accepts it, but ct-go's explicit-tag walk does not bound `[0]` by its length (`parseField` advances by the inner element only), so ct-go reads the elements after the INTEGER as the next TBS fields. It rejects most such inputs. One it accepts carries an SPKI and other fields the JDK does not read, which matter when the certificate is an issuer, while the keyed serial comes from the length-bounded stdlib re-parse (Appendix A) and is the JDK's. Whether the producer keys the same bytes therefore depends on crafted content, and the case is excluded by rule: such input is D1-dom (D1 below), never queried. Confirmed by running the producer (Appendix A).

Ignored bytes contribute no field. Their offsets are recorded, and any ignored element makes the leaf unkeyable (K2). For example, `subjectUniqueID` before `issuerUniqueID` ends the read at the second, so the `extensions` after it are not read, as the JDK reads it. A constructed `[1]` then `[3]` yields the JDK's extensions where ct-go's struct walk yields none (outside the profile under K2, and a D8-gap entry where oracle 4 keys it); revokt takes the JDK's view, which only adds extensions and SCTs.

**Where revokt is more lenient than the JDK** (the platform rejects such input first, so D1 is unaffected):
- revokt does not gate on the version. The JDK rejects a v1 certificate with anything after `subjectPublicKeyInfo`, and a v2 certificate with any element after the unique IDs (a NULL or `extensions`).
- revokt does not inspect unique-id content. The JDK requires BIT STRING content.
- revokt's time decoding is more lenient, as follows.

**Times.** `notBefore` and `notAfter` decode at least as the JDK's `DerValue` does:
- seconds optional;
- `Z` or `±hhmm` in both `UTCTime` and `GeneralizedTime`;
- `GeneralizedTime` fractions after `.` or `,` of any length, truncated to milliseconds;
- a day of 1 to 31 in any month, a day past the month's end rolling into the next month as the JDK's lenient calendar does (2026-02-31 is 2026-03-03, 2026-04-31 is 2026-05-01).

Conscrypt 2.7.0 and 2.8.0 drop a `UTCTime` differential and reject a `GeneralizedTime` one (`CONSCRYPT_TIME_OFFSET`, D2),
and read a time before 1582-10-15 in the Julian calendar (`CONSCRYPT_TIME_JULIAN`, D2).

revokt also accepts optional minutes, second 60 (the first second of the next minute) and an absent zone, which it takes as UTC. A time outside these forms is null; only platform-rejected input reaches that. A rule that needs a null time fails closed: M4's distrust-after treats a null `notBefore` as after any distrust date.

**The unsigned headers.** The JDK verifies the signature over `DerValue.toByteArray()` of the TBS: its content under
a minimal definite header, after `DerIndefLenConverter` has re-encoded every indefinite length reachable from the TBS
through indefinite elements only. `getEncoded()` keeps the presented bytes. So the `tbsCertificate` header is not
signed, nor is any header on that indefinite chain (JDK 17, 21 and 27; Appendix A). A non-minimal definite header
inside the TBS, and an indefinite header under a definite parent, break the signature. The parser therefore accepts
these forms (indefinite lengths only at the first two and on the indefinite chain below them):
- the `tbsCertificate` header (`30`) in any definite form, or indefinite;
- the outer `signatureAlgorithm` (`30`) in any definite form, or indefinite; its content is parsed only for the §5.1
  `AlgorithmIdMismatch` comparison, where any form other than minimal DER counts as a mismatch, and yields no field;
- `signatureValue` as a primitive BIT STRING (`03`) with a definite length of any form. An indefinite `signatureValue`
  is `STRUCTURE`: JDK 17, 21 and 27 reject it (JDK 11, below the floor, verifies some; Appendix A).

An indefinite element at these two places is delimited and re-encoded as the JDK's converter does:
- Each TLV header met in the reading below, other than end-of-contents, is read as the JDK's converter reads it: one
  tag octet, whatever its low five bits, then a length octet that is `80`, short form, or `81` to `84` followed by
  that many octets. A definite length must be minimal; a non-minimal length, or any other length octet, is
  `STRUCTURE`: under the TBS it makes the JDK's message differ from the signed bytes, and under the outer
  `signatureAlgorithm` the JDK fails to parse the certificate (Appendix A). A multi-octet tag is so misread; it
  survives in `Cert.tbs` only where the TBS rules after this list leave bytes unparsed.
- From its first content octet, TLVs are read in turn. Every byte up to its end-of-contents is part of a TLV,
  including elements the trailing-element rule ignores.
- `00 00` at a tag position closes the innermost open indefinite element.
- A TLV whose length octet is `80`, constructed or primitive, opens a nested indefinite element whose content is read
  the same way.
- A definite TLV is skipped whole by its length, so `00 00` inside it is never end-of-contents.
- The re-encoding replaces each indefinite header and its end-of-contents octets with a minimal definite header, and
  copies every other octet unchanged.

`Cert.tbs` is the TBS so re-encoded, under a minimal definite header; for a definite TBS that is its content byte for
byte. It is the message the walker verifies, the input of every TBS field and of K1–K8, and the first element of
`canon(encoded)`. D2 requires it to equal oracle 1's `getTBSCertificate()`. `Cert.sig` is the `signatureValue` content
after its unused-bits octet u, with the last octet's u low bits cleared, as `DerValue.getBitString` returns it. Forms
the parser accepts and the JDK rejects are harmless for D1 and are not listed as accepted by the platform: a length of
five or more octets on the TBS or `signatureValue` header; an empty `signatureValue`, more than 7 unused bits, or
u > 0 with no further octet; outer AlgorithmIdentifier content the JDK refuses.

**Everywhere else the parse is structurally strict.** Lengths must be definite (except on the indefinite chain under the unsigned headers above), and tags and lengths well-formed (the SCT list's inner length follows the rule above). `Certificate`, `[0]` (exactly its INTEGER), `Validity`, the `Extensions` SEQUENCE and each `Extension` before its `extnValue` hold exactly their elements, and no bytes may follow `Certificate`; **non-minimal definite lengths are
accepted for extraction**, and the JDK preserves them through `getEncoded()`; whether the leaf is queried is the keyability profile's (below).

**`producerKeyable` is a conservative keyability profile, not a model of the producer.** It is true only when every
clause K1–K8 holds, and false for everything else, including certificates the producer does key (the D8 gap). It is
evaluated for the leaf only.

It reads the signed content of `tbsCertificate` alone. Nothing outside that content is signed, so a network attacker
can re-encode the envelope and the platform still verifies the certificate (Appendix A): the `tbsCertificate` header
itself, the outer `signatureAlgorithm` in any length form with its NULL parameters flipped, the `signatureValue`
header in any definite length form, and the RSA signature's unused-bits octet. The producer keyed the bytes
the CA logged, not the presented envelope. Oracle 4 therefore runs on `canon(encoded)`, which is
`SEQUENCE { the TBS re-encoded by the unsigned-header rule above, the signature AlgorithmIdentifier TLV taken from
that re-encoded TBS, a BIT STRING with zero unused bits holding the `signatureValue` content after its unused-bits
octet, with its padding bits not cleared }`, each located by the reference view (3a, else 3b), the TBS re-encoded by
3b's implementation of the rule, never by revokt's parser, so `canon` exists for inputs revokt fails to parse; for a
parsed input its first element is `Cert.tbs` (D2). The new outer SEQUENCE and BIT STRING headers are minimal; the
re-encoded TBS, and the AlgorithmIdentifier TLV from it, are copied byte for byte.

The producer path is `types.ParseCertificate` (certificate-transparency-go, a `lax` retry, then zcrypto) →
`NewSerialFromCertificate` (a stdlib `encoding/asn1` re-parse of the raw TBS). It keys on the serial's INTEGER content
and the SPKI TLV (Appendix A). `types.ParseCertificate` keeps ct-go's certificate whenever ct-go returns one, so each
clause is stated against ct-go's strict (non-`lax`) parse and the stdlib re-parse only. No clause relies on `lax` or
zcrypto, and D8 requires the strict path, so dropping either fallback cannot break D8.

The baseline is Go's checks with narrowed value domains, not X.690 DER everywhere. Go keys honest encodings that DER
forbids, such as an explicit `FALSE` BOOLEAN or an unsorted `SET OF`. A profile stricter there would reject valid
certificates under `STRICT`.
- **K1 headers**: every TLV header in the content of `tbsCertificate` (not its own header, which is unsigned) outside
  an opaque region, read on `Cert.tbs`, has a single-octet tag and a minimal definite length below 2^31.
  - The opaque regions are the content of each `extnValue` whose OID is not in K8's list: the SCT list, the
    precertificate poison, the RFC 3779 extensions and every unknown extension. There ct-go either reports errors as
    non-fatal or does not look. The list is matched on canonical OID content; a non-minimal spelling of a listed OID is
    opaque here and fails K4.
  - Inside them only the §9.2 SCT-list rule applies, and only for extraction.
- **K2 TBS shape**:
  - `[0]` is absent, or is constructed (`A0`) and holds exactly one INTEGER with content `00`, `01` or `02`; when `[3]`
    is present, `[0]` is present and holds `02`.
  - There is no `issuerUniqueID` or `subjectUniqueID`.
  - `[3]` is absent, or is constructed and holds exactly one non-empty `Extensions` SEQUENCE.
  - No element is one the trailing-element rule ignores, and no bytes follow an `extnValue`.
  - Each `AlgorithmIdentifier` is an OID and at most one further TLV. `Validity` holds exactly two times.
  - Every BIT STRING the profile reads is primitive, and its content is an unused-bits octet u ≤ 7, followed by at
    least one octet when u > 0, with the last octet's u low bits zero (Go's `parseBitString`; ct-go's keyUsage parse is
    fatal on anything else, with no `lax` retry).
  - Each name is a `SEQUENCE OF SET OF SEQUENCE { OID, value }`. Each `Extension` is an OID, an optional BOOLEAN and a
    primitive `OCTET STRING`. A repeated extension OID is allowed, as ct-go allows it, and each copy is checked on its
    own (K8).
- **K3 integers**: the serial's content is non-empty and minimal. Any sign, zero, and any length up to `MAX_CERT_BYTES` are
  accepted, because the producer keys them, mozilla::pkix and BoringSSL accept them, and private PKI issues them.
  Every other INTEGER the profile reads is non-empty, minimal and in the range its clause states.
- **K4 OIDs**: every OID the profile reads is non-empty, with minimal subidentifiers each below 2^31, the first
  (40X + Y) included. That covers algorithms, attribute types, extension IDs, curves, EKU purposes, policies and access
  methods. Minimality is stricter than the pinned ct-go, whose `parseBase128Int` keys a leading `80`; where the platform
  accepts a leaf with such an OID, it is a D8-gap entry by rule, and its record carries a written justification.
- **K5 names**: each attribute value is one of:
  - a `PrintableString` in Go's set: letters, digits, space, `'()+,-./:=?`, and the `*` and `&` Go also accepts;
  - a `UTF8String` that is valid UTF-8;
  - an `IA5String` of ASCII octets.

  Any other type is outside the profile.
- **K6 times**: `UTCTime` is `YYMMDDHHMMSSZ` and `GeneralizedTime` is `YYYYMMDDHHMMSSZ` with a year from 1950 to 9999.
  The month is 1–12 and the day falls within the Gregorian month; a `UTCTime` year below 50 is 20YY, else 19YY. The
  hour is at most 23, and the minute and second at most 59. revokt's own §9.2 time decoding is more lenient by design,
  and the profile does not reuse it.
- **K7 key**: the SPKI is an `AlgorithmIdentifier` and a BIT STRING with zero unused bits. The key is one of:
  - `rsaEncryption` with NULL parameters and `RSAPublicKey { n > 0, 0 < e < 2^31 }` filling the key, its three headers
    each with a single-octet tag and a minimal definite length, and both INTEGERs minimal (ct-go parses it out of the BIT
    STRING, which K1 does not walk);
  - `id-ecPublicKey` with `namedCurve` P-256, P-384 or P-521 and an uncompressed point `04 ‖ X ‖ Y` of the curve's
    length, with X and Y below p and on the curve;
  - Ed25519 with absent parameters and 32 octets.

  Any other algorithm is outside the profile, including those ct-go keys without inspecting them, so ct-go adding a
  parser later cannot break D8.
- **K8 extensions**: each extension ct-go parses with a fatal return is walked whole under K1 and must match the
  table's grammar for its OID:
  - keyUsage: a BIT STRING under K2's rule (so `03 00` and `03 01 05` are outside the profile);
  - basicConstraints: `SEQUENCE { cA BOOLEAN optional, pathLen INTEGER 0..2^31−1 optional }`;
  - subjectAltName: non-empty, with only `dNSName` and `rfc822Name` of ASCII octets and `iPAddress` of 4 or 16 octets;
  - cRLDistributionPoints: each point `[0] { [0] GeneralNames }`, holding only `[6]` URIs of ASCII octets;
  - authorityKeyIdentifier: exactly `SEQUENCE { [0] }`, primitive;
  - extKeyUsage: a non-empty `SEQUENCE OF OID`;
  - subjectKeyIdentifier: a primitive `OCTET STRING`;
  - certificatePolicies: `SEQUENCE OF SEQUENCE { OID, … }`;
  - authorityInfoAccess: non-empty, each entry `SEQUENCE { OID, [6] }` with ASCII octets.

  nameConstraints and subjectInfoAccess put the leaf outside the profile by their presence. A BOOLEAN anywhere is
  `00` or `FF`.

**The table is the proof.** Each clause's row cites the certificate-transparency-go and Go `encoding/asn1` return sites
it covers: every fatal return of `ParseCertificate`, `parseCertificate`, `parsePublicKey` and the dispatched extension
parsers, plus the per-type checks. It is pinned to the producer's toolchain: the `mozilla/crlite` commit, the
certificate-transparency-go and zcrypto versions, and the Go release (Appendix A). The argument runs:
1. Under K1 and K2, ct-go's struct walk visits exactly the TLVs revokt reads.
2. Every visited header is minimal, and every leaf decode maps to a clause.
3. So ct-go's strict parse succeeds, `lax` never runs and zcrypto is never reached.
4. The stdlib re-parse then sees minimal headers and an exact `[0]`, so the keyed serial is `rawSerial` and the keyed
   SPKI is `rawSpki`.

A pin bump re-runs the audit as a diff of those files. Oracle 4 and fuzzing test the table; they do not replace it. A
violation of D8's gated direction is a P0, fixed by narrowing the profile or adding the missed check, never by
weakening D8. A widening is allowed only under D8. Extraction is semantically lenient: unknown OIDs, unknown critical extensions, non-DER
times, any string type, negative or oversize serials and duplicate extensions are accepted and
reported, never rejected as `ParseFailed`; whether such a leaf is queried is the profile's. Result: `Parsed | ParseFailed(reason)`; no other exception may escape.

**Oracles.** Each is wrapped to `Accept(fields, encoded) | Reject | Crash` by the rules in the table.

| # | Oracle | What it answers | Accept | Reject | Crash |
|---|---|---|---|---|---|
| 1 | `CertificateFactory.getInstance("X.509")`, `SUN` provider (the same `X509Factory` SunJSSE's `CertificateMessage` uses), per JDK in the matrix | platform acceptance on the JVM; `encoded = getEncoded()`, or the platform canon where revokt's parse of that is `ParseFailed(STRUCTURE)` (the read fallback above) | `generateCertificate` returns | `CertificateException` | any other `Throwable` |
| 2 | Conscrypt `CertificateFactory` (BoringSSL): `conscrypt-openjdk-uber` versions in the matrix; the **platform** Conscrypt on the instrumented tier | platform acceptance on Android; `encoded = getEncoded()` (`i2d_X509`) | as above | as above | as above |
| 3a | `revokt-oracle`: `x509-parser` on one certificate | raw `serial`, SPKI TLV, names, extension table, SCT list or `ParseError` or duplicate-extension error; the TBS TLV re-headed to minimal, its signature AlgorithmIdentifier and the `signatureValue` octets, for `canon` | `Ok` | `Err` | caught panic |
| 3b | `revokt-oracle`: a minimal independent TLV locator (delimit the `tbsCertificate`, the outer `signatureAlgorithm` and the `signatureValue` (an indefinite `signatureValue` is not located) and re-encode the TBS under the §9.2 unsigned-header rule, implemented independently of revokt; then walk the re-encoded TBS, with `[0]` read bounded as the JDK reads it, the TBS tail under the §9.2 trailing-element rule so extensions the JDK does not read are not located; slice from the re-encoded TBS the serial content, SPKI TLV, subject, issuer, TBS signature AlgorithmIdentifier, extension values by OID, the TLS-encoded `(logId, timestamp)` prefix of each SCT the §9.2 SCT-list rule keeps, under the same header, item and prefix rules; output the re-encoded TBS and the content of a definite `signatureValue` after its unused-bits octet, for `canon`; no other semantics; 3a needs no change, since x509-parser rejects every indefinite length, but its TBS is re-headed to minimal for `canon`) | raw bytes where 3a rejects, and the `canon` parts | located | not located | caught panic |
| 3c | `revokt-oracle`: webpki through `upki`'s `RevocationCheckInput::from_certificates` on `[cert, syntheticIssuer]` | the `rustls-upki` verifier's (webpki's) view of the certificate, no longer any engine's input (§3.2); **never a precondition** | `Ok` | `Err` | caught panic |
| 4 | **Producer**: Mozilla's `crlite/go/types` (`ParseCertificate`, `NewSerialFromCertificate`, `RawSubjectPublicKeyInfo`, `IsPreIssuer`) built as a Go CLI, pinned to the `crlite` commit of the filters in the fixture set; always out of process (fuzzing and corpus admission), batched over a pipe | whether the producer can key `canon(encoded)` (above), with which bytes and through which path (`ct` for certificate-transparency-go's strict parse, that is `ParseCertificate` without a `lax` retry returning a certificate, its non-fatal x509 errors included, `lax` for ct-go only through a `lax` retry, `zc` for the zcrypto fallback) | both calls return | a `ParseCertificate` error, or a panic anywhere in the producer (the shim recovers around the whole call) | unrecovered; counts as `Reject` under D8 |

3b's `CANON` reply (its `canon` parts located, its walk failed) is not located for D2's reference and still supplies
`canon`. A getter that throws on an accepted object (Conscrypt `getPublicKey()` on a damaged modulus is
common) marks that field `unavailable`: the comparison is skipped and counted. Oracle `Crash`
never fails revokt's gate, except oracle 4's under D8, where it counts as `Reject`; it is reported upstream. A `Crash` or `unavailable` rate above 0.1 % on
the secondary corpus fails the job as infrastructure. A Rust or Go abort that kills the JVM is
attributed by re-running the input through the out-of-process CLI before it is filed against revokt.
Java field normalisation: `getSerialNumber()` by value (`BigInteger` drops padding and sign-extends);
`getPublicKey().getEncoded()` by SHA-256 against `rawSpki` with a recorded allow-list of
re-encoding cases, two rules on the bytes alone: `rawSpki` with every header minimal (Java re-encodes RSA parameters),
and `rawSpki` with every header minimal and NULL parameters added to an AlgorithmIdentifier that has none, nothing
else differing (a generic key of an algorithm the platform does not know, revision 41); the getter is never hashed for
a lookup, since every SPKI hash revokt computes is `SHA-256(rawSpki)`; `getIssuerX500Principal()` and
`getSubjectX500Principal()` as `X500Principal(raw).getName(CANONICAL)`; `getExtensionValue(oid)`
unwrapped; `getCriticalExtensionOIDs()`; `getNotBefore()`/`getNotAfter()` in epoch milliseconds against
`notBefore`/`notAfter`, where oracle 2's difference on a `UTCTime` with a `±hhmm` differential (read from the input
bytes) is recorded as `CONSCRYPT_TIME_OFFSET` (a `D3_DIVERGENCE` record per Conscrypt version, revision 41) when oracle
2's value is revokt's plus the signed differential, revokt's being the local time minus the differential ("Times"),
and, on a matrix run, revokt's equals oracle 1's: Conscrypt drops the differential; oracle 2's difference on a `Z` time
without fractional seconds before 1582-10-15 is recorded as `CONSCRYPT_TIME_JULIAN` (a `D3_DIVERGENCE` record per
Conscrypt version, revision 44) when oracle 2's value is the time's fields read in `java.util.GregorianCalendar`'s
Julian–Gregorian hybrid and revokt's, the proleptic Gregorian reading, equals oracle 1's; on oracle 1,
`id-pkix-ocsp-nocheck`'s value is expected empty (in effect, presence only), since the JDK reports it empty whatever
the certificate carries (revision 44). Raw-byte equality is asserted against 3a, else 3b.

**Properties.** For each platform oracle *i* ∈ {1, 2} and each version *v* in the matrix:
- **D1 leniency (security)**: `Accept_i,v(b)` ⇒ `parse(encoded_i,v)` is `Parsed`, for every input in
  the D1 domain: platform-accepted and producer-keyable (oracle 4 `Accept` on `canon(encoded)`, through any path (`ct`, `lax` or `zc`), with serial and SPKI equal to the
  reference view's, 3a else 3b). This is the producer's keyability, not revokt's profile, so the domain includes the D8 gap
  and every issuer; over its end-entity inputs each is exactly one of: keyable as a leaf (`producerKeyable`), a D8-gap
  entry, or a D1 violation. An input with any bytes after the version INTEGER inside `[0]` is D1-dom whatever
  oracle 4 keys. A violation is a P0 and
  a security advisory class once the input is CA/B-lint clean.
- **D1-dom (recorded)**: platform-accepted inputs on whose `canon(encoded)` oracle 4 rejects, or accepts with key bytes other than the
  reference view's, and any input with content after the INTEGER inside `[0]`, excluded by rule (the `[0]`
  flattening above). That case is excluded conservatively, not because its key is outside the universe. It costs
  `PARSE_FAILED` for such a leaf and a dropped candidate for such an intermediate, both allowing in `DEFAULT`; such
  certificates are not CA/B-conformant. Also by rule, a JDK-accepted input for which no platform canon can be built
  (the read fallback above) is D1-dom: the producer's parse needs at least the forms the locator reads up to the
  signature AlgorithmIdentifier, so it cannot key a TBS in which the locator finds none. A getter that throws there is
  counted `unavailable`, not D1-dom: D1 is skipped for that input, which counts toward the 0.1 % infrastructure
  threshold. For the other D1-dom inputs, no filter can contain such a certificate and its key is outside the filter's
  universe, so it must never be queried (a query would answer arbitrarily, a false `REVOKED` at about 2^-(rank+1) and
  with high probability under an inverted issuer block); D8's gated direction enforces that; each entry is kept with
  the producer's error (a by-rule entry with its rule) so a producer change can be re-evaluated.
- **D8 producer-keyability (0.1 gate, zero tolerance, one direction)**: `producerKeyable(encoded)` ⇒ oracle 4 on
  `canon(encoded)` returns `Accept` through certificate-transparency-go's strict parse (`ct`), with serial content equal to
  `rawSerial` and SPKI equal to `rawSpki`.
  - It holds for every input where `parse(encoded)` is `Parsed`, platform-accepted or not (on `b` when no platform oracle
    accepts it), on every corpus (committed,
    boundary and secondary) and on the fuzz corpus.
  - An oracle-4 `Crash` counts as `Reject`. Requiring the strict `ct` path means a producer that drops the `lax` retry
    or the zcrypto fallback cannot break D8.
  - The predicate has no value on `ParseFailed`. Go ignores trailing `SEQUENCE` elements; revokt ignores them only
    where the rule above does and elsewhere rejects them as `STRUCTURE`; over-cap inputs never reach the parser.
    Oracle-4 outcomes on `ParseFailed(STRUCTURE)` inputs outside the D1 domain are recorded as information. Inside the
    domain they are D1 violations.
  - The **boundary corpus** is committed inputs at each clause's edge, accept-side unless marked, each with its oracle-4
    golden:
    - OID arcs at 2^31 − 1, and a first subidentifier at the limit;
    - 29 February in 2000 and in 2024, and as `UTCTime` year 52;
    - the years 1950, 2049, 2050 and 9999;
    - RSA e = 2^31 − 1, and an EC coordinate of p − 1;
    - an explicit `FALSE`, a negative serial and a 21-octet serial;
    - `*` and `&` in a PrintableString;
    - NIST and JDK-generated EC points, and single-bit flips of them;
    - the unsigned-header forms: a `tbsCertificate` header with a long-form length carrying leading zero octets, and
      one with an indefinite length, each with the base certificate's key bytes and a `VERIFIED` link;
    - reject-side, each outside the profile with its golden: keyUsage `03 00` and `03 01 05`, which only zcrypto keys.
- **D8 gap (measured)**: end-entity inputs in the D1 domain where `parse(encoded)` is `Parsed` and `producerKeyable`
  is false. The issuer corpus and CA certificates are never counted, since `producerKeyable` is a leaf predicate.
  - Each record carries oracle 4's path (`ct`, `lax` or `zc`), the first failing clause and the pinned zlint result,
    whatever its class; an entry admitted for that reason alone has class `KEYABILITY_GAP`.
  - They are never queried: `DEFAULT` allows them and `STRICT` rejects them (§10 item 8).
  - The gap is zero on the committed real end-entity fixtures (the parser's real-certificate test resources).
  - The PR replay fails on a gap entry in the committed corpora that is not in the recorded baseline, until its record
    carries a written justification.
  - A gap entry with no zlint error is a profile defect. It blocks the release until the profile is widened under D8
    or the entry is justified. Revision 46 keeps K6, K7 and K8 narrow for those found so far (#57): the lint-clean
    `x509-limbo` entries at SAN, AIA, nameConstraints, extKeyUsage and K7 (and the P-192 key, which zcrypto cannot
    parse), and the seed corpus's year-0000 and 0001 times; their written justifications stand.
  - The count by clause over the seed corpus's CT leaves of index issuers is reported in each release's notes and in
    `docs/dev/status.md`. A leaf is of an index issuer when the test JDK verifies its signature under the key of an
    issuer-corpus certificate whose SPKI hashes to a key of the fixture generation's indexes and whose subject is the
    leaf's issuer. The filters hold no revocation of any other issuer's leaf, so a gap entry there leaves no revocation
    unchecked (revision 45). A gap leaf is `PARSE_FAILED(PRODUCER_UNKEYABLE)` whatever its issuer; a keyable leaf of
    another issuer would be `NOT_ENROLLED`, which `STRICT` also rejects. The two differ only where `NOT_ENROLLED` is
    exempted, as under `anchorIn` for a private anchor, since `PARSE_FAILED` is not exemptable; revision 34's caveat for
    a gap entry under a private anchor (§10 item 8) covers that case.
  - **Re-decision**: if gap entries among the seed corpus's unexpired CT leaves of index issuers exceed 10^-4 of them
    once at least 100 000 leaves are pinned (re-evaluated whenever a later pin changes them), exact keyability is
    reconsidered in a spec revision before 0.1 ships.
- **D1-raw (informational)**: inputs where `encoded ≠ b`, or `parse(b)` fails while
  `parse(encoded)` succeeds. This is the `EvaluationRequest.presented` raw-DER surface (§4), documented,
  not gated.
- **D2 extraction agreement (security)**: on `parse(encoded_i,v)`: `Cert.tbs` equals `canon(encoded)`'s first element
  and oracle 1's `getTBSCertificate()`, while a difference from oracle 2's is recorded as a divergence, not a violation
  (Conscrypt verifies over the presented TBS TLV, so a difference marks an input it cannot verify); `Cert.sig` equals
  `canon(encoded)`'s signature octets with the last octet's u low bits cleared, u being `encoded`'s unused-bits
  octet as located by 3a, else 3b;
  `rawSerial` equals oracle 4's serial bytes and `SHA-256(rawSpki)` equals `SHA-256` of oracle 4's SPKI where `producerKeyable` (implied by D8's gated direction, restated so that a mismatch names the field);
  `rawSerial`, `rawSpki`, `rawSubject`, `rawIssuer`, extension values and the SCT pair set equal 3a's
  where 3a accepts, else 3b's. The expected SCT pair set is the union over SCT extensions of a per-extension
  expectation: the reference's pairs for that extension, or ∅ when the extension value's first octet is not `0x04`.
  That octet is read by 3b's locator, never by revokt. An extension whose expectation is ∅ while 3a yields pairs is
  recorded as `3A_HEADER_LAX`, so the comparison substitutes ∅ rather than skipping. Where 3a takes as extensions an
  element with tag number 3 that is not a constructed context-specific `[3]` (a primitive `[3]`, or tag number 3 in
  another class; decided by 3b's TBS walk), the reference extension table and SCT pairs are the §9.2 read (∅),
  recorded as `3A_TBS_LAX`; the normalised Java fields equal oracle *i,v*'s, except that a `notBefore`/`notAfter`
  difference from oracle 2 meeting the `CONSCRYPT_TIME_OFFSET` or `CONSCRYPT_TIME_JULIAN` condition (Java field
  normalisation, above) is recorded, not a violation. A violation is a P0.
  The count of platform-accepted inputs whose `encoded` has no raw-byte reference (3a rejects, and 3b does not locate
  it: its re-encoding or its walk fails), other than inputs revokt does not parse on whose `canon(encoded)` oracle 4
  rejects or for which no platform canon can be built, is a gate metric and must be zero on the committed corpora.
- **D3 SCT classification**: mapping from 3a: no extension → `NO_SCTS`; `ParseError` → `NO_SCTS`
  (an empty list is a `ParseError`; `x509-parser` 0.18.1 never returns `Ok([])`); `Ok(list)` → pair-set equality (D2), with the per-extension ∅ expectation for an inner identifier other than `0x04` (`3A_HEADER_LAX`); 3a's duplicate-extension error →
  the union rule, recorded as a divergence class. Firefox's divergences and 3c's errors are
  recorded as divergence entries, never gate failures. Firefox's decoder fails the whole list on version ≠ 0, trailing
  bytes in the OCTET STRING and per-item length errors; mozilla::pkix rejects the certificate itself where an
  end-entity certificate's SCT `extnValue` is not exactly one DER OCTET STRING (a non-minimal length on the inner
  OCTET STRING, or bytes after it) and where it carries a second SCT extension (revision 46). A divergence is recorded
  where revokt extracts pairs, so every recorded one is in the more-checking direction (revokt queries where Firefox
  or the `rustls-upki` verifier would not); where revokt's list fails as well, §10 item 7 applies. Firefox is not an
  oracle and is not run in CI; its stricter behaviour is argued here, and its divergences are hand-recorded
  `D3_DIVERGENCE` entries (record schema) in the D7 corpus. A 3c error where revokt yields pairs is recorded, never a gate failure. A 3c pair that
  revokt does not yield blocks the release until a spec revision resolves it; revokt follows §9.2, never 3c. A
  further class, also against 3a only, is `3A_TBS_LAX`: 3a takes as extensions an element with tag number 3 that is not
  a constructed context-specific `[3]` (`x509-parser` checks the tag number only), which the JDK and revokt do not, so
  D2's reference for that certificate's extension table and SCT pairs is the §9.2 read (∅), asserted, not skipped. A
  separate class, against 3a only, is `3A_HEADER_LAX`: 3a yields pairs under an inner identifier other than
  `0x04`; webpki and revokt do not, and Firefox rejects the certificate. revokt's reading is equivalent to issuing without SCTs. For a key outside the filter's universe
  a query answers arbitrarily. That is the M1 unverified-SCT residual (§10 item 7), unchanged by revision 33,
  because every pair set revision 33 newly accepts is also produced by some well-formed list.
- **D4 strictness bound (informational)**: revokt `Parsed` while every oracle rejects; the platform
  rejects such input first.
- **D5 crash-freedom and budgets**: no exception other than `ParseFailed`; allocation ≤ budget;
  `-max_len` = `RevoktLimits.MAX_CERT_BYTES + 1` (262145), so the over-cap behaviour is asserted;
  parse steps ≤ 8·len + 1024, asserted by a step counter in the replay; `-timeout=1`.
- **D6 determinism and round trip**: `parse(b) == parse(b)`; offsets of TBS fields index `Cert.tbs` from its tag
  octet and re-slice it to the reported values, and, shifted by the TBS content's start in `b` less `Cert.tbs`'s header
  length, also re-slice `b` when the TBS header is definite; `parse(encoded_i,v)` has the same status and fields as
  `parse(b)` whenever both are `Parsed`, for oracle 1 and for oracle 2 on the uber artifact and on the platform tier.
- **D7 leniency corpus**: a committed corpus of real-world oddities, each entry carrying the
  recorded outcome of every oracle version and revokt's required outcome (the SCT-list outcomes named below, which
  follow from the rule above, and every outcome stated with an entry are normative; for an entry with no stated
  outcome the corpus is the record): negative serial, serial over 20 bytes, serial with leading
  zeros, TBS/outer algorithm mismatch (NULL vs absent), `GeneralizedTime` with fractional seconds,
  `UTCTime` used for a date in 2050 or later, PrintableString/UTF8String/TeletexString/BMPString
  names, an empty subject, duplicate extension OIDs, **two SCT extensions** (empty list first,
  covered SCT second → union queries), on which Firefox rejects the certificate (`FIREFOX_SCT_STRICT`), an unknown critical extension, an SCT list whose declared
  length is longer than its content (the list fails) or shorter (the items that fit extracted), a malformed first SCT followed by valid ones (the list fails), a non-minimal length on the SCT extension's inner OCTET STRING, `81 nn` with nn < 0x80 and `84 00 00 00 nn` (required outcome: `Parsed`, the list's SCTs extracted, `producerKeyable` unaffected because the SCT extension is opaque to the profile, K1), on which Firefox rejects the certificate (`FIREFOX_SCT_STRICT`), an inner length `0x80` or `0xFF` (the list fails), an inner identifier other than `0x04` that is tag number 4 (for example `0x44`, `1F 04`; `3A_HEADER_LAX`: no pairs), a constructed inner OCTET STRING (the list fails), a non-zero SCT version (extracted), a truncated last SCT (the items before it extracted), trailing bytes after the inner OCTET STRING (on which Firefox rejects the certificate), after the declared list region and inside an SCT after its signature (ignored), an SCT hidden in ignored bytes (never extracted), a zero-length signature (extracted),
  an inner identifier that is not tag number 4, such as `0x30` (the list fails in revokt and 3a alike, not `3A_HEADER_LAX`),
  the trailing-element cases of the §9.2 rule (bytes after `[3]`; an element between `subjectPublicKeyInfo` and `[3]`,
  dropping the extensions; `[2]` before `[1]` and `[1]` twice, dropping them; constructed `[1]`/`[2]`; a primitive
  `[3]`, ignored; an element with tag number 3 in another class or form holding an Extensions SEQUENCE (`03`, `23`,
  `43`, `63`, `C3`, `E3`), ignored, `Parsed` and outside the profile (K2), `3A_TBS_LAX`; a stop element with a
  multi-octet identifier (`9f 03` or `bf 03` holding the Extensions SEQUENCE; `9f 01 01 00`, `bf 02 01 00`, or `9f 1f`
  and 31 octets, before `[3]`), `STRUCTURE`, which JDK 17 and later reject; two `[3]`, the second ignored;
  bytes after the Extensions SEQUENCE inside `[3]` and after `extnValue`, ignored; anything after the INTEGER
  inside `[0]`, `STRUCTURE`, with the flattening case whose producer SPKI differs; a zero-length primitive `[3]`
  (`83 00`), `Parsed` and outside the profile; a constructed `[1]` then `[3]` carrying a non-minimal length, `Parsed`
  and outside the profile (K1, and K2), a D8-gap entry because ct-go never visits `[3]` there and keys it), the
  more-lenient-than-JDK cases (a v1 or v2 certificate carrying elements its version does not allow; unique-id content
  that is not BIT STRING content), times with an offset (on a `UTCTime`, a `CONSCRYPT_TIME_OFFSET` record against oracle
  2; on a `GeneralizedTime`, oracle 2 rejects), without seconds and with a day past the month's end
  (2026-02-31, rolling over to 2026-03-03), a 64 KB extension, BER indefinite lengths, non-minimal definite lengths, and
  a `Certificate` with trailing bytes; the envelope re-encodings (a non-minimal length on the outer `signatureAlgorithm`
  or `signatureValue` header, the outer NULL parameters flipped, a non-zero unused-bits octet on an RSA
  `signatureValue`, an indefinite outer `signatureAlgorithm`, an OID header `06 81 08` or a NULL as `05 81 00` inside
  it, a `tbsCertificate` header with a long-form length carrying leading zero octets or an indefinite length, an
  indefinite TBS with an indefinite Validity, subject RDN chain, `[0]`, or `[3]` down to an `extnValue` as
  `04 80 … 00 00`, an outer AlgorithmIdentifier `30 80 <OID> 05 80 00 00 00 00`, an RSA `signatureValue` with
  unused-bits octet `01` and the padding bit set; required outcome for each: `Parsed`, with
  the `producerKeyable` and key bytes of the unmodified certificate and a `VERIFIED` link, since the profile reads
  `Cert.tbs`; an indefinite TBS holding a non-minimal definite child (`02 81 …`, an SPKI `30 83 00 …`), which the
  JDK accepts and fails to verify (`parse(b)` is `STRUCTURE`; oracle 1's read is `Parsed` through the platform
  canon); and on the reject side an indefinite outer AlgorithmIdentifier holding a
  non-minimal OID header (`30 80 06 81 08 … 00 00`), which the JDK rejects, and an indefinite `signatureValue`
  (`03 80 <content> 00 00`, whether or not its content reads as a chain of minimal TLVs), which JDK 17 and later
  reject; each `STRUCTURE`); and a CA-signed TBS whose extensions are followed by a trailing element with a
  multi-octet tag (`9f 01 02 05 00`), presented with a definite and with an indefinite TBS header (`Parsed`, outside
  the profile (K1, and K2 for the ignored element), the same outcome for both); and the D8-gap examples (a serial with non-minimal INTEGER
  content, a keyUsage or basicConstraints value only zcrypto accepts, a `UTCTime` without seconds; each `Parsed` and
  outside the profile).

**Issuer corpus (zero tolerance).** Every certificate in Mozilla's `intermediates` Remote Settings
collection, the CCADB all-certificate-records export (its PEMs from `AllCertificatePEMsCSVFormat` by `NotBeforeYear`,
and from crt.sh by fingerprint where that export lacks one), the CCADB `MozillaAllUnexpiredPEMs` report (the source of
the producer's program set), the JDK `cacerts` store, and Android's system
store (for 0.1 taken from the AOSP `ca-certificates` sources of the pinned images; the 0.3 instrumented tier replaces it with the device read-back through the platform `X509Certificate.getEncoded()`),
under D1 and D2 with no tolerated violation; each snapshot is recorded in revokt-corpus with its URL, its retrieval
time and the SHA-256 of the raw download. The **producer SPKI check** (revision 42) runs against the committed fixture
generation (`corpus/clubcard`: its full filter and each delta, each with its own index map, §6.2, §6.3). The
producer's program set is the report's intermediates that zcrypto parses, that are not revoked, that zcrypto verifies
to a Mozilla root for serverAuth, and that certificate-transparency-go's `ParseCertificate` returns with no error,
non-fatal included, each keyed by `SHA-256(RawSubjectPublicKeyInfo)`; every index is a subset of the program set the
producer computed for that generation. Oracle 4 runs on `canon` of each certificate, as everywhere (revision 43):
on every `ct`-path input its TBS, and so the SPKI it hashes, is the TBS of the DER the producer would read (the PEM-
or store-decoded DER), since `canon` keeps the TBS content and ct-go's parse requires minimal headers; the envelope
can differ (an outer `signatureAlgorithm` other than the TBS's, which `canon` replaces and ct-go rejects on the DER),
which leaves the SPKI unchanged. revokt's `rawSpki` is taken from the DER (and from each platform's `encoded` under
D2). (1) **SPKI agreement**: for every issuer-corpus certificate oracle 4 parses through
`ct` (a superset of the program set: it also holds ct-go's non-fatal x509 errors), `SHA-256(rawSpki)` equals oracle
4's SPKI hash; a difference is a producer/revokt SPKI-byte divergence and fails, and a certificate revokt does not
parse counts as one where oracle 4's hash is an index key (elsewhere D1 and D1-dom decide). (2) **Index coverage**:
every key of each index equals oracle 4's `ct` SPKI hash of an issuer-corpus certificate whose `canon` is its DER (one
the producer could read), and so, by (1), revokt's;
for a key no snapshot covers (for example, its certificate left the report after the generation), every CA
certificate CT holds for that SPKI hash is fetched (crt.sh, by `spkisha256`, its id and retrieval time recorded in
revokt-corpus) and admitted, and a key still uncovered fails.

**Corpus record schema (one for all four kinds; committed).**
`{sha256, path, revokt: {outcome, rawSerial, spkiSha256, scts[]}, oracles: [{id, version, outcome, read?, holds?,
fields | unavailable}], class ∈ {D7_LENIENCY, D2_REENCODE_ALLOW, D3_DIVERGENCE, D1_DOM,
KEYABILITY_GAP, FUZZ_FINDING, ISSUER_CORPUS}, divergence: String? (required for D3_DIVERGENCE: `3A_HEADER_LAX`, `3A_TBS_LAX`, `CONSCRYPT_TBS` (D2: `Cert.tbs` differs from oracle 2's `getTBSCertificate()`), `CONSCRYPT_TIME_OFFSET` (D2: oracle 2 drops a `UTCTime` differential, revision 41), `CONSCRYPT_TIME_JULIAN` (D2: oracle 2 reads a pre-1582 time in the Julian calendar, revision 44), the
duplicate-extension class, or a named 3c/Firefox class), keyability: {parser, clause, zlint}? (required on every D8-gap entry whatever its class, and on every `KEYABILITY_GAP` record: `parser ∈ {ct, lax, zc}` from oracle 4, `clause` a `KeyabilityClause`, `zlint` the pinned zlint result), justification, added}`. Goldens for 3a/3b/4 are computed at admission
so the PR replay evaluates D1–D3 and D8 offline, JDK-only. A platform oracle's entry carries `holds` on an oracle-dependent record (`D1_DOM`, `D2_REENCODE_ALLOW`,
`KEYABILITY_GAP`, the `CONSCRYPT_*` divergences): whether the class holds on that version. Its `version` is the
matrix's name for it: the JDK feature release, the Conscrypt uber release, or on the platform tier the system-image
revision, with the Conscrypt APEX version recorded beside it; a JDK patch or an APEX update that changes an outcome
fails the run until the records are regenerated. Oracle 1's `read` is the SHA-256 of the bytes revokt reads
for that version where they differ from the input (the read fallback), recorded with their goldens; a matrix job that
meets a read without goldens fails as infrastructure until they are recorded, never as a violation. The release review
mechanically lists entries whose oracle version has left the matrix. The seed corpus (≥ 100 000 CT leaves of the
enrolled CAs, below; the `x509-limbo` vectors, the D7 corpus, the issuer corpus) is pinned by a committed SHA-256
manifest and a corpus-repository tag.

**The seed corpus's CT leaves** (revision 45) are two sets. The **log sample** reads random entries of every
CRLite-enrolled log and drops CT test traffic: the leaves whose issuer Name is one of the test issuers of Appendix A,
which log operators and monitors use to test logs and no root program trusts. The **crt.sh top-up** adds, for each key
of the fixture generation's indexes, at most 120 of the most recently issued certificates (issued in the last 400 days)
of the crt.sh CAs whose public key hashes to that key that are valid at the top-up's start and cannot issue
certificates; crt.sh holds a precertificate and its final certificate as two. Nothing crt.sh sends is trusted: a
certificate is kept only when it is one DER Certificate with nothing after it, minimal lengths in the headers checked
(the Certificate, the TBSCertificate's header, the AlgorithmIdentifier and its OID, the BIT STRING) and a v3
TBSCertificate, whose signature verifies under that key, and a TBSCertificate already kept, in either set, is not kept
again, so an attacker on the path can withhold certificates, which the recorded per-key counts show, but not add one. A
leaf counts for an index key only when the test JDK verifies its signature under the key of an issuer-corpus certificate
whose SPKI hashes to that index key and whose subject is the leaf's issuer; at least 100 000 such leaves are pinned, a
precertificate and its final certificate counting as two. The index keys are those of the fixture generation's indexes,
a stand-in for the live filters' issuers, and are taken again whenever the fixture generation changes. An index key with
no such certificate in crt.sh, or whose crt.sh query timed out, has none from the top-up, recorded per key with the
counts of certificates returned, rejected, filtered, duplicated and kept and any CA's timeout; its leaves in the log
sample still count.

**Generators.** (1) Mutational, Jazzer byte-level, seeded from the pinned seed corpus. (2)
Structure-aware: a DER grammar generator for `Certificate` mutating at TLV level (length forms, tag
classes, element reorder, duplicate and dropped elements, extension insertion, SCT-list specific
mutations, serial and SPKI variants, algorithm-identifier parameter variants). (3) Platform-accepted
bias: a mutant oracle 1 or 2 accepts enters the **secondary corpus** only if it adds revokt-parser
coverage (`-merge=1` over the accepted set) or is a D1/D2/D3 divergence; hash-keyed, capped by
entry count and bytes, stored in the corpus repository, re-seeded each run.

**Tiers and matrix.** Fuzzing runs on one pinned JDK ≥ 22 (Panama) with oracle 1 of that JDK, one Conscrypt uber
artifact and 3a/3b/3c in-process, oracle 4 out of process; one ClusterFuzzLite job per generator. The **version
matrix** is a replay of the union corpus (committed, secondary, divergence): one job per JDK, each running every
Conscrypt version of the matrix, with 3a/3b/4 goldens read from the records so no matrix job needs a native oracle.
Versions are named in a committed matrix file, `gradle/oracle-matrix.properties` (JDK: 17, 21, the current LTS, the
current feature release, each at its latest patch at run time; the nightly's JDK EA release, rolled by hand; Conscrypt uber: current and previous minor,
named by their catalog keys; Android system images by revision (from 0.3), with the Conscrypt APEX version logged per
run since it is updated out of band) with the roll rule "add the new version, keep the old until its support ends",
except that the bytecode target (JDK 17) stays while it is the target. A nightly job replays the committed corpus
against the newest JDK EA and fails on any new D1 violation against the recorded baseline. A Conscrypt release newer
than the matrix's current one fails the nightly, and so blocks a release, until it is admitted like any dependency
(checksums and signing key verified) and rolled into the matrix, after which every PR replays it; no unverified
Conscrypt artifact is resolved in CI. A scheduled **producer job** (weekly, on every change to the producer,
certificate-transparency-go, zcrypto or Go pin, and before each release) builds oracle 4 at the pin and at
`mozilla/crlite` `main`, replays D8's gated direction over the union corpus with both, and runs at least 100 000 fresh
entries from CRLite-enrolled logs, precertificates included, through oracles 1 and 4 and the profile. A violation at
the pin is a P0; one only at `main` is a P0 for the next release and bumps the pin in a spec revision, since live
filters come from Mozilla's current producer. The sample's gap by clause is published with each release; a new clause,
or D8-gap entries above 10^-4 of the sample's unexpired entries (precertificates and certificates counted alike),
needs a recorded decision before the release. This per-release check on fresh entries is separate from the D8 gap's
re-decision on the pinned seed corpus (§9.2 D8), which can reopen the D8 decision itself.

**Scope limits, stated.** The oracle set is a version matrix, not a proof; platform parsers drift
and the platform Conscrypt differs per device. `Revokt.evaluate` over raw bytes is outside the
platform-accepted premise and is documented as such (§4).

**Acceptance.** 0.1 gate: zero D1, D2, D3 and D8 violations on the pinned seed corpus, `x509-limbo`, the D7 corpus and
the issuer corpus against oracles 1 (every JDK in the matrix), 2 (uber versions in the matrix), 3a/3b and 4; the
producer SPKI check green; the D8-gap baseline recorded, and zero on the real end-entity fixtures; zero
platform-accepted inputs without a raw-byte reference, outside the unparsed inputs D2's metric excludes; Kover branch
coverage of the parser package ≥ 90 % measured over the committed replay (fuzz-run coverage is reported only). 0.3
gate: the same replay on the platform Conscrypt tier (API 26, 31, 34, 36) at zero tolerance. Continuous: no open D1,
D2 or D8 finding at any release; the divergence, D1-dom and D8-gap records reviewed at each release with every entry
justified in writing.

### 9.3 The upki-backed engine and the cross-engine suite (CI only)

Moved here from the spec's §3.2 at revision 59 (#216), verbatim; references to §3.2 for the adapter mean this section.

**upki adapter (`revokt-engine-upki`, Panama, JDK 22+; CI-only until the §12 trigger).**
Verified against upki at tag v1.0.1 (crates.io: 1.0.0; the shim's `Cargo.lock` pins the git tag) `ffi.rs`, `revocation/mod.rs` and `rustls-upki` (Appendix A).
- *Name*: `"upki"`, the `engineName` of its `ENGINE_ERROR` findings.
- *Formats*: `{V3, V4}`. upki's `clubcard-crlite` dependency (`bincode` feature) decodes both version bytes (`Encoding::read` accepts 3 and 4), so Mozilla's v3 filters are read as served; the C2SP spec says v4 and the crate is laxer than the spec. The engine never transcodes.
- *Lifecycle*: `prepare` writes the files verbatim into a fresh directory, writes a TOML config whose
  `cache_dir` is that directory and calls `revokt_upki_config_new`; the returned `PreparedGeneration`
  owns that handle and directory and its `query` runs `revokt_upki_check` against the handle, so the
  §6.5 self-check exercises the real native path; `activate` publishes the handle with a `@Volatile`
  swap and frees the previous handle with `revokt_upki_config_free` once in-flight queries on it drain
  (per-handle in-flight counter), deleting its directory; `PreparedGeneration.close()` without
  `activate` frees the handle and deletes its directory. `Store::from_config` re-opens `index.bin` on
  every check, so a handle has no state to invalidate. `close()` frees the live handle and deletes the directories.
  `coverageEndMillis` is read from `index.bin` by revokt's own reader.
- *Query*: **not** the stock `upki_check_revocation`, which parses the leaf with webpki and
  resolves the issuer by byte-equal subject name and would make the verdict depend on webpki's
  profile. The adapter loads exactly one native artifact, `revokt-upki-shim` (§3 module table), a
  cdylib of ours that statically links the `upki` crate and is built by the native CI job; it
  exposes `revokt_upki_config_new/free` and `revokt_upki_check(handle, serial, serial_len,
  spki_hash[32], scts, n)` over upki's public library API, `RevocationCheckInput::new(CertSerial,
  IssuerSpkiHash, Vec<CtTimestamp>)` + `Store::check` (verified in upki 1.0.1 `revocation/mod.rs`),
  and returns ffi.rs's result codes, mapping `Store::check`'s `Result` exactly as
  `upki_check_revocation` does, so the table below is unchanged; upstreaming the check function to
  rustls/upki is attempted but not required. upki takes no time. Panics surface as
  `UPKI_ERR_PANICKED` through `catch_unwind` in the shim.
- *Result mapping* (fixed; the suite asserts the table):

| upki result | `CrliteQueryResult` | Suite treatment |
|---|---|---|
| `UPKI_REVOCATION_NOT_REVOKED` / `_REVOKED` | `NOT_REVOKED` / `REVOKED` | compare, exact |
| `UPKI_REVOCATION_NOT_COVERED` | `NOT_COVERED` | compare by class (below) |
| `UPKI_ERR_REVOCATION_NO_DATA` (76; `Error::NoData`, outside the `UPKI_REVOCATION_*` range) | `NO_DATA` | compare, exact |
| `UPKI_ERR_PANICKED`, any other code (76 excepted) | `ENGINE_ERROR`, `engineName = "upki"` | failure |

(No abstain rows: with the extracted triple as input, upki parses nothing and resolves no issuer.)

**Cross-engine equivalence classes.** Through the shim the class
`{NOT_COVERED, NOT_ENROLLED, NO_SCTS}` is one value, `UPKI_REVOCATION_NOT_COVERED`: `Store::check`
applies no `cert_has_no_scts` policy (that is `rustls-upki`'s verifier), and with no SCT timestamps
no filter covers the certificate.
`REVOKED`, `NOT_REVOKED` and `NO_DATA` compare exactly; any `REVOKED`/`NOT_REVOKED` disagreement
between the two engines is a release blocker (no input is abstained). The finer split of that
class is compared against `revokt-oracle`'s `clubcard-crlite` binding instead. What an engine swap
can still change is therefore only the lookup itself and the data decoding, both pinned by this
suite. Documented, out of scope: the `rustls-upki` verifier, a different product, fails the
handshake on a malformed SCT list and on a leaf webpki cannot parse; revokt yields `NO_SCTS` when no
list parses under §9.2 (otherwise it queries the items §9.2 keeps) and `PARSE_FAILED`, both allowing in
`DEFAULT`. Generations: (i) Mozilla's v3 generations as served, both engines directly (no transcoder
in the oracle path); (ii) the v4 generations `upki.rustls.dev` serves, fetched by the oracle job; (iii) the v3
generations re-encoded as v4 by `revokt-oracle`, a bare `clubcard-crlite` `to_bytes(V4)` (upki-mirror
v1.0.1 does not transcode; upki main added one in `c2ba5e3`, which also sorts the coverage, so the bytes may differ
from the live mirror's, while verdicts cannot), a third leg; every generation whose `index.bin` revokt did not write passes the spec's §3.2 selection-equivalence check (`C2spIndex.inconsistencies`) before it enters the suite. Lands in 0.2; published only if the §12 trigger fires, which is additive because every
engine-side type above is public from 0.1.
