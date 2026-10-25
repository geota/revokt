# Approach 2 — **revokt**: a pure-Kotlin CRLite engine with JVM and Android bindings, growing into a WebPKI client-policy library

Status: **draft spec / project proposal, revision 39** · Target: JVM 17+ and Android API 26+, Kotlin 2.3+ consumers · Date: 2026-10-25

> **Name decided (revision 11): `revokt`.** Maven group `dev.revokt`, GitHub repository under the
> maintainer's own account, domain `revokt.dev`. `revokt.com` is an unrelated SaaS and the GitHub
> handle `Revokt` is taken; see §13 for the disambiguation rules that follow from that.

### Changes in revision 39 (the raw-byte-reference metric and D1-dom, 2026-10-25)
- **Corrected** (found while implementing #12, oracle 1): D2's gate metric, the count of platform-accepted inputs with
  no raw-byte reference, had to be zero on the committed corpora, but the D7 corpus's own reject side breaks it. The
  JDK parses an indefinite TBS holding a non-minimal definite child (`02 81 …`, an SPKI `30 82 00 …`) and fails to
  verify it, and 3a and 3b locate neither. JDK 27 also parses a definite TBS with an indefinite Validity (probed,
  Appendix A). Such an input is now D1-dom by rule: no `canon` exists for oracle 4 to read, and every producer path
  rejects a non-minimal length (Appendix A). The JDK-27 case already was D1-dom, since oracle 4 rejects its `canon`.
  The metric now excludes D1-dom inputs revokt does not parse; any parsed input without a reference still counts.

### Changes in revision 38 (the JVM floor is 17; an indefinite `signatureValue` is `STRUCTURE` again, 2026-10-24)
- **Changed** (the maintainer's decision, 2026-10-24, on #42): the JVM floor and bytecode target move from 11 to 17.
  Android stays at API 26+: revokt is built with Kotlin 2.4 (CONTRIBUTING), so its Android consumers already need AGP
  8.5.2 or later, whose D8 is expected to dex Java 17 class files (§3, Appendix A). JDK 11's parser reads every
  identifier as one octet, and it accepts forms that JDK 17, 21 and 27 reject:
  - an indefinite `signatureValue` (revision 35);
  - found by the independent review of #41 (#42), a trailing-element stop element with a multi-octet identifier
    (`9f 01 00` before `[3]`, `9f 03` or `bf 03` holding the Extensions SEQUENCE), which JDK 17, 21 and 27 reject
    (probed, Appendix A).

  Rather than loosen the parser for JDK 11, the floor rises: JDK 11 leaves the §9.2 version matrix, so it is no longer
  a platform oracle for D1. revokt's rejection of a multi-octet stop element matches every JDK in the matrix.
- **Reverted**: revision 35's acceptance of an indefinite `signatureValue`. No JDK in the matrix verifies it, so it is
  `STRUCTURE` again, as before revision 35. The `tbsCertificate` header and the outer `signatureAlgorithm` keep their
  indefinite forms, which JDK 17 and later verify. 3b's envelope follows, locating a definite `signatureValue` only.
  The D8 boundary corpus drops its indefinite-`signatureValue` leaf, and D7's case moves to the reject side. The JDK
  11 probes in Appendix A stay as the record of the change.

### Changes in revision 37 (`3A_TBS_LAX` covers every tag-number-3 element, 2026-10-24)
- **Corrected** (found by the independent review of #37, oracle 3a): `x509-parser` 0.18.1's `parse_extensions` checks
  only the tag number of the element after the SPKI, so 3a takes as extensions not only a primitive `[3]` but any
  element with tag number 3 that is not a constructed context-specific `[3]`: all seven forms `03`, `23`, `43`, `63`,
  `83`, `C3` and `E3` (probed, Appendix A). revokt and the JDK read such an element as the trailing-element rule's
  stop element (JDK 11 and 21 probed: no extensions). D7 and Appendix A record the cases. `3A_TBS_LAX` now names that
  whole class in D2 and D3, so such an input is a recorded divergence with the §9.2 read (∅), not an unexplained D2
  failure.

### Changes in revision 36 (oracle 4's reply carries its parse path, 2026-10-24)
- **Corrected** (found by the independent review of #30): §9.1's pipe protocol gave oracle 4's reply as
  `OK <serial-hex> <spki-sha256-hex>`, without the `ct`, `lax` or `zc` path §9.2's oracle table and D8 require. The
  reply is now `OK <serial-hex> <spki-sha256-hex> <ct|lax|zc>`, and an empty input line is answered `REJECT` so the
  replies stay one per input.

### Changes in revision 35 (an indefinite `signatureValue` verifies on JDK 11, 2026-10-24)
- **Blocker, found by the independent review of #24 (the unsigned-header parser)**: JDK 11.0.32, the bytecode target,
  verifies a certificate whose `signatureValue` has an indefinite length (`03 80 … 00 00`) whenever its content, read
  from the unused-bits octet on, is a chain of TLVs with minimal headers ending at the end-of-contents. `getEncoded()`
  keeps the presented bytes. About 0.44 % of P-256 ECDSA signatures read that way (17 of 4 000 and 7 of 1 500
  re-signed probes; 0 of 1 500 RSA-2048), and no CA signature is needed to present one. revokt answered `STRUCTURE`,
  so such a leaf was `PARSE_FAILED`, an allow in `DEFAULT`. JDK 17, 21 and 27 reject the form (0 of 4 000). This
  supersedes revision 34's statement that JDK 11 verifies a strict subset of JDK 17's inputs: that held on the
  revision 34 probe sets only.
  - §9.2 now accepts an indefinite `signatureValue`, delimited and re-encoded by the same converter rule; `Cert.sig`
    is read from the re-encoded content. A non-minimal header on its chain stays `STRUCTURE`: JDK 11 does not verify
    such a form (probed, Appendix A).
  - Oracle 3b delimits and re-encodes the `signatureValue` too, and `canon` holds its content after the unused-bits
    octet, re-encoded when indefinite. D2 also compares `Cert.sig` with that content, its padding bits cleared.
  - D7 gains the case on both sides, and the boundary corpus gains the accept side.
  - Appendix A records the case as a revision 35 probe, and its statement that the JDK rejects a constructed or
    indefinite `signatureValue` now separates the two: every probed JDK rejects a constructed one (JDK 11 and 17 probed
    again), and JDK 17, 21 and 27 reject an indefinite one.
- **K7 states header minimality inside the RSA key** (found by the independent review of #26, the keyability
  profile): ct-go parses `RSAPublicKey` out of the BIT STRING and rejects a non-minimal header there, with no `lax`
  retry, while K1 walks no primitive content. **K1's K8 list is matched on canonical OID content**, so a non-minimal
  spelling of a listed OID is opaque to K1 and fails K4. K4's minimality is noted as stricter than the pinned ct-go,
  which keys a leading `80`.
- **Corrected**: walker fixture (r) contradicted §5.1 and §9.2, which compute `AlgorithmIdMismatch` after NULL/absent
  normalisation. (r) is now an OID mismatch with the finding, and a NULL-vs-absent pair gives no finding.
- **Clarified**: D6's offsets of TBS fields index `Cert.tbs` from its tag octet; they re-slice `b`, for a definite TBS
  header, shifted by the TBS content's start in `b` less `Cert.tbs`'s header length.

### Changes in revision 34 (D8 made one-directional after a four-seat cohort, and the envelope re-encoding blocker closed, 2026-10-23)
- **Decision (issue #11): `producerKeyable` is a conservative keyability profile** (§9.2 clauses K1–K8) instead of an
  exact model of Mozilla's producer. The cohort (security, implementer, spec coherence, operator/data) was unanimous.
  - An exact model meant about 2 000 lines tracking certificate-transparency-go strict and `lax`, zcrypto with its own
    `asn1` fork, and Go's `net/url`, `time` and `crypto/elliptic`.
  - An error in the model of one parser shows only when the other also rejects, so fuzzing finds it slowly, and each
    is a false-`REVOKED` P0.
  - A sample of 200 230 entries from 18 CRLite-enrolled logs found none outside a strict DER profile and none keyed
    only by zcrypto (Appendix A).
- **D8 gates one direction at zero tolerance**: `producerKeyable` ⇒ oracle 4 keys `canon(encoded)` through ct-go's
  strict parse with revokt's bytes; an oracle-4 crash counts as a rejection, and oracle 4 reports `ct`, `lax` or `zc`. The reverse is the measured **D8 gap**:
  - D8-gap records (end-entity inputs only) carry oracle 4's path, the failing clause and the zlint result;
  - the gap is zero on the real fixtures, ratcheted against a baseline, and a lint-clean entry blocks the release;
  - a re-decision trigger at 10^-4 applies on the #15 seed corpus.
- **Unchanged**: D1's domain is still defined by oracle 4, and the `[0]` rule and key-byte equality stand. The SCT
  extension is opaque to the profile, so its non-minimal inner lengths still extract and stay keyable.
- **Removed**: the zcrypto-only list, the ct-go struct-walk model and conditions (i) and (ii).
- **Blocker, present since `producerKeyable` was introduced (revision 23) under either form of D8**: nothing outside
  `tbsCertificate` is signed.
  - The JDK verifies a certificate whose outer `signatureAlgorithm` or `signatureValue` header has a non-minimal
    length, whose outer NULL parameters are flipped, or whose RSA `signatureValue` has a non-zero unused-bits octet.
    It keeps those bytes through `getEncoded()` (probed on JDK 17, 21 and 27, Appendix A).
  - revokt marked such a leaf unkeyable. A network attacker holding a revoked certificate's key could therefore turn
    `REVOKED` into a `DEFAULT` allow.
  - The `tbsCertificate` header is unsigned too: the JDK verifies over the TBS after `DerIndefLenConverter`, under a
    minimal header. A non-minimal or indefinite TBS header, indefinite elements on a chain of indefinite elements
    under it, an indefinite outer `signatureAlgorithm` and set signature padding bits also verify. revokt answered
    `STRUCTURE` or unkeyable, or failed the walker's link check.
  - The profile now reads `Cert.tbs`, the TBS re-encoded as the JDK re-encodes it (D2 checks it against
    `getTBSCertificate()`); `Cert.sig` has its padding bits cleared; oracle 4 runs on `canon(encoded)` in D1, D1-dom
    and D8.
  - keyUsage BIT STRINGs that only zcrypto keys (`03 00`, `03 01 05`) are outside the profile.
- **The profile follows Go's checks with narrowed value domains, not X.690 everywhere.** It accepts what the producer
  keys and honest or private-PKI certificates use: negative, zero and long serials, an explicit `FALSE`, an explicit
  v1, and `*` or `&` in a PrintableString. It still needs the EC on-curve check (pure-Kotlin field arithmetic, §10).
- **Corrected statements**: §5.1 step 3 and §10 item 8 no longer say an unkeyable leaf is in no filter. Appendix A
  records that a fatal parse halts the producer's log ingestion rather than skipping the entry.
- **Additions**:
  - new §10 item 15: the producer keys the logged precertificate;
  - `RevoktStatus.parseFailed` and `Finding.Path.keyabilityClause`, so the outcome can be counted;
  - a scheduled producer job that builds oracle 4 at the pin and at `mozilla/crlite` `main` and samples fresh CT
    entries;
  - the boundary corpus;
  - D8 in the §9.2 Acceptance list.
- **JDK 11 and 17 probed**: every revision 34 JDK probe was re-run on JDK 11.0.32, 17.0.21, 21.0.13 and 27 `SUN`.
  JDK 17 matches JDK 21 on every input, so the blocker entry above, §9.2 and Appendix A cite JDK 17, 21 and 27.
  JDK 27 differs only on an indefinite header under a definite parent: it parses every such case and then fails to
  verify it. JDK 11 verifies a strict subset of JDK 17's inputs, with the same `getTBSCertificate()`, so the §9.2
  rule holds there too (on these probe sets; revision 35 found an indefinite `signatureValue` only JDK 11 verifies).
  The bypass remains on JDK 11 through an indefinite `tbsCertificate` header, an indefinite outer
  AlgorithmIdentifier, the NULL flip and the RSA padding bits. JDK 11, the bytecode target, joins the §9.2 version
  matrix (#20).
- **Considered and not adopted**: deciding keyability at the query, after the walk. §10 item 8 says why, and when the
  decision reopens.

### Changes in revision 33 (SCT list rule restated against `x509-parser` 0.18.1, with one mini consistency round, 2026-10-22)
- §9.2 "Parser contract": the SCT-list parenthetical described a stricter parser than the one D2 compares
  against (oracle 3a). A probe of `x509-parser` 0.18.1 (asn1-rs 0.7.2, nom 7.1.3) showed:
  - bytes after the inner `OCTET STRING`, after the declared list region and inside an item after its
    signature are ignored;
  - the list keeps the items before the first one that fails, and fails only when its first item fails;
  - an empty list, or a first item of length 0, is an error (a later item of length 0 ends the list);
  - any long-form inner length is accepted, and a zero-length signature is accepted.

  §9.2 now states a self-standing rule. It follows 3a for list framing and length forms. It differs at the
  inner identifier: revokt requires `0x04`, whereas 3a accepts tag number 4 in any class and in multi-octet
  form, with a u32 wrap. That wider acceptance is the recorded D3 divergence class `3A_HEADER_LAX`, excluded
  from D2's SCT comparison. It is equivalent to issuing without SCTs.
- §9.2 `producerKeyable` paragraph and D7: a non-minimal inner `OCTET STRING` length extracts the SCTs, not
  `NO_SCTS` (`producerKeyable = true` is unchanged, since ct-go's SCT sub-parse is non-fatal). D7 now states
  normative outcomes for its SCT-list entries and splits them: both directions of a wrong declared length, a
  bad first item, the three ignore levels, an SCT hidden in ignored bytes, a zero-length signature, a
  non-`0x04` inner identifier, and a constructed inner `OCTET STRING`.
- D2 states a per-extension expected SCT pair set, with ∅ for an inner identifier other than `0x04`. That octet
  is read by 3b, so the comparison substitutes ∅ rather than skipping. The record schema gains `divergence`, and the
  end-to-end oracle takes the same expectation.
- D3: `Ok([])` does not occur; an empty list is `ParseError` → `NO_SCTS`. Firefox's decoder is not an oracle; its
  divergences are hand-recorded `D3_DIVERGENCE` entries in the D7 corpus. A 3c pair revokt does not yield blocks the release until a spec
  revision resolves it. `3A_HEADER_LAX` is a class against 3a only. The direction note names the M1
  unverified-SCT residual.
- §9.2 "Structurally strict" notes that the SCT list's inner length follows the SCT-list rule.
- The `NO_SCTS` failure lists in §3.2, §4 and §10 item 7 are examples; §9.2 is the complete statement.
- Oracle 3b's SCT walk applies the §9.2 rule, so D2 against 3b does not raise false P0s.
- "Malformed list → `NO_SCTS`" in §3.2 (twice), §4 (`CrliteQuery.scts`), §6.1, §6.2 and §10 item 7 now reads
  "no list that parses under §9.2". §10 item 7 says the Firefox match is narrowed: a list §9.2 accepts in
  part is queried, and `STRICT` then sees the CRLite answer.
- §9.2 "Parser contract" (Independent review of the parser, PR #16): the TBS read now tolerates trailing elements wherever the JDK's
  `X509CertInfo` does, closing a D1 violation that made such leaves `PARSE_FAILED` and dropped such intermediates
  (`NO_ISSUER`), which fails open in `DEFAULT`. The tolerated places are:
  - after `subjectPublicKeyInfo`, read sequentially as optional `[1]`, `[2]` (either form) and constructed `[3]`;
  - inside `[3]`, the bytes after the `Extensions` SEQUENCE, unparsed;
  - inside an `Extension`, the bytes after `extnValue`, unparsed.

  Ignored bytes are recorded for `producerKeyable`. The D8 note on trailing SEQUENCE elements follows. revokt is
  stated as more lenient than the JDK in three places: no version gating, unique-id content not inspected, and the
  time forms, now stated in §9.2 (the JDK's day rollover included) with a fail-closed rule for a null time; D2's
  Java fields gain `notBefore`/`notAfter`. §5.5's "structurally strict" is qualified.
  Oracle 3b walks the TBS tail by the same rule, and D7 gains the cases. `[0]` stays strict: ct-go does not
  bound explicit `[0]`, so a trailing element there changes what ct-go accepts and which SPKI it records. The keyed
  serial is bounded (the stdlib `RawValue` re-parse) and is the JDK's. Both are confirmed by running the producer
  (Appendix A). No input is known on which the filter key
  differs, so the case is excluded conservatively, D1-dom by rule. The cost is `PARSE_FAILED` for such a leaf and a
  dropped candidate for such an intermediate, both allowing in `DEFAULT`. "Producer-keyable" now requires key-byte equality, in D1, D1-dom, D8 and
  `producerKeyable`. The table models ct-go's struct walk. 3a's primitive-`[3]` reading is the declared class
  `3A_TBS_LAX` (widened in revision 37), stated in D2, D3 and the record schema. The end-to-end oracle excludes
  chains `x509-parser` rejects. D1's domain is defined against the reference view, with `[0]`-trailing input D1-dom
  outright. D2's oracle-4 clause applies where `producerKeyable`.
- §5.1 `Cert.notBefore`/`notAfter` are `Long?`: the parse yields null for a time that does not decode, which only
  platform-rejected input reaches.
- Appendix A records `x509-parser` 0.18.1, asn1-rs 0.7.2 and nom 7.1.3 by sha256. They are pinned exactly in
  `revokt-oracle` when oracle 3a lands with the 0.1 oracle issue. The probed behaviour becomes a committed `revokt-oracle` test, and bumping any of the three
  crates is a spec revision that re-runs it. 3b's SCT walk runs the same cases.

### Changes in revision 32 (two factual corrections from the development-expectations review, 2026-10-22)
- Maven Central's Portal has no OIDC "trusted publishing": publishing is a user token plus PGP signatures.
  §10 and §14 now say "published from CI only, through a protected release environment with a second
  maintainer's approval, PGP-signed with provenance attestations" (key custody and the release flow live in
  CONTRIBUTING.md / MAINTAINERS.md).
- §14's "Org" is read as "project": the repository stays under the maintainer's personal account (§13 item 1)
  and uses only features free for public repositories there (ADR-0004 in the repository).

### Changes in revision 31 (mini consistency round on revision 30, two seats: fold consistency, new-surface adversary)
No blocker; eleven majors and about thirty minors, every one a precision gap in revision-30 material:
- **Acceptance memo** keyed on (chain hash, host') only (the platform's acceptance does not depend on
  revokt's snapshot and the retry re-validates under the platform's current store, so a `refreshAnchors()`
  every minute can no longer empty it), 24 h TTL, live in every lifecycle state; the overload table and
  §5.2 say "memo", "at most two validations"; a limits-table row.
- **Fetcher attribution**: the per-source internal instance is handed only to the factory, and writes
  `feedHostBlock`/`updateBlockedBySelf` only while a fetch of its source is in flight on it (the
  revision-29 guard restored as a second condition); the `HttpFetcher.Factory` contract (one call per
  source at `build()`, every handshake through the given `FetcherTls`); internal instances never counted
  or listed; one shared snapshot refreshed as one; `FETCHER_TRUST` failure attribution; a §9 fixture.
- **Sole-seed gap**: `close()` waits unconditionally for the decoding thread to re-take the lock; the
  three outcomes tabled (flag seen before `activate`; flag missed; no `close()`); a cancelled `start()`
  throws `IllegalStateException("closed")`; re-entrant `start()`/`close()` from the decoding thread throw.
- **`exemptAnchors`** applied at its call position (later calls win), excludes rules by the §8 table's
  "empty path" mark (`NO_ISSUER`, `ISSUER_UNVERIFIED`; the golden fixture carries the column), so M2's
  `ISSUER_UNKNOWN_TO_MOZILLA` is covered; the recipe pairs `platformOnly()` with `hostSuffixIn`.
- **`SeedOpener`** is jvmMain over `java.io.InputStream` (Okio stays out of every public signature);
  `of(opener)` lives on the jvmMain actual companion.
- **Clock-behind install**: carved out of "the three advance together"; `UNCHANGED`-by-timestamp defined
  (attempt fields only, one `_since` body per poll while the clock is behind); `clockBehind` recomputed
  at the sync decision, not read from the last publish.
- Shadow: the §5.5 catch rule, a shadow-only `ENGINE_ERROR` is not cached (`shadowVerdict = null` in
  the entry, counted once), counters applied by `apply()` after step 3a, shadow diagnostics logged at
  `WARN`, `Revokt.evaluate` runs 3a and `Evaluator.evaluate` does not. Fallback migration: per-field
  `updater.json` merge, failed-lock state, `STORE_UNREADABLE` clears on migration, a fallback still syncs.
  Every `SyncStage` producer names its stage; cross-references and the changes block corrected.

### Changes in revision 30 (mini consistency round on revision 29, two seats: fold consistency, new-surface adversary)
No blocker; eight majors and twenty minors, every one in material revision 29 added; no design reversal:
- **Clock-behind devices no longer freeze on the seed**: a changeset newer than a live generation that is
  itself `clockBehind` installs under the same no-watermark-advance rule, `UNCHANGED` is tested before
  `CLOCK_SKEW`, `lastVerifiedAtMillis` advances on such installs, `clockBehind` is recomputed at every
  publish (never persisted); the §9 fixture rewritten.
- **Shadow policy**: evaluated after the enforced catch boundary has closed, under its own boundary
  (a shadow throw is a shadow-only `EngineError`, never on the enforced verdict); the shadow pair is read
  with the policy pair at flow step 2; every setter call bumps the epoch; validated under `OBSERVE`
  semantics; touches only `shadowWouldRejects` and `RevoktEvent.shadowVerdict`; computes its own data rules.
- **Fetcher attribution is structural**: one internal trust-manager instance per configured source,
  handed to that source's `HttpFetcher.Factory.create`; the public `fetcherTrustManager` is a distinct
  consumer-facing instance that is always "no fetch in flight"; all share one snapshot over `fetcherDelegate`.
- **`index.bin` consistency** restated as selection equivalence per (log id, timestamp), well-defined for
  overlapping windows; upki-mirror's writer and `Index::check` on overlaps are a named 0.2 verification.
- **3-arg Android overload**: a dedicated acceptance memo (chain hash, snapshot id, host'; 1,024 entries,
  1 h) written only by socket and engine acceptances drives the null-host retry, independent of the path
  LRU; `Revokt.evaluate` and 3-arg calls never write it; "at most two platform validations".
- **Sole-seed gap**: an internal `STARTING` flag under the factory lock; a second `start()` waits for
  the first and follows its outcome; `close()` sets a cancel flag the decode checks before `activate`
  and waits (bounded) for it; a post-`activate` throw leaves the written generation, loaded as stored
  on retry. **Fallback migration** under the ordinary candidate rules (class and age), watermark = max,
  lock or registry failure → read-only or stay in fallback. The worker returns `failure()` for
  `SEED_CHANNEL_MISMATCH` and validate `ERROR`s, `success()` for `DEFERRED`; `Provider` may return `CREATED`.
- **Exemptions**: `exemptAnchors` declared, covering exemptable non-`EVIDENCE` rules whose outcome is
  `REJECT` and skipping `PATH`-layer rules (their reported path is empty when they fire, so `anchorIn`
  never matches); the enterprise recipe uses `hostSuffixIn`/`platformOnly` for `NO_ISSUER` and
  `ISSUER_UNVERIFIED`; fixture (j) split (brainpool is now `NO_ISSUER(ALL_CANDIDATES_INVALID)`).
- API sketch: `NOT_STARTED` removed from `DiagnosticCode`; `RevoktLoggers.jul()`/`RevoktAndroid.logger()`;
  `SeedOpener` declared (jvmMain); `SeedSource` as `expect`/`actual`; `maxTrustManagers` overridable in both directions;
  `SyncStage.FETCHER_TRUST` and the stage named per producing bullet; `logger` in the builder sketch;
  `RevoktWork.uninstall` declared; `RULE_FLIPPED_THIS_MINOR`/`UNVERIFIED_REJECTS_WITH_CLASSICAL_GAP`
  recomputed with the policy pair; snapshot-read wording, "three data rules", `Residual 10` label,
  `(B)` on `x5uHostRewrite`, `storageFallback` retry exception, data-rule snapshot site.

### Changes in revision 29 (full cohort round four on revision 28, six seats: coherence, implementer, security, operator, format/differential, platform)
Three blockers, all folded, none in the walker or the data path: two API-level crashes on the declared
minSdk and one fail-closed path the default preset reached through a routine clock condition.
- **Android API 26–30**: futures are completed through `executor.execute { future.complete(v) }`, never
  `CompletableFuture.completeAsync` (API 31+); an API-26 instrumented fixture and a `NewApi` lint gate on
  a minSdk-26 consumer guard it. **Android default fetcher**: `HttpURLConnection.setAuthenticator` does not
  exist on Android; `revokt-android` defaults `http` to `OkHttpFetcher` when `revokt-okhttp` resolves, else
  its own `AndroidHttpFetcher` (global-`Authenticator` residual recorded in §10); a 401/407 is `FAILED` on
  every platform. **Future-dated seed**: installed, never refused (its timestamp is Mozilla-signed, so
  "future" can only mean the local clock is behind): `ageMillis` clamps at 0, `DataState.clockBehind` and
  the `CLOCK_BEHIND` warning are loud, the watermark takes the signed timestamp; the §9 fixture flips.
  A `CLOCK_SKEW` changeset for a dataset with no generation installs the same way without advancing the
  watermark. `pending` also clears at the end of the start task when no fetching source is configured.
- **Engine agreement**: the loader verifies `index.bin`'s log directory against the union of the referenced
  filters' coverage maps before `prepare()` (`INDEX_INCONSISTENT`), so coverage-driven selection equals
  C2SP's `index.bin` selection; the upki adapter reads `{V3, V4}` (clubcard-crlite decodes both; the "v4
  only" claim deleted) and the cross-engine suite runs the upki leg on Mozilla's v3 generations directly,
  the v4 transcode a third leg; `query()` precedence closed → `ENGINE_ERROR`, no generation → `NO_DATA`,
  empty SCTs → `NO_SCTS`; `UPKI_ERR_REVOCATION_NO_DATA` (76) named; v3/v4 decode-strictness rules stated.
  **`producerKeyable`** restricted to headers the producer's *fatal* walk visits (ct-go's SCT-list parse is
  non-fatal, so a non-minimal inner length there is keyable, `NO_SCTS`); **D8** scoped to `Parsed` inputs.
  Self-check inputs fully named (issuer hash, SCT, outside probe, iteration order).
- **Flow**: the 3-arg Android overload's step 1 defined relative to the caches (the null-host retry only
  for a chain and host a socket or engine overload already accepted); the anchor snapshot is read exactly
  once per handshake; `decide` = decision steps 1–6, `evaluate` = steps 7–8; one list of what a path-cache
  entry reproduces; `Revokt.evaluate` runs step 1 with `authType = "UNKNOWN"` and is `@Throws`;
  `Evaluator.evaluate` walks the default instance's snapshot and throws outside `STARTED`;
  `revokt.trustManager` is created lazily (fixture (h) holds); `customCanonicaliser` is a class check over
  the two final shipped `PlatformTrust`s; candidate order within a store group puts compatible `keyFamily`
  first; `ISSUER_UNVERIFIED` counts only the child's signature OID (a server-chosen key OID on a decoy can
  no longer relabel `NO_ISSUER`); `UnsupportedAlgorithm` emission rule stated; `MAX_PRESENTED` counts the raw chain.
- **Lifecycle**: the synchronous seed decode runs only when no complete stored generation exists, and the
  factory lock is released around it; `resetState()` publishes the empty snapshot before `engine.clear()`;
  `install()` uses `use {}`; `close()` idempotence and single-owner injection in the engine contract; the
  engine thread contract names the `start()` caller; fresh dependent futures per call; the policy setter
  publishes `ready`; `RevoktState.warnings` is the set of currently true conditions with a clearing rule per
  code and carries the V warnings of the published pair; `NOT_STARTED` is a counter only;
  `RevoktState.storageFallback`; an in-memory fallback retries its configured storage and migrates; the
  WorkManager worker starts a `CREATED` instance itself, syncs in-memory instances, has stop semantics and
  an `uninstall`; `store.version` higher → `STORE_NEWER_LAYOUT` (JVM: in memory; Android: rebuild, one
  package owns the directory), lower → `STORE_MIGRATED`.
- **Operator surface (additive)**: `shadowPolicy` (steps 7–8 re-run under a second policy on cache misses;
  `shadowWouldRejects`, `RevoktEvent.shadowVerdict`), the measurement path from `DEFAULT` to `STRICT`
  without `OBSERVE`; `STALE`, `UNSIGNED_DATA` and `NO_DATA` exemptable (a feed outage no longer takes down
  exempted private-anchor traffic under `STRICT`); `limits { maxTrustManagers }`; `RevoktLogger`;
  `TrustManagerStatus.anchorRefreshFailures`; `SyncResult.{sourceId, stage, httpStatus, cause}` and
  `SyncOutcome.DEFERRED`; `x5uHostRewrite` (a byte-for-byte reverse proxy is now a supported mirror);
  `SeedSource.of(source)`; `sync()` with no fetching source re-checks the seed; `hostSuffixIn`;
  `OkHttpClient.revoktTrustManager()`; `RevoktWork.uninstall`; V `NO_FETCHING_SOURCE`; R `STORAGE_UNSET`
  on Android; R https-only source URLs; `/v1` is the default base URL; `mode` read and rejected when not
  `p384ecdsa`; `If-None-Match` synthesised from the verified cursor; seed archive entries capped while
  inflating; seed artifacts carry no code dependency (the floor lives in `seed.json`).
- **Fetcher**: handshakes on `fetcherTrustManager` are attributed to the in-flight `FetchRequest`, never the
  peer host; a handshake with no engine fetch in flight is evaluated under the fetcher policy but neither
  writes `feedHostBlock` nor receives the `feedHostRevoked` allowance; `FETCHER_HOST_UNAVAILABLE` and the
  Ktor-CIO exception are deleted; the fetcher policy ignores `Enforcement`; `FetcherTls.hostnameVerifier`
  deleted (hostname verification is binding-owned; the OkHttp fetcher keeps OkHttp's verifier).
- **Platform facts**: Android's `ApplicationConfig` holds one `RootTrustManager` (the memo rule stands and an
  explicitly passed default is the same instance); OkHttp runs the chain cleaner lazily and coalesces HTTP/2
  connections across hosts (per-host attribution and `hostIn` are per handshook host; stated in §5.1, §8, §10).
- Milestones: the walker fuzzer is a 0.2 deliverable (its types exist there); the `Rule → BasicReason`
  map moves to `revokt-engine` jvmMain so the 0.1 golden fixture is total; §9 `Rule` tests tagged by
  milestone; the 0.1 gate is D1–D3, D5, D6, D8. Appendix A corrected (producer file path, panic site,
  upki crates.io 1.0.0 vs tag v1.0.1, Android API facts, `allOf` entry removed).

### Changes in revision 28 (mini consistency round on revision 27, two seats)
Twenty-seven consistency findings on the revision-27 fold, no new design:
- **Two-phase install carried through**: `formats`/seam/serialisation text says `prepare`/`activate`;
  the upki adapter's lifecycle bullet maps `prepare` (handle + directory owned by the
  `PreparedGeneration`, whose `query` runs the real native path), `activate` (swap, free previous)
  and `close()`-without-activate; ownership after `activate`; a cancelled install closes an
  un-activated prepared generation; an `activate()` throw leaves the live generation; the sole-seed
  synchronous `start()` runs `prepare`, self-check and `activate` on the calling thread, the one
  exception to "loader dispatcher only"; "an *install*" defined once as the whole sequence.
- **Self-check probe fully deterministic**: a fixed candidate list (`0x01`..`0x1000`), inverted blocks
  with `approxM == 0` included (every serial is revoked there), exception-list fallback, member of a
  non-inverted block last.
- `Evaluator` rename completed (three stale `Evaluator.evaluate`); `Evaluator`/`EvaluationRequest` in
  the module table; `customCanonicaliser` set when `canonicalSubject` is overridden **or** the
  delegate is not the default; `platformDefault` named; a `canonicalSubject` null or throw means no
  canonical match; `DISTRUST` on a `PRELOAD`-only outcome is the unevaluable finding; `needsData`
  reads the policy pair at step 0; `SeedSource`/`GenerationFiles` `internal constructor` with
  `JvmGenerationFiles.fromDirectory`; `RevoktWork` as an object.
- **Watermark**: the private mirror carries the cursor (the watermark is per dataset regardless);
  the coverage-monotonic bound is read from the live generation, never stored. **Hold**: cleared only
  by a hit-free sync completing after `sinceMillis + FEED_HOST_HOLD`, so an alternating-certificate
  host cannot reset it; `updateBlockedBySelf`/§10 say "without a time bound" for TLS-only sources.
  **`STALE` gate**: `seedInstalledAtMillis` and a dataset-level `lastAttemptAtMillis` persisted
  beside the watermark; read-only instances stay gated until promotion; the §9 test updated.
  **Host attribution**: the Ktor fetcher over CIO drops the host; a single configured class takes
  null hosts; configured hosts enumerated; §10 records the host-dropping exception. **Pending**:
  `generationEpoch` also advances when a dataset leaves `pending` without a generation, so a cached
  pending-allow is never served afterwards; `pendingAllows` counts misses only. **`store.version`
  rebuild** deletes every other key after writing the version. §5.2 observer defined.

### Changes in revision 27 (full cohort round three on revision 26, three seats: coherence, new-surface adversary, API freeze)
Four blockers, all in material added since revision 23 or in the §4 sketch's compile-ability; all folded.
- **Adversary**: the engine self-check is **deterministic** (the loader picks a serial its own reference
  evaluator calls revoked; never a random draw) and runs on a **two-phase install**:
  `RevocationEngine.prepare(generation)` → self-check on the inactive `PreparedGeneration` →
  `activate(prepared)`; a failure before `activate` leaves the engine untouched, so no recovery path
  has a window (`install()` stays as a default convenience). The signed-source hold is keyed **per
  source**, set on the first hit of any of its hosts and cleared only by a hit-free sync, so a CDN
  with two certificates or a 398-day record cannot keep it alive. `fetcherTrustManager` attributes a
  handshake to a source by `host'` (`FETCHER_HOST_UNAVAILABLE` when a consumer fetcher drops it).
  `policy`/`policyEpoch` are one `@Volatile` pair read once at flow step 2; the two setters serialise
  and validate the pair. The `STALE`-on-seed gate is the persisted `lastAttemptAtMillis`, and a
  backoffed first sync completes as `BACKOFF` at once. **The rollback watermark is per dataset and
  channel**, outside the per-source map, so a relabelled `sourceId` cannot roll back. `PRELOAD`
  paths are never the clean alternative for the every-path rule. `fetcherDelegate` may not be a
  `RevoktTrustManager`; `pendingAllows` counted; `cache(null)` forced and the JDK authenticator
  answers proxies only; a rebuild writes `store.version` first; null host or anchor never matches a
  helper; the preview-collection residual recorded.
- **API freeze**: `FetchResponse.of`/`Builder` public (the fetcher seam was unimplementable);
  `RevoktLifecycle` top-level in commonMain and the cross-artifact `@RevoktInternalApi` rule stated;
  BCV `nonPublicMarkers` excludes `@RevoktTestingApi`; `GenerationFiles`/`CrliteSct` testing builders
  and `GenerationFiles.fromDirectory`; `canonicalSubject` `internal expect … : String?` with
  `PlatformTrust.canonicalSubject` as the public seam; `JvmSeedSource`; `RevoktWork.install(context, …)`;
  **`Engine` renamed `Evaluator`** (sealed); `ExemptionContext.chain` nullable and `credentialType`
  reserved for M5; `FakeRevokt` as a builder preset; the reference walker returns hex strings;
  `StoreLockedException`/`OwnershipCheck` declared; the seed fields folded into `DataState` and
  `remoteSettings` hoisted to `sources {}` now rather than at 0.4; `@JvmOverloads`, `@JvmField`,
  `@JvmSynthetic`, `Revokt.builder()`, `AutoCloseable`, a nullable `verdict` after deserialisation.
- **Coherence**: `pending` definition carries the future-dated-seed case; goal 3 names the sole
  `c2spCache` case; `IllegalArgumentException` for a plain delegate everywhere; the blob rule stated
  once; `Walk` variants carry `WalkStats`; test support lives in `revokt-engine`'s test set from 0.1;
  `ChainSource.PRESENTED` reserved; `STORE_FAILED` producer named; `ENGINE_CLOSE_DRAIN` and
  `FETCH_TIMEOUT` rows; "§5.1 limits"; sync-time diagnostics list complete; `FEED_HOST_REVOKED` is a
  sync code; `PATH_BUDGET_EXCEEDED` produced at steps 3, 5, 6; §5.3 wrapper sentence; the null
  delegate on `Revokt.evaluate`; cleanups.

### Changes in revision 26 (mini consistency round on revision 25, two seats)
Thirty-eight consistency findings on the revision-25 fold, no new design:
- `fetcherTrustManager`'s warning-not-throw rule applied everywhere it was still a throw (§4 bullet,
  §5.1 lifecycle and anchor-snapshot paragraphs, §9 invariant, §10 item 3); its start()-time failure
  makes syncs `FAILED` **without a fetch** and `unevaluated[FETCHER_SNAPSHOT_UNAVAILABLE]` counts only
  handshakes delivered to it directly; it wraps `fetcherDelegate` everywhere.
- **Engine self-check** restated in equivalence classes (so the upki engine passes), per-filter
  coverage, exception-list or three-draw serial for the inverted case, and an explicit re-install of
  the previous generation on failure.
- **Signed-source hold** persisted in `updater.json` (`feedHostBlock`), fixed at `FEED_HOST_HOLD` =
  24 h, counts toward `signedSourceFailing`; `updateBlockedBySelf`/`SyncResult` fields and fixture (g)
  aligned (23 h still blocked, 25 h installs).
- `producerKeyable`: P0 parentheticals un-swapped; the serial is always INTEGER content (step (i)
  tag-checks it) so `rawSerial` reproduces it exactly; non-minimal lengths matter only at visited
  headers; a zcrypto-only acceptance is keyable and listed separately; `buildIndex` output frozen per
  `seedFormat`; a future-dated seed is a warning with the dataset `pending`, excluded from the
  synchronous throw.
- Walker pseudocode: `Walk`/`CandidateIndex` `internal`, `WalkPath` at step 2, `endDepth` assigned at
  every limit, `WalkStats` carried by every `Walk` variant; `expected Walk` asserted only in the
  walker-only harness; fixtures (i), (s2), (t), (y) marked harness-only with their trust-manager-path
  expectation (`MAX_PRESENTED` cuts them at step 3).
- Flow 3b distinguishes a throwing `executor.execute` (listener removed) from a throwing `onVerdict`
  (drain continues); ring counters untouched. `endReason = COMPLETE` on the fallback-skipped exit.
  `policyEpoch` declared and in the cache-key sentence; the policy setter runs the `NO_DATA_AT_FLIP`
  check (V bullet, fixture) and recomputes `ready`/`needsData`. `STALE` on seed data fires at once
  when no fetching source exists. `Exemption` helpers in a shape that compiles (companion + extension
  `and`/`or`, content-compared hashes). Path-cache entries keep the leaf's bytes only; the presented
  chain is rebuilt from the live call. `unevaluated` monotonic since `build()`. Private mirror rewrites
  `x5u` to an `x5uHosts` entry; `store.version` higher releases the lock; WorkManager `Result` rules;
  milestone rows and fixture (e), (g) aligned; `CROSS_CALL_MEMO_ENTRIES` row; cleanups.

### Changes in revision 25 (full cohort round two on revision 24, three seats: implementer, adversary, consumer/operator)
One blocker (the `producerKeyable` gate had no codable predicate), fifteen majors, thirty-odd minors; all folded.
- **Implementer**: `producerKeyable` is now an exact predicate derived from Mozilla's producer source
  (ct-go/zcrypto parse plus the stdlib TBS re-parse; DER-minimal tag/length at every visited header,
  lax INTEGER content; serial = content of the first TBS element after the optional version, whatever
  its tag), pinned, with oracle 4 as ground truth (D8); the walker pseudocode is closed (`Cert`,
  `WalkPath`, `WalkStats`, `endDepth`, `crossCallMemo`, leaf-level `NoIssuerReason` flags, `internal`
  visibility, the harness in `revokt-engine`'s test set); fixture (y) made reachable; 0.2 ships a
  minimal `Revokt`; the seed archive format and `SeedSource`/`MozillaRemoteSettings` shapes are
  declared; `endReason` defined once; §6.2 `shift`/`eval` bounds; cache TTL semantics; fallback
  anchor re-parse; path-cache entries keep the `PresentedChain`; SCT grammar pinned to `x509-parser`;
  `classicalOids` defined; signature and canonical-JSON references named.
- **Adversary**: the catch boundary closes before event emission and a throwing listener executor
  can no longer turn `REVOKED` into an allow (`listenerFailures`); fired rules accumulate across a
  late throw; **fetcher policy by source authenticity**: on the end-to-end-signed Mozilla source a
  `REVOKED` feed-host chain is honoured for at most `signedSourceFailingAfter` (24 h), then the fetch
  proceeds with `feedHostRevoked` loud, so no signed record can freeze the signed source for good;
  TLS-only mirrors keep the hard `BLOCKED_BY_SELF`, with the blocked chain reported; a format the
  engine does not list is `SEED_UNREADABLE`/`FORMAT_UNSUPPORTED`, never a silent skip; a post-install
  engine self-check; `NO_DATA_AT_FLIP`; exempted-evidence events carry `Rejected` priority;
  `NO_REQUIRED_DATASETS`; `MAX_PRESENTED_BYTES`; the Android 3-arg hit path mirrors step 4; bounded
  waits on injected fetchers, engines and listeners; a newer `store.version` is left untouched; a
  `fetcherTrustManager` build failure is a warning, never a crash loop.
- **Operator**: `RevoktStatus.unevaluated` counts every fail-open path; `fetcherDelegate` seam and
  the fetcher hostname list; the supported private-mirror path (`MozillaRemoteSettings` overrides,
  `SIGNED` class) and `MIRROR_WITH_SEED_NEVER_INSTALLED`; runtime `policy` setter with `policyEpoch`
  in the verdict-cache key; `STALE` does not fire on a seed generation until the first sync attempt
  completes; `OkHttpFetcher` forces no redirects, no authenticator, no cookies; WorkManager request
  contract and keep rule; `IN_MEMORY_STORE_WITH_FETCHING_SOURCE`; public `refreshAnchors()`;
  `OwnershipCheck`; `JdkHttpFetcher` proxy rules; readiness-wait counters; `RULE_FLIPPED_THIS_MINOR`;
  `EXEMPTION_ON_EVIDENCE_RULE`; seed POM floor; blob re-download on the delta path; shipped
  `Exemption` helpers; the intercepting-proxy statement in §10.

### Changes in revision 24 (mini consistency round on revision 23, two seats)
Consistency fixes to the revision-23 fold, no new design:
- **Seed as sole local source**: when the seed is the only local data source and `NO_DATA` rejects
  under `ENFORCE`, its verification, `index.bin` rebuild and decode run synchronously inside
  `start()` before the flip, so `start()` can throw `SEED_UNREADABLE` as §4 promised; otherwise the
  seed loads on the loader task as before. `STORE_UNREADABLE` never throws. Goal 3 says "sole seed".
- `SeedSource.bundled()` resolves at `build()`; an absent artifact is "no seed source" and the
  `validate()` diagnostic; `SeedSource.none()` opts out.
- `explore` pseudocode rewritten so it compiles against its declarations: preload certificates are
  store candidates yielded by `related()`, a preload-only path is recorded only when no anchor is
  reachable through it (`terminalKind = PRELOAD`, a terminal of last resort); `CandidateIndex.customCanonicaliser`.
- `NO_DATA` definition carries `pending` everywhere (§4 `dataStates`, §8, §9 `Rule` test).
- `BasicReason` lives in a jvmMain `Rule → BasicReason` map in `revokt-jsse`, in the golden fixture
  tuple, asserted for every rule.
- `dataDeadline` origin, the `SIGNED` cap (`FetchRequest`, §6.3) and the data-path fixture
  milestones stated once; 0.2 runs the updater over `RevoktStorage.inMemory()`; `records.json`
  reserved and in the layout; async futures complete off the loader and `close()` fails pending
  ones; `PathHit.onReportedPath` meaningful; residual 1 and the fallback rationale restated;
  `terminalKind` null on an empty path; §13 quickstart item; trust-class table rows merged;
  artifact table, sync-time diagnostics and Appendix A heading updated.

### Changes in revision 23 (full cohort on revision 22, three seats: API/extensibility, security/data path, systems/platform; plus the seed decision)
No blockers were found. Every major and minor is folded; prose nits where cheap.
- **Decision: a seed ships by default.** `SeedSource.bundled()` is the builder default and resolves
  the `revokt-seed-<channel>` artifact; the quickstarts declare it (§4, §6.5, §13 item 5).
- **API/extensibility (M2–M5)**: `RevocationEngine` is declared CRLite-only, other layers get their
  own evaluator seams (§3.2, §12); preloaded intermediates are candidates the walk continues from,
  terminals only of last resort when no anchor is reachable through them (`Finding.Path.terminalKind`,
  `AnchorSnapshot.preloadGenerationId`, an `INTERMEDIATES` install rebuilds the index); the M2
  exhaustive re-walk runs under fresh budgets and never demotes a `Found` (`Finding.Path.rewalkEnd`),
  including on a `PLATFORM` path (`ChainSource.MIXED`); the one-minor grace no longer traps a consumer
  who wrote an explicit `ALLOW` (`WARNING` in the flip minor, `ERROR` after), and `ONECRL`/`DISTRUST`
  are exemptable; `BasicReason` is a per-rule constant (`UNSPECIFIED` for `CT` and `DISTRUST`);
  `Finding.PathHit` reshaped; M5 routes through `EvaluationRequest.credentialType`; channel-less
  datasets use the `all` segment and `channel` is mandatory only with a CRLite source; M4 dataset and
  source named; `notBefore`/`notAfter` parsed from 0.1; `CT_UNVERIFIED` covers SCTs delivered outside
  the certificate.
- **Security/data path**: a changeset `timestamp` beyond local now + `clockSkew` is `CLOCK_SKEW` and
  prolonged `ROLLBACK_REFUSED` sets `signedSourceFailing`; **`producerKeyable`**: a leaf Mozilla's
  producer cannot key is `PARSE_FAILED(PRODUCER_UNKEYABLE)` and never queried (D8, 0.1 gate); goal 3
  names `NO_DATA` as its second exception and `start()` throws when the only local data source is
  unreadable; `NO_DATA` does not fire while the start task has not passed the seed step
  (`DataState.pending`); the `SIGNED` body cap is `min(attachment.size, MAX_FILTER_BYTES)` and the
  loader catches `Throwable`; P8 honest acceptance; residual 1 restated and the unrelated loop runs
  at the leaf under a non-platform canonicaliser; blobs re-hashed on reuse; backoff clamped on read;
  `records.json` persisted per `SIGNED` generation; x5u algorithm floor; the catch boundary catches
  `Throwable` short of `VirtualMachineError`; a one-certificate `PLATFORM` path; `resetState()`
  rollback bound recorded.
- **Systems/platform**: `close()` holds the factory lock only for the flip; `meteredNetwork` seam
  and `METERED_DEFERRED`; the null-host retry is unavailable with any `<domain-config>` (AOSP
  `RootTrustManager`), named in the §5.2 residual; `resetState()` keeps the published generation
  until the replacement swaps in; read-only promotion re-runs the start task as owner; a null
  delegate resolves to the one memoised default instance; walker and `Evaluator.evaluate` move to 0.2
  with the fuzzer gate, the store to 0.3, estimates revised; fixture (y2) `verifications = 3`;
  directory fsync on every rename; `.lock` key exclusivity; listener cursor at registration;
  non-reentrant factory lock; `start()` racing `close()`; `close()` on the loader thread throws;
  issuer corpus 0.1 tier; `dataDeadline` from the flip; `/v1` and `/v2` both recorded.

### Changes in revision 22 (mini round on revision 21, one seat; `CrliteQuery` value class)
- **`CrliteQuery` value class** replaces the three positional engine parameters, so a field can be
  added in a minor without breaking third-party engines.
- **Shim is the only native artifact the adapter loads**: `revokt-upki-shim` statically links the
  `upki` crate and exposes `revokt_upki_config_new/free` and `revokt_upki_check`; no `Config`
  pointer crosses between two cdylibs. Module table, license line, lifecycle bullet, §9 suite, oracle
  3c, D3, §12 trigger and Appendix A updated; the equivalence-class paragraph names `Store::check`.
- **`NO_SCTS` classification stated once**: revokt's parser collapses absent, empty and malformed to
  an empty list; the Kotlin engine answers `NO_SCTS` on it, the upki engine `NOT_COVERED` (one class).
- **Path-cache entries store the leaf's serial and SCT list**, so a path-cache hit never re-parses.
- **Lazy `fetcherTrustManager` build failure no longer throws**: the call returns on the platform
  verdict (flow step 1 only), is logged, and the next call retries; goal 3 holds without exception.
- Numbering fixed: "flow step 1" (platform call) versus "decision step 1" (take the snapshot); the
  invariant reads "can go past flow step 1"; "handed out" wording replaced in `ready`, decision
  step 1 and residual 3.

### Changes in revision 21 (engine seam below the parser; mini round on revision 20, one seat)
- **Decision: swapping engines must not change verdicts.** `RevocationEngine.query` now takes the
  extracted triple (issuer SPKI SHA-256, raw serial, SCT timestamps) for every engine; the DER-based
  `query(leafDer, issuerDer, nowMillis)` and the internal `IndexedRevocationEngine` are gone. revokt's
  parser and issuer resolution feed every engine the same values. The upki adapter calls upki's
  library API (`RevocationCheckInput::new` + `Store::check`, public in upki 1.0.1) through a small
  shim of ours, not the stock `upki_check_revocation`, so webpki never parses a certificate in
  revokt. The §3.2 mapping table loses its three abstain rows; the cross-engine suite compares the
  lookup alone. Path-cache entries no longer carry an issuer DER.
- Consistency fixes from the rev20 seat: the invariant reads "can go past decision step 1" (step 1
  is the platform call, the snapshot is first consulted at step 2); `fetcherTrustManager`'s lazy
  build defined (no `HttpFetcher`/`FetcherTls` without a fetching source; built under the factory
  lock on its first `checkServerTrusted` in `STARTED`, a failure there is `CertificateException`,
  not memoised; `status()` reports null until then); the factory-lock hold during `start()` stated in
  full; flow step 0 and the readiness paragraph say "before any handshake can go past step 1";
  §10 residual 3 restated for the unconditional guard; fixture (h) scoped to `trustManager(d)`
  instances; "fetching source" defined at its first use; §7.3 says `SYSTEM` is attempted, not fetched.

### Changes in revision 20 (mini consistency round on revision 19, two seats)
Consistency fixes to the synchronous anchor snapshot, no new design:
- **`start()` holds the factory lock for its whole synchronous part and flips to `STARTED` last**,
  so a `trustManager(d)` or a second `start()` can never observe a flip that is later undone;
  `close()` flips under the same lock. A throwing `start()` discards the snapshots it built and a
  retry rebuilds every pre-start instance.
- **No trust-store broadcast receiver.** Android clears the NSC caches in every running process by
  a system push (`handleTrustStorageUpdate()`), with no app receiver; a receiver would be a second,
  unordered delivery. The walker-reason trigger (`NO_CANDIDATE`/`UNANCHORED` → `refreshAnchors()`)
  covers a newly installed user CA. The Android `StrictMode.allowThreadDiskReads` guard is therefore
  **unconditional** around the delegate call, whatever the delegate and thread, restored in a
  `finally`; it hides the report, not the read (a Conscrypt `TrustManagerImpl` over `AndroidCAStore`
  re-enumerates the cacerts directories on every call).
- `fetcherTrustManager`'s snapshot is built inside `start()` only when a fetching source is
  configured (an empty or throwing default trust store then fails `start()`, since no fetch could
  succeed); with none it is built lazily at first access with the wiring rule.
- `TrustManagerStatus.anchorSnapshotId`/`anchorSnapshotAgeMillis` nullable again, null only for an
  instance obtained in `CREATED` before `start()` or in `CLOSED`; the invariant reads "a trust
  manager that can reach decision step 1 has a snapshot". `Finding.Path.anchorSnapshotId` is 0 when
  no snapshot was consulted. `RevoktTrustManager.awaitReady()` defined as the owning `Revokt`'s.
- A concurrent `trustManager(d)` after a failed build retries it (failures are not memoised); the
  dead default-delegate warm-up clause removed; fixtures (h)/(u) de-duplicated and six cases added;
  the 0.3 probe names its trigger; Appendix A corrected for `TrustManagerImpl` and the NSC push.

### Changes in revision 19 (anchor snapshot synchronous on both platforms; mini round on the revision-18 draft, two seats)
Revision 18 built the anchor snapshot synchronously on the JVM only and kept a loader build on
Android. The mini round found that the loader path still leaked into the start task, `resetState()`,
a `start()`/`trustManager(d)` race, `fetcherTrustManager` and a settled future that cannot be
re-completed on retry, and verified (AOSP `NetworkSecurityTrustManager`, `DirectoryCertificateSource`)
that Android's `getAcceptedIssuers()` is lazy and cached per process: disk is read on the first
call per process and after a trust-store change only. So revision 19 makes the build synchronous
on **both** platforms and deletes the asynchronous snapshot machinery:
- **Built before the trust manager is handed out**: inside `start()` for trust managers created in
  `CREATED` (first synchronous step, before the registry and the store lock) and at wiring, inside
  the factory lock, for trust managers created in `STARTED`; `start()` collects the pre-start set
  and flips the lifecycle under that same lock, so no instance falls between. A throw from
  `getAcceptedIssuers()`, an empty anchor set or a build failure throws `IllegalStateException`
  from `start()` (which stays `CREATED`, holds no lock, registers nothing, may be retried) or from
  `trustManager(d)` (no registry entry, no cap slot, no `sslContext` memo entry).
- **Android**: `start()` warms the NSC certificate sources once; a later wiring on the main thread
  reads disk only after a trust-store change and runs the delegate call under
  `StrictMode.allowThreadDiskReads`. The rule is thread-independent.
- **Deleted**: `snapshotReady(tm)`, `snapshotDeadline`, `TrustManagerStatus.snapshotFailed`,
  `DiagnosticCode.SNAPSHOT_FAILED`, `NoIssuerReason.SNAPSHOT_UNAVAILABLE`, the snapshot clause of
  `RevoktState.ready`, the snapshot wait in flow step 0. Decision step 1 now reads the snapshot
  reference. `refreshAnchors()` rebuilds on the loader and a failed rebuild keeps the current snapshot.
- `fetcherTrustManager` is created at `build()` and built inside `start()`. `resetState()` leaves
  snapshots untouched. Fixtures (h) and (u), the trust-manager invariants, the §11 0.3 emulator
  probe and Appendix A updated. **§10 residual 3 is closed.**

### Changes in revision 17 (mini consistency round on the revision-16 edits, two seats)
Consistency-only fixes, no new design: download and record caps are builder-overridable while
walker budgets stay constants; `CAP_NEAR_LIMIT` measures against the fixed caps and the live check
warns; §6.3 "declared size" qualified; `FetchRequest.maxBodyBytes` is the signed size or the fixed
cap; leaf validity is checked at a live fetch (only the terminal is exempt); a fourth
`ENGINE_ERROR` producer wording; the read-only lock retry uses the bounded try; a cancelled install
deletes its directory at once while a crash-interrupted one is pruned at the next `start()`;
`GenerationFiles.generationId` added so `install()` echoes it; `SNAPSHOT_FAILED` and `SYNC_FAILED`
codes defined where emitted; `BLOCKED_BY_SELF` mapped for the worker; the Go producer oracle is a
CLI during fuzzing and admission, `c-shared` nowhere required; `STORE_LOCKED` cites §5.1; x5u cap
in KiB; a sync-time `engine.install()` throw increments `storeFailures`.

### Changes in revision 16 (round E: third full-spec pass, three independent seats)
Six blockers, all three seats converging on one: the read-only instance of revision 15 was told to
run the same loader task as the owner, which writes. Resolved here:
- **Read-only mode never writes**: the seed and the system cache are installed into the engine and
  published in memory only, the seed-vs-stored rule is re-applied on every pointer reload,
  `store.version` is not initialised, `resetState()` throws; the instance retries the try-lock every
  `READONLY_POLL_INTERVAL` (60 s) and on `sync()`, and **promotes itself to writer** when the owner
  is gone; `OverlappingFileLockException` maps to `StoreLockedException`; `close()` deregisters the
  directory. `RevoktStorage.identity()` is the registry key.
- **Prune never touches a pointer-named directory**; a failed or interrupted `engine.install()`
  deletes its directory; "newest" is pointer order. Two consecutive bad records can no longer turn
  a stale client into a fail-closed one.
- **Cursor, `lastVerified*` and the watermark advance only after the pointer flip of a successful
  install**, and every record is schema-validated for the requested collection before any state
  change: the content signature does not bind the collection id, so a replayed signed changeset
  from a sibling collection could otherwise freeze the cursor. `collection` recorded in `meta.json`.
- **x5u terminal has trust-anchor semantics**: only its pinned SPKI is checked; validity, CA bits
  and subject are evaluated on the leaf and non-terminal links only. Root expiry can no longer
  freeze deployed clients or seeds, and the check it replaces stopped no attacker.
- **Caps**: for `SIGNED` sources the per-body cap is the signed `attachment.size`; the fixed caps
  bound unsigned bodies only; `MAX_MANIFEST_ENTRIES` is over C2SP manifest attachments, changeset
  records have their own cap; bodies are fetched, verified and written one at a time; gzip inflation
  is capped while inflating; every download and record cap is overridable upward through
  `limits { }` (walker budgets stay constants); a live check warns at half of each fixed cap.
- **Seed**: skipped when the stored `SIGNED` generation is not older; blobs with an existing key are
  never rewritten; a complete existing directory is `UNCHANGED`; the watermark takes
  `max(watermark, verified seed timestamp)`.
- `CrliteQueryResult.NO_DATA` mapping split by whether a generation is published; step 7 never
  queries an engine for a dataset without a generation; `RevocationEngine.clear()` with a default
  body; `install()` returns the identity the loader publishes.
- `RevoktState.warnings` and `SyncResult.warnings` are `List<PolicyDiagnostic>`; `ready` requires
  `STARTED` and settled snapshots; `snapshotDeadline` measured from `max(created, startedAt)`;
  `resetState()` re-runs the start task; on-disk field derivations fixed (directory name, blob map,
  `updater.json` source id, persisted enum names, lowercase segments); owner-uid and permission
  check falls back to `inMemory()` for the session; redirects never followed; events enqueued only
  with a listener and drained outside the ring lock with a lost-wakeup re-check; the Go producer
  oracle runs out of process during fuzzing; `GenerationFiles.sha256(name)`; `channel` is mandatory
  on the builder; dependency scopes `api` where types cross; `Finding` labelled growable.

### Changes in revision 15 (round D: second full-spec pass, three independent seats)
Round D found eight blockers, seven of them inconsistencies among the revision-14 edits and one
older (`java.time` members on commonMain types). All are resolved here:
- **Public types with `java.time` members live in jvmMain** (`Staleness`, `RevoktPolicy` and its
  `Builder`); commonMain holds only an internal policy table. The purity gate compiles commonMain.
- **Store lock**: acquired once in `start()`, held to `close()`, bounded try-lock; a locked-out
  instance (another process) runs **read-only** and re-reads the pointer each loader tick; writes
  never take the lock themselves; single instance per directory per process by registry.
- **Fetch is buffered, not streamed**: per-kind download caps (filter 16 MiB, JSON 4 MiB, x5u 64 KB),
  manifest entry cap, per-sync total cap, manifest rejected before any body fetch.
- **Event delivery**: per-listener cursor and drain flag over one sequence-indexed ring.
- **`start()` split**: synchronous on both platforms for the lock, `store.version`, pointer and
  `meta.json` reads and the `seed.json` header (these may throw); decode, seed verification, install,
  snapshot builds and first sync run as one loader task that the JVM joins; the loader is the sole
  publisher of the generation.
- **After `close()`** every live trust manager runs step 1 only (the "keep evaluating" sentence is
  gone); in-flight counter pattern stated.
- **Seed vs stored generation**: the seed installs unless the stored generation is `SIGNED` and
  newer; a stored lower-class generation is always evicted by the seed and pruned at once; the
  pointer file records `previous` explicitly and recovery never selects a lower class than the
  class being replaced; the seed advances the watermark; seed `index.bin` is rebuilt from
  `records.json` and byte-compared.
- **Rollback**: the coverage-monotonic refusal applies only inside the rollback window
  (`timestamp ≤ watermark`); a newer signed changeset installs whatever its coverage (reverses a
  revision-14 rule that would have frozen every client on a legitimate Mozilla rebuild). Honoured
  `Backoff`/`Retry-After` capped at 24 h, failure backoff at 6 h, persisted backoff at 24 h.
- **Store layout**: content-addressed blobs for filter files, generation directories named
  `gen-<timestamp>-<hash16>`, `channel` in `meta.json` and in the layout, `meta.json` written last as
  the completeness marker, delta parent derived from the pointed generation, first run is not a
  store failure, directory permissions checked on POSIX, path-escape and reserved-name rules.
- **Install order**: `engine.install()` → publish snapshot → flip pointer → `updater.json`;
  `CrliteQueryResult.NO_DATA` while a generation is published is `ENGINE_ERROR`.
- Sync source order by descending rank with the bootstrap condition; lower-class sources are not
  fetched while a higher-class generation exists; `mirrorFallback` dropped (redundant with
  `trustClass`); `c2spCache` counts as local data only when the policy can install it.
- `awaitReady()` settles on a failed snapshot and fails on `close()`; `resetState()` rules;
  output-type builders stay on the production types behind `@RevoktTestingApi`; `Finding` sealed;
  `FetcherTls` members and a default `JdkHttpFetcher`; `OkHttpFetcher` replacement list; WorkManager
  name per instance and worker in the store-owning process; `MAX_CERT_BYTES` consistent; new §9
  fixtures for every rule above.

### Changes in revision 14 (round C: full-spec pass, three independent seats: API, security, systems)
- **Blocker, security: mirror displacement.** A `MIRROR`/`SYSTEM` generation could displace a stale
  `SIGNED` one after 24 h of a blocked feed, and the mirror is TLS-only. Now **bootstrap-only**: a
  lower-class generation installs only when the dataset has no higher-class generation at all and is
  evicted by the first `SIGNED` one (seed included); a stale `SIGNED` generation is never displaced
  by a lower class (§7.3, §6.3, §10).
- **Blocker, API: `EVIDENCE_ALLOWS`** (introduced in revision 12) would have made the shipped
  presets fail `validate(ENFORCE)` on the M3/M4 releases; it now fires only when the consumer lowers
  an `EVIDENCE` rule below its preset, and a test asserts every preset validates at every release.
- **Rollback**: coverage-monotonic rule applied to `SIGNED` generations too; `rollbackWindow`
  default = `clockSkew` (24 h); a refused rollback is not a feed failure.
- **Fetcher policy defined** (§8): `REVOKED` and later evidence rules reject, everything else allows,
  no data rules, no exemptions, evaluated against `SIGNED`/`BUNDLED` generations only, from M1.
  Self-lockout is possible only by a signed revocation of the feed host's certificate, reported as
  `updateBlockedBySelf`.
- **x5u chain**: basicConstraints, pathLen, name chaining, keyUsage and per-certificate validity on
  every non-leaf link; `mode` pinned to `p384ecdsa`; attachment base URL pinned; absolute per-file
  download cap.
- **Store specified** (§6.5): `RevoktStorage` is an interface over a flat key space; the engine's
  layout has a `store.version`, per-generation `meta.json`, a persisted updater record (backoff,
  consecutive failures, cursors, watermark), pointer-file flip with fsync, crash recovery order
  (pointer → previous → seed, counted), advisory file lock, single instance per directory, and a
  versioned seed manifest with channel and format floors.
- **Lifecycle** (§5.1): `CREATED → STARTED → CLOSED`; `start()` installs the stored generation and
  seed synchronously on the JVM; `close()` ordering with in-flight handshakes and engine ownership;
  `RevocationEngine.query` after `close()` returns `ENGINE_ERROR`; trust managers created before
  `start()` or after `close()` run step 1 only; the loader runs under every enforcement mode.
- **Readiness**: `awaitReady()`/`readyFuture()` complete when `RevoktState.ready` first becomes
  true with no internal deadline; `ready` no longer depends on a default trust manager nobody built.
- **Counters** increment per applied verdict, cache hit or miss; events on misses only; one
  immutable `GenerationSnapshot` read per call; event drain is triggered on enqueue.
- Fetch moved off the loader thread with streaming to the store; `FetchRequest`/`FetchResponse`
  shaped; `PlatformTrust` moved to jvmMain with its member list; `EvaluationRequest` split into
  `presented` and `verifiedPaths`; `JcaSignatureVerifier` key cache bounded; `TrustClass` growable
  with `rank`; `DataState.trustClass` nullable; `MAX_CERT_BYTES` 256 KiB; WorkManager worker name
  and `Revokt.Provider` fixed; new §9 data-path fixtures as 0.2 gates.

### Changes in revision 13 (round B: §9.2 differential parser oracle, two independent seats)
- **D1 and D2 restated over each oracle's own `getEncoded()` output (blocker, both seats)**: the
  JDK factory ignores trailing bytes and converts BER before parsing, so a raw-bytes D1 was
  violated by the spec's own D7 corpus. Raw-byte leniency is now informational (D1-raw).
- **Producer oracle added**: Mozilla's own `crlite/go/types` (`ParseCertificate`,
  `NewSerialFromCertificate`, `RawSubjectPublicKeyInfo`) compiled as a Go `c-shared` library.
  Verified in source: the producer keys on the **raw INTEGER content bytes** of the TBS serial
  (`asn1.RawValue.Bytes`) and the raw SPKI TLV, parsed by ct-go's lax parser; a proposed
  minimal-encoding normalisation of the serial was therefore rejected. D1's security domain is
  "platform-accepted and producer-keyable"; a certificate the producer cannot key is recorded, not
  gated, since no filter can contain it and revokt's `PARSE_FAILED` is the correct answer.
- **Oracle 3 split**: `x509-parser` single-certificate reference for D2/D3; webpki via upki
  (pair input) records divergence only and is never a precondition; a minimal independent TLV
  locator supplies raw bytes where `x509-parser` rejects. Per-oracle `Accept | Reject | Crash`
  rules and the effect of an oracle crash on the gate are tabled.
- **Issuer corpus**: every Mozilla `intermediates` record, the CCADB export and both platform root
  stores at zero tolerance; every CRLite-enrolled intermediate's `SHA-256(rawSpki)` must be a key of
  the live filter index; a dropped candidate is now observable (`Finding.Path.candidatesDropped`).
- **SCT rules fixed**: pairs are the union over every SCT extension whose list parses; `NO_SCTS`
  iff the union is empty; the `x509-parser` mapping and Firefox-decoder divergences are recorded.
- **Harness made runnable**: fuzzing on one pinned JDK ≥ 22 with oracles in-process; the version
  matrix is a replay of the union corpus with goldens recorded at admission; one entry schema for
  the four record kinds; seed corpus pinned by manifest; secondary corpus bounded by coverage merge;
  platform-Conscrypt replay is a 0.3 gate; Kover over the committed replay is the coverage gate.
- Public byte contracts fixed in §3.2/§4: `serial` is `rawSerial`; `issuerSpkiHash` is the SHA-256
  of the SPKI TLV; SCT timestamps are RFC 6962 `u64` carried in `Long`, compared unsigned.
- Appendix A: producer-side verification entries.

### Changes in revision 12 (round A: `Rule` model, two independent seats)
- **`STALE` semantics fixed (blocker)**: `STALE` fires for a dataset iff `rejectStaleAfter != null
  && age > rejectStaleAfter`; `staleAfter` is only the loud threshold (`DataState.stale`,
  `RevoktStatus.stale` per dataset, metered deferral). The `DEFAULT` row never fires; `validate()`
  warns when `STALE` rejects but no dataset has a reject threshold.
- **Data rules computed outside the catch boundary** and merged into every verdict, `ENGINE_ERROR`
  included, so an engine exception can no longer turn a `NO_DATA` reject into an allow.
- **`MIRROR_FALLBACK` replaced by `UNSIGNED_DATA`** defined by trust class against a per-dataset
  floor (`minTrustClass`), so `SYSTEM` and mirror-only data are covered; the loader never installs a
  lower-class generation that the policy would reject, so a mirror can only add availability.
- **Growability contract repaired**: the one-minor `ALLOW → REJECT` flip is an accepted fixture
  diff (`flippedIn` column, once per rule and preset); "frozen rows" carves it out.
- **`Exemption` takes an `ExemptionContext`** (growable final class) instead of positional parameters.
- **`RevoktCertificateException` cause**: `BasicReason.REVOKED` only for an `EVIDENCE` rule;
  `UNDETERMINED_REVOCATION_STATUS` otherwise.
- **Path aggregation for L1/L2/L5 stated now** (M2 ships `REJECT` without the one-minor rule):
  a path-level evidence rule fires only when every found path carries a hit after the exhaustive
  re-walk; `Finding.PathHit` reserved.
- `RuleClass` defined one line each; M3 `CT` planned as `EVIDENCE`, `CT_UNVERIFIED` as `NON_ANSWER`.
- `NOT_WALKED(SNAPSHOT_UNAVAILABLE)` spellings replaced by `NO_ISSUER(SNAPSHOT_UNAVAILABLE)`.
- Additive-but-cheap-now: `Finding.DataState.rules`, `PolicyDiagnostic.code`/`dataset` with the
  emitting call per diagnostic, `Rejected.rule` non-null, `EVIDENCE` rule set to `ALLOW` is an
  error under `ENFORCE`, missing Java overloads, `exempt()` replaces, `Finding.EngineError.producer`
  an enum, `Severity` and `DiagnosticCode` declared, duplicate `GenerationFiles` removed from §4,
  §6.2 `NO_SCTS` branch, `rules` iteration order, new §9 tests.

### Changes in revision 11 (decisions, upki-engine seam, standalone text)
- **Decisions recorded**: the name stays `revokt` (§13); `NO_SCTS` and `PARSE_FAILED` keep allowing
  in `DEFAULT`, matching Firefox (§10, residuals 7 and 8 are now decisions, not open items).
- **§3.2 rewritten so a upki-backed engine is a drop-in**: `revocationEngine(…)` is a public builder
  seam from 0.1; `GenerationFiles` carries a `format` (`FilterFormat.V3 | V4`) and is always in C2SP
  layout with an `index.bin` that revokt builds for Remote Settings generations; `RevocationEngine`
  declares the formats it accepts; the upki adapter's lifecycle (fresh directory per generation,
  volatile handle swap, drain before `upki_config_free`), its fixed result-code mapping, and the
  cross-engine **equivalence classes** are specified, verified against upki's `ffi.rs`,
  `revocation/mod.rs` and `rustls-upki` (Appendix A). Corrected: through the C FFI a certificate
  with no SCTs is `NOT_COVERED`, not a `cert_has_no_scts` outcome, and `rustls-upki` rejects a
  malformed SCT list rather than treating it as absent; the suite classes reflect both.
- **Standalone text**: §9 M1 test bullets, §9.1 targets and harness, and the §10 security bullets
  previously cited "as in revision 7/8" are inlined.
- **New §9.2 differential parser oracle**, the mitigation that residual 8 relies on: oracles,
  properties D1–D7, generators, platform matrix, and acceptance gates. It is a 0.1 gate.
- `Revokt.evaluate` over raw bytes is documented as presuming platform-accepted encodings.

### Changes in revision 10 (seventh review round, scoped to §5.1 and the `Rule` model)

Cohort 7 again found **no blocker in §5.1 from either walker seat**; the adversarial reviewer's
verdict is that a server cannot choose to go unchecked on JVM bindings or the Android socket
binding, and that §5.1 is clean once three text items land. The two blockers this round were
outside the walker: a committed fixture that contradicted the ordering rule, and `kotlin.time.Duration`
on the policy surface, which broke the spec's own Java rule. All items are folded in below.

- **Walker text**: one ordering rule for byte-duplicates (earliest position in the node's order;
  store position below the leaf); the unrelated loop stops as soon as a path exists and is the
  complement of the related set; `MAX_PRESENTED` (64) added with excess as `Budget`; a `NotFound`
  on a chain the platform accepted but too long for the fallback is `PATH_BUDGET_EXCEEDED`, not an
  allow; the fallback's role restated (canonicalisation residue on `NotFound` chains of at most 8
  certificates; on default delegates every honest issuer is related, so the residue is confined to
  custom delegates); a no-throw contract for the walk under any verifier; `MAX_DEPTH` convention
  fixed; `Walk` variants all carry the unsupported-OID set; Android step 4 retries the extension
  call with a null host before falling to the walker. (§5.1, §5.2)
- **Decision list**: every exit from steps 1–6 continues to step 7; parse inside step 3;
  `PLATFORM_ONLY` applies to any `NotFound` whose fallback also failed on a trust-manager binding,
  with the walker's own reason kept on `Finding.Path.walkerReason`; anchor refresh keyed on the
  walker reason. (§5.1)
- **Caches, readiness, factory, events**: `PLATFORM` entries carry hashes, not indices; the 3-arg
  Android overload always calls the extension to obtain its return value; readiness waits only on
  what the policy needs and not under `OFF`; `ENGINE_ERROR` and `SNAPSHOT_UNAVAILABLE` never cached;
  `sslContext` memo holds contexts weakly; queue drained on loader ticks; concurrency of caches
  stated. (§5.1)
- **Fixtures**: (y) rewritten to a chain whose sub-leaf issuer is not in the store, with the old
  construction kept as (y2) pinning terminal-first; (k) count corrected; (ac)/(ad) marked
  walker-harness-only; (ad) rebuilt as an exploration-budget mesh; a verification-budget fixture;
  determinism notes; P3/P4/P6 wording; P7 no-throw. (§9, §9.1)
- **`Rule` model**: time fields stored as millis with `java.time.Duration` accessors and factories,
  `kotlin.time` as `@JvmSynthetic` extensions; `Rule.PRECEDENCE` in a companion with the invariant
  "declaration order grouped by class, append at the end of the group"; explicit `PathStatus → Rule`
  and `CrliteQueryResult → Rule` tables and multi-key aggregation; `validate()` returns typed
  diagnostics; empty `requiredDatasets` semantics; `generationEpoch` internal and `dataStates`
  entries for every required dataset; `RevoktEvent.chainSha256`; sync timestamps and counters;
  `Verdict.crlite` and the reported path defined on `Budget`; `Freshness` moved to `DataState` with
  `fromSeed`; the one-minor rule applied uniformly with a golden-fixture test; output builders moved
  to `revokt-testing`; walker counters behind `Path.WalkStats`. (§4, §8)
- **§10 residuals** corrected and extended.

### Changes in revision 9 (sixth review round, scoped to §5.1 and the `Rule` model)

Cohort 6 was the first in which **neither walker reviewer found a blocker in §5.1**: the
adversarial reviewer could not construct an allow for a revoked leaf under `DEFAULT` on any binding,
and the implementation reviewer confirmed termination and that every exhaustion unwinds to a
reject. The changes below are the should-fix items from that round plus two blockers outside the
walker itself (the fuzzer oracle and the data rules).

- **Walker text and limits corrected to match the code.** Unrelated candidates are presented
  certificates only (store anchors never enter the unrelated loop) and are not capped, so an honest
  issuer the relation test misclassifies is still explored unless the chain exceeds the verification
  guard; below the leaf, related candidates are ordered terminal-first (store anchors, then
  presented) so an honest cross-signed chain costs two verifications; `MAX_RELATED_PER_LEVEL` raised
  to 64; "any exhaustion anywhere is `Budget`" stated plainly; the cost claim restated as bounded by
  the guards; exact-byte dedup across presented and store; unsupported OIDs collected from related
  candidates only; `leafKeys` defined for a `[leaf]` path; `WalkEnd.DEPTH` dropped. (§5.1)
- **Decision list made total**: snapshot → anchor-by-bytes → parse → Android platform path →
  walk → fallback → data → rules; `NO_DATA` fires whenever the data step runs; on `Budget` only
  `REVOKED` fires from CRLite; `ENGINE_ERROR`'s three producers named; `PLATFORM_ONLY` reason for a
  chain the platform accepted that neither the walker nor the fallback can reproduce. (§5.1, §8)
- **Fallback's role stated**: it covers canonicalisation residue and platform divergence; a
  policy may not disable it while `NO_ISSUER` allows; capped at 8 presented certificates against
  PKIX backtracking blow-up. **Fixtures (s) and (t) corrected** to what the code does. (§5.1, §9)
- **§9.1 fuzzer oracle rewritten**: a relation-aware, uncapped reference walker; world versus
  attacker mutations; P2–P6 restated so a correct implementation passes them. (§9.1)
- **Readiness, factory, flow and listener mechanics made implementable**: component futures
  completed at their own deadlines by the loader; waiting overloads always wait for the snapshot;
  verdict cache consulted before parsing; one lock for the factory; `ReferenceQueue` on the trust
  manager reference; `sslContext` matched by identity per key manager; `Rejected` events evict
  `Accepted` ones with a bounded side queue. (§5.1)
- **`Rule` model**: data rules scoped **per dataset** (`requiredDatasets`, per-dataset staleness,
  per-dataset freshness timestamp) so OneCRL's quiet months never trip `STALE`; `Verdict.path`
  non-null with `NOT_WALKED` producers; `CrliteStatus` merged into `CrliteQueryResult`;
  `Verdict.crlite` defined; `TrustManagerStatus`; `exempted` counter; the seed rule warns under
  `OBSERVE` and fails under `ENFORCE` with `validate(enforcement)`; growability contract completed
  (`layer`/`exemptable` frozen, every enum labelled, new `REJECT` rows ship `ALLOW` for one minor);
  closed `RuleClass` deriving precedence; `onStateChanged` default listener method; `CrliteSct` defined. (§4, §8)
- **§10 residuals recorded** as the adversarial reviewer listed them.

### Decisions carried from revisions 2 to 8 (verified against live sources, Appendix A)

Mozilla serves CRLite **v3** on two channels and the upki mirror a **v4 transcode**; three source
trust classes; Conscrypt's hostname-only path drops TLS SCTs; `DEFAULT` is fail-closed on missing
CRLite data and allows stale data loudly with no ceiling (upki's model); seeds verified at their
signed timestamp; `channel` top-level and required; observe mode is a runtime switch; pure-Kotlin
engine on DER bytes with `LongArray` columns; minSdk 26; MPL port contained per §3.1; Apache-2.0;
0.x until M2; `kotlin.time.Clock`; fuzzing a requirement; CI-only upki-backed engine; chain-driven
`RevocationEngine`; §6.2 aggregates over covering filters only; mirror precedence trust-class-aware;
extended delegates required on the JVM; `ENGINE_ERROR` allows in `DEFAULT`; deferral by relation.

## 1. Problem and gap

As of 2026-10-21, a JVM or Android client has no maintained way to consume browser-grade PKI
policy data. No Kotlin or Java library reads **CRLite**, **OneCRL**, Mozilla's **intermediate
preload** set, or Chrome **CRLSets**. The closest tools are `rustls/upki` (Rust 1.0.1, C FFI of
three functions, no Android targets), Mozilla's `rust-query-crlite` CLI, and `agl/crlset-tools`.
OkHttp (5.5.0, now at `lysine-dev/okhttp`) does no revocation checking; JSSE's OCSP/CRL support is
off by default, slow and privacy-leaking; the JVM has no CT enforcement and Android gained it only
in Android 16 via NSC. The eMudhra compromise (8 intermediate keys recoverable from the public
certificates, 2026-10-17, CVE-2026-111943) showed the gap.

revokt fills the gap in stages, natively on the JVM by default: no JNI, no `.so`, no second TLS
stack, one line into OkHttp and every Ktor engine.

## 2. Goals and non-goals

**Goals for M1 (0.x until M2)**
1. **CRLite leaf revocation** from Mozilla's signed filters, both channels, both encodings, C2SP
   `upki-revocation@v1.0.0` conformant, able to read a system upki cache.
2. **Authenticated data with an explicit trust class per dataset**; policy can require signed data.
3. **Additive-only rejection.** The platform verdict runs first and is final for acceptance. revokt
   never rejects because of its own failures (`NO_ISSUER`, `ISSUER_UNVERIFIED`, `PARSE_FAILED`,
   `ENGINE_ERROR` in `DEFAULT`). **Two stated exceptions**: `PATH_BUDGET_EXCEEDED` rejects in
   `DEFAULT`; it is reachable only by a chain carrying more same-name or same-key-identifier
   candidates for one certificate, or more verifying junk overall, than any honest chain has (§5.1).
   And `NO_DATA` rejects in `DEFAULT`, only after the consumer has promised local data and
   `validate()`/`start()` have confirmed it is loadable (§4; an unreadable sole seed fails `start()`; an
   unreadable sole `c2spCache` rejects loudly after a `STORE_UNREADABLE` warning, which is why the seed is the default).
4. **Pure-Kotlin engine**, `commonMain`, enforced by a CI-only native compile; 1.0 ships `jvm()` only.
5. **Per-handshake cost**: p95 under 1 ms with the JIT warm and the chain's path cached; first
   contact with an honest chain performs at most depth + 1 signature verifications (§5.1).
6. **Operable**: `Enforcement.OBSERVE` runs the exact policy that will be enforced and yields
   would-reject rates by rule, host, anchor and generation; runtime switch; explanatory status.
7. **Binary-compatible within a major** from 1.0; opt-in APIs excluded from the promise.

**Later goals** (§11): intermediates, OneCRL and emergency intermediate revocation (M2); CT (M3);
broader distrust (M4); Merkle Tree Certificates (M5).

**Non-goals**: OCSP or CRL fetching; client-certificate revocation; replacing the platform
verifier; non-JVM targets in 1.0.

## 3. Modules, dependencies and licensing

| Artifact | Source set | Contents | Depends on |
|---|---|---|---|
| `revokt-clubcard` | common | Port of `clubcard` and `clubcard-crlite` query and decoding (no builder), v3 and v4. Public only under `@RevoktInternalApi`. | Okio |
| `revokt-engine` | common | `KotlinRevocationEngine` (the default engine), DER/TBS parser, `EvaluationRequest` and `Evaluator` (sealed; its single implementation lives beside it and is what `Revokt.evaluator` returns), candidate index and path walker, CRLite evaluation, coverage index, generation model, policy and precedence, `Verdict`, updater state machine, Remote Settings protocol, JSON tree and canonical JSON, content-signature logic, C2SP cache reader/writer, `RevocationEngine` (Kotlin), the `SignatureVerifier`, `HttpFetcher`, `PathBuilderFallback`, `RevoktStorage` interfaces, `expect class FetcherTls`, `expect class SeedSource`, `expect fun canonicalSubject`, `RevoktLimits`, the internal policy table; **no public type with a `java.time` member** | `revokt-clubcard`, Okio, kotlinx-coroutines |
| `revokt-engine` `jvmMain` | jvm | `Staleness`, `RevoktPolicy` and its `Builder` (the public policy surface, with `java.time` members), `JvmStorage`, `actual FetcherTls` with its members, `actual canonicalSubject` (`X500Principal.getName(CANONICAL)`), `actual SeedSource` (`of`, `fromResource`, `bundled`), `SeedOpener` and `JvmSeedSource`, `JcaSignatureVerifier(provider)`, `PkixPathBuilderFallback`, `PlatformTrust`, the `Rule → BasicReason` map (`java.security.cert`, so jvmMain; total over `Rule.entries`, asserted by the 0.1 golden fixture), `RevoktLoggers.jul()` | JDK |
| `revokt-jsse` | jvm | `Revokt` facade and `Builder`, `RevoktTrustManager`, `JvmPlatformTrust`, `X509Certificate` adapters, `JdkHttpFetcher.Factory` (HttpsURLConnection over `FetcherTls`, the default `http` on the JVM; never on Android, §4) | `revokt-engine` |
| `revokt-bc` *(optional)* | jvm | BouncyCastle `SignatureVerifier` for ML-DSA, SLH-DSA, composite OIDs and BC-only curves | `revokt-engine`, bcprov |
| `revokt-okhttp` | jvm | `RevoktOkHttp.install(builder, revokt, delegate?)`, `OkHttpClient.Builder.revokt(…)`, `OkHttpClient.withRevokt(…)`, `OkHttpClient.revoktTrustManager()`, OkHttp-backed `HttpFetcher` | `revokt-jsse`, OkHttp 4.12+ / 5.x |
| `revokt-ktor-core` | jvm | Ktor-backed `HttpFetcher` (refuses CIO on Android) | `revokt-jsse`, ktor-client-core |
| `revokt-ktor-okhttp`, `-ktor-cio`, `-ktor-java`, `-ktor-android` | jvm | One adapter per engine (Ktor's Android engine is a JVM artifact) | `revokt-ktor-core`, that engine |
| `revokt-android` | android | `AndroidPlatformTrust` (final), `AndroidStorage.noBackup(context, name)` / `deviceProtected(context, name)`, `RevoktAndroid.meteredNetwork(context)`, `RevoktAndroid.observeLifecycle(provider)` (the §5.2 lifecycle observer, for consumers without WorkManager), `AndroidHttpFetcher.Factory` (HttpsURLConnection without the JDK-only `setAuthenticator`; the fallback default `http` on Android, §4), `RevoktAndroid.logger()`, consumer R8 rules, Baseline Profile; the Android PKIX fallback | `revokt-jsse` |
| `revokt-android-work` | android | WorkManager periodic sync: worker class `dev.revokt.android.work.RevoktSyncWorker` and unique work name `dev.revokt.sync.<name>` (one per instance, `name` carried in the worker's input data) are fixed from 0.3 (WorkManager persists both across upgrades); `object RevoktWork { @JvmStatic @JvmOverloads fun install(context: Context, provider: Revokt.Provider, name: String = "default"); @JvmStatic @JvmOverloads fun uninstall(context: Context, name: String = "default") }` (`uninstall` also removes the §5.2 lifecycle observer `install` registered), called in `Application.onCreate`, registers the provider by name in a static map; the worker takes the instance from it (`Provider.revokt()` runs on the worker thread, off the main thread), calls `start()` itself when the instance is `CREATED` (idempotent, under the factory lock; a `start()` throw is `Result.retry()` with the exception logged at `WARN`, except `SEED_CHANNEL_MISMATCH` and a validate() `ERROR`, which cannot change between periods and are `Result.failure()` that cancels the unique work, logged at `ERROR`), then `syncBlocking()`, which queues behind the start task; a worker with no registered provider returns `Result.failure()` and cancels its own unique work; `RevoktWork.uninstall(context, name)` cancels the unique work and removes the provider (an app that drops the library must call it once, or WorkManager keeps instantiating the missing class every period); **stop semantics**: on `onStopped` or interruption the worker returns (WorkManager ignores its result), the in-flight sync completes on the loader, the next period re-runs; the worst-case fetch sum of one signed sync (≈ 11 fetches × `FETCH_TIMEOUT`) is under WorkManager's 10-minute limit by construction; outcome mapping: `INSTALLED`/`UNCHANGED`/`DEFERRED`/`BACKOFF`/`ROLLBACK_REFUSED`/`STORE_LOCKED`/`BLOCKED_BY_SELF` → success, `FAILED`/`CLOCK_SKEW`/`STORE_FAILED` → retry. A read-only instance (§5.1) may still host the worker: it promotes itself to writer when the lock is free | `revokt-android`, WorkManager; `RevoktWork.install` enqueues `PeriodicWorkRequest(6 h, flex 1 h)` with `NetworkType.CONNECTED`, exponential backoff and `ExistingPeriodicWorkPolicy.UPDATE` (so a library upgrade can change them); consumer rules in this artifact keep `RevoktSyncWorker` and its `(Context, WorkerParameters)` constructor (WorkManager instantiates it by name, an obfuscated class fails silently); a provider that throws is `Result.retry()` with the exception logged at `WARN`; a `CLOSED` instance is `Result.failure()` and cancels the unique work (it can never become `STARTED`); an instance running on the in-memory fallback (`RevoktState.storageFallback`, §6.5) **syncs as any other** (the metered rule bounds the cost; the fallback retries its configured storage on every tick and migrates, §5.1 "Storage fallback"), so a direct-boot or rolled-back process still receives data; the §5.2 lifecycle observer's foreground `sync()` queues behind and honours `backoffUntilMillis`, so overlap with the worker is harmless |
| `revokt-testing` | jvm | `FakeRevokt` (a builder preset, `object FakeRevokt { @JvmStatic fun builder(): Revokt.Builder }`, since `Revokt` is final), `SymVerifier`, the reference walker (takes `List<ByteArray>`, returns `Set<String>` of lowercase-hex leaf-issuer SPKI hashes, so P2's equality is by value), recorded fixtures, the §9.1 chain generator; from 0.1 to 0.3 these live in `revokt-engine`'s test source set and move here in 0.3. Built from public API only (output-type builders are on the production types under `@RevoktTestingApi`). | `revokt-engine`, `revokt-jsse` |
| `revokt-bom` | — | Code artifacts only, including both `revokt-engine` (KMP root) and `revokt-engine-jvm`; the Maven consumer test references both | — |
| `revokt-seed-compat`, `revokt-seed-default`, `revokt-denylist` *(M2)* | data | Date-versioned, weekly, not in the BOM (§7.2) | — |
| `revokt-engine-upki` *(CI-only, unpublished)* | jvm 22+ | `RevocationEngine` over `revokt-upki-shim` via Panama (§3.2) | `revokt-engine`, `revokt-upki-shim` |
| `revokt-upki-shim` *(CI-only, unpublished)* | — | Rust cdylib (~40 lines) statically linking the `upki` crate; exposes `revokt_upki_config_new/free` (thin wrappers over `Config`/`Store`) and `revokt_upki_check(handle, serial, serial_len, spki_hash[32], scts, n)` over `RevocationCheckInput::new` + `Store::check`; returns ffi.rs's result codes; `catch_unwind` | Rust |
| `revokt-oracle` *(test-only)* | — | Rust cdylib (Panama) and CLI over `clubcard-crlite`, `upki`, `rust-query-crlite`, `x509-parser`, the §9.2 TLV locator, `canonical_json`, with a `catch_unwind` shim; plus a Go CLI over Mozilla's `crlite/go/types` (the producer oracle, §9.2; out of process, batched over a pipe) with a `recover` shim | Rust, Go |

**Dependency scopes**: `revokt-engine` is `api` in `revokt-jsse` and `revokt-jsse` is `api` in every binding (their types cross the builder signatures); `revokt-clubcard` `implementation` (MPL containment); Okio `implementation`;
kotlinx-coroutines **`api`** (in signatures); `androidx.profileinstaller` `api` (android); AndroidX
Lifecycle `compileOnly` with a `Class.forName` guard; OkHttp and Ktor engines `api` in their own
binding only; bcprov `api` in `revokt-bc` only; no kotlinx-serialization.

**Seams are interfaces injected through the builder.** Any interface member added after 1.0 has a
default body; an abstract addition is a major. One functional type per member.

```kotlin
interface SignatureVerifier {
    fun verify(sigAlg: ByteArray, spki: ByteArray, message: ByteArray, signature: ByteArray): VerifyResult   // sigAlg: the signed TBS AlgorithmIdentifier
    fun unsupportedOids(): Set<String>                      // startup probe over the signature, key and curve OID tables
}
enum class VerifyResult { VERIFIED, INVALID, UNSUPPORTED }   // closed
interface PathBuilderFallback { fun build(chainDer: List<ByteArray>, anchors: AnchorSnapshot, nowMillis: Long): List<ByteArray>? }   // leaf first, trust anchor's certificate appended last
internal expect fun canonicalSubject(nameDer: ByteArray): String?     // JVM/Android: X500Principal(der).getName(CANONICAL), null on a construction failure; linuxX64 gate: an empty actual stub returning null (the gate only compiles); the public seam is PlatformTrust.canonicalSubject
class StoreLockedException @JvmOverloads constructor(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
enum class NewerLayout { IN_MEMORY, REBUILD }   // growable; what a store whose `store.version` is higher than this engine's gets (§6.5)
fun interface RevoktLogger { fun log(level: LogLevel, message: String, cause: Throwable?) }   // commonMain; every "logged" in this document names its level. jvmMain: object RevoktLoggers { @JvmStatic fun jul(): RevoktLogger } (java.util.logging "dev.revokt"); revokt-android: RevoktAndroid.logger() (android.util.Log, tag "revokt"; kept by the consumer R8 rules); builder default: RevoktAndroid.logger() when revokt-android resolves by class name, else RevoktLoggers.jul() (a commonMain fun interface cannot gain companion members in another source set); a throwing logger is swallowed (never on a handshake path's verdict)
enum class LogLevel { DEBUG, INFO, WARN, ERROR }   // closed
enum class OwnershipCheck { STRICT, OWNER_OR_GROUP }   // growable
interface RevoktStorage {                                   // flat key space; the engine owns the layout (§6.5)
    fun read(name: String): ByteArray?
    fun write(name: String, bytes: ByteArray)              // atomic replace, durable (fsync) before return; visible to read() only when complete
    fun delete(name: String); fun names(): Set<String>     // keys: segments of [A-Za-z0-9._-]{1,96} joined by '/', never '.' or '..'; a key resolving outside the root is rejected; delete() removes directories left empty; names() excludes the lock and temp keys
    fun identity(): String? = null                         // stable key for the per-process single-instance registry; JvmStorage: the canonical absolute directory; null = not registered (inMemory)
    fun lock(): AutoCloseable                              // exclusive; acquired in start() and held to close(); bounded wait ≤ 1 s then StoreLockedException (JvmStorage: FileChannel.tryLock; OverlappingFileLockException maps to StoreLockedException); a read-only instance retries it (the same bounded try) from the loader (§5.1); never called per write
    companion object { @JvmStatic fun inMemory(): RevoktStorage } }   // methods are thread-safe for concurrent reads; every write() fsyncs the file, renames into place, then fsyncs the parent directory, new key or not (a rename over an existing name is otherwise not durable); the lock lives under the reserved key `.lock`, which no path other than lock() ever opens, lists or deletes (names()/delete() exclude it), so the POSIX fcntl lock cannot be dropped by a stray close; JvmStorage's ownership check compares the directory's unix:uid attribute with that of the lock file it created
// jvmMain: object JvmStorage { @JvmStatic @JvmOverloads fun directory(dir: java.nio.file.Path, ownership: OwnershipCheck = OwnershipCheck.STRICT, onNewerLayout: NewerLayout = NewerLayout.IN_MEMORY): RevoktStorage }   // Java sees (dir), (dir, ownership) and the full form, so a REBUILD caller spells out STRICT; creates rwx------; on POSIX the directory must be owned by the process uid and, under STRICT, not group/other-writable (OwnershipCheck.OWNER_OR_GROUP tolerates group-writable, the Kubernetes fsGroup case, documented in the README), else STORE_UNREADABLE and the instance runs on inMemory() for the session (no read, no write, never chmod; the store lock is released and the identity deregistered, as for STORE_NEWER_LAYOUT, §6.5, and RevoktState.storageFallback = true); the lock is per directory while the layout is per channel, so two channels on one directory in two processes leave the second instance read-only, and in one process the registry throws (use one directory per channel); never share a directory across hosts (advisory fcntl over NFS); Windows: ATOMIC_MOVE over an open `current` is retried
// revokt-android: AndroidStorage.noBackup(context, name) = JvmStorage.directory(context.noBackupFilesDir.toPath().resolve(name), STRICT, onNewerLayout = REBUILD) (one package owns its directory, so a higher store.version there can only be a Play rollback to an older binary, which must keep working: rebuilt from the seed with STORE_NEWER_LAYOUT); credential-encrypted, so unavailable before the first unlock: an instance started from a direct-boot-aware component gets STORE_UNREADABLE, runs on the in-memory fallback and migrates to the directory once it becomes readable (§5.1 "Storage fallback"); AndroidStorage.deviceProtected(context, name) is the recommended value for anything started before unlock (the data is public Mozilla data). Builder default: RevoktStorage.inMemory(), meant for tests and 0.2; on AndroidPlatformTrust build() throws R STORAGE_UNSET unless storage was set, inMemory() included (an explicit inMemory() is a decision; the default would silently age the seed); on the JVM V IN_MEMORY_STORE_WITH_FETCHING_SOURCE warns
expect class FetcherTls                                     // linuxX64 gate: an empty actual stub, as for canonicalSubject. jvmMain actual: val sslSocketFactory: SSLSocketFactory; val trustManager: X509TrustManager /* that source's internal fetcher trust manager (§5.1 "Anchor snapshot"), never the public fetcherTrustManager */. Hostname verification is binding-owned, never a FetcherTls member (the JDK has no public RFC 6125 verifier): the JDK and Android fetchers rely on HttpsURLConnection's endpoint identification ("HTTPS", set by HttpsClient; a §9 fixture asserts a SAN mismatch is FAILED), the OkHttp fetcher keeps the base client's hostnameVerifier and build() throws IllegalArgumentException when it is not OkHttp's default (a replaced verifier is both a regression and non-coalescable), the Ktor fetchers keep their engine's
class FetchRequest private constructor(…) {   // @RevoktTestingApi Builder, so fetcher tests can construct requests; val url: String; val headers: Map<String, String> /* engine sets User-Agent and If-None-Match, the latter synthesised as the quoted verified cursor ("<lastVerifiedLastModified>"), never an echoed server ETag (a persisted ETag the transport rejects would fail every later request); a 304 is UNCHANGED and updates lastAttemptAtMillis only; never Accept-Encoding */; val maxBodyBytes: Long /* min(attachment.size, MAX_FILTER_BYTES) for a SIGNED body, else the per-kind RevoktLimits cap */; val timeoutMillis: Long /* enforced by the engine: each fetch runs under Future.get(timeoutMillis) on ioDispatcher; expiry is FAILED and the next sync proceeds, so a hung injected fetcher cannot block later syncs */ }
class FetchResponse private constructor(…) { class Builder { fun status(status: Int): Builder; fun header(name: String, value: String): Builder; fun headers(headers: Map<String, List<String>>): Builder; fun body(body: ByteArray): Builder; fun build(): FetchResponse }; companion object { @JvmStatic fun of(status: Int, headers: Map<String, List<String>>, body: ByteArray): FetchResponse }   // public, not testing-API: an HttpFetcher must construct one
    val status: Int; val headers: Map<String, List<String>>; val body: ByteArray /* decoded, buffered; the fetcher stops at maxBodyBytes while inflating (gzip bomb) and throws; 3xx is never followed and is FAILED; the engine re-checks and hashes */ }
fun interface HttpFetcher { fun fetch(request: FetchRequest): FetchResponse /* synchronous; one HttpFetcher per configured source, created by one Factory.create(tls) call per source at build() with that source's FetcherTls (a throwing factory propagates from build()); the contract: every TLS handshake the returned fetcher performs goes through the given tls and nothing else, one factory call serves one source only, and the shipped factories are the supported ones (§8 fetcher policy); runs on ioDispatcher, never the loader; must honour thread interruption so a timed-out fetch does not pile up; the body is handed to the loader, which alone writes the store; any Throwable = SyncOutcome.FAILED for that sync; a 401 or 407 is FAILED on every platform and no fetcher ever answers a challenge */; fun interface Factory { fun create(tls: FetcherTls): HttpFetcher } }   // a fetcher-policy reject and a 401/407 carry the stage of the fetch they interrupted (CHANGESET, X5U or ATTACHMENT)
// jvmMain (JVM types, so not in commonMain):
interface PlatformTrust {
    fun defaultDelegate(): X509TrustManager
    fun requiresExtendedDelegate(): Boolean
    fun verifiedChain(delegate: X509TrustManager, chain: Array<X509Certificate>, host: String?): List<X509Certificate>?   // null = unavailable on this binding; a throw = decision step 4 failure
    fun pathBuilder(): PathBuilderFallback
    fun anchors(delegate: X509TrustManager): List<X509Certificate>    // getAcceptedIssuers()
    fun canonicalSubject(nameDer: ByteArray): String? = dev.revokt.canonicalSubject(nameDer) }   // the internal expect, qualified. JvmPlatformTrust and AndroidPlatformTrust are final; CandidateIndex.customCanonicaliser = (platformTrust is neither of the two shipped final classes) || (delegate !== platformTrust.defaultDelegate()), a class check, never reflection on an override (§5.1 deferral rule)
```

**Verifier contract.** The engine never hands the verifier a non-X.509 encoding and always passes
the signed TBS `signature` field. `JcaSignatureVerifier(provider: Provider? = null)` selects
`KeyFactory` by the SPKI key OID, creates `Signature`/`KeyFactory` per call, honours RSASSA-PSS
parameters, caches parsed `PublicKey`s by SPKI hash in an LRU of 1,024 entries holding only keys that
produced `VERIFIED` (presented junk keys are server-chosen; entry count exposed), and classifies by the startup probe, never by a
server-chosen exception: an OID in `unsupportedOids()` → `UNSUPPORTED`; any
`GeneralSecurityException` on a supported OID → `INVALID`; any `RuntimeException` from the provider
→ `INVALID` plus `Finding.VerifierError`. Signature OIDs: RSA PKCS#1 SHA-2, `id-RSASSA-PSS`, ECDSA
SHA-2, Ed25519/448, ML-DSA-44/65/87 (RFC 9881), SLH-DSA, composite as drafts settle. Key OIDs:
`rsaEncryption`, `id-RSASSA-PSS`, `id-ecPublicKey` with named curves, Ed25519/448, ML-DSA, SLH-DSA.
Key families (ordering only, used by `CandidateIndex.related()`, §5.1): RSA = {`rsaEncryption`, `id-RSASSA-PSS`} ↔ {RSA PKCS#1, PSS}; EC ↔
ECDSA; EdDSA, ML-DSA, SLH-DSA, composite: key OID equals signature OID; unknown compatible with
everything. Composite signatures are delegated to a provider owning the composite OID (BC) or
`UNSUPPORTED`.

**Purity gate.** `linuxX64()` only when `revokt.purityGate` is present; never published; BCV
`klib { enabled = false }`. Generation publication is a `@Volatile` reference whose only writers are
the single-parallelism loader dispatcher and, in the sole-seed synchronous path of §4 S, the `start()`
caller's thread before any loader task exists; never two at once.

Dependency and version choices: Okio internal only; no JSON library (§7.1); Kotlin floor 2.3; stable stdlib types in
Kotlin-facing signatures with `java.time` and `long` overloads; no third-party or unstable stdlib types in public
signatures; minSdk 26; JVM bytecode 17 (revision 38), which Android consumers dex with the AGP that revokt's Kotlin
2.4 build already requires (8.5.2 or later, confirmed by the 0.3 consumer fixture; Appendix A), while the JVM
artifacts call no JDK API above API 26 (animal-sniffer against an API-26 signature, CONTRIBUTING); compile against
OkHttp 4.12 and the Okio 3.x floor.

**License: Apache-2.0** for every published artifact except `revokt-clubcard` (MPL-2.0) and, if
the §12 trigger fires, `revokt-engine-upki` and its `revokt-upki-shim`. Data artifacts: "no copyright claimed; contains Mozilla
Remote Settings data". Apache over MIT: explicit patent grant and retaliation, contribution
licensing without a CLA, name protection, JVM scanner expectations.

**`revokt-clubcard`: MPL-2.0 port**, about 44 KB of Rust, contained per §3.1, replaceable later.

### 3.1 Containing the MPL port

MPL-2.0 is file-level copyleft. Upstream files carry the Exhibit A header only, **no Exhibit B**.
1. One module, own `LICENSE` and `NOTICE`; every publication's POM lists MPL-2.0 only; CI asserts.
2. 1:1 translation files in `…clubcard.port` with SPDX and provenance headers; glue in `…clubcard.api` under Apache.
3. `reuse lint` on every PR plus the header-location rule.
4. `public` + `@RevoktInternalApi` (error-level opt-in, engine only), BCV `nonPublicMarkers = ["dev.revokt.RevoktInternalApi", "dev.revokt.RevoktTestingApi"]` (so testing builders never enter the 1.0 dump), `implementation` scope. The cross-artifact plumbing `Revokt` (revokt-jsse) drives in revokt-engine (identity registry, store lock, loader, `FetcherTls` construction, `generationEpoch`/`policyEpoch`) is public under `@RevoktInternalApi`; a Kotlin consumer compile runs beside the Java one in CI, since `@JvmSynthetic` members are invisible to BCV.
5. No `inline fun`, no `const val` in the port.
6. Never shaded or merged into another Apache artifact.
7. `UPSTREAM.md`; weekly drift job; re-syncs translate the upstream diff.
8. `-sources.jar` on Central; POM license picked up by notice tooling.
9. Contributions under MPL-2.0; DCO.
10. Exit path: nothing MPL is supported API; the oracle corpus is the acceptance test.

### 3.2 `RevocationEngine` and the upki-backed engine

```kotlin
interface RevocationEngine : AutoCloseable {
    val formats: Set<FilterFormat>                                   // generations in other formats are never offered to prepare()
    fun prepare(generation: GenerationFiles): PreparedGeneration     // serialised: the loader dispatcher, or the start() caller's thread in the sole-seed synchronous path (§4 S), never concurrently; builds an inactive state (decode, validate); throws on a corrupt generation; the engine's live generation is untouched
    fun activate(prepared: PreparedGeneration)                        // loader only; atomic swap with respect to concurrent query(); the previous generation is released once in-flight queries drain; a throw leaves the live generation in place
    fun install(generation: GenerationFiles): String = prepare(generation).use { activate(it); it.generationId }   // convenience (use {} so an activate() throw closes the prepared generation; close() after activate() is a no-op); the loader never calls it: it runs the §6.5 self-check on the prepared state between the two calls, so a failure leaves the engine untouched and no recovery path has a window
    fun clear() {}                                                   // default body is a no-op for an engine that holds no state; an engine holding a live generation must override: drops it, query() then returns NO_DATA
    fun query(q: CrliteQuery): CrliteQueryResult                        // the only engine input, extracted by revokt's parser from the path-verified leaf and issuer (§5.1) for every engine, so an engine swap cannot change what is looked up; never throws; precedence, fixed for every engine: after close() → ENGINE_ERROR; no generation → NO_DATA; q.scts empty → NO_SCTS; else the §6.2 aggregate
    val coverageEndMillis: Long?                                     // null when the engine cannot tell
}
interface PreparedGeneration : AutoCloseable { val generationId: String; fun query(q: CrliteQuery): CrliteQueryResult }   // inactive; close() without activate() discards it; after activate() the engine owns it and close() is a no-op. RevocationEngine.close() is idempotent; an engine instance may be injected into one Revokt only (R: build() throws on a second, identity registry)
enum class FilterFormat { V3, V4 }                                                             // growable
enum class CrliteQueryResult { NOT_REVOKED, REVOKED, NOT_COVERED, NOT_ENROLLED, NO_SCTS, NO_DATA, ENGINE_ERROR }   // growable; the only CRLite status type
class GenerationFiles internal constructor(…) {                      // always C2SP layout: "index.bin" plus the files it names; @RevoktTestingApi Builder; jvmMain: object JvmGenerationFiles { @RevoktTestingApi @JvmStatic fun fromDirectory(dir: java.nio.file.Path, dataset: Dataset, trustClass: TrustClass, format: FilterFormat): GenerationFiles }, so a third-party engine is testable against the §9 corpus images from revokt-engine alone
    val generationId: String; val dataset: Dataset; val trustClass: TrustClass; val format: FilterFormat
    val names: Set<String>; fun bytes(name: String): ByteArray /* fresh copy; a disk-backed implementation later is not a break */; fun sha256(name: String): ByteArray /* content hash, computed once by the loader */; val sourceTimestampMillis: Long }
class CrliteSct private constructor(…) { val logId: ByteArray /* 32 bytes */; val timestampMillis: Long /* RFC 6962 u64 carried in Long; compared with java.lang.Long.compareUnsigned */ }   // @RevoktTestingApi Builder
class CrliteQuery private constructor(…) {                           // growable value-semantics class (builder, @RevoktTestingApi); a field added in a minor does not break engines
    val issuerSpkiHash: ByteArray /* SHA-256 of the issuer's SPKI TLV */; val serial: ByteArray /* rawSerial: DER INTEGER content bytes as encoded (the producer's RawValue.Bytes, §9.2) */; val scts: List<CrliteSct> /* order not significant; empty when no SCT extension has a list that parses under §9.2 (absent, or for example empty, a first item that fails, an inner identifier other than 0x04; §9.2 states every case); a list that fails later keeps the items before the failure */ }
```

**Seam.** `Revokt.Builder.revocationEngine(engine: RevocationEngine)` is public from 0.2 (the first `Revokt`; the engine-side types are public from 0.1) and
defaults to the Kotlin engine (`formats = {V3, V4}`). The
updater builds `index.bin` itself for Remote Settings generations (full, deltas and their
parentage, coverage), so every `GenerationFiles` is a directory image any C2SP reader accepts; the
only engine-specific property is `format`. **`index.bin` consistency, verified by the loader before
`prepare()` for every generation it did not build** (`MIRROR`, `SYSTEM`, a seed's rebuilt index being
byte-compared instead): **selection equivalence**: for every log id and every timestamp (inclusive at both
ends, overlapping windows allowed), the set of filters the `index.bin` log directory names for that
(log id, timestamp) must equal the set of referenced filters whose own coverage map contains it, i.e. every
directory entry lies within its filter's window and every filter's window is exactly covered by its entries;
a mismatch is `SyncOutcome.FAILED` with `INDEX_INCONSISTENT` (stage `INDEX`; `SEED_UNREADABLE` for a seed,
`STORE_UNREADABLE` for a system cache) and nothing is installed. This is what makes the Kotlin engine's
coverage-driven filter selection (§6.2, every filter consulted by its own coverage) equal to C2SP's
`index.bin`-driven selection (upki binary-searches the log directory and loads only the filters it names)
on every generation the suite admits; how `upki-mirror` writes overlapping windows and how `Index::check`
treats them is a named 0.2 verification (Appendix A) before the suite's `MIRROR` leg lands, and a legitimate
Mozilla generation (a full and its deltas sharing boundary timestamps) passes by construction. **A fetched generation whose format the engine does not list is
`SyncOutcome.FAILED` with `DiagnosticCode.FORMAT_UNSUPPORTED`** (stage `PREPARE`), counts toward `consecutiveFailures`
and `signedSourceFailing`, and advances nothing (never a silent skip; a seed in such a format is
`SEED_UNREADABLE` at `start()`, §6.5; for fetching sources `validate()` warns or errors up front, §4 V `FORMAT_UNSUPPORTED`). **The seam carries `Dataset.CRLITE` only**: the loader
offers `prepare()` only generations whose `dataset == CRLITE`; every other dataset (M2 preload,
OneCRL, CRLSet, denylist; M3 log lists; M4 distrust; M5 MTC tree heads) is consumed by revokt's
own evaluators and never crosses this interface, so `GenerationFiles.dataset` is `CRLITE` for every
value an engine receives and `formats` is a CRLite-format set; a later pluggable evaluator for
another layer is a separate interface with its own builder method, never a widening of
`RevocationEngine`. `prepare`/`activate` are serialised (the loader dispatcher, or the `start()` caller in the sole-seed synchronous path, never both at once) and throw after `close()`; `query` is called concurrently
from connection threads and must observe either the previous or the new generation, never a mix;
`close()` waits for in-flight `query` calls at most `ENGINE_CLOSE_DRAIN` (5 s), then proceeds; a query that returns later sees `ENGINE_ERROR`. **Ownership**:
`Revokt` owns the engine whether defaulted or injected and closes it last (§5.1 lifecycle). `NO_SCTS` means
no SCT extension, or none whose list parses under §9.2 (for example an empty list, a first item that fails, an inner identifier other than `0x04`; §9.2 states every case; decision,
§10 item 7); revokt's parser passes an empty `scts` list in each case before the engine is called; the Kotlin engine answers
`NO_SCTS` on it, the upki engine `NOT_COVERED` (one equivalence class, below).

**upki adapter (`revokt-engine-upki`, Panama, JDK 22+; CI-only until the §12 trigger).**
Verified against upki at tag v1.0.1 (crates.io: 1.0.0; the shim's `Cargo.lock` pins the git tag) `ffi.rs`, `revocation/mod.rs` and `rustls-upki` (Appendix A).
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
`DEFAULT` by decision. Generations: (i) Mozilla `SIGNED` v3 generations as served, both engines directly (no transcoder
in the oracle path); (ii) `MIRROR` v4 generations as fetched from `upki.rustls.dev`; (iii) the v3
generations transcoded to v4 by `revokt-oracle` (`upki-mirror`'s transcoder), a third leg that pins the
transcoder; every generation passes the `index.bin` consistency check above before it enters the suite. Lands in 0.2; published only if the §12 trigger fires, which is additive because every
engine-side type above is public from 0.1.

## 4. Public API (sketch, M1 surface)

One configuration surface: fluent `Builder` classes (`fun channel(c: CrliteChannel): Builder`, …);
`Revokt(block)`, `sources { }` and the assignment-style `var`s shown below are `@JvmSynthetic` sugar
over the same builder. Every public value or output type, including every `Finding` subclass, is a final class with a private
constructor, content-based `equals`/`hashCode`/`toString` (timing fields excluded), a nested `Builder` and
`newBuilder()` (service types such as `KotlinRevocationEngine()`, `AndroidPlatformTrust()`, `JcaSignatureVerifier()` and exceptions have public constructors); on output types (`Verdict.*`, every `Finding`, `RevoktEvent`, `RevoktStatus`,
`RevoktState`, `AnchorSnapshot`, `ExemptionContext`) the builder is `@RevoktTestingApi` (opt-in,
`WARNING` level, outside the 1.0 promise). `Finding` is a sealed class, **growable** (a subtype may be added in a minor; use `else`); `Verdict` is closed. No data classes, no inline value classes. **Public type rule**: stable stdlib types
in Kotlin-facing signatures; `java.time` and `long` overloads for Java; one functional type per
member; kotlinx-coroutines is the one non-stdlib dependency in signatures, with a listener or
`CompletableFuture` alternative for each member. `Revokt` is the JVM facade in `revokt-jsse`.

```kotlin
val revokt = Revokt {
    channel = CrliteChannel.COMPAT                      // enum class CrliteChannel { COMPAT, DEFAULT } (growable); mandatory iff a CRLite source is configured (a seed counts); R: build() throws when unset (decision: the consumer chooses); channel-less datasets (M2+) use the literal store segment `all`
    storage = AndroidStorage.noBackup(context, "revokt")
    platformTrust = AndroidPlatformTrust()              // default: auto-detected (AndroidPlatformTrust when android.os.Build resolves, else JvmPlatformTrust); R: on Android a platformTrust that is not AndroidPlatformTrust throws
    fetcherDelegate = corpTrustManager                   // the delegate fetcherTrustManager wraps; default platformTrust.defaultDelegate(); R: where requiresExtendedDelegate() is true a plain X509TrustManager throws IllegalArgumentException from build(), as trustManager(d) does at wiring; R: a RevoktTrustManager as fetcherDelegate throws IllegalArgumentException (the fetch would wait on the data it is supposed to produce); its snapshot is attempted inside start() when a fetching source is configured (§5.1 "Anchor snapshot"); with remoteSettings(MozillaRemoteSettings.DEFAULT) the fetcher contacts firefox.settings.services.mozilla.com, firefox-settings-attachments.cdn.mozilla.net and content-signature-2.cdn.mozilla.net (the NSC and egress allowlist, §7.1)
    signatureVerifier = JcaSignatureVerifier()
    revocationEngine = KotlinRevocationEngine()           // default; §3.2 seam
    clock = Clock.System                                // Java: clock(java.time.Clock); timeSource(TimeSource) for the monotonic deadlines (testable)
    sources { remoteSettings(MozillaRemoteSettings.DEFAULT); c2spMirror("https://upki.rustls.dev/revocation/") /* with a seed this trips MIRROR_WITH_SEED_NEVER_INSTALLED; shown for completeness */; c2spCache("/var/cache/upki"); seed(SeedSource.fromResource("/revokt/seed-compat.zip")) }   // seed default when none is configured: SeedSource.bundled(), resolved at build(): /revokt/seed-<channel>.zip from the revokt-seed-<channel> artifact (§6.5; the quickstarts declare it); absent from the classpath → no seed source, and validate() emits NO_DATA_REJECTS_WITHOUT_LOCAL_DATA; present but unreadable → SEED_UNREADABLE at start() (§4 S bullet); seed(SeedSource.none()) opts out explicitly. No fetching source is configured by default (a library never opens the network unasked); a required dataset with local data and no fetching source is V NO_FETCHING_SOURCE, a WARNING under both enforcements (the instance updates only through sync()'s seed re-check, below; air-gapped seed-by-deploy fleets are legitimate). R: every source URL (baseUrl, attachmentBaseUrl, a c2spMirror URL, x5uHosts) is https with no userinfo, else build() throws (NSC blocks cleartext on API 28+, the JVM does not).
    meteredNetwork { false }                             // BooleanSupplier; revokt-android: RevoktAndroid.meteredNetwork(context) over ConnectivityManager.isActiveNetworkMetered(); sampled once per sync before a full download; a throw reads as false (§7.2)
    logger = RevoktLoggers.jul()                        // RevoktLogger; default auto-detected (§3)
    policy = RevoktPolicy.DEFAULT                       // or STRICT; RevoktPolicy.DEFAULT.newBuilder().rule(Rule.NO_SCTS, REJECT).exempt(Rule.NO_SCTS, …).staleness(Dataset.CRLITE, Staleness.ofMillis(3.days.inWholeMilliseconds, null))
    enforcement = Enforcement.ENFORCE
    awaitData(2.seconds)                                // Java: awaitData(java.time.Duration) / awaitDataMillis(long); defaults RevoktLimits.AWAIT_DATA_<CHANNEL>
    caches { pathEntries = 256; verdictEntries = 1024 }
    ioDispatcher = Dispatchers.IO                       // fetch I/O; Java: ioExecutor(Executor). The loader dispatcher is internal, single-parallelism
    limits { maxFilterBytes = 32 * MiB; maxTrustManagers = 64 }   // MiB = 1 shl 20 (a RevoktLimits constant); download and record caps (MAX_FILTER_BYTES, MAX_JSON_BYTES, MAX_X5U_BYTES, MAX_MANIFEST_ENTRIES, MAX_CHANGESET_RECORDS, MAX_SYNC_BYTES) are overridable upward only (R: a lower value throws IllegalArgumentException from build()); maxTrustManagers in both directions, ≥ 1; walker budgets are constants. MAX_FILTER_BYTES also caps SIGNED bodies (limits table below), so raising it is the recovery for a larger Mozilla filter; maxTrustManagers is the multi-tenant case (per-tenant trust stores), one CandidateIndex and two small caches per instance
    http = OkHttpFetcher.Factory(baseClient)             // default on the JVM: JdkHttpFetcher.Factory (ProxySelector.getDefault() and a per-connection HttpURLConnection.setAuthenticator that answers RequestorType.PROXY only, JDK 9+, so a trusted intercepting proxy cannot harvest default credentials; a 401/407 is FAILED; revokt configures no proxy; Basic auth to an HTTPS tunnel is disabled by the JDK unless jdk.http.auth.tunneling.disabledSchemes is cleared; proxy-authenticated fleets use OkHttpFetcher.Factory with proxyAuthenticator; setInstanceFollowRedirects(false)). Default on Android (AndroidPlatformTrust): OkHttpFetcher.Factory over a fresh OkHttpClient() when revokt-okhttp resolves (detected by class name), else AndroidHttpFetcher.Factory from revokt-android (HttpURLConnection.setAuthenticator does not exist in Android's libcore, so JdkHttpFetcher is never used there; Android's HttpsURLConnection answers a 407 from the VM-global Authenticator.getDefault() with no per-connection suppression, the §10 residual, which is why the OkHttp fetcher is preferred). OkHttp: sslSocketFactory and x509TrustManager are replaced from FetcherTls unconditionally, the base client's hostnameVerifier is kept (R: must be OkHttp's default), and followRedirects(false), followSslRedirects(false), authenticator(NONE), cookieJar(NO_COOKIES) and cache(null) are forced (a consumer disk cache would serve the first ETag-less request, on a fresh install or after resetState(), from its own max-age) (§7.1 "redirects are never followed" holds at the transport); proxy, dns, interceptors and certificatePinner are inherited and consumer-owned: application and network interceptors see every revokt request, so the consumer must not attach credential-adding interceptors to the base client (the README warns)
}
revokt.start(); revokt.close()                          // Revokt : AutoCloseable; Java entry Revokt.builder(); DSL vars carry @get:JvmSynthetic @set:JvmSynthetic; idempotent; lifecycle CREATED → STARTED → CLOSED (§5.1). start() throws IllegalStateException on a validate() ERROR, SEED_CHANNEL_MISMATCH, a consumer trust manager's pre-start anchor snapshot build failure (fetcherTrustManager's is the FETCHER_TRUST_UNAVAILABLE warning), a second instance on the same storage identity in this process, a call from a thread holding the factory lock, or, under ENFORCE with outcome(NO_DATA) == REJECT, SEED_UNREADABLE when the seed is the only local data source (verified synchronously inside start() in that configuration, §4 S bullet); stays CREATED and may be retried. close() on the loader thread throws IllegalStateException (listener executors are never the loader; syncAsync(), resetStateAsync() and readyFuture() are completed by `ioExecutor.execute { future.complete(v) }` / `completeExceptionally(t)`, the Java 8 shape (never `CompletableFuture.completeAsync`, `orTimeout` or any other API-31+ member: minSdk is 26, core-library desugaring does not cover them, and an API-26 instrumented fixture plus an Android Lint `NewApi` check on a minSdk-26 consumer of revokt-jsse guard it), so dependent stages never run on the loader; each call returns a fresh dependent future (`internal.thenApply { it }`), so a consumer's cancel()/complete() cannot corrupt readiness; close() completes a pending syncAsync()/resetStateAsync() exceptionally as it does readyFuture()); a start() whose loader join observes CLOSED returns normally on a CLOSED instance whose readyFuture() has failed
suspend fun Revokt.awaitReady(); fun readyFuture(): CompletableFuture<Void>          // completes when RevoktState.ready first becomes true; no internal deadline; close() completes it exceptionally with IllegalStateException("closed") and the suspend form throws CancellationException
fun interface Revokt.Provider { fun revokt(): Revokt }       // may return a CREATED or STARTED instance (the WorkManager worker starts a CREATED one itself, §3; a CLOSED one is Result.failure()); a direct sync() in CREATED or CLOSED throws IllegalStateException
suspend fun Revokt.sync(): SyncResult; fun syncAsync(): CompletableFuture<SyncResult>; fun syncBlocking(): SyncResult   // with no fetching source configured, sync() re-opens the seed source and, when the seed is newer than the live generation, installs it under the seed-vs-stored rule with writes (an air-gapped refresh: replace the seed artifact, call sync(); the watermark is intact), else UNCHANGED; either way it is a completed attempt (§8 STALE gate, datasetLastAttemptAtMillis)
suspend fun resetState(); fun resetStateBlocking(); fun resetStateAsync(): CompletableFuture<Void>   // STARTED only; read-only → IllegalStateException; runs on the loader after any in-flight install; deletes every key names() lists except store.version (never `.lock`; updater.json included: the rollback watermark restarts from the seed's timestamp, or from zero with SeedSource.none(), §10) while the published generation and the engine's installed generation stay live (DataState.pending stays false while a generation is published), re-runs the loader start task (seed, system cache) and swaps old → new atomically (generationEpoch++ then); only when no local source yields a generation does it publish the empty snapshot (generationEpoch++) and **then** engine.clear(), in that order, so a handshake holding the old snapshot still finds data in the engine (step 7 never queries without a generation); a concurrent handshake is never NO_DATA while the previous generation existed; schedules the first sync before completing; anchor snapshots are untouched
var revokt.enforcement: Enforcement                     // @Volatile, read once per handshake (that one value drives step 0, step 4 and RevoktEvent.enforced); the enforcement and policy setters serialise under one lock and validate the (enforcement, policy) pair that will be published; setter runs validate(); throws IllegalStateException with the same messages; allowed in any lifecycle state, takes effect at the next handshake in STARTED; in STARTED a flip to ENFORCE with outcome(NO_DATA) == REJECT and a required dataset whose DataState has generationId == null, pending == false and a SEED_UNREADABLE/STORE_UNREADABLE warning for its sole local source is refused with ERROR NO_DATA_AT_FLIP (V bullet below); while pending == true the flip is accepted
var revokt.policy: RevoktPolicy                         // runtime-replaceable with the enforcement setter's contract (runs validate(enforcement), throws on ERROR, any lifecycle state, next handshake); the per-rule kill switch for non-exemptable rules; the setter runs the NO_DATA_AT_FLIP check against (current enforcement, new policy) and is refused under the same conditions; the setter recomputes and publishes RevoktState.ready (awaitReady() must not hang after a change that empties requiredDatasets); flow step 0's needsData is recomputed at the next handshake; the setter publishes (policy, policyEpoch) as one @Volatile pair, read once per handshake (at flow step 0 when it runs, else at step 2) and threaded through steps 3, 7, 8, the exemptions and the cache put, like enforcement; policyEpoch (public on RevoktEvent; process-local, not stable across processes, like AnchorSnapshot.id) is part of the verdict-cache key, so a change is a cache miss and OBSERVE would-rejects can be attributed across it
var revokt.shadowPolicy: RevoktPolicy?                  // builder shadowPolicy(p) too; default null. The measurement path from DEFAULT to STRICT (or to a new rule's REJECT) without OBSERVE: on every verdict-cache miss, after the enforced verdict is final, decision steps 7–8 are re-run under the shadow policy over the same path status, CRLite results and generation snapshot (no second walk, no second engine query; the shadow policy's own requiredDatasets, staleness map, outcomes and exemptions apply; a throwing shadow exemption is not exempt plus a shadow-only EngineError), yielding RevoktEvent.shadowVerdict (cached beside the verdict, so hits count too) and RevoktStatus.shadowWouldRejects: Map<Rule, Long> keyed by the shadow verdict's rule; the shadow never throws, never waits (step 0 is the enforced policy's) and never changes the enforced verdict; shadowPolicyEpoch is part of the verdict-cache key; the (shadowPolicy, shadowPolicyEpoch) pair is published and read exactly as the policy pair (one @Volatile pair, read at flow step 0 or 2 beside it, threaded through step 3 and the cache put); every setter call bumps shadowPolicyEpoch, setting null included; the setter takes the same lock as the two setters; the shadow is validated under OBSERVE semantics (its diagnostics are WARNINGs, never thrown and never copied to RevoktState.warnings, logged at WARN through RevoktLogger by the setter: a shadow must be measurable on a fleet that has not yet shipped the seed STRICT would require); the shadow runs under ENFORCE and OBSERVE (not OFF, where steps 2–4 do not run), after the enforced catch boundary has closed, under its own boundary (§5.5), and touches nothing but shadowWouldRejects and RevoktEvent.shadowVerdict (never fired, exempted, the per-dataset maps or event priority); it computes its own data rules from the same generation snapshot under its own requiredDatasets and staleness map
fun revokt.validate(enforcement: Enforcement): List<PolicyDiagnostic>   // the setter throws iff any ERROR; validateOrThrow(enforcement) for Java
fun revokt.status(): RevoktStatus                       // cheap snapshot; counters monotonic since build() for unevaluated, since start() for every other
val revokt.state: StateFlow<RevoktState>                // slow-changing fields only; Java: RevoktListener.onStateChanged
fun addListener(listener: RevoktListener, executor: Executor); fun removeListener(listener: RevoktListener)
val revokt.trustManager: RevoktTrustManager               // the single memoised instance over platformTrust.defaultDelegate(); the delegate is captured at build(), the RevoktTrustManager is created on the first read of this property or the first null-delegate wiring (lazily, under the factory lock; in STARTED with its snapshot), so a seed-only configuration over an empty default trust store starts (fixture (h)) and throws only once something asks for the instance
fun revokt.trustManager(delegate: X509TrustManager): RevoktTrustManager   // RevoktTrustManager is a final class extending X509ExtendedTrustManager. In STARTED builds the anchor snapshot synchronously inside the factory lock (§5.1 "Anchor snapshot"); a plain delegate (JVM) → IllegalArgumentException; a throwing getAcceptedIssuers() or an empty anchor set → IllegalStateException; nothing registered in either case
val revokt.evaluator: Evaluator; fun Revokt.Builder.pkixFallback(enabled: Boolean): Builder   // Evaluator.evaluate walks against revokt.trustManager's anchor snapshot (created lazily as above; one @Volatile read at entry, its id reported as anchorSnapshotId) and shares no path or verdict cache; outside STARTED it throws IllegalStateException (there is no step 1 to fall back to)
val revokt.fetcherTrustManager: RevoktTrustManager          // created at build() over fetcherDelegate; snapshot attempted inside start() when a fetching source (remoteSettings, c2spMirror) is configured (a failure is S FETCHER_TRUST_UNAVAILABLE, a WARNING: syncs return FAILED until the build succeeds, retried per sync; never a start() throw), else under the factory lock on its first checkServerTrusted in STARTED (§5.1 "Anchor snapshot"); status() reports null snapshot fields until then
expect class SeedSource internal constructor(…) { companion object { fun none(): SeedSource } }   // commonMain; internal open(): okio.Source? (Okio never appears in a public signature)
// jvmMain: fun interface SeedOpener { fun open(): java.io.InputStream? }   // one functional type, usable from Java as a lambda; the actual companion adds @JvmStatic fun of(opener: SeedOpener): SeedSource /* asset packs, a downloaded seed; re-opened on every start task and sync() seed re-check; wrapped into okio internally */, @JvmStatic fun fromResource(path: String): SeedSource and @JvmStatic fun bundled(): SeedSource /* resolve through SeedSource::class.java.classLoader, then the thread context loader, in that order (app servers) */
// jvmMain: object JvmSeedSource { @JvmStatic fun fromPath(path: java.nio.file.Path): SeedSource }   // mirrors JvmStorage
class MozillaRemoteSettings private constructor(…) { class Builder { fun baseUrl(url: String): Builder; fun bucket(name: String): Builder /* security-state */; fun collection(dataset: Dataset, name: String): Builder /* cert-revocations */; fun attachmentBaseUrl(url: String): Builder; fun x5uHosts(hosts: Set<String>): Builder; fun x5uHostRewrite(from: String, to: String): Builder /* applied to the parsed x5u URI host before the x5uHosts check; `to` must be in x5uHosts, else MozillaRemoteSettings.Builder.build() throws IllegalArgumentException; makes a byte-for-byte reverse proxy of the three Mozilla hosts a supported mirror, §7.1 */; fun pinnedRootSpkiSha256s(hashes: Collection<ByteArray>): Builder /* compared by content */; fun userAgent(ua: String): Builder; fun sourceId(id: String): Builder /* default "mozilla-remote-settings"; the updater.json key */; fun build(): MozillaRemoteSettings }; companion object { @JvmField val DEFAULT: MozillaRemoteSettings } }   // the signature fields read from metadata.signature are exactly signature, x5u and mode (mode is read and must equal "p384ecdsa", else FAILED; the algorithm is never derived from it)
@JvmOverloads fun revokt.sslContext(delegate: X509TrustManager? = null, keyManagers: Array<KeyManager>? = null): SSLContext
fun RevoktTrustManager.status(): TrustManagerStatus; suspend fun RevoktTrustManager.awaitReady(); fun RevoktTrustManager.readyFuture(): CompletableFuture<Void>   // = the owning Revokt's; kept so a binding that holds only the trust manager can wait
fun RevoktTrustManager.refreshAnchors(): CompletableFuture<Void>   // rebuilds the anchor snapshot on the loader (rate-limited by ANCHOR_REFRESH_MIN_INTERVAL; a failed rebuild keeps the snapshot); for delegates that reload their trust store
@JvmOverloads fun OkHttpClient.Builder.revokt(revokt: Revokt, delegate: X509TrustManager? = null): OkHttpClient.Builder   // a null delegate on every binding resolves to revokt.trustManager, the single memoised instance over platformTrust.defaultDelegate() (captured once per Revokt at build(); on Android ApplicationConfig holds exactly one RootTrustManager per process, so a default trust manager obtained through TrustManagerFactory and passed explicitly is === the captured delegate and resolves to the same instance, counting once); only distinct explicit delegates create further instances, so the cap counts delegates, not clients. Call it last on the builder: a later sslSocketFactory(...) from a debug-proxy or pinning module silently replaces it (evaluations and unevaluated both stay 0); withRevokt(client) is the terminal form
fun OkHttpClient.withRevokt(revokt: Revokt): OkHttpClient; fun OkHttpClient.revoktTrustManager(): RevoktTrustManager?   // the client's x509TrustManager when it is revokt's, else null; for a startup assertion
class EvaluationRequest private constructor(…) { class Builder {
    fun presented(chain: List<ByteArray>): Builder            // leaf first, as sent; walked (decision steps 2–6)
    fun verifiedPaths(paths: List<List<ByteArray>>): Builder  // leaf → anchor each, trusted without re-verification; source = PLATFORM; the walk is skipped
    fun host(host: String?): Builder; fun nowMillis(nowMillis: Long): Builder; fun build(): EvaluationRequest } }   // at least one of presented/verifiedPaths; chainSource is derived. M5 adds credentialType(CredentialType) (growable, default X509), routed before decision step 3 with PathStatus.NOT_APPLICABLE; JSSE never delivers an MTC credential to an X509TrustManager, so M5 is Evaluator.evaluate-only
sealed interface Evaluator { fun evaluate(request: EvaluationRequest): Verdict }   // sealed, never consumer-implemented, so members can be added; formerly `Engine`, renamed so it cannot collide with RevocationEngine
@Throws(CertificateException::class) @JvmOverloads fun Revokt.evaluate(chain: List<X509Certificate>, host: String? = null, delegate: X509TrustManager? = null): Verdict   // never waits; always runs step 1 (a null delegate resolves to platformTrust.defaultDelegate()) as `delegate.checkServerTrusted(chain.toTypedArray(), "UNKNOWN")`, the 2-arg call with SunJSSE's own TLS 1.3 authType (a signature-capable key-usage check, no endpoint identification since there is no peer; Conscrypt only requires a non-empty authType), host being used for host' only; a step-1 reject propagates the delegate's CertificateException unchanged, no Verdict (the annotation is what lets a Java caller catch it); with a delegate it uses (and if needed creates, counting toward MAX_TRUST_MANAGERS) the registry instance for that delegate and shares its caches; Evaluator.evaluate shares no trust-manager path or verdict cache
// Raw DER in EvaluationRequest is presumed to come from a platform-accepted chain; PARSE_FAILED on caller-fabricated bytes is the caller's to police (§9.2)
```

**Status, event and rule model, defined once.** `Verdict` is the policy result independent of
`Enforcement`; `Rejected` means "policy says reject"; only the trust manager decides whether to throw.

```kotlin
/** closed. EVIDENCE: a verified positive finding against the chain (revoked, listed, distrusted, CT policy verified and not met).
 *  UNEVALUABLE: revokt could not evaluate this chain. NON_ANSWER: a layer ran and had nothing to say. DATA_QUALITY: about the data, not the chain. */
enum class RuleClass { EVIDENCE, UNEVALUABLE, NON_ANSWER, DATA_QUALITY }
/** One-to-one with the §8 table, the policy builder, RevoktStatus counters and RevoktEvent; a unit test asserts it. Growable.
 *  Invariant: declaration order is precedence; rules are grouped by class; a new rule is appended at the end of its class group.
 *  ordinal is not stable across minors: persist name. ruleClass, layer and exemptable are frozen within a major (exemptable may change false → true). */
enum class Rule(val ruleClass: RuleClass, val layer: Layer?, val exemptable: Boolean) {   // RuleClass.* and Layer.* are imported; constants below are unqualified for brevity
    REVOKED(EVIDENCE, CRLITE, false),                                   /* M2: DENYLIST, ONECRL, CRLSET; M3: CT; M4: DISTRUST */
    PATH_BUDGET_EXCEEDED(UNEVALUABLE, PATH, false), NO_DATA(UNEVALUABLE, null, true), ENGINE_ERROR(UNEVALUABLE, null, false),
    PARSE_FAILED(UNEVALUABLE, PATH, false), ISSUER_UNVERIFIED(UNEVALUABLE, PATH, true), NO_ISSUER(UNEVALUABLE, PATH, true),
    NOT_ENROLLED(NON_ANSWER, CRLITE, true), NO_SCTS(NON_ANSWER, CRLITE, true), NOT_COVERED(NON_ANSWER, CRLITE, false),
                                                                        /* M2: ISSUER_UNKNOWN_TO_MOZILLA(NON_ANSWER, PATH, true); M3: CT_UNVERIFIED */
    STALE(DATA_QUALITY, null, true), UNSIGNED_DATA(DATA_QUALITY, null, true);   // Rule.NO_DATA is driven by requiredDatasets, never by CrliteQueryResult.NO_DATA. The three data rules (NO_DATA, STALE, UNSIGNED_DATA) are exemptable (decision, revision 29): under STRICT a feed outage must not take down traffic under a private anchor the operator already exempted from CRLite; ExemptionContext carries path.anchorSha256 and host for the data rules too (the walk still runs)
    companion object { @JvmField val PRECEDENCE: List<Rule> = entries }                 // declaration order; a test asserts entries == entries.sortedBy { it.ruleClass }
}
enum class Outcome { ALLOW, REJECT }                     // closed
enum class Enforcement { ENFORCE, OBSERVE, OFF }         // closed. OFF: platform only; steps 2–4 do not run; no events; evaluations does not advance, unevaluated[OFF] does
enum class TrustClass(val rank: Int) { SIGNED(300), MIRROR(200), SYSTEM(150), BUNDLED(100) }   // growable; the floor rule compares rank, never ordinal, so a value can be inserted later
enum class Severity { WARNING, ERROR }                   // closed
enum class DiagnosticCode /* one per validate()/start()/sync/setter bullet */ { METERED_DEFERRED, CLOCK_BEHIND, NO_FETCHING_SOURCE, INDEX_INCONSISTENT, STORE_MIGRATED, STORE_NEWER_LAYOUT, STORAGE_UNSET, FORMAT_UNSUPPORTED, NO_DATA_AT_FLIP, NO_REQUIRED_DATASETS, ENGINE_SELF_CHECK_FAILED, FEED_HOST_REVOKED, FETCHER_TRUST_UNAVAILABLE, MIRROR_WITH_SEED_NEVER_INSTALLED, IN_MEMORY_STORE_WITH_FETCHING_SOURCE, RULE_FLIPPED_THIS_MINOR, EXEMPTION_ON_EVIDENCE_RULE, NO_DATA_REJECTS_WITHOUT_LOCAL_DATA, STALE_REJECTS_WITHOUT_THRESHOLD, SEED_PAST_REJECT_THRESHOLD, EXEMPT_ON_ALLOW, UNVERIFIED_REJECTS_WITH_CLASSICAL_GAP, STRICT_ON_ANDROID_WITHOUT_NO_ISSUER_EXEMPTION, BUDGET_ALLOWS, EVIDENCE_LOWERED_BELOW_PRESET, LOWER_CLASS_SOURCE_NEVER_INSTALLED, STALENESS_CLEARED_FOR_REQUIRED_DATASET, SEED_UNREADABLE, SEED_CHANNEL_MISMATCH, STORE_UNREADABLE, STORE_LOCKED, CHANNEL_UNSET, PLATFORM_TRUST_MISMATCH, CAP_NEAR_LIMIT, SYNC_FAILED, SYNC_SCHEMA_REJECTED }   // growable
enum class EngineErrorProducer { BOUNDARY, ENGINE, EXEMPTION }   // growable; exactly these three in M1
enum class Layer { PATH, CRLITE }                        // growable; M2: ONECRL, CRLSET, DENYLIST (L1/L2); M3: CT (L4); M4: DISTRUST (L5)
enum class Dataset { CRLITE /* M2: INTERMEDIATES, ONECRL, CRLSET, DENYLIST; M3: CT_LOGS; M4: DISTRUST */ }   // growable; the freshness rule per dataset and source is §7.2 prose
enum class Freshness { RECORD_LAST_MODIFIED, LAST_VERIFIED_POLL, MANIFEST_LAST_MODIFIED, SEED_SIGNED_TIME, SEQUENCE_TIME, ARTIFACT_DATE }   // growable; what a generation's sourceTimestamp means
enum class PathStatus { FOUND, NO_ISSUER, ISSUER_UNVERIFIED, PATH_BUDGET_EXCEEDED, PARSE_FAILED, NOT_WALKED }   // growable; M5: NOT_APPLICABLE
enum class ParseReason { STRUCTURE, OVERSIZE, PRODUCER_UNKEYABLE }   // growable; parseReason != null ⇔ path.status == PARSE_FAILED (§5.1 step 3, §9.2 D8)
enum class KeyabilityClause { HEADER, TBS_SHAPE, INTEGER, OID, NAME, TIME, KEY, EXTENSION }   // growable; the first failing §9.2 keyability clause, K1 to K8 in order; keyabilityClause != null ⇔ parseReason == PRODUCER_UNKEYABLE
enum class TerminalKind { ANCHOR /* M2: PRELOAD */ }   // growable; the reported path's terminal (§5.1 invariant)
enum class NoIssuerReason { NO_CANDIDATE, ALL_CANDIDATES_INVALID, UNANCHORED, PLATFORM_ONLY }   // growable; noIssuerReason != null ⇔ path.status == NO_ISSUER
enum class CredentialType { X509 /* M5: MTC */ }   // growable
enum class RevoktLifecycle { CREATED, STARTED, CLOSED }   // closed; commonMain
enum class WalkEnd { COMPLETE, RELATED_BUDGET, VERIFICATION_BUDGET, EXPLORATION_BUDGET }   // growable
enum class ChainSource { PLATFORM, RECONSTRUCTED, PRESENTED /* reserved; produced by no M1 path */ }   // growable; M2: MIXED (paths from both a PLATFORM chain and the re-walk)
enum class SyncOutcome { INSTALLED, UNCHANGED, DEFERRED /* a metered-deferred full (§7.2); not UNCHANGED, which reads as healthy */, FAILED, CLOCK_SKEW, ROLLBACK_REFUSED, BACKOFF, STORE_FAILED, STORE_LOCKED, BLOCKED_BY_SELF }   // growable
enum class SyncStage { FETCHER_TRUST, CHANGESET, X5U, ATTACHMENT, SIGNATURE, SCHEMA, INDEX, PREPARE, SELF_CHECK, ACTIVATE, STORE }   // growable; where a sync failed: FETCHER_TRUST = the §5.1 build retry failed (no fetch); CHANGESET = the changeset fetch or its last_modified CLOCK_SKEW; X5U = the x5u fetch or a validity CLOCK_SKEW; ATTACHMENT = a body fetch or the over-cap signed record; each producing bullet names its stage

/** jvmMain. Time fields are stored as millis. Java: *Millis properties and java.time.Duration accessors/factories (API 26+). Kotlin: kotlin.time.Duration via @JvmSynthetic extensions. No inline value class on the surface. commonMain sees only an internal PolicyTable these compile to. */
class Staleness private constructor(…) { val staleAfterMillis: Long; val rejectStaleAfterMillis: Long?   // staleAfter: loud threshold only (DataState.stale). rejectStaleAfter: the only threshold at which Rule.STALE fires; null = STALE never fires for this dataset
    fun staleAfter(): java.time.Duration; fun rejectStaleAfter(): java.time.Duration?
    companion object { @JvmStatic fun ofMillis(staleAfter: Long, rejectStaleAfter: Long?): Staleness; @JvmStatic fun of(staleAfter: java.time.Duration, rejectStaleAfter: java.time.Duration?): Staleness } }
class PolicyDiagnostic private constructor(…) { val code: DiagnosticCode; val severity: Severity; val rule: Rule?; val dataset: Dataset?; val message: String }   // tests and consumers match on code, never on message
class RevoktPolicy private constructor(…) {           // newBuilder() only from a preset; no from-scratch builder; companion object { @JvmField val DEFAULT; @JvmField val STRICT }; fun exemption(rule: Rule): Exemption?
    fun outcome(rule: Rule): Outcome; val requiredDatasets: Set<Dataset>; fun staleness(dataset: Dataset): Staleness?; fun minTrustClass(dataset: Dataset): TrustClass
    val rollbackWindowMillis: Long; val clockSkewMillis: Long; val signedSourceFailingAfterMillis: Long   // plus java.time accessors
    class Builder {                                      // every method returns Builder; build() returns RevoktPolicy and runs the build()-time checks below
        fun rule(rule: Rule, outcome: Outcome): Builder
        fun exempt(rule: Rule, exemption: Exemption): Builder                 // a second call for the same rule replaces the first; clearExemption(rule)
        fun exemptAnchors(sha256s: Collection<ByteArray>): Builder             // = exempt(rule, anchorIn(sha256s)) for every exemptable rule that is not EVIDENCE, is not marked "empty path" in the §8 table, and whose outcome in the builder at this call is REJECT; applied at its call position over the rule set as it stands then (a later rule() or exempt() on the same builder wins, so a narrower explicit exempt() written after it is kept): EVIDENCE rules (M2 ONECRL, M4 DISTRUST) need an explicit exempt(), so an M1 call never widens to evidence on upgrade, while a non-EVIDENCE rule that flips to REJECT in a later minor (M3 CT_UNVERIFIED) is covered by a call made after the flip, as a private CA wants; the "empty path" rules (NO_ISSUER, ISSUER_UNVERIFIED; a column of the golden fixture, so a future rule must declare it) fire only on an empty reported path, where anchorIn can never match (use hostSuffixIn, platformOnly), whereas M2's ISSUER_UNKNOWN_TO_MOZILLA fires on a Found path and is covered
        fun requiredDatasets(set: Set<Dataset>): Builder
        fun staleness(dataset: Dataset, s: Staleness): Builder; fun clearStaleness(dataset: Dataset): Builder   // clearing a required dataset's entry → validate() WARNING STALENESS_CLEARED_FOR_REQUIRED_DATASET
        fun rejectStaleAfter(dataset: Dataset, d: java.time.Duration?): Builder; fun rejectStaleAfterMillis(dataset: Dataset, millis: Long?): Builder   // null clears only the reject threshold; the loud flag stays; on a dataset with no entry, creates one with staleAfter = rejectStaleAfter
        fun minTrustClass(dataset: Dataset, floor: TrustClass): Builder       // UNSIGNED_DATA fires for the dataset iff DataState.trustClass is below floor
        fun rollbackWindow(d: java.time.Duration): Builder; fun rollbackWindowMillis(millis: Long): Builder
        fun clockSkew(d: java.time.Duration): Builder; fun clockSkewMillis(millis: Long): Builder
        fun signedSourceFailingAfter(d: java.time.Duration): Builder; fun signedSourceFailingAfterMillis(millis: Long): Builder
        fun build(): RevoktPolicy }                       // Kotlin: kotlin.time.Duration overloads as @JvmSynthetic extensions
}
sealed interface Verdict {
    val rules: Set<Rule>                                 // every rule that fired, whatever its outcome; iterates in Rule.PRECEDENCE order (an ordered set sorted by Rule.PRECEDENCE; a LinkedHashSet in commonMain)
    val rule: Rule?                                      // Rejected: first fired, non-exempted REJECT rule in Rule.PRECEDENCE. Accepted: null
    val findings: List<Finding>; val elapsedNanos: Long   // generationEpoch is @RevoktInternalApi (cache key only; not stable across processes)
    val path: Finding.Path                               // non-null; status NOT_WALKED when the engine did not reach the walk (catch boundary)
    val crlite: Finding.Crlite?                          // the first Finding.Crlite with result REVOKED in issuerSpkiSha256s order; else the finding for issuerSpkiSha256s[0]; else null
    val dataStates: Map<Dataset, Finding.DataState>      // an entry for every required dataset and every dataset consulted; generationId == null ⇔ no generation; Rule.NO_DATA fires only when the dataset is required and not pending. Computed before the catch boundary: present on every verdict, ENGINE_ERROR included
    class Accepted private constructor(…) : Verdict { class Builder { … } }
    class Rejected private constructor(…) : Verdict { override val rule: Rule; class Builder { … } }   // non-null narrowing; Java getRule() is @NotNull on Rejected
}
sealed class Finding {
    class Path : Finding() { val status: PathStatus; val source: ChainSource; val noIssuerReason: NoIssuerReason?; val walkerReason: NoIssuerReason?   // the walker's own reason before any PLATFORM_ONLY promotion
        val parseReason: ParseReason?                    // non-null ⇔ status == PARSE_FAILED
        val keyabilityClause: KeyabilityClause?          // non-null ⇔ parseReason == PRODUCER_UNKEYABLE (§9.2 K1–K8)
        val terminalKind: TerminalKind?                  // null when the reported path is empty; else ANCHOR in M1; M2: PRELOAD for a preload-only path (a terminal of last resort), where anchorSha256 is null
        val rewalkEnd: WalkEnd?                          // null unless a re-walk ran; M2: the re-walk's WalkEnd (COMPLETE or its exhaustion), which never demotes the first walk's Found
        val endReason: WalkEnd?                          // COMPLETE on Found/NotFound (the step-6 fallback-skipped exit included), the Budget's end on Budget, EXPLORATION_BUDGET with endDepth = 0 for the step-3 no-walk cut, null only when no walk ran (NOT_WALKED, PLATFORM, the step-2 anchor leaf)
        val endDepth: Int?                               // path size at which the walk ended (1 = leaf level)
        val cacheHit: Boolean; val anchorSnapshotId: Long /* id of the snapshot read once at flow step 2 (Evaluator.evaluate: at its entry) and consumed at decision step 1; 0 when none was consulted (Evaluator.evaluate with verifiedPaths only); the walker harness assigns ids to its fixture snapshots */; val usedFallback: Boolean   // true whenever a fallback path was evaluated, Found or Budget
        val pathsFound: Int                              // on Found: the paths found (M2: first walk plus completed re-walk paths); on Budget: the partial paths
        val reportedPathSha256s: List<ByteArray>         // DER hashes leaf → terminal of the reported path: the first found path, else the first partial path, else empty
        val issuerSpkiSha256s: List<ByteArray>           // every distinct leaf-issuer key evaluated: walker keys in candidate order, then the fallback key if new; first is the reported path's
        val candidatesDropped: Int                       // presented or platform-built certificates the parser rejected and the walker never saw (§9.2 issuer corpus); also RevoktStatus.candidatesDropped
        val anchorSha256: ByteArray?                     // SHA-256 of the reported path's anchor DER; null when the reported path is empty or (M2) terminalKind == PRELOAD
        @RevoktInternalApi val walkStats: WalkStats      // @RevoktInternalApi class WalkStats(val verifications: Int, val candidatesExplored: Int, val relatedExploredAtLeaf: Int, val unrelatedExploredAtLeaf: Int), annotated at class level so it stays out of the dump; walker internals, opt-in
        val credentialType: CredentialType               // growable enum, X509 in M1; M5 adds MTC (reserved now so M5 lands additively) }
    class Crlite : Finding() { val result: CrliteQueryResult; val issuerSpkiSha256: ByteArray?; val coverageEndMillis: Long? }
    class DataState : Finding() { val dataset: Dataset; val trustClass: TrustClass? /* null ⇔ generationId == null; UNSIGNED_DATA never fires on null */; val generationId: String?   // SIGNED: "<changeset timestamp>/<last applied record id>"; MIRROR/SYSTEM: manifest hash; seed: seed id; null ⇔ no generation
        val freshness: Freshness?; val fromSeed: Boolean; val sourceTimestampMillis: Long?; val ageMillis: Long?
        val pending: Boolean                             // true while the loader's start task has not passed the seed and system-cache steps for this dataset (in-process; the §8 STALE gate is the persisted one); false at the end of the start task whatever it found, a fetching source configured or not; Rule.NO_DATA never fires while pending (§5.1 overload table)
        val clockBehind: Boolean                         // sourceTimestampMillis > now + clockSkew, recomputed at every publish (a load after restart included) and never persisted (a future-dated seed, or a changeset installed under the §6.3 clock-behind rule): ageMillis is clamped at 0 and the CLOCK_BEHIND warning is on RevoktState.warnings while any dataset has it
        val seedFormat: Int?                             // when fromSeed
        val stale: Boolean                               // loud flag: ageMillis > staleAfter
        val rules: Set<Rule>                             // the data rules that fired for this dataset: NO_DATA, STALE, UNSIGNED_DATA }
    /* M2, reserved shape: class PathHit : Finding() { val rule: Rule; val dataset: Dataset; val certSha256: ByteArray; val onReportedPath: Boolean; val recordId: String? }  // M4: certSha256 == anchorSha256 */
    class UnsupportedAlgorithm : Finding() { val oid: String; val where: Layer; val outcomeDepended: Boolean }
    class VerifierError : Finding() { val oid: String; val message: String }
    class AlgorithmIdMismatch : Finding() { val certIndex: Int }
    class EngineError : Finding() { val message: String; val producer: EngineErrorProducer; val engineName: String? /* "kotlin", "upki" when producer == ENGINE */ }
    class Exempted : Finding() { val rule: Rule }
}
class PresentedChain private constructor(…) { val size: Int; fun der(i: Int): ByteArray; fun subject(i: Int): ByteArray; fun issuer(i: Int): ByteArray; fun spkiSha256(i: Int): ByteArray /* SHA-256 of the SPKI TLV */; fun serial(i: Int): ByteArray /* rawSerial: INTEGER content bytes as encoded, sign byte and leading zeros preserved */; fun dnsNames(i: Int): List<String> }
fun interface Exemption { fun isExempt(context: ExemptionContext): Boolean   // pure; runs after policy mapping for fired REJECT rules on exemptable rules; cached with the verdict; a throw = not exempt + Finding.EngineError(EXEMPTION)
    companion object {                                                        // shipped helpers, commonMain, in the same file as Exemption (a companion cannot straddle source sets; they need only ByteArray, String and okio.ByteString); the enterprise-CA and §5.2-gap cases without hand-written lambdas
        @JvmStatic fun anchorIn(sha256s: Collection<ByteArray>): Exemption   // copied into a Set<okio.ByteString> at construction; matches context.path.anchorSha256 by content
        @JvmStatic fun hostIn(hosts: Collection<String>): Exemption          // normalised as host' (lowercase, trailing dot stripped); matches context.host, which on an HTTP/2-coalesced connection is the host OkHttp handshook for (§5.1)
        @JvmStatic fun hostSuffixIn(suffixes: Collection<String>): Exemption // host' equals a suffix or ends with "." + suffix; private CAs serve many subdomains
        @JvmStatic fun platformOnly(): Exemption } }                         // context.path.noIssuerReason == PLATFORM_ONLY; a null host or anchorSha256 never matches hostIn/anchorIn
// Exemptions.kt, @file:JvmName("Exemptions"): infix fun Exemption.and(other: Exemption): Exemption; infix fun Exemption.or(other: Exemption): Exemption   // Java: Exemptions.and(a, b); a throw in either operand is the EXEMPTION engine error
class ExemptionContext private constructor(…) { val rule: Rule; val chain: PresentedChain? /* null for a non-X.509 credential (M5) */; val credentialType: CredentialType; val path: Finding.Path; val host: String? /* normalised */; val nowMillis: Long; val dataStates: Map<Dataset, Finding.DataState> }   // growable: new evidence (M3 SCTs, M4 distrust record) lands as new nullable properties; builder @RevoktTestingApi on the type
class AnchorSnapshot private constructor(…) { val id: Long /* process-local counter, like generationEpoch; not stable across processes */; val sha256: ByteArray /* of the sorted anchor DERs only; stable */; val anchors: List<ByteArray>; val createdMillis: Long; val preloadGenerationId: String? /* null in M1; M2: the INTERMEDIATES generation the index holds; an INTERMEDIATES install rebuilds every live index and advances id, so both caches miss */ }
class SyncResult private constructor(…) { val outcome: SyncOutcome; val atMillis: Long; val installed: Map<Dataset, String>; val sourceId: String? /* the source the outcome is about */; val stage: SyncStage? /* where a FAILED/STORE_FAILED/CLOCK_SKEW sync stopped */; val httpStatus: Int? /* the last response status when a fetch was involved */; @Transient val cause: Throwable? /* the fetcher's or loader's throwable; null after deserialisation */; val blockedSource: String? /* BLOCKED_BY_SELF: which source */; val blockedChainSha256: ByteArray?; val blockedLeafSerial: ByteArray? /* BLOCKED_BY_SELF only */; val warnings: List<PolicyDiagnostic> }
class RevoktEvent private constructor(…) { val sequence: Long; val atMillis: Long; val policyEpoch: Long; val credentialType: CredentialType; val host: String?; val chainSha256: ByteArray; val leafSerial: ByteArray? /* rawSerial */; val verdict: Verdict; val shadowVerdict: Verdict? /* null when no shadowPolicy is set, and when the enforced evaluate threw before the shadow ran */; val enforcement: Enforcement; val enforced: Boolean /* = verdict is Rejected && enforcement == ENFORCE */ }
interface RevoktListener { fun onVerdict(event: RevoktEvent); fun onStateChanged(state: RevoktState) {} }   // second method has a default body; Java alternative to the state flow
class RevoktStatus private constructor(…) {            // snapshot; counters monotonic since build() for unevaluated, since start() for every other; maps zero-filled over Rule.entries
    val evaluations: Long; val rejects: Map<Rule, Long> /* ENFORCE only */; val wouldRejects: Map<Rule, Long> /* OBSERVE only */; val shadowWouldRejects: Map<Rule, Long> /* the shadow policy's Rejected verdicts by rule, under ENFORCE and OBSERVE */; val fired: Map<Rule, Long>; val exempted: Map<Rule, Long>
    val noData: Map<Dataset, Long>; val stale: Map<Dataset, Long> /* loud flag seen */; val unsignedData: Map<Dataset, Long>; val noIssuer: Map<NoIssuerReason, Long> /* keyed by the reported (promoted) reason */; val parseFailed: Map<ParseReason, Long> /* fired[PARSE_FAILED] split by reason, zero-filled */; val walkEnds: Map<WalkEnd, Long>; val chainSources: Map<ChainSource, Long>; val fallbackUsed: Long
    val verifierErrors: Long; val candidatesDropped: Long; val verdictCacheHits: Long; val storeFailures: Long; val trustManagerCount: Int; val droppedEvents: Long; val droppedRejectedEvents: Long; val listenerFailures: Long
    val unevaluated: Map<UnevaluatedReason, Long>        // handshakes that returned after flow step 1 without reaching step 2, on every trust manager including fetcherTrustManager (FETCHER_SNAPSHOT_UNAVAILABLE counts only handshakes a consumer delivers to it directly while it has no snapshot; a sync whose build retry failed runs no fetch, §5.1); the one counter group that still advances in CREATED, after close() and under OFF, so an operator can tell "no traffic" from "not checking"
    val readinessWaits: Long; val readinessTimeouts: Long; val readinessWaitNanosTotal: Long   // flow step 0
    val pendingAllows: Map<Dataset, Long> }               // verdicts computed (verdict-cache misses only) while the dataset was pending (allowed without data); separates "checked" from "pending-allow"
enum class UnevaluatedReason { NOT_STARTED, CLOSED, OFF, FETCHER_SNAPSHOT_UNAVAILABLE }   // growable
// Counters increment per applied verdict, cache hit or miss (§5.1 step 2); events are emitted on misses only. ByteArray getters return copies; Verdict.rules is an unmodifiable view.
class TrustManagerStatus private constructor(…) { val anchorCount: Int; val anchorSnapshotId: Long?; val anchorSnapshotAgeMillis: Long?; val pathCacheHits: Long; val verdictCacheHits: Long; val anchorRefreshFailures: Long; val lastAnchorRefreshFailedAtMillis: Long? /* a failed refreshAnchors() rebuild is a status, not only a WARN log line */ }   // null only while the owning Revokt is CREATED or CLOSED (flow step 1 only), or for fetcherTrustManager before its first successful build; non-null for every instance that can go past flow step 1
class RevoktState private constructor(…) { val lifecycle: RevoktLifecycle /* top-level enum in commonMain (RevoktState is an engine output type; Revokt lives in revokt-jsse): CREATED, STARTED, CLOSED; named to avoid androidx.lifecycle.Lifecycle */; val readOnly: Boolean /* store lock held by another process; retried every READONLY_POLL_INTERVAL */; val storageFallback: Boolean /* running on inMemory() instead of the configured storage (ownership, direct boot, STORE_NEWER_LAYOUT under IN_MEMORY); the configured storage is retried every loader tick and on sync(), except under STORE_NEWER_LAYOUT, §5.1 "Storage fallback" */; val ready: Boolean /* lifecycle == STARTED && every required dataset has a generation (true at once when requiredDatasets is empty); anchor snapshots exist before any handshake can go past flow step 1 (§5.1 "Anchor snapshot") and play no part */; val enforcement: Enforcement
    val dataStates: Map<Dataset, Finding.DataState>      // an entry for every configured dataset; fromSeed and freshness say where the generation came from
    val unsupportedOids: Set<String>; val signedSourceFailing: Boolean; val signedSourceFailingSinceMillis: Long?; val updateBlockedBySelf: Boolean /* a source's own chain is currently rejected on a signed revocation: without a time bound on a TLS-only source (until the host presents a chain that is not hit), for at most FEED_HOST_HOLD on the signed source (§8); cleared when feedHostRevoked takes over */; val feedHostRevoked: Boolean /* the signed source's own chain carries a signed revocation; the hold has expired and fetches proceed loudly (§8); cleared together with feedHostBlock */
    val lastSync: SyncResult?; val nextSyncAtMillis: Long?; val warnings: List<PolicyDiagnostic> }   // consumers match on code, never on message. `warnings` is the set of conditions currently true, recomputed on every publish: session-sticky codes stay until close() (SEED_UNREADABLE, SEED_CHANNEL_MISMATCH, STORE_MIGRATED, STORE_NEWER_LAYOUT, SEED_PAST_REJECT_THRESHOLD; STORE_UNREADABLE until a fallback migration succeeds, §5.1); cleared codes leave when their condition does (STORE_LOCKED on promotion to writer; FETCHER_TRUST_UNAVAILABLE on the first successful build; FEED_HOST_REVOKED with feedHostBlock; CLOCK_BEHIND when no dataset has clockBehind; METERED_DEFERRED on the next non-deferred sync; NO_FETCHING_SOURCE, RULE_FLIPPED_THIS_MINOR, UNVERIFIED_REJECTS_WITH_CLASSICAL_GAP and every other V or S WARNING that is a function of the published (enforcement, policy) pair, copied in by start() and the two setters, when a later pair no longer emits it); NOT_STARTED is never on it (it is the unevaluated counter). A read-only instance derives signedSourceFailing, nextSyncAtMillis and lastSync from the owner's updater.json on each pointer re-read, so a second process is not read as "never synced"; dataStates[…].ageMillis is frozen at publish time, compute a live age from sourceTimestampMillis
```

Growable enums are labelled above; closed ones are `Outcome`, `Enforcement`, `RuleClass`,
`Severity`, `RevoktLifecycle`, `VerifyResult`, `LogLevel`. `RevoktLimits` constants are `@JvmField val`, never `const val`. Members
shown as extensions are declared as members (except the binding extensions on `OkHttpClient`/`OkHttpClient.Builder`, which are top-level in their artifact under `@file:JvmName("RevoktOkHttp")`), `suspend` members are `@JvmSynthetic`, and every file
holding public top-level `kotlin.time` extensions carries `@file:JvmName`. The build asserts
`-jvm-default=enable` so interface members with bodies are default methods for Java implementers.
`RevoktCertificateException : CertificateException` carries the `Verdict.Rejected` as `@Transient val verdict: Verdict.Rejected?` (null only after deserialisation) and a
`CertPathValidatorException` as its immediate cause whose reason is a **per-rule constant** in the
`revokt-engine` jvmMain `Rule → BasicReason` map (`java.security.cert` is not commonMain; in `revokt-engine`, not `revokt-jsse`, so the 0.1 golden fixture can assert it), total
over `Rule.entries`, part of the golden fixture tuple and asserted for every rule by the §9 `Rule` test: `BasicReason.REVOKED` for `REVOKED` and (M2)
`ONECRL`, `CRLSET`, `DENYLIST`; `BasicReason.UNSPECIFIED` for (M3) `CT` and (M4) `DISTRUST`;
`BasicReason.UNDETERMINED_REVOCATION_STATUS` for every `UNEVALUABLE`, `NON_ANSWER` and
`DATA_QUALITY` rule; a rule added in a minor declares its reason with its row. So a `NO_DATA`,
budget, CT, distrust or `STRICT` rejection is never triaged as a revocation. The fetcher trust
managers' verdicts (public and per-source) neither count in `evaluations` nor emit events in M1.

**Status-to-rule mappings** (functions; a unit test asserts them):

| `PathStatus` | fires |
|---|---|
| `FOUND`, `NOT_WALKED` | nothing |
| `NO_ISSUER` (any reason, including `PLATFORM_ONLY`) | `NO_ISSUER` |
| `ISSUER_UNVERIFIED`, `PATH_BUDGET_EXCEEDED`, `PARSE_FAILED` | the same-named rule |

| `CrliteQueryResult` | fires |
|---|---|
| `REVOKED`, `NOT_COVERED`, `NOT_ENROLLED`, `NO_SCTS` | the same-named rule |
| `NOT_REVOKED` | nothing |
| `NO_DATA` | nothing when `dataStates[dataset].generationId == null` (step 7 does not query an engine for such a dataset; the finding is synthesised; the §3.2 precedence puts `NO_DATA` before `NO_SCTS`, so an engine with no generation never answers `NO_SCTS`); `ENGINE_ERROR` with producer `ENGINE` and `engineName` when a generation is published (`Rule.NO_DATA` itself is driven by `requiredDatasets`, never by the engine result) |
| `ENGINE_ERROR` | `ENGINE_ERROR` with producer `ENGINE` |

**Key aggregation (L3, M1)** at step 8: if any evaluated key is `REVOKED`, `REVOKED` fires; otherwise
every evaluated key's non-answer or `ENGINE_ERROR` fires (conservative; only adversarial chains have
a second verifying key). On `Budget`, only `REVOKED` fires from CRLite. **Path aggregation (L1/L2 at
M2, L5 at M4), stated now because those rules ship `REJECT` at 1.0**: a path-level evidence rule
(`ONECRL`, `CRLSET`, `DENYLIST`, `DISTRUST`) fires only when **every** found path, after the
exhaustive re-walk, carries a hit (Chrome's builder discards a path that fails and keeps searching;
a clean alternative path is an allow; **a `PRELOAD`-terminal path is never the clean alternative**: when any `ANCHOR`-terminal path exists, `PRELOAD` paths are excluded from this aggregation (they stay in `issuerSpkiSha256s` for L3), and only when no `ANCHOR` path exists is the rule evaluated over the `PRELOAD` paths (for `DISTRUST`, which is per anchor, a `PRELOAD`-only outcome is the §5.1 invariant's unevaluable finding, never an allow), so a retired-root certificate in Mozilla's preload cannot shadow a OneCRL hit on the live anchor); every hit is a `Finding.PathHit` (`onReportedPath` says whether it lies on `Verdict.path`), and a hit on a non-reported path fires no rule by itself;
when the rule fires, `Verdict.path` is the first hit path, otherwise the first clean path. **The
re-walk** runs only after a `Found` (a `PLATFORM` path included: a hit on it runs decision step 5
as the re-walk and the verdict's `source` is `MIXED`; on `Evaluator.evaluate` with `verifiedPaths` only there is no chain to re-walk and the rule is evaluated over the verified paths alone) and only when a hit lies on a found path; it
reuses the first walk's memo under its own fresh budgets; a `Budget` on the re-walk **never demotes**
the first walk's `Found`: the rule is evaluated over the paths found so far (the hit path plus any
clean path the re-walk completed), the re-walk's `WalkEnd` is recorded on `Finding.Path.rewalkEnd`,
and `PATH_BUDGET_EXCEEDED` fires only from the first walk; the §9.1 properties cover the re-walk from 0.4. **Data
rules (`NO_DATA`, `STALE`, `UNSIGNED_DATA`)** are map lookups over the generation snapshot taken at
flow step 2, computed **before** the catch boundary and merged into every verdict,
`ENGINE_ERROR` included.

**Growability contract.** `newBuilder()` derives from a preset only. A `Rule` added in a minor
takes the preset's table value in every derived policy; **every post-1.0 rule that will be `REJECT`
in any preset, `STRICT` included, ships `ALLOW` in that preset for one minor and flips in the next
with a release note** (the M2 rows are the 0.4 → 1.0 transition and are the only exception); preset
rows for rules present at the major's x.0, `Rule.layer`, `Rule.ruleClass` and `Rule.exemptable`
(except false → true) are frozen within a major, the single `ALLOW → REJECT` flip permitted by the
one-minor rule being the only change to a preset row (the release note must say that a consumer
skipping the `ALLOW` minor sees the flip without warning); a new `Dataset` never joins a preset's `requiredDatasets` or staleness map
within a major; `fired` contains every rule including ones a custom policy never set; `ordinal` is
not stable, persist `name`. **Enforced by a golden fixture** `(rule, class, layer, exemptable, emptyPath, basicReason,
introducedIn, flippedIn, DEFAULT outcome, STRICT outcome, requiredDatasets, staleness map,
minTrustClass map, three time fields, precedence)` whose CI diff accepts only: a new rule with
`ALLOW` when `introducedIn == current minor`; a preset outcome `ALLOW → REJECT` when
`introducedIn == current minor − 1` and `flippedIn` is null, setting `flippedIn = current minor`
(at most once per rule and preset); `exemptable` false → true; existing precedence entries
remaining a subsequence.

**`build()`, `validate(enforcement)` and `start()`**
- V `NO_DATA_REJECTS_WITHOUT_LOCAL_DATA`: `requiredDatasets.isNotEmpty() && outcome(NO_DATA) == REJECT && no local data source` (a seed, or a
  `c2spCache` only when the policy can install it: its rank ≥ `minTrustClass` or `outcome(UNSIGNED_DATA) == ALLOW`):
  a `WARNING` under `OBSERVE`, an `ERROR` under `ENFORCE`, emitted once per required dataset with no
  local source (`PolicyDiagnostic.dataset` set); the setter throws iff any `ERROR`;
  `validate(enforcement)` returns the diagnostics. With `requiredDatasets` empty, `NO_DATA` can never
  fire and readiness never waits for data; V `NO_REQUIRED_DATASETS`: a CRLite source configured and
  `CRLITE ∉ requiredDatasets` → `WARNING` (data loss would be silent). V `IN_MEMORY_STORE_WITH_FETCHING_SOURCE`:
  `RevoktStorage.inMemory()` with a fetching source → `WARNING` (a full re-download per restart, no crash recovery).
  V `MIRROR_WITH_SEED_NEVER_INSTALLED`: a `c2spMirror` configured with any seed source → `WARNING` under both
  enforcements (bootstrap-only, §7.3; the supported offline path is a `SIGNED` private mirror, §7.1).
  V `FORMAT_UNSUPPORTED`: a `remoteSettings` source while `V3 ∉ revocationEngine.formats`, or a `c2spMirror`
  while `V4 ∉ formats` → `WARNING` under `OBSERVE`, `ERROR` under `ENFORCE` (Mozilla serves v3, `upki.rustls.dev` v4; both shipped engines list both, so it fires only for a third-party engine). V `NO_FETCHING_SOURCE`: a required dataset with a local data source and no fetching source → `WARNING` under both enforcements (the instance updates only through `sync()`'s seed re-check, §4). `minTrustClass(dataset)` for a dataset with no entry is
  the preset floor, which therefore applies to datasets added later.
- Each diagnostic names its `DiagnosticCode` and the call that emits it: **B** = `RevoktPolicy.Builder`
  method throws `IllegalArgumentException`; **R** = `Revokt.Builder.build()` throws `IllegalArgumentException`; **V** = `validate(enforcement)` returns it (the setter and
  `start()` throw `IllegalStateException` iff any `ERROR`); **S** = `start()` appends it to
  `RevoktState.warnings`.
- B: `rejectStaleAfter < staleAfter` for any dataset.
- V `STALE_REJECTS_WITHOUT_THRESHOLD`: `outcome(STALE) == REJECT` and no dataset has a
  `rejectStaleAfter` → `WARNING` (the rule can never fire).
- S `SEED_PAST_REJECT_THRESHOLD`: `outcome(STALE) == REJECT` and the seed already past a dataset's
  `rejectStaleAfter` → `WARNING`.
- B: `exempt()` on a non-exemptable rule. V `EXEMPT_ON_ALLOW`: exemption on a rule whose outcome is
  `ALLOW` → `WARNING`.
- V `EVIDENCE_LOWERED_BELOW_PRESET`: `outcome(rule) == ALLOW && preset.outcome(rule) == REJECT` for
  an `EVIDENCE` rule, where `preset` is the one `newBuilder()` derived from → `WARNING` under
  `OBSERVE`; under `ENFORCE` a `WARNING` in the minor in which the preset row flipped
  (`flippedIn == current minor`) and an `ERROR` from the following minor, so an explicit `ALLOW`
  written during the grace minor (the consumer who watched `fired[rule]`, the only signal an `ALLOW`
  row gives, since `wouldRejects` cannot show it) is loud for one more minor instead of fatal; a row
  `REJECT` since the major's x.0 (`flippedIn == null`) is an `ERROR` under `ENFORCE` at once; the message
  names the two supported routes (derive from `DEFAULT` and raise the other rows, or exempt per anchor).
  V `EXEMPTION_ON_EVIDENCE_RULE`: any exemption registered on an `EVIDENCE` rule → `WARNING` (a constant-true
  exemption is `ALLOW` by another name). A
  preset's own `ALLOW` rows (a new evidence rule in its one-minor grace) never fire it: **every preset passes `validate(ENFORCE)` with no `ERROR` at every
  release** (a §9 test).
- S `UNVERIFIED_REJECTS_WITH_CLASSICAL_GAP`: `outcome(ISSUER_UNVERIFIED) == REJECT && unsupportedOids() ∩ classicalOids ≠ ∅` → `WARNING`; `classicalOids` = RSA PKCS#1 with SHA-256/384/512, ECDSA P-256/P-384 with SHA-2, Ed25519.
- S `RULE_FLIPPED_THIS_MINOR`: for every rule with `flippedIn == current minor` whose outcome in the consumer's policy is `REJECT` by inheritance → `WARNING` on `RevoktState.warnings` (a runtime signal that this build enforces a newly flipped rule; a rule in its grace minor is visible only in `fired`).
- S `FETCHER_TRUST_UNAVAILABLE`: `fetcherTrustManager`'s snapshot build failed in `start()` → `WARNING` (cleared by the first successful build); each sync first retries the build on the loader (under the factory lock) and, while it fails, is `FAILED` without a fetch (stage `FETCHER_TRUST`, `sourceId` null, every configured fetching source's `consecutiveFailures` advancing; counting toward `signedSourceFailing` and the failure backoff as any `FAILED`); with a fetching source configured the public instance never attempts the lazy build itself, a handshake on it counts `unevaluated[FETCHER_SNAPSHOT_UNAVAILABLE]` until the loader's retry succeeds.
- V `NO_DATA_AT_FLIP` (the one state-dependent V code): in `STARTED`, `validate(ENFORCE)` (the enforcement setter, and the policy setter against the current enforcement) returns `ERROR` when `outcome(NO_DATA) == REJECT` and a required dataset has `generationId == null`, `pending == false` and a `SEED_UNREADABLE`/`STORE_UNREADABLE` warning for its sole local source; while `pending == true` the flip is accepted and the dataset becomes `NO_DATA` if the start task finds nothing, which `validate()` cannot see.
- Sync `FEED_HOST_REVOKED` (on `SyncResult.warnings`, and carried on `RevoktState.warnings` while `feedHostRevoked`): the signed source's hold expired and fetches proceed (§8). Sync `CLOCK_BEHIND` (and on `RevoktState.warnings` while any dataset has `clockBehind`): a future-dated seed or changeset was installed under the §6.3 rule, so the local clock is behind the signed data.
- V `STRICT_ON_ANDROID_WITHOUT_NO_ISSUER_EXEMPTION`: `STRICT` on `AndroidPlatformTrust` with no `NO_ISSUER` exemption → `WARNING` citing the §5.2 gap.
- V `BUDGET_ALLOWS`: `outcome(PATH_BUDGET_EXCEEDED) == ALLOW` → `WARNING` (re-opens the stuffing evasion).
- R: `outcome(NO_ISSUER) == ALLOW` with the PKIX fallback disabled (§5.1: the fallback is load-bearing).
- V `LOWER_CLASS_SOURCE_NEVER_INSTALLED`: a `MIRROR` or `SYSTEM` source configured for a dataset
  whose `minTrustClass` is above that class while `outcome(UNSIGNED_DATA) == REJECT` → `WARNING`
  (the loader will never install it, §7.3).
- (not a diagnostic) An empty anchor set, a throwing `getAcceptedIssuers()` or a failed index build throws `IllegalStateException` from `trustManager(delegate)` in `STARTED` and from `start()` for consumer trust managers created in `CREATED`, on both platforms (§5.1 "Anchor snapshot"); `fetcherTrustManager`'s failure is the S `FETCHER_TRUST_UNAVAILABLE` warning instead.
- S `SEED_UNREADABLE` / `SEED_CHANNEL_MISMATCH` / `STORE_UNREADABLE` / `STORE_MIGRATED` / `STORE_NEWER_LAYOUT` (per §6.5) / `STORE_LOCKED` (per §5.1 read-only mode); S→`ERROR` thrown by `start()` under `ENFORCE` with `outcome(NO_DATA) == REJECT` when the seed is the only local data source and is unreadable: **in that configuration, and only when the synchronous `meta.json` read finds no complete stored generation (first run, a rebuild, corruption), the seed's verification, `index.bin` rebuild, `prepare`, the §6.5 self-check and `activate` run synchronously inside `start()` on the calling thread, before the flip and before any loader task exists (the one exception to "loader dispatcher only"; a self-check failure is `SEED_UNREADABLE` and throws here; the factory lock is released around this work, §5.1 lifecycle)**; with a complete stored generation the loader decodes it as §5.1 states (falling to `previous`, then the seed, so a readable store masks a bad seed and the common cold start never decodes on the calling thread), otherwise on the loader task (a loud failure in `CREATED`, platform-only, instead of a silent reject-all); `STORE_UNREADABLE` never throws (§6.5), and an unreadable sole `c2spCache` is a `STORE_UNREADABLE` warning with the dataset `NO_DATA` once the start task completes, which is why the seed is the default; a seed
  channel mismatch is an `ERROR` thrown synchronously by `start()` on both platforms (the `seed.json`
  header is read synchronously).
- `NOT_STARTED` is not a warning: a trust manager or `sslContext()` obtained before `start()` runs step 1 only until `start()` and counts `unevaluated[NOT_STARTED]` (creating trust managers before `start()` is the recommended main-thread pattern, so it cannot be a stuck alert).
- R `CHANNEL_UNSET`: no `channel` configured while a CRLite source (a seed included) is. R `PLATFORM_TRUST_MISMATCH`: Android runtime with a non-Android `platformTrust`. R `STORAGE_UNSET`: `AndroidPlatformTrust` with no explicit `storage` (§3).
- Sync-time diagnostics on `SyncResult.warnings`: `SYNC_FAILED` (any `FAILED`/`STORE_FAILED`/`CLOCK_SKEW` sync, with the cause), `SYNC_SCHEMA_REJECTED` (a verified changeset whose records fail the collection schema), `CAP_NEAR_LIMIT` (a body, record count or manifest above half the `RevoktLimits` constant, not the overridden value, the signed size notwithstanding, and the code on the over-cap `FAILED` of a signed record, §5.1 limits table; the §9 live check warns on it), `METERED_DEFERRED` (§7.2, with `SyncOutcome.DEFERRED`), `ENGINE_SELF_CHECK_FAILED` (the §6.5 self-check mismatch, `SyncOutcome.FAILED`), `INDEX_INCONSISTENT` (§3.2), `FORMAT_UNSUPPORTED` (§3.2), `FEED_HOST_REVOKED` (§8) and `CLOCK_BEHIND` (§6.3). `SyncResult.stage`, `httpStatus` and `cause` say where and why without parsing `message`.

## 5. Trust manager [M1]

### 5.1 Common flow

**Limits** (`object RevoktLimits`; walker budgets are documented constants; download and record caps are builder-overridable upward; cache sizes are builder-configurable):

| Constant | Value | Meaning |
|---|---|---|
| `MAX_DEPTH` | 16 | a path holds at most `MAX_DEPTH + 1` certificates including the terminal; deeper is a dead end, not exhaustion (same convention in the reference walker) |
| `MAX_PRESENTED` / `MAX_PRESENTED_BYTES` | 64 / 1 MiB | presented certificates and their summed DER; beyond either the chain is `Budget(EXPLORATION_BUDGET)` without a walk (honest chains are under 20 KB; bounds per-handshake memory independently of `MAX_CERT_BYTES`) |
| `MAX_RELATED_PER_LEVEL` | 64 | related candidates explored at one node; the 65th triggers `RELATED_BUDGET` without being explored |
| `MAX_VERIFICATIONS` | 256 | verifier calls per walk (memo hits excluded; the guard-tripping attempt not counted) |
| `MAX_EXPLORED` | 1,024 | candidates for which verification was requested per walk, memo hits included |
| `FALLBACK_MAX_PRESENTED` | 8 | the PKIX fallback is skipped for longer presented chains; a `NotFound` on such a chain that the platform accepted is `PATH_BUDGET_EXCEEDED`, never `NO_ISSUER` |
| `PATH_CACHE_ENTRIES` / `PATH_CACHE_TTL` | 256 / 10 min | per trust manager; TTLs are absolute from insertion on the monotonic `TimeSource`, not sliding; entries hold the leaf's DER, `serial` and `scts` only, never the presented chain |
| `CROSS_CALL_MEMO_ENTRIES` | 1,024 | per `Revokt`; `VERIFIED` only; synchronized, shared by concurrent handshake threads across trust managers |
| `ACCEPTANCE_MEMO_ENTRIES` / `ACCEPTANCE_MEMO_TTL` | 1,024 / 24 h | per trust manager; the 3-arg null-host retry memo (flow step 1), keyed (chain hash, host'), written only after a Socket/SSLEngine overload's flow step 1 returned; absolute TTL; an expired entry costs a failed lazy cleaner on a long-lived connection and buys no safety, hence long |
| `FEED_HOST_HOLD` | 24 h | the signed source's `BLOCKED_BY_SELF` hold (§8); fixed, not the policy's `signedSourceFailingAfter` |
| `ENGINE_CLOSE_DRAIN` | 5 s | `RevocationEngine.close()` waits this long for in-flight queries (§3.2) |
| `FETCH_TIMEOUT` | 30 s | default `FetchRequest.timeoutMillis`, enforced by the engine (§3), so "a sync attempt completed" is bounded |
| `VERDICT_CACHE_ENTRIES` / `VERDICT_CACHE_TTL` | 1,024 / 60 s | per trust manager |
| `ANCHOR_REFRESH_MIN_INTERVAL` | 60 s | |
| `EVENT_RING_CAPACITY` / `REJECTED_QUEUE_CAPACITY` | 64 / 4,096 | |
| `MAX_TRUST_MANAGERS` | 16 | live instances per `Revokt`, builder-overridable in both directions, ≥ 1 (`limits { maxTrustManagers }`); live referents are counted through `WeakReference`, and before the cap throws every entry whose referent has cleared is evicted regardless of `ReferenceQueue` delivery, so a rebuilt client's dropped instance never counts |
| `MAX_CERT_BYTES` | 262144 | per-certificate DER size (measured max over the seed corpus with margin); a larger certificate is a dropped candidate (`candidatesDropped`; leaf: `PARSE_FAILED(OVERSIZE)`, checked before the parse); §9.2 fuzzes to the cap + 1 and asserts the over-cap behaviour |
| `MAX_FILTER_BYTES`, `MAX_JSON_BYTES`, `MAX_X5U_BYTES` | 16 MiB, 4 MiB, 64 KiB | caps for **unsigned** bodies (mirror and system-cache files, the changeset JSON itself, x5u); for a `SIGNED` attachment the cap is `min(attachment.size, MAX_FILTER_BYTES)` (hash and size both verified; a signed record declaring more is `SyncOutcome.FAILED` with `CAP_NEAR_LIMIT` (stage `ATTACHMENT`) and advances nothing: a 16 MiB freeze is recoverable by raising the cap, a crash loop from one bad signed record is not); enforced while inflating; bodies are fetched, verified and written **one at a time**, so heap peak is one body plus its decode |
| `MAX_MANIFEST_ENTRIES`, `MAX_CHANGESET_RECORDS`, `MAX_SYNC_BYTES` | 32, 256, 128 MiB | manifest cap over C2SP attachments to fetch; record cap per changeset after channel filtering; per-sync total bounds bandwidth and disk; a manifest or changeset over its cap is rejected before any body fetch |
| `READONLY_POLL_INTERVAL` | 60 s | a read-only instance's pointer re-read and lock retry |
| `MAX_BACKOFF` | 24 h | cap on honoured `Backoff`/`Retry-After` and on persisted `backoffUntilMillis`; computed failure backoff ≤ the 6 h poll interval |
| `AWAIT_DATA_COMPAT`, `AWAIT_DATA_DEFAULT` | measured (§6.4) on Android; a fixed 2 s on the JVM (§11) | readiness deadline per channel |

**Flow**

```
checkServerTrusted(chain, authType, socket|engine|host|none)
  1. platform.checkServerTrusted(...)                                 // authoritative; throws → done. Under OFF: return here.
     Android 3-arg overload (OkHttp's chain cleaner, which runs lazily: when a pin matches, when consumer code reads handshake.peerCertificates, or for HTTP/2 coalescing eligibility; so seconds or minutes after the socket overload, possibly past the verdict TTL): compute chainHash and host' first; if the **acceptance memo** holds (chainHash, host') (a per-trust-manager LRU of `ACCEPTANCE_MEMO_ENTRIES` entries with the `ACCEPTANCE_MEMO_TTL` absolute TTL, written **only** at flow step 2 of a Socket or SSLEngine overload whose flow step 1 returned, never by a 3-arg call or by `Revokt.evaluate`; keyed without the anchor snapshot id, since the platform's acceptance does not depend on revokt's snapshot and the retry re-validates under the platform's current trust store, so a `refreshAnchors()` cannot empty it; independent of the path cache's LRU and TTL so the lazy cleaner is not broken by eviction; live in every lifecycle state and under every `Enforcement`, since it records platform acceptance only and OkHttp's cleaner runs after `close()` for connections made before it), step 1 is the extension call with host' and, on a throw, the null-host retry of decision step 4 (that overload enforced CT with the TLS SCTs and the pins, so the retry re-validates nothing the platform has not accepted for this chain and host); otherwise step 1 is the extension call with host' only, and its returned list is this call's step-4 result. At most two platform validations per 3-arg call, the second only the null-host retry; the retry is never applied to a chain and host no socket or engine overload has accepted, which a direct 3-arg caller (a consumer's own `X509TrustManagerExtensions`) therefore never obtains.
  0. readiness (after step 1; waiting overloads only, under needsData): dataReady.get(max(0, dataDeadline − now)), TimeoutException = proceed; the anchor snapshot needs no wait, it exists before any handshake can go past step 1 (§5.1 "Anchor snapshot")
     needsData = requiredDatasets.isNotEmpty() && (outcome(NO_DATA) == REJECT || outcome(NO_ISSUER) == REJECT), from the (policy, policyEpoch) pair read once here when step 0 runs   // NO_ISSUER is here because from M2 the preload is data that can turn NO_ISSUER into Found
  2. gen = generationSnapshot (one @Volatile read: generation, epoch, dataStates, coverageEnd; threaded through decide and the engine query)
     chainHash = sha256(for each cert in order: u32be(len) ‖ DER); host' = host (argument, socket.handshakeSession.peerHost or engine.peerHost) lowercased, trailing dot stripped
     (policy, policyEpoch) = the pair step 0 read, else one @Volatile read now; threaded through steps 3, 7, 8, the exemptions and the cache put
     (shadowPolicy, shadowPolicyEpoch) = likewise, read beside the policy pair at step 0 or here; threaded through step 3a and the cache put
     for a Socket or SSLEngine overload: acceptanceMemo.put(chainHash, host')   // flow step 1 returned, so the platform accepted this chain and host; written before any lifecycle or Enforcement check (under OFF, in CREATED and in CLOSED the write still happens right after flow step 1)
     index = trustManager.candidateIndex (the one @Volatile read of the anchor snapshot per handshake; its id is anchorSnapshotId; decision step 1 uses this reference and performs no read of its own)
     verdictCache[(chainHash, host', gen.epoch, anchorSnapshotId, policyEpoch, shadowPolicyEpoch)]?.let { return apply(it) }   // no parse, no event; counters (evaluations, fired, exempted, rejects/wouldRejects, shadowWouldRejects, per-dataset and per-reason maps) advance exactly as on a miss; verdictCacheHits++; the Android 3-arg overload still calls the extension for its return value
     pathKey = (chainHash, anchorSnapshotId, host' if step 4 would run on this platform and host' != null)
     walk = pathCache[pathKey] ?: decide(chain, index).also { cache unless decide threw }               // decide = decision steps 1–6 only (the path result; no CRLite query, so the path cache is valid across installs)
  3. verdict = evaluate(walk, gen, policy)                                                            // decision steps 7–8; the enforced catch boundary closes here: the verdict is final before any event work
  3a. shadowVerdict = evaluate(walk, gen, shadowPolicy) under its own boundary (the §5.5 catch rule) when set, skipped (null) when verdict carries EngineError(BOUNDARY)   // after the enforced boundary closed: a throw yields a shadow Verdict carrying Finding.EngineError(BOUNDARY) and never touches `verdict`; verdictCache.put(verdict, shadowVerdict) unless `verdict` is ENGINE_ERROR, with shadowVerdict stored as null when it is a shadow-only ENGINE_ERROR (never cached, counted once on this miss); counters (`rejects`/`wouldRejects`/`fired`/`exempted`, per-dataset and per-reason maps from `verdict`; `shadowWouldRejects` from `shadowVerdict`) are applied by `apply()` here, after 3a, never inside `evaluate`. Runs on every trust-manager path and in `Revokt.evaluate` (which shares the registry caches); `Evaluator.evaluate` evaluates the enforced policy only, `shadowVerdict` null
  3b. emit event (verdict-cache misses only): each listener's drain submission (executor.execute) runs under its own try/catch; a throw (RejectedExecutionException after shutdown, or any Throwable other than a VirtualMachineError except StackOverflowError, as §5.5) counts listenerFailures, removes that listener and clears its cursor; the ring entry is untouched, so droppedEvents/droppedRejectedEvents are unaffected; nothing here changes the verdict or step 4
  4. if enforcement == ENFORCE && verdict is Rejected throw RevoktCertificateException(verdict)
```

**Decision list** (steps 1–6 are `decide`, steps 7–8 are `evaluate`; total and ordered; **every exit from steps 1–6 continues to step 7**;
`decide` and `evaluate` run inside the one catch boundary, and the walk itself never
throws: a verifier throw is `INVALID` plus `VerifierError`, a `canonicalSubject` null or throw means "no
canonical match" with raw-byte and SKI matching still applied, for any verifier):
1. Use the `CandidateIndex` reference captured by the single `@Volatile` read at flow step 2 (built
   before any handshake can go past flow step 1, §5.1 "Anchor snapshot", and replaced whole by
   `refreshAnchors()`, so a handshake sees exactly one index); its id keys the path and verdict caches
   and is threaded through every later step; `Evaluator.evaluate`, which has no flow step 2, performs
   that one read at its own entry. (`NOT_WALKED` is reserved for "the engine did not get here".)
2. Leaf is an anchor by bytes (compared against the index's parsed anchor byte set, so an anchor
   the parser dropped at index build never matches) → `Found([WalkPath([leaf], terminal = ANCHOR)])`, `leafKeys = {leaf.spkiHash}`.
3. Parse the leaf. Unparseable → `PARSE_FAILED(STRUCTURE)`, over `MAX_CERT_BYTES` →
   `PARSE_FAILED(OVERSIZE)` (the size check runs before the parse), and a leaf the parser marks
   `producerKeyable == false` (the conservative keyability profile of §9.2, a function of the signed `tbsCertificate` alone; D8) → `PARSE_FAILED(PRODUCER_UNKEYABLE)` with its `keyabilityClause`:
   the leaf is never queried (counters zero), because a query for a key outside the filter's universe answers
   arbitrarily and revokt cannot show this key is inside it; such a leaf may still be in a filter (the D8 gap, §10 item 8).
   Walk and fallback do not run. `producerKeyable` gates the leaf only: an issuer candidate is never dropped for it.
   `presented.size > MAX_PRESENTED` or summed DER > `MAX_PRESENTED_BYTES`, both over the raw presented chain before any candidate is dropped (`MAX_PRESENTED` bounds parsing, §10) → `Budget(EXPLORATION_BUDGET)` without a walk.
4. Android with `host' != null`: `platformTrust.verifiedChain(delegate, chain, host')` → `Found([chain'], source = PLATFORM)`;
   a `PLATFORM` chain of one certificate yields `leafKeys = {leaf.spkiHash}` as step 2 does.
   On a throw (the §5.2 CT gap): retry `verifiedChain(delegate, chain, null)` (Conscrypt's `checkCT`
   needs a host; NSC pins cannot exist without a `<domain-config>`, which already forbids the null-host
   call; step 1 has enforced both) → `Found(PLATFORM)`; only if
   that also throws continue to step 5. **The null-host retry is available only when the
   application's network security config has no `<domain-config>`**: AOSP `RootTrustManager`
   throws `CertificateException("Domain specific configurations require that the hostname be
   provided")` on a null hostname otherwise (Appendix A); the 0.3 probe confirms behaviour per image,
   with and without a `<domain-config>`, it does not establish availability.
5. `walk = reconstruct(presented, index)`; `Found` → step 7.
6. `fallback = pathBuilder.build(presented, anchors, now)` if `presented.size ≤ FALLBACK_MAX_PRESENTED`,
   cached under the path key:
   - walk `NotFound` and the fallback finds a path → `Found([fallback], usedFallback = true)`.
   - walk `NotFound`, the fallback was **skipped** (chain too long) and the platform accepted in
     step 1 → `PATH_BUDGET_EXCEEDED` with `endReason = COMPLETE` (the walk itself completed) and `VerifierError("fallback skipped")`:
     no honest Web PKI chain is longer than 8 certificates and unreproducible by the walker, and the
     server controls chain length.
   - walk `NotFound` and the fallback failed: `ISSUER_UNVERIFIED` when the child's own signature OID
     (`child.tbsSigOid`, CA-chosen) was `UNSUPPORTED` against a **related** candidate; a candidate's key or
     curve OID (server-chosen on a decoy) never counts, so a related unsupported decoy cannot relabel
     `NO_ISSUER` into the separately exemptable `ISSUER_UNVERIFIED`; else `NO_ISSUER`. On a trust-manager
     binding (and `Revokt.evaluate`, which always runs step 1), **any** such `NO_ISSUER` is `PLATFORM_ONLY` (the platform trusts a chain
     neither revokt's walker nor its PKIX builder can reproduce: divergent canonicalisation,
     constraints, verifier or anchors); the walker's own reason is kept in `Finding.Path.walkerReason`.
     In the walker-only harness and `Evaluator.evaluate` the walker's reason is reported directly.
   - walk `Budget`: the fallback path's issuer key (appended last) and the walk's partial leaf keys
     are evaluated in step 7 **only so that `REVOKED` is reported when reachable**; the path status
     is `PATH_BUDGET_EXCEEDED` regardless; `usedFallback = true` when a fallback path was evaluated.
7. Data: the data rules (`NO_DATA` for each required dataset with no generation and not `pending`,
   never with a generation installed from a seed or a system cache for that dataset; `STALE`; `UNSIGNED_DATA`) were computed from the generation
   snapshot (read at flow step 2) before decision step 1, outside the catch boundary (the one clock read is itself guarded: a
   throwing consumer `Clock` is `ENGINE_ERROR(BOUNDARY)`, never an escape), and are merged into every verdict whatever
   the path status or any exception. Then evaluate CRLite once per distinct leaf-issuer key; `REVOKED` wins; every evaluated key
   gets a `Finding.Crlite`; on `Budget` only `REVOKED` fires a rule, other results are findings only.
8. Rules fire from the path status, the CRLite results, the `DataState`s and an exemption that throws; outcomes from the
   policy; exemptions for fired exemptable `REJECT` rules; `Verdict.rule` is the first fired,
   non-exempted `REJECT` rule in `Rule.PRECEDENCE`; `rejects`/`wouldRejects` increment once on it;
   `fired` and `exempted` increment per rule.

| Overload | Who calls it | Waits? | Before readiness |
|---|---|---|---|
| `(chain, authType, Socket)` | OkHttp, HttpsURLConnection, Ktor OkHttp/Android; Conscrypt's `ConscryptEngineSocket` forwards here | yes | waits |
| `(chain, authType, String host)` 3-arg | OkHttp's Android chain cleaner, lazily after the socket overload (flow step 1) | yes | its step 1 is defined at flow step 1: the extension call with host', with the null-host retry only for a chain and host a socket or engine overload already accepted (acceptance memo entry present, flow step 1; never a path-cache lookup); at most two platform validations per call, the second only the null-host retry, the last one's returned list being the call's return value and its step-4 result; declared on the final `RevoktTrustManager` in `revokt-jsse` (`revokt-android` cannot subclass it); on the JVM, where `verifiedChain` is null, it returns the presented chain as a list |
| `(chain, authType, SSLEngine)` | `java.net.http`, Netty, Ktor Java | no | seed if loaded; while the start task has not passed the seed and system-cache steps the dataset is `pending` and `NO_DATA` does not fire (allow), so the Android seed load never rejects on a non-waiting overload; `NO_DATA` only once the start task found nothing local; the anchor snapshot always exists in `STARTED` |
| `(chain, authType)` 2-arg | Ktor CIO, casts to `X509TrustManager` | no | as above; step 5 runs via `reconstruct` |

**HTTP/2 coalescing (OkHttp, verified in `RealConnection.isEligible`).** A request to host B reuses an established HTTP/2 connection to host A when the route's socket address matches, A's certificate covers B and B's pins pass; `checkServerTrusted` never runs for B. revokt therefore evaluates once per connection for the host OkHttp handshook for: the verdict cache key, `RevoktEvent.host`, `hostIn`/`hostSuffixIn`, `OBSERVE` attribution by host and the NSC `<domain-config>` selection at step 1 are all A's, and a coalesced B inherits A's verdict. A consumer that needs per-host policy on coalescable hosts uses a separate `OkHttpClient` or `ConnectionPool` per host (OkHttp treats a non-default `HostnameVerifier` instance as non-coalescable, but revokt does not rely on that). Ktor-OkHttp inherits this; `java.net.http` does not coalesce across hosts (unverified).

**Lifecycle.** `RevoktLifecycle`: `CREATED → STARTED → CLOSED`; `start()` and `close()` are
idempotent; `start()` after `close()` throws. **`start()`, synchronous on both platforms** (may throw;
performs small disk reads, calls each delegate's `getAcceptedIssuers()` and takes the factory lock
and the store lock, so call it off the main thread or under `StrictMode.allowThreadDiskReads`;
`seed.json` is the first, stored entry of the seed zip so the header read is one small read). **The
whole synchronous part runs under the factory lock of "Trust managers per delegate"** (an internal
`STARTING` flag set under the lock for its duration, released around the sole-seed decode below) and the
lifecycle flips to `STARTED` as its last step under that lock, so no `trustManager(d)` and no second
`start()` can observe a flip that is later undone (a second `start()` that finds `STARTED` under the
lock returns at once, on the JVM without joining the loader; the `STARTED` state is published and
listeners dispatched after the lock is released). First, build the anchor snapshot of every trust
manager created so far on the calling thread ("Anchor snapshot" below; `revokt.trustManager` only if
it has been created; `fetcherTrustManager`'s when a fetching source is configured; on Android this is
also the warm-up of the NSC certificate sources);
a failure throws `IllegalStateException` before any registry entry or store lock is taken, except
`fetcherTrustManager`'s, which is recorded as the S `FETCHER_TRUST_UNAVAILABLE` warning and retried per
sync ("Anchor snapshot" below). Then register `storage.identity()` in the in-process registry when non-null
(a second instance throws), `storage.lock()` (`StoreLockedException` → this instance is
**read-only**, below), read `store.version` (an empty store is initialised by the owner only; lower →
`STORE_MIGRATED`, higher → `STORE_NEWER_LAYOUT`, §6.5), the
pointer and the pointed `meta.json` (channel mismatch or unreadable → treated as no stored generation,
`STORE_UNREADABLE`, `storeFailures++`), and the `seed.json` header (`SEED_CHANNEL_MISMATCH` →
`IllegalStateException`). **When the sole-seed `ENFORCE` configuration finds no complete stored
generation** (§4 S bullet) the factory lock is now released, the seed is verified, rebuilt, prepared,
self-checked and activated on the calling thread (150–300 ms interpreted on the default channel, §6.4),
the lock is re-taken, snapshots are built for any trust manager created in the gap (it saw `CREATED`
and built nothing), and the flip follows; a `trustManager(d)` racing this therefore blocks only for the
lock's short holds, never for the decode. **The other two racers in the gap, stated**: a second `start()`
that finds `STARTING` under the lock waits on the lock's condition until the first completes and then
returns or throws per the first's outcome (it never registers, locks or decodes a second time, so
`prepare`/`activate` stay serialised; the WorkManager worker's `start()` racing the app's is this case);
`close()` that finds `STARTING` sets a cancel flag and **waits, unconditionally, until the decoding
thread has re-taken the lock and left** (the wait's duration is bounded by the decode plus the
self-check; it is not a timeout); `close()` never releases a store lock it did not take and never calls
`engine.close()` while a `prepare`/self-check/`activate` is in flight. The three outcomes: (i) the
decoder sees the flag before `activate`: it closes the prepared generation, releases the store lock,
deregisters the identity, and `start()` throws `IllegalStateException("closed")`, lifecycle `CLOSED`;
(ii) the decoder missed the flag: `activate`, the pointer flip and `updater.json` complete, the
decoder publishes the generation reference, re-takes the lock, sees `CLOSED`, releases the store lock
and throws the same exception; the written generation stays on disk and `close()` then clears the
reference and runs `engine.close()` in its usual order; (iii) no `close()` raced: a `start()` that
throws **after** `activate` (a gap trust manager's snapshot build fails) leaves the live engine
generation, the written seed generation and the flipped pointer in place and the lifecycle unchanged
(`CREATED`, or `CLOSED` when `close()` raced); the retry finds a complete stored generation and loads
it on the loader without a second seed verification. The decoding thread is recorded: a `start()` or
`close()` from it (consumer code inside an injected engine's `prepare`, a `SeedOpener` or a verifier)
throws `IllegalStateException("re-entrant start()/close() from the start() thread")` instead of
waiting on itself. The worker maps a cancelled `start()` (`"closed"`) to `Result.failure()` like a
`CLOSED` instance. **A `start()` that throws** releases the store lock and deregisters the
identity if it had taken them, leaves the lifecycle at `CREATED` (never flipped), submits no loader
task, discards the snapshots it built in that call (no handshake can have keyed a cache on them: in
`CREATED` every trust manager runs step 1 only; ids are not reused), and may be called again once
the cause is fixed, when it rebuilds every pre-start instance; a pre-start instance whose delegate
keeps failing therefore fails every retry until the consumer drops it and it is collected. Then **one loader task**: decode the stored generation (unless `start()` found none synchronously and installed the seed instead; failure →
`previous` → nothing, each `storeFailures++`), verify and install the seed (unless `start()` already did so synchronously, §4 S bullet) **unless the stored
generation is `SIGNED` and not older than the seed** (a stored lower-class generation is always
evicted and pruned, §7.3; the watermark becomes `max(watermark, seed timestamp)` taken from the
verified `records.json`; a blob whose key exists and re-hashes to its name is never rewritten (a mismatch is rewritten from the seed, `storeFailures++`, §6.5); a complete directory that already
exists is `UNCHANGED`), read the system cache (§7.3), schedule the first sync (under a persisted `backoffUntilMillis` it runs at once and completes as `BACKOFF`, setting `lastSync` and both `lastAttemptAtMillis` fields (per source and `datasetLastAttemptAtMillis`), then reschedules at the backoff). The JVM `start()`
joins that task up to `awaitData` (after the factory lock is released) and then returns (the
readiness future covers the rest); Android returns after the synchronous part without joining the
loader and its waiting bindings cover the gap; while `STARTED`
the loader is the only publisher of the generation reference. The loader thread is a daemon named
`revokt-loader-<identity or build sequence>` (two channels in one process are told apart). The loader runs under every `Enforcement`, `OFF` included, so a runtime flip is
immediate. An explicit `sync()` queues behind the start task and any in-flight install, ignores
the poll interval and honours `backoffUntilMillis` (`BACKOFF`).

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
stored `SIGNED`), merges `updater.json` per field (watermark = max; `feedHostBlock` = the later episode; cursor and
`lastVerified*` from the generation that ends up installed; `backoffUntilMillis` = max; `consecutiveFailures`
and per-source `lastAttemptAtMillis` from the newer record; `seedInstalledAtMillis` from whichever seed
install is live; `datasetLastAttemptAtMillis` = max, so an in-memory attempt that opened the `STALE` gate
is never undone by an older disk record) and clears `storageFallback` and the `STORE_UNREADABLE` warning
that caused it (a `STORE_NEWER_LAYOUT` fallback is never retried, so that warning stays), so a direct-boot process
migrates to disk after unlock instead of staying in memory for its lifetime.

**`close()`** (never on the Android main thread, and never on the loader thread, where it throws
`IllegalStateException`; it blocks): take the factory lock **only** to flip the state to `CLOSED`
(serialised with `start()`'s flip and `trustManager(d)`'s lifecycle read; a `start()` that then sees
`CLOSED` under the lock throws; a `start()` already past its flip whose loader join observes `CLOSED`
returns normally) and release it before anything else → stop scheduling → complete the internal
`dataReady` future and the public `readyFuture()` (the public one exceptionally) → cancel the
loader and await an in-flight install (a cancelled install never flips the pointer, closes an un-activated `PreparedGeneration` and deletes its
own directory before returning) → drain in-flight handshakes (a handshake thread increments the in-flight counter
**before** it reads the lifecycle state and decrements after, so the drain cannot miss a thread that
has passed the check; `fetcherTrustManager`'s lazy build re-reads the lifecycle under the factory
lock and returns on the platform verdict when it is not `STARTED`) → release the store lock → deregister the identity → clear the generation reference
(the loader is stopped, so this is the only post-loader write) → `engine.close()` (always; `Revokt`
owns the engine). **After `close()`, and in `CREATED`, every trust manager, existing ones included,
runs step 1 only**, as `OFF`, with no events and frozen counters other than `unevaluated`; `trustManager(d)` in `CLOSED`
returns such an instance. Clients that outlive `close()` therefore keep working on the platform verdict alone.
`dataDeadline` is measured from the lifecycle flip to `STARTED`, not from the call to `start()`, which may block on the store lock's try and the NSC warm-up first. Every handshake that returns after flow step 1 without reaching step 2 (in `CREATED`, after `close()`, under `OFF`, or on `fetcherTrustManager` without a snapshot) increments `RevoktStatus.unevaluated[reason]`, the one counter group that is never frozen.

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

**`reconstruct`: invariant, deferral rule, termination rule and argument.**

*Invariant.* A returned path is leaf → … → terminal in which every link's signature was
`VERIFIED` by the injected verifier under the next certificate's key and whose terminal is in the
anchor snapshot by exact bytes. **M2**: a candidate found in Mozilla's signed preload by Mozilla's
bytes is a *candidate*, not a terminal: the walk continues from it toward an anchor; a preload-only
path with no anchor reachable is reported with `Finding.Path.terminalKind = PRELOAD` and
`anchorSha256 = null`, counts as `Found` for L3 CRLite, and is `DISTRUST`-unevaluable at M4 (a
`Finding`, never an allow of a listed anchor). The leaf's
issuer keys are taken only from such paths. Platform-verified chains are trusted without re-verification.

*Deferral rule.* No candidate may be excluded because of a property it shares with another
candidate (no deduplication by key, name or key identifier; only exact byte duplicates, across
presented and store, and certificates already on the current path are skipped; **an exact-byte
duplicate is yielded once, at the earliest position in the node's order: the presented position at
the leaf, the store position below the leaf**). A candidate may be deferred
or capped only by its own relation to the child. A candidate is **related** when its subject equals
the child's issuer (raw bytes, or under `canonicalSubject`, which on the JVM and Android is the
platform's own `X500Principal` canonical form) or its SKI equals the child's AKI `keyIdentifier` (an
AKI carrying only the issuer-and-serial form, or an issuer without an SKI, makes the test name-only).
Every honest issuer is related under the platform's own canonicalisation, which is why the engine
delegates canonicalisation to the platform; on both default delegates every honest issuer is
therefore related, and the misclassification residue is confined to custom delegates whose name
equality differs from `X500Principal`'s. **Unrelated candidates are the presented certificates not
related to the child**, are explored only while no path exists through the node (checked before
every candidate), and are not capped; **at the leaf, when `CandidateIndex.customCanonicaliser` is set
(`platformTrust` is not one of the two shipped final classes, or the delegate is not `platformTrust.defaultDelegate()`; §3), the unrelated loop runs regardless of `foundHere`** (cost bounded by
`presented − 1`, so P6 holds on the default delegates), otherwise an honest issuer misclassified as
unrelated could be hidden by a related decoy path (§10 residual 1). Store certificates are never unrelated candidates.

*Termination rule.* At the leaf, every related candidate is explored, so every distinct key that
verifies the leaf and terminates is collected; below the leaf, the first sound path through a node
suffices in M1 (M2 re-walks exhaustively when a layer hits, under the re-walk rule of step 8: fresh
budgets, shared memo, never demoting the first walk's `Found`). **Any limit exceeded at any node
aborts the whole walk with `Budget`**; only `MAX_DEPTH` is a local dead end. `Found` is returned
only when the walk completed without exhaustion; a `Budget` may carry partial paths.

*Why this is sound.* Recovered or substituted keys cannot chain to a real anchor (rounds 1–2). An
`UNSUPPORTED` link is never trusted (round 2). Nothing is excluded for a shared property, so a
same-key decoy or a cross-certificate to a non-anchor listed first cannot hide the real certificate,
which is related and is explored (round 3). The honest issuer's key is the only key that verifies a
real leaf's signature other than a recovered key, and a recovered key terminates only if certified
under a real anchor, which the attacker cannot obtain; so a `Found` carrying only benign keys is
unreachable for a real revoked leaf. Stuffing related junk past the cap, or verifying junk past the
guards, yields `Budget`, which rejects; an exhaustion in any subtree also yields `Budget`, so a
stuffed subtree cannot starve the honest key out of a `Found` (round 4). Every terminating
leaf-issuer key is evaluated and `REVOKED` wins. The PKIX fallback covers one residue the walker
does not: a `NotFound` on a chain of at most `FALLBACK_MAX_PRESENTED` certificates whose honest link
the walker could not reproduce (a custom delegate's constraints or verifier divergence; canonicalisation alone no longer yields `NotFound`, §10 residual 1). Beyond the
guards the walk is `Budget`, which rejects whatever the fallback does, and a `NotFound` too long for
the fallback is `PATH_BUDGET_EXCEEDED`. A policy may not disable the fallback while `NO_ISSUER` allows.

```kotlin
// Declarations the walker and the §9.1 harness compile against. Walk, WalkPath, Cert, CandidateIndex and reconstruct are `internal`
// to revokt-engine; the walker-only harness and the Jazzer walker fuzzer live in revokt-engine's own test source set; revokt-testing's
// reference walker takes List<ByteArray> and returns the Set<String> of lowercase-hex leaf-issuer SPKI hashes (value equality), so it needs no internal type.
internal class Cert(val der: ByteArray, val bytesHash: ByteString, val tbs: ByteArray /* the TBS re-encoded by the §9.2 unsigned-header rule: the verified message and the input of every TBS field */, val sig: ByteArray /* signatureValue content after the unused-bits octet, padding bits cleared (§9.2) */, val tbsSigAlg: ByteArray, val tbsSigOid: String, val spki: ByteArray /* rawSpki TLV */, val spkiHash: ByteString, val keyOid: String, val curveOid: String?, val keyFamily: KeyFamily, val subjectRaw: ByteArray, val issuerRaw: ByteArray, val canonicalSubject: String?, val ski: ByteArray?, val akiKeyId: ByteArray?, val serial: ByteArray, val scts: List<CrliteSct>, val notBefore: Long? /* null when the time does not decode (§9.2; every JDK-accepted form decodes) */, val notAfter: Long?, val producerKeyable: Boolean, val keyabilityClause: KeyabilityClause? /* null ⇔ producerKeyable (§9.2 K1–K8); evaluated for the leaf at decision step 3 only */, val findings: List<Finding>)   // the §5.5/§9.2 parser's output; one object per certificate
internal class WalkPath(val certs: List<Cert>, val terminal: TerminalKind)   // leaf → … → terminal; distinct from Finding.Path
internal sealed interface Walk {                          // every variant carries unsupportedOids (related candidates only), findings and stats: WalkStats (verifications, candidatesExplored, relatedExploredAtLeaf, unrelatedExploredAtLeaf), built at the three return sites
    class Found(val paths: List<WalkPath>, val leafKeys: Set<ByteString>, val unsupportedOids: Set<String>, val findings: List<Finding>, val stats: WalkStats) : Walk
    class NotFound(val reason: NoIssuerReason, val unsupportedOids: Set<String>, val findings: List<Finding>, val stats: WalkStats) : Walk
    class Budget(val end: WalkEnd, val endDepth: Int, val partialPaths: List<WalkPath>, val partialLeafKeys: Set<ByteString>, val unsupportedOids: Set<String>, val findings: List<Finding>, val stats: WalkStats) : Walk
}
/** Built once per snapshot, synchronously at wiring or inside start(), or lazily for fetcherTrustManager (§5.1 "Anchor snapshot"), rebuilt on the loader by refreshAnchors() (~10 ms for 140 anchors on ART; ~150–200 ms for M2's 2,500 preload certificates):
 *  bySubjectRaw, bySubjectCanonical, bySki over store certificates, with canonicalSubject, keyFamily and spkiHash precomputed and exact-byte duplicates removed.
 *  The presented chain (≤ ~10 certificates) is scanned linearly per call; no maps are built for it. */
internal class CandidateIndex {
    fun related(presented: List<Cert>, child: Cert, seen: Set<ByteString>, belowLeaf: Boolean): Sequence<Cert>   // belowLeaf: store (terminal-first) before presented; at the leaf: presented (by index) before store. Within store, in order: raw-name matches, canonical-name matches, SKI matches; within each group candidates whose keyFamily is compatible with child.tbsSigOid's family first, incompatible last; ties by bytesHash. Byte-duplicates yielded once at the earliest position. The index is per snapshot and shared across calls, so the presented chain is an argument.
    fun unrelated(presented: List<Cert>, child: Cert, seen: Set<ByteString>): Sequence<Cert>   // the presented certificates NOT in related(child), by index
    fun isAnchorBytes(c: Cert): Boolean
    fun isPreloadBytes(c: Cert): Boolean                                                   // M2: the store's second candidate set (Mozilla's bytes), yielded by related() after the anchors
    val customCanonicaliser: Boolean                                                        // platformTrust is not one of the two shipped final classes, or the delegate is not platformTrust.defaultDelegate() (§3, a class check); §5.1 deferral rule
}
internal class LruMap<K, V>(capacity: Int) { /* synchronized, access-ordered; put/get */ }

internal fun reconstruct(presented: List<Cert>, index: CandidateIndex, verifier: SignatureVerifier, probe: Set<String>, crossCallMemo: LruMap<Pair<ByteString, ByteString>, VerifyResult>): Walk {
    val leaf = presented[0]
    val found = mutableListOf<WalkPath>(); val unsupported = mutableSetOf<String>(); val findings = mutableListOf<Finding>()
    var verifications = 0; var explored = 0; var relatedAtLeaf = false; var verifiedAtLeaf = false   // leaf-level flags decide NoIssuerReason; deeper nodes never change it
    var relatedExploredAtLeaf = 0; var unrelatedExploredAtLeaf = 0
    var endDepth = 0                                                                                // set to path.size at the node where a limit is detected, before unwinding
    val memo = HashMap<Pair<ByteString, ByteString>, VerifyResult>()        // (child bytesHash, candidate spkiHash) → result

    fun verifyOnce(child: Cert, cand: Cert): VerifyResult? {               // null = VERIFICATION_BUDGET
        memo[child.bytesHash to cand.spkiHash]?.let { return it }
        crossCallMemo[child.bytesHash to cand.spkiHash]?.let { return it }   // per Revokt, VERIFIED only, CROSS_CALL_MEMO_ENTRIES, synchronized
        if (verifications >= MAX_VERIFICATIONS) return null
        verifications++
        return verifier.verify(child.tbsSigAlg, cand.spki, child.tbs, child.sig).also { memo[child.bytesHash to cand.spkiHash] = it; if (it == VERIFIED) crossCallMemo.put(child.bytesHash to cand.spkiHash, it) }
    }

    /** null when the node completed; a WalkEnd when any limit stopped the walk */
    fun walk(child: Cert, path: List<Cert>, seen: Set<ByteString>): WalkEnd? {
        if (path.size > MAX_DEPTH) return null                                // dead end
        val isLeaf = path.size == 1
        var foundHere = false; var related = 0

        fun explore(cand: Cert, isRelated: Boolean): WalkEnd? {
            if (explored >= MAX_EXPLORED) { endDepth = path.size; return EXPLORATION_BUDGET }
            explored++
            when (verifyOnce(child, cand) ?: run { endDepth = path.size; return VERIFICATION_BUDGET }) {
                INVALID -> return null
                UNSUPPORTED -> { if (isRelated && child.tbsSigOid in probe) unsupported += child.tbsSigOid; return null }   // only the child's own signature OID counts toward ISSUER_UNVERIFIED (decision step 6); a candidate's key or curve OID is server-chosen
                VERIFIED -> { if (isLeaf) verifiedAtLeaf = true }
            }
            val before = found.size
            if (index.isAnchorBytes(cand)) {
                found += WalkPath(path + cand, terminal = ANCHOR)
            } else {
                walk(cand, path + cand, seen + cand.bytesHash)?.let { return it }
                if (found.size == before && index.isPreloadBytes(cand)) found += WalkPath(path + cand, terminal = PRELOAD)   // M2: preload-only path, recorded only when no anchor is reachable through it (invariant); a terminal of last resort
            }
            if (found.size > before) foundHere = true
            return null
        }

        for (cand in index.related(presented, child, seen, belowLeaf = !isLeaf)) {
            if (isLeaf) relatedAtLeaf = true
            if (!isLeaf && foundHere) break
            if (related >= MAX_RELATED_PER_LEVEL) { endDepth = path.size; return RELATED_BUDGET }   // the 65th related candidate is not explored
            related++; if (isLeaf) relatedExploredAtLeaf++
            explore(cand, isRelated = true)?.let { return it }
        }
        for (cand in index.unrelated(presented, child, seen)) { if (foundHere && !(isLeaf && index.customCanonicaliser)) break; if (isLeaf) unrelatedExploredAtLeaf++; explore(cand, isRelated = false)?.let { return it } }   // stops as soon as a path exists, except at the leaf under a custom canonicaliser (deferral rule)
        return null
    }

    val end = walk(leaf, listOf(leaf), setOf(leaf.bytesHash))          // endDepth is recorded where the WalkEnd originated
    val leafKeys = found.map { it.certs[1].spkiHash }.toSet()            // every found path here has ≥ 2 certificates; the [leaf] case is decision step 2
    val stats = WalkStats(verifications, explored, relatedExploredAtLeaf, unrelatedExploredAtLeaf)
    return when {
        end != null        -> Walk.Budget(end, endDepth, found, leafKeys, unsupported, findings, stats)   // some node did not complete
        found.isNotEmpty() -> Walk.Found(found, leafKeys, unsupported, findings, stats)
        else               -> Walk.NotFound(when { !relatedAtLeaf -> NO_CANDIDATE; !verifiedAtLeaf -> ALL_CANDIDATES_INVALID; else -> UNANCHORED }, unsupported, findings, stats)
    }
}
```

- **Explored** means the walker requested the candidate's verification (memo hits included);
  **verifications** counts calls into the injected verifier. `related` counts related candidates
  for which exploration was requested at that node; exactly 64 completes, the 65th aborts.
- **Cost.** An honest leaf → I → root chain: at the leaf, related = I (one verification, recurse);
  at I, related terminal-first = the store anchor (one verification, terminal, stop). Two
  verifications. A presented cross-certificate of the root sorts after the store anchor and is never
  reached once the anchor verifies, and even when reached it is a memo hit (same key); a root-issued
  leaf is one verification; a chain whose snapshot holds the other root of a cross-sign costs
  depth + 1 (three). A verifying decoy costs one extra verification per presented certificate not on
  the path, since the unrelated loop runs at every node without a path. Honest bound: **≤ depth + 1**;
  fixture (v) asserts ≤ 4 against a 200-anchor snapshot. **Worst case is bounded by `MAX_VERIFICATIONS` and `MAX_EXPLORED`, not by the
  per-level cap**: a nested subtree of verifying junk (RSA duplicate-signature keys make junk verify)
  can reach the guard in two levels, about 250 ms of RSA-4096 verification on a mid-range ART device,
  and ends in `Budget`, never an allow. Per-candidate sub-budgets treated as dead ends must not be
  introduced: they would let a stuffed subtree starve the honest key out of a `Found`.
- **Findings** produced during the walk (`AlgorithmIdMismatch` once per presented certificate,
  computed at parse time after NULL/absent normalisation; `VerifierError`) ride on the `Walk`.
  `UnsupportedAlgorithm(oid, PATH, outcomeDepended)` is emitted once per OID in `Walk.unsupportedOids`
  on **every** outcome, with `outcomeDepended = (status == ISSUER_UNVERIFIED)`; fixture (n) asserts the
  `false` case on a `Found`.
- **PKIX fallback contract** (`PathBuilderFallback`; the fallback re-parses the snapshot's anchors with `CertificateFactory` once per `AnchorSnapshot.id`, memoised, and its `CollectionCertStore` holds every presented certificate): result lists the leaf first and **appends the
  trust anchor's certificate**; the leaf must be in the `CollectionCertStore`; one base
  `PKIXBuilderParameters` per snapshot, `clone()` per call; `CertPathBuilder.getInstance("PKIX")` per
  call; `setRevocationEnabled(false)`, `setPolicyQualifiersRejected(false)`, `setDate(now)`,
  `X509CertSelector().apply { certificate = leaf }`; Android resolves to ojluni's `SunCertPathBuilder`
  with Conscrypt doing signatures. The builder verifies every link under the platform's providers,
  so its path satisfies the invariant's intent; `jdk.certpath.disabledAlgorithms` and provider
  divergence from the delegate are reported as `Finding.VerifierError("fallback")` and surface as
  `PLATFORM_ONLY`. It is skipped above `FALLBACK_MAX_PRESENTED` presented certificates (no candidate
  budget; exponential on stuffed chains) with `VerifierError("fallback skipped")`, which cannot change
  a `Budget` outcome.
- **Caches**, per trust manager, LRU-bounded (a synchronized access-ordered `LinkedHashMap` or a
  striped LRU; touched from concurrent handshake threads): the path cache holds `Found`, `NotFound`,
  `Budget` and the fallback result alike. **A path-cache entry is exactly**: `status`, `source`,
  `noIssuerReason`, `walkerReason`, `parseReason`, `keyabilityClause`, `terminalKind`, `endReason`, `endDepth`,
  `usedFallback`, `pathsFound`, the reported path as (source, index) pairs for walker entries or, for
  `PLATFORM` entries, the leaf-issuer SPKI hash, the anchor hash and the path length (a
  Conscrypt-completed chain can contain certificates from neither source), `reportedPathSha256s`,
  `issuerSpkiSha256s`, `candidatesDropped`, `anchorSha256`, the walk's `WalkStats` and `unsupportedOids`
  (the overload that produced it is **not** recorded; the 3-arg retry decision lives in the separate acceptance memo, flow step 1),
  plus the leaf's DER, `serial` and `scts` (never the other presented certificates, which would let a
  server park `PATH_CACHE_ENTRIES × MAX_PRESENTED_BYTES` in the cache); on a hit the `Finding.Path` is
  the stored one with `cacheHit = true` and `anchorSnapshotId` from the key, step 7 runs without
  re-parsing, and an exemption's `PresentedChain` is rebuilt from the live `chain` argument of that
  call; `PLATFORM` results are keyed with the host; nothing is cached when `decide` threw. The
  verdict cache key includes `generationEpoch` (internal; a `Long` incremented on any install and whenever a dataset leaves `pending` without a generation at the end of the start task, so a verdict cached as a pending-allow is never served once `NO_DATA` should fire), `policyEpoch` and `shadowPolicyEpoch` (the §4 setters) and
  the anchor snapshot id. Events are emitted only on verdict-cache misses. On a walker reason of
  `NO_CANDIDATE` or `UNANCHORED` (read before any `PLATFORM_ONLY` promotion) a rate-limited
  `refreshAnchors()` is scheduled (`ANCHOR_REFRESH_MIN_INTERVAL`; never while a rebuild is in
  flight); the triggering verdict stands; the next call re-walks under the new snapshot id. `canonicalSubject`
  is total (a `X500Principal` constructor failure yields null and raw-only matching) and is cached on
  each `Cert`, presented and store, so the relation test never allocates twice per pair.

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
loader (which takes this lock) and `fetcherTrustManager`'s lazy build, and none falls between (the JVM join of the loader task runs after the lock is released). The `ReferenceQueue` is registered on the **trust-manager** reference
(the trust manager holds its delegate strongly, so the delegate reference can never clear first).
Loader and refresh tasks hold a `WeakReference` to the trust manager, `get()` it each tick and reach
the delegate through it. `sslContext(delegate, keyManagers)` is memoised by bucket on identity hashes
but matched by `delegate === e.delegate && km.size == e.km.size && km.indices.all { km[i] === e.km[i] }`;
`null` and empty arrays are distinct keys; **contexts are held through `WeakReference`** (an
`SSLContext` strongly holds its trust managers, so a strong memo would pin every instance; the
client's own context keeps it alive); the `ReferenceQueue` is drained on every factory call and on
every loader and refresh tick (on those ticks under a `tryLock` that skips when contended, so the
loader never blocks on the factory lock); all contexts are dropped on `close()`.

**Anchor snapshot, built where upki builds its state.** The snapshot (`getAcceptedIssuers()` plus
the `CandidateIndex` build over `platformTrust.anchors(delegate)`, i.e. `getAcceptedIssuers()`, ~10 ms for 140 anchors) exists before any handshake can go past step 1
on the trust manager, **on both platforms and regardless of the calling thread**: built synchronously
inside `start()` for every trust manager created in `CREATED` (`fetcherTrustManager` only when a
fetching source is configured, below; the first synchronous step, under the factory lock, before
the registry and the store lock) and at wiring, inside the factory lock,
for a trust manager created in `STARTED`. A throw from `getAcceptedIssuers()`, an empty anchor set
or a build failure throws `IllegalStateException` from `start()` (lifecycle stays `CREATED`, nothing
held, retryable) or from `trustManager(d)` (nothing registered); `fetcherTrustManager` excepted, whose
failure is the `FETCHER_TRUST_UNAVAILABLE` warning (below). There is therefore no snapshot
future, no snapshot deadline and no `SNAPSHOT_UNAVAILABLE` verdict reason: a trust manager that can go
past **flow** step 1 has a snapshot (flow step 1 is the platform call; the snapshot id keys the
caches at flow step 2, where the snapshot is read, and decision step 1 consumes it; instances obtained in
`CREATED` before `start()` or in `CLOSED` run flow step 1 only and report null snapshot fields; the one
trust manager that may lack a snapshot in `STARTED`, `fetcherTrustManager`, never goes past flow step 1
without it and counts `unevaluated[FETCHER_SNAPSHOT_UNAVAILABLE]` instead). **Android**: the NSC
`NetworkSecurityTrustManager.getAcceptedIssuers()` is lazy and cached per default config (one per
process) over process-wide directory sources (`DirectoryCertificateSource` lists the system and
user cacerts directories and reads one file per certificate on the first call per process; every
later call clones the cached array; the system clears these caches in every running process by its
own `handleTrustStorageUpdate()` push when the trust store changes, with no app receiver involved,
and revokt registers none), so `start()`, already off the main thread, warms it by building the
pre-start snapshots (`fetcherTrustManager`, over `fetcherDelegate`, is among them whenever a
fetching source is configured). `trustManager(d)` on Android runs the delegate's
`getAcceptedIssuers()` under `StrictMode.allowThreadDiskReads` **whatever the delegate and the
thread** (the previous policy is restored in a `finally`; the index build runs outside the guard);
the guard hides the StrictMode report, not the read: with the default delegate the call reads disk
only after a trust-store change, a Conscrypt `TrustManagerImpl` over `AndroidCAStore` re-enumerates
the cacerts directories on every call, a consumer-written delegate is arbitrary. A consumer that
wants no main-thread work at all creates its trust managers before `start()`. **Rebuild**:
`refreshAnchors()` (public on `RevoktTrustManager` for delegates that reload their store; also scheduled by the walker-reason trigger above, which is how a newly installed
user CA is picked up: its first chain walks `UNANCHORED`) rebuilds on the loader and publishes the
new reference whole; a failed rebuild keeps the current snapshot, is logged at `WARN` through
`RevoktLogger`, counts `TrustManagerStatus.anchorRefreshFailures` and sets
`lastAnchorRefreshFailedAtMillis`, and is never surfaced as a verdict. After `close()` see the lifecycle paragraph: every instance runs step 1
only; refresh is disabled. `fetcherTrustManager` is created at `build()` over `fetcherDelegate`
(default `platformTrust.defaultDelegate()`), as is **one internal instance per configured fetching
source**, handed only to that source's `HttpFetcher.Factory.create(FetcherTls)` as `tls.trustManager`
(typed `X509TrustManager`; a factory that leaks it into another client is outside the contract, and the
in-flight guard of §8 bounds the damage); all of them share one anchor snapshot over `fetcherDelegate`
(one `CandidateIndex`, one id: `refreshAnchors()` on the public instance and the walker-reason trigger
from any internal instance rebuild the one shared reference, and `anchorRefreshFailures` /
`lastAnchorRefreshFailedAtMillis` are reported on the public instance's `status()`) and the fixed fetcher
policy (§8); the internal instances never count toward `maxTrustManagers` and never appear in
`RevoktStatus.trustManagerCount`; the public `fetcherTrustManager` is the consumer-facing instance that
never has a fetch in flight. The shared
snapshot is attempted inside `start()` when a
fetching source (`remoteSettings`, `c2spMirror`) is configured; a failure there is the
`FETCHER_TRUST_UNAVAILABLE` warning, never a `start()` throw (an app that starts revokt in
`Application.onCreate` must not crash-loop where without revokt it would merely fail TLS): each sync
first retries the build on the loader and, while it fails, is `FAILED` **without a fetch** (stage `FETCHER_TRUST`; counting
toward `consecutiveFailures`, `signedSourceFailing` and the failure backoff as any `FAILED`; no
handshake runs on `fetcherTrustManager`, so `unevaluated` does not advance there; the signed source is
never fetched over an unchecked chain). `unevaluated[FETCHER_SNAPSHOT_UNAVAILABLE]` counts only
handshakes a consumer delivers to `fetcherTrustManager` directly while it has no snapshot (the lazy
path below). With no fetching source no `HttpFetcher` and no `FetcherTls` are created, `sync()` never
touches it, and its snapshot is built under the factory lock on the first `checkServerTrusted` it
receives in `STARTED`, after flow step 1; a failed build there is logged at `WARN`, the call returns on the
platform verdict (flow step 1 only, as in `CREATED`), the failure is not memoised and the next call
retries, so goal 3 holds without exception; reading the property or `status()` builds nothing
(`status()` reports null snapshot fields until then). It does not count toward
`maxTrustManagers` (nor do the per-source instances), wraps `fetcherDelegate` (default `platformTrust.defaultDelegate()`), uses the fixed
fetcher policy (§8), never waits, and runs step 2 from M1 against `SIGNED`/`BUNDLED` generations only.

**Listeners** are dispatched off the handshake thread. `Accepted` events go through a ring of
`EVENT_RING_CAPACITY` (drop-oldest, `droppedEvents`); a `Rejected` event evicts the oldest `Accepted`
one, and when the ring holds only `Rejected` events it overflows into a side queue of
`REJECTED_QUEUE_CAPACITY` with its own counter `droppedRejectedEvents`. Events carry monotonic
sequence numbers. **Drain**: the ring is sequence-indexed; each registered listener holds its own
cursor (set to the current tail by `addListener`, so a listener sees only events enqueued after
registration; `removeListener` clears it and a running drain stops at its next event) and its own `drainScheduled` flag; each delivery runs under try/catch (a throwing `onVerdict` counts `listenerFailures` and the drain continues, so a cursor never stalls; a throwing `executor.execute` removes the listener instead, flow 3b); an event whose verdict carries `Finding.Exempted` is enqueued with `Rejected` priority (it evicts `Accepted` events and overflows to the side queue), so exempted evidence never vanishes from the audit stream under load; on enqueue the handshake thread CASes each listener's flag
and submits one drain task to that listener's executor; the task delivers every event with
`sequence > cursor` still in the ring or side queue in order, advances the cursor and clears the
flag, then re-checks `tail > cursor` and, if so, re-CASes and loops (no lost wake-up). The task copies
the pending slice under the ring lock and delivers outside it. Events are enqueued, and drops counted,
only while at least one listener is registered; side-queue entries are released once every cursor has
passed them. Delivery latency is one executor hop. `droppedEvents`/`droppedRejectedEvents` count
evictions from the ring (global); a slow listener misses evicted events and its gap is visible as a
sequence jump.

`checkClientTrusted` and `getAcceptedIssuers` delegate to the platform unchanged.

### 5.2 Android (`AndroidPlatformTrust`)
- Default delegate: the NSC `RootTrustManager`. `requiresExtendedDelegate()` is false. `pathBuilder`
  is the platform PKIX `CertPathBuilder`. `PlatformTrust.canonicalSubject` defaults to `X500Principal.getName(CANONICAL)`.
- Verified chain: `X509TrustManagerExtensions(delegate).checkServerTrusted(chain, authType, host')`
  at decision step 4; its last element is the anchor. **Known gap, confirmed in Conscrypt:**
  `checkCT` runs only when `host != null && isCTVerificationRequired(host)`, with TLS SCT data
  `null` in the hostname-only variant; under Android 16 CT enforcement a chain that passed step 1 via
  TLS-extension SCTs can throw here and the flow continues with `reconstruct`.
- **Named M1 residual.** On the plain-delegate binding (`X509TrustManagerExtensions` cannot wrap
  it, so step 4 is unavailable), and on any path where the null-host extension call is unavailable,
  the walker cannot complete a chain whose intermediate is omitted (Conscrypt's intermediate index
  accepts such chains, and a revoked leaf without embedded SCTs that delivers SCTs in the TLS
  extension reaches the CT gap on demand) or whose presented intermediate is signed by a retired
  root while Conscrypt completes through a cached cross-certificate; those yield
  `NO_ISSUER(PLATFORM_ONLY)` until M2's preload. Decision step 4's null-host retry closes the CT-gap
  and host-null cases only for an app whose NSC has no `<domain-config>` (`RootTrustManager`
  rejects a null hostname otherwise, Appendix A); any app with a `<domain-config>` ends the CT-gap
  path in `reconstruct` against the default config's anchors (`RootTrustManager.getAcceptedIssuers()`
  returns those only), and a host whose `<domain-config>` declares its own `<trust-anchors>` then
  yields `NO_ISSUER(PLATFORM_ONLY)`; the 0.3 emulator probe runs with and without a `<domain-config>`.
- `RevoktTrustManager` is a public, final, non-anonymous class in `revokt-jsse` with public
  `checkServerTrusted(X509Certificate[], String, String): List<X509Certificate>` and
  `isSameTrustConfiguration(String, String)` declared on it for every platform (`X509TrustManagerExtensions`
  duck-types them; on the JVM the former returns the presented chain); consumer R8 rules keep both; `authType` is not validated.
  AOSP main also carries a 5-arg `checkServerTrusted(chain, ocspData, tlsSctData, authType, host)` on
  `RootTrustManager` and `X509TrustManagerExtensions` (public API level unverified), which would close the
  CT gap if the TLS SCT bytes were available, which app code cannot read from a platform Conscrypt session;
  the 0.3 matrix probes for it.
- `RootTrustManager`'s 2-arg `checkServerTrusted` throws with any `<domain-config>` (§5.4 CIO caveat).
- The 3-arg overload on a plain delegate returns the presented chain after step 1; otherwise the extension call with host', or on a memo hit its null-host retry, is both its return value and its step-4 result (flow step 1).
- Lifecycle observer in its own class, guarded on `androidx.lifecycle.ProcessLifecycleOwner`, installed by `RevoktWork.install` when the dependency resolves, or directly by `RevoktAndroid.observeLifecycle(provider)` for consumers without WorkManager: it calls `sync()` on the process's `onStart` (a `CREATED` instance is started first under the worker's rule, §3, a `start()` throw logged at `WARN` and the sync skipped; queues behind the start task and honours `backoffUntilMillis`, §5.1, so overlap with the worker is harmless); consumer rules carry `-dontwarn androidx.lifecycle.**` and the keep rules verbatim, and keep `AndroidPlatformTrust` (revokt-jsse auto-detects it by name).

### 5.3 JVM (`JvmPlatformTrust`)
- Default delegate: SunJSSE's `X509ExtendedTrustManager`. `requiresExtendedDelegate()` is **true**
  for every JVM binding (SunJSSE's `AbstractTrustManagerWrapper.checkAdditionalTrust` applies algorithm constraints on both the socket and the engine path and endpoint identification on the engine path; fronting a plain delegate removes them).
- `pathBuilder` is `CertPathBuilder("PKIX")`; `PlatformTrust.canonicalSubject` defaults to `X500Principal.getName(CANONICAL)`,
  which is what SunJSSE's `X500Name.equals` compares. Every M1 chain is `RECONSTRUCTED`.

### 5.4 Ktor engine caveats (verified against Ktor 3.6.0 source)
- **CIO**: a JVM artifact that also runs on Android, TLS 1.2 only, 2-arg `checkServerTrusted`, never runs CT; **refused on Android by revokt** (`RootTrustManager`'s 2-arg overload throws with any `<domain-config>`).
- **OkHttp**, **Java**, **Android** engines pass the socket or host; every adapter takes an optional
  explicit delegate and replaces a previously configured factory or context.

### 5.5 Engine evaluation (shared)
All byte inputs come from one minimal DER parse of each certificate's `Cert.tbs` (the TBS re-encoded by the §9.2 unsigned-header rule):
`rawSerial`, `rawSpki` (complete TLV), `rawSubject`, `rawIssuer`, AKI/SKI, TBS `signature`,
`notBefore`/`notAfter` (M4's distrust-after needs them; parsed from 0.1 so the corpus covers them), the SCT list, extension byte offsets, and `producerKeyable` (§9.2 D8); the outer `signatureAlgorithm` and `signatureValue` come from the envelope under §9.2's unsigned-header rule. Structurally strict except where §9.2
follows the JDK's TBS read, semantically lenient, at least as lenient as the platforms (§9.2 differential parser oracle). The
leaf is parsed once at decision step 3; `PARSE_FAILED` applies to the leaf only; unparseable
candidates are dropped. SCTs: only `(log_id, timestamp)` is used. **One catch boundary**: steps 2–3
and `Evaluator.evaluate` (which throws `IllegalStateException` outside `STARTED`, §4, before any boundary) catch `Throwable` (every `VirtualMachineError` except `StackOverflowError` is rethrown; a `LinkageError` from a bad R8 config or a `StackOverflowError` is not a policy reject) into `ENGINE_ERROR`; the boundary closes at flow step 3, before event emission; **fired rules accumulate**: a throw after step 7 answered adds `ENGINE_ERROR` to the rules fired so far (`REVOKED` included) rather than replacing them, so a late failure is allow-safe by construction; `Verdict.path.status = NOT_WALKED` when
the exception preceded the walk; the data rules and `dataStates`, computed before the boundary, are
on the verdict regardless. `ENGINE_ERROR` has exactly three producers (`EngineErrorProducer`): the
catch boundary, an engine result (`CrliteQueryResult.ENGINE_ERROR`, or `NO_DATA` while a generation
is published; with `engineName`), and an exemption that throws;
each attaches `Finding.EngineError`.

Layers by milestone: **[M2] L1/L2** over every path the walker (or an exhaustive re-walk) returned;
**[M1] L3 CRLite** (leaf only, per distinct issuer key); **[M3] L4 CT**; **[M4] L5 distrust**.

## 6. CRLite engine [M1]

### 6.1 Inputs
`issuerSpkiHash` = SHA-256 of a path-verified issuer's `rawSpki` (the complete SPKI TLV, as Mozilla's
producer takes `RawSubjectPublicKeyInfo`); `serial` = `rawSerial` (INTEGER content bytes as encoded,
as the producer takes `asn1.RawValue.Bytes` from the TBS, Appendix A); SCTs = the union, over every
extension with OID `1.3.6.1.4.1.11129.2.4.2`, of the items its list keeps under §9.2; `key` = `SHA-256(issuerSpkiHash ‖ serial)`; one covered SCT suffices.

### 6.2 Query (exact port; W = 4)
```
a[i] = littleEndianU64(key[8i .. 8i+8]) for i in 0..3;  a[0] |= 1
query(m) = Equation(s = (a[3].toULong() % max(1, m).toULong()).toLong(), a)
eval(eq, z: LongArray): limb = s/64; sh = s%64; r = 0
  for i in limb until min(z.size − 1, limb + 4):            // z.size includes the pad word
     t = z[i] ushr sh; if (sh != 0) t = t or (z[i+1] shl (64 - sh))   // columns padded with one zero word
     r = r xor (t and a[i - limb])
  return r.countOneBits() and 1
query(q): if q.scts.isEmpty(): return NO_SCTS   // revokt's parser passes an empty list when no SCT extension's list parses under §9.2 (§3.2, §6.1; decision §10 item 7); never reaches a filter
perFilter(filter, key, scts):
  if no (log, ts) in scts is within filter.coverage: return NotCovering
  meta = filter.index[issuerSpkiHash] ?: return NotEnrolled
  member = if (meta.approxM == 0) false else
              (0 until meta.rank).all { eval(query(meta.approxM).shift(meta.approxOffset), approx[it]) == 0 } &&
              eval(query(meta.exactM).shift(meta.exactOffset), exact) == 0 &&
              meta.exceptions.none { it contentEquals serial }
  return if (member xor meta.inverted) Revoked else Good
aggregate over filters that are not NotCovering (C2SP step 3):
  none covering → NOT_COVERED; any Revoked → REVOKED; else any Good → NOT_REVOKED; else NOT_ENROLLED
```
The `sh != 0` guard is load-bearing. `approx` is `Array<LongArray>`. Exact port of `clubcard` 0.3.4 and `clubcard-crlite` 0.6.2: `shift(o)` adds `o` to `s`; coverage is `low ≤ ts ≤ high`, unsigned; every delta file is a filter with its own coverage and index and enters the aggregate.

### 6.3 Filter decoding
Detect the encoding from the 2-byte prefix `[version, reserved0 = 0]`:
- **v4 (C2SP, big-endian):** `CRLiteCoverage` (`u16` n × {`[32]` logId, `u64` low, `u64` high}),
  `ClubcardIndex` (`u32` n × {`[32]` issuerSpkiHash, `u32` approx_m, `u8` rank, `u32` approx_offset,
  `u32` exact_m, `u32` exact_offset, `u8` inverted, `u16` n × {`u8` len, serial}}),
  approx filter (`u8` columns × {`u32` words, BE `u64`…}), exact filter (one column). Reject trailing bytes (as `clubcard-crlite`'s `Clubcard::read` does).
- **v3 (bincode 1.x, little-endian fixint, `u64` lengths):** coverage map (`u64` n × {`[32]`,
  `u64` low, `u64` high}), `()` (0 bytes), index map (`u64` n × {`u64` len + key bytes,
  `u64` approx_m, `u64` exact_m, `u64` rank, `u64` approx_offset, `u64` exact_offset, `u8` inverted,
  `u64` n × {`u64` len + bytes}}), approx (`u64` n × {`u64` len + LE `u64`…}), exact (`u64` len + LE `u64`…).
- **Decode strictness, stated per rule** (decode-only; a violation is `SyncOutcome.FAILED`, never a verdict): v3 trailing bytes are accepted (bincode 1.x legacy `deserialize` allows them), v4 trailing bytes rejected; a row window past the end of a column reads as zero (C2SP lets a builder omit trailing all-zero words; `Equation::eval` bounds the same way), so `offset + 256 > 64·words` is **not** rejected; `rank > columns` is rejected at `prepare()` (unchecked by `clubcard-crlite`, where it panics → upki `ENGINE_ERROR`); `inverted ∉ {0, 1}` is rejected (C2SP MUST; `clubcard-crlite` reads `!= 0`); the sorted-index and distinct-log-id MUSTs are checked. The resulting decode-only asymmetries against upki are recorded in the cross-engine suite as `FAILED`-vs-loaded, never as verdict classes.
- **Observed 2026-10-21:** Mozilla serves v3 on both channels; `upki.rustls.dev` serves a v4 transcode.
- **Validated 2026-10-21:** prototype matched `clubcard-crlite 0.6.2` on 43,510 / 43,510 queries.
- **Coverage sanity at install, trust-class-aware**: `SIGNED`: coverage `high` later than the signed
  record's `last_modified` + `clockSkew` is rejected (`SyncOutcome.FAILED`, stage `INDEX`; cursor and watermark unchanged); **inside the rollback window** (changeset
  `timestamp ≤ watermark`) a maximum coverage below the active `SIGNED` generation's is
  `ROLLBACK_REFUSED`; a changeset with `timestamp > watermark` installs and advances the watermark
  whatever its coverage (signed, server-timestamped and newer than anything seen; a Mozilla rebuild
  from an earlier snapshot must not freeze clients), **but a changeset whose signed `last_modified` exceeds
  local now + `clockSkew` is `SyncOutcome.CLOCK_SKEW`** (stage `CHANGESET`): not installed, watermark, cursor and
  `lastVerified*` unchanged (the bound the x5u validity check already imposes on the local clock;
  otherwise one far-future signed changeset, from a leaked signing leaf or a server bug, would make
  every real changeset `ROLLBACK_REFUSED` until `resetState()`) **except when the dataset has no
  generation at all (no stored, no seed) or its live generation is itself `clockBehind`**, where a
  changeset newer than the live generation installs with `DataState.clockBehind = true` and the
  `CLOCK_BEHIND` warning, advancing `lastVerifiedAtMillis` (so `signedSourceFailing` stays false) but
  neither watermark nor cursor (the bootstrap and clock-behind cases: a fleet behind a wrong clock must
  neither sit at `NO_DATA` nor freeze on its seed while server time keeps moving away from it; the
  watermark stays unpinned, so the first sane changeset once the clock is right advances it, and the
  cursor stays, so the next poll re-fetches from the last verified cursor (a 200 with a full `_since` body
  every poll while the clock is behind, the accepted cost) and finds the same changeset
  **`UNCHANGED`-by-timestamp**: a verified changeset whose signed `<ts>` equals the live generation's
  `sourceTimestampMillis` is `UNCHANGED`, updating the attempt fields only, and that test precedes the
  `CLOCK_SKEW` test; "the live generation is `clockBehind`" is recomputed at the sync decision as
  `sourceTimestampMillis > now + clockSkew`, never read from the last publish, so a clock corrected
  between publishes closes the carve-out at once). The timestamp compared everywhere here (watermark, coverage
  bound, `CLOCK_SKEW`) is the signed `<ts>` of the verified payload, never the unsigned envelope
  `timestamp`. `MIRROR`/`SYSTEM`: later than local now +
  `clockSkew` is rejected; installs only under the §7.3 bootstrap rule and never reads or writes the watermark. A `SIGNED` generation always
  evicts a `MIRROR` or `SYSTEM` one.

**Hardening**: every length and offset checked before allocation with an explicit allocation budget
per decoder; filenames validated against `^(?!\.{1,2}$)[A-Za-z0-9._-]{1,64}$` (today's attachment names are 31 characters; a three-digit daily index must not fail the rule) and never a reserved name (`meta.json`, `records.json`, `current`, `updater.json`, `store.version`, `.lock`); downloads capped at `min(attachment.size, MAX_FILTER_BYTES)` for signed bodies and at the per-kind fixed cap for unsigned bodies (§5.1 limits).

### 6.4 Filter storage
`LongArray` columns padded with one zero word in an immutable `Generation`. No mmap.

| Channel | Full | Resident with ~8 deltas | Load, JIT-compiled | Load, interpreted |
|---|---|---|---|---|
| `compat` | 1.57 MB | ~2.5 MB | ~5–10 ms | ~50–100 ms plus seed verification |
| `default` | 6.0 MB | ~7.8 MB | ~15–30 ms | ~150–300 ms plus seed verification |

Baseline Profile covering the decoder, seed verification, the TBS parser, the walker and `evaluate`,
with `androidx.profileinstaller` as `api`. `AWAIT_DATA_<CHANNEL>` from a physical ARM device at API
26 without a profile, including the `start()` anchor build, with a ceiling; on the JVM both constants
are a fixed 2 s.

### 6.5 Store, persistence and seeds

**Layout over `RevoktStorage`'s key space** (each generation is materialisable into a C2SP directory
image; `index.bin` names files by their Remote Settings attachment filename and `meta.json` maps each
name to its blob). Path segments for dataset and channel are lowercase enum names; persisted enum
values are names, never ordinals:
- `store.version`: integer, `1` in 0.3, read before anything else; an empty store is initialised
  silently by the owner (never by a read-only instance); a non-empty store with a missing or **lower** version is treated as empty and rebuilt
  (`STORE_MIGRATED` warning, a planned migration, not a corruption alert, `storeFailures` unchanged; the rebuild writes `store.version` first, then deletes every other key `names()` lists, then runs the start task as on an empty store, so an older co-tenant cannot mistake a half-written new layout for its own empty store and no old-layout `current` or `updater.json` survives), never an error and never `NO_DATA` beyond what an
  empty store already implies; a **higher** version is `STORE_NEWER_LAYOUT` and follows the storage's `NewerLayout` (§3): `IN_MEMORY` (the `JvmStorage` default: a newer co-tenant's store is left untouched, the store lock taken by `start()` is released, the identity deregistered, and the instance runs on the in-memory fallback, `RevoktState.storageFallback`, which for this code is never retried) or `REBUILD` (the `AndroidStorage` default: one package owns its directory and Android kills every process of the package on replace, so a higher version there is a rollback of the binary and is rebuilt exactly as a lower one).
- `<dataset>/<channel>/current`: a small pointer file `{live, previous}` naming generation
  directories; `previous` is only ever a complete generation of the same or higher trust class as
  `live`, so recovery never falls to a lower class than the one being replaced.
- `<dataset>/<channel>/gen-<timestamp>-<hash16>/` (`timestamp` = `sourceTimestampMillis` zero-padded to
  13 digits so lexical order is chronological; `hash16` = the first 16 lowercase hex characters of
  `SHA-256(generationId)`; `generationId` itself may contain `/`): immutable; `index.bin`, delta files, `records.json` for `SIGNED`, and `meta.json` **written last as
  the completeness marker** (engine's own JSON tree): `metaVersion`, `dataset`, `channel`,
  `trustClass`, `generationId`, `format`, `freshness`, `sourceTimestampMillis`, `collection`, a map from
  each full-filter name to `blobs/<sha256>`, and for `SIGNED` the changeset timestamp, signer leaf
  SHA-256 and signature bytes. A
  `MIRROR` generation reloads as `MIRROR`, never as `SIGNED`; a `channel` mismatch is no generation.
  A `SIGNED` generation directory also holds `records.json`, the full verified record set (the same bytes as the seed's `records.json`: the canonical-JSON signed payload), so a
  `_since` changeset can be verified against it (tombstones merged) without a full re-fetch.
- `<dataset>/<channel>/blobs/<sha256>` (64 lowercase hex): content-addressed full-filter files referenced from
  `meta.json`; when the key exists the stored blob is re-hashed and reused on a match (a mismatch rewrites it, `storeFailures++`; on the delta path, where the full is not being fetched, the full attachment is fetched again in the same sync, subject to the metered rule), so a daily delta install never rewrites the 6 MB full and a bit-rotted blob is never decoded; prune removes unreferenced
  blobs. The upki CI adapter materialises a C2SP directory image from a generation (it already
  copies into a fresh directory, §3.2).
- `<dataset>/<channel>/updater.json`: **the rollback watermark is per dataset and channel, stored once outside the per-source map** together with `seedInstalledAtMillis` (written with the watermark when the seed install flips the pointer) and a dataset-level `datasetLastAttemptAtMillis` (written at the end of every sync whatever its outcome, `STORE_LOCKED` excepted; the §8 `STALE` gate; the loader evaluates the gate when it writes this file and carries the boolean in the published `DataState`, internal field, so handshakes read the snapshot only, never the store) (a changeset installs only if its timestamp passes the dataset watermark, whichever source delivered it, so a relabelled `sourceId` on a private mirror cannot start a fresh watermark and roll back; the coverage-monotonic bound is the live `SIGNED` generation's maximum coverage, read from the published generation, never from this file); the per-source map is keyed by a **stable source id** (not the URL, so overriding a
  base URL keeps the cursor): `lastVerifiedLastModified` (the `_since` cursor),
  `lastVerifiedAtMillis`, `lastAttemptAtMillis`, `backoffUntilMillis` (clamped to now + `MAX_BACKOFF` on write and again on read, so a clock that was far ahead at write time cannot leave a years-long backoff),
  `consecutiveFailures`, `feedHostBlock: {sinceMillis, chainSha256s}` (the §8 signed-source hold, **per source, not per chain**: `sinceMillis` is set on the first `BLOCKED_BY_SELF` of any host of the source and cleared only by a hit-free sync that completes after `sinceMillis + FEED_HOST_HOLD`, never earlier and never by an install alone, so an episode lasts at least the hold and expires exactly once (an alternating hit/clean chain cannot reset it); `chainSha256s` is the set of hit chains, for reporting; the hold is measured from the persisted value, so restarts do not extend it; with `RevoktStorage.inMemory()` it restarts per process); written atomically. **The cursor, `lastVerified*`
  and the watermark advance only after the pointer flip of a successful install** (one carve-out: the §6.3 clock-behind install advances `lastVerifiedAtMillis` only); a failure-path
  write (`consecutiveFailures`, `backoffUntilMillis`) leaves those three untouched; `UNCHANGED`
  against the pointed generation rewrites the file (repairing a crash between flip and write). The
  delta parent is derived from the pointed generation's `meta.json` at `start()`, never from this
  file.
- **Prune keeps exactly the directories the pointer names** (`live`, `previous`) and deletes every
  other directory, complete or not, and every unreferenced blob; on a failed `prepare()`, self-check or `activate()` the loader deletes
  the directory it was given before returning (blobs stay, content-addressed); an interrupted install
  (process death; no `meta.json`) is deleted by prune at the next `start()`; a sync-time `prepare()`/`activate()`
  throw and a self-check mismatch increment `storeFailures` and are `SyncOutcome.FAILED` (stage `PREPARE`, `ACTIVATE` or `SELF_CHECK`; cursor and watermark do not advance, so the same changeset is retried under backoff); a store write or pointer-flip failure during an install is `SyncOutcome.STORE_FAILED` (stage `STORE`, `storeFailures++`); "newest" is pointer order, never directory timestamp.
**Order of an install** (an *install* anywhere in this document means this whole sequence): fetch, verify and write **one body at a time** (hash against the signed
record or the manifest, write the blob unless the key exists, drop the body) → write the generation
directory (`meta.json` last) → the §3.2 `index.bin` consistency check for a generation the loader did not build (`INDEX_INCONSISTENT`, stage `INDEX`) → `prepared = engine.prepare(files)` (validates and decodes into an inactive
state; the live generation is untouched) → **engine self-check on `prepared.query`** (deterministic,
never probabilistic, every input named: the absent issuer hash is `SHA-256("revokt-self-check")`,
incremented in its last byte until absent from every filter's index; the inside SCT is (`logId`, `low`)
of the first coverage entry of the filter under test in `index.bin` order; the outside probe is
(`logId`, `high + 1` unsigned, or `low − 1` when `high` is the maximum); filters are iterated in
`index.bin` order and index entries by ascending issuer hash, so "some block" is reproducible. The absent
issuer hash with the inside SCT must answer in the `NOT_ENROLLED` class (`{NOT_COVERED, NOT_ENROLLED,
NO_SCTS}`, the §3.2 equivalence class, so the upki engine passes); the outside SCT must answer
`NOT_COVERED` or its class; and the `REVOKED` probe uses a serial the loader's own `revokt-clubcard`
reference evaluator (§6.2) calls `Revoked`, chosen deterministically and first-match (one branch is
exercised per generation, the first that yields): the first of the serials
`0x01`..`0x1000` (minimal DER INTEGER content, ascending) that is `Revoked` against some inverted
block (`approxM == 0`: every serial; `approxM > 0`: a non-member), else an exception-list serial of an
inverted block (exceptions make `member` false, so `false xor inverted` is `Revoked`), else the first
such candidate that is a member of a non-inverted block, with the inside SCT of that filter; when no
block yields one or no coverage entry exists the probe is skipped and logged at `INFO`; circular for the Kotlin
engine but it still catches a constant-answer engine, which is its purpose, while the §9 oracle covers
shared decoder bugs; the same check runs on every `prepare`, the seed's and the `start()` recovery
chain's included, where a failure is the corresponding load failure, `SEED_UNREADABLE` for the seed)
→ on a mismatch `prepared.close()`, `storeFailures++`, `SyncOutcome.FAILED` with `ENGINE_SELF_CHECK_FAILED` (stage `SELF_CHECK`), the directory
deleted, the engine and the published snapshot untouched (no window, nothing to re-install)
→ `engine.activate(prepared)` → publish the generation snapshot with that id (`generationEpoch++`; the window between `activate` and publish, i.e. between
install and publish is stated: a verdict in it carries the new answer under the old epoch for at most
the verdict-cache TTL) → flip the pointer → write `updater.json`. Decision step 7 never queries an
engine for a dataset whose snapshot has no generation; `CrliteQueryResult.NO_DATA` from an engine
while the snapshot holds a generation for that dataset is reported as `ENGINE_ERROR(ENGINE)`, never
as nothing, so an injected engine's install failure is visible, not silent (in `DEFAULT` it allows, loudly). **Every loader task catches `Throwable`**: an `OutOfMemoryError` during an install is `SyncOutcome.FAILED` for that sync, `storeFailures++`; nothing escapes the loader thread. **Crash recovery at
`start()`**: `live` → `previous` → seed (per the §5.1 rule) → system cache → nothing, each failure
counted. **The store is trusted
at the OS level**: a stored `SIGNED` generation is not re-verified at load (the seed is, since it
ships inside the APK); `JvmStorage` enforces ownership and owner-only write permission on POSIX. Temp
names carry pid and random bytes and are excluded from `names()`; only the owning loader writes, under
the lock `start()` holds; readers re-read the pointer once on a missing key. Install-time memory peak
≤ 3× resident + one body; decoded immutable filters are shared across generations by
`GenerationFiles.sha256(name)`; decoding uses bulk
`ByteBuffer.asLongBuffer().get(LongArray)`. Allocation budgets per decoder: filter ≤ len + 1 MiB +
entries × 128 B; JSON ≤ 4·len; DER ≤ 2·len; asserted in the §9.1 replay by
`com.sun.management.ThreadMXBean.getThreadAllocatedBytes` deltas (HotSpot).

**Seed archive** (`revokt-seed-<channel>`, weekly; **shipped by default**: `SeedSource.bundled()`, the builder default, resolves `/revokt/seed-<channel>.zip` from that artifact on the classpath, and the OkHttp and Android quickstarts declare the dependency; decision, revision 23): a zip with `seed.json` {`seedFormat`, `channel`,
`dataset`, `filterFormat`, `recordsLastModified`, `engineFloor`}, `records.json` (byte-for-byte the canonical-JSON signed payload `{"data": records sorted by id, tombstones removed, "last_modified": "<ts>"}`, so the seed verifier hashes the file unchanged; the `<ts>` inside it, verified, is the seed's timestamp for every rule below, the unsigned `seed.json.recordsLastModified` being a hint for the header read only), `signature` (the `signature` field as served: the 128-character base64url text encoding 96 raw r‖s bytes), `x5u.pem` (the x5u body as served, leaf first), `attachments/<name>`, `index.bin` (produced by one engine function `buildIndex(records, channel)` with entries ordered by `(effectiveTimestamp, record id)`, full before deltas; its output bytes are frozen per `seedFormat`, a change bumps `seedFormat`, which is what makes the load-time byte compare valid across minors; the weekly job calls that function from the oldest supported minor). **Entry caps, enforced while inflating** (zip-declared sizes are untrusted; `fromResource`/`fromPath`/`of` accept any file, and the sole-seed `ENFORCE` path inflates inside `start()`, where an `OutOfMemoryError` would crash-loop an app): `records.json` ≤ `MAX_JSON_BYTES`, `x5u.pem` ≤ `MAX_X5U_BYTES`, each attachment ≤ `min(signed size, MAX_FILTER_BYTES)`, `index.bin` ≤ 1 MiB, `seed.json` ≤ 64 KiB; over any cap → `SEED_UNREADABLE` (§10 supply chain). Engine rules: `seedFormat` or
`engineFloor` above what this engine supports, or `filterFormat ∉ revocationEngine.formats`, → `SEED_UNREADABLE` warning and the seed is ignored (so in the sole-seed `ENFORCE` configuration `start()` throws, §4 S bullet); **a seed whose signed timestamp exceeds local now + `clockSkew` is installed** (decision, revision 29: the timestamp is Mozilla-signed and its x5u checks run at that signed time, so "future" can only mean the local clock is behind, which the spec calls routine; refusing it put the default preset at `NO_DATA` on every device whose clock was a day behind) with `DataState.clockBehind = true`, `ageMillis` clamped at 0, the sticky-while-true `CLOCK_BEHIND` warning, and the watermark at the signed timestamp as for any seed (rollback comparisons are server time against server time and never involve the local clock);
`channel` ≠ configured channel → `SEED_CHANNEL_MISMATCH` `ERROR` thrown by `start()`; the shipped
`index.bin` is **rebuilt from `records.json` and byte-compared** at load (the signature binds records
and attachment hashes, not parentage), a mismatch → `SEED_UNREADABLE`; the weekly job publishes
every `seedFormat` the oldest supported minor lists, in the filter format Mozilla signs.
`DataState.fromSeed`, `ageMillis`, `stale` and `seedFormat` are loud. **Seed artifacts declare no code dependency**: the floor lives in `seed.json` (`engineFloor`, enforced at load as above). A POM dependency would let a seed bump drag `revokt-engine` above the BOM-pinned bindings (Gradle resolves the highest version; BOM constraints are not strict) and the `@RevoktInternalApi` plumbing between artifacts carries no compatibility promise; instead every code artifact's Gradle module metadata depends on `revokt-bom` as an aligning platform, so a single-artifact bump aligns the set.

## 7. Data sources

| Class | Sources | Integrity | Authenticity |
|---|---|---|---|
| `SIGNED` | Mozilla Remote Settings (CRLite [M1]; intermediates, OneCRL [M2]; ct-logs [M3]; root-store distrust-after dates and CCADB export [M4]); Chrome CRLSet [M2]; seeds [M1] | signed record hash / CRX proof | Mozilla content-signature roots / Google CRX key |
| `MIRROR` | C2SP manifest mirrors [M1] | `manifest.json` SHA-256 per file | TLS to the mirror only |
| `SYSTEM` | read-only C2SP cache directory [M1] | none | OS package management |
| `BUNDLED` | denylist artifact [M2] | reproducible from signed public inputs, attested | project-attested, availability-only |

### 7.1 Mozilla Remote Settings protocol and verification [M1]
All constants live in `MozillaRemoteSettings` (per source, overridable), including the pinned root
SPKI hash set and the three `metadata.signature` fields read (`signature`, `x5u`, `mode`). `MozillaRemoteSettings.Builder` exposes `baseUrl`, `attachmentBaseUrl` and `x5uHosts` (§4): **a private mirror that serves the changeset, attachment and x5u bytes unchanged (a byte-for-byte reverse proxy of the three Mozilla hosts) with the builder's `baseUrl`, `attachmentBaseUrl` and `x5uHostRewrite("content-signature-2.cdn.mozilla.net", mirrorHost)` pointing at it (`attachment.location` is relative, so `attachmentBaseUrl` suffices; the rewrite is applied to the parsed x5u URI host before the `x5uHosts` check, so no JSON is rewritten on the wire; x5u is outside the signed payload; the https-only, port-443 and no-userinfo rules apply to the mirror host too), verifies and installs as `SIGNED` under the default `sourceId`, so the `_since` cursor carries over (the watermark is per dataset and channel and carries over whatever the `sourceId`, §6.5); this is the supported offline-fleet path** (`c2spMirror` is bootstrap-only and never updates a seeded client, §7.3). Base `https://firefox.settings.services.mozilla.com/v1` (the Kinto API, Firefox's own `services.settings.server`; `/v2`, a distinct newer server that was hours old at verification, serves the same changeset shape and is the documented alternative value of `MozillaRemoteSettings.baseUrl`; both verified 2026-10-22, Appendix A);
only `monitor/changes` and per-collection `changeset`; `_expected` mandatory; `User-Agent`; gzip;
honour `Backoff` and `Retry-After` up to `MAX_BACKOFF` (24 h; transport headers are unsigned): a non-2xx with such a header waits the header, one without it waits the computed failure backoff, capped at the poll interval; poll at most every 6 h with jitter. **Verify** every collection
state (`"Content-Signature:\0"` + canonical JSON of `{"data": records sorted by id (deleted removed),
"last_modified": "<ts>"}`; merge `_since` tombstones first; reset-and-retry once; canonical JSON per `canonical_json` 0.7.0 number and escape rules, pinned by the §9 differential test; the `signature` field is base64url of raw r‖s, converted to DER for `SHA384withECDSA`). **The signed
payload does not bind the collection id**, and every security-state collection shares a signer, so
before any state change every record is schema-validated for the requested collection (CRLite:
`channel`, `incremental`, `attachment.{hash,size,location}`, `effectiveTimestamp`, `parent`; M2
schemas likewise); a verified changeset whose records fail validation is `SyncOutcome.FAILED` with
`SYNC_SCHEMA_REJECTED` (stage `SCHEMA`), counts as a feed failure, and advances nothing. Redirects are never followed. **JSON**: the
engine's own tree and tokenizer; duplicate keys and unpaired surrogates rejected; keys sorted by code
point. **Content signature**: `mode` is read and must equal `p384ecdsa` (else `FAILED`, stage `SIGNATURE`); the algorithm is never derived from it; the attachment
base URL pinned in `MozillaRemoteSettings`, never taken from the server root response. **x5u chain**:
HTTPS from the allowlist (today `content-signature-2.cdn.mozilla.net`; the parsed URI host after rejecting userinfo, a non-https scheme and a port other than 443; `_expected` is validated as an integer before it enters a query string), `MAX_X5U_BYTES` (64 KiB) cap; **algorithm floor** for every link below the terminal: SHA-256 or stronger, RSA ≥ 2048, P-256 or stronger, anything else `FAILED` (the JCA verifier is called directly, so `jdk.certpath.disabledAlgorithms` does not apply); validity at verification time for the leaf
and every non-terminal link; for every non-leaf link below the terminal: basicConstraints `cA = TRUE`,
`pathLenConstraint` honoured, subject name equal to the child's issuer (raw or canonical), keyUsage
`keyCertSign` when present;
links verified with the signed TBS algorithm; root SPKI hash in the pinned set (today
`CN=root-ca-production-amo`, certificate SHA-256 `C8A80E9A…A106DB`; the set is additive while any seed
references a root); **the terminal is a trust anchor**: the first certificate on the path whose SPKI is
pinned, anything after it ignored; only its SPKI is checked, never its validity, CA bits, key usage
or subject (mozilla::pkix semantics; the wrapper around a pinned key is attacker-choosable, so a
check on it stops nothing, while root expiry would freeze every deployed client and seed); leaf EKU
codeSigning; leaf SAN exactly `onecrl.content-signature.mozilla.org`. Any non-terminal certificate
on the path outside its window at a live fetch is `SyncOutcome.CLOCK_SKEW` (stage `X5U`). **Rollback guard**: high-water mark on
the signed `last_modified` (`<ts>` of the verified payload, never the unsigned envelope `timestamp`), persisted in `updater.json`; older by less than `rollbackWindow`
(default = `clockSkew`, 24 h; collection timestamps are server-assigned and monotone) may still
install subject to the §6.3 coverage-monotonic rule, which applies only inside the window;
`ROLLBACK_REFUSED` is not a feed failure, never advances `consecutiveFailures`, and never updates
`lastVerified*`; `ROLLBACK_REFUSED` on every poll for longer than `signedSourceFailingAfter` does set
`signedSourceFailing`, so a stuck watermark is visible.

### 7.2 Mozilla CRLite, channels, seeds and data artifacts [M1]
Channel is top-level (`DEFAULT`: all reasons, 6.0 MB / ~220 KB, Firefox desktop and the public
mirrors; `COMPAT`: keyCompromise, cessationOfOperation, privilegeWithdrawn, 1.57 MB / ~120 KB,
Firefox for Android, no public mirror). Recommended: `DEFAULT` for backends, `COMPAT` for Android apps (APK and metered cost, §12). Delta chain depth is about four days; Phase-0 task: observe
two full-filter cuts for re-parenting. When the stored full is no longer the delta parent, a full
download is deferred while `meteredNetwork` (§4; sampled once per sync; Android: `ConnectivityManager.isActiveNetworkMetered()`) reports true, until `staleAfter`, then proceeds; a deferred full is `SyncOutcome.DEFERRED` with the `METERED_DEFERRED` warning; missing data always
downloads. **Seeds** verified like a live fetch except x5u validity at the seed's signed
`last_modified`; a seed-backed generation is never `NO_DATA`; a future-dated seed installs with `clockBehind` (§6.5); `DataState.fromSeed`, `ageMillis` and
`stale` are loud. **Data artifacts**: date-versioned, weekly, attested, not in the BOM, no
build-time plugin. **Freshness per dataset** (`Freshness`, reported on `DataState`): CRLite ages from the filter
record's `last_modified`; OneCRL and intermediates (M2) age from the last **verified poll**, since
their content changes only when a CA is listed; CRLSet from its sequence time; the denylist from the
artifact date; seeds from their signed timestamp.

### 7.3 C2SP manifest mirrors and system cache [M1]
Protocol as `upki fetch`. **Bootstrap only.** A `MIRROR` or `SYSTEM` generation installs **only when
the dataset has no generation of a higher trust class at all** (no seed, no stored `SIGNED`
generation), its trust class is not below the dataset's `minTrustClass` while
`outcome(UNSIGNED_DATA) == REJECT`, and its coverage passes §6.3; it is evicted by the first
`SIGNED` generation, seed included, and pruned at once. A stale `SIGNED` generation is never
displaced by a lower class: stale-but-signed is the accepted state under the no-ceiling decision,
and a TLS-only mirror must never be able to hide revocations the signed data already holds or turn
into a kill switch. `DataState.trustClass` is the carrier. **Within one sync, sources are attempted
in descending `TrustClass.rank`; a lower-class source is fetched only after every higher-class
source failed in this sync and the bootstrap condition holds** (so a healthy signed install never
downloads the mirror; `MIRROR` precedes `SYSTEM`, which is attempted, not fetched: the cache is re-read). The `c2spCache` is read at `start()` after the
seed, in the recovery order of §6.5. `signedSourceFailing` (3 consecutive failures or more than
`signedSourceFailingAfter` since the last verified changeset, both persisted) is reported in
`RevoktState` and drives nothing else. A configured `c2spCache` counts as local data for the
`NO_DATA` validation rule only when the policy can install it (§4). Residual, recorded in §10: a fresh install without a seed, on-path,
with a mirror certificate the platform trusts can be bootstrapped with attacker data until Mozilla
is reachable; `NO_DATA_REJECTS_WITHOUT_LOCAL_DATA` pushes consumers to ship a seed.

### 7.4 Mozilla intermediate preloading [M2]
Second candidate set by Mozilla's bytes (candidates the walk continues from; a terminal only of last resort when no anchor is reachable through it, `terminalKind = PRELOAD`, §5.1 invariant); splits `NOT_ENROLLED` (with no `INTERMEDIATES` generation the split does not happen and `NOT_ENROLLED` fires; the upki engine never produces it, class collapse); closes the
§5.2 residual; `Dataset.INTERMEDIATES` with `LAST_VERIFIED_POLL` freshness.

### 7.5 OneCRL, bundled denylist and Chrome CRLSet [M2]
OneCRL applied as Firefox does (all records enforced). Denylist project-attested, availability-only.
CRLSet opt-in with CRX3 verification and `crl-set` parsing per Chromium.

## 8. Policy

`RevoktPolicy` is a map from `Rule` to `Outcome`, per-rule exemptions, `requiredDatasets`, a
per-dataset staleness map and three time fields. Presets: `DEFAULT`, `STRICT`. **`Enforcement.OBSERVE`
runs the configured policy, emits events, and never throws.**

| `Rule` | Class | `DEFAULT` | `STRICT` | Firefox / Chrome / upki | Produced by |
|---|---|---|---|---|---|
| `REVOKED` | evidence | reject | reject | reject | CRLite, any evaluated key |
| `PATH_BUDGET_EXCEEDED` | unevaluable | **reject** | reject | n/a; one of goal 3's two stated exceptions | decision steps 3, 5, 6 |
| `NO_DATA` | unevaluable | **reject** (exemptable) | reject (exemptable) | upki `missing_data = Error` | decision step 7, per required dataset |
| `ENGINE_ERROR` | unevaluable | allow | reject | upki hard-errors; its caller decides | boundary, engine result, exemption throw |
| `PARSE_FAILED` | unevaluable | allow | reject | n/a; goal 3 | decision step 3 |
| `ISSUER_UNVERIFIED` | unevaluable | allow | reject (exemptable; **empty path**) | n/a | decision step 6 |
| `NO_ISSUER` | unevaluable | allow | reject (exemptable; **empty path**: `anchorIn` never matches; reason on `Finding.Path`, including `PLATFORM_ONLY`) | n/a; goal 3 | decision step 6 |
| `NOT_ENROLLED` | non-answer | allow | reject (exemptable) | collapsed into not covered | CRLite |
| `NO_SCTS` | non-answer | allow | reject (exemptable) | allow | CRLite |
| `NOT_COVERED` | non-answer | allow | allow | Firefox → OCSP; upki allow | CRLite (the coverage gap: a certificate issued after the live filter's coverage `high` is unchecked by every preset; §10) |
| `STALE` | data quality | never fires (`rejectStaleAfter` null; loud via `DataState.stale` and `RevoktStatus.stale`) | reject at 30 d, after a sync attempt has completed since the seed was installed (persisted gate, bullet below; exemptable) | upki keeps old data; Chrome drops an expired CRLSet; Firefox → OCSP | `DataState`, per dataset |
| `UNSIGNED_DATA` | data quality | never fires (floor `BUNDLED`) | reject (floor `SIGNED`; M2: `DENYLIST` floor `BUNDLED`; exemptable) | n/a; goal 2 | `DataState`, per dataset: `trustClass` below `minTrustClass` |
| [M2] `DENYLIST`, `ONECRL`, `CRLSET` | evidence (`ONECRL` exemptable per anchor through `ExemptionContext.path.anchorSha256`, the enterprise-CA case; `CRLSET`, `DENYLIST` not exemptable) | reject | reject | reject | L1/L2 (the 0.4 → 1.0 transition; not subject to the one-minor rule) |
| [M2] `ISSUER_UNKNOWN_TO_MOZILLA` | non-answer | allow | reject (exemptable) | n/a | preload |
| [M3] `CT` | evidence | allow | reject (ships `ALLOW` for one minor in `STRICT`) | browsers reject | L4: CT policy verified and not met |
| [M3] `CT_UNVERIFIED` | non-answer | allow | reject (exemptable; ships `ALLOW` for one minor) | n/a | L4: log list missing, SCTs unverifiable, or the only SCTs delivered outside the certificate (TLS extension, OCSP), which an `X509TrustManager` cannot observe; this is why `CT` ships `ALLOW` in `DEFAULT`. M3 adds `EvaluationRequest.Builder.tlsScts(...)`, a full-SCT type separate from `CrliteSct`, and the path cache keeps the raw extension bytes |
| [M4] `DISTRUST` | evidence | reject (ships `ALLOW` for one minor in both presets) | reject (same; exemptable per anchor) | reject | L5 |

- **Data rules are per dataset.** `NO_DATA` fires for a dataset in `requiredDatasets` with no
  generation and `DataState.pending == false` (the start task has passed the seed and system-cache steps; `pending` is false at the end of the start task whether or not a fetching source is configured, with `generationEpoch++` when it clears without a generation, so a seed-only configuration can never sit in `pending`); presets' `requiredDatasets` is `{CRLITE}`. `STALE` fires for a dataset present in the staleness map
  (presets: `CRLITE` only) iff `rejectStaleAfter != null && ageMillis > rejectStaleAfter`;
  `DataState.stale` (the loud flag) is `ageMillis > staleAfter` and never fires a rule.
  `UNSIGNED_DATA` fires for a dataset iff `DataState.trustClass` is below `minTrustClass(dataset)`
  (`DEFAULT`: `BUNDLED` for every dataset; `STRICT`: `SIGNED`, M2 `DENYLIST` `BUNDLED`). `ageMillis = now − sourceTimestampMillis` per the dataset's
  `Freshness`. Preset defaults: `CRLITE` `staleAfter` 3 d, `rejectStaleAfter` null in `DEFAULT`, 30 d
  in `STRICT`. **Stated plainly:** `DEFAULT` with stale data is "reject what the stale filter says is
  revoked, allow the rest", with `STALE` never firing; `DEFAULT.newBuilder().rule(STALE, REJECT)`
  alone changes nothing until a `rejectStaleAfter` is set. **`STALE` does not fire for a dataset whose
  generation is `fromSeed` until a sync attempt has completed since the seed was installed** (the persisted
  `updater.json.datasetLastAttemptAtMillis ≥ updater.json.seedInstalledAtMillis`, both per dataset (§6.5), never the in-process `lastSync`; the loader carries the boolean in the published `DataState`;
  a read-only instance (§5.1) makes no attempt and writes nothing, so its in-memory seed stays gated until it
  promotes itself to writer and the owner start task's first sync completes, `STORE_LOCKED` results not being attempts; a backoffed
  first sync completes at once as `BACKOFF`, §5.1, and `FETCH_TIMEOUT` bounds "completed", so an on-path
  attacker answering `503 + Retry-After` cannot keep the gate shut across restarts),
  or at once when no fetching source is configured (there is no fetch to race; `sync()`'s seed re-check is still an attempt; `SEED_PAST_REJECT_THRESHOLD` is still emitted), because installs happen months after a build and the first
  handshakes race the first sync; after that attempt `STRICT` with no reachable signed source and a seed older
  than 30 days rejects everything until a sync succeeds, by design.
- **Time fields, exactly three** on the policy plus the per-dataset map, all stored as millis with
  `java.time.Duration` accessors: `rollbackWindow` (24 h), `clockSkew` (24 h; also every coverage
  future bound), `signedSourceFailingAfter` (24 h). `wouldRejects` advances only under `OBSERVE` and
  `rejects` only under `ENFORCE`, so the two columns compare cleanly after a flip.
- **`ENGINE_ERROR` allows in `DEFAULT`** and rejects in `STRICT`.
- **Exemptions** register per exemptable rule and run after policy mapping for fired `REJECT` rules only. **Enterprise-CA recipe under `STRICT`**: exempt `NO_SCTS`, `NOT_ENROLLED` **and the data rules** (`NO_DATA`, `STALE`, `UNSIGNED_DATA`) with the same `anchorIn(privateCa)` (`RevoktPolicy.Builder.exemptAnchors(sha256s)` does exactly that, §4), and `NO_ISSUER`/`ISSUER_UNVERIFIED` with `hostSuffixIn(corpDomains) and platformOnly()` (they fire only on an empty reported path, where `anchorIn` never matches; `platformOnly()` alone would exempt every chain the §5.2 intermediate-omission residual produces on Android, for every host, turning `STRICT` into `DEFAULT` for a revoked public leaf presented without its intermediate), so a feed outage never takes down traffic CRLite cannot evaluate anyway ( on the JVM the supported private-CA delegate is a `TrustManagerFactory` over a merged `KeyStore`, never a hand-written `X509ExtendedTrustManager` composite, which passes `requiresExtendedDelegate()` but drops SunJSSE's constraints; call `refreshAnchors()` on rotation).
- **`outcomeDepended`** (M1): "no path was found and at least one `UNSUPPORTED` link was encountered
  among related candidates"; `Budget` yields `outcomeDepended = false`.
- **Fetcher policy**, fixed, **ignores `Enforcement`** (under `OBSERVE` or `OFF` a hit chain on a TLS-only mirror would otherwise be accepted and the signed-source hold could never be set), applies only to the fetcher trust managers, **per source authenticity class, attributed structurally**: each configured source has its own internal trust-manager instance (§5.1 "Anchor snapshot"), created at `build()` and handed to that source's `HttpFetcher` through `FetcherTls`, so a handshake on it is that source's by construction, whatever the peer host and whichever fetcher dropped the host (Ktor CIO needs no exception); **and, as a second condition, an internal instance writes `feedHostBlock`, `updateBlockedBySelf` and `blockedSource` only while a fetch of its source is in flight on it** (the engine knows when it called `fetch`; a handshake outside that window, from a factory that leaked the instance or from a timed-out fetch handshaking late, is rejected on a hit but records nothing); the public `fetcherTrustManager` is a distinct instance over the same snapshot that is always "no fetch in flight": a handshake on it (a consumer that wired the property into another client) is evaluated under this policy but **never writes `feedHostBlock`, `updateBlockedBySelf` or `blockedSource` and never receives the `feedHostRevoked` allowance** (a rejected hit there is just a reject), so unrelated traffic can neither start a hold on the signed source nor inherit its post-hold acceptance; no global pointer exists:
  evidence rules (`REVOKED`; M2: `DENYLIST`, `ONECRL`, `CRLSET`; M4: `DISTRUST`) are evaluated against
  `SIGNED`/`BUNDLED` generations only, so attacker-fed mirror data can never block the signed source;
  every other rule `ALLOW`; no data rules; no exemptions; from M1. For a **TLS-only source**
  (`c2spMirror`) an evidence hit on the host's chain is `REJECT` for as long as its current chain is hit: `SyncOutcome.BLOCKED_BY_SELF` with
  `SyncResult.blockedSource`, `blockedChainSha256` and `blockedLeafSerial` (the name says which rule,
  not the cause: an on-path attacker with a mis-issued-then-revoked certificate produces the same
  signal; compare `blockedChainSha256` with the host's current chain), and `RevoktState.updateBlockedBySelf`.
  For the **end-to-end-signed source** (`remoteSettings` changesets, attachments and x5u, whose payload
  is authenticated by the content signature regardless of transport) the hit is honoured for at most
  `FEED_HOST_HOLD` (24 h, fixed; §5.1 limits) **per source**, measured from the first hit of any of its hosts and persisted in `updater.json` (`feedHostBlock`, cleared only by a hit-free sync that completes after `sinceMillis + FEED_HOST_HOLD`, never by an install alone, so restarts, a CDN alternating or holding two certificates, three hosts in one source, or a record that stays listed for a year cannot extend it: the hold expires once per episode), reported the same way and counting toward `signedSourceFailing`;
  after that the fetch **proceeds** with `RevoktState.feedHostRevoked = true` and the `FEED_HOST_REVOKED`
  warning, so a single signed record naming the feed host (a leaked signing leaf, a producer false
  positive, a seed cut in that window) can never stop the next signed record from arriving: a MITM on
  that path can only serve real signed data, old signed data (rollback guard) or nothing, which a
  packet-dropping attacker already can.
- **Established connections**: a rejection applies to new handshakes; pooled connections already established are not torn down (the README says so); an HTTP/2 connection coalesced onto another host inherits that host's verdict (§5.1).
- **What `OBSERVE` yields**: `wouldRejects` over `evaluations` by rule from `status()`; by host, policy epoch,
  anchor, issuer key and generation from events. **What `shadowPolicy` yields while `ENFORCE` stays on**: `shadowWouldRejects` by rule and `RevoktEvent.shadowVerdict` per event, so `STRICT` (or a rule in its grace minor set to `REJECT` in the shadow) is measured for weeks without lifting `REVOKED`, `NO_DATA` or `PATH_BUDGET_EXCEEDED` enforcement; the migration procedure is: shadow `STRICT`, drive `shadowWouldRejects` to the exemptions above, then set `policy = STRICT`.

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
  path); the 10⁶-key comparison as a second tier; `index.bin` byte comparison;
  canonical JSON against `canonical_json`.
- **Cross-engine suite** (0.2): chain corpus × generations against both `RevocationEngine`s under
  the §3.2 equivalence classes; the `CrliteQuery` is extracted once by revokt's parser and handed to
  both engines, so no input is abstained; any `REVOKED`/`NOT_REVOKED` disagreement and any class
  disagreement fails the job.
- **Content-signature fixtures** with mutations; incremental fixtures; a seed with an expired signer
  leaf must load; a seed 25 h ahead of local now loads with `clockBehind = true`, `ageMillis = 0`, `CLOCK_BEHIND` on `RevoktState.warnings`, the watermark at its signed timestamp; a changeset 2 h ahead of that seed then installs with `clockBehind = true`, `lastVerifiedAtMillis` advanced, watermark and cursor unchanged, and the next poll of the same changeset is `UNCHANGED`; after the local clock is advanced 30 h the next changeset installs normally, `clockBehind = false`, `CLOCK_BEHIND` gone, the watermark advanced; a restart with the clock still behind republishes `clockBehind = true` from the stored generation; a signed changeset with `last_modified` 25 h ahead of local now against a live generation that is not `clockBehind` → `CLOCK_SKEW`, watermark unchanged, the next poll installs once the timestamp is within `clockSkew`; the same against a dataset with no generation → installs with `clockBehind`, watermark and cursor unchanged; a `mode` other than `p384ecdsa` rejected (stage `SIGNATURE`); a seed with a 70 MiB declared attachment → `SEED_UNREADABLE` before inflation; a mirror generation whose `index.bin` names a log window absent from the filter's coverage → `FAILED`, `INDEX_INCONSISTENT`; signature
  over records with a tombstone merged vs not merged.
- **Data-path fixtures** ((a), (b), (d) and (g) less its `BLOCKED_BY_SELF` and `MIRROR` items are 0.2 gates; those items and (c), (e), (f), (h) need the store, mirror or lifecycle machine and are 0.3 gates): (a) changeset older than the watermark beyond the window →
  `ROLLBACK_REFUSED`, within the window but lower max coverage → `ROLLBACK_REFUSED`, within the window
  with equal coverage → installs; **newer timestamp with lower coverage → installs and advances the
  watermark**; a refused rollback leaves `consecutiveFailures` and `lastVerified*` unchanged;
  `Backoff: 100000000` → next poll ≤ 24 h and `backoffUntilMillis ≤ now + 24 h`; (b)
  `SIGNED` coverage `high` beyond `last_modified + clockSkew` → `FAILED`, stage `INDEX`; `MIRROR` coverage beyond
  now + `clockSkew` → `FAILED`; (c) mirror precedence: healthy signed source → mirror never installed;
  signed source failing for 48 h with a stored `SIGNED` generation → mirror still not installed,
  `signedSourceFailing = true`; no generation at all → mirror installs as `MIRROR`; next `SIGNED` →
  evicted; an attacker-style mirror with an inverted index against a stored `SIGNED` generation →
  not installed; (d) x5u mutations: wrong leaf SAN, missing codeSigning EKU, root not pinned, non-CA
  certificate as intermediate, name-chaining break, `pathLenConstraint` violation, keyUsage without
  `keyCertSign`, an x5u URL on a non-allowlisted host, an x5u over 64 KiB, expired intermediate or
  leaf at live fetch → `CLOCK_SKEW`, expired leaf in seed → loads; a pinned SPKI as a non-terminal
  link → loads with the path truncated there; the pinned terminal expired, or wrapped in a
  self-signed certificate with another subject → loads; (e) store: power loss simulated after the pointer flip with a zero-length filter → start
  falls to `previous`, `storeFailures = 1`; a crash before `meta.json` leaves an incomplete directory
  that prune deletes; a non-empty store with a lower `store.version` → rebuilt from seed, `STORE_MIGRATED`, `storeFailures = 0`; with a higher `store.version` under `JvmStorage` → no file written, the lock released, `storageFallback = true` with `STORE_NEWER_LAYOUT`, and the worker-style `sync()` still installs in memory; under `AndroidStorage` → rebuilt from seed with `STORE_NEWER_LAYOUT`; an instance on the ownership fallback whose directory is chowned during the session → migrates within one `READONLY_POLL_INTERVAL`, `storageFallback = false`, the in-memory generation on disk; an empty
  directory → `storeFailures = 0`; a `MIRROR` `meta.json` reloads as `MIRROR`; a `meta.json` with the
  other channel → no generation; two instances on one directory in one process → the second throws;
  a second JVM process on a held lock → read-only start within 1 s, `sync()` → `STORE_LOCKED`, the
  directory listing is byte-identical before and after its start even with a newer seed configured
  (served in memory, `fromSeed = true`), it observes the first process's install within
  `READONLY_POLL_INTERVAL`, and after the owner closes it acquires the lock within one interval and
  its next `sync()` installs; `close()` then a new instance on the same directory in the same process
  starts as owner; a directory owned by another uid or group-writable on POSIX → `STORE_UNREADABLE`
  and no file written for the session; two consecutive syncs whose `engine.prepare()` throws → `live`
  and `previous` still load, `storeFailures = 2` (sync-time `prepare()` throws count), both syncs `FAILED` with stage `PREPARE`, the two failed directories deleted; stored
  generation equal to the seed → no verification, `names()` unchanged; a manifest with 33 entries or a 17 MiB declared filter → rejected before any
  body fetch; (f) seed: `seedFormat` above supported → ignored with a warning; channel mismatch →
  `start()` throws on both platforms; stored `MIRROR` with coverage newer than the seed → seed
  installed, `trustClass = SIGNED`, the `MIRROR` directory pruned; stored `SIGNED` newer than the seed
  → seed skipped; corrupt `live` with an evicted `MIRROR` still on disk → recovery goes to seed, never
  to the `MIRROR`; a mutated shipped `index.bin` → `SEED_UNREADABLE`; (g) fetcher: the feed host's own
  chain revoked in the stored `SIGNED` generation → `BLOCKED_BY_SELF` within the 24 h hold, `blockedSource`, `blockedChainSha256` and `blockedLeafSerial` set,
  `updateBlockedBySelf = true`, no mirror install while the signed generation exists (after the hold see below); a bootstrap-state
  `MIRROR` generation whose index marks the feed host revoked → sync proceeds, no `BLOCKED_BY_SELF`;
  a signed `intermediates` changeset served on the `cert-revocations` URL → `FAILED`,
  `SYNC_SCHEMA_REJECTED`, cursor, watermark and `lastVerified*` unchanged; a 3xx → `FAILED`; a gzip
  body inflating past its cap → `FAILED` before the cap is exceeded; a signed attachment whose size
  exceeds `MAX_FILTER_BYTES` → `FAILED` with `CAP_NEAR_LIMIT`, nothing advanced, not fetched; a signed revocation of the Remote Settings host → `BLOCKED_BY_SELF`; the same hit chain delivered to the public `fetcherTrustManager` by a consumer client → rejected, `feedHostBlock` not written, `updateBlockedBySelf` unchanged, while the same chain on the source's internal instance during its fetch → `BLOCKED_BY_SELF`; two sources with a factory that returns one client built over the first source's `tls` for both → the second source's hit chain, handshaking outside any fetch of the first source, writes nothing; a sync 23 h after the first block (across a process restart) is still `BLOCKED_BY_SELF`; one at 25 h installs with `feedHostRevoked = true` and `FEED_HOST_REVOKED` on `RevoktState.warnings`; the same on a `c2spMirror` host → `BLOCKED_BY_SELF` while its chain is hit (fetcher-trust-manager unit fixture: in M1 a mirror is fetched only with no `SIGNED` generation and evidence comes from `SIGNED`/`BUNDLED` data, so the end-to-end case is M2's denylist); a test engine whose `formats` is `{V4}` with the v3 seed and no fetching source → `start()` throws `SEED_UNREADABLE` in the sole-seed `ENFORCE` configuration (V `FORMAT_UNSUPPORTED` cannot fire first, there is no fetching source); a fetch answered 401 or 407 → `FAILED` with `httpStatus` set, on the JDK, Android and OkHttp fetchers; the JDK and Android fetchers against a server whose certificate lacks the host's SAN → `FAILED` (endpoint identification);
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
- **Verifier**: OID harvest; key-OID gaps; PSS parameters; raw-to-DER edge cases; an off-curve point
  on a supported OID → `INVALID`; a throwing provider → `INVALID` plus `VerifierError`; PQ chain matrix.
- **Parser corpus** and the §9.2 differential parser oracle; **Android instrumented** (API 26, 31,
  34, 36) including the null-host extension-call probe and the §9.2 corpus replay against the
  platform `CertificateFactory` (a 0.3 gate; pinned system-image revisions, Conscrypt APEX version logged); **live checks**; **benchmarks** on a physical ARM device including
  verifications per honest handshake.
- **Walker fixtures**, schema `id | presented (ordered) | snapshot | preload | verifier.unsupported |
  expected Walk (asserted only in the walker-only harness, revokt-engine's test set; every other path asserts the Finding.Path columns, and revokt-testing's recorded fixtures carry the Walk column as a string) | expected PathStatus / NoIssuerReason / WalkEnd | expected Path fields | verdict
  relation to the honest chain`, on every platform path (JVM walker, JVM walker with the fallback
  disabled in the walker-only harness, Android CT-gap path, Android plain delegate, `Revokt.evaluate`):
  (a) random-key fake issuer; (b) ECDSA-recovered second key; (c) RSA duplicate-signature key;
  (d) recovered-key fake with an unsupported own signature, terminating at a real anchor; (e) 8, 16
  and 63 distinct-key related junk ahead of the real one → `Found`, verdict equals honest; (f)
  cross-signed chain with both roots in the snapshot → first path in M1, both on exhaustive re-walk;
  (g) chain omitting the intermediate → walker-harness `NO_ISSUER(NO_CANDIDATE)`; on trust-manager bindings `PLATFORM_ONLY` with `walkerReason = NO_CANDIDATE`; on Android with a warm intermediate index and a host, `Found(PLATFORM)` via step 4; (h) self-signed non-anchor and an
  A↔B loop; (i) 65 related junk at the leaf → `Budget(RELATED_BUDGET)`, `candidatesExplored = 64`,
  fallback skipped (chain too long), `PATH_BUDGET_EXCEEDED`; (j) ML-DSA anchor on a JDK without ML-DSA →
  `ISSUER_UNVERIFIED`; (j2) brainpool anchor on SunEC (walker harness) → `NO_ISSUER(ALL_CANDIDATES_INVALID)`, no `UnsupportedAlgorithm` (the curve OID is the candidate's); (k) same-key decoy with a garbage
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
  PATH_BUDGET_EXCEEDED}`, and `REVOKED ⇔ honestKey ∈ issuerSpkiSha256s`; **(t)** (o) plus 80 junk → same expectation as (s2); **(i), (s2), (t) and (y) present more than `MAX_PRESENTED` certificates and are walker-harness only; on every trust-manager path and `Revokt.evaluate` they are cut at step 3: `Budget(EXPLORATION_BUDGET)`, `endDepth = 0`, `PATH_BUDGET_EXCEEDED`, no CRLite query, as (ag) asserts**;
  (u) `getAcceptedIssuers()` throws during `refreshAnchors()` → the current snapshot is kept, `anchorSnapshotId` unchanged, the walk proceeds under it (the wiring and `start()` throw cases are lifecycle fixtures, (h));
  (v) honest chain against a 200-anchor snapshot → `verifications ≤ 4`, `COMPLETE`; (v2) the same
  with a retired-root cross-certificate presented → `≤ 4`; (w) dense cross-certified mesh (6 roots,
  12 cross-certs) → `Found`, reported path `leaf → I → anchor`; (x) self-signed anchor as server
  certificate → `Found([leaf])`, key = the leaf's own; **(y)** honest chain leaf → I1 → I2 → root with the root in the snapshot and 65 presented
  certificates whose subject equals I2's name and whose keys do **not** verify I1 (one `INVALID` exploration each), placed before I2 →
  `Budget(RELATED_BUDGET)` at `endDepth = 2` (sub-leaf cap propagates), fallback skipped,
  `PATH_BUDGET_EXCEEDED`; **(y3)** (M2) leaf whose issuer I has one certificate under OneCRL-listed anchor A and another under a retired root present only in the preload → paths `leaf → I_A → A` (ANCHOR, hit) and `leaf → I_B` (PRELOAD); `ONECRL` fires (the PRELOAD path is not a clean alternative); **(y2)** the same chain with the junk carrying the root's name and the
  root in the snapshot → `Found`, `verifications = 3` (leaf/I1, I1/I2, I2/root; the junk is never explored because the store root sorts first at I2, which pins terminal-first ordering); **(z)** `NotFound` where only
  an unrelated presented certificate has an unsupported key OID → `NO_ISSUER(UNANCHORED)`, no
  `UnsupportedAlgorithm`; (aa) root-issued leaf with the root also presented → `pathsFound = 1`;
  (ab) `PARSE_FAILED` leaf with no CRLite generation → `rules = {PARSE_FAILED, NO_DATA}`, `rule = NO_DATA`;
  (ac) **walker-harness only, custom canonicaliser** (on both default delegates every honest issuer
  is related, since `X500Principal`'s canonical form hex-encodes TeletexString and both platforms
  chain by it): issuer unrelated by encoding with AKI in issuer-and-serial form and four unrelated
  junk ahead → `Found` through the unrelated loop, `REVOKED`; (ad) **walker-harness only**: leaf,
  honest issuer unrelated by encoding, six same-name mutually cross-signing junk certificates ahead →
  `Budget(EXPLORATION_BUDGET)`, `candidatesExplored = 1024`, `usedFallback = true`,
  `PATH_BUDGET_EXCEEDED`, `rule = REVOKED`, honest key last in `issuerSpkiSha256s`; (ae) platform
  accepts, walker `UNANCHORED` and fallback fails → `NO_ISSUER(PLATFORM_ONLY)`,
  `walkerReason = UNANCHORED`; (af) 9 presented certificates with a link the walker cannot reproduce
  (custom delegate) → fallback skipped, `PATH_BUDGET_EXCEEDED`; (ag) 70 presented certificates →
  `Budget(EXPLORATION_BUDGET)` without a walk; (ah) `VERIFICATION_BUDGET`: 12 presented certificates
  of distinct RSA duplicate-signature keys each verifying the leaf and recursing into a
  32-certificate dead-end subtree → `Budget(VERIFICATION_BUDGET)`, `verifications = 256`; (ai) a
  17-certificate honest path (16 non-terminal plus the anchor) → `Found`; an 18-certificate one →
  dead end. Fixtures run with the cross-call memo cleared; (aa) presents the root's exact bytes;
  (z) has a related candidate that verifies but is unanchored; stuffing fixtures present their junk.
- **Trust-manager invariants**: never accept what the platform rejected (the 3-arg overload's null-host retry only after a socket or engine overload accepted the chain and host); under `DEFAULT` never
  reject on a step-2 failure alone except `PATH_BUDGET_EXCEEDED`; at most one event per (connection, verdict-cache TTL window) on Android
  OkHttp (the chain cleaner runs lazily, §5.1 flow step 1); at most two platform validations per 3-arg call, the second only the null-host retry; a direct 3-arg call for a chain and host no socket or engine overload accepted gets no retry; a plain delegate on the JVM throws `IllegalArgumentException` at wiring; an empty or throwing anchor set throws `IllegalStateException`
  at wiring (`STARTED`) or from `start()` (instances created in `CREATED`) on both platforms and
  consumes no cap slot; the cap throws at `maxTrustManagers + 1` live instances and instances are collected when their
  client is dropped; a trust manager that can go past flow step 1 has a snapshot (`fetcherTrustManager` without one never goes past flow step 1); `enforcement = ENFORCE` after the start task found the sole seed unreadable → `IllegalStateException` `NO_DATA_AT_FLIP`, enforcement unchanged; two concurrent
  `trustManager(d)` calls return the same instance.
- **`Rule` model tests** (tagged by milestone: **0.1** the enum, preset tables, golden fixture, the `revokt-engine` jvmMain `Rule → BasicReason` map and precedence; **0.2** everything that needs `evaluate`; **0.3** exceptions, caches, listeners and the Java compile): [0.1] both preset tables are total over `Rule.entries`, the two status-map ranges are subsets of it, the `Rule → BasicReason` map is total, and the `RevoktStatus` and `RevoktEvent` rule-keyed maps are zero-filled over `Rule.entries`; `entries == entries.sortedBy { ruleClass }`; the golden growability fixture diff is
  additive; the `PathStatus → Rule` and `CrliteQueryResult → Rule` tables; `parseFailed` zero-filled over `ParseReason.entries`; [0.2] `Verdict.rule` is the
  first fired non-exempted `REJECT` rule; `parseFailed.values.sum() == fired[PARSE_FAILED]`; a leaf failing K6 →
  `PARSE_FAILED(PRODUCER_UNKEYABLE)` with `keyabilityClause = TIME` and `crlite == null`, the same clause on a path-cache
  hit, and an issuer candidate outside the profile not dropped; `rejects` sums equal rejection counts; per-dataset
  `NO_DATA` and `STALE` with a fresh CRLite and a 30-day-old OneCRL generation (M2) fire nothing;
  `DEFAULT.newBuilder().rule(STALE, REJECT)` with 4-day-old data → `Accepted`, `DataState.stale`,
  `rules` empty; the same with `rejectStaleAfter(CRLITE, 3 d)` on a generation that is not `fromSeed` (or, when `fromSeed`, after a sync attempt has completed since the seed install: persisted `datasetLastAttemptAtMillis ≥ seedInstalledAtMillis`) → `Rejected(STALE)`, and with `exempt(STALE, anchorIn(privateCa))` a chain under that anchor → `Accepted` with `Finding.Exempted(STALE)`; a `shadowPolicy = STRICT` under `DEFAULT`/`ENFORCE` with a `NO_SCTS` chain → `Accepted`, `shadowVerdict` is `Rejected(NO_SCTS)`, `shadowWouldRejects[NO_SCTS] == 1`, `rejects` unchanged, one event;
  `dataStates[CRLITE].rules == {STALE}`; `STRICT` with a `SYSTEM` generation (reached through a runtime `policy` flip from `DEFAULT`, since §7.3 never installs one under `STRICT`) → `Rejected(UNSIGNED_DATA)`
  and, through the loader, the generation is not installed while a `SIGNED` one exists;
  `requiredDatasets = {CRLITE}`, no generation after the start task completed (`pending == false`), and a walker that throws → `Rejected(NO_DATA)` with
  `rules == {ENGINE_ERROR, NO_DATA}`; the golden fixture accepts the `ALLOW → REJECT` flip exactly
  once per rule and preset and rejects a second; [0.3] `RevoktCertificateException.cause.reason` equals
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
Set<Oid>)`, which implements `SignatureVerifier.verify(sigAlg, spki, message, signature)` over bytes with `KeyId = SHA-256(spki)` and `CertId = SHA-256(message)` (the TBS); the generator emits real DER and writes the key id into the SPKI BIT STRING under a private-arc key OID, and `unsupported` is matched against `tbsSigOid`/`keyOid`/`curveOid` exactly as the startup probe does, so recovered and duplicate-signature keys are free to generate. Generator: an honest
world (1–200 anchors, some with unsupported OIDs; chain depth 0–9, depth = the number of intermediates; cross-signs only between
snapshot roots), then **world mutations** (`NameEncoding`, `AlgMismatch`, `UnsupportedOwnSig` on
honest certificates, `DropIntermediate`) and **attacker mutations** (`Recover(child)` with a fresh key
in `ok`, optionally `CertifiedBy(anchor)`; `SameKeyDecoy`; `CrossCertToNonAnchor`; `Stuff(n ≤ 300,
related)`; `SelfSignedNonAnchor`; `Loop`; `Permute`; `Duplicate`; `DepthPad`, junk certificates off the honest path that never lengthen it, so P3 is not tripped by a dead end). **Oracle**: a
**relation-aware, uncapped reference walker** (at every node: related candidates, plus unrelated
presented certificates only when no related path exists; depth ≤ `MAX_DEPTH`; no other limits; the fuzzer runs both walkers with the platform canonicaliser, so the leaf-level custom-canonicaliser clause is inert for P2/P6 and is covered by the walker-harness fixtures instead) →
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
  `RELATED_BUDGET`, `relatedExploredAtLeaf == 64 ⇔ endDepth == 1`) and the fallback invoked at most
  once; `verifications` never exceeds `MAX_VERIFICATIONS`.
- **P6 honest cost**: unmutated world, whose generator never emits two anchors with the same
  subject name, ⇒ `verifications ≤ depth + 1`.
- **P7 no throw**: no attacker mutation produces `ENGINE_ERROR`, run with the real `X500Principal`
  canonicaliser and a verifier that throws on a configurable candidate.
- **P8 honest acceptance** (goal 3's core guarantee): an unmutated world, or one with only
  `NameEncoding`/`AlgMismatch`, ⇒ `Found` with `PathStatus.FOUND`, never `Budget`, and
  `Rejected ⇔ the CRLite stub maps the honest key to REVOKED`; `UnsupportedOwnSig` on a non-anchor certificate ⇒
  `ISSUER_UNVERIFIED`, never `PATH_BUDGET_EXCEEDED` (an anchor's self-signature is never verified, so the mutation is applied to non-anchors only); `DropIntermediate` ⇒ `NO_ISSUER(NO_CANDIDATE)`
  (a world mutation under P3: the platform's acceptance of such a chain is the §5.2 residual,
  outside the fuzzer's model).
Rounds 1–2 are `Recover` + P3; round 2's OID case is `UnsupportedOwnSig` + P1; round 3 is
`SameKeyDecoy`/`CrossCertToNonAnchor` + `Permute` + P4; round 4 is `Recover(CertifiedBy)` + `Stuff` +
P3. Run under Jazzer with the mutation list as the structured input, plus the committed corpus.

### 9.2 Differential parser oracle

**Why it is load-bearing.** Every certificate the trust manager parses has already been accepted by
the platform: presented chain, platform-built chain, anchors and preloads all arrive as platform
`X509Certificate`s and are re-read through `getEncoded()` (SunJSSE returns the stored bytes;
Conscrypt returns `i2d_X509` of the parsed object). `PARSE_FAILED` on the leaf allows in `DEFAULT`
and an unparseable candidate is dropped (decision, §10 item 8). Two failure classes matter: (i) a
certificate the platform accepts and revokt rejects is unchecked (a leaf) or invisible as an issuer
(a dropped candidate ends the walk `NO_ISSUER`, which allows in `DEFAULT` for every leaf under that
CA), and a leaf revokt parses but cannot show producer-keyable is a sub-case, unchecked but never mis-answered (the D8 gap); (ii) a certificate from which revokt extracts **different bytes** than Mozilla's producer used
to form the key (`SHA-256(SHA-256(issuer SPKI TLV) ‖ serial content bytes)`) or different SCT
timestamps queries the wrong key or the wrong coverage, which can hide a revocation or, for a key
outside the filter's universe, return an arbitrary answer. The oracle bounds both.

**Parser contract under test.** One minimal parse of `Certificate` → `tbsCertificate` producing
`rawSerial` (INTEGER content bytes as encoded, sign and leading zeros preserved), `rawSpki` (complete
TLV), `rawSubject`, `rawIssuer` (complete Name TLVs), SKI/AKI, TBS `signature` and outer
`signatureAlgorithm` TLVs, the extension table (OID, critical, value bytes, offsets), and the SCT
pairs `(logId, timestamp)` as the **union** over every extension with OID `1.3.6.1.4.1.11129.2.4.2`
whose list parses under the SCT-list rule here. The rule follows `x509-parser` 0.18.1's `parse_ct_signed_certificate_timestamp_list` (oracle 3a; Appendix A pins it) except at the inner identifier.

- **Inner header.** The extension value must begin with the identifier octet `0x04` (universal, primitive `OCTET STRING`) and a definite length. The length is either short form, or long form `0x81`–`0xFE` followed by that many length octets, with leading zero octets allowed and the value below 2^64 and not past the end of the extension value; `0x80` and `0xFF` fail the list.
- **Divergence from 3a.** 3a also accepts tag number 4 in any class and in multi-octet form (asn1-rs checks the tag number only). That wider acceptance is the recorded D3 divergence class `3A_HEADER_LAX`. D2 expects no pairs from such an extension, so revokt yielding none is still asserted, never skipped. Firefox and webpki yield none either.
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
| 1 | `CertificateFactory.getInstance("X.509")`, `SUN` provider (the same `X509Factory` SunJSSE's `CertificateMessage` uses), per JDK in the matrix | platform acceptance on the JVM; `encoded = getEncoded()` | `generateCertificate` returns | `CertificateException` | any other `Throwable` |
| 2 | Conscrypt `CertificateFactory` (BoringSSL): `conscrypt-openjdk-uber` versions in the matrix; the **platform** Conscrypt on the instrumented tier | platform acceptance on Android; `encoded = getEncoded()` (`i2d_X509`) | as above | as above | as above |
| 3a | `revokt-oracle`: `x509-parser` on one certificate | raw `serial`, SPKI TLV, names, extension table, SCT list or `ParseError` or duplicate-extension error; the TBS TLV re-headed to minimal, its signature AlgorithmIdentifier and the `signatureValue` octets, for `canon` | `Ok` | `Err` | caught panic |
| 3b | `revokt-oracle`: a minimal independent TLV locator (delimit the `tbsCertificate`, the outer `signatureAlgorithm` and the `signatureValue` (an indefinite `signatureValue` is not located) and re-encode the TBS under the §9.2 unsigned-header rule, implemented independently of revokt; then walk the re-encoded TBS, with `[0]` read bounded as the JDK reads it, the TBS tail under the §9.2 trailing-element rule so extensions the JDK does not read are not located; slice from the re-encoded TBS the serial content, SPKI TLV, subject, issuer, TBS signature AlgorithmIdentifier, extension values by OID, the TLS-encoded `(logId, timestamp)` prefix of each SCT the §9.2 SCT-list rule keeps, under the same header, item and prefix rules; output the re-encoded TBS and the content of a definite `signatureValue` after its unused-bits octet, for `canon`; no other semantics; 3a needs no change, since x509-parser rejects every indefinite length, but its TBS is re-headed to minimal for `canon`) | raw bytes where 3a rejects, and the `canon` parts | located | not located | caught panic |
| 3c | `revokt-oracle`: webpki through `upki`'s `RevocationCheckInput::from_certificates` on `[cert, syntheticIssuer]` | the `rustls-upki` verifier's (webpki's) view of the certificate, no longer any engine's input (§3.2); **never a precondition** | `Ok` | `Err` | caught panic |
| 4 | **Producer**: Mozilla's `crlite/go/types` (`ParseCertificate`, `NewSerialFromCertificate`, `RawSubjectPublicKeyInfo`, `IsPreIssuer`) built as a Go CLI, pinned to the `crlite` commit of the filters in the fixture set; always out of process (fuzzing and corpus admission), batched over a pipe | whether the producer can key `canon(encoded)` (above), with which bytes and through which path (`ct` for certificate-transparency-go's strict parse, `lax` for ct-go only through a `lax` retry, `zc` for the zcrypto fallback) | both calls return | a `ParseCertificate` error, or a panic anywhere in the producer (the shim recovers around the whole call) | unrecovered; counts as `Reject` under D8 |

A getter that throws on an accepted object (Conscrypt `getPublicKey()` on a damaged modulus is
common) marks that field `unavailable`: the comparison is skipped and counted. Oracle `Crash`
never fails revokt's gate, except oracle 4's under D8, where it counts as `Reject`; it is reported upstream. A `Crash` or `unavailable` rate above 0.1 % on
the secondary corpus fails the job as infrastructure. A Rust or Go abort that kills the JVM is
attributed by re-running the input through the out-of-process CLI before it is filed against revokt.
Java field normalisation: `getSerialNumber()` by value (`BigInteger` drops padding and sign-extends);
`getPublicKey().getEncoded()` by SHA-256 against `rawSpki` with a recorded allow-list of
re-encoding cases (Java re-encodes RSA parameters); `getIssuerX500Principal()` and
`getSubjectX500Principal()` as `X500Principal(raw).getName(CANONICAL)`; `getExtensionValue(oid)`
unwrapped; `getCriticalExtensionOIDs()`; `getNotBefore()`/`getNotAfter()` in epoch milliseconds against
`notBefore`/`notAfter`. Raw-byte equality is asserted against 3a, else 3b.

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
  certificates are not CA/B-conformant. Also D1-dom by rule is any input whose TBS the unsigned-header rule makes
  `STRUCTURE` for a non-minimal definite length on the indefinite chain: it has no `canon` for oracle 4 to read, and
  every producer path rejects a non-minimal length (Appendix A). For it and the other D1-dom inputs, no filter can
  contain such a certificate and its key is outside the filter's universe, so it must never be queried (a query
  would answer arbitrarily, a false `REVOKED` at about 2^-(rank+1) and with high probability under
  an inverted issuer block); D8's gated direction enforces that; each entry is kept with the producer's error so a
  producer change can be re-evaluated.
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
    or the entry is justified.
  - The count by clause over the seed corpus's CT leaves is reported in each release's notes and in
    `docs/dev/status.md`.
  - **Re-decision**: if gap entries among the seed corpus's unexpired CT leaves exceed 10^-4 of them when #15 pins it,
    exact keyability is reconsidered in a spec revision before 0.1 ships.
- **D1-raw (informational)**: inputs where `encoded ≠ b`, or `parse(b)` fails while
  `parse(encoded)` succeeds. This is the `EvaluationRequest.presented` raw-DER surface (§4), documented,
  not gated.
- **D2 extraction agreement (security)**: on `parse(encoded_i,v)`: `Cert.tbs` equals `canon(encoded)`'s first element
  and oracle 1's `getTBSCertificate()`, while a difference from oracle 2's is recorded as a divergence, not a violation
  (Conscrypt verifies over the presented TBS TLV, so a difference marks an input it cannot verify); `Cert.sig` equals
  `canon(encoded)`'s signature octets with the last octet's u low bits cleared, u being the presented unused-bits
  octet as located by 3a, else 3b;
  `rawSerial` equals oracle 4's serial bytes and `SHA-256(rawSpki)` equals `SHA-256` of oracle 4's SPKI where `producerKeyable` (implied by D8's gated direction, restated so that a mismatch names the field);
  `rawSerial`, `rawSpki`, `rawSubject`, `rawIssuer`, extension values and the SCT pair set equal 3a's
  where 3a accepts, else 3b's. The expected SCT pair set is the union over SCT extensions of a per-extension
  expectation: the reference's pairs for that extension, or ∅ when the extension value's first octet is not `0x04`.
  That octet is read by 3b's locator, never by revokt. An extension whose expectation is ∅ while 3a yields pairs is
  recorded as `3A_HEADER_LAX`, so the comparison substitutes ∅ rather than skipping. Where 3a takes as extensions an
  element with tag number 3 that is not a constructed context-specific `[3]` (a primitive `[3]`, or tag number 3 in
  another class; decided by 3b's TBS walk), the reference extension table and SCT pairs are the §9.2 read (∅),
  recorded as `3A_TBS_LAX`; the normalised Java fields equal oracle *i,v*'s. A violation is a P0.
  The count of platform-accepted inputs with no raw-byte reference (3a rejects, and 3b's walk does not locate the
  input), other than D1-dom inputs revokt does not parse, is a gate metric and must be zero on the committed corpora.
- **D3 SCT classification**: mapping from 3a: no extension → `NO_SCTS`; `ParseError` → `NO_SCTS`
  (an empty list is a `ParseError`; `x509-parser` 0.18.1 never returns `Ok([])`); `Ok(list)` → pair-set equality (D2), with the per-extension ∅ expectation for an inner identifier other than `0x04` (`3A_HEADER_LAX`); 3a's duplicate-extension error →
  the union rule, recorded as a divergence class. Firefox's decoder (fails the whole list on
  version ≠ 0, trailing bytes in the OCTET STRING, per-item length errors) and 3c's errors are
  recorded as divergence entries, never gate failures: every such divergence is in the
  more-checking direction (revokt queries where Firefox or the `rustls-upki` verifier would not). Firefox's
  decoder is not an oracle and is not run in CI; its stricter behaviour is argued here, and its divergences are hand-recorded
  `D3_DIVERGENCE` entries (record schema) in the D7 corpus. A 3c error where revokt yields pairs is recorded, never a gate failure. A 3c pair that
  revokt does not yield blocks the release until a spec revision resolves it; revokt follows §9.2, never 3c. A
  further class, also against 3a only, is `3A_TBS_LAX`: 3a takes as extensions an element with tag number 3 that is not
  a constructed context-specific `[3]` (`x509-parser` checks the tag number only), which the JDK and revokt do not, so
  D2's reference for that certificate's extension table and SCT pairs is the §9.2 read (∅), asserted, not skipped. A
  separate class, against 3a only, is `3A_HEADER_LAX`: 3a yields pairs under an inner identifier other than
  `0x04`; Firefox, webpki and revokt do not; that is equivalent to issuing without SCTs. For a key outside the filter's universe
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
  recorded outcome of every oracle version and revokt's required outcome (the SCT-list outcomes named below follow from the rule above and are
  normative; for every other entry no outcome is asserted in this text and the corpus is the record): negative serial, serial over 20 bytes, serial with leading
  zeros, TBS/outer algorithm mismatch (NULL vs absent), `GeneralizedTime` with fractional seconds,
  `UTCTime` used for a date in 2050 or later, PrintableString/UTF8String/TeletexString/BMPString
  names, an empty subject, duplicate extension OIDs, **two SCT extensions** (empty list first,
  covered SCT second → union queries), an unknown critical extension, an SCT list whose declared
  length is longer than its content (the list fails) or shorter (the items that fit extracted), a malformed first SCT followed by valid ones (the list fails), a non-minimal length on the SCT extension's inner OCTET STRING, `81 nn` with nn < 0x80 and `84 00 00 00 nn` (required outcome: `Parsed`, the list's SCTs extracted, `producerKeyable` unaffected because the SCT extension is opaque to the profile, K1), an inner length `0x80` or `0xFF` (the list fails), an inner identifier other than `0x04` that is tag number 4 (for example `0x44`, `1F 04`; `3A_HEADER_LAX`: no pairs), a constructed inner OCTET STRING (the list fails), a non-zero SCT version (extracted), a truncated last SCT (the items before it extracted), trailing bytes after the inner OCTET STRING, after the declared list region and inside an SCT after its signature (ignored), an SCT hidden in ignored bytes (never extracted), a zero-length signature (extracted),
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
  and outside the profile (K2), a D8-gap entry because ct-go never visits `[3]` there and keys it), the
  more-lenient-than-JDK cases (a v1 or v2 certificate carrying elements its version does not allow; unique-id content
  that is not BIT STRING content), times with an offset, without seconds and with a day past the month's end
  (2026-02-31, rolling over to 2026-03-03), a 64 KB extension, BER indefinite lengths, non-minimal definite lengths, and
  a `Certificate` with trailing bytes; the envelope re-encodings (a non-minimal length on the outer `signatureAlgorithm`
  or `signatureValue` header, the outer NULL parameters flipped, a non-zero unused-bits octet on an RSA
  `signatureValue`, an indefinite outer `signatureAlgorithm`, an OID header `06 81 08` or a NULL as `05 81 00` inside
  it, a `tbsCertificate` header with a long-form length carrying leading zero octets or an indefinite length, an
  indefinite TBS with an indefinite Validity, subject RDN chain, `[0]`, or `[3]` down to an `extnValue` as
  `04 80 … 00 00`, an outer AlgorithmIdentifier `30 80 <OID> 05 80 00 00 00 00`, an RSA `signatureValue` with
  unused-bits octet `01` and the padding bit set; required outcome for each: `Parsed`, with
  the `producerKeyable` and key bytes of the unmodified certificate and a `VERIFIED` link, since the profile reads
  `Cert.tbs`; and on the reject side an indefinite TBS holding a non-minimal definite child (`02 81 …`, an SPKI
  `30 82 00 …`), which the JDK accepts and fails to verify, an indefinite outer AlgorithmIdentifier holding a
  non-minimal OID header (`30 80 06 81 08 … 00 00`), which the JDK rejects, and an indefinite `signatureValue`
  (`03 80 <content> 00 00`, whether or not its content reads as a chain of minimal TLVs), which JDK 17 and later
  reject; each `STRUCTURE`); and a CA-signed TBS whose extensions are followed by a trailing element with a
  multi-octet tag (`9f 01 02 05 00`), presented with a definite and with an indefinite TBS header (`Parsed`, outside
  the profile under K2, the same outcome for both); and the D8-gap examples (a serial with non-minimal INTEGER
  content, a keyUsage or basicConstraints value only zcrypto accepts, a `UTCTime` without seconds; each `Parsed` and
  outside the profile).

**Issuer corpus (zero tolerance).** Every certificate in Mozilla's `intermediates` Remote Settings
collection, the CCADB all-certificate-records export, the JDK `cacerts` store, and Android's system
store (for 0.1 taken from the AOSP `ca-certificates` sources of the pinned images; the 0.3 instrumented tier replaces it with the device read-back through the platform `X509Certificate.getEncoded()`),
under D1 and D2 with no tolerated violation. **Producer SPKI check**: for every intermediate the
collection marks CRLite-enrolled, `SHA-256(rawSpki)` must be a key of the live filter's index map
(§6.3) for the fixture generation; a miss is a producer/revokt SPKI-byte divergence and fails.

**Corpus record schema (one for all four kinds; committed).**
`{sha256, path, revokt: {outcome, rawSerial, spkiSha256, scts[]}, oracles: [{id, version, outcome,
fields | unavailable}], class ∈ {D7_LENIENCY, D2_REENCODE_ALLOW, D3_DIVERGENCE, D1_DOM,
KEYABILITY_GAP, FUZZ_FINDING, ISSUER_CORPUS}, divergence: String? (required for D3_DIVERGENCE: `3A_HEADER_LAX`, `3A_TBS_LAX`, `CONSCRYPT_TBS` (D2: `Cert.tbs` differs from oracle 2's `getTBSCertificate()`), the
duplicate-extension class, or a named 3c/Firefox class), keyability: {parser, clause, zlint}? (required on every D8-gap entry whatever its class, and on every `KEYABILITY_GAP` record: `parser ∈ {ct, lax, zc}` from oracle 4, `clause` a `KeyabilityClause`, `zlint` the pinned zlint result), justification, added}`. Goldens for 3a/3b/4 are computed at admission
so the PR replay evaluates D1–D3 and D8 offline, JDK-only. The release review mechanically lists entries
whose oracle version has left the matrix. The seed corpus (≥ 100 000 CT leaves across all enrolled
CAs, the `x509-limbo` vectors, the D7 corpus, the issuer corpus) is pinned by a committed SHA-256
manifest and a corpus-repository tag.

**Generators.** (1) Mutational, Jazzer byte-level, seeded from the pinned seed corpus. (2)
Structure-aware: a DER grammar generator for `Certificate` mutating at TLV level (length forms, tag
classes, element reorder, duplicate and dropped elements, extension insertion, SCT-list specific
mutations, serial and SPKI variants, algorithm-identifier parameter variants). (3) Platform-accepted
bias: a mutant oracle 1 or 2 accepts enters the **secondary corpus** only if it adds revokt-parser
coverage (`-merge=1` over the accepted set) or is a D1/D2/D3 divergence; hash-keyed, capped by
entry count and bytes, stored in the corpus repository, re-seeded each run.

**Tiers and matrix.** Fuzzing runs on one pinned JDK ≥ 22 (Panama) with oracle 1 of that JDK, one
Conscrypt uber artifact and 3a/3b/3c in-process, oracle 4 out of process; one ClusterFuzzLite job per generator. The
**version matrix** is a replay of the union corpus (committed, secondary, divergence): one job per
(JDK, Conscrypt) pair, with 3a/3b/4 goldens read from the records so no matrix job needs a
native oracle. Versions are named in a committed matrix file (JDK: 17, 21, the current LTS, the
current feature release; Conscrypt uber: current and previous minor; Android system images by
revision, with the Conscrypt APEX version logged per run since it is updated out of band) with the
roll rule "add the new version, keep the old until its support ends", except that the bytecode
target (JDK 17) stays while it is the target. A nightly job replays the committed corpus against the
newest JDK EA and Conscrypt release and fails on any new D1 violation
against the recorded baseline. A scheduled **producer job** (weekly, on every change to the producer,
certificate-transparency-go, zcrypto or Go pin, and before each release) builds oracle 4 at the pin and at
`mozilla/crlite` `main`, replays D8's gated direction over the union corpus with both, and runs at least 100 000
fresh entries from CRLite-enrolled logs, precertificates included, through oracles 1 and 4 and the profile. A violation
at the pin is a P0; one only at `main` is a P0 for the next release and bumps the pin in a spec revision, since
live filters come from Mozilla's current producer. The sample's gap by clause is published with each release; a
new clause, or D8-gap entries above 10^-4 of the sample's unexpired entries (precertificates and certificates
counted alike), needs a recorded decision before the release. This per-release check on fresh entries is separate
from the D8 gap's one-time re-decision on the #15 seed corpus, which can reopen the D8 decision itself.

**Scope limits, stated.** The oracle set is a version matrix, not a proof; platform parsers drift
and the platform Conscrypt differs per device. `Revokt.evaluate` over raw bytes is outside the
platform-accepted premise and is documented as such (§4).

**Acceptance.** 0.1 gate: zero D1, D2, D3 and D8 violations on the pinned seed corpus, `x509-limbo`,
the D7 corpus and the issuer corpus against oracles 1 (every JDK in the matrix), 2 (uber versions
in the matrix), 3a/3b and 4; the producer SPKI check green; the D8-gap baseline recorded, and zero on the real end-entity fixtures; zero platform-accepted inputs without a
raw-byte reference, outside the D1-dom inputs revokt does not parse; Kover branch coverage of the parser
package ≥ 90 % measured over the committed
replay (fuzz-run coverage is reported only). 0.3 gate: the same replay on the platform Conscrypt
tier (API 26, 31, 34, 36) at zero tolerance. Continuous: no open D1, D2 or D8 finding at any release; the
divergence, D1-dom and D8-gap records reviewed at each release with every entry justified in writing.

## 10. Security considerations

- Platform verdict first and final for acceptance; revokt's own failures never reject in `DEFAULT`,
  with the two stated exceptions of `PATH_BUDGET_EXCEEDED` and `NO_DATA` (goal 3).
- **Issuer identity is pinned by a path of `VERIFIED` links to a known anchor by bytes.** No
  candidate is excluded for a shared property; deferral is by the candidate's own relation, which the
  server cannot forge for a real certificate; related candidates at the leaf are fully explored or
  the result is not an allow; every terminating leaf-issuer key is evaluated and `REVOKED` wins;
  any exhaustion anywhere rejects.
- **Residual risks recorded from the sixth and seventh review rounds:**
  1. On a custom delegate whose name equality differs from `X500Principal`'s, an honest issuer may
     be classified unrelated; at the leaf it is then explored regardless of a related path (§5.1
     deferral rule, custom canonicaliser), below the leaf only while no related path exists at that
     node (a related path there is itself sound: only the honest key verifies a real certificate and
     a recovered key cannot reach an anchor), so misclassification alone no longer yields `NotFound`;
     what remains is cost and order: the unrelated loop always runs at the leaf (bounded by
     `presented − 1`) and junk ahead of the misclassified issuer can exhaust the budgets first
     (`PATH_BUDGET_EXCEEDED`); the PKIX fallback covers the constraints and verifier residue for
     chains of at most 8 certificates. Consumers with a custom delegate accept the ordering residue. The fallback may not be disabled while `NO_ISSUER` allows. On both
     default delegates every honest issuer is related.
  1b. **Behind a TLS-intercepting proxy revokt sees the proxy's chain**: no SCTs, an issuer CRLite does
     not enroll, so every verdict is a non-answer and `STRICT` reduces to exempting the proxy's anchor;
     CRLite cannot evaluate such traffic, deploy revokt on the egress proxy instead (§8 `OBSERVE`
     shows `fired[NO_SCTS] / evaluations` near 100 % in that case).
  2. Divergence between the delegate's constraints and `CertPathBuilder("PKIX")` or the injected
     verifier can leave a chain the platform trusts unchecked in `DEFAULT`; it is reported as
     `NO_ISSUER(PLATFORM_ONLY)` and `STRICT` rejects it.
  3. **Closed (revision 19).** The anchor snapshot is built synchronously before any handshake can
     go past flow step 1 on both platforms (inside `start()`, at wiring, or on `fetcherTrustManager`'s
     first handshake), so there is no startup window; the only failed-build states are
     `fetcherTrustManager`'s: its `start()` build (`FETCHER_TRUST_UNAVAILABLE`, syncs `FAILED` without
     a fetch until a per-sync retry succeeds) and its lazy build, which returns that call on the
     platform verdict and retries.
     What remains is operational: on Android the delegate's `getAcceptedIssuers()` at wiring runs
     under an unconditional `StrictMode.allowThreadDiskReads`, which hides the report, not the read:
     the default delegate reads the cacerts directories only when wired after a trust-store change,
     a Conscrypt `TrustManagerImpl` over `AndroidCAStore` on every wiring. A consumer that wants no
     main-thread disk read creates its trust managers before `start()`.
  4. `MAX_RELATED_PER_LEVEL = 64` rejects honest nodes with more than 64 same-name certificates;
     unknown in the Web PKI, possible in bridge PKIs, which are out of scope for TLS clients.
  5. CRLite's (issuer key, serial) model: a certificate revoked under one issuer key and re-presented
     under a cross-issuing key with a different serial is a data-model limit, not a walker defect.
  6. The named M1 Android residual (§5.2), including any app whose NSC carries a `<domain-config>`, where `RootTrustManager` rejects a null host: the plain-delegate binding and any path where the
     null-host extension call is unavailable.
  7. **Decided (revision 11): kept; revision 33 narrows the Firefox match.** A certificate issued without
     embedded SCTs, or whose every SCT list fails under §9.2 (for example an empty list, a first item that fails, an inner identifier other than `0x04`; §9.2 states every case), yields `NO_SCTS`, which allows in `DEFAULT`: an issuance-time
     opt-out from checking. Firefox skips CRLite without usable SCT timestamps and falls to OCSP, which
     revokt does not do; `STRICT` rejects; the `rustls-upki` verifier rejects a malformed list (§3.2
     divergence). A list §9.2 accepts in part, which Firefox and webpki fail whole, is queried, so `STRICT`
     then sees the CRLite answer, not `NO_SCTS`. SCTs are not verified in M1: a forged covered SCT on a key
     outside a filter's universe gets an arbitrary answer, a residual that predates revision 33.
  8. **Decided (revision 11): kept; revision 34 widens `PRODUCER_UNKEYABLE`.** `PARSE_FAILED` on the leaf allows in
     `DEFAULT`, so a leaf encoding the platform accepts and the Kotlin parser rejects is unchecked. The subscriber
     controls leaf content only at issuance, under CA linting, and the §9.2 differential parser oracle (D1, a 0.1
     gate) is the mitigation.

     A leaf outside the §9.2 keyability profile is `PARSE_FAILED(PRODUCER_UNKEYABLE)` and is never queried (D8). That
     covers two kinds of leaf:
     - a leaf the producer cannot key: its fatal parse halts Mozilla's ingestion of that log (Appendix A), so it is in
       no filter;
     - a leaf the producer did key that revokt cannot show keyable, the D8 gap: non-minimal INTEGER serial content,
       encodings only `lax` or zcrypto accept, and ignored trailing elements.

     A revoked gap leaf is unchecked in `DEFAULT`, an issuance-time opt-out like item 7 that only the issuing CA
     controls. `STRICT` rejects a gap leaf even when it is valid. The gap is measured per release (§9.2 D8 gap). No
     entry of a 200 230-entry CT sample on 2026-10-23 fell outside a strict DER profile, and its 159 270 RFC 6962
     entries showed no K5 type or K8 shape outside the profile (Appendix A); the full K1–K8 gap is first measured on
     the #15 seed corpus.

     The profile reads only the signed content of `tbsCertificate`, and the parser accepts every unsigned header form
     the JDK verifies (§9.2), including the indefinite chain the JDK re-encodes and the cleared signature padding,
     so a network attacker re-encoding the envelope or the TBS headers reaches neither
     `PRODUCER_UNKEYABLE` nor `STRUCTURE`.

     Firefox has no keyability notion. mozilla::pkix rejects most gap encodings before CRLite, and accepts the serial
     forms (negative, zero, long) and the explicit `FALSE` that the profile also accepts.

     Considered and not adopted (revision 34): deciding keyability at the query, after the walk. That would make the
     outcome exemptable under `anchorIn`, and `NOT_ENROLLED` under an unenrolled issuer. The profile already accepts
     the private-PKI serial forms, so the remaining unkeyable leaves are encodings that mozilla::pkix and BoringSSL
     also reject. This reopens if a gap entry under a private anchor is reported.
  9. Walker CPU per uncached connection is bounded by `MAX_VERIFICATIONS`, about 250 ms of RSA-4096
     on a mid-range ART device, and both caches are defeated by one varying junk byte per connection;
     `MAX_PRESENTED` bounds parsing (counted over the raw chain, before dropping).
  10. **Coverage gap, every preset**: a certificate issued after the live filter's coverage `high`
     is `NOT_COVERED` and allowed; Firefox goes to OCSP there, revokt does not; with no ceiling in
     `DEFAULT` an update blackout leaves every newer certificate unchecked. The only closures are
     `rule(NOT_COVERED, REJECT)` (rejects every certificate newer than the data) and a `rejectStaleAfter`.
  11. **HTTP/2 coalescing** (§5.1): a coalesced host inherits the handshook host's verdict,
     exemptions and `<domain-config>`; per-host policy needs a per-host client or pool.
  12. **Android default fetcher without OkHttp**: Android's `HttpsURLConnection` answers a 407 from the
     VM-global `Authenticator.getDefault()` with no per-connection suppression; revokt sends no credentials
     and treats 401/407 as `FAILED`, but a trusted intercepting proxy on the fetch path can elicit the
     app's default proxy credentials once; the OkHttp fetcher (`authenticator(NONE)`) is preferred and is
     the default whenever `revokt-okhttp` resolves.
  13. **JVM PKIX fallback and AIA**: with `-Dcom.sun.security.enableAIAcaIssuers=true` the
     `CertPathBuilder` (and the delegate itself) fetches AIA issuers over the network inside the
     handshake; the fallback may then find a path the walker called `NO_CANDIDATE`; revokt neither sets
     nor clears the property (unverified beyond `sun.security.provider.certpath.Builder.USE_AIA`).
  14. **`ISSUER_UNVERIFIED` relabelling, closed (revision 29)**: only the child's own signature OID
     counts, so a related decoy carrying an unsupported key OID cannot turn a `NO_ISSUER` into the
     separately exemptable `ISSUER_UNVERIFIED`; consumers scoping that exemption use `hostIn`/`hostSuffixIn` or `platformOnly()` (`anchorIn` never matches on an empty reported path, §4).
  15. **Keyability is a prediction.** The producer keys the logged precertificate (about half of CT entries). It also
     needs the logged `chain[0]` to parse, and `chain[1]` behind a precertificate signing certificate. revokt sees
     only the final certificate, so `producerKeyable` predicts the producer's result through RFC 6962's identical-TBS
     rule.
      - **Mismatched precertificate**: a CA's precertificate and certificate differ, the precertificate is unparseable,
        and the certificate is never logged. revokt then queries outside the filter's universe and gets an arbitrary
        answer, which under an inverted issuer block is a false `REVOKED`. Ingestion halting at that entry usually
        leaves its SCTs past coverage `high`, which gives `NOT_COVERED`. Firefox shares this residual.
      - **Two SPKI encodings**: two enrolled issuer certificates carry one key with different SPKI encodings, for
        example RSA with and without NULL parameters. A query under the encoding Mozilla did not key falls outside the
        universe.
- Feed authenticity: `SIGNED` by Mozilla/Google signatures; `MIRROR`/`SYSTEM` by TLS or the OS,
  **bootstrap only** (§7.3): never displaces a higher-class generation, evicted by the first signed
  one; `BUNDLED` is project-attested and availability-only. The §7.3 residual: a fresh install without a
  seed, on-path, with a platform-trusted certificate for the mirror host, runs on attacker data until
  Mozilla is reachable; shipping a seed closes it and `validate()` says so.
- Rollback and freeze: a persisted non-decreasing watermark with a 24 h tolerance and a
  coverage-monotonic rule inside that window; a newer signed changeset always installs and the
  pinned terminal's validity is never checked; **no signed record can freeze the signed source**: a
  signed revocation of the feed host holds fetches for at most 24 h, then they proceed with
  `feedHostRevoked` loud, while `BLOCKED_BY_SELF` has no time bound only for TLS-only sources (§8); handshakes are attributed structurally (one internal trust manager per source), so a consumer's unrelated traffic on the public `fetcherTrustManager` can neither start the hold nor inherit `feedHostRevoked`; the cursor and watermark move only on a
  successful install after collection-schema validation, so a replayed sibling-collection changeset
  cannot freeze them; the content signature binds neither bucket nor collection, so a party the fetcher's TLS trusts (a private mirror) can serve `security-state-preview`'s `cert-revocations` as production data (residual: Mozilla data pending review, low impact; recorded beside the collection-id note); unsigned transport headers cannot persist a backoff beyond 24 h;
  staleness always visible; no ceiling in `DEFAULT` (upki's model); `rejectStaleAfter` is the
  optional ceiling; a changeset dated beyond local now + `clockSkew` is refused while a generation that is not itself `clockBehind` exists, and installed without advancing the watermark or cursor when none does or the live one is `clockBehind` (§6.3), so a single
  future-dated signed record cannot pin the watermark in either case; a future-dated seed installs with the watermark at its signed timestamp, which only a newer signed changeset can pass, as for any seed. After `resetState()` the rollback bound is the
  seed's timestamp (residual: `updater.json` is deleted with the store).
- Self-lockout bounded: a signed revocation of the signed source's own certificate holds fetches 24 h and is
  then reported as `feedHostRevoked` while fetches proceed (the payload is authenticated end to end, so
  TLS authenticity to that host protects nothing an attacker could exploit); a TLS-only mirror's host is
  blocked while its current chain is hit (`updateBlockedBySelf`); this is the one deliberate departure from Firefox's behaviour on the feed path; untrusted bytes hardened per C2SP with allocation budgets and per-kind download caps,
  so an unsigned manifest bounds neither heap nor disk nor metered bandwidth;
  x5u allowlisted, capped and path-validated; the parser is at least as lenient as the platforms,
  verified differentially (§9.2), and `PARSE_FAILED` applies to the leaf only.
- Crypto never implemented in Kotlin except the raw-to-DER ECDSA conversion and the §9.2 profile's EC on-curve check (public field arithmetic over P-256, P-384 and P-521, no secret data); `UNSUPPORTED` is decided
  by a startup probe, never by a server-chosen exception; provider exceptions never escape the
  trust manager.
- Privacy: no per-connection lookups. Blast radius mitigated by `Enforcement.OBSERVE`, `shadowPolicy`, the runtime
  switch, seeds, the fixed fetcher policy (which ignores `Enforcement`), dated data artifacts, and `ENGINE_ERROR = allow` in `DEFAULT`;
  an engine exception never masks a data rule, which is computed outside the catch boundary.
- Supply chain: reproducible builds, publishing from CI only (a protected release environment with a second maintainer's approval, PGP-signed artefacts, SLSA provenance attestations; Central Portal has no OIDC trusted publishing), SBOM, `dependencyLocking`,
  `SECURITY.md`, two-person review on the clubcard module, the verifiers, the walker,
  `RevoktTrustManager` and the §9.2 parser; seed archive entries are capped while inflating (§6.5) and
  everything in a seed outside `seed.json` is Mozilla-signed or hashed; seed artifacts carry no code
  dependency, so a data bump cannot desynchronise the code set.

## 11. Milestones and versioning

0.x until M2; from 1.0 BCV dumps (the 1.0 promise covers revokt's own API; the OkHttp and Ktor bindings pin those libraries' majors and follow them), deprecation `WARNING` → `ERROR` → removal in a major, opt-in
APIs outside the promise, the growability contract in §4.

| Release | Scope | Estimate |
|---|---|---|
| 0.1 | engine scaffold, `RevocationEngine`, `Rule`/precedence model with the one-to-one tests, purity gate, BCV, POM assertions; `SymVerifier`, the reference walker and the §9.1 chain generator in `revokt-engine`'s test source set (they move to the published `revokt-testing` in 0.3); TBS/SCT parser (incl. `producerKeyable`, `notBefore`/`notAfter`) with the D7 corpus, the issuer corpus and the §9.2 differential parser oracle (0.1 gate: oracles 1, 2 uber, 3a/3b, 4, properties D1–D3, D5, D6, D8 (gated direction; D8 gap reported)); JSON tree; clubcard port (v3 + v4); the C2SP `index.bin` reader/writer and `GenerationFiles` (`KotlinRevocationEngine.prepare` needs them); the `revokt-engine` jvmMain `Rule → BasicReason` map; the §9.1 chain generator, `SymVerifier` and the reference walker (the walker fuzzer itself is 0.2, with the walker); oracle CI | 5 weeks |
| 0.2 | a minimal `Revokt` (`build()`, a synchronous `start()` that builds one `CandidateIndex` over `platformTrust.anchors(platformTrust.defaultDelegate())`, loads the seed, runs the in-memory updater on the loader dispatcher and publishes the generation reference, `close()`; no readiness future, caches, factory lock, per-delegate instances or `state`; start diagnostics returned from `start()` as `List<PolicyDiagnostic>` until `state` exists); candidate index and walker per §5.1, PKIX fallback on both platforms, the walker-only harness, `Evaluator.evaluate` over that one index (decision steps 2–3 and 5–8, walker reason reported directly; `Revokt.evaluate(…, delegate)` is 0.3); **the §9.1 walker fuzzer is built and runs against the implementation here (P1–P8 gate)** and the walker's adversarial review precedes it; Remote Settings protocol and content-signature verification with x5u path validation; CRLite updater and the updater record over `RevoktStorage.inMemory()` (the §6.5 key layout in memory; durability, `store.version`, pointer flip, crash recovery and the lock are 0.3); seeds with `seed.json`; data artifacts job; coverage sanity and rollback; the §9 data-path fixtures (a), (b), (d) and (g) less its `BLOCKED_BY_SELF` and `MIRROR` items; CI-only upki engine and the cross-engine suite (the issuer taken from the corpus chain's presented order, no walk needed); benchmarks | 4 weeks |
| 0.3 | §6.5 store (`store.version`, `meta.json`, pointer flip, crash recovery, lock); C2SP bootstrap-only mirror and system cache; the §9 data-path fixtures (c), (e), (f), (h) and the (g) items deferred from 0.2; caches; per-delegate trust managers and `Revokt.evaluate(…, delegate)`; lifecycle state machine and readiness future; OkHttp and per-engine Ktor bindings; `OBSERVE` events, `status()` and `state`; Android instrumented suite including the null-host probe and the main-thread wiring probe under `StrictMode.detectDiskReads` on API 26/31/34/36, cold process and after a trust-store change (induced by `am broadcast -a android.security.STORE_CHANGED` as root on AOSP userdebug images, or by installing a user CA through `KeyChain.createInstallIntent()` under UiAutomator on images without root; the mirrored image matrix carries a userdebug variant for this); a consumer fixture built with AGP 8.5.2 that dexes the published artifacts (revision 38's Android floor; Appendix A); Baseline Profile and measured `AWAIT_DATA` (JVM default 2 s); WorkManager (`RevoktSyncWorker`, `Revokt.Provider`); system images mirrored into project storage for the emulator matrix; `revokt-testing`; optional `revokt-bc` | 5 weeks |

About 14 weeks. **M2** (0.4, then 1.0): preloading as a second candidate set, exhaustive re-walk on L1/L2
hits, OneCRL including anchors, denylist, CRLSet, `NOT_ENROLLED` split, the §5.2 residual closed,
eMudhra suite; new `REJECT` rows ship `ALLOW` for one minor. **M3**: CT with `CT_UNVERIFIED`. **M4**:
per-anchor distrust over every walker path. **M5**: MTC through `Evaluator.evaluate` only, routed by `EvaluationRequest.credentialType` before decision step 3, evaluated by its own seam (never a `RevocationEngine`, §3.2).

## 12. Approach 1 vs approach 2 for crema

| | Approach 1 (embed upki via FFI) | Approach 2 (revokt) |
|---|---|---|
| CRLite engine | upstream `upki` (Rust) | our port, two oracles end to end, plus upki as a CI-only second engine |
| What the FFI provides | three functions; config file; no fetch; no Android prebuilt | n/a |
| Still written in Kotlin either way | trust managers, walker, signed fetch, canonical JSON, seeds, policy, Android lifecycle, OneCRL, CRLSet, M3–M5 | same |
| APK impact | ~+320 KB `.so` per ABI, 16 KB page alignment, cargo-ndk matrix | ~+100–150 KB dex; plus the bundled seed in both approaches (1.6 MB `compat`, 6 MB `default`, incompressible) |
| Per-check cost | opens files per check | in-memory columns |
| Failure mode | native crash takes the process | Kotlin exception |

Recommendation: ship **Phase 0 in crema now**; build revokt with the Kotlin engine, which stays
published regardless. **Publication trigger** for `revokt-engine-upki`: if upki's library API
(`RevocationCheckInput::new`, `Store::check`) is stable, the `upki` crate builds for Android targets
under cargo-ndk, and upki gains verify-time CT or MTC evaluation before M3 starts, publish
`revokt-engine-upki` with `revokt-upki-shim` as a separately licensed artifact and re-evaluate a
separate CT/MTC evaluator seam backed by upki for M3 onward; `RevocationEngine` stays CRLite-only (the query ABI is ours, so upki's C ABI is no longer a condition).

## 13. Naming and publishing

**Decision (revision 11): `revokt`.** Verified 2026-10-21: Maven Central `dev.revokt` free;
`revokt.dev`, `.io`, `.org` free; GitHub handle `Revokt` taken (inactive since 2023); `revokt.com` is
a live SaaS called "Revokt" (registered 2026-03-12), unrelated field. Consequences:
1. Register `revokt.dev` and claim `dev.revokt` on Central before the first tag; the repository lives
   under the maintainer's account, never a `Revokt` organisation.
2. README and POM description open with "revokt, a Kotlin TLS revocation library, is not affiliated
   with Revokt (revokt.com)"; no `.com` anywhere in docs or artifacts; the project never uses the
   bare word as a product name in marketing contexts outside the JVM ecosystem.
3. Artifact ids per §3; POM license Apache-2.0 except `revokt-clubcard`.
4. Trademark risk is accepted as low (different field, descriptive compound); revisit only if the
   SaaS enters the TLS or PKI field.
5. The OkHttp and Android README quickstarts declare `revokt-seed-<channel>` beside the binding, so
   the `SeedSource.bundled()` default resolves (§4, §6.5).

## 14. Governance and maintenance

A project with two release-capable maintainers (under the maintainer's personal account, §13); Central Portal publishing from CI only, through a protected release environment with a second maintainer's approval, PGP-signed, with provenance attestations (no OIDC trusted publishing exists for the Portal);
`MAINTAINERS.md` (what keeps working untouched for a year; the pinned-root retention rule); the
§3.1 containment checks on every PR; weekly upstream-drift and `mozilla/crlite` release watchers;
`SECURITY.md` with a 90-day disclosure policy; two-person review on the trust manager, walker,
verifiers and clubcard module; external review before 1.0; **the walker and the `Rule` model get a
dedicated adversarial review before 0.2's walker is coded**, since every review round so far found its hole there.
**Before 0.2 ships, the §9.1 walker fuzzer must pass P1–P8 against the implementation.**

## Appendix A. Verification log (2026-10-21, additions 2026-10-22)

- Remote Settings `monitor/changes`: `cert-revocations` 1792598222216, `intermediates`
  1792465022155, `onecrl` 1792274405312, `ct-logs` 1792002263015.
- `cert-revocations`: 18 records, 9 per channel = 1 full (effective 2026-10-17) + 8 deltas through
  2026-10-21. Signed by `onecrl_202402`; x5u chain leaf P-384 (2026-09-06 to 2026-11-25) →
  `Content Signing Intermediate` (P-384) → `root-ca-production-amo` (RSA-4096, 2024-02-01, SHA-256 `C8A80E9A…A106DB`).
- `onecrl`: 1,901 records; 645 `enabled = false`.
- Filters begin `03 00` (v3) on both channels; `default` 6,006,419 B, `compat` 1,574,015 B.
- Firefox: `crlite_channel` `"compat"` on Android; `crlite_mode` 2; `crlite_timestamps_for_coverage` 1;
  OCSP fallback when CRLite is stale or absent.
- C2SP `upki-revocation@v1.0.0`: the spec says v4; `clubcard-crlite` (the crate upki depends on, `bincode` feature) decodes version bytes 3 and 4, so upki reads Mozilla's v3 filters as served (verified 2026-10-22 in rustls/upki `Cargo.toml` and clubcard-crlite `Encoding::read`); aggregation over covering filters only; selection goes through `index.bin`'s log directory (`Index::check` binary-searches it per SCT and loads only the named filters). **0.2 verification, open**: how `upki-mirror` writes overlapping windows (a full and its deltas sharing boundary timestamps) and how `Index::check` treats overlapping directory entries; the §3.2 selection-equivalence check is stated so that either representation passes.
- `upki.rustls.dev`: GitHub Pages, `default` only, v4 transcode; `upki-mirror` verifies the
  attachment hash, not the content signature. upki FFI: three functions; no Android prebuilt.
  `rustls_upki::Policy` defaults: `missing_data = Error`, `cert_not_covered = Allowed`, `cert_has_no_scts = Allowed`.
- **Producer key bytes** (`mozilla/crlite` `main`): `PrepareSetMember` in `go/storage/certdatabase.go` (about line 278) calls
  `types.NewSerialFromCertificate`, which unmarshals the raw TBS with Go `encoding/asn1` into a
  `RawValue` and keeps `SerialNumber.Bytes` (the INTEGER content bytes, no normalisation); the issuer
  key is `RawSubjectPublicKeyInfo` (the SPKI TLV); certificates are parsed by `ctx509.ParseCertificate`
  (certificate-transparency-go, `"lax"` fallback that allows non-minimal integers) with a zcrypto
  fallback. Go's stdlib `asn1` rejects non-minimal lengths and BER; ct-go and zcrypto reject them first, in
  `ParseCertificate`, and a TBS that passes `ParseCertificate` but fails the stdlib re-parse panics in
  `NewSerialFromCertificate` (killing ct-fetch's insert worker). Neither reaches a filter. A fatal `ParseCertificate` makes both ct-fetch workers' `storeLogEntry` return an error: the RFC 6962 worker sleeps and retries the same range, and the tiled worker halts (`tiled.go`: "(false, err) indicates a fatal error that should halt log ingestion"), so an unparseable entry stalls that log's ingestion rather than being skipped (verified 2026-10-23 at `0082998`). Trillian's CTFE rejects certificate-transparency-go fatal errors at submission (`trillian/ctfe/cert_checker.go`, `x509.IsFatal`, v1.3.2), so a zcrypto-only certificate cannot enter a log running it. `rust-query-crlite` uses `x509-parser`'s
  `raw_serial()`; webpki's `serial()` is also the raw content.
- **upki** (`rustls/upki` tag v1.0.1, whose `Cargo.toml` says 1.0.1; crates.io's latest `upki`/`rustls-upki` is 1.0.0, 2026-10-05; `RevocationCheckInput::new`, `from_certificates`, `Store::check` and `Store::from_config` are `pub` at both; the stock FFI, not used for queries since revision 21, §3.2): `ffi.rs` `upki_check_revocation` wraps `catch_unwind`,
  builds `RevocationCheckInput::from_certificates` (end entity first; `find_issuer` by byte-equal
  subject name among the rest, parsed with `anchor_from_trusted_cert`; `TooFewCertificates` below 2);
  `revocation/index.rs` `Index::check` takes no clock and, with no SCT timestamps, returns
  `NotCoveredByRevocationData`; `rustls-upki` applies `cert_has_no_scts` only in its own verifier and
  fails the handshake on a malformed SCT list (`sct_error`). `revocation/mod.rs`:
  `RevocationCheckInput::new(CertSerial, IssuerSpkiHash, Vec<CtTimestamp>)` and `Store::check` are
  public, which is what `revokt-upki-shim` calls.
- Crates: `clubcard` 0.3.4, `clubcard-crlite` 0.6.2 (MPL-2.0, Exhibit A only); `upki`/`rustls-upki`
  1.0.x; `canonical_json` 0.7.0; the oracle-3a reference crates are pinned exactly when oracle 3a lands with the 0.1
  oracle issue, by `=` requirements in `revokt-oracle/Cargo.toml` and the workspace `native/Cargo.lock`:

  | Crate | Version | sha256 |
  |---|---|---|
  | `x509-parser` | 0.18.1 | `d43b0f71ce057da06bc0851b23ee24f3f86190b07203dd8f567d0b706a185202` |
  | asn1-rs | 0.7.2 | `b7f43a50ac4fdca5df8e885c21b835997f0a1cdee65494a6847694a98652d9d8` |
  | nom | 7.1.3 | `d273983c5a657a70a3e8f2a01329822f3b8c8172b73826411a55751e404a0a4a` |

  The `x509-parser` behaviour §9.2 relies on was probed (the SCT list on 2026-10-22, the TBS tail on 2026-10-24),
  and each part comes from one place in the code:
  - `parse_extension0` discards each extension parser's rest;
  - `map_parser(take(len), …)` discards the rest of the declared region, and `map_parser(length_data(be_u16), …)` the rest of each item;
  - `many1(complete(item))` keeps the items before the first failure;
  - asn1-rs `Header::from_der` takes any long-form length;
  - asn1-rs `TryFrom<Any> for &[u8]` checks the tag number only;
  - `parse_extensions` checks only the tag number of the element after the SPKI: the real extensions of
    `letsencrypt.org-1` under each of `03`, `23`, `43`, `63`, `83`, `C3` and `E3` give 3a its 10 extensions, while
    JDK 11 and 21 parse each and read none (probed 2026-10-24, the review of #37).

  That behaviour becomes a committed `revokt-oracle` test with one case per §9.2 sentence and per D7 SCT entry, landing
  with oracle 3a. The same cases, with §9.2's expected outcomes (∅ on the `3A_HEADER_LAX` and `3A_TBS_LAX` rows), run against
  3b's SCT and TBS walks, so a misreading of §9.2 in either walk fails a case rather than passing as agreement. A bump of any of the three crates is a spec revision. It re-runs that test. If a case changes,
  §9.2 is re-derived, every 3a golden is recomputed, and the diff is reviewed as D2/D3 entries. revokt's rule
  changes only through §9.2, never by following the crate.
- JDK `X509CertInfo` trailing-element behaviour, probed 2026-10-22 on JDK 21 (SUN `CertificateFactory`, each input
  `getEncoded()`-identical).
  - **Accepted:**
    - a trailing NULL or non-TLV bytes after `[3]`;
    - a NULL between `subjectPublicKeyInfo` and `[3]`, which drops the extensions;
    - a NULL, or non-TLV bytes, after the `Extensions` SEQUENCE inside `[3]` and after `extnValue`;
    - a trailing element, or non-TLV bytes, inside `[0]` (revokt keeps `[0]` strict: ct-go flattens `[0]`, reading
      the elements after the INTEGER as TBS fields, while the stdlib serial re-parse is bounded; confirmed below);
    - a stopping element with a non-minimal header (`05 81 00`);
    - a v2 certificate with only `[1]`;
    - constructed `[1]`/`[2]`;
    - `[2]` before `[1]`, or `[1]` twice, either of which drops the extensions;
    - a primitive `[3]`, ignored;
    - two `[3]` elements, the second ignored.
  - **Rejected:**
    - an element after `signatureValue` ("signed overrun");
    - a trailing element in `Validity`;
    - a non-`Extension` element in the `Extensions` SEQUENCE;
    - an element between an extension's OID and its value;
    - a malformed element where the read stops;
    - a v1 certificate with anything after `subjectPublicKeyInfo` ("no more data allowed for version 1 certificate");
    - a v2 certificate with any element after the unique IDs, a NULL or `extensions` ("Extensions not allowed in v2
      certificate");
    - day 00, month 13, hour 24 and second 60 in a time (the day past a month's end is accepted and rolls over);
    - unique-id content `00`, `08 00` or `09 00` (an empty BIT STRING, or padding bits outside 0 to 7).

- Producer `[0]` behaviour, run 2026-10-23 with `mozilla/crlite` `go/types` at `008299826177078097b2539a57564b7926916a2c`
  (Go 1.27.3, certificate-transparency-go v1.3.2, zcrypto `v0.0.0-20260109180747-df961ee46a6c`):
  - a NULL after the version INTEGER inside `[0]` is rejected ("SerialNumber: tags don't match"), so ct-go read the
    NULL as the serial, which shows that the explicit `[0]` is not bounded;
  - a `[0]` holding a fake serial `0f ac` and a complete fake TBS prefix, followed by the real serial `0e a1`, is
    accepted and keyed `0ea1`, the outer serial and the JDK's (`getSerialNumber()` = `0xea1`);
  - a `[0]` holding a complete fake TBS prefix with a different SPKI is accepted. The producer keys the outer serial, the JDK's (the
    `RawValue` re-parse is bounded), but records the inner SPKI as `RawSubjectPublicKeyInfo`, which the JDK does not
    read. As an issuer, such a certificate's children would be keyed under an SPKI the platform never sees.
  - The producer rejects a zero-length explicit `[3]` (`83 00`, `a3 00`): "explicit tag has no child".

  These are the first oracle-4 records; the part-3 issue (#11) commits the CLI and its goldens.

  The probe is committed as the parser's JDK cross-check (`CertificateParserJdkTest` and its `certs/variants/`, on
  `feat/9-der-tbs-parser`, PR #16). `DerValue`'s time forms are stated in §9.2.
- Ktor 3.6.0; CIO 2-arg, TLS 1.2 only. OkHttp 5.5.0 at `lysine-dev/okhttp`; the Android cleaner
  calls the 3-arg method with `"RSA"`; builder TLS fields are `internal`.
- Conscrypt: hostname-only path passes null OCSP/SCT data; `checkCT` only when `host != null &&
  isCTVerificationRequired`; `ConscryptEngineSocket` forwards to the Socket overload;
  `TrustManagerImpl` does not cache validated paths; its intermediate index accepts chains omitting
  the intermediate; `TrustManagerImpl.getAcceptedIssuers()` clones an array computed at construction,
  except over an `AndroidCAStore` KeyStore, where `acceptedIssuers` is null and the `TrustedCertificateStore`
  (the cacerts directories) is re-enumerated on every call.
- AOSP NSC (frameworks/base, not Conscrypt): `RootTrustManager.checkServerTrusted(certs, authType, hostname)` throws `CertificateException("Domain specific configurations require that the hostname be provided")` when `hostname == null` and the config has any `<domain-config>`, which is what `X509TrustManagerExtensions` reaches, so the null-host retry of decision step 4 is unavailable for such apps; `RootTrustManager.getAcceptedIssuers()` delegates to the
  default config's `NetworkSecurityTrustManager`, which computes `mIssuers` lazily from
  `DirectoryCertificateSource` (directory listing and `CertificateFactory` reads on the first call per
  process, process-wide singletons for the system and user sources; `NetworkSecurityConfig` also
  caches `mAnchors`) and clones the cached array thereafter. On a trust-store change the system pushes
  `handleTrustStorageUpdate()` into every running process (`ApplicationConfig` → config, sources,
  `NetworkSecurityTrustManager` and `TrustManagerImpl`), clearing those caches; no app receiver is
  involved, and `android.security.STORE_CHANGED` is a protected broadcast.
- SunJSSE: `SSLContextImpl.chooseTrustManager` wraps a plain `X509TrustManager` in
  `AbstractTrustManagerWrapper` (algorithm constraints on both paths, endpoint identification on the
  engine path); `X500Name.equals` and BoringSSL `X509_NAME_cmp` compare canonicalised names;
  SunJSSE's `AlgorithmId` normalises NULL parameters; SunEC pure Java since JDK 16, no brainpool since 15.
- Crypto: ECDSA public-key recovery (SEC 1 §4.1.6); RSA duplicate-signature key selection
  (Blake–Smart; SunRsaSign accepts any exponent for moduli ≤ 3072); ML-DSA in X.509 is RFC 9881;
  JDK 24 ships ML-DSA; Conscrypt does not; composite signatures are not one JCA operation.
- Kotlin: `kotlin.time.Clock` stable since 2.3; `kotlin.concurrent.atomics` still experimental;
  kotlinx-serialization-json cannot reject duplicate keys.
- Fuzzing: ClusterFuzzLite and OSS-Fuzz need a static entry point; OSS-Fuzz admission requires usage.
- MTC: `draft-ietf-plants-merkle-tree-certs` -05; Chrome rollout with Cloudflare since Feb 2026.
- Mozilla producer keyability, verified 2026-10-22 in `mozilla/crlite` `go/types.go` (package `types`) and `certificate-transparency-go` `asn1/asn1.go`, `x509/x509.go` (master): `ParseCertificate` tries ct-go then zcrypto and keeps whichever returns a certificate; `NewSerialFromCertificate` re-parses `RawTBSCertificate` with stdlib `encoding/asn1` into `{Raw RawContent; Version RawValue "optional,explicit,default:0,tag:0"; SerialNumber RawValue}` and **panics** on failure (so a certificate the re-parse rejects never reaches a filter), keying on `SerialNumber.Bytes`; ct-go's `parseTagAndLength` rejects non-minimal tags, indefinite lengths, superfluous leading length zeros, long-form lengths under 128 and lengths ≥ 2^31 regardless of `lax`; `lax` relaxes `checkInteger` (non-minimal INTEGER content), OID and PrintableString parsing; Go's struct parse ignores trailing SEQUENCE elements; ct-go's SCT-list branch (`asn1.Unmarshal(e.Value, &out.RawSCT)` then `tls.Unmarshal`) reports every error through `NonFatalErrors`, `ParseCertificate` returns the certificate when `ctCert != nil`, and both ct-fetch workers (`rfc6962.go` `storeLogEntry`, `tiled.go`) log "Nonfatal parsing error" and continue to `PrepareSetMember`; zcrypto's only length leniency is `AllowPermissiveParsing`, which crlite never sets.
- Revision 34 probes, run 2026-10-23 against the oracle-4 binary at `0082998` (the cohort's scripts and outputs are kept
  with the #11 records). Every JDK probe below ran on JDK 17.0.21, 21.0.13 and 27 `SUN`. The verdicts and, where
  recorded, the `getTBSCertificate()` outputs agree across the three, except where noted; the JDK 11 results are
  the last item. The matrix replay re-checks them once the D7 entries land:
  - **Envelope re-encodings**, applied to an RSA and an EC leaf. In each case `generateCertificate` accepts the
    certificate, `getEncoded()` returns the input bytes and `verify(issuerKey)` passes:
    - a non-minimal length on the outer `signatureAlgorithm` header (`30 0a` → `30 81 0a`);
    - a non-minimal length on the `signatureValue` header (`03 47` → `03 82 00 47`);
    - the outer NULL parameters flipped;
    - for RSA only, an unused-bits octet of 1, with or without the padding bit set (the JDK clears it before
      verifying).

    Also verifying and kept by `getEncoded()`: the `tbsCertificate` header as `30 83 00 03 94`, `30 84 00 00 03 94` or
    indefinite closed by `00 00` (the JDK verifies over the TBS re-encoded with a minimal header), and the outer
    AlgorithmIdentifier indefinite (including `30 80 <OID> 05 80 00 00 00 00`) or with `06 81 08` or `05 81 00`
    inside a definite one. Under an indefinite TBS, an indefinite header on any element whose ancestors up to the TBS
    are all indefinite verifies, primitive ones included (Validity, a subject RDN chain, `[0]`, `[3]` down to an
    `extnValue` as `04 80 … 00 00`), because `DerIndefLenConverter` re-encodes it; a non-minimal definite header
    there, or anywhere in the TBS, breaks the signature, and so does an indefinite header under a definite parent
    (JDK 17 and 21 reject some of these in `generateCertificate` and the rest fail `verify`; JDK 27 parses them all
    and `verify` fails).
    An indefinite outer AlgorithmIdentifier holding a non-minimal OID header (`30 80 06 81 08 … 00 00`) is rejected by
    `generateCertificate` ("Too short"), and one holding `05 81 00` is rejected ("extra data").
    The re-encoding rule of §9.2 reproduces `getTBSCertificate()` on every input the JDK verifies. Every probed JDK
    rejects a constructed `signatureValue`, and JDK 17, 21 and 27 an indefinite one; the JDK rejects a fourth
    `Certificate` element and a high-tag signature OID, and normalises the outer `Certificate` header and trailing
    bytes away in `getEncoded()`. Conscrypt was not probed; BoringSSL parses strict DER.

    Oracle 4 rejects the two header cases ("non-minimal length", "superfluous leading zeros"). The NULL flip is keyed
    through zcrypto only, because ct-go rejects "mismatching signature algorithm identifiers". The JDK re-encodes the
    outer `Certificate` header, so that header is not a vector.
  - **Content the JDK accepts and the producer rejects**: non-zero padding bits in the `signatureValue` or
    `subjectPublicKey` BIT STRING; a day past the month's end ("day out of range"); a `GeneralizedTime` fraction;
    invalid UTF-8 in a `UTF8String`; a BOOLEAN `01`; an EC point off the curve; secp256k1; RSA e < 0 and e longer than
    64 bits. The producer also rejects an OID arc of 2^31 or more, including in an unknown extension ID, and a
    constructed `extnValue` (JDK acceptance of these two not probed).
  - **Content certificate-transparency-go keys outside X.690 DER**: a negative serial, a 21-octet serial, an explicit
    `critical FALSE` and `cA FALSE`, an explicit v1, `*` and `&` in a PrintableString, and an unsorted multi-valued
    RDN. ct-go also keys SPKIs it does not parse (RSA-PSS, ML-DSA, X25519) without inspecting them.
  - **CT sample**: 200 230 entries from 14 RFC 6962 and 4 static-CT CRLite-enrolled logs, comprising 104 800
    precertificates and 95 430 final certificates under 296 issuer CNs (153 532 unexpired). All were keyed through
    ct-go, none only through zcrypto, and none deviated from a strict DER profile; the revision-34 consistency round's re-scan of the 159 270 RFC 6962
    entries found no K5 attribute type, repeated extension or K8 SAN, AKI, CRLDP, AIA, nameConstraints or
    subjectInfoAccess shape outside the profile. That puts a 95 % upper bound of about 2·10^-5 per unexpired entry.
  - **Precertificates**: `rfc6962.go` (`storeLogEntry`, `types.ParseCertificate(rawLogEntry.Cert.Data)`, which holds
    the precertificate for a precert entry) and `tiled.go` (`logEntry.PreCertificate`) parse the logged
    precertificate, not the final certificate.
  - **JDK 11.0.32** `SUN` (below the floor since revision 38; kept as the record), on the same JDK probe sets: it
    verifies 31 of the 69 inputs JDK 17 verifies, and none that JDK 17 does not (revision 35 found one form outside
    these sets that it alone verifies, below). On each of the 31, `getTBSCertificate()` is byte-identical to JDK 17's.
    - Under a definite TBS, `generateCertificate` rejects every non-minimal definite length ("Redundant length bytes
      found", "Should use short form for length"): the `tbsCertificate`, outer `Certificate`, `signatureAlgorithm`
      and `signatureValue` headers, and every probed TBS field header. Under an indefinite TBS, a non-minimal serial
      or SPKI header inside it parses and fails `verify`, as on JDK 17.
    - `generateCertificate` rejects an indefinite element on the indefinite chain below an indefinite TBS (the
      Validity, subject, `[0]` and `[3]` chains), and an indefinite NULL inside an indefinite outer
      AlgorithmIdentifier.
    - Still verifying: the `tbsCertificate` header indefinite; the outer AlgorithmIdentifier indefinite with definite
      content; the outer NULL parameters flipped; an RSA unused-bits octet of 1, with or without the padding bit;
      and an indefinite outer `Certificate` header or trailing bytes, which `getEncoded()` normalises away.
    - Of the indefinite headers under a definite parent, it rejects only an indefinite `[3]` in
      `generateCertificate`; the rest, including those JDK 17 and 21 reject, parse and fail `verify`.
- The trailing-element rule's stop element with a multi-octet identifier, probed 2026-10-24 on JDK 11.0.32, 17, 21
  and 27 (the review of #41, #42):
  - The inputs: `9f 01 00`, `1f 01 00`, `9f 01 01 00`, `bf 02 01 00`, or `9f 1f` followed by 31 octets, each placed
    before the `[3]` of `letsencrypt.org-1`; and `9f 03` or `bf 03` holding its Extensions SEQUENCE.
  - JDK 17, 21 and 27 reject each one ("Tag number over 30 … is not supported"), and revokt rejects each with
    `STRUCTURE`.
  - JDK 11 reads the identifier as one octet and accepts each, with no extensions. It rejects such an element whose
    length is non-minimal, has five length octets, is indefinite, or runs past the TBS.
  - Oracle 4 rejects the forms whose tag number is below 31 ("non-minimal tag") and keys `9f 1f`.
  - 3a reads extensions from `9f 03`, `bf 03`, `9f 01 01 00` and `bf 02 01 00` (taking the last two as unique IDs).
  - These forms are why the floor moved to 17 in revision 38, rather than the parser being loosened for JDK 11.
- Revision 35 probe, run 2026-10-24 (the independent review of #24, then the maintainer's follow-up), on JDK 11.0.32
  `SUN` unless noted. JDK 11 is below the floor since revision 38, and these results are kept as the record:
  - An indefinite `signatureValue` (`03 80 … 00 00`) verifies when its content, read from the unused-bits octet on, is
    a chain of TLVs with minimal headers: 17 of 4 000 and 7 of 1 500 P-256 signatures re-signed over the
    `letsencrypt.org-1` TBS, 0 of 1 500 RSA-2048. `getEncoded()` keeps it. JDK 17, 21 and 27 verified 0 of 4 000.
  - Writing that chain's first header non-minimally (`00 81 30` for `00 30`) does not verify (3 of 3).
  - A constructed `signatureValue`, definite or indefinite, is rejected by `generateCertificate` on JDK 11 and 17
    ("not a bit string").
- Revision 39 probe, run 2026-10-25 over the committed replay corpus (1 803 inputs) on JDK 17, 21 and 27 `SUN`, each
  input's `verify` run against its issuer from the fixture chain:
  - On all three JDKs, `generateCertificate` accepts an indefinite TBS holding a non-minimal serial header (`02 81`,
    `02 84 00 00 00`) or SPKI header (`30 83 00 …`), on each of the three leaves the D7 envelope cases use. `verify`
    fails ("Signature does not match"), and neither 3a nor 3b locates them: 3b fails with "non-minimal length under an
    indefinite element".
  - JDK 27 alone also accepts a definite TBS holding an indefinite Validity, on the same three leaves. `verify` fails,
    3a rejects it, and 3b's walk does not locate it. Oracle 4 rejects its `canon` ("Validity: indefinite length found
    (not DER)").
  - No other platform-accepted input lacks a raw-byte reference. `getEncoded()` differs from the input on 18 inputs: a
    non-minimal outer `Certificate` header, re-encoded minimally, and trailing bytes, dropped.
- Remote Settings base paths, verified 2026-10-22: `https://firefox.settings.services.mozilla.com/v1/` is the Kinto API (`http_api_version 1.23`, Firefox's `services.settings.server`); `/v2/` is a distinct newer server (`project_version 0.0.1`, built 2026-10-22, 235 `monitor/changes` entries) serving the same `changeset` shape and the same attachments base URL; both answered the `cert-revocations` changeset with 200. `metadata.signature` carries `ref`, `x5u`, `mode`, `type`, `signature`, `signer_id`, `public_key`.
- Android toolchain fact, verified 2026-10-24: a library built with Kotlin 2.4 needs AGP 8.5.2 or later
  (developer.android.com, "AGP, D8, and R8 versions required for Kotlin versions"), and D8 from AGP 8.8.1 is tested
  against OpenJDK up to 23 (the AGP 8.8 release notes). That D8 from AGP 8.5.2 to 8.8.0 dexes Java 17 class files is
  not sourced here: a consumer fixture built with AGP 8.5.2 confirms it with the 0.3 Android modules, and if it fails,
  the stated floor for Android consumers rises to the first AGP that passes. The 0.3 Android instrumented tier runs the
  artifacts on every API level it covers.
- Android API facts, verified 2026-10-22: `CompletableFuture.completeAsync`, `orTimeout`, `completeOnTimeout`, `failedFuture` and `delayedExecutor` were added at API 31 (API-31 diff page), outside core-library desugaring; libcore's `java.net.HttpURLConnection` declares no `setAuthenticator`; `ApplicationConfig.getTrustManager()` creates one `RootTrustManager` per config under `ensureInitialized()` and `RootTrustManagerFactorySpi.engineGetTrustManagers` returns that instance; `ApplicationConfig.getConfigForHostname` lowercases and strips a trailing dot; NSC pins are `NetworkSecurityTrustManager.checkPins` on every overload, absent without a `<domain-config>`.
- OkHttp (master `ConnectPlan.kt`, `RealConnection.kt`, `CertificatePinner.kt`): the `Handshake` is built with a lazy lambda around `certificateChainCleaner.clean(peerCertificates, host)`, `CertificatePinner.check` returns before invoking it when no pin matches, and `RealConnection.supportsUrl`/`certificateSupportHost` read `handshake.peerCertificates` for HTTP/2 coalescing; `isEligible` refuses coalescing unless the address's `hostnameVerifier === OkHostnameVerifier`.
- eMudhra: fixture URLs live; CVE-2026-111943; Go 1.27.3; Firefox 158.0.1; NSS 3.131.1.
- Names: §13; `repo1.maven.org` was the authority.
- Path validation: both SunJSSE and BoringSSL enforce RFC 5280 name chaining; AKI↔SKI is mandatory
  for Web PKI certificates under the CA/Browser Forum Baseline Requirements; `SunCertPathBuilder` has
  no candidate budget and backtracks through all name-matching candidates; `CertPath.getCertificates()`
  excludes the trust anchor.
