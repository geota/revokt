# revokt divergences from reference implementations

A running log of every known place where revokt behaves differently from a reference implementation, and why.
The point is to re-evaluate each one as revokt and the references change. Moved here from the maintainer's working
notes on 2026-11-16 (#217); decisions are in [DECISIONS.md](DECISIONS.md).

**Updating it:**
- Add a row whenever a review, an audit or a decision finds a difference.
- Never delete a row; when a difference is removed, set its status to `aligned` and say in which commit.
- When a reference version is bumped (for example the upki pin in `gradle/oracle-matrix.properties`), re-check every
  `open` and `kept` row against the new version.

**References, with the version each row was checked at:**
- **upki:** rustls/upki v1.0.1 (9821cce), revokt's second engine. It builds paths with rustls-webpki
  0.104.0-alpha.7 (`upki/Cargo.toml:32`; its Cargo.lock gives that version to `upki` and `rustls-upki`, and carries
  0.103.15 only as rustls's own dependency) and reads PEM with rustls-pki-types 1.15.1. Before #217 this log and the
  spec named 0.103.15, the wrong tree; rows E3, E8, E9, E10, E11 and X14 were re-read against 0.104.0-alpha.7 on
  2026-11-16. upki has no content-signature, x5u or chain-walker code of its own, and webpki builds its paths. v1.0.3
  is released and not yet admitted (#240); see the log entry of 2026-11-16 for what it changes.
- **Firefox:** mozilla-central, as fetched on the date in the row. `ContentSignatureVerifier.cpp`,
  `AppTrustDomain.cpp`, `nsSecurityHeaderParser.cpp`, `RemoteSettings.worker.mjs`, `RemoteSettingsClient.sys.mjs`,
  and for x5u `ReadChainIntoCertList`. Rows that say "cac25a6" were checked at that commit.
- **Signer:** Mozilla Remote Settings, `kinto_remote_settings/signer/serializer.py`. It defines the bytes that get
  signed.
- **NSS:** `dsautil.c` (ECDSA raw to DER).
- **canonical_json:** the crate, `=0.7.0` (the #97 oracle).
- **JDK:** the platform TLS stack revokt runs on (JDK 17/21/25/27, SunEC, Conscrypt 2.7/2.8).

**Columns:**
- **Dir:** `stricter`, `looser` or `different`, from revokt's side.
- **Status:**
  - `kept`: deliberate, with a justification;
  - `open`: undecided, or a fix is pending;
  - `aligned`: removed; the row is kept for history.
- **Decided by:** maintainer (date), reviewer, or spec (§, revision).
- **Code refs:** `file:line` at the commit named; lines drift, so re-check them against main.

**Verified vs inferred.** Every row says how the reference behaviour was established: `src` (source read, file and
line), `probe` (run against the real implementation) or `memory` (not checked; treat it as a lead, not a fact).

---

## 1. x5u PEM reader

Code: `revokt-engine/src/commonMain/kotlin/dev/revokt/engine/parse/X5uPem.kt` (PR #164, e92566f). Reference:
rustls-pki-types 1.15.1 `pem.rs` and `base64.rs`, src and a probe through a scratch Rust harness. Firefox
`ReadChainIntoCertList` at cac25a6, src.

| # | revokt | Reference | Dir | Why | Decided by | Status |
|---|---|---|---|---|---|---|
| P1 | The 64 KiB cap (`MAX_X5U_BYTES`) is checked before any split or decode (`X5uPem.kt:71`) | rustls-pki-types: 256 MiB per section | stricter | Bounds memory on an unsigned download | spec §6.5 caps table, `MAX_X5U_BYTES` | kept |
| P2 | Inside a block, padding must be canonical and leftover bits zero | rustls-pki-types accepts missing padding and drops leftover bits; Firefox accepts unpadded base64 | stricter | None for security: every certificate is path-validated to the pinned root | maintainer 2026-11-06: **match fully** | aligned (#165, a10583e) |
| P3 | Skips malformed BEGIN lines, text after BEGIN, and an unterminated other-label block at the end of the body | rustls-pki-types treats all three as errors | looser | Accidental (follow-up nit in the #164 review) | maintainer 2026-11-06: match fully | aligned (#165, a10583e) |
| P4 | Rejects `-----BEGIN CERTIFICATE--- --` | rustls-pki-types accepts it | stricter | Accidental | maintainer 2026-11-06: match fully | aligned (#165, a10583e) |
| P5 | A nested BEGIN inside a block is a BASE64 failure | rustls-pki-types concatenates the two blocks | stricter | Arguably safer; under "match fully" it would become rustls's behaviour | maintainer 2026-11-06: match fully | aligned (#165, a10583e) |
| P6 | Reads every CERTIFICATE block | upki's mirror calls `from_pem_slice`, which takes the first block only | different | upki reads one certificate per CSV row; an x5u file is a whole chain. Firefox reads every block | issue #106 | kept |
| P7 | Firefox: exact boundary lines, no whitespace inside the base64 | revokt follows rustls-pki-types (spaces after BEGIN, END matched by prefix, whitespace skipped) | looser than Firefox | The maintainer chose upki's library as the reference over Firefox | maintainer 2026-11-06 | kept |
| P8 | Text, blank lines and other labels outside blocks are skipped; LF, CR and CRLF line endings; any line length | Same in rustls-pki-types and Firefox | none | Aligned in #164 (it was strict at 8fe2433) | maintainer 2026-11-06 | aligned (e92566f) |

## 2. Certificate extension readers

Code: `revokt-engine/src/commonMain/kotlin/dev/revokt/engine/parse/ExtensionValues.kt` (PR #164, e92566f). Reference:
rustls-webpki 0.104.0-alpha.7, src (re-read 2026-11-16 for #217; the rows were first read against 0.103.15); the
JDK, by probe.

| # | revokt | Reference | Dir | Why | Decided by | Status |
|---|---|---|---|---|---|---|
| E1 | Checks keyUsage keyCertSign on the x5u chain | webpki never reads keyCertSign; it reads keyUsage only for CRL signing | stricter | Required by spec | spec §7.1 | kept |
| E2 | A non-minimal OID spelling in an extension is MALFORMED (fails closed) | webpki treats it as an unknown extension, an error only if critical | stricter | Stops a respelled OID from hiding basicConstraints or keyUsage | #164 review | kept |
| E3 | pathLen is accepted up to 2^31−1 by the parser; the x5u chain fails one above 127 (§7.1) | webpki accepts 0 to 255 only (`u8::from_der`, `verify_cert.rs:435-436`) | looser | RFC 5280 allows the full range, and the 0.1 K8 grammar did too | #164 review | kept |
| E4 | `dnsNames` returns raw IA5 strings | webpki's `valid_dns_names` drops non-DNS-syntax entries (NUL, space, empty) | looser | None yet; it doesn't matter for #126's exact match | — | open: #120 (filter like webpki, or document it) |
| E5 | keyUsage BIT STRING with untrimmed trailing zero bits is accepted (`03 02 00 04`) | webpki, the JDK and Go accept it; mozilla::pkix not checked (memory) | none known | Matches the references | #164 review | kept |
| E6 | K8 (the CRLite leaf keyability grammar) reads non-minimal lengths leniently (`strict = false`) | webpki rejects them everywhere (`der.rs:166-190`) | looser | §9.2 parser contract: on the CRLite leaf, revokt must be at least as lenient as the platform TLS stacks. The x5u reads are strict | spec §9.2 | kept |
| E7 | BIT STRING with non-zero padding bits (`03 01 05`) is MALFORMED | The JDK reads a value; Go and webpki reject it | stricter than the JDK | DER X.690 §11.2.1 | #164 review | kept |
| E8 | BOOLEAN `cA = 0x01` is MALFORMED | The JDK reads TRUE; webpki requires `00`/`FF` (`der.rs:446-462`) | stricter than the JDK | DER; matches webpki | #164 review | kept |
| E9 | The TLS-side parser reads any non-zero critical octet as TRUE (`CertificateParser.kt:389`); the x5u chain requires `00`/`FF` (`X5uDer.kt`, `criticalIsDer`), and so does K8 for its extensions | webpki requires `00`/`FF` for the flag too: `Extension::from_der` reads it with `bool::from_der` (`x509.rs:37`, `der.rs:446-462`), now checked | looser on the TLS parser only | §9.2: the CRLite leaf parser is at least as lenient as the platform TLS stacks; the x5u chain matches since #170 | spec §9.2, §7.1 | kept (TLS parser); aligned on the x5u chain (#170) |
| E10 | GeneralName identifier octets: exactly `a0 81 82 a3 a4 a5 86 87 88` | webpki, the same (`subject_name/mod.rs:290-311`) | none | Aligned in #164 | #164 review | aligned (e92566f) |
| E11 | Duplicate extension → DUPLICATE (FAILED for #126) | webpki rejects duplicates of the extensions it tracks (`set_extension_once`, `x509.rs:49-62`); the JDK rejects them at parse | none | — | #164 review | kept; #126 also rejects a duplicate of any OID |

## 3. Content signature

Code: `revokt-engine/src/commonMain/kotlin/dev/revokt/engine/verify/ContentSignature.kt` and `RawSignature.kt`
(#163, merged 8f4e442). References: Firefox and NSS sources fetched 2026-11-06, the signer's `serializer.py`.
upki has no equivalent.

| # | revokt | Reference | Dir | Why | Decided by | Status |
|---|---|---|---|---|---|---|
| C1 | An entry is tried when its `mode` is absent, `null` or `p384ecdsa`; any other value is skipped, `""` and non-strings included | Firefox: `mode && mode !== "p384ecdsa"` skips a truthy other mode and tries a falsy one (`RemoteSettingsClient.sys.mjs:1103`) | stricter (a falsy non-absent mode only) | revokt verifies P-384 only, so an unknown mode gains nothing; requiring `mode` had no security reason (the algorithm is never derived from it) | maintainer 2026-11-06 (keep §7.1); reversed by the lead on #223 under the audit (A-1) | aligned for an absent mode (24f2656); kept for `""` and non-strings |
| C2 | Signature text is base64url without padding only | Firefox's header parser rejects `=` and `/` but accepts `+` | stricter | Mozilla emits base64url | #163 builder, src | kept |
| C3 | Raw signature: a non-empty even length ≤ 132 bytes | Firefox and NSS: any non-zero even length, no maximum | stricter (the cap) | 132 is P-521's size; the cap bounds work | #163 | kept |
| C4 | Unused tail bits of the base64 are not checked, so several texts give one signature | Firefox decoder (not compared) | — | Harmless: the signature text is never an identity or a cache key (KDoc rule) | #163 review | kept |
| C5 | Record ids sort by Unicode code point | The signer sorts by code point (Python `sorted`); Firefox JS compares UTF-16 units | differs from Firefox | The signer defines the signed bytes. Kinto ids are ASCII (memory, not checked) | #163 review | kept |
| C6 | Tombstone = Python-truthy `deleted` | The signer is the same; Firefox JS also treats `[]` and `{}` as deleted | differs from Firefox | The signer defines the signed bytes | #163, maintainer parity | kept |
| C7 | No leaf curve check (P-256/384/521) | Firefox: the same (`CheckECDSACurveIsAcceptable`) | none | Firefox parity | maintainer 2026-11-06 | aligned (87e294b) |
| C8 | High-s ECDSA accepted | NSS and SunEC accept it; real Mozilla data has s > n/2 | none | Rejecting it would reject Mozilla's own data | #163 review, probe on ct-logs | kept |
| C9 | Reads `metadata.signatures[]`, as Firefox does; `metadata.signature` is no longer read | Firefox reads `metadata.signatures` (an array); real changesets carry both | none | — | maintainer 2026-11-13 (rev56) | aligned (#198) |
| C10 | signatures[]: the first 4 entries tried in array order and the rest never read, an already-fetched x5u is reused and a failed one is not retried, and when none verifies the last error is reported | Firefox tries every entry and throws the first error (`RemoteSettingsClient.sys.mjs:1100-1132`) | stricter, bounded | A hostile changeset cannot force unbounded x5u fetches and chain validations; ignoring the rest, rather than failing on a fifth entry, keeps a client working if Mozilla ever publishes more | lead under the maintainer's signatures[] decision, 2026-11-13 (#188, #191); the 2026-11-16 design audit (A-1) | kept, the fifth entry no longer fails (1a08929, #223) |

## 4. Canonical JSON

Code: `revokt-engine/src/commonMain/kotlin/dev/revokt/engine/json/` (#97). Reference: `canonical_json` 0.7.0, src
and a 200k-input differential.

| # | revokt | Reference | Dir | Why | Decided by | Status |
|---|---|---|---|---|---|---|
| J1 | A duplicate object key is `DUPLICATE_KEY` (rejected) | `canonical_json` accepts it (4 of 4,198 vectors; all 7,295 differences in the 200k differential) | stricter | Two documents with the same bytes could mean different things; fails closed | #97 review | kept |

## 5. CRLite engine (filters, index, query, issuer, SCTs, fetch)

| # | revokt | Reference | Dir | Why | Decided by | Status |
|---|---|---|---|---|---|---|
| Q1 | A filter decodes by its own prefix, whatever the declared format | upki, the same | none | An extra rule was removed in #95 to match upki | #95 review | aligned (de48c02) |
| Q2 | `coverageEndMillis` for an open-ended `u64::MAX` window is clamped to `Long.MAX_VALUE` | upki uses u64 natively | different (representation) | Kotlin `Long` is signed | #95 review | kept |

### From the upki audit (2026-11-06)

**Scope and sources:**
- revokt: main at 45de107, spec revision 51.
- upki: v1.0.1 (9821cce), with clubcard 0.3.4, clubcard-crlite 0.6.2, rustls-webpki 0.104.0-alpha.7 (upki's lockfile) and bincode 1.3.3.
- C2SP `upki-revocation.md` at 7e6ded4.
- The live mirror `upki.rustls.dev`, read 2026-11-06.
- Everything below is src (code read) unless it says otherwise. The auditor ran nothing from upki.

**Short forms used in the code refs:**
- `BincodeV3.kt`, `Codec.kt`, `CrliteQuery.kt`: under `revokt-clubcard/src/commonMain/kotlin/dev/revokt/clubcard/`.
- Every other `.kt` file: under `revokt-engine/src/commonMain/kotlin/dev/revokt/`.
- `index.rs`, `fetch.rs`, `mod.rs`: `upki/src/revocation/`.

**Already covered by the recorded differential,** so not listed:
- the per-filter results (5,719 goldens, v3 and v4);
- the v3/v4 transcode check;
- the index.bin writer (byte-identical) and reader.

**Not covered:**
- upki's `Index::check`, i.e. filter selection and aggregation;
- upki's error mapping (the shim is a skeleton);
- oracle 3c (webpki's view of the SCTs);
- generations with more than one filter;
- fetching and the manifest.

| # | Area | revokt | upki | Dir | Why | Decided by | Status |
|---|---|---|---|---|---|---|---|
| Q3 | v3 filter caps | Rejects approx_m/exact_m/offsets > u32, rank > 255, > 255 columns (`BincodeV3.kt:50,90-97,150`) | `usize` via serde, no caps | stricter | No real filter is near them; availability only | code KDoc only (`BincodeV3.kt:79-84`), not in the spec | open: add to the §6.3 strictness list (#160) |
| Q4 | Filter decode | Rejects rank > columns, `inverted` ∉ {0,1}, unsorted or duplicate block index, duplicate coverage log id (`Codec.kt:129,176,212`; `CrliteQuery.kt:108`) | rank > columns panics at query; `inverted` read as `!= 0` (clubcard-crlite `codec.rs:144`); duplicates overwrite | stricter | revokt is the safer side | spec §6.3 | kept |
| Q5 | Filter selection | Every filter is consulted by its own coverage (`CrliteGeneration.kt:48-64`) | Only the filters named by a matching index.bin entry (`index.rs:255-301`) | different | §3.2 selection equivalence. The loader builds every index it installs, so no install path checks one; `C2spIndex.inconsistencies` remains as the tests' oracle against upki's selection | spec §3.2 | kept (#218 cut the MIRROR and SYSTEM sources) |
| Q6 | Decode timing | Every filter is decoded at `prepare`, so a query can't fail on data (`CrliteGeneration.kt:78-88`) | Lazy; REVOKED vs error depends on SCT and entry order (`index.rs:310-334`) | different | Deterministic | spec §6.3 (partly) | kept |
| Q7 | index.bin magic | Only `upkiidx1` (`C2spIndex.kt:96,122`) | Also reads legacy `upkiidx0` (`index.rs:88-105,289-292`), which upki-1.0.0-beta.1 wrote (beta.2 not checked) | stricter | C2SP allows rejecting it. A system cache from an early beta is unreadable until the next `upki fetch` | not in the spec | open: document in §3.2/Appendix A (#160) |
| Q8 | index.bin validation | Rejects the whole file on: unsorted or duplicate log ids, out-of-bounds or overlapping sections, filter_idx ≥ the name count, non-zero name padding, an empty section past the end of the file, an illegal filename (`C2spIndex.kt:140-223`) | Checks the header and table fit only; the rest is checked lazily or never (`index.rs:84-140,259-301,351-363`) | stricter | Fails closed | spec rev48, "C2SP index rules for every source"; the individual rules are in code only | kept |
| Q9 | index.bin size cap | 1 MiB (`C2spIndex.kt:94,114`) | None | stricter | The live index is about 63 KB (estimate) | spec §3.2 | kept |
| Q10 | Issuer choice | The issuer on the verified path (§6.1) | The stock `from_certificates` takes the first byte-equal subject (`mod.rs:183-213,348-368`); webpki's verified path uses the immediate issuer | different (from the stock API) | revokt calls upki through the shim, never the stock API | spec §3.2 | kept |
| Q11 | SCT parsing | Keeps items with any version and empty signatures, keeps the items before the first failure, and takes the union of several SCT extensions (`SctList.kt:91,100`; `CertificateParser.kt:333-335`) | webpki rejects version ≠ 0, empty signatures (`sct.rs:64-73`) and a second SCT extension (`x509.rs:49-62`); rustls-upki fails the handshake | looser (queries more) | The more-checking direction; the SCTs sit inside the CA-signed leaf | spec §9.2 | kept; oracle 3c not yet built |
| Q12 | **Manifest entry cap** | `MAX_MANIFEST_ENTRIES` was 32, and is 256 since rev56 (`RevoktLimits.kt`) | No cap (`fetch.rs:202-212`). **The live manifest lists 40 files (1 full + 39 deltas, 14.3 MB)** | stricter | Its premise ("about four days" of deltas, §7.2; about 8 deltas in §6.4's memory table) no longer held | maintainer 2026-11-06: 32 → 256 (rev56) | decided; moot with the MIRROR source cut (#218) |
| Q13 | **Manifest protocol** | §7.3 says only "Protocol as `upki fetch`" | `GET {base}manifest.json` with If-Modified-Since from the file's mtime, reusing it on 304 (`fetch.rs:44,64-117`). JSON: `generated_at` (u64 s), `comment` (required), `files` (alias `filters`), each `{filename, size, hash hex}` (`mod.rs:86-158`). 30 s timeout (`fetch.rs:479`); reqwest follows up to 10 redirects (checked in 0.12.28, not 0.13.0). C2SP leaves the manifest out of scope | — | Accidental gap. The pin doesn't cover it, and the live mirror runs upki main, not v1.0.1 | maintainer 2026-11-06, 2026-11-13: the grammar went into §7.3 and redirects are followed by one `RedirectingFetcher` (rev56, rev58) | decided; moot with the MIRROR source cut (#218) |
| Q14 | Mirror freshness | `Freshness.MANIFEST_LAST_MODIFIED` (`Freshness.kt:15`) is never defined | `generated_at` is when the mirror job ran (every 6 h by cron), not how old Mozilla's data is | — | Accidental. ageMillis wouldn't show the data's age | maintainer 2026-11-06: the newest coverage end (rev56, §7.2) | decided; moot with the MIRROR source cut (#218) |
| Q15 | Filename validation | Validates every manifest and index filename per C2SP filename rules before it is used (`C2spIndex.kt:105`) | not compared here | stricter | Defence in depth | spec §6.3 Hardening | kept |
| Q16 | Failed index rebuild | A file that can't be stored or decoded fails the sync loudly | A filter that cannot be indexed leaves the old index.bin in place, and the sync still succeeds (`fetch.rs:337-345`) | stricter | Loud vs silently stale | maintainer 2026-11-06: mirror names over 32 bytes get §6.5's derived names, with the collision check before any fetch (rev52) | decided; moot with the MIRROR source cut (#218) |
| Q17 | Hash check, body caps | Hashes before writing; per-kind body caps (§6.5) | Writes in place and then hashes, leaving a bad file under its name; no body cap (`fetch.rs:304-326`) | stricter | Security and availability, on upki's side | spec §6.5 | kept |
| Q18 | Oracle transcoder wording | §3.2 says the oracle "pins upki-mirror's transcoder", but the oracle does a bare `to_bytes(V4)` (`native/revokt-oracle/src/main.rs:107-111`) | upki-mirror v1.0.1 doesn't transcode; upki main added it in c2ba5e3 (2026-10-21) and also sorts the coverage | — | Inaccurate wording; bytes differ, verdicts can't | — | open: fix the wording (#160); sort coverage in the oracle if byte identity matters |
| Q19 | Overlapping windows (Appendix A open item) | — | `upki fetch` writes the index, one entry per (log, filter) in manifest order; `check` queries each matching filter once (`index.rs:185-234,288-341`) | none | The answer to the open item | — | open: close the item in #160 |
| Q20 | Cache path | The §4 example uses `c2spCache("/var/cache/upki")`, and the spec doesn't say whether `revocation/` is appended | Data lives in `<cache_dir>/revocation/`; the root is `/var/cache/upki` on Linux, `/Library/Caches/dev.rustls.upki` on macOS (`lib.rs:83-85,154-169`) | different | As written, the example would have found no index.bin | maintainer 2026-11-13: no helper; the caller passes the directory that holds index.bin (rev56) | decided |
| Q21 | Engine and parse errors | ENGINE_ERROR and PARSE_FAILED allow in DEFAULT (`PolicyTable.kt:56-58`) | rustls-upki fails closed on everything except NoData (`lib.rs:132-136`) | looser | A deliberate availability trade-off | ADR-0001, spec §8 | kept |
| Q22 | Stale data | STALE never fires in DEFAULT; STRICT rejects data over 30 days old (`PolicyTable.kt:75,86`) | No clock at query time (`mod.rs:122-141`) | stricter in STRICT | — | spec §8 | kept |
| Q23 | Missing filter file | n/a (immutable in-memory generations) | Immediate error, no retry (`index.rs:311-319`); C2SP SHOULD retry | — | upki-only | — | kept (no action) |
| Q24 | **Empty generation** | An index with no filters is valid (`GenerationFiles.kt:30-36`); queries answer NOT_COVERED, so NO_DATA stops firing | The same (`index.rs:448-459`) | none | Security: an empty mirror or system-cache bootstrap would turn the NO_DATA reject into an allow | maintainer 2026-11-06, 2026-11-13: refused, with `SOURCE_EMPTY` (rev56) | stricter; decided |
| Q25 | buildIndex: exactly one full filter (else refused) plus every delta of the channel, `parent` not read | upki-mirror: the channel's full, then the `parent` chain from it | different on unusual data only | Firefox parity (RemoteSecuritySettings.sys.mjs:646-659); fails closed, since an extra delta only adds revocations | maintainer 2026-11-08 | kept |

**Agreements checked (src unless noted):**
- **Query math:** key hash, `a[0] |= 1`, `s mod m`, offset shift, bounded eval, exceptions and the inverted flag. Read side by side; the golden replay also covers it.
- **Within one filter:** the first covering SCT decides.
- **Across filters:** revoked > not revoked > the rest. upki's "not enrolled" is revokt's "not covered" class. Both match C2SP step 3.
- **Coverage windows:** inclusive, compared unsigned.
- **Trailing bytes:** v4 rejects them and v3 accepts them, as bincode 1.3.3 does. The reserved byte and versions match.
- **index.bin layout:** byte-identical (golden test).
- **Query inputs:** the serial is the raw content bytes, and the key is SHA-256(spkiHash ‖ serial). revokt hashes the full SPKI TLV; webpki re-wraps it but rejects non-canonical lengths, so the hashes match for every certificate webpki accepts. The issuer is the immediate one in both.
- **SCTs:** log ids match on all 32 bytes, timestamps compare as u64, and no SCTs means "not covered" in both.
- **Policy defaults:** missing data is rejected; "not covered" and "no SCTs" are allowed. The FFI codes match `ffi.rs:148-203`.
- **Rollback:** neither protects mirror data against it (a shared weakness, already on record).
- **The live mirror:** default channel only, v4, 81 logs per filter. Every cap holds except Q12.

## 6. Chain walker and decide

There is no direct reference: upki hands path building to webpki, which builds a single path and reports a limit hit
as an error kind with no detail.

| # | revokt | Reference | Dir | Why | Decided by | Status |
|---|---|---|---|---|---|---|
| W1 | Walks every candidate under budgets and collects all leaf-issuer keys; Budget, NotFound and Found carry diagnostics (`endDepth`, `walkerReason`, `WalkStats`) | webpki: the first path only, and a budget error with no depth (0.104.0-alpha.7 `verify_cert.rs:52, 761-777`, checked by the 2026-11-16 audit); Firefox: the first issuer that verifies, and a revocation failure stops the search (`pkixbuild.cpp:211-260`) | different (stricter) | CRLite needs the issuer key under cross-signed and junk-stuffed chains (§5.1) | spec §5.1 | kept |
| W2 | No `maxDepth` diagnostic | — | — | Nothing reads it | maintainer 2026-11-06 | kept |

## 7. x5u chain (#126, merged in #170 at 0b6895c; spec revisions 54 and 55)

References: mozilla::pkix at Firefox cac25a6fa321b0051932359b84c4e2fe3caabdc5 (the model), and rustls-webpki (consulted:
0.103.15 when #126 was decided, re-read against 0.104.0-alpha.7, upki's own, for X14 on 2026-11-16). upki has no x5u
code.

| # | revokt | Reference | Dir | Why | Decided by | Status |
|---|---|---|---|---|---|---|
| X1 | Terminal = the pinned SPKI hash only; nothing else about the root is read (no validity, CA bits, KU, EKU, TLS feature) | Firefox matches the whole root DER and checks the anchor's properties; webpki: (subject, SPKI) | looser | §7.1: the root is pinned, so its other fields cannot widen trust | spec §7.1 | kept |
| X2 | The x5u order is the path: leaf first, each link verified under the next; no reordering or depth cap (the 64 KiB cap bounds it) | Both build by issuer name in any order, with at most 6 sub-CAs; Firefox runs mozilla::pkix over the certificates after the leaf | stricter | No path search over an unsigned body: each link is verified once, so the cost is linear in the chain; Mozilla serves leaf first, and a misordered chain fails SIGNATURE | spec §6.5/§7.1; kept by the lead on #223 under the audit (A-1) | kept |
| X3 | Name chaining: raw bytes or canonicalSubject | Bytes only | looser | Each link is signature-verified under the next key, so this is not a trust boundary | spec §7.1 | kept |
| X4 | Leaf SAN: dNSNames only, each a plain DNS host name, one equal to `onecrl.content-signature.mozilla.org` with ASCII case ignored; no wildcard match; nameConstraints checked against every dNSName | Firefox: any matching dNSName, case-insensitive, wildcards; every name checked against nameConstraints | stricter (two narrowings) | A wildcard never matches: the signer name is exact, and a wildcard leaf would sign for every content-signature signer. Other name forms fail: nameConstraints are evaluated for dNSNames only (X6), so such a name could escape a CA's constraint | spec §7.1; the lead on #223 under the audit (A-1) | kept for the two narrowings; aligned for several names and case (24f2656) |
| X5 | Leaf EKU: absent passes; present must hold codeSigning and not OCSPSigning | Firefox requiredEKUIfPresent (absent passes) | none | The leaf is bound by the pinned root, the CA constraints and the signer name; requiring EKU had no security reason | spec §7.1; the lead on #223 under the audit (A-1) | aligned (24f2656) |
| X6 | nameConstraints checked against the leaf only; a directoryName subtree fails closed | Both check every descendant; Firefox evaluates directoryName | narrower/stricter | Mozilla's leaf carries only a dNSName; this avoids a brittle fail-closed on other forms | lead under "match Firefox" (#173 review) | kept |
| X7 | Any duplicate OID rejected | mozpkix: only remembered extensions | stricter | RFC 5280 MUST NOT | lead (#173 review) | kept |
| X8 | Validity checked at millisecond `at` and separately (a seed checks at `<ts>`) | Both truncate to seconds and check at Now() | stricter by <1 s | Seed loading (§6.5) | spec §6.5/§7.2 | kept |
| X9 | RSA counted in significant bits (2047 fails); no upper cap | Firefox: bytes × 8; webpki/ring cap 8192 | mixed | Unchanged policy | maintainer | kept |
| X10 | Bytes after the terminal are never parsed (an empty block loads) | Both read only what they need | same in effect | §7.1 "anything after it ignored" (#165 review) | spec §7.1 | kept |
| X11 | No revocation check of chain certificates | Firefox checks OneCRL on every link | looser | Not in §7.1 | spec | kept |
| X12 | Unread extension contents (SKI, AKI, policies, AIA) are not held to strict DER | mozpkix parses the extensions it reads | same | Firefox does not read them on this path | #170 review | kept |
| X13 | The anchor's TLS feature is not read | Firefox CheckTLSFeatures also covers the anchor | looser | The root is pinned; a TLS feature there could only add a constraint | lead (#173) | kept |
| X14 | webpki-only differences, at 0.104.0-alpha.7: its smaller understood set (keyUsage, subjectAltName, basicConstraints, nameConstraints, cRLDistributionPoints, extKeyUsage and the SCT list; `cert.rs:319-347`); keyUsage recorded but read only for a CRL issuer (`verify_cert.rs:151, 171`); v3 required (`cert.rs:276-291`); the outer and TBS algorithms compared as bytes (`cert.rs:90-92`). Unique IDs, rejected by 0.103.15 (`cert.rs:98-101`), are skipped by 0.104.0-alpha.7 (`cert.rs:123-139`), as mozilla::pkix and revokt do, so that one is no longer a difference | — | — | revokt follows mozilla::pkix | maintainer (follow Firefox) | kept |

Now matching Firefox, so no longer differences: strict DER (mozpkix leniencies included); outer = TBS algorithm; LEAF_CA; malformed leaf BC/KU; leaf OCSPSigning; unknown critical extensions; CA EKU codeSigning; the TLS feature below the terminal; nameConstraints dNSName semantics; CheckSubjectPublicKeyInfo; pathLen ≤ 127; non-empty keyUsage; minimal serials; explicit v1; the three PSS encodings and rsaEncryption/id-ecPublicKey keys; the leaf SCT list; the reason boundary (PARSE vs EXTENSION).

Also: the ECDSA r/s range check (#174, f8410e9) matches ring and aws-lc-rs (SEC 1 §4.1.4 step 1). It is stricter than SunEC, which accepts a negative-encoded r.

## 8. Decisions since 2026-11-06 (from the 2026-11-16 design audit)

Rows the 2026-11-16 design audit (#230) found missing from this log. References: upki v1.0.1 with rustls-webpki
0.104.0-alpha.7 ("webpki-104"), and Firefox at cac25a6 ("RSC" = `RemoteSettingsClient.sys.mjs`, "RSS" =
`RemoteSecuritySettings.sys.mjs`, "NSSTD" = `NSSCertDBTrustDomain.cpp`). Every reference cell is src, read by the
audit. Rows with a follow-up issue change when that issue lands.

### Walker

| # | revokt | upki / webpki | Firefox | Dir | Why | Decided by | Status |
|---|---|---|---|---|---|---|---|
| W3 | Candidate order at every depth: store anchors, presented certificates by index, then store non-anchors | Anchors first, then presented intermediates (webpki-104 `verify_cert.rs:73-112`) | Built-in and third-party roots, then handshake certificates, third-party intermediates, preloaded (NSSTD:214-322) | none | Firefox's order, which also matches webpki | maintainer 2026-11-13 (#196 F2) | aligned |
| W4 | A candidate is related by raw name, canonical name, or SKI = AKI | Raw name bytes only (webpki-104 `verify_cert.rs:76, 114`) | Raw name bytes only; AKI and SKI ignored (`pkixbuild.cpp:154`, `pkixcheck.cpp:1023-1025`) | looser (candidate set) | The walker must reproduce the platform's path, and the JDK compares canonical names. Each link is still signature-verified | spec §5.1 | kept |
| W5 | **The unrelated loop:** presented certificates that are not name-related are tried when no related path exists (custom delegates, #98) | none: an unrelated candidate is never tried (webpki-104 `verify_cert.rs:114-116`) | none (`pkixbuild.cpp:154-157`) | looser | The PKIX fallback covers the same residue with the platform's own name matching. Harmless once issuers must be CAs (W7); without that, it is how an unrelated non-CA certificate could enter a path | spec §5.1 | open: the audit asks whether the loop earns its fixtures (#225) |
| W6 | **Loop prevention compares bytes only:** a certificate is skipped when it is byte-equal to one on the path | A candidate with the same subject and SPKI as one on the path is skipped (webpki-104 `verify_cert.rs:118-124`) | The same (`pkixbuild.cpp:162-171`) | looser | Costs budget only (a cross-signed loop is walked until the budget ends), never a verdict | spec §5.1 | open: noted by the audit, no issue yet |
| W7 | A non-anchor issuer must have basicConstraints `cA = TRUE`, checked before its link is verified; an anchor is exempt (`walker/IssuerProfile.kt`, `walker/Reconstruct.kt`; fixture (aq)) | `EndEntityUsedAsCa` (webpki-104 `verify_cert.rs:422-452`) | `ERROR_CA_CERT_INVALID` (`pkixcheck.cpp:712-715`) | looser | Undeclared until the audit; it was the premise behind W5 | maintainer 2026-11-16 (accept the audit) | aligned (#225, #234); the anchor itself follows webpki (no basicConstraints check) |
| W8 | Budgets: depth 16, 256 verifications, 1,024 explored, 64 related per level; exhaustion rejects (`PATH_BUDGET_EXCEEDED`) | 6 sub-CAs, 100 signatures, 200,000 calls; exhaustion is fatal (webpki-104 `verify_cert.rs:131, 345-349, 851`) | 6 sub-CAs, 200,000 calls; exhaustion is `ERROR_UNKNOWN_ISSUER` (`pkixbuild.cpp:195-200, 324-330, 392`) | different (values) | Same failure class; the server controls the stuffing, so exhaustion must reject | spec §5.1 | kept |
| W9 | `NO_ISSUER` and `ISSUER_UNVERIFIED` share one outcome and exemption | none | Both errors are in one override category (`SSLServerCertVerification.cpp:250-266`) | different (shape) | The shared slot is right; two names for one rule are not | maintainer 2026-11-13; the 2026-11-16 design audit | open: #225 (one `NO_ISSUER` rule with a reason) |
| W10 | `EvaluationRequest` takes one platform-verified path; a mismatched leaf throws | One `VerifiedPath` (`rustls-upki/src/lib.rs:95-127`) | Revocation inside path building (`pkixbuild.cpp:237-260`) | none | It closed a fail-open | maintainer 2026-11-13 (#195) | aligned |
| W11 | `pathLenConstraint` on every non-anchor issuer, self-issued certificates counted; above 127 is not a CA (`walker/IssuerProfile.kt`) | `sub_ca_count > len` (webpki-104 `verify_cert.rs:449-450`); reads a `u8` | `subCACount > pathLenConstraint` (`pkixcheck.cpp:718`); reads 0 to 127 | none | Both references; neither applies RFC 5280's self-issued exemption | lead 2026-11-17 (#237 R3) | aligned (#237) |
| W12 | `keyCertSign` required when an issuer has keyUsage | ignored for path building (webpki-104 `verify_cert.rs:370-375`) | `CheckKeyUsage` (`pkixcheck.cpp:405 ff.`, `pkixbuild.cpp:205`) | stricter than webpki | Firefox and the JDK's `KeyChecker` enforce it | lead 2026-11-17 (#237 R4) | kept |
| W13 | An issuer's extKeyUsage must list the request's purpose; anyEKU does not count; serverAuth unless a binding says clientAuth | `ExtendedKeyUsage::validate` (webpki-104 `verify_cert.rs:381, 572-598`) | `CheckExtendedKeyUsage` (`pkixcheck.cpp:816-846`) | none | Both references | lead 2026-11-17 (#237 R5) | aligned (#237) |
| W14 | nameConstraints by mozilla::pkix's rule (`pkixnames.cpp` at `cac25a6`), the anchor's included: directoryName subtrees as an RDN prefix of the subject and any subjectAltName directoryName, every excluded one refusing; rfc822Name subtrees against subjectAltName mailboxes and, without a subjectAltName, the subject's emailAddress attributes; dNSName and iPAddress subtrees also against a serverAuth leaf's CN-ID when its subjectAltName has no dNSName or iPAddress; URI and other shared forms a violation; 250,000 comparisons per walk, one more per directoryName AVA pair (`walker/NameConstraints.kt`, `walker/PkixNames.kt`) | directoryName and URI subtrees fail closed, an rfc822Name subtree is a violation, no CN or emailAddress fallback (webpki-104 `verify_cert.rs:282-300, 353`; `subject_name/mod.rs:32-200`) | the same (`pkixbuild.cpp:173-186`; `pkixnames.cpp:327-357, 377-702, 836-977, 1405-1651`) | against Firefox, stricter only in the comparison bound, webpki's iPAddress mask check, and a subjectAltName revokt's reader refuses (empty, or a non-ASCII dNSName); against webpki, looser on directoryName and rfc822Name subtrees, stricter through the CN-ID and emailAddress fallbacks | Firefox is the main CRLite client; with webpki's rule a directoryName- or rfc822-constrained issuer gave `NO_ISSUER`, allowed unchecked under `DEFAULT` (spec §10 residual 15) | lead 2026-11-17 (#237 R1, R2, R7); maintainer 2026-11-19 (match mozilla::pkix, R4a and R4b ported) | aligned with Firefox (#261) |
| W15 | A fallback path must end at an anchor by bytes and meet W7, W11–W14 | n/a (no fallback) | n/a | stricter than the JDK | The JDK exempts self-issued certificates and the anchor's own nameConstraints, and does not read a CA's extKeyUsage | lead 2026-11-17 (#237 R6), #253's review | kept |

### Remote Settings sync

| # | revokt | upki / webpki | Firefox | Dir | Why | Decided by | Status |
|---|---|---|---|---|---|---|---|
| S1 | The x5u URL host (after the rewrite) must be under `allowedDomains` (default `cdn.mozilla.net`, on a label boundary, exact case) | none | No host check; the URL is fetched as given (RSC:1109) | stricter | The x5u URL is unsigned: the rule keeps a compromised settings host from pointing clients at arbitrary hosts; the suffix rule no longer freezes a client on one host | spec §7.1; the 2026-11-16 design audit; the lead on #223 | kept, narrowed to a suffix rule (c473fe8) |
| S2 | The attachment base is the server root's `capabilities.attachments.base_url`, read once per sync before the first attachment fetch and never persisted, unless `attachmentBaseUrl` pins it; the value must pass the x5u URL grammar (no query) and `allowedDomains`, else `FAILED` at `ATTACHMENT` with no fallback | Configured (`upki-mirror/src/bin/mozilla-crlite.rs:71`) | Read from the server's capabilities and cached in a pref keyed by the server URL; no host check (`Utils.sys.mjs:335-387`) | stricter (the host rule, no persistence) | The server root response is unsigned: the rule keeps a compromised settings host from pointing clients at arbitrary hosts, while the attachment bytes are bound to the signed hashes | spec §7.1; the audit; the lead on #223 | kept, narrowed (c473fe8) |
| S3 | `Backoff` and `Retry-After` honoured on every response, capped at 24 h | none (no backoff in `fetch.rs`) | `Backoff` from `/changes` only (`remote-settings.sys.mjs:493-516`) | stricter | The cap bounds the cost | maintainer 2026-11-08 (#131 R3) | kept |
| S4 | Rollback floor: max(stored watermark, the live `<ts>`) while a generation is live, a loaded generation counted as verified; with none loaded (none stored, or each absent or malformed, never a read that threw, and no seed) the stored watermark is not read and the install sets it to its `<ts>` | No rollback check | The local data's timestamp is the floor, but the local data is verified again at the comparison, and older data is imported when that check fails or throws for any reason, an x5u it cannot fetch included (RSC:1203-1230); a local read that throws fails the sync (RSC:744-750) | stricter | revokt does not re-verify a loaded generation at each sync, so a live generation whose x5u could not be fetched now still floors; a read that threw is never read as no data | maintainer 2026-11-13 (#190); 2026-11-19 (#224) | kept (#224: the watermark is not read, and is set to the install's `<ts>`, with no generation loaded) |
| S5 | A changeset older than the floor is `ROLLBACK_REFUSED`, however little older, and one equal to it installs; no window and no coverage rule | No rollback check | Anything older than local verified data is ignored (RSC:1203-1226) | none | Firefox's rule | maintainer 2026-11-19 (#224) | aligned (#224: `rollbackWindow` and the in-window coverage rule removed) |
| S6 | Reset-and-retry once as the whole collection on a content-signature mismatch, on no usable signature entry (`NO_SIGNATURES`, `NONE_TRIED`, `NULL_ENTRY`) and on an unmergeable change list; never on an x5u failure (fetch, PEM, chain, validity) | none (the first error aborts, `fetch.rs`) | On every `InvalidSignatureError` (RSC:862-889): a mismatch, `MissingSignatureError`, `CorruptedDataError`, and x5u chain and validity failures. A `null` entry throws a `TypeError` in the destructuring (RSC:1102), which is not retried. The x5u response status is never checked (RSC:1108), so a 404 or 500 body fails in the verifier and is retried; only a rejected network fetch escapes | different: broader on `NULL_ENTRY`, narrower on an HTTP-error x5u and on x5u PEM, chain and validity | The sync holds one x5u result per URL, so a retry of an x5u failure fails the same way; the `NULL_ENTRY` retry is harmless, since the retry must verify | maintainer 2026-11-19 (#224) | kept, narrowed (#224) |
| S7 | No per-sync byte total (`MAX_SYNC_BYTES` removed); per-file and count caps only | No caps | No total | none | Neither reference has one | maintainer 2026-11-14 (#137 Q1) | aligned |
| S8 | `MAX_CHANGESET_RECORDS` = 1,024; over it fails the sync | none | none | stricter | About four deltas a day reached 256 in 64 days; 1,024 is about 256 days, and the per-file caps still bound the bodies | spec §5.1; the audit (A-1) | kept, raised from 256 (1a08929, #223) |
| S9 | All-or-nothing install: one failed body fails the generation | The first error aborts (`fetch.rs:148-150`) | A failed delta is skipped and the rest installs (RSS:718-724) | stricter than Firefox | Generations are immutable | spec §6.5 | kept |
| S10 | No metered deferral: a full downloads in the same sync on any network | none | none | none | Neither reference has one | maintainer 2026-11-19 (#224) | aligned (#224: `meteredNetwork`, `DEFERRED` and `METERED_DEFERRED` removed) |
| S11 | No rule compares signed data with the local clock: no changeset `CLOCK_SKEW`, no `clockBehind`, no coverage bound; `CLOCK_SKEW` is the x5u validity at stage `X5U` only | No clock (`revocation/mod.rs:124-139`) | No clock comparison on data; the x5u validity at `Now()` (X8) | none | Both references | maintainer 2026-11-19 (#224) | aligned (#224) |
| S12 | A far-future `<ts>` (a server bug) installs and advances the watermark; `ageMillis` reads 0 until local time passes it, so `stale` and `STALE` fire late by as much if the feed then stops | No `<ts>`; no data age | Installs too; `ageSeconds` is server time minus `<ts>`, telemetry only (RSC:957-958, 1367-1368) | different | revokt's `STALE` reads data age from the local clock, which neither reference does; the next server `<ts>` passes the far-future one (Kinto's monotonic timestamps; the signer drops `last_modified`, `updater.py:366-368` at 92b74ed), so the feed does not freeze | maintainer 2026-11-19 (#224); spec §10 | kept (residual) |
| S13 | After an older changeset installs with no generation loaded, the watermark is set to its `<ts>` in the install's own write, so once that generation is live anything newer installs (100, then 80, then 90 installs) | No rollback check | The imported data's timestamp is the local one (RSC:1203) | none | Firefox's rule | maintainer 2026-11-19 (#224) | aligned (#224) |
| S14 | A seed that installs with no generation loaded (no trusted pointer, nothing the engine serves) sets the watermark to its `<ts>` in its own write; beside a loaded generation it keeps `max(watermark, <ts>)` | No rollback check | The dump's timestamp is the local one once imported (RSC:756-773) | none | Firefox's floor after a dump import, as S13 | maintainer 2026-11-19 (#224) | aligned (#224) |

### Store and install

| # | revokt | upki / webpki | Firefox | Dir | Why | Decided by | Status |
|---|---|---|---|---|---|---|---|
| T1 | Immutable generation directories, a pointer flip with `previous`, content-addressed blobs | One directory, files replaced in place, index then manifest (`fetch.rs:214-223, 304-306`) | One directory; old files deleted before the new full is written | different | Neither reference is atomic across files | spec §6.5 | kept |
| T2 | Store recovery heals, never bricks, never deletes: a malformed `updater.json` reads as absent; a read that throws writes nothing (#209); beside a malformed pointer a directory whose `meta.json` is present is held (#236) | none (no pointer or updater record; it fetches again) | none (it fetches again) | different | Neither reference has the files that can be damaged | lead 2026-11-16 (#236, #242) | kept |

### C2SP mirror (cut, #218)

| # | revokt | upki / webpki | Firefox | Dir | Why | Decided by | Status |
|---|---|---|---|---|---|---|---|
| M1 | The mirror was bootstrap only: it never displaced signed data | The mirror is the only source and updates continuously (`fetch.rs:37-155`) | none | different | Security; the largest divergence from upki | spec §7.3 | moot: the MIRROR source is cut (#218) |
| M2 | Redirects followed by one `RedirectingFetcher`: https only, 10 hops, strict RFC 3986 `Location`, credential headers stay stripped, no Referer | reqwest's default, 10 hops, https not enforced; Referer on | none | stricter | upki follows redirects only because reqwest does by default | maintainer 2026-11-13, 2026-11-15 (#192, #208) | removed with the mirror (#218): no fetch follows a redirect, and the code is in git history |

### Policy (§8)

| # | revokt | upki / webpki | Firefox | Dir | Why | Decided by | Status |
|---|---|---|---|---|---|---|---|
| R1 | `NO_DATA` rejects in `DEFAULT` (exemptable) | `missing_data = Error` (`rustls-upki/src/lib.rs:259-267`) | No filter is `Success`, so it falls back to OCSP, as `NOT_COVERED` does (NSSTD:712-715) | stricter than Firefox | Matches upki | spec §8 | kept; the §8 table now cites both (#217) |
| R2 | `ENGINE_ERROR` allows in `DEFAULT` | Hard fail (`rustls-upki/src/lib.rs:132-136`) | `FATAL_ERROR_LIBRARY_FAILURE` (NSSTD:716-720) | looser than both | ADR-0001; see Q21 | ADR-0001, spec §8 | kept |

## Log
- 2026-11-19 (#224): S5, S10, S11 and S13 aligned with Firefox (no rollback window or coverage rule, no metered
  deferral, no clock rule on signed data, the watermark set to an install's `<ts>` with no generation loaded); S4
  extended and marked stricter (a loaded generation counts as verified; a read that threw is never no data); S6
  narrowed, with its `NULL_ENTRY` and HTTP-error x5u differences named; S12 (the far-future residual) added; S14
  (a seed that installs with nothing loaded sets the watermark to its `<ts>`) aligned. Checked against
  `RemoteSettingsClient.sys.mjs` at cac25a6 (lines 744-750, 756-773, 862-889, 1102, 1108, 1203-1230, 1367-1368), Kinto 26.6.0 and mozilla/remote-settings at 92b74ed.
- 2026-11-19 (#223, the audit's A-1): C1 and X5 aligned with Firefox, X4 narrowed to two stated narrowings, X2
  kept with its reason, S1 and S2 narrowed to `allowedDomains` and the server's `base_url`, C10 and S8 loosened
  (the first 4 signatures, 1,024 records). Checked against the Firefox copies at cac25a6
  (`RemoteSettingsClient.sys.mjs:1097-1132`, `Utils.sys.mjs:335-387`).
- 2026-11-16 (#217): moved into the repository. The upki pin's webpki version corrected to 0.104.0-alpha.7, and rows
  E3, E8, E9, E10, E11 and X14 re-read against it: E9 is now checked and documented (the x5u chain already requires
  `00`/`FF`), and X14 loses the unique-ID difference. Stale rows closed (C9, Q5, Q12, Q13, Q14, Q16, Q20, Q24), Q15
  restated, W1's reference cell checked, and §8 added from the 2026-11-16 design audit.
- 2026-11-16 (#217), upki v1.0.3 against v1.0.1 (the pin; admitting it is #240). What it changes for these rows:
  - **The webpki pin moves back to 0.103.17** (`Cargo.toml`, 8905bf0). Once #240 admits v1.0.3, the webpki rows (§2,
    W1, W3 to W8, X14) are re-read against 0.103.17. Unique IDs (X14) are rejected again on that line.
  - **Q11, SCTs:** an SCT with an unsupported version is now skipped instead of failing the check
    (`rustls-upki/src/lib.rs` and `revocation/mod.rs`, 65701c6). revokt still keeps such SCTs and queries them, so it
    is still the more-checking side, but upki no longer fails the handshake on one.
  - **Q18 and Q25, the mirror tool** (upki-mirror 0.2.0): v3 filters are transcoded to v4 (c2ba5e3) and the channel
    is selectable; it still walks the `parent` chain. Moot for revokt with the MIRROR source cut (#218).
  - **No other behaviour change:** the fetcher is refactored (`fetch.rs` moved to `upki/src/fetch.rs`, a
    `FetchContext`, a `PostProcess` step), with the same requests, plan and deletions.
- 2026-11-06: P2–P5 aligned in #165 (a10583e). X5uPem now matches rustls-pki-types 1.15.1 (0 differences over 30,065 inputs), except that the cap is checked first and only CERTIFICATE blocks are returned. An empty block yields an empty DER; #126 ignores whatever follows the terminal.
- 2026-11-06: Added the upki audit (Q3–Q24). Maintainer decisions for Q12–Q16, Q20 and Q24 are in DECISIONS.md, and the spec items are on #160. #164 merged as eb3af7a.
- 2026-11-06: Created from the #163/#164 reviews, the #95 and #97 reviews, and the maintainer's decisions. P2–P5 set
  to match rustls-pki-types fully.
