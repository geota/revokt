<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Rationale, measurements and worked examples behind the core

Not normative. Moved out of [the spec's core](../spec/revokt-spec.md) by the 0.2 deletion pass (#399), as it stood
after revision 61; milestone: background, never promoted. The core keeps each normative sentence and points here for
why it holds, what was measured, or how a case works out. Sections follow the core's numbering. Where this note and
the core differ, the core wins.

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

## 3. Modules, dependencies and licensing

**Why the PSS salt cap is 2,048 bytes.** 2,048 bytes, the modulus bits / 8 at SunRsaSign's
largest modulus of 16,384 bits, is an upper bound on any RSA key's salt. The real maximum is `emLen - hLen - 2`
(RFC 8017 §9.1.1, `emLen >= hLen + sLen + 2`). The JDK refuses a
longer salt for the key on its own, with a `GeneralSecurityException`, except near `Int.MAX_VALUE`. There its
`hLen + sLen + 2` overflows into an `ArithmeticException`, which would otherwise become a `VerifierError` for a
CA-chosen length. On JDK 21.0.13 with SHA-256, the overflow starts at 2,147,483,614 (Appendix A, "PSS salt on the
JDK").

**Why the ECDSA range check.** SEC 1 §4.1.4 step 1, which ring's verifier also performs. The JDK's own check was
missing from JDK 15 to 17.0.2 and in 18 GA (CVE-2022-21449), which within revokt's JVM 17+ target is 17.0.0 to 17.0.2
and 18 GA.

**What the probe reports under Conscrypt** moved to Appendix A ([references.md](../spec/references.md), the
"`JcaSignatureVerifier` over Conscrypt" entry), beside the probe that established it.

**Why Apache-2.0 over MIT:** explicit patent grant and retaliation, contribution licensing without a CLA, name
protection, JVM scanner expectations.

## 3.2 `RevocationEngine` and the upki-backed engine

**Why selection equivalence makes the two engines agree.** The core's `index.bin` consistency rule (every
`index.bin` the loader installs is selection-equivalent by construction) is what makes the Kotlin engine's
coverage-driven filter selection (§6.2, every filter consulted by its own coverage) equal to C2SP's
`index.bin`-driven selection (upki binary-searches the log directory and loads only the filters it names)
on every generation the suite admits; upki's `Index::write` writes one entry per (log, filter), the filter's
coverage window for that log, so overlapping windows (a full and its deltas sharing boundary timestamps) are
separate entries, which the check admits (Appendix A), and a legitimate Mozilla generation
passes by construction.

## 4. Public API

- **No fetching source by default.** A required dataset with local data and no fetching source is the V
  `NO_FETCHING_SOURCE` warning, not an error, because air-gapped seed-by-deploy fleets are legitimate.
- **`limits { }`.** Since `MAX_FILTER_BYTES` also caps `SIGNED` bodies, raising it is the recovery for a larger
  Mozilla filter. `maxTrustManagers` is the multi-tenant case (per-tenant trust stores), one `CandidateIndex` and two
  small caches per instance.
- **`http` on Android.** Android's `HttpsURLConnection` answers a 407 from the VM-global `Authenticator.getDefault()`
  with no per-connection suppression (§10 residual 12), which is why the OkHttp fetcher is preferred.
- **`cache(null)` on the OkHttp fetcher.** A consumer disk cache would serve the first ETag-less request, on a fresh
  install or after `resetState()`, from its own max-age.

## 5.1 Common flow

**`MAX_CHANGESET_RECORDS` = 1,024.** Remote Settings listed 53 records a channel on 2026-11-12; about four deltas a day
reach 256 in 64 days, so a lower cap would freeze a shipped client. Neither upki nor Firefox has a per-sync total.

**Decision step 6.**
- A `NotFound` on a chain too long for the fallback is `PATH_BUDGET_EXCEEDED(FALLBACK_LIMIT)` because no honest Web
  PKI chain is longer than 8 certificates and unreproducible by the walker, and the server controls chain length.
- `UNSUPPORTED_ALGORITHM` is a reason of `NO_ISSUER`, not a rule of its own, because a server can steer the reason
  there. Unlike mozilla::pkix, revokt does not collapse to one error when candidates fail differently.
- With the fallback disabled, a binding's walk `NotFound` is `PLATFORM_ONLY` because the platform trusts a chain the
  walker cannot reproduce, and no PKIX builder ran.

**The issuer rules and the references.** Each rule is a dead end before the link is verified, as pkix checks an
issuer before `VerifySignedData`; an anchor by bytes is exempt from all but its nameConstraints, as webpki's
`TrustAnchor` has no other extension.

**Why the walk is sound.** Anyone can obtain an end-entity certificate under a
real anchor, and its key can sign a certificate for any other key, a recovered one included; the issuer rules remove
that route, and with it the limited sub-CAs that organisations hold under public roots (a `pathLen 0` one, one
name-constrained to its own domains, an EKU-limited one; fixtures (ar) and (as)). An `UNSUPPORTED` link is never
trusted. Nothing is excluded for a shared property, so a same-key decoy or a cross-certificate to a non-anchor listed
first cannot hide the real certificate, which is related and is explored. The honest issuer's key is the only key that
verifies a real leaf's signature, other than a recovered key. A recovered key terminates only through CA certificates
whose constraints admit the real leaf, so a `Found` carrying only benign keys needs the cooperation of an unconstrained
CA key holder under a real anchor (§10 residual "constrained sub-CA"), who can mint a fresh leaf anyway. Stuffing junk
ahead of the honest issuer past the budget yields `Budget`, which rejects; an exhaustion in any subtree aborts the whole
walk, so a stuffed subtree cannot starve the honest key out of a `Found`. The key evaluated is the first sound path's,
as in both references; a second key that verifies the leaf and terminates needs such a CA (§10 residual 15). The PKIX
fallback covers the residue the walker does not: a `NotFound` on a chain of at most `FALLBACK_MAX_PRESENTED`
certificates whose honest link the walker could not reproduce (a custom delegate's canonicalisation, constraints or
verifier divergence, §10 residual 1). Beyond the budget the walk is `Budget`, which rejects whatever the fallback does,
and a `NotFound` too long for the fallback is `PATH_BUDGET_EXCEEDED`. A policy may not disable the fallback while
`NO_ISSUER` allows (§4, the R bullet).

**Cost, worked.** An honest leaf → I → root chain: at the leaf, I (one verification, recurse); at I, the store anchor
first (one verification, terminal, stop). Two verifications. A presented cross-certificate of the root sorts after the
store anchor and is never reached once the anchor verifies, and even when reached it is a memo hit (same key); a
root-issued leaf is one verification, its presented cross-certificates included, since the walk stops at the store
root; a chain whose snapshot holds the other root of a cross-sign costs depth + 1 (three). A related decoy ahead of
the honest issuer costs one exploration. The worst case: junk ahead of the honest issuer, or a nested subtree of
verifying junk (RSA duplicate-signature keys make junk verify), reaches `MAX_EXPLORED` in one or two levels, about
250 ms of RSA-4096 verification on a mid-range ART device, and ends in `Budget`.

**The PKIX fallback and the references.**
- A presented intermediate or an anchor the `CertificateFactory` rejects is left out, as webpki and mozilla::pkix skip
  a candidate that does not parse.
- Decision step 6 re-checks the issuer rules on a fallback path because the JDK's builder enforces less: it exempts
  self-issued certificates from `pathLenConstraint` and name constraints, does not apply the anchor certificate's own
  nameConstraints, and does not read a CA's extKeyUsage, so a JDK path through an EKU-limited intermediate is
  refused, as Firefox refuses it.
- The fallback is skipped above `FALLBACK_MAX_PRESENTED` presented certificates because `CertPathBuilder` has no
  candidate budget and is exponential on stuffed chains (§10 residual 9).

**The anchor snapshot on Android.** The NSC `NetworkSecurityTrustManager.getAcceptedIssuers()` is lazy and cached per
default config (one per process) over process-wide directory sources (`DirectoryCertificateSource` lists the system and
user cacerts directories and reads one file per certificate on the first call per process; every
later call clones the cached array; the system clears these caches in every running process by its
own `handleTrustStorageUpdate()` push when the trust store changes, with no app receiver involved), which is why
`start()` warms it by building the pre-start snapshots. Under `trustManager(d)`'s `StrictMode.allowThreadDiskReads`
guard, with the default delegate the call reads disk only after a trust-store change, a Conscrypt `TrustManagerImpl`
over `AndroidCAStore` re-enumerates the cacerts directories on every call, and a consumer-written delegate is
arbitrary.

**Fetches run no revokt trust manager**, so revokt's verdicts never gate its own feed, as in Firefox and upki.

## 6.3 Filter decoding

- **Observed 2026-10-21:** Mozilla serves v3 on both channels; `upki.rustls.dev` serves a v4 transcode.
- **Validated 2026-10-21:** prototype matched `clubcard-crlite 0.6.2` on 43,510 / 43,510 queries.

## 6.4 Filter storage

| Channel | Full | Resident, 8 deltas | Resident, 52 deltas (measured) | Load, JIT-compiled (emulator, lower bound) | Load, interpreted (emulator, lower bound) |
|---|---|---|---|---|---|
| `compat` | 1.57 MB | ~2.5 MB | 8.56 MB (8,558,354 B) | 73 ms cold, 28 ms warm | 190 ms plus seed verification |
| `default` | 6.0 MB | ~7.8 MB | 18.59 MB (18,593,366 B) | 86 ms cold, 51 ms warm | 332 ms plus seed verification |

The measured column is the sum of the signed `attachment.size` values per channel in the live
`cert-revocations` changeset of 2026-11-12 (`timestamp` 1794499022363, 106 records: per channel 1 full and 52 deltas;
deltas average 134 KB on `compat` and 242 KB on `default`; Appendix A). The delta count varies: 8 per channel on
2026-10-21, 52 per channel on 2026-11-12.
`MAX_CHANGESET_RECORDS` (1,024) admits a full and 1,023 deltas, about 254 MB at `default`'s 6 MB full and ~242 KB a
delta; no per-sync total caps it, only the count and the per-file caps.
The load columns are `start()`'s load of a stored generation of 1 full filter and 52 deltas (§6.5 Load's steps 1 to 4,
then `prepare`), measured on ART: an API 31 arm64 emulator with 4 cores on an Apple M3 Max host, the code run under
`dalvikvm` from a d8 build at min-api 26. Cold is the median first load of 14 fresh processes and warm the median of
each process's 6th to 15th, with the JIT on; interpreted is the median of 24 loads with app code interpreted
(`-Xusejit:false`). `compat` is the corpus's real full filter beside 52 synthetic deltas of the measured mean size;
`default` is synthetic, a 6 MB full and 52 deltas of 242 KB: the shapes `StoreLoadTimeTest` measures on HotSpot.
An emulator on a fast host is a lower bound for the physical API 26 device the core's §6.4 measures
`AWAIT_DATA_<CHANNEL>` on. Of each interpreted load, `prepare`'s decode is about 168 ms on `compat` and 296 ms on
`default`, and steps 1 to 4 about 21 and 34 ms, of which re-hashing the generation file and every blob alone takes
about 11 and 18 ms.

## 6.5 Store, persistence and seeds

- **The `previous` candidates, served first:** so a flip that failed after activation, which left the engine
  serving a generation `current` does not name, never loses it to the next prune.
- **Load's steps 1 and 3** make what a load returns (the `GenerationFiles` handed to `prepare`, the `records` used as
  a delta base) byte-equal to a generation file and blobs written from verified data: without step 1, a flipped byte
  inside `records` that still parses could drop a delta, and its revocations, silently.
- **Prune beside a pointer that does not read** deletes nothing, where upki deletes beside an old manifest it cannot
  read and Firefox clears local data that does not verify (DIVERGENCES T2).
- **Two JSON allocation bounds:** a tree with one object per value cannot hold 4·len on every input, `[1.5,…]` alone
  needing about 6·len, and a bound needs a constant term; hence 20·len + 64 KiB on any input and 4·len + 64 KiB on
  Remote Settings data.
- **Seed artifacts declare no code dependency** because a POM dependency would let a seed bump drag `revokt-engine`
  above the BOM-pinned bindings (Gradle resolves the highest version; BOM constraints are not strict) and the
  `@RevoktInternalApi` plumbing between artifacts carries no compatibility promise.

## 7.1 Mozilla Remote Settings protocol and verification [M1]

**The x5u terminal is matched by its SPKI alone.** This is revokt's own rule, not Firefox's: `AppTrustDomain` matches
the anchor by its whole DER and mozilla::pkix still checks it. Pinning the key alone keeps a re-issued root working, and
the wrapper around a pinned key is attacker-choosable, so a check on it stops nothing, while root expiry would freeze
every deployed client and seed.

**The path is the x5u order**, where Firefox builds the path by issuer name over the certificates after the leaf. This
stays because no path search ever runs over an unsigned body: each link is verified once, so the cost is linear in the
chain under the 64 KiB cap; Mozilla's chains are served leaf first.

## 7.2 Mozilla CRLite, channels, seeds and data artifacts [M1]

An open Phase-0 task, as the core stated it: observe two full-filter cuts for re-parenting.

## 8. Policy

**`DEFAULT` with stale data, stated plainly:** `DEFAULT` with stale data is "reject what the stale filter says is
revoked, allow the rest", with `STALE` never firing; `DEFAULT.newBuilder().rule(STALE, REJECT)` alone changes nothing
until a `rejectStaleAfter` is set.

## 10. Security considerations

**Residual 3**, as it stood: "**Closed.** The anchor snapshot is built synchronously before any handshake can go past
flow step 1 on both platforms (inside `start()` or at wiring), so there is no startup window. What remains is
operational: on Android the delegate's `getAcceptedIssuers()` at wiring runs under an unconditional
`StrictMode.allowThreadDiskReads`, which hides the report, not the read: the default delegate reads the cacerts
directories only when wired after a trust-store change, a Conscrypt `TrustManagerImpl` over `AndroidCAStore` on every
wiring. A consumer that wants no main-thread disk read creates its trust managers before `start()`."

**Residual 7, the references.** Firefox skips CRLite without usable SCT timestamps and falls to OCSP, which revokt does
not do. Firefox rejects the certificate outright where the SCT extension's `extnValue` is not exactly one DER OCTET
STRING, as with an inner identifier other than `0x04`. The `rustls-upki` verifier rejects a malformed list (test-plan.md
§9.3 divergence). A list §9.2 accepts in part is one Firefox and webpki fail whole. Firefox rejects a certificate with a
list in an inner OCTET STRING with a non-minimal length, or followed by bytes in `extnValue`, or with two SCT
extensions.

**Residual 8, the measurements.** No entry of a 200 230-entry CT sample on 2026-10-23 fell outside a strict DER
profile, and its 159 270 RFC 6962 entries showed no K5 type or K8 shape outside the profile (Appendix A); the full K1–K8
gap is first measured on the pinned seed corpus's leaves of index issuers (0 of 117 603 unexpired leaves, Appendix A).

**Residual 8, the references and the alternative.** Firefox has no keyability notion. mozilla::pkix rejects most gap
encodings before CRLite, and accepts the serial forms (negative, zero, long) and the explicit `FALSE` that the profile
also accepts.

Considered and not adopted: deciding keyability at the query, after the walk. That would make the
outcome exemptable under `anchorIn`, and `NOT_ENROLLED` under an unenrolled issuer. The profile already accepts
the private-PKI serial forms, so the remaining unkeyable leaves are encodings that mozilla::pkix and BoringSSL
also reject. This reopens if a gap entry under a private anchor is reported.

**Residual 15, the references.** mozilla::pkix evaluates that one path as well: it checks revocation only for the
issuer of the path it built, and a failing check ends the search. webpki goes on past a revoked path to the next
candidate, so it accepts the attacker's path in either order. M2's candidate order, presented certificates before the
preload, is Firefox's `FindIssuer` order. Querying only the first path's SPKI encoding is as in Firefox. Neither
reference applies the RFC 5280 self-issued exemptions either.

Name constraints follow Firefox's mozilla::pkix (the core's §5.1 "Why this is sound", pinned to `pkixnames.cpp` at
`cac25a6`): directoryName and rfc822Name subtrees are evaluated, the subject's emailAddress attributes stand in
for a missing subjectAltName, and a serverAuth leaf's CN-ID is checked when its subjectAltName has no dNSName or
iPAddress. Where revokt is stricter than Firefox:
- the 250,000-comparison bound, which pkix does not have;
- an iPAddress subtree whose mask is not ones then zeros fails, as in webpki, where pkix applies the mask as
  written;
- a subjectAltName that revokt's reader refuses (an empty one, or a dNSName that is not ASCII) fails under any
  nameConstraints, where pkix reads it and checks each entry against the subtrees of its form only.

What else was checked: no root in the JDK 21 `cacerts` (118) or macOS `SystemRootCertificates` (158) carries
nameConstraints; live Web PKI sub-CAs were not surveyed for directoryName or rfc822Name subtrees.

**Residual 16, the references.** The 8-certificate rule follows from #226's `FALLBACK_MAX_PRESENTED`. It is not
narrower than Firefox: mozilla::pkix caps the path it builds, at 6 intermediates (`MAX_SUBCA_COUNT` in
`pkixbuild.cpp`), not the count presented. So a padded chain whose short path the walker cannot build, for example a
leaf, an intermediate and a root sent with 6 extra certificates (old cross-signs), is accepted by Firefox and rejected
here. The missing intermediate is one Firefox's preload would supply; the misclassified honest issuer is #226's case.

**Rollback and freeze, the references.** Firefox and upki have no rule on signed data that reads the local clock
either. A changeset dated ahead of the local clock is passed by the next one because Kinto assigns a collection's
timestamps monotonically and Mozilla's signer publishes them unchanged (Appendix A). With no generation loaded, older
signed data installs as Firefox imports when its local data does not verify.

**No self-lockout, why.** The payload is authenticated end to end, so TLS authenticity to the feed host protects
nothing an attacker could exploit; Firefox and upki do the same.

## 13. Naming and publishing

**What was verified for the name**, 2026-10-21: Maven Central `dev.revokt` free; `revokt.dev`, `.io`, `.org` free;
GitHub handle `Revokt` taken (inactive since 2023); `revokt.com` is a live SaaS called "Revokt" (registered
2026-03-12), unrelated field.

**Trademark risk** is accepted as low (different field, descriptive compound); revisit only if the SaaS enters the
TLS or PKI field.
