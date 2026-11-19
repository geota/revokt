<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# revokt references: the verification log

Appendix A of the spec: what was verified against live sources and reference code, and when. Moved out of `revokt-spec.md` at revision 59 (#216), verbatim.

## Appendix A. Verification log (2026-10-21, additions 2026-10-22)

- Remote Settings `monitor/changes`: `cert-revocations` 1792598222216, `intermediates`
  1792465022155, `onecrl` 1792274405312, `ct-logs` 1792002263015.
- `cert-revocations`: 18 records, 9 per channel = 1 full (effective 2026-10-17) + 8 deltas through
  2026-10-21. Signed by `onecrl_202402`; x5u chain leaf P-384 (2026-09-06 to 2026-11-25) →
  `Content Signing Intermediate` (P-384) → `root-ca-production-amo` (RSA-4096, 2024-02-01, SHA-256 `C8A80E9A…A106DB`).
- **`root-ca-production-amo`, the §7.1 pinned root** (revision 49, verified 2026-11-05): SPKI SHA-256 (over the DER
  `SubjectPublicKeyInfo` TLV) `3317FA45154AC7DA55694D3782316056471FC147C04AED3E03FFE99565B1E2E7`; certificate SHA-256
  `C8A80E9AFAEF4E219B6FB5D7A71D0F101223BAC5001AC28F9B0D43DC59A106DB`; self-signed, subject `C=US, O=Mozilla
  Corporation, OU=Mozilla AMO Production Signing Service, CN=root-ca-production-amo`, RSA-4096, valid 2024-02-01 to
  2200-12-03. Two independent sources give byte-identical DER:
  - the terminal certificate of the live x5u chain the `cert-revocations` changeset names (signer `onecrl_202402`,
    `content-signature-2.cdn.mozilla.net/g/chains/202402/onecrl.content-signature.mozilla.org-2026-12-15-22-12-40.chain`),
    a rotated chain: its leaf is valid 2026-09-26 to 2026-12-15, where the bullet above recorded 2026-09-06 to
    2026-11-25. Its leaf and `Content Signing Intermediate` verify up to it under `openssl verify`;
  - Firefox's built-in content-signature production root, `security/manager/ssl/content-signature-prod.pem` in
    `mozilla-firefox/firefox` at `cac25a6` (the file last changed in `3ad0ffc`, bug 1914064), the anchor of
    `nsIContentSignatureVerifier.ContentSignatureProdRoot`.

  application-services' Remote Settings client pins the same certificate SHA-256 (`ROOT_CERT_SHA256_HASH_PROD`,
  `components/remote_settings/src/client.rs` at `9ef6d76`). The SPKI hash was computed twice with OpenSSL 4.1.0: from
  `openssl x509 -pubkey` re-encoded as DER, and from the SPKI TLV cut out of the certificate at its DER offset.
- `onecrl`: 1,901 records; 645 `enabled = false`.
- Filters begin `03 00` (v3) on both channels; `default` 6,006,419 B, `compat` 1,574,015 B.
- Firefox: `crlite_channel` `"compat"` on Android; `crlite_mode` 2; `crlite_timestamps_for_coverage` 1;
  OCSP fallback when CRLite is stale or absent.
- C2SP `upki-revocation@v1.0.0`: the spec says v4; `clubcard-crlite` (the crate upki depends on, `bincode` feature) decodes version bytes 3 and 4, so upki reads Mozilla's v3 filters as served (verified 2026-10-22 in rustls/upki `Cargo.toml` and clubcard-crlite `Encoding::read`); aggregation over covering filters only; selection goes through `index.bin`'s log directory (`Index::check` binary-searches it per SCT and loads only the named filters). **Closed in revision 56** (the 0.2 verification of overlapping windows): upki v1.0.1's `Index::write` (`upki/src/revocation/index.rs`, from line 156) pushes, for each manifest file and each `(log, interval)` of its coverage, one entry, so a full and its deltas sharing boundary timestamps are separate entries per (log, filter); the §3.2 selection-equivalence check admits them. **The index magic** (revision 56): upki v1.0.1 reads `upkiidx1` and the legacy `upkiidx0` (`index.rs`, the header read); revokt reads `upkiidx1` only and rejects `upkiidx0` (§3.2).
- C2SP `upki-revocation@v1.0.0` filenames, read 2026-11-04 at the pinned commit `7e6ded4` (`upki-revocation.md`, "Revocation cache directory layout", "Header" and "Filename table"): filter filenames "MUST be between 1 and 32 bytes long and MUST consist only of the ASCII characters `A`–`Z`, `a`–`z`, `0`–`9`, hyphen (`-`), period (`.`), and underscore (`_`)"; "The names `.` and `..` MUST NOT be used"; an index naming a file that violates these is malformed; each name slot is 32 bytes, zero-padded; `num_filenames` limits an index to 65535 files. The spec states no uniqueness rule for filenames, does not reserve `index.bin` as a filter name, and sets no size cap on `index.bin`: revokt's derived names (§6.5), its `index.bin` reservation (§6.3) and its 1 MiB cap (§3.2) are its own rules (revision 48), as are a mirror manifest's checks of reserved names and of uniqueness ignoring ASCII case, and its ban on a trailing `.` (§7.3, revision 52). `C2spIndex.isFilename` implements exactly the filename rule.
- `upki.rustls.dev`: GitHub Pages, `default` only, v4 transcode; `upki-mirror` verifies the
  attachment hash, not the content signature. `upki-mirror` writes only `manifest.json` and the filter files;
  `upki fetch` builds `index.bin` locally from the manifest's files in its cache directory (v1.0.1
  `upki/src/revocation/fetch.rs`, `PlanStep::SaveIndex` → `Index::write`, read 2026-11-06 at tag v1.0.1, commit
  `9821cce`; `upki-mirror` there names no `index.bin`). For a filename over 32 bytes, `Index::write` returns no
  index; revokt instead gives the file its §6.5 derived name
  and builds the index under it (§7.3, revision 53). upki FFI: three functions; no Android prebuilt.
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
  JDK 24 ships ML-DSA (backported in 17.0.21 and 21.0.13). No provider of JDK 17.0.21, 21.0.13 or 27 registers
  SLH-DSA or a composite OID (revision 51). A composite signature is not one operation of the JDK's providers, so
  only a provider registering the composite OID verifies one.
  - **Conscrypt uber 2.7.0 and 2.8.0** (revision 51; both register the same set). Probed on JDK 17.0.21 and 21.0.13
    with a single-file Java program over the Gradle-cached jars. It lists the provider's `Signature`, `KeyFactory`
    and `KeyPairGenerator` services and their `Alg.Alias` entries, then looks each algorithm up by name, bare OID and
    `OID.`-prefixed OID.
    - **ML-DSA-44, -65 and -87:** registered by name and by both OID aliases. Each verifies a signature the JDK's
      `SUN` provider made, with the key decoded from the JDK's SPKI encoding, and rejects it with one bit flipped.
    - **SLH-DSA-SHA2-128s:** registered by name only, with no OID alias for 2.16.840.1.101.3.4.3.20 (the OID its
      own keys encode). It also registers a HashSLH-DSA `SLH-DSA-SHA2-128S-WITH-SHA384`, by name only. Only a
      Conscrypt-made signature was checked, since none of those JDKs makes one.
    - **15 composite ML-DSA OIDs** of draft-ietf-lamps-pq-composite-sigs: `1.3.6.1.5.5.7.6.37`–`.46`, `.48`,
      `.49` and `.52`–`.54` (not `.47`, `.50` or `.51`). Each is registered for `Signature`, `KeyFactory` and
      `KeyPairGenerator` under a name such as `MLDSA44-RSA2048-PSS-SHA256`, with a bare OID alias but no
      `OID.`-prefixed one. Each round-trips a Conscrypt-made key and signature, and the key's SPKI
      carries the OID. **Unverified:** whether Conscrypt's composite key and signature encodings match draft -19.
      The round trip shows only that Conscrypt agrees with itself; no draft test vector or other implementation
      was checked.
    - **PSS:** there is no `RSASSA-PSS` `Signature` or `KeyFactory` and no `id-RSASSA-PSS` alias. PSS is registered
      only as `SHA1withRSA/PSS` to `SHA512withRSA/PSS`.
    - **`JcaSignatureVerifier` over Conscrypt** (at `5d419cc`): a scratch `jvmTest` on 21.0.13 ran under both
      releases. Printed in full, `unsupportedOids()` is exactly the 21 OIDs §3's "From OID to JCA service" lists,
      identical under both releases. ML-DSA-44/65/87,
      SLH-DSA-SHA2-128s and the 15 composites each give `VERIFIED` for a Conscrypt-made key and signature, and
      `INVALID` with one bit flipped. A SHA-1 PSS signature is `UNSUPPORTED` over Conscrypt and `INVALID` over the
      JDK's providers, which verify it themselves.
    - **Not probed:** the platform Conscrypt on Android, whose version is the device's.
  - **PSS salt on the JDK** (revision 51, a scratch `jvmTest` at `5d419cc` on 21.0.13, 2048-bit key, SHA-256 and MGF1
    with SHA-256): `RSASSA-PSS` throws `InvalidAlgorithmParameterException` for salts of 2,048 and 2,049 bytes, and
    `ArithmeticException` from 2,147,483,614 up to `Int.MAX_VALUE`. The verifier gives `INVALID` for each.
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
    bytes away in `getEncoded()`. Conscrypt was not probed; BoringSSL parses strict DER lengths and tags (it accepts a
    `UTCTime` differential, revision 41).

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
  - JDK 27 also accepts a definite TBS holding an indefinite Validity, on the same three leaves. `verify` fails, 3a
    rejects it, and 3b's walk does not locate it. Oracle 4 rejects its `canon` ("Validity: indefinite length found
    (not DER)").
  - Read through the platform canon (§9.2 revision 39), each of the nine parses, has a raw-byte reference and passes
    D1 and D2 on JDK 17, 21, 25 and 27 (the replay; JDK 25's `verify` was not probed, and it accepts the same three
    inputs as JDK 27); oracle 4 rejects the platform canon of the three that JDK 25 and 27 accept, which are
    D1-dom.
  - No other platform-accepted input lacks a raw-byte reference. `getEncoded()` differs from the input on 18 inputs: a
    non-minimal outer `Certificate` header, re-encoded minimally, and trailing bytes, dropped.
- Revision 41 probes, run 2026-10-25:
  - JDK 17.0.20.1+1 and 17.0.20+8 have no ML-DSA `KeyFactory`; `getPublicKey()` on an ML-DSA leaf is a generic
    `X509Key` whose `getEncoded()` is `30 82 05 34 30 0d 06 09 60 86 48 01 65 03 04 03 11 05 00 …` where the
    certificate's SPKI is `30 82 05 32 30 0b 06 09 … 03 82 05 21 …`; 17.0.21+9 and 21.0.13 return a named ML-DSA key
    with the presented bytes.
  - Conscrypt uber 2.7.0 and 2.8.0 read `UTCTime` `261022134530+0100` and `261022134530-0130` both as
    2026-10-22T13:45:30Z, where the JDK reads 12:45:30Z and 15:15:30Z; both reject a `GeneralizedTime` with `+0100`,
    and both they and the JDK reject a differential of `+2400` or `+0099`.
- Revision 42 probe, run 2026-10-25: the pinned producer (`mozilla/crlite` go `0082998`, `rootprogram/issuers.go`)
  loads `https://ccadb.my.salesforce-sites.com/ccadb/Report?Name=MozillaAllUnexpiredPEMs`; it requires
  `zcx509.ParseCertificate` to succeed, skips revoked rows (a `Revocation_Status__c` other than empty or "Not
  Revoked"), uses roots only as verification anchors (never enrols them), keeps the intermediates zcrypto verifies to a
  Mozilla root with serverAuth at the run's time, re-parses each with `ctx509.ParseCertificate`, dropping it on any
  error, non-fatal included, and keys it by `types.NewIssuer`'s `SHA-256(RawSubjectPublicKeyInfo)`
  (`LoadEnrolledIssuers` re-parses with `ctx509.ParseCertificate` and fails the whole load on any error). Run over that
  day's report (2 662 rows, 2 544 intermediates), it admits 1 852 issuer keys: exactly the distinct SPKIs of the
  `intermediates` collection's 1 903 certificates. The live full filter that day was the `20261017-1` compat generation
  (the committed fixture): its index has 1 033 keys, all 32 octets, and the committed `20261021-1` delta's has 1 030, 2
  of them not in the full filter's (both in that day's report). 1 017 of the full filter's keys are in the program set;
  the other 16 are in neither the report nor the collection, under any parse path, and crt.sh finds an unexpired CA
  certificate for each by `spkisha256` (intermediates under UniTrust, NAVER and emSign roots; one checked was issued by
  "emSign Root TLS CA - G3", itself absent from that day's report), consistent with their leaving the report after the
  generation. Of the `intermediates` records, 1 020 (modified 2019-06-07 to 2024-10-21) carry `crlite_enrolled: false`
  and the 883 since 2024-11-09 omit it; none marks it true.
- Revision 43 probe, run 2026-10-25 over the issuer corpus (10 347 distinct certificates; the revision 42 snapshots
  with the CCADB `AllCertificatePEMsCSVFormat` export by `NotBeforeYear`, the 15 records-export certificates that
  export lacks from crt.sh by fingerprint, the matrix JDKs' `cacerts` and AOSP `ca-certificates`): every key of the
  fixture generation's two indexes (1 035) is `SHA-256(rawSpki)` of one of them, so no certificate was fetched by SPKI
  hash for coverage; 10 343 parse through oracle 4's `ct` path and all agree with revokt. On 5 of
  those, `canon` differs from the DER only in the outer `signatureAlgorithm` (sha1WithRSAEncryption where the TBS
  names ecdsa-with-SHA384 or sha384WithRSAEncryption); their TBS is the DER's, and ct-go rejects their DER
  ("mismatching signature algorithm identifiers", `x509/x509.go`). None of their SPKIs is an index key. The records
  export lists 15 certificates the PEM export lacks (10 "Bayerische SSL-CA-20xx", 4 "Dell Inc. Enterprise CA", "DPDHL
  TLS CA I3", all revoked and not trusted), fetched from crt.sh. The CT seed pilot (22 559 leaves, 80 of the 81
  CRLite-enrolled logs; Let's Encrypt Oak2026h2 did not answer `get-sth`) has 19 846 unexpired leaves JDK 21 accepts,
  all in the D1 domain, and no D8-gap entry among them.
- Revision 44, the CT seed corpus, collected 2026-10-25T23:56:38Z to 2026-10-26T00:22:38Z by revokt-corpus
  `tools/ct-seed/collect.py` (seed 20261026: five random data tiles of each static-ct-api log, eight random 256-entry
  `get-entries` batches of each RFC 6962 log, paged until complete): 118 528 entries read and 110 043 distinct
  certificates as logged, from 80 of the 81 CRLite-enrolled logs (Let's Encrypt Oak2026h2 did not answer `get-sth`).
  91 345 of them are unexpired and accepted on each matrix JDK, all in the D1 domain; 6 are D8-gap leaves, all issued
  by eMudhra's "EM DV TLS CA - G3B" for subjects under `Shelikhoo.kkdev.org.invalid`, logged at indices near 2 000 of
  GoDaddy's Aquamarine2027h2 and Aquamarine2028h2: 4 with a `notBefore` of 0000-01-01 or 0001-01-01 (GeneralizedTime;
  K6, zlint clean) and 2 with ordinary times outside the profile at EXTENSION (zlint: a SAN `uniformResourceIdentifier`,
  nameConstraints in a leaf, an invalid TLD, among others). Conscrypt 2.7.0 and 2.8.0 report the four `notBefore` as
  -62167392000000 (year 0000) and -62135769600000 (year 0001) ms, exactly `java.util.GregorianCalendar`'s lenient hybrid
  reading, two days before the proleptic Gregorian -62167219200000 and -62135596800000 that the JDK and revokt give. JDK
  21 reports `id-pkix-ocsp-nocheck` empty on 2 leaves that carry `05 00`, both eMudhra's: a leaf of "EM DV TLS CA -
  G3B" and an OCSP responder certificate of "emSign Root TLS CA - G1".
- Revision 45, the CT seed corpus at revokt-corpus `v5`. The log sample is revision 44's without the leaves whose issuer
  Name (as DER, by SHA-256) is a CT test issuer, dropped by `tools/ct-seed/drop-test-issuers.py`: C=GB, ST=London,
  O=Google UK Ltd., OU=Certificate Transparency, CN=Merge Delay Intermediate 1 (`83dafb70…`, 35 447 leaves); O=Geomys,
  CN=CT Uptime Test Root (`f4097973…`, 7 407); CN=DigiCert CT Monitor, C=US, ST=UT, L=Lehi City, O=DigiCert, Inc.
  (`8d070279…`, 1 598); C=CN, O=TrustAsia Technologies, Inc., CN=TrustAsia DV TLS ECC Test CA G4 (`11bcaeb7…`, 2, in no
  CCADB snapshot). 65 589 leaves remain, 60 427 of which JDK 21 verifies under an index key, of 201 keys. The top-up was
  read from crt.sh's public database (`certwatch`, as `guest`) by `tools/ct-seed/topup.py` from 2026-10-29T14:02:24Z to
  2026-10-29T23:06:44Z, the end of the last run that queried it (`crtsh.json`'s `finished` is a later run that only
  rewrote the outputs from the cache; `crtsh-ca.json` is the cache's map of keys to crt.sh CAs): 1 034 of the 1 035
  index keys hash the public key of a crt.sh CA (1 036 CAs; "Telia CA EC QWAC R1", valid from 2026, has none), 71 629
  certificates were returned, 0 rejected (structure or signature), 0 filtered (not valid at the start, or a CA), 15
  duplicates of a TBSCertificate kept, 0 past the cap, and 71 614 kept, for 927 keys. The queries of 49 CAs reached
  crt.sh's statement timeout on every try, among them CAs that seem to have stopped issuing (Amazon RSA 2048 M03,
  Cloudflare TLS Issuing RSA CA 1) and some of the largest (Sectigo Public Server Authentication CA DV E36, Encryption
  Everywhere DV TLS CA - G2); the log sample covers 44 of their 49 keys. JDK 21 verifies 60 427 log-sample leaves under
  201 index keys and all 71 614 top-up leaves under 927, 132 041 leaves of 975 keys, 118 159 distinct index keys and
  serials. 117 603 of them are unexpired at the top-up's start and accepted on each matrix JDK (104 033 distinct index
  keys and serials), all in the D1 domain, with no D8-gap entry; the 6 gap leaves of revision 44 stay in the log sample,
  outside the count (their issuer is not an index issuer). crt.sh's server certificate (CN=crt.sh, Sectigo) had expired
  on 2026-06-21, and its `ca.last_not_after` showed no update after 2026-10-24 (both seen on 2026-10-29), so CAs were
  selected by key, not by recorded activity.
- **Revision 54, the ECDSA range check** (§3, #172): SEC 1 v2 §4.1.4 ("Verifying Operation") step 1 rejects a
  signature unless r and s are integers in [1, n − 1]. CVE-2022-21449 is the JDK skipping it, so that r = s = 0
  verified under any key.
  - **Affected versions:** the reporter's write-up (Neil Madden, "Psychic Signatures in Java", 2022-04-19, read
    2026-11-07) gives Java 15 to 18 before the April 2022 Critical Patch Update, since JDK 15 rewrote ECDSA in Java;
    the 15 to 18 range rests on it. Oracle's advisory (`cpuapr2022.html`) still lists "Oracle Java SE: 17.0.2, 18"
    in its risk matrix; its revision log records Rev 2 (2022-04-21), "Updated the affected versions for
    CVE-2022-21449", and Rev 4, "Note Removed". NVD (CVE-2022-21449, read 2026-11-07) lists only the then-supported
    versions: "Oracle Java SE: 17.0.2 and 18; Oracle GraalVM Enterprise Edition: 21.3.1 and 22.0.0.2". The fix is in
    17.0.3 and 18.0.1. Within revokt's JVM 17+ target that is 17.0.0 to 17.0.2 and 18 GA. Every JDK revokt tests on
    (17.0.21, 21, 25 and 27) has the fix; revokt checks the range itself, so neither an older JDK nor an injected
    provider can bring the gap back.
  - **SunEC reads a negative INTEGER as unsigned** (checked 2026-11-07 on Temurin 17.0.21, 21.0.13 and 27 with a
    single-file Java program, not committed): for 20 P-256 `SHA256withECDSA` signatures each, an r re-encoded without
    its required leading `00`, so that it reads as negative, still verified (20 of 20 on each JDK), while an r with a
    redundant leading `00` did not (0 of 20). revokt's profile rejects both, so it is stricter than SunEC there.
  - **High s:** the #163 review found Mozilla's `ct-logs` collection signature with s > n/2; SEC 1 and NSS accept a
    high s, so revokt does too.
  - **Composite owners range-check their ECDSA component** (revision 55, §3), read at each project's main branch on
    2026-11-07, not at the versions revokt tests:
    - BC: bc-java `core/src/main/java/org/bouncycastle/crypto/signers/ECDSASigner.java` `verifySignature` returns
      false unless 1 ≤ r ≤ n − 1 and 1 ≤ s ≤ n − 1 ("r in the range [1,n-1]");
    - BoringSSL: `crypto/fipsmodule/ecdsa/ecdsa.cc.inc` lines 74 to 81 reject a zero r or s (`ec_scalar_is_zero`),
      and `crypto/fipsmodule/ec/scalar.cc.inc` `ec_scalar_from_bytes` (lines 73 to 85) rejects a value ≥ n.
- **Revision 54, the x5u chain follows mozilla::pkix at Firefox `cac25a6fa321b0051932359b84c4e2fe3caabdc5`**
  (tag `FIREFOX_BETA_161_BASE`, 2026-11-05), with rustls-webpki consulted, read 2026-11-07 (Firefox through the
  GitHub contents API; webpki from the local cargo registry). That reading used 0.103.15; upki at 9821cce builds paths
  with 0.104.0-alpha.7 (`upki/Cargo.toml:32`), and the rows that depend on webpki were re-read against it on
  2026-11-16 (#217, `docs/decisions/DIVERGENCES.md`):
  - `pkixcert.cpp` `BackCert::RememberExtension` understands keyUsage, subjectAltName, basicConstraints,
    nameConstraints, certificatePolicies, policyConstraints, extKeyUsage, inhibitAnyPolicy, authorityInfoAccess, the
    TLS feature extension, the embedded SCT list and qcStatements, plus `id-pkix-ocsp-nocheck` (whose value may be
    empty) and the Netscape certificate type only when critical. Any other critical extension is
    `ERROR_UNKNOWN_CRITICAL_EXTENSION` (`pkixder.h` `OptionalExtensions`, and `pkixcert.cpp` line 161 for the
    Netscape type, understood only when basicConstraints and extKeyUsage are both present). An understood
    extension with an empty value is `ERROR_EXTENSION_VALUE_INVALID`.
  - `pkixder.h`: `Boolean` takes `00` or `FF` only; `OptionalBoolean` accepts an explicit FALSE; `OptionalExtensions`
    accepts an empty Extensions SEQUENCE (bug 997994); `CertificateSerialNumber` accepts a negative or zero serial;
    `OptionalInteger` reads 0 to 127 only, which bounds `pathLenConstraint`. `pkixder.cpp` `OptionalVersion` accepts
    0 to 3 and an explicitly encoded v1 (bug 1031093); `TimeChoice` reads `YYMMDDHHMMSSZ` and `YYYYMMDDHHMMSSZ`
    for either type, with no year rule between them, and rejects a year before 1970. `pkixcert.cpp` parses the
    extensions of v1 and v2 certificates as of v3. `pkixcheck.cpp` `ParseValidity` rejects notBefore > notAfter (line 170), and
    `CheckKeyUsage` reads the keyUsage bits without requiring the minimal named-bit encoding.
  - `pkixcheck.cpp`: `ERROR_SIGNATURE_ALGORITHM_MISMATCH` compares the parsed outer and TBS algorithms, so a NULL and
    an absent parameter are equal (line 82); `ERROR_EMPTY_ISSUER_NAME` for an issuer with no RDN (line 143);
    `ERROR_CA_CERT_USED_AS_END_ENTITY` (line 705); `CheckExtendedKeyUsage` requires the purpose in every present
    extKeyUsage, anyExtendedKeyUsage not counting, and rejects `id-kp-OCSPSigning` in an end entity (line 864);
    `CheckSubjectPublicKeyInfo` takes a namedCurve P-256, P-384 or P-521 with an uncompressed point of exact length,
    or `rsaEncryption` with NULL parameters and positive modulus and exponent, and a BIT STRING without unused bits;
    `CheckTLSFeatures` (line 885) requires a child to carry its issuer's TLS feature value.
  - `pkixder.cpp` accepts `id-RSASSA-PSS` only with one of three parameter encodings, matched byte for byte (lines
    186 to 250, NULL hash parameters and no explicit `trailerField`), and NULL or absent parameters for the other
    signature algorithms (line 259).
  - `pkixbuild.cpp` checks an issuer's nameConstraints whenever they are present, critical or not (line 173), and
    `pkixnames.cpp` matches a dNSName subtree on label boundaries, ignoring case, with `""` matching every name; it
    rejects an empty NameConstraints, an encoded `minimum` or `maximum` and an invalid base, and applies a permitted
    subtree only to names of its own type.
  - **Revision 55:** at the same commit, `pkixbuild.cpp` lines 218 to 229 extract an end entity's embedded SCT list
    with `pkixcert.cpp` `ExtractSignedCertificateTimestampListFromExtension` (lines 312 to 322:
    `ExpectTagAndGetValueAtEnd(extnValue, OCTET_STRING, …)`), and a failure fails every path through the
    certificate, as revision 46 recorded at `86136a5`.
  - **webpki's divergences**, consulted and not followed (at 0.104.0-alpha.7, upki's version; re-read for #217): its
    understood critical set is only id-ce 15, 17, 19, 30, 31 and 37 (keyUsage, subjectAltName, basicConstraints,
    nameConstraints, cRLDistributionPoints, extKeyUsage) and the SCT list (`cert.rs` lines 319 to 347); it does not
    require keyCertSign on a CA, reading keyUsage only for CRL checks (`verify_cert.rs` lines 151 and 171); it requires
    v3 (`UnsupportedCertVersion`, `cert.rs` lines 276 to 291); it compares the outer and TBS algorithms by bytes
    (`SignatureAlgorithmMismatch`, `cert.rs` lines 90 to 92); and it checks every descendant's names against
    nameConstraints. Unique IDs, which 0.103.15 rejected, are skipped (`cert.rs` lines 123 to 139), as mozilla::pkix
    and revokt do.
  - **Differences from mozilla::pkix that remain, each by §7.1's own text:** the terminal is its pinned SPKI only
    (Firefox matches the root's DER and checks it), so the terminal's nameConstraints are never read, and neither is its
    TLS feature, which Firefox also checks against the anchor's child; the path is the
    x5u order with no depth cap (both references build by name, at most six sub-CAs); name chaining also accepts the
    canonical form; the leaf SAN holds dNSNames only and never matches a wildcard; RSA size counts significant bits
    (Firefox rounds to bytes); a seed's chain validity is checked at its signed time; links are not checked against
    OneCRL; nameConstraints are checked against the leaf's name only, where mozilla::pkix and webpki check every
    descendant.
  - **Stricter than mozilla::pkix:** any repeated extension OID fails (RFC 5280's MUST NOT), where mozilla::pkix
    rejects only a repeated extension it understands; a nameConstraints with a directoryName subtree fails closed,
    where mozilla::pkix checks it against the subject. (mozilla::pkix's check of the subject's emailAddress against
    rfc822Name subtrees runs only for a certificate with no subjectAltName, so it cannot apply to the leaf, which
    must carry one.) Mozilla's `Content Signing Intermediate` carries a
    non-critical nameConstraints with two dNSName subtrees only (`content-signature.mozilla.org` and
    `.content-signature.mozilla.org`), which the leaf satisfies.
- **Revision 56 sources** (read 2026-11-12 unless a date is given: Firefox at
  `cac25a6fa321b0051932359b84c4e2fe3caabdc5` through the GitHub contents API, cel-spec at `21ec6f4`, upki v1.0.1's
  `revocation/mod.rs`, `revocation/fetch.rs`, `revocation/index.rs` and `lib.rs` and upki-mirror's `mozilla-crlite.rs`
  in the cargo git checkout of tag `v1.0.1` (`9821cce`), and the crates below from the local cargo registry):
  - **The attachments base URL:** `https://firefox-settings-attachments.cdn.mozilla.net/` is
    `capabilities.attachments.base_url` of `https://firefox.settings.services.mozilla.com/v1/`, with its trailing
    `/`, read 2026-11-06/07 in the review of #177 and again on 2026-11-12 (kinto-attachment 9.0.1). §7.1 reads it from
    the server root, as Firefox does: `Utils.sys.mjs` at `cac25a6fa321b0051932359b84c4e2fe3caabdc5` (lines 335 to 387)
    fetches `${SERVER_URL}/`, takes `capabilities.attachments.base_url` with no host check, and caches it in the
    `services.settings.base_attachments_url` pref keyed by the server URL. revokt checks the host against
    `allowedDomains` and keeps nothing after the sync.
  - **`buildIndex` against Firefox and upki-mirror:** Firefox's `RemoteSecuritySettings.sys.mjs` at
    `cac25a6fa321b0051932359b84c4e2fe3caabdc5` (lines 645 to 659) takes the records' full filters, refuses unless
    there is exactly one ("expected 1"), and takes every incremental record beside it, reading no `parent`; revokt's
    `buildIndex` does the same (§6.5). upki-mirror v1.0.1's `mozilla-crlite.rs` instead maps each record by its `parent`
    (line 47, a `HashMap`, so of two records with one parent only the last is kept) and walks from the `default`
    channel's full filter with no `parent` (lines 54 to 66). The two differ only on unusual data: a delta outside the
    chain (revokt places it; it can only add revocations), two deltas with one parent (revokt places both; upki-mirror
    follows one), or two fulls (revokt refuses; upki-mirror takes the first it finds).
  - **The changeset `<ts>`, `_since` and `metadata.signatures`:** Firefox's `RemoteSettingsClient.sys.mjs` at
    `cac25a6fa321b0051932359b84c4e2fe3caabdc5` builds the signed payload from the changeset's `timestamp`
    (`_fetchChangeset` reads it from the envelope at line 1354, and `validateCollectionSignature`, from line 1076,
    canonicalises the records with it), requires a non-empty `metadata.signatures` array and accepts the first entry
    that verifies (from line 1097); `Utils.sys.mjs` sends
    `_since` bare (`params._since = lastEtag`, line 518). Each entry gives `x5u`, `signature` and `mode`; an entry
    missing `x5u` or `signature`, or with a `mode` other than `p384ecdsa`, is skipped with a warning (line 1103), and
    when none verifies the first error is thrown (line 1132). revokt reads `signatures[]` the same way (§7.1),
    with four differences: it skips an entry whose `mode` is `""` or not a string, where Firefox tries a falsy one; it tries only the first 4
    entries and ignores the rest, where Firefox tries them all; it reuses an `x5u` already fetched and validated in
    the same sync, and does not retry one that failed; and when none verifies it reports the last entry's error, where
    Firefox throws the first.
  - **CEL's logical operators**, the model for `Exemptions.and`/`or` (§4): cel-spec `doc/langdef.md` at
    `21ec6f4e52e8d694687ff9ed7408d3eccbb955d7`, "Logical Operators": "if any of their operands uniquely determines the
    result (`false` for `&&` and `true` for `||`) the other operand may or may not be evaluated, and if that
    evaluation produces a runtime error, it will be ignored. This makes those operators commutative". revokt
    evaluates left to right and absorbs the other side's error exactly when one side decides.
  - **The mirror protocol** (§7.3): upki v1.0.1 `revocation/mod.rs` (`Manifest`: `generated_at: u64`, `comment:
    String`, `files` with the serde alias `filters`; `ManifestFile`: `filename`, `size`, `hash` as hex) and
    `revocation/fetch.rs` (the manifest URL `<fetch_url>manifest.json`, `If-Modified-Since` and the 304 reuse, a file
    URL `<remote_url><filename>`, `REQUEST_TIMEOUT` of 30 s, one client timeout for the whole request, redirects
    included); upki's redirect limit is reqwest's default, `Policy::limited(10)` (`src/redirect.rs`) in reqwest 0.13.0,
    the version upki v1.0.1's `Cargo.lock` pins; upki does not set `https_only`, so reqwest would follow an
    `https`-to-`http` hop, which the cut mirror design refused (`docs/design/mirror-and-system-cache.md`). The live mirror listed 40 files (1 full and 39 deltas, 14.3 MB)
    on 2026-11-06. reqwest 0.13.0's `remove_sensitive_headers` (`src/redirect.rs`) drops `Authorization`, `Cookie`,
    `cookie2`, `Proxy-Authorization` and `WWW-Authenticate` on a hop to another host or port; the cut mirror's
    `RedirectingFetcher` stripped the same headers on such a hop, but kept them stripped where reqwest re-sends them
    (revision 58 sources).
  - **The memory figures** (§6.4): the live `cert-revocations` changeset
    (`/v1/buckets/security-state/collections/cert-revocations/changeset?_expected=0`), read 2026-11-12, `timestamp`
    1794499022363, 106 records; per channel 1 full and 52 deltas; the signed `attachment.size` values sum to 8,558,354
    bytes on `compat` (full 1,574,015) and 18,593,366 on `default` (full 6,006,419). The committed fixtures hold no
    whole changeset, so the live one was measured. Its `metadata` carried both `signature` and a one-entry
    `signatures`.
  - **upki `c2ba5e3`** (main, 2026-10-21, "mirror: convert CRLite v3 filters to v4", read through the GitHub API): its
    upki-mirror re-encodes a filter whose version byte differs from the configured encoding with
    `CRLiteClubcard::to_bytes(encoding)` and then sorts the encoded coverage entries by log ID, since
    `clubcard-crlite` writes them in `HashMap` order; v1.0.1 has no such step. revokt's oracle leg (§3.2) is the bare
    `to_bytes(V4)` without the sort.
  - **`rustls-pki-types` 1.15.1** (upki v1.0.1's pin), `src/pem.rs` and `src/base64.rs`: the labels it knows
    (`CERTIFICATE`, `PUBLIC KEY`, `RSA PRIVATE KEY`, `PRIVATE KEY`, `EC PRIVATE KEY`, `X509 CRL`, `CERTIFICATE
    REQUEST`, `ECHCONFIG`), `-----BEGIN ` and `-----END ` line matching, and a decoder that skips whitespace and
    accepts missing padding; `X5uPem` reproduces it (§7.1).
  - **upki's cache roots** (the cut `c2spCache`, `docs/design/mirror-and-system-cache.md`): upki v1.0.1 `upki/src/lib.rs`, `Config::try_default` (the user cache from
    `ProjectDirs::from("dev", "rustls", "upki")`, else the system cache when the user cache does not exist and the
    system one does) and `platform::system_cache_dir` (`/var/cache/upki` on Unix, `/Library/Caches/dev.rustls.upki`
    on Apple, `%ProgramData%\rustls\upki\cache` on Windows), with `revocation` appended
    (`revocation_cache_dir`).
- **Revision 57 sources** (Firefox at `cac25a6fa321b0051932359b84c4e2fe3caabdc5`):
  - **`Backoff` and `Retry-After`** (§7.1), read 2026-11-14 through the GitHub contents API: `Utils.sys.mjs`
    `fetchLatestChanges` throws on a status of 500 or more (lines 529 to 531), on a non-JSON `Content-Type` (lines 537
    to 540) and on JSON without a `changes` member (lines 549 to 560) before it reads `Backoff` (lines 570 to 576), and `remote-settings.sys.mjs` persists that value as the
    `server.backoff` pref (lines 507 to 516). Neither file reads `Retry-After`. kinto-http reads both headers on every
    response, but `RemoteSettingsClient.sys.mjs` builds its kinto-http client with only a `fetchFunc` (lines 391 to
    395), so no listener takes kinto-http's backoff and no retry follows a `Retry-After` (the 2026-11-13 decision
    audit read kinto-http's side). revokt honours both on every response, so it is stricter than Firefox, not equal
    to it.
  - **The `signatures[]` loop** (§7.1), `RemoteSettingsClient.sys.mjs` lines 1100 to 1132, read 2026-11-14 through the
    GitHub contents API: `const { x5u, signature, mode } = sig` (line 1102) throws on a `null` element; `!x5u ||
    !signature` (line 1103) skips an empty string as a missing one; `(await Utils.fetch(x5u)).text()` (line 1109) reads
    the body without checking the status, so a 404 or 5xx body goes to verification, which fails, and the loop moves
    on (the #198 review), while a rejected fetch (a network error, timeout or abort) leaves the loop at once. revokt
    moves on after any failed fetch, a fifth difference beside the four listed under revision 56.
  - **Issuer labels and candidate order** (§5.1 decision step 6, `related()`, §8), as the maintainer's decisions of
    2026-11-13 and 2026-11-14 on #196 record them (not re-read for this revision): mozilla::pkix runs
    `CheckIssuerIndependentProperties` (`pkixcheck.cpp`, line 993; `pkixbuild.cpp`, lines 106 to 117) before it
    verifies the link's signature, and defers an end-entity error until an issuer is found (`pkixbuild.cpp`, lines
    281 to 292 and 354 to 357); `SSLServerCertVerification.cpp` (lines 247 to 252) puts both errors in one override category;
    `CertVerifier.cpp` (lines 312 to 315) applies the anchor-dependent CT rules to the one chain it built; and
    `NSSCertDBTrustDomain` `FindIssuer` offers roots first, then the presented certificates, then the preloaded
    intermediates. upki takes one webpki `VerifiedPath` (rustls-upki `lib.rs`, lines 95 to 127), the model for
    `EvaluationRequest.verifiedPath` (§4).
- **Revision 58 sources** (§7.3 "Redirects", read 2026-11-15):
  - **reqwest 0.13.0 and tower-http 0.6.11**, the versions upki v1.0.1's `Cargo.lock` pins (read through the GitHub
    contents API), from the local cargo registry. reqwest follows redirects through tower-http's `FollowRedirect`:
    `follow_redirect/mod.rs` follows only 301, 302, 303, 307 and 308 and returns any other status as it came (lines
    273 to 293); it takes the response's first `Location` (`HeaderMap::get`, which returns the first of several values,
    http 1.5.0 `src/header/map.rs` lines 786 to 790) and returns the response unchanged when there is none or it does
    not resolve against the request URI (lines 301 to 309). So reqwest returns a 3xx with no `Location`, as revokt does,
    and follows the first of two differing `Location`s, where revokt fails, as Necko does. reqwest's
    `TowerRedirectPolicy::redirect` (`src/redirect.rs`, lines 306 to 334) refuses a hop only for a scheme other than
    `http` or `https` (and `http` under `https_only`), so a hop to an IP literal host is followed: url 2.5.8's `Host` is
    `Domain`, `Ipv4` or `Ipv6` (`src/host.rs`, lines 46 to 64). `Policy::limited(10)` is the default (lines 160 to
    164) and only counts: it errors once the URLs already requested, the initial one included, exceed 10 (lines 131
    to 141), so it follows 10 redirects as revokt does, and has no loop check of its own; revokt's is its own rule.
    tower-http rebuilds each hop's headers from the original request's (`follow_redirect/mod.rs` line 327,
    `*req.headers_mut() = this.headers.clone()`), and reqwest's `on_request` then strips the five credential headers from
    that copy only when the next host or port differs from the previous URL's (`src/redirect.rs`, lines 239 to 250 and
    336 to 338), so on a chain A → B → B reqwest strips them for the first hop to B and sends them again on the second;
    revokt keeps them stripped. The same `on_request` adds a `Referer` when `referer` is set (lines 339 to 345), which
    reqwest's `ClientBuilder` defaults to true (`src/async_impl/client.rs` line 308); upki's client (`fetch.rs`, lines
    50 to 58) does not turn it off, so upki sends one on every hop, and revokt sends none.
  - **Firefox's Necko** at `cac25a6fa321b0051932359b84c4e2fe3caabdc5`, `netwerk/protocol/http/`, read through the
    GitHub contents API. `nsHttpChannel.cpp` processes 301, 302, 303, 307 and 308 as redirects, 305 being disabled
    (lines 3371 to 3378). `AsyncProcessRedirection` returns `NS_ERROR_FAILURE` when there is no `Location` ("carry on as
    though this were a normal response", lines 6929 to 6933), and `NS_ERROR_CORRUPTED_CONTENT` for a `Location` that
    does not parse (lines 6953 to 6958); the caller then renders the 3xx as a normal response unless the error is one
    of `DoNotRender3xxBody`'s (lines 3397 to 3409; `nsHttpChannel.h`, lines 533 to 537), which `NS_ERROR_FAILURE` is
    not and `NS_ERROR_CORRUPTED_CONTENT` is. `nsHttpHeaderArray::SetHeaderFromNet` fails a response whose second value
    of a header differs from the first with `NS_ERROR_CORRUPTED_CONTENT` when `IsSuspectDuplicateHeader` names the
    header (`nsHttpHeaderArray.cpp`, lines 192 to 196), and it names `Content-Length`, `Content-Disposition` and
    `Location` (`nsHttpHeaderArray.h`, lines 300 to 304); an equal second value is kept as one. That Necko follows a
    hop to an IP literal host is not cited here.
  - **upki v1.0.1's failure split** (§7.3 "Stages"), `upki/src/revocation/fetch.rs` in the cargo git checkout of tag
    `v1.0.1` (`9821cce`): a manifest request that fails to send or has an error status is `FetchError::HttpFetch`
    carrying the manifest URL (lines 82 to 93), and a body that is not a manifest is `FetchError::FileDecode` with no
    path (lines 95 to 104). A file download that fails to send, has an error status or fails while its body is read
    is the same `FetchError::HttpFetch`, carrying the file's URL (lines 290 to 310), and a body whose SHA-256 differs
    is `FetchError::HashMismatch` with the local path (lines 317 to 319). upki has no stage, so only the URL in the
    error tells a manifest fetch from a file fetch; revokt's `CHANGESET` and `ATTACHMENT` make that split explicit.
- Revision 46, mozilla::pkix at Firefox `86136a5faf970e59063cd07b822717f6fd03a958` (main, 2026-10-29), read
  2026-10-30: `pkixcert.cpp` `ExtractSignedCertificateTimestampListFromExtension` reads the SCT extension's
  `extnValue` with `der::ExpectTagAndGetValueAtEnd(extnValue, der::OCTET_STRING, …)`, which requires the tag `0x04`
  and then `der::End` (`include/pkix/pkixder.h`, lines 234 to 248), so nothing may follow the OCTET STRING;
  `pkixder.cpp` `ReadTagAndGetValue` rejects a high tag number, a non-minimal length (`81 nn` with nn < 128, `82`
  below 256) and every other length form (`0x80`, `0x83` and above), minimal or not, as `ERROR_BAD_DER`;
  `pkixbuild.cpp` (lines 218 to 229), for a `MustBeEndEntity` certificate, records a failure of that extraction as
  one where "all paths through it will fail" and stops building. `pkixcert.cpp` `BackCert::RememberExtension` (lines
  295 to 303) rejects a second SCT extension, as any duplicate extension it understands, with
  `ERROR_EXTENSION_VALUE_INVALID`.
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
- **Issuer basicConstraints** (revision 59), read 2026-11-16: rustls-webpki 0.104.0-alpha.7 `verify_cert.rs`
  `check_basic_constraints` (422–454) rejects an issuer with no basicConstraints or `cA` FALSE as `EndEntityUsedAsCa`
  (442, 448), and enforces `pathLenConstraint` (449); anchors are `TrustAnchor`s and are not checked. mozilla::pkix
  `pkixcheck.cpp` `CheckBasicConstraints` returns `ERROR_CA_CERT_INVALID` for a non-CA issuer (712–715) and
  `ERROR_V1_CERT_USED_AS_CA` for a v1 non-anchor without the extension (689–695), and checks anchors too (1057);
  `pkixbuild.cpp` checks the issuer (205) before `VerifySignedData` (212). **Divergence, followed from webpki:** revokt
  does not check an anchor's basicConstraints (pkix fails a v3 anchor without `cA = TRUE`). **Not followed yet:**
  `pathLenConstraint`, and pkix's `keyCertSign` requirement. **Also different from webpki, and unreachable without a
  real CA's signature:** revokt reads basicConstraints in a v1 or v2 certificate, which webpki rejects whole (it
  requires v3, `cert.rs` 276–290); and a `pathLenConstraint` above 255 still reads as a CA, which webpki reads as a
  `u8` and fails with `BadDer` (`verify_cert.rs` 436). More generally, revokt's parser keeps the JDK's envelope
  leniency on issuers (any version INTEGER, an extension `critical` BOOLEAN of any single byte, elements after
  extnValue or after `[3]`, an unknown critical extension), so it can read as a CA a certificate that webpki rejects
  whole; each such certificate still needs the signature of a key that chains to a real anchor.
