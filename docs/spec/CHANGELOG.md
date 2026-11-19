<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Spec changelog

The "Changes in revision N" blocks of `revokt-spec.md`, newest first, moved here verbatim at revision 59 (#216). Section numbers in them refer to the spec as it stood at that revision; §9 is now [test-plan.md](test-plan.md) and Appendix A [references.md](references.md).

### Changes in revision 60 (the trust-class cut of #218, #246, and the seed loader of #138)

- **#218, the trust-class cut:**
  - No MIRROR or SYSTEM source. `TrustClass`, `UNSIGNED_DATA`, `minTrustClass`, the bootstrap-only rule,
    `MANIFEST_LAST_MODIFIED`, `MAX_MANIFEST_ENTRIES` and the diagnostics `MIRROR_WITH_SEED_NEVER_INSTALLED`,
    `LOWER_CLASS_SOURCE_NEVER_INSTALLED` and `SOURCE_EMPTY` are gone.
  - The goals: §2 goal 2 is "authenticated data only".
  - §3.2: the loader builds every index it installs, and only a seed's is byte-compared.
  - §4: the API sketch, the validation bullets and the golden fixture's columns.
  - §5.1: the seed rule loses its class condition.
  - §6.3: the coverage bound applies to every generation.
  - §6.5: `meta.json` always carries the signed members; `records.json` is in every generation; `previous` has no
    rank rule.
  - §7: the source table and §7.3's stub. §7.3's hop grammar and the R diagnostic for a `c2spMirror` URL went with
    the source, and so did `StrictUrl`'s IP-literal mode.
  - §8: the `UNSIGNED_DATA` row and floor.
  - §10: the bootstrap-only and mirror bullets.
  - §11: the mirror and system-cache deliverables.
  - The test plan: data-path fixture (c) and the MIRROR, SYSTEM and `UNSIGNED_DATA` items.
- **#246:** §6.5 reads `current` strictly (an unknown or duplicate member is malformed); `previous` must read back as
  the loader reads it, `records.json` included; a heal flip is not followed by a prune (the lead's decision on r256).
- **#138 (#235):** §6.5 states the seed-load rule (a)/(b) with adopt, never-prune and never-delete, the `seed.json` encoding, the zip the loader reads, the `signature` cap of 64 KiB and the 256 MiB archive cap, the canonical `records.json` and the seed's generation id; §5.1's loader task cites the rule; the test plan's (f) replaces the `MIRROR` eviction rows with the rule's rows.

### Changes in revision 59 (the spec split of #216, and the deltas of #209, #234, #242 and #244, 2026-11-18)

- **The split.** `revokt-spec.md` is the normative core. §9 is now `test-plan.md` (section numbers kept), with the
  upki adapter and the cross-engine equivalence classes of §3.2 as its new §9.3; Appendix A is `references.md`; the
  revision blocks are this file. Moved to `docs/design/`, not normative: §5.1's trust managers per delegate, caches,
  readiness, read-only mode, storage fallback, listeners and HTTP/2 coalescing; §5.2 Android; §5.4 Ktor; the
  `reconstruct` pseudocode; §7.3 mirrors and the system cache (cut by #218); §8's fetcher policy (cut by #219);
  §7.4 and §7.5 (M2); §12. The core keeps a stub where a section moved. `specStatus` reads the fixture lists from
  `test-plan.md`.
- **Present tense.** The core drops every revision number, issue number and attribution of a decision; this file
  and `docs/decisions/` keep them. Text that #141 retired ("until #141 every sync fetches the whole changeset")
  states the delta poll as it runs.
- **#234 (#225):** every non-anchor path member must be a CA (`cA = TRUE`); `ISSUER_UNVERIFIED` folds into
  `NO_ISSUER(UNSUPPORTED_ALGORITHM)` (§2, §4, §5.1 step 6, "Findings", the PKIX fallback contract, §8, the test
  plan's (j), (ak), (al), (an), the §9.1 generator, reference walker and P8); fixture (aq); §10 drops the relabelling
  residual (14) and adds residual 15, "constrained sub-CA"; a verification-log entry on issuer basicConstraints.
- **#242:** a `_since` changeset merges over the pointed `records.json`; beside a malformed pointer, a directory with a
  `meta.json` is held, and only one without is staged; a failing storage read throws; the healed pointer's
  `previous`.
- **#209 (#231):** a sync whose `updater.json` read throws writes nothing: no attempt, no `consecutiveFailures`, no
  backoff, and it is not an attempt for the §8 `STALE` gate; `storeFailures` is the only signal.
- **#244:** its corrections of fact (the webpki pin, the reference columns) are recorded here.
- **Kept in the core from §7.3:** the x5u URL grammar (DNS host names only, port 443, lowercase `https://`, `pchar` path
  and query, the fragment rule, `FAILED` at stage `X5U`, never repaired) is stated in §7.1; the design note keeps only
  the hop variant. `MAX_EXPLORED` counts a candidate the CA check refuses; §7.1's feed-failure list carries #209's
  exception.

### Changes in revision 58 (the redirect and URL grammar of #192, 2026-11-15)
The maintainer approved this revision on 2026-11-15. It writes in only the redirect and URL grammar decided on #192
(the maintainer's Q2 and Q3, the lead's Q1, Q4 and Q5 and the readings the lead accepted) and built in #204's
`StrictUrl`, `HopUrl` and `RedirectingFetcher`; where #204's drafted spec lines and the merged code differ, the code
and the #192 decisions are written.
- **§7.3 "Redirects", the hop grammar** (Q2, Q3): every URL of a mirror's chain, the request's own included, is read by
  the one strict grammar the x5u URL is read by, with IP literals allowed: `https://` in lowercase, no userinfo, a DNS
  host name, an IPv4 dotted quad with no leading zeros or a bracketed IPv6 address with no zone identifier (a dotted
  quad only as its last 32 bits), a port of 1 to 65535, a path and query of RFC 3986 `pchar`s, `/` and `?` with valid
  `%` escapes. Anything else is `FAILED`, never repaired. This replaces "`https` with no userinfo … no port rule".
- **§7.3, the fetched URL:** each hop, the first included, is fetched as revokt re-serialises it (the host lowercased,
  `:443` dropped, dot segments removed, an empty path `/`), never as the configured string or the `Location` value.
- **§7.3, `Location`** (Q1, Q4): a 301, 302, 303, 307 or 308 with no `Location` is returned as the final response, as
  reqwest and Necko return it, and the mirror client fails it with its `httpStatus` (#194); distinct `Location` values
  on a redirect response are `FAILED`, as Necko's are, and equal ones collapse.
- **§7.3, the loop key** (Q5): the re-serialised URL without its fragment, the initial URL counted; it is RFC 3986's
  simple string comparison, so `%2e` is not a dot segment (a loop spelled with it ends at the hop limit, `FAILED`
  either way).
- **§7.3, the accepted readings:** the five credential headers are stripped on a host or port change from the
  previous hop and stay stripped for every later hop, which is stricter than reqwest (it rebuilds each hop's headers
  from the original request, so it re-sends them on a later same-host hop); `If-Modified-Since` is kept and no
  `Referer` is sent, where reqwest, and so upki, sends one on every hop; the body cap and the time left apply to each
  hop, not only to the final response.
- **§7.3, the mirror client's 3xx rule** (a reading the lead accepted, from #204's review mapping for #194): the mirror
  client fails any 3xx the wrapper returns except the manifest's 304, with that `httpStatus`; this is revision 56's
  "any other 3xx is `FAILED`" moved to the caller, and it covers a 304 to a filter request.
- **§4:** the `c2spMirror` URL is read by §7.3's hop grammar (IP literals allowed), and `build()` throws when it fails;
  the "https with no userinfo" rule names the other source URLs only.
- **§7.1:** the x5u URL is read by the same shared grammar, DNS host names only; its rules are unchanged.
- **§7.3 and §4 `SyncStage`, a mirror's stages** (the maintainer's decision for #194, 2026-11-15; #207's code): the
  manifest fetch, a malformed manifest and an over-cap manifest are stage `CHANGESET`; a file fetch, or a file body
  whose size or SHA-256 differs from its manifest entry, is stage `ATTACHMENT`, as upki splits them by URL.
- **§9:** mirror fixtures for an IPv6 hop, `HTTPS://`, differing and equal duplicate `Location`s, a 302 with no
  `Location` at the mirror client and the host `[1.2.3.4::]`. Row (e)'s "the built `index.bin` 1 MiB + 1 byte"
  becomes "over 1 MiB", since a built index is 14 bytes plus multiples of 32, 42 and 18, always an even size (#207,
  #194's reading 10); the system-cache row keeps 1 MiB + 1 byte, since that file is read, not built.
- **§10:** the TLS-only mirror item names the shared grammar, the re-serialised fetch and the headers that stay
  stripped.
- **Appendix A:** reqwest 0.13.0 with tower-http 0.6.11 (upki v1.0.1's pins) and Firefox's Necko at
  `cac25a6fa321b0051932359b84c4e2fe3caabdc5`, for the statuses followed, a 3xx with no `Location` and duplicate
  `Location` values; reqwest alone for IP literal hosts, the redirect limit, the headers it re-sends and its
  `Referer`; the revision 56 entry's "does the same" is narrowed to the per-hop strip; upki v1.0.1's `fetch.rs`, for how it tells a manifest failure from
  a file failure.

### Changes in revision 57 (the items queued on #160 after revision 56, 2026-11-14)
The maintainer approved writing in every item queued on #160 since revision 56 as one revision (2026-11-14). Each is a
maintainer decision, a lead decision under one, or matches merged code (#195, #197, #198, and #186's evaluator);
none is open.
- **§4 and §5.1, `EvaluationRequest.verifiedPath`** (the maintainer's decisions on #195, like upki's single webpki
  `VerifiedPath`): `verifiedPaths(List<List<ByteArray>>)` becomes `verifiedPath(List<ByteArray>)`, capped at
  `MAX_DEPTH + 1` certificates; `build()` throws when `presented` is set and `presented[0]` is not the verified leaf, and
  with both set the verified path wins; a one-certificate path skips the keyability check only when its leaf is an anchor
  by bytes in the snapshot read at entry, whose id it then reports; `ChainSource.PLATFORM` names both routes; a
  `FOUND` decision with no leaf-issuer key is the boundary's `ENGINE_ERROR` (#186's code).
- **§5.1 decision step 6, the walker and §8, issuer labels** (the maintainer's decisions on #196, revised after the
  comparison with Firefox, and on #197):
  - `ISSUER_UNVERIFIED` follows mozilla::pkix's order: an explored related non-anchor counts its own unsupported
    signature OID whether or not it verifies, so does a node the unrelated loop reached, and the leaf's own OID counts
    only once it has a related candidate. A candidate's key or curve OID still never counts.
  - `NO_ISSUER` and `ISSUER_UNVERIFIED` share one outcome and one exemption: `rule`, `exempt` and `clearExemption` on
    either apply to both, and a policy cannot hold a split pair. A relabel between them changes only the diagnostic.
  - On a trust-manager binding and `Revokt.evaluate` every walk `NotFound` whose fallback failed or is disabled is `NO_ISSUER(PLATFORM_ONLY)`,
    whatever the label, so `platformOnly()` matches either way; `ISSUER_UNVERIFIED` appears only off the bindings.
  - `outcomeDepended` is `status == ISSUER_UNVERIFIED` in §8 too; §10 item 14 is rewritten, with the note that a
    consumer's own exemption can still tell the labels apart off the bindings.
- **§5.1, candidate order** (the maintainer's decision on #196, Firefox's order): at every depth the store's anchors,
  then the presented certificates by index, then (M2) the preload; `related()` loses `belowLeaf`; a byte-duplicate is
  yielded at its earliest position, an anchor's in the store; `anchorIn` matches the anchor of the first path found in that order. §10 item 4 notes
  that 64 same-name store anchors can now fill a node's cap.
- **§3, §5.1 and §5.5** (#196 F5 and F6, the #160 issue text): the verifier must not modify its arguments; a caught
  `InterruptedException` restores the interrupt flag at every catch of consumer code and at the boundary; only
  `VerifierError` rides on the `Walk`, and its `oid` is `""` when the TBS AlgorithmIdentifier does not decode; "Cost"
  states the root-issued leaf with a presented cross-certificate.
- **§4 and §7.1, `signatures[]`** (#198, and #191's verifier queued on #160): an empty `x5u` or `signature` is skipped
  like a missing one; a `null` element the loop reaches is `FAILED` at `SIGNATURE`; every x5u PEM or chain failure
  but validity, and a content-signature failure, is `FAILED` at stage `SIGNATURE`, a failed x5u fetch `FAILED` at `X5U`; any failed entry,
  a failed fetch included, moves on to the next; the installed records are the verified ones. Appendix A records
  Firefox's loop, including that it leaves the loop on a rejected fetch.
- **§7.1, `Backoff` and `Retry-After`** (the 2026-11-13 decision audit): revokt's behaviour stays, but "as Firefox and
  Kinto do" was false. Firefox keeps `Backoff` only from a `/changes` response that is not a server error and carries
  the expected JSON, and never reads `Retry-After`, so revokt is stricter; Appendix A cites the lines.
- **§9:** walker rows (ak) to (ap) for the labels, the leaf deferral, anchors that never count, the unrelated-loop node,
  the candidate order and the 64 same-name anchors; row (j) on the bindings; API rows for `verifiedPath` and the shared
  slot; content-signature rows for the `signatures[]` stages; P5 holds only as `endDepth == 1 ⇒ relatedExploredAtLeaf
  == 64`.
- **§3.2, §4, §6.4, §6.5, §7.1 and §10, the sync** (the maintainer's decisions on #137, 2026-11-14, after the
  upki/Firefox comparison): `MAX_SYNC_BYTES` is removed, leaving the per-file and count caps (about 4 GiB from a
  malicious mirror, accepted); prune runs after every `INSTALLED`, never after a failure; a channel may mix filter
  encodings, with `meta.json`'s `format` the full's, and the format check covers every placed filter, a full or delta
  the engine cannot read failing the install with `FORMAT_UNSUPPORTED`; until #141 a sync never sends `_since` or `If-None-Match`; a
  `SIGNED` `generationId`'s last applied record is the last filter in `buildIndex` placement order; `meta.json`'s
  signature is any non-empty even length.
- **§10:** residual 9 adds the PKIX fallback's unbudgeted build (the #134 review record, F4); the rollback item says that after `resetState()` the
  watermark floor holds the old live generation's timestamp until the start task swaps it (from the #190 review).

### Changes in revision 56 (the items queued on #160, 2026-11-12)
The maintainer approved writing in every item queued on #160 as one revision (2026-11-08). Items marked decided there
or in the decisions log are written as decided; where merged code is the source, the spec now matches it; the items
that were open in the first draft were decided by the maintainer in its review (last bullet).
- **§3 and §4, the surface** (from the reviews of #177, #179, #180, #182 and #183, matching the merged code):
  - `RevoktLoggers.jul()` maps `DEBUG` → `FINE`, `INFO` → `INFO`, `WARN` → `WARNING`, `ERROR` → `SEVERE`, so `DEBUG` is
    hidden under JUL's default level.
  - "Timing fields" are measured durations such as `Verdict.elapsedNanos`; timestamps take part in equality.
    `PolicyDiagnostic` and `SyncResult` join the output types whose builders are `@RevoktTestingApi`.
  - `SyncResult.installed` holds the installed generation's id; `SyncResult.cause` is "not persisted; null when read
    back" and outside equality.
  - `Verdict.generationEpoch` stays `@RevoktInternalApi` and is outside equality, hashing and `toString`.
  - `PresentedChain` (the maintainer's decision, #180): every presented certificate in presented order, so index i is
    `AlgorithmIdMismatch.certIndex`'s; an unparsed entry keeps its DER, `parsed(i)` is false and its other fields
    are empty.
  - `EvaluationRequest.Builder.build()` (the maintainer's decision, #182) rejects an empty `presented`, an empty
    `verifiedPaths` and an empty path.
  - `RevoktPolicy` (#183): `newBuilder()` works on any policy and keeps its preset (the growability contract says so
    too); every duration and millis argument is ≥ 0, a `Duration` overflow included; under `Enforcement.OFF` every V
    diagnostic is a `WARNING`.
  - `Exemptions.and`/`or` follow CEL's `&&`/`||` (the maintainer's decision, #182): commutative, the deciding side
    wins whatever the other did, an absorbed error is not recorded, fatal errors propagate.
  - host' (§5.1, §4 `hostIn`): ASCII-only case folding, one trailing dot stripped, applied once; an entry that is
    non-ASCII, empty after normalisation, starts with `.` or holds `*` throws; an empty host never matches.
  - `ioDispatcher`/`ioExecutor` must not run tasks inline (from the review of #181).
  - `MozillaRemoteSettings`: the `attachmentBaseUrl` default is written; hosts and rewrite targets are compared
    exactly; `build()` also throws for an `x5uHosts` entry, or either side of a rewrite, outside X5uUrl's fetch-time host grammar
    (LDH labels of 1 to 63, at most 253, no trailing dot, no all-numeric or hex last label; upper case allowed), so
    both checks accept the same set (the maintainer's decision; its code is a follow-up in `MozillaRemoteSettings`).
  - `c2spCache` takes the directory holding `index.bin` (`…/revocation`); the §4 example is fixed and upki's per-OS
    roots are listed.
  - `Freshness.MANIFEST_LAST_MODIFIED` is the newest coverage end (§7.2): an end up to `clockSkew` ahead installs
    with age 0 and no `clockBehind`, one beyond is rejected (§6.3); `MAX_MANIFEST_ENTRIES` is 256.
- **§3.2** (the upki audit, Q12 to Q24, and #184): `buildIndex` places the channel's one full filter and every delta
  by time, without `parent`; the index reader rejects `upkiidx0`; the oracle leg is a bare `to_bytes(V4)`, not
  upki-mirror's transcoder; the overlapping-windows verification is closed (one entry per (log, filter)).
- **§5.1** (the maintainer's decisions on #124 and #133):
  - the path finding: `reportedPathSha256s` on a `Budget` walk with a fallback path and no partial path is the
    fallback path; `endDepth` is null on a completed walk and set only on `Budget` (0 at the step-3 cut);
    `walkerReason` is set on every walk `NotFound`; `AlgorithmIdMismatch` is once per certificate step 3 parsed;
  - steps 7 and 8, R1 to R5: engine results in `Finding.Crlite`, no exemption after a boundary catch, the consulted
    datasets, a throwing clock, and a throwing `engine.query`.
- **§6.3 to §6.5:** v3 filters are held to v4's ranges; the memory table is recomputed for 8 deltas and for the 52
  deltas measured in the live changeset of 2026-11-12, and the
  delta count is stated as observed, not "about four days"; `buildIndex`'s selection, with its refusal codes; the
  install order gains the format check before the directory is written, as #184 does; in 0.2 `UNCHANGED` writes only
  the attempt fields (#131 R4).
- **§7.1** (from the reviews of #163, #164, #177 and #181, and #131's R1 to R3):
  - the content signature's leaf may be on any EC curve the floor admits, and the raw signature length follows the
    key; `mode == p384ecdsa` is recorded as a deliberate narrowing from Firefox;
  - `metadata.signatures[]` is read as Firefox reads it, the first entry that verifies under the pinned chain
    accepted, and `metadata.signature` no longer (the maintainer's decision; code follow-up #191);
  - `<ts>` is the value the verified payload was built from (the envelope `timestamp` for a live sync, which is then
    signed), not "never the envelope `timestamp`"; the unsigned value is `monitor/changes`' `last_modified`;
  - `parent` is required on deltas only; `_since` is sent bare;
  - the x5u body is read as `rustls-pki-types` reads it: text outside blocks skipped, known labels decoded (a bad one
    fails the body) and only `CERTIFICATE` kept, unknown labels skipped, whitespace-tolerant base64 without padding;
  - feed failures and backoff: which outcomes count, the reset on every successful poll, `Backoff`/`Retry-After`
    on every response, and the failure backoff 15 min × 2^(n − 1), capped at the 6 h poll interval.
- **§7.3** (the upki audit): the manifest grammar, the file URL and the 30 s timeout; redirects, followed only by the shared
  `RedirectingFetcher` in the fetch layer, with per-hop rules (301/302/303/307/308 on `GET`, a relative `Location`
  resolved, https with no userinfo, a query allowed, a fragment dropped and no port rule, `FetcherTls` and the §8
  host checks on every hop, any other 3xx `FAILED`, at most 10 and no loops, one
  deadline for the chain, credentials dropped across hosts, the body cap on the final response; §3's fetcher contract
  and §10 say the same); a `MIRROR` or
  `SYSTEM` generation with no filters or no coverage (every filter's universe empty) is refused: a mirror's sync is
  `FAILED` at `INDEX` with `SOURCE_EMPTY`, a system cache is not installed at `start()`, S `SOURCE_EMPTY`.
- **§9:** rows for the behaviour above (data-path (a), (c), (e), the content-signature fixtures and a new "API rows"
  list); the verifier row drops the brainpool cases (the maintainer's decision with #175); the walker rows (e) with
  63 junk, (s1) and (y2) join the harness-only list; row (ac) moves the encoding difference to the issuer
  certificate's subject and gives the leaf a non-matching keyIdentifier AKI; the rule "a row's leaf stays within K1
  to K8 unless it tests `PRODUCER_UNKEYABLE`" is added.
- **§10:** the TLS-only mirror item names the `https`-only redirects and the refusal of empty mirror data.
- **Appendix A:** the attachments base URL with its read dates, `buildIndex` against Firefox and upki-mirror, the
  changeset `<ts>`/`_since`/`signatures` reading of Firefox, CEL's logical operators, the mirror protocol sources,
  upki's cache roots, `upkiidx0`, and the closed overlapping-windows item.
- **Decided in the review of this revision** (the maintainer): the `SOURCE_EMPTY` code; a mirror's
  `If-Modified-Since` from the time its manifest was stored; no `c2spCache` helper; V `IO_DISPATCHER_UNCONFINED` for
  exactly `Dispatchers.Unconfined`; `metadata.signatures[]` read as Firefox reads it (code follow-up #191); the
  measured memory figures; the shared `RedirectingFetcher` (#192); the coverage-end tolerance; the rollback watermark floor
  (from the #190 review).

### Changes in revision 55 (x5u failure reasons, the leaf's SCT list, the ECDSA scope, 2026-11-07)
- **Clarified** (§7.1, from the #170 and #174 reviews): which failure reason a malformed encoding gets.
  - `PARSE` covers the certificate's outer structure: the TBS and the outer `signatureAlgorithm`, an indefinite length
    included; the serial's minimal encoding; the primitive unique IDs; the `critical` BOOLEAN.
  - Each extension value revokt reads (basicConstraints, keyUsage, extKeyUsage, subjectAltName, nameConstraints,
    the leaf's SCT list) is parsed first, and anything malformed is `EXTENSION`: bytes after the value, a BOOLEAN such
    as `cA` of `01`, a non-minimal length, an empty keyUsage (`03 00`, `03 01 00`), an empty extKeyUsage (`30 00`) or
    a non-OID element in it, an unknown GeneralName tag. Only a well-formed value reaches the `SAN`, `EKU` and
    `KEY_USAGE` checks. The TLS feature is compared byte for byte and never parsed. Before, the "DER" bullet said
    `PARSE` for these, which contradicted the "Extensions" bullet.
- **Added** (§7.1, matching Firefox): when the leaf carries the embedded SCT list, its `extnValue` is exactly one
  OCTET STRING with nothing after it, else `EXTENSION` (`pkixbuild.cpp` lines 218 to 229 at
  `cac25a6fa321b0051932359b84c4e2fe3caabdc5`). The list's content is not read.
- **Fixtures** (§9 (d)):
  - the extension-internal rows now expect `EXTENSION`;
  - new rows: the empty keyUsage and extKeyUsage forms, a non-OID extKeyUsage element and a SAN with an unknown
    GeneralName tag → `EXTENSION`; a serial with a redundant leading `00` or `FF`, or an empty serial (`02 00`), →
    `PARSE`, beside "a zero or negative serial loads"; a constructed unique ID → `PARSE`; `rsaEncryption` NULL
    parameters with content → `ALGORITHM`; an empty critical Netscape certificate type → `EXTENSION`, and an empty
    non-critical one → loads; the SCT list cases.
- **Scoped** (§3, the #160 comment): the ECDSA range check covers standalone ECDSA. A composite ML-DSA + ECDSA
  signature verifies as one provider operation, so its ECDSA component is the owning provider's responsibility;
  both owning providers (BC's `ECDSASigner`, BoringSSL under Conscrypt) range-check it.
- **Gated** (§9 verifier row): the brainpool cases under BC wait on #175, the BC dependency decision, instead of
  being [0.2, #172]. The NIST-curve cases stay [0.2, #172].

### Changes in revision 54 (the x5u chain follows mozilla::pkix, and the ECDSA range check, 2026-11-07)
- **Added** (§7.1, the maintainer's decision on #126): the x5u chain follows mozilla::pkix at Firefox
  `cac25a6fa321b0051932359b84c4e2fe3caabdc5`, with rustls-webpki consulted and its divergences listed (Appendix A;
  this entry said 0.103.15, but upki builds paths with 0.104.0-alpha.7, against which the rows were re-read, #217).
  Each failure is `SyncOutcome.FAILED`, and §7.1 names the chain's failure reason for each. The rules, now after
  §7.1's `CLOCK_SKEW` sentence, cover every link below the terminal:
  - **DER as mozilla::pkix reads it** (`PARSE`): non-minimal headers, elements the grammar does not place, an
    indefinite-length TBS, a BOOLEAN other than `00` or `FF`, unused bits in the signature BIT STRING, and times
    other than `YYMMDDHHMMSSZ` or `YYYYMMDDHHMMSSZ` (either type for any year, from 1970, notBefore ≤ notAfter) fail.
    Each extension value revokt reads is parsed to its end. What mozilla::pkix accepts against DER or RFC 5280,
    revokt accepts too: an explicit v1 version, an explicit DEFAULT FALSE for `critical` and `cA`, an empty Extensions
    SEQUENCE, a negative or zero serial, and a keyUsage without the minimal named-bit encoding. §9.2's TLS parser is
    unchanged.
  - **Version and issuer:** the version INTEGER is 0 to 3 (`PARSE`), and `[3]` is read whatever the version. An issuer
    with no RDN fails (`NAME`). The outer `signatureAlgorithm` equals the TBS one as parsed (`ALGORITHM`).
  - **SubjectPublicKeyInfo** (`ALGORITHM`), as `CheckSubjectPublicKeyInfo`: a namedCurve with an uncompressed point
    of exact length, `rsaEncryption` with NULL parameters and a minimal positive modulus and exponent, and no unused
    bits.
  - **Extensions** (`EXTENSION`): any repeated OID (stricter than mozilla::pkix, Appendix A); an empty value for an
    understood extension, `id-pkix-ocsp-nocheck` excepted; a `pathLenConstraint` above 127; a critical extension
    outside `BackCert::RememberExtension`'s set; a critical Netscape certificate type without basicConstraints and
    extKeyUsage (Firefox's actual rule; it does not read the type bits); and, enforced between the links below the
    terminal, a link's TLS feature that its child does not carry with the same value (the terminal's is not read,
    a remaining difference).
  - **Leaf basicConstraints:** `cA = TRUE` fails (`LEAF_CA`, a new reason).
  - **EKU** (`EKU`): every non-leaf link below the terminal with an extKeyUsage includes codeSigning
    (anyExtendedKeyUsage alone does not), and the terminal is never checked. The leaf also rejects
    `id-kp-OCSPSigning`.
  - **nameConstraints**, critical or not, as `pkixnames.cpp`: dNSName subtrees against the leaf's dNSName on label
    boundaries ignoring case, permitted applying per name type, `""` matching every name. A name outside fails
    (`NAME_CONSTRAINTS`, a new reason). A malformed or unsupported constraint fails (`EXTENSION`): an invalid base, an
    encoded `minimum` or `maximum`, an empty NameConstraints or GeneralSubtrees, and a directoryName subtree
    (fail closed, stricter than mozilla::pkix). Every GeneralSubtree is still parsed (an unknown tag is malformed,
    and a `minimum` or `maximum` fails whatever the form); only the base of a form revokt does not evaluate is left
    alone. An rfc822Name subtree has no effect, as in mozilla::pkix, since the leaf carries a subjectAltName. Only the leaf's name is checked, a remaining difference.
  - **Algorithm floor** (`ALGORITHM`): `id-RSASSA-PSS` only in mozilla::pkix's three byte-exact encodings, only
    `rsaEncryption` and `id-ecPublicKey` keys, and ECDSA AlgorithmIdentifiers with NULL or absent parameters.
    **§3's `id-RSASSA-PSS` rule for the TLS verifier (revision 51) is unchanged.**
- **Confirmed** (§7.1): the terminal is the first certificate *after the leaf* whose SPKI is pinned, so a pinned leaf
  SPKI pins nothing (`NOT_PINNED`). The pin lookup runs before the strict parse, and the terminal is read for its SPKI
  alone. §7.1's rationale now says that this is revokt's rule: Firefox matches the anchor by its
  whole DER.
- **Added** (§3, the maintainer's decision; #172): the ECDSA range check.
  - The curve probe decides first, as for PSS: an unsupported curve is `UNSUPPORTED`, never `INVALID`. Then, after
    the provider's `KeyFactory` has decoded the key and before `Signature`, every ECDSA signature's `ECDSA-Sig-Value`
    is decoded, and the signature is `INVALID` unless 1 ≤ r ≤ n − 1 and 1 ≤ s ≤ n − 1.
  - n comes from the decoded key's curve (`ECPublicKey.params.order`), so the brainpool curves under BC are covered;
    a key whose order cannot be read is `INVALID`.
  - The value is a SEQUENCE of exactly two minimal positive INTEGERs with no trailing bytes, else `INVALID`, which
    can be stricter than SunEC.
  - The reasons: SEC 1 §4.1.4 step 1, as ring does, and CVE-2022-21449 (JDK 15 to 17.0.2 and 18 GA).
  - High s stays accepted (the #163 review; SEC 1 and NSS).
  - It covers every ECDSA signature through the verifier, the x5u links and the content signature included, and
    §10's list of crypto written in Kotlin gains the decode and the comparison.
- **Fixtures** (§9):
  - (d) has a row for each rule, in the leaf and the intermediate where both apply. The accepting counterparts are
    there too: mozilla::pkix's accepted encodings, a non-critical unknown extension, a critical certificatePolicies,
    an intermediate without extKeyUsage, a terminal without codeSigning, NULL against absent parameters, a version 3
    (v4) and an implicit v1 with `[3]`. So are the nameConstraints cases (`""` permitted and excluded, a leading-dot
    base, a suffix off a label boundary, upper case, an excluded `mozilla.org`, an encoded minimum, Mozilla's real
    intermediate), a leaf-only pin, a pinned terminal with a non-minimal length, and Mozilla's committed chain.
  - The verifier row, tagged [0.2, #172], has the range check on the NIST curves and under BC on brainpool, the
    CVE form against a stub provider that answers `VERIFIED`, and the `ECDSA-Sig-Value` profile (a redundant leading
    `00` included).
- **§10 and Appendix A:**
  - §10's feed-path item names the chain checks.
  - Appendix A records the mozilla::pkix and webpki sources read, webpki's divergences, the differences that remain,
    and the two places revokt is stricter.
  - It also gives the CVE's affected versions from the reporter's write-up, with Oracle's advisory revision log and
    NVD's, and the SunEC check of a negative INTEGER.

### Changes in revision 53 (a mirror's `index.bin` is built locally, 2026-11-06)
- **Decided** (§7.3, §3.2; the maintainer's decision on #160): revokt never fetches an `index.bin` from a mirror.
  - **Before:** §3.2 capped "a mirror's `index.bin` fetch" and ran the selection-equivalence check on `MIRROR`
    generations, and the content-signature fixtures expected a mirror to serve an index. Revision 52 left open
    whether a mirror's index is fetched or built.
  - **Now:** as `upki fetch` does, a mirror publishes only `manifest.json` and the filter files. The loader builds
    the generation's `index.bin` with its own index writer from each downloaded filter's coverage, under the
    generation's names, including the derived name of a manifest name over 32 bytes.
  - **§3.2:** the selection-equivalence check runs on every generation whose `index.bin` the loader reads rather
    than builds: a `SYSTEM` cache, with a seed's rebuilt index byte-compared as before. The 1 MiB cap applies to
    every `index.bin` the loader reads (a system cache's, a seed's, a stored generation's), and revokt fetches
    none. The cross-engine suite's check and §6.5's install order say the same.
  - **Outcomes per source:** a mismatch or an over-cap read is `STORE_UNREADABLE` for a system cache and
    `SEED_UNREADABLE` for a seed. `INDEX_INCONSISTENT` there covered a fetched mirror index, which no longer exists;
    §6.5's install order and §4's `INDEX_INCONSISTENT` line follow.
  - **A built index over 1 MiB** (new): an `index.bin` the loader builds, for a Remote Settings or `MIRROR`
    generation, that is over 1 MiB fails the install before the generation is written: `FAILED`,
    `INDEX_INCONSISTENT`, stage `INDEX`. So the loader never writes a generation its own read cap would refuse at
    reload, and a mirror's unsigned coverage cannot produce one. For signed data the cap only moves earlier a reload
    failure that revision 48's read cap already guarantees, and real data is far below it: the live mirror's 40
    files over 81 logs index to about 62 KiB (14 + 32 per file + 42 per log + 18 per log and file, bytes).
  - **The limits table** (§5.1): the 1 MiB note names a system cache's `index.bin`.
- **Fixtures** (§9):
  - (e) regains the row for a 33-byte manifest name: it installs under its derived name, no `index.bin` is fetched,
    and the locally built `index.bin` names the derived name. Revision 52's caveat now points here. Beside it, a
    mirror whose coverage would build an `index.bin` of 1 MiB + 1 byte fails with `INDEX_INCONSISTENT`, and no
    generation directory is written.
  - The two [0.3] content-signature rows that expected a mirror's `index.bin` now apply to a system cache, the
    source that still reads one: a log window absent from the filter's coverage, and an `index.bin` of 1 MiB + 1 byte,
    are each not installed at `start()`, with `STORE_UNREADABLE`, §3.2's system-cache outcome. Their header and
    §11's 0.3 row say so.
- **Appendix A:** the `upki.rustls.dev` entry records the protocol:
  - The mirror publishes no index, and `upki fetch` builds one (v1.0.1 `PlanStep::SaveIndex` → `Index::write`).
  - `upki-mirror` writes only `manifest.json` and the filter files. For a filename over 32 bytes, `Index::write`
    returns no index, while revokt renames the file and builds the index under the derived name.
  - The open overlapping-windows verification (§3.2 and the C2SP entry) now names upki's `Index::write`, not
    `upki-mirror`.

### Changes in revision 52 (names from unsigned source data, 2026-11-06)
- **Added** (§7.3, §6.3, §6.5; the maintainer's rules on #160, from the review of #166): a mirror's manifest names.
  - **Why:** a mirror's data is unsigned, so a name it serves is checked before it names a file or a URL.
  - **The check:** every `manifest.json` filename passes §6.3's filename rule, does not end in `.` (Win32 strips a
    trailing `.`, so `meta.json.` would open `meta.json`), is none of §6.3's reserved names (compared ignoring ASCII
    case, so `META.JSON` fails), and is unique in the manifest ignoring ASCII case.
  - **The hash:** each file's manifest `hash`, the one unsigned string that reaches a storage key (`blobs/<sha256>`,
    looked up before the fetch), is exactly 64 hex characters (32 bytes); the blob key is its lowercase re-encoding.
  - **The URL:** the base is the configured `c2spMirror` URL with a `/` appended when it does not end in one;
    `manifest.json` and every mirror file are fetched only from the base followed by their name. §4 gains the rule
    "R: a `c2spMirror` URL with a query or a fragment": `build()` throws `IllegalArgumentException`.
  - **The outcome:** any failing name or hash rejects the whole manifest before any body is fetched or written:
    `SyncOutcome.FAILED` with `INDEX_INCONSISTENT`, stage `INDEX`, the outcome of §6.5's name collision. §4's
    `INDEX_INCONSISTENT` line names it.
  - **Names over 32 bytes:** the adopted text names `C2spIndex.isFilename`, C2SP's 1-to-32-byte rule. The
    maintainer's earlier decision on #160 gives mirror filenames over 32 bytes §6.5's derived names, so the manifest
    name is checked under §6.3's 1-to-64-byte rule, and the generation's name is the filename when it passes
    `isFilename` and its derived name otherwise. So every name a mirror generation stores passes `isFilename`. The
    generation's names are unique ignoring ASCII case too, and §6.5 now derives names from manifest filenames as well as
    attachment filenames.
- **Added** (§6.5): a seed's entry names.
  - **Why:** a zip entry's name is outside the signature.
  - **The rule:** the loader never derives a name or a path from a zip entry. It accepts exactly the fixed entries
    (`seed.json`, `records.json`, `signature`, `x5u.pem`, `index.bin`), plus `attachments/<f>` for each §6.3-checked
    `attachment.filename` f of a record in the verified `records.json` that `buildIndex(records, channel)` places
    in the generation, and reads each entry by that exact name.
  - **The outcome:** a duplicate, extra or missing entry is `SEED_UNREADABLE`. An entry that differs from an
    expected name only in letter case is an extra entry, and so is a directory entry.
  - **The central directory:** the entries are the zip's central directory. Every read goes through a
    central-directory entry whose local header names the same file, and the first entry is `seed.json` (§5.1's header
    read takes it), else `SEED_UNREADABLE`.
  - **When:** the fixed entries are checked before any entry but `seed.json` is read, and at that check every name
    that is neither a fixed entry nor under `attachments/` is already extra; the attachment entries are checked once
    `records.json` is verified and before any of them is inflated.
  - **Which records:** the verified `records.json` holds every channel's records, so the expected attachments are
    the ones `buildIndex` places in the seed's generation, not one per record.
- **Fixtures** (§9): the manifest rows join (e), beside the manifest cap: `.`, `..`, `../x`, `/x`, `a/b`,
  `META.JSON`, `meta.json.`, two names equal ignoring case and a hash of 63 or 65 or non-hex characters each fail the
  sync with nothing fetched or written; a mirror URL without a trailing `/` gets one, and one with a query or a
  fragment throws at `build()`. No row tested a name over 32 bytes in this revision, since whether a mirror's
  `index.bin` is fetched or built locally was still open on #160; revision 53 decides it and adds the row. The seed rows join the
  content-signature fixtures, beside the seed's entry cap, as 0.2 gates: `attachments/../x`, a duplicate entry, an
  extra entry, a case variant, a local-header name that differs from the central directory's, a first entry other
  than `seed.json` and a missing attachment are each `SEED_UNREADABLE`.
- **§10 and Appendix A:** §10's TLS-only mirror item says an unsigned name never names a path outside its generation
  directory. A checked name can still be a Windows device name such as `NUL`; that only makes the install fail (the
  read-back or `prepare()` fails, so the sync is `FAILED`), and full filters are stored under blob keys, not their
  names. Its supply-chain item names the seed rule.
  Appendix A's C2SP filename entry lists the case-insensitive checks as revokt's own rules.
- **Omitted as not needed** (the maintainer, on #160), since signed data, the pinned-root chain check, or a check the names
  already pass covers each: engine-side storage-key checks, a store symlink rule, load-time re-checks, the shape of
  `attachment.location`, an x5u URL rebuild and a change to the install order.

### Changes in revision 51 (Conscrypt's post-quantum algorithms and the PSS hashes, 2026-11-05)
- **Corrected** (Appendix A, §3; found in the review of #156): Appendix A said Conscrypt does not ship ML-DSA.
  Conscrypt uber 2.7.0 and 2.8.0, the §9.2 matrix's two releases, both register ML-DSA-44, -65 and -87,
  SLH-DSA-SHA2-128s and 15 composite ML-DSA OIDs (`1.3.6.1.5.5.7.6.37`–`.46`, `.48`, `.49`, `.52`–`.54`).
  - **How it was checked:** a single-file Java program over the Gradle-cached jars, on JDK 17.0.21 and 21.0.13,
    listed the provider's services and `Alg.Alias` entries and looked each algorithm up by name and by OID. Each
    ML-DSA set verifies a signature the JDK made. Appendix A records the details.
  - **By name or by OID:** ML-DSA and the composites are registered by name and by OID alias, and
    SLH-DSA-SHA2-128s by name only, with no OID alias.
  - **Unverified:** whether Conscrypt's composite encoding matches draft -19, and the platform Conscrypt on Android.
  - **§3:** the composite delegation rule names Conscrypt beside BC as a provider owning composite OIDs. No rule
    changes. The JDK-provider fixtures, such as (j)'s JDK without ML-DSA, are unaffected, since the §9.2 matrix
    uses Conscrypt as oracle 2's `CertificateFactory`, not as a `Signature` provider.
- **Stated** (§3, as merged in #156 at `5d419cc`): how an OID reaches a JCA service.
  - The probe and `verify` resolve it through one table to a `Signature` and a `KeyFactory` name: standard names
    for RSA and ECDSA, `RSASSA-PSS`, the algorithm names for EdDSA, ML-DSA and SLH-DSA, and the bare OID for each
    composite.
  - **Under Conscrypt alone:** ML-DSA, SLH-DSA-SHA2-128s (by name) and the 15 registered composites are supported.
    `unsupportedOids()` is 21 OIDs, the same under 2.7.0 and 2.8.0:
    - `SHA512/224withRSA` and `SHA512/256withRSA`;
    - `id-RSASSA-PSS`;
    - Ed448;
    - the other 11 SLH-DSA sets;
    - the composites `.47`, `.50` and `.51`;
    - the three brainpool curves.

    §3 lists them all.
  - An OID outside the tables is `INVALID`.
  - **The unverified composite encoding:** if it differs from draft -19, the probe says supported and a real
    certificate is `INVALID`, not `UNSUPPORTED`.
- **Added** (§3, §9; the maintainer's choice on #156): the `id-RSASSA-PSS` parameter rule.
  - The parameters are present.
  - The message hash and the MGF1 hash are each a SHA-2 hash, the family the list gives RSA PKCS#1.
  - The mask is `id-mgf1`, and `trailerField` is 1.
  - An omitted field takes RFC 4055's SHA-1 DEFAULT.
  - **Salt:** a salt over 2,048 bytes is `INVALID`. This describes #156's merged `MAX_SALT_LENGTH` guard, not a new
    choice: the JDK throws `ArithmeticException` on salts near `Int.MAX_VALUE`.
  - Any other PSS parameters are `INVALID`, whatever the provider would answer. That covers SHA-1 PSS, the
    all-default parameters, a SHA-2 hash under MGF1 with SHA-1, and any other mask.
  - **The probe decides first:** with `id-RSASSA-PSS` in `unsupportedOids()` (a verifier over Conscrypt alone),
    every PSS signature is `UNSUPPORTED`.
  - **Before:** §3 said only that the verifier "honours RSASSA-PSS parameters".
  - **§9's verifier tests** name the SHA-1, MGF1-SHA-1 and non-MGF1 cases, and the `UNSUPPORTED` precedence.

### Changes in revision 50 (the walker review's timing and the PKIX fallback finding, 2026-11-05)
- **Aligned** (§14, #117): §14 gave the walker and the `Rule` model a dedicated adversarial review "before 0.2's
  walker is coded". The review now runs once they are implemented (after the walker, `reconstruct` and decision steps
  1–8 merge) and before the §9.1 walker fuzzer runs against them. §14 and §11's 0.2 row now say the same.
  - **Why:** §11's 0.2 row already ordered the review before the fuzzer, and the spec's own review rounds on §5.1 and
    the `Rule` model ran in revisions 9, 10 and 12. What is left to review adversarially is the implementation.
  - The next sentence, the fuzzer's P1–P8 gate before 0.2 ships, is unchanged.
- **Added** (§4, §5.1, §9; the maintainer's choice): `Finding.FallbackNotUsed` with `val reason: FallbackReason`, and
  the growable `enum class FallbackReason { SKIPPED, DISABLED, FAILED }`.
  - **Before:** step 6 and the PKIX fallback contract reported `VerifierError("fallback skipped")`,
    `VerifierError("fallback disabled")` and `VerifierError("fallback")`. But `VerifierError.oid` is the signature
    algorithm whose verification failed, and these three carried no algorithm.
  - **Now:** `VerifierError` is a verifier or algorithm failure only, both fields non-null. Step 6 reports exactly
    one `FallbackNotUsed` when the step-5 walk ended `NotFound` or `Budget` and no fallback path was evaluated: `SKIPPED`
    above `FALLBACK_MAX_PRESENTED` with the fallback enabled, `DISABLED` under `pkixFallback(false)` and the
    walker-only harness's disabled path, `FAILED` when the fallback ran and gave no path. It is named "not used"
    because a `FAILED` fallback did run. A chain cut at step 3 (`MAX_PRESENTED`, `PARSE_FAILED`) never reaches the
    walk and carries none.
  - **`FAILED`** is a `build` that returned null or threw. A `jdk.certpath.disabledAlgorithms` rejection and a
    provider that diverges from the delegate, which the contract already reported, are two such failures. Before,
    the other failed runs had no finding. They now have one, since the JDK's builder reports them alike (below).
  - **A throwing `build`** (the maintainer's choice, "`FAILED`, not cached"): before, a throw was unspecified and
    reached the catch boundary as `ENGINE_ERROR`. Now step 6 catches it as a failed fallback, `FallbackNotUsed(FAILED)`,
    and rethrows every `VirtualMachineError` except `StackOverflowError`, as §5.5's catch boundary does. A result
    produced by a throw is cached nowhere, neither as a path-cache entry nor as the verdict built on it (flow step
    3a), so a transient error is not remembered; a null return is cached as before. The acceptance memo (platform
    acceptance at flow step 1) and the cross-call memo (the walker's `VERIFIED` signatures) hold nothing the
    fallback produces.
    - **Status effect:** a throw on a `Budget` walk is `PATH_BUDGET_EXCEEDED` instead of `ENGINE_ERROR`, so it
      rejects under `DEFAULT` too. A throw on a `NotFound` walk is `NO_ISSUER` (`PLATFORM_ONLY` on a trust-manager
      binding) or `ISSUER_UNVERIFIED` instead of `ENGINE_ERROR`; under `STRICT` it still rejects, but as
      `NO_ISSUER`, which is exemptable.
    - **`PathBuilderFallback`'s declaration** says that a throw counts as a failed build.
  - **No message string:** every build failure of the JDK's `SunCertPathBuilder` carries the same text, "unable to
    find valid certification path to requested target" (checked in JDK 21's source). Other builders' texts differ,
    and consumers match on codes, never on messages. The reason is the triage value, and it fits the path cache.
  - **Path cache:** an entry keeps the reason, so a hit reports the finding the miss did.
  - **`RevoktStatus.verifierErrors`** counts `VerifierError` findings only; `FallbackNotUsed` has no counter.
  - **Fixtures:** the walker-fixture header states the rule for every row and names the step-3 cuts that carry none.
    (ad) and (af) disabled now expect `FallbackNotUsed(DISABLED)`, and (ae) `FallbackNotUsed(FAILED)`. Revision 49's
    entry below names the new finding once, in its rule bullet; its fixture text and older entries stay as written.

### Changes in revision 49 (0.2's scope, step 6 without the fallback, the engine name, the AMO SPKI pin, 2026-11-05)
- **Retagged** (§9, §11; the maintainer's decisions on the 0.2 plan): four groups of items tagged or listed for 0.2
  need machinery §11 puts in 0.3. They move to 0.3, and §11's 0.2 and 0.3 rows now say the same as §9.
  - **`Rule` model:** the counter sums (`parseFailed.values.sum() == fired[PARSE_FAILED]`, the `rejects` sums), the
    K6 clause on a path-cache hit, the `shadowPolicy` item and the loader halves of the `c2spCache`/`SYSTEM` items
    need `status()` counters, the path cache, the shadow policy and the system cache.
    - **Their verdict-level halves stay [0.2]:** over a `SYSTEM` generation the test hands the evaluator, `Accepted`
      with `UNSIGNED_DATA` under `minTrustClass(CRLITE, SIGNED)` and `Rejected(UNSIGNED_DATA)` under `STRICT`; a
      `NO_SCTS` chain under `DEFAULT` is `Accepted`.
    - **§11's 0.3 row** now names `shadowPolicy`, which no row named before.
  - **PKIX fallback:** "on both platforms" becomes the jvmMain `PkixPathBuilderFallback`, which Android also runs
    through ojluni, tested on the JVM in 0.2. Its Android instrumented run joins the 0.3 suite, with `revokt-android`.
  - **(g)'s fetcher items:** the 401/407 item's Android and OkHttp halves and the SAN item's Android half are 0.3,
    with those fetchers' modules. The JDK halves stay 0.2.
  - **Content-signature fixtures:** the restart with the clock still behind needs a store that outlives the
    instance. The mirror `index.bin` window and the 1 MiB + 1 mirror `index.bin` need a `MIRROR` source. All three
    are tagged [0.3].
- **Decided** (§11, 0.2's minimal `Revokt`):
  - **`FetcherTls`:** in 0.2 each source's `FetcherTls` carries the platform `fetcherDelegate` only. The fetcher
    trust managers (`fetcherTrustManager` and the per-source instances), `FETCHER_TRUST_UNAVAILABLE` and the
    `BLOCKED_BY_SELF` hold arrive together in 0.3, so the §8 fetcher policy does not run in 0.2. The signed feed is
    still authenticated end to end by its content signature (§7.1).
  - **`sync()`:** `sync()`, `syncAsync()` and `syncBlocking()` are internal in 0.2, so the updater syncs only on its
    schedule; they are public from 0.3. `SyncResult`, `SyncOutcome` and `SyncStage` ship public in 0.2.
  - **An empty or throwing default trust store:** `start()` succeeds, and `evaluator.evaluate` throws
    `IllegalStateException` until an index exists. That is 0.3's behaviour too: fixture (h) starts a seed-only
    configuration over an empty default trust store, and §4's lazily created `revokt.trustManager` throws only once
    something asks for it. So 0.3 does not reverse 0.2.
- **Decided** (§5.1 decision step 6, the walker fixtures): step 6 never said what happens with the PKIX fallback
  disabled (`pkixFallback(false)`, and the walker-only harness's disabled path).
  - **Now:** the disabled branch gives what step 6 gives when no fallback path exists. A walk `Budget` is
    `PATH_BUDGET_EXCEEDED`, the same as with the fallback enabled, with `usedFallback = false` and only the walk's
    partial leaf keys evaluated. A `NotFound` over more than `FALLBACK_MAX_PRESENTED` certificates is
    `PATH_BUDGET_EXCEEDED`, whether or not step 1 ran. Any other `NotFound` is `ISSUER_UNVERIFIED` or `NO_ISSUER`
    under the fallback-failed branch's rule, `PLATFORM_ONLY` on a trust-manager binding.
  - **The finding** (the maintainer's choice): wherever the fallback did not run because it is configured off, step
    6 reports a distinct `FallbackNotUsed(DISABLED)` (named so since revision 50). `SKIPPED` stays for the enabled,
    too-long case only.
  - **The skipped branch with the fallback enabled** named only "the platform accepted in step 1". It now also
    applies where step 1 does not run (the walker-only harness and `Evaluator.evaluate`), as fixture (af) already
    expected on every platform path.
  - **Fixtures:** a row whose outcome depends on the fallback states its disabled expectation. (ad) disabled →
    `PATH_BUDGET_EXCEEDED`, `usedFallback = false`, `VerifierError("fallback disabled")`, and the honest key absent
    because only the fallback reaches it, so `rule = PATH_BUDGET_EXCEEDED`. (af) disabled → `PATH_BUDGET_EXCEEDED`
    with `VerifierError("fallback disabled")`.
- **Added** (§3.2, §4, §5.5): `RevocationEngine` gains `val name: String`, defaulting to the class's simple name, or
  `"anonymous"` when the class has none. The Kotlin engine returns `"kotlin"` and the upki engine `"upki"`.
  `Finding.EngineError.engineName` is that name whenever `producer == ENGINE`, so it is never null there. Before, a
  third-party engine had no name to report. `name` must not throw, and revokt reads it once; an engine in an
  R8-minified Android app overrides it with a stable string.
- **Completed** (§7.1, Appendix A): §7.1 gave `root-ca-production-amo` only as a truncated certificate hash, from
  which no SPKI pin can be written. Its full SPKI SHA-256, `3317FA45…B1E2E7`, is now the default pin of
  `MozillaRemoteSettings.DEFAULT`. Appendix A records it, the full certificate hash and the two independent sources
  it was verified against: the live x5u chain and Firefox's built-in content-signature root.

### Changes in revision 48 (every unrelated leaf issuer collected, the C2SP index rules for every source, and the JSON allocation budget, 2026-11-04)
- **Decided** (#98, found while reviewing #91's reference walker; the maintainer chose reading B): at the leaf, §5.1's
  unrelated loop now also runs regardless of `foundHere` when **no related path** exists there, as it already did
  under a custom canonicaliser.
  - **Before:** with no related path at the leaf, the loop stopped at the first unrelated path. If two unrelated
    presented certificates both verified the leaf and reached an anchor, only the first one's key was collected.
    `leafKeys` then depended on the presented order, against P4. It differed from the §9.1 reference walker, against
    P2. The second key was never evaluated, against §10's "every terminating leaf-issuer key is evaluated and
    `REVOKED` wins".
  - **Now:** the pseudocode keeps `relatedPath` (whether a related candidate's path exists at the node) and breaks
    out of the unrelated loop only when a path exists and the node is not the leaf, or the leaf has a related path
    and no custom canonicaliser.
    - `unrelatedExploredAtLeaf` stays at most `presented − 1`, the bound the custom-canonicaliser case already has.
      Each subtree stays under `MAX_VERIFICATIONS` and `MAX_EXPLORED`.
    - P6 is unchanged: on the default delegates an honest issuer is related, so an honest world always has a related
      path.
    - §10's issuer-identity bullet now states exactly which leaf-issuer keys are evaluated.
  - **A refinement of #98's text:** #98 keyed reading B on "no related candidate". The condition is "no related
    path", so that a related decoy which verifies the leaf but leads nowhere cannot restore the order dependence.
    This is exactly the §9.1 reference walker's "unrelated presented certificates only when no related path exists",
    and it is what #91's reference implements.
  - **Fixtures:** the termination rule and §9.1's reference-walker sentence say the same. A walker-harness fixture,
    (aj), covers two unrelated anchored issuers in either order, with and without an unanchored related decoy.
- **Changed** (§6.5, #87): `index.bin` names a generation's files by their Remote Settings attachment filenames, but
  §6.3 admits attachment names of up to 64 characters and C2SP only 1 to 32 bytes. A 33-character name (today's
  31-character names with a three-digit daily index) would have made the index writer throw.
  - **The rule:** a name over 32 bytes becomes its first 15 characters, `-` and 16 hex characters of the SHA-256 of
    its ASCII bytes. That derived name is the file's name everywhere in the generation: `index.bin`,
    `GenerationFiles.names`, the directory and `meta.json`. The attachment filename stays only in the signed records.
  - **Collisions:** two attachments that map to one name fail the generation before any body is fetched (stage
    `INDEX`, `INDEX_INCONSISTENT`; `SEED_UNREADABLE` for a seed).
  - **Seeds:** `buildIndex` follows the same rule. No seed has been published, so no `seedFormat` changes.
  - **Related edits:** the CRLite schema check now names `attachment.filename`, and `index.bin` joins §6.3's reserved
    names, since a filter of that name cannot sit beside the index.
  - **New data-path fixtures:** a 33- and a 64-character name, and a colliding pair.
- **Changed** (§3.2, #86): the 1 MiB cap §6.5 gives a seed's `index.bin` now applies to every `index.bin` revokt's
  loader reads, including a mirror's fetch, checked before parsing.
  - **Outcome:** the same as an inconsistent index. A stored generation over the cap is a failed load in the §6.5
    recovery chain.
  - **Already enforced:** #86's reader applies the cap to every source.
  - **Effect:** it bounds the parse and the fetch. Real indexes are far smaller (the corpus golden is 8 KB).
  - **Fixture:** a 1 MiB + 1 mirror `index.bin`.
- **Changed** (§6.5, #97's review): the JSON allocation budget was `4·len`, with no constant term and no measurement
  protocol.
  - **Why it changes:** a tree with one object per value cannot meet `4·len` on every input. `[1.5,…]` needs a 24 B
    number per 4 input bytes, about 6·len. A 1-byte input fails on the parser object alone, and the first decode in a JVM
    allocates several MB of class initialisation.
  - **The new budget:** `20·len + 64 KiB` on any input, asserted on every fuzz and replay input, and `4·len + 64 KiB`
    on Remote Settings data, asserted on named fixtures: a committed CRLite-shaped changeset, and the pinned corpus's
    real changeset.
  - **Measurement protocol:** after one warm-up decode, on the same thread, of a fixed small document that contains
    every value kind. Per-process class loading therefore does not count, and the warm-up never decodes the measured
    input itself. Every buffer a decoder keeps across calls counts, so a cached buffer cannot hide allocation.
  - **The worst case is stated and accepted.** A changeset can cost about 20 × `MAX_JSON_BYTES` (80 MiB at the default
    cap), because it is decoded before its signature can be checked. A seed's `records.json` is now verified as raw
    bytes before it is decoded: the signature and the x5u chain to the pinned root, every check except validity
    periods, pass first. Validity periods are then checked at the decoded `<ts>` (§7.2), so `start()` decodes only
    JSON signed under Mozilla's root.
  - **Measured:** #97 measured a real Remote Settings changeset at about 3·len once the per-member and per-container
    copies are gone. The worst adversarial shape measured was about 17·len. A 4 MiB input at the §9.1 harness's
    `-Xmx256m` then no longer exhausts the heap.
  - **Unchanged:** the filter and DER budgets.
- **Clarified** (§11, the 0.1 row): it lists `SymVerifier`, the reference walker and the chain generator once, not
  twice, and it names canonical JSON beside the JSON tree, as #92 implements it. The content-signature payload
  builder is 0.2.
- **Not changed:** historical changelog entries keep the names of their time. For example, revision 27's
  `GenerationFiles.fromDirectory` became §3.2's `JvmGenerationFiles.fromDirectory` later.

### Changes in revision 47 (the `DEFAULT` outcome of the two data rules that never fire there, 2026-10-30)
- **Decided** (#75, found while implementing #72, the `Rule` model's golden fixture): §8 gave `DEFAULT`'s `STALE`
  and `UNSIGNED_DATA` cells only as "never fires", while the golden fixture freezes each preset outcome within a
  major. Both outcomes are `ALLOW`.
  - **`STALE`:** the spec already implied it. `validate()`'s `STALE_REJECTS_WITHOUT_THRESHOLD` warns when
    `outcome(STALE) == REJECT` and no dataset has a `rejectStaleAfter`, so a `REJECT` outcome would make plain
    `DEFAULT` warn on every `validate()`. §8's "`DEFAULT.newBuilder().rule(STALE, REJECT)` alone changes nothing
    until a `rejectStaleAfter` is set" says the same.
  - **`UNSIGNED_DATA`:** the maintainer chose the same pattern, with one setting for the threshold and another for
    the outcome. A policy derived from `DEFAULT` that raises `minTrustClass` makes the rule fire on lower-class data
    and report it: it shows in `Verdict.rules`, in `DataState.rules` and in the counters `fired[UNSIGNED_DATA]` and
    `unsignedData`. The verdict stays `Accepted`, and §7.3 still installs a lower-class generation as a bootstrap.
    The rule rejects only with `rule(UNSIGNED_DATA, REJECT)` as well.
  - **What `REJECT` would have meant:** raising the floor to `SIGNED` alone would reject on mirror or system-cache data
    and stop §7.3 from installing it. A configuration without a seed, whose only local data is a `c2spCache`, would
    then fail `validate()` with `NO_DATA_REJECTS_WITHOUT_LOCAL_DATA`, an `ERROR` under `ENFORCE`.

  Neither rule fires in plain `DEFAULT`, whatever its outcome, so no verdict of the presets changes.
- **Added** (§9, `Rule` model tests, 0.2): the `UNSIGNED_DATA` counterpart of the `STALE` test. An instance whose
  policy is derived from `DEFAULT` with a `SIGNED` floor, with no seed and a `c2spCache` as its only source, installs
  the cache and accepts with the rule fired.

### Changes in revision 46 (D7's wording, Firefox's inner OCTET STRING, K6 to K8 kept narrow, 2026-10-30)
- **Corrected** (#61): D7 called only its SCT-list outcomes normative, yet states required outcomes with other entries
  (the envelope re-encodings, the `STRUCTURE` cases, the trailing-element cases, the D8-gap examples), which `D7Test`
  asserts. Every outcome stated with an entry is now normative too; for an entry without one, the corpus is the record.
- **Corrected** (#61): two of D7's trailing-element entries named K2 as their clause, but the first clause each fails
  is K1 (HEADER), as their records show: the trailing element `9f 01 02 05 00` has a multi-octet tag, and the `[3]`
  after a constructed `[1]` has the header `a3 81 nn`. They now read "(K1, and K2 for the ignored element)" and
  "(K1, and K2)".
- **Added** (#61): the Firefox SCT conditions in D3 gain those of mozilla::pkix, checked at Firefox `86136a5`
  (Appendix A), which reject the certificate, not only the list. For an end-entity certificate, mozilla::pkix requires
  the SCT extension's `extnValue` to be exactly one DER OCTET STRING, and otherwise fails every path through the
  certificate; it also rejects any certificate with a second SCT extension, as a duplicate extension. revokt extracts
  pairs from three such forms, each now a `FIREFOX_SCT_STRICT` record:
  - a non-minimal length on the inner OCTET STRING (`d3/sct-inner-81`, `d7/sct-inner-84`, new);
  - bytes after the inner OCTET STRING (`d7/sct-trailing-after-inner`, already one);
  - two SCT extensions, whose union revokt queries (`d3/sct-two-extensions`, new).

  On the other forms revokt's list fails too and the answer is `NO_SCTS` (§10 item 7, which now says that Firefox
  rejects these certificates). Those forms are an inner length `0x80` or `0xFF`, a constructed inner OCTET STRING,
  and an inner identifier other than `0x04`. Whether such a certificate is accepted stays the platform's decision;
  revokt queries the pairs it extracts, the more-checking direction.
- **Decided** (#57): K6, K7 and K8 stay narrow. No row is widened for the D8-gap entries with no zlint error, nor for
  the P-192 key on which zlint gives no verdict (zcrypto cannot parse it), and their written justifications stand:

  | Shape | Entries | Row |
  |---|---|---|
  | subjectAltName with a `directoryName`, `uniformResourceIdentifier` or `otherName`, or a dNSName of non-ASCII octets | 9 `x509-limbo` | K8 SAN |
  | nameConstraints in a leaf | 2 `x509-limbo` | K8 |
  | authorityInfoAccess with a `dNSName` accessLocation | 2 `x509-limbo` | K8 AIA |
  | extKeyUsage with no purposes | 1 `x509-limbo` | K8 EKU |
  | a DSA key | 1 `x509-limbo` | K7 |
  | an EC key on P-192 (zlint gives no verdict) | 1 `x509-limbo` | K7 |
  | a GeneralizedTime `notBefore` in year 0000 or 0001 | 4 seed-corpus leaves | K6 |

  Widening a row needs its certificate-transparency-go return-site proof (§9.2, "The table is the proof"), and a
  wrongly widened row is a false-`REVOKED` P0; a row kept narrow costs only that `DEFAULT` never queries such a leaf
  and `STRICT` rejects it. Appendix A's re-scan of 159 270 RFC 6962 entries found none of the SAN, AIA or
  nameConstraints shapes outside the profile, the D8 gap over the seed corpus's leaves of index issuers is 0 of
  117 603 (revision 45), and the K6 leaves are those of eMudhra's "EM DV TLS CA - G3B", which no root program trusts.
  The EKU and K7 rows have no CT evidence either way; a gap entry at them among a later pin's CT leaves of index
  issuers counts toward the 10^-4 re-decision as any other does.
- **Recorded**: the 24 corpus records whose justifications deferred to #57 now cite this decision, at revokt-corpus
  `v6`, which differs from `v5` only in `replay/records.jsonl`, `replay/PROVENANCE`, the tool that writes the
  `x509-limbo` gap justifications, and the manifest.

### Changes in revision 45 (the seed corpus's leaves of every index issuer, 2026-10-29)
- **Corrected** (#15): revision 44 took the `v4` pin for the 100 000 leaves the D8 re-decision needs. 44 454 of its
  110 043 leaves are CT test traffic, certificates that log operators and monitors issue to test logs, under four
  issuer names no root program trusts: Google's "Merge Delay Intermediate 1" (35 447), Geomys's "CT Uptime Test Root"
  (7 407), "DigiCert CT Monitor" (1 598) and TrustAsia's "TrustAsia DV TLS ECC Test CA G4" (2). Only 60 427 of its
  leaves verify under the key of an index issuer, those of 201 of the 1 035 index keys, so the re-decision was
  evaluated on fewer leaves than §9.2 requires, and the seed did not reach most enrolled CAs.
- **Changed** (#15): the seed corpus's CT leaves are two sets, pinned at revokt-corpus `v5` (§9.2, Appendix A): the log
  sample of revision 44 without its CT test traffic (65 589 leaves), and a top-up from crt.sh of each index key's most
  recently issued certificates valid at the top-up's start that cannot issue certificates, at most 120 per key (71 614
  leaves of 927 keys). 132 041 leaves verify on the test JDK under an index key, of 975 of the 1 035 keys (118 159
  distinct index keys and serials, since a precertificate and its final certificate count as two; 104 033 among the
  117 603 unexpired leaves the D8 gap counts). Of the other 60, crt.sh holds no such certificate issued in the last 400
  days for 54, its query timed out for 5 (the queries of 49 CAs timed out on every try; the log sample covers 44 of
  their keys), and one key, of Telia's "Telia CA EC QWAC R1", has no crt.sh CA.
- **Stated**: the top-up trusts nothing crt.sh sends (§9.2). crt.sh's database serves TLS under a certificate that
  expired on 2026-06-21, so the connection is encrypted but not authenticated; a certificate is kept only when it is one
  DER Certificate with nothing after it, minimal lengths in the headers checked and a v3 TBSCertificate, whose signature
  verifies under the key that hashes to the index key, and a TBSCertificate is kept once. An attacker on the path can
  withhold certificates, which the recorded counts show, but cannot add one its issuer did not sign.
- **Changed** (§9.2 D8 gap): the gap and its 10^-4 re-decision count only the seed's leaves of index issuers, as the
  100 000 do: those the test JDK verifies under the key of an issuer-corpus certificate whose SPKI hashes to an index
  key and whose subject is the leaf's issuer. The filters hold no revocation of any other issuer's leaf, so a gap entry
  there leaves no revocation unchecked; such leaves stay in the corpus for D1–D3. A gap leaf is
  `PARSE_FAILED(PRODUCER_UNKEYABLE)` whatever its issuer, since keyability is decided at parse (revision 34); a keyable
  leaf of such an issuer would be `NOT_ENROLLED`, which `STRICT` also rejects. The two differ only where `NOT_ENROLLED`
  is exempted, as under `anchorIn` for a private anchor, since `PARSE_FAILED` is not exemptable: revision 34's
  private-anchor caveat (§10 item 8). Revision 44's 6 gap entries are all of one such issuer: both CCADB records of
  eMudhra's "EM DV TLS CA - G3B" are revoked and trusted by no root program, and its key is in neither fixture index.
  Its 4 at TIME are the only K6 entries among the CT leaves, so no CT leaf of an index issuer argues for widening K6
  (#57).
- **Recorded**: the D8 gap over the `v5` pin's unexpired leaves of index issuers the matrix JDKs accept (as of the
  top-up's start) is 0 of 117 603, the same on JDK 17, 21, 25 and 27, all in the D1 domain. With at least 100 000
  leaves pinned and the gap below 10^-4, exact keyability is not reconsidered (§9.2 D8). The count by clause is
  recorded per matrix JDK and shown in `docs/dev/status.md`.

### Changes in revision 44 (the seed corpus's CT leaves pinned, 2026-10-29)
- **Recorded** (#64, toward #15's seed corpus): the CT seed corpus is pinned at revokt-corpus `v4`, 110 043 distinct
  leaves from 80 of the 81 CRLite-enrolled logs (Appendix A). A random sample of the logs, it has some 400 distinct
  issuer names; that it covers every enrolled CA (§9.2) is not yet checked, and #15 stays open for it. Its D8 gap over
  the unexpired leaves each matrix JDK accepts is 6 of 91 345 (6.6·10^-5, the same on JDK 17, 21, 25 and 27), below the
  10^-4 re-decision threshold, so exact keyability is not reconsidered (§9.2 D8: the pin has the 100 000 leaves; a later
  pin that #15's coverage check brings is re-evaluated). All 6 are leaves of one CA ("EM DV TLS CA - G3B", eMudhra) for
  subjects under the `.invalid` TLD: 2 outside the profile at EXTENSION with zlint errors, and 4 at TIME, lint-clean,
  whose `notBefore` is the GeneralizedTime year 0000 or 0001, outside K6's 1950 to 9999. They carry written
  justifications, and whether to widen K6 joins #57's decision. The count by clause is recorded per matrix JDK and shown
  in `docs/dev/status.md`.
- **Added** (found on the same corpus): two more recorded platform cases in D2's normalisation, where revokt is right.
  `CONSCRYPT_TIME_JULIAN`: Conscrypt 2.7.0 and 2.8.0 read a time before the Gregorian reform (1582-10-15) in
  `java.util.GregorianCalendar`'s Julian–Gregorian hybrid, so the four year-0000/0001 `notBefore` above come out two
  days earlier than the JDK's and revokt's proleptic Gregorian reading; a difference is recorded per Conscrypt version
  only where the platform's value is exactly that hybrid reading of the time's fields and revokt's equals oracle 1's.
  And the JDK's `getExtensionValue` reports `id-pkix-ocsp-nocheck` (whose value RFC 6960 makes NULL) with empty content
  whatever the certificate carries, since its `OCSPNoCheckExtension` keeps no value: on oracle 1, D2 expects that
  extension's value empty, in effect comparing its presence only (2 leaves of the corpus).

### Changes in revision 43 (oracle 4's input in the producer SPKI check, 2026-10-25)
- **Corrected** (found while implementing #15): revision 42 said oracle 4 runs on the DER, not `canon`, and that the
  two are equal on every `ct`-path input. They are not: 5 issuer-corpus certificates (Appendix A) carry an outer
  `signatureAlgorithm` (sha1WithRSAEncryption) other than their TBS's (ecdsa-with-SHA384, sha384WithRSAEncryption),
  which `canon` replaces with the TBS's. Oracle 4 runs on `canon`, as everywhere, and what agreement needs holds: on
  every `ct`-path input the TBS, and so the SPKI hashed, is the DER's, which the replay asserts. certificate-transparency-go
  rejects those 5 on the DER ("mismatching signature algorithm identifiers"), so `canon`'s `ct` set is a superset of
  the DER's (canon only removes ct-go errors) and index coverage counts only a certificate whose `canon` is its DER.
- **Stated**: the issuer corpus's CCADB certificates come from the `AllCertificatePEMsCSVFormat` export by
  `NotBeforeYear`, since the all-certificate-records export carries no PEM; the records export's certificates that
  export lacks (15 on 2026-10-25, all revoked) are fetched from crt.sh by fingerprint. Until the 0.3 images are pinned,
  AOSP `ca-certificates` `main` stands in for "the sources of the pinned images".
- **Recorded**: the CT seed corpus starts as a pilot of 22 559 leaves from 80 of the 81 CRLite-enrolled logs (one did
  not answer), with no D8-gap entry among its 19 846 unexpired leaves the JDK accepts (Appendix A). At that size
  10^-4 is about 2 entries, so the re-decision is evaluated when #15 pins the full corpus (at least 100 000 leaves).

### Changes in revision 42 (the producer SPKI check without an enrolment flag, 2026-10-25)
- **Changed** (found while implementing #15): the producer SPKI check named "every intermediate the collection marks
  CRLite-enrolled", but no record of Mozilla's `intermediates` collection marks it true: on 2026-10-25, the 1 020
  records modified from 2019-06-07 to 2024-10-21 carry `crlite_enrolled: false`, and the 883 since 2024-11-09 omit the
  field. The old check selected nothing and held vacuously. The pinned producer does not read the `intermediates`
  collection. Its **program set** comes from the CCADB `MozillaAllUnexpiredPEMs` report: the intermediates zcrypto
  parses, not revoked, that zcrypto verifies to a Mozilla root for serverAuth, each re-parsed by
  certificate-transparency-go's `ParseCertificate` and dropped on any error, non-fatal included, and keyed by
  `SHA-256(RawSubjectPublicKeyInfo)`, the SPKI TLV as presented (Appendix A). A generation's index (its full filter's
  and each delta's) is a subset of the program set; "enrolled" means in an index, as `NOT_ENROLLED` does (§6.2, §8).
  The check now has two parts, neither needing a flag: **SPKI agreement**, `SHA-256(rawSpki)` equal to oracle 4's SPKI
  hash for every issuer-corpus certificate oracle 4 parses through `ct`, a superset of the program set, and a revokt
  parse failure counting as a difference where oracle 4's hash is an index key; and **index coverage**, every key of
  each index of the fixture generation equal to oracle 4's `ct` SPKI hash of an issuer-corpus certificate, and so, by
  agreement, to revokt's. Together they assert what the old check meant, that revokt keys every enrolled issuer as the
  producer does (a divergence makes revokt miss the issuer and skip its leaves, fail-open), over every enrolled
  issuer. The old check would also have failed on a flagged issuer the producer left out; that was never a property of
  revokt, and an issuer outside the index is not enrolled (`NOT_ENROLLED`, §6.2, §8).
- **Added**: the issuer corpus includes the `MozillaAllUnexpiredPEMs` report. For an index key no snapshot covers (for
  example, its certificate left the report after the generation), every CA certificate CT holds for that SPKI hash is
  admitted, fetched from crt.sh by `spkisha256` with its id and retrieval time recorded in revokt-corpus. Each
  snapshot is recorded in revokt-corpus with its URL, its retrieval time and the SHA-256 of the raw download.
- **Clarified**: ct-go's strict parse, oracle 4's `ct` path, is `ParseCertificate` without a `lax` retry returning a
  certificate, its non-fatal x509 errors included; the producer's program set takes only those it returns with no
  error. D8 and the audit argument keep the term with that meaning.

### Changes in revision 41 (two recorded platform cases in D2, 2026-10-25)
- **Added** (found while implementing #14, the `x509-limbo` replay; #59): a second rule in D2's SPKI re-encoding
  allow-list. A JDK without a KeyFactory for an algorithm returns a generic key whose `getEncoded()` re-encodes the
  AlgorithmIdentifier with NULL parameters where the certificate has none; JDK 17.0.20.1 does so for ML-DSA keys,
  17.0.21 knows ML-DSA and keeps the bytes. The rule, on the bytes alone, admits exactly that case: `rawSpki` with every
  header minimal and NULL parameters added to an AlgorithmIdentifier that has none, nothing else differing. revokt is right there, since `rawSpki` is the
  certificate's bytes, equals the raw-byte reference and is what the producer keys. CI runs each matrix JDK at its
  latest patch (CONTRIBUTING §6), so the rule names a case a lagging patch, or any JDK meeting an algorithm it does
  not know yet, would otherwise report as a violation.
- **Added** (found while building the D7 corpus, #14): `CONSCRYPT_TIME_OFFSET`, a `D3_DIVERGENCE` record (a D2 field
  difference) of oracle 2.
  Conscrypt 2.7.0 and 2.8.0 accept a `UTCTime` with a `±hhmm` differential and drop the differential, reading the
  local time as UTC (probed 2026-10-25: `261022134530+0100` is 13:45:30Z, where the JDK reads 12:45:30Z, and
  `-0130` is also 13:45:30Z); they reject a `GeneralizedTime` with one. revokt decodes as the JDK does (§9.2
  "Times"). A `getNotBefore()`/`getNotAfter()` difference from oracle 2 is recorded under this class, per Conscrypt
  version, only where the time is a `UTCTime` with a differential (read from the input bytes by the replay, never by
  revokt's parse) and oracle 2's value is revokt's plus the signed differential, revokt's being the local time minus
  it; on a matrix run revokt's value must also equal oracle 1's. Any other time difference stays a violation. RFC 5280
  requires `Z`, so only non-conforming certificates carry such a time, and K6 puts such a leaf outside the keyability
  profile, so CRLite never queries it. M4's distrust-after reads revokt's `notBefore`, with the JDK's meaning, on both
  platforms; a decision made from Android's `getNotBefore()` can differ from it by the differential, less than a day,
  since the JDK and Conscrypt 2.7.0 and 2.8.0 reject an hour of 24 or more and a minute of 60 or more.
- **Stated**: every SPKI hash revokt computes (`Cert.spkiHash`: the candidate index, `leafKeys`, the verifier caches)
  is `SHA-256(rawSpki)`, over the encoded certificate's bytes, never over a platform's `getPublicKey().getEncoded()`
  (§9.2 D2's normalisation is the only use of that getter in revokt's code). A binding that hashed it would usually
  miss an enrolled issuer (fail open); where the re-encoding is another enrolled encoding of the same key, it would
  query outside the universe (§10, "Two SPKI encodings").
- **Clarified**: the matrix runs each JDK at its latest patch at run time ("Tiers and matrix"); "strict DER" for
  Conscrypt means its TLV parse (no indefinite or non-minimal lengths), since it accepts a `UTCTime` differential; the
  record schema's platform oracle entries carry `holds` on an oracle-dependent record, as the corpus already does, and
  each entry's `version` is defined (a JDK patch or an APEX update that changes an outcome fails the run until the
  records are regenerated).

### Changes in revision 40 (the matrix file and the nightly's Conscrypt release, 2026-10-25)
- **Clarified** (found while implementing #13): the version matrix runs one job per JDK with every Conscrypt version
  of the matrix inside it, a test run per version, as CONTRIBUTING §6 already said. The committed matrix file is
  `gradle/oracle-matrix.properties`; it names the Conscrypt versions by their catalog keys and the nightly's JDK EA
  release, rolled by hand, and from 0.3 the Android system images.
- **Changed**: the nightly replays the committed corpus against the newest JDK EA as before, but cannot replay a
  Conscrypt release newer than the matrix's current one: an unadmitted dependency fails dependency verification
  (CONTRIBUTING §3), and resolving an unverified Conscrypt artifact in CI is not acceptable. The nightly fails
  instead, and so blocks a release (CONTRIBUTING §6), until that release is admitted (checksums and signing key
  checked) and rolled into the matrix, after which every PR replays it. The cost: between a Conscrypt release and its
  admission nothing replays it, where before the nightly did within a day. A patch of the previous minor waits for the
  next roll.

### Changes in revision 39 (the JDK read fallback, 2026-10-25)
- **Added** (found while implementing #12, oracle 1; #49): on the JDK, a certificate whose `getEncoded()` is
  `ParseFailed(STRUCTURE)` is read once more through the bytes the JDK verified the signature over,
  `getTBSCertificate()` and `getSignature()`, assembled as `canon` is but with the padding bits cleared (the platform
  canon, §9.2). A valid signature makes those bytes what the CA signed, however the presented encoding was altered, so
  a certificate the platform or the walker verified is read as the CA issued it. Oracle 1's `encoded` is the bytes so
  read, and D1, its domain, D2 and D6 follow unchanged. The JVM binding applies the fallback where the engine parses a
  certificate; the bytes read are its DER for parsing and the engine's hashes, while the identity keys stay over
  `getEncoded()` (§5.3, 0.2). Conscrypt needs none, since it parses strict DER. A certificate so read carries no
  `AlgorithmIdMismatch` finding unless its TBS AlgorithmIdentifier is not minimal DER.
- **Why**: the committed D7 corpus holds platform-accepted inputs that neither 3a nor 3b locates (an indefinite TBS
  holding a non-minimal definite child, on JDK 17, 21 and 27; a definite TBS holding an indefinite Validity, on JDK 25
  and 27; Appendix A), which broke D2's raw-byte-reference metric. A rule-based exclusion was drafted, but its
  argument misread what the JDK verifies (the independent review of #48). With the fallback, revokt's safety does not
  depend on that question, which #49 keeps open. The replay (#12) reads the nine indefinite-TBS inputs through their
  platform canon: each parses, has a raw-byte reference and passes D1 and D2 on all four matrix JDKs, and oracle 4
  rejects the platform canon of the three that JDK 25 and 27 accept, which are D1-dom. D7 records the nine's outcome
  accordingly.
- **Changed**: a JDK-accepted input for which no platform canon can be built is D1-dom by rule, since the producer
  cannot key a TBS in which the locator finds no signature AlgorithmIdentifier. D2's metric gains an exclusion: inputs
  revokt does not parse on whose `canon(encoded)` oracle 4 rejects, or for which no platform canon can be built; the
  Acceptance criterion follows. The record schema carries oracle 1's read per JDK version. The 3b table notes its
  `CANON` reply, and D7's SPKI form reads `30 83 00 …`, as the corpus builds it.

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
