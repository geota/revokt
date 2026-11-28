# revokt decision log

Every maintainer and lead decision on an ask-first question, newest last, with the references (upki and webpki, and
Firefox) each was compared against. Spec text follows from these through the next spec revision. Moved here from the
maintainer's working notes on 2026-11-16 (#217); earlier entries keep their wording, except where noted below.

**Conventions.**
- Numbers such as "#1" and "A1" in the first sections are items of the 0.2 plan (its ask-first list and its critique),
  which is not in the repository.
- "The 2026-11-16 design audit" is the Fable 5.2 audit of decisions, architecture and process, tracked in #230.
- Divergences from the references are in [DIVERGENCES.md](DIVERGENCES.md).
- Rewritten on the move: an entry about filename validation is stated in generic terms, and the reproduction detail
  of a CI hardening finding is summarised.

---

## 0.2 ask-first decisions (maintainer, 2026-11-05)

Numbers are INDEX.md's "Ask-first items" (1–11) and CRITIQUE.md's missed items (A1–A8).

### Behaviour
- **#1 FetcherTls:** A. In 0.2, FetcherTls carries the platform fetcherDelegate only. The fetcher trust managers,
  FETCHER_TRUST_UNAVAILABLE and the BLOCKED_BY_SELF hold arrive in 0.3. §11 (rev49) says the §8 fetcher policy does
  not run in 0.2.
- **#2 sync():** internal in 0.2 and runs only on its schedule. SyncResult, SyncOutcome and SyncStage still ship
  public (T2). §11 note in rev49.
- **A3 empty or throwing default trust store:** start() succeeds; evaluator.evaluate throws IllegalStateException
  until an index exists. Fix R2's acceptance and drop the false (h) attribution.
- **A4 step 6 with the fallback disabled:** PATH_BUDGET_EXCEEDED, the same as enabled. D1 gains the disabled branch.
  H1/H2 list per-path expectations: (ad) disabled → PATH_BUDGET_EXCEEDED, usedFallback = false.
- **#8 engineName:** RevocationEngine gains `val name: String`, defaulting to the class's simple name. Our engines
  override it with "kotlin" and "upki". engineName is then never null for producer ENGINE. This needs the rev49 spec
  PR (§3.2, §4 line ~1618) and an API change to the RevocationEngine merged in #95.

### Spec revision 49 (one PR): retag [0.2] → [0.3], and record the above
- **#3** Rule-model items: the counter sums (parseFailed, rejects), shadowPolicy, the c2spCache/SYSTEM items, and
  the clause on a path-cache hit. Their verdict-level half stays in 0.2 (E1).
- **#6** PKIX "both platforms": the jvmMain PkixPathBuilderFallback is JVM-tested in 0.2; Android instrumented in 0.3.
- **A1** (g): the Android and OkHttp halves of the 401/407 and SAN items move to 0.3; the JDK half stays.
- **A2** U4's clock-behind restart, the mirror index.bin window, and the 1 MiB + 1 cap via a mirror.
- Also in rev49: #1, #2, A3, A4 (step 6 disabled branch), #8 (engine name), and Appendix A's full SPKI SHA-256 of
  root-ca-production-amo (#10).

### Dependencies, assets, workflows
- **#5 benchmarks:** uncached Evaluator.evaluate in 0.2; the cached p95 in 0.3. kotlinx-benchmark (pulls JMH) in a
  separate, never-published benchmark source set, with a GPL-2.0-with-Classpath-Exception licence exception scoped
  to that configuration only (security.yml allow-licenses).
- **#7 R0:** review the walker implementation after W2/D1 and before Z1. A kind/test tracking issue that also covers
  the Rule model; its findings become fixture PRs. Fix ROADMAP's "before the walker is coded" sentence.
- **#9 upki crate:** add it to native/revokt-upki-shim, pinned `=1.0.1`. CI-only, with cargo-deny and licence checks.
- **#10 / A6 assets, all approved:** the AMO root pin through the spec (full SPKI hash in Appendix A, no committed
  certificate); revokt-corpus v7 with a real cert-revocations changeset plus its x5u chain, and the
  corpus-pin.properties bump; recorded MIRROR v4 generations from upki.rustls.dev for X2 leg (ii), after closing
  Appendix A's open check on upki-mirror's overlapping windows.
- **#11 workflows, both approved:**
  - CI1 nightly fuzzing: built now but disabled. `runs-on: [self-hosted, revokt-fuzz]`, workflow_dispatch only, with
    the nightly cron present but commented out. Never on pull_request (self-hosted runner). No ClusterFuzzLite.
  - S3 weekly seed job: publishing defaults to off; harden-runner egress allow-list of the three Mozilla hosts;
    CODEOWNERS entry and seed-publish environment. A data-only Central Portal account is still needed to publish.
- **A5 parser glob:** one kind/ci PR adds `**/parse/**` to protected-paths.txt, labeler.yml and CODEOWNERS, with a
  retro note listing #18, #24, #26, #27, #31, #41, #44 and #47. J1's read fallback and C2 go in engine/parse/.
- **A7 data licence:** approved. verifyPomLicenses accepts the "No copyright claimed; contains Mozilla Remote
  Settings data" text only for the data artifact's coordinates; code artifacts stay on the allow-list.

### Not asked
- **#4** fixture (b)'s MIRROR item: not ask-first (CRITIQUE). Assert it on the coverage function in 0.2 and say so in
  the PR. The MIRROR branch is dead code in 0.2, and G1 must not delete it.
- **A8** parallel lanes: already decided on 2026-11-04. It's a per-session instruction, and CONTRIBUTING is not amended.

## #124 decide readings (maintainer, 2026-11-06)
- `endDepth`: null on a completed walk; set only on Budget, and 0 on the step-3 cut. A `maxDepth` in WalkStats was considered and dropped: nothing reads it, and upki/webpki report no depth either. **Superseded by #226** (2026-11-22): `endDepth` and `WalkEnd` are removed; a walk has one budget and a `Budget` carries no path.
- `walkerReason`: set on every walk NotFound, whatever the status (so a fallback Found after UNANCHORED also triggers refreshAnchors).
- Budget with a fallback path and no partial path: the reported path is the fallback path; terminalKind/anchorSha256 follow it (keeps issuerSpkiSha256s[0] = reported path's key). Wording for #160.
- `AlgorithmIdMismatch` before the walk: once per certificate decide parsed (the leaf only at the step-2/PRODUCER_UNKEYABLE/MAX_PRESENTED exits).
- Standing direction: when in doubt, look at how upki handles it, and audit revokt against upki's approach.
- #163 content signature: Firefox parity on the leaf curve (any EC; no P-384 rule). High s stays accepted (real Mozilla data has s > n/2).
- #164 x5u PEM: lenient like upki/Firefox outside blocks (skip text and blank lines); each block strict.
- #163 mode: keep §7.1 (mode == p384ecdsa), a narrowing from Firefox, which accepts a missing mode.

## upki audit decisions (maintainer, 2026-11-06); rows in [DIVERGENCES.md](DIVERGENCES.md)
- Q12: MAX_MANIFEST_ENTRIES 32 → 256; fix §7.2 "about four days" and recompute §6.4's memory table from live mirror sizes.
- Q24: a MIRROR/SYSTEM generation with no filters or no coverage is refused (NO_DATA keeps firing), with a warning naming the source.
- Q15: validate every mirror and index filename per C2SP filename rules before it is used.
- Q13: the mirror fetch follows up to 10 redirects, HTTPS only; write upki's manifest/fetch grammar into §7.3.
- Q14: a mirror generation's age = now − newest coverage end, capped at now (a future end raises clock-behind).
- Q16: mirror filenames over 32 bytes get §6.5's derived names, with the collision check before any fetch.
- Q20: c2spCache takes the directory holding index.bin (…/revocation); fix the §4 example; add a helper with upki's per-OS default roots.
- 2026-11-06, #168 (rev52): the seed's expected attachments are those buildIndex(records, channel) places in the generation, not every records.json filename (records.json holds every channel's records). The maintainer confirmed; it matches upki-mirror's one-channel walk (mozilla-crlite.rs:55-66). Rules 8 and 9 adopted with the case clauses; rules 1, 2, 5, 6, 7 and 10 omitted; rule 4 is a #109 test.
- 2026-11-06: a mirror's index.bin is built locally from the downloaded filters, as upki fetch does (fetch.rs PlanStep::SaveIndex → Index::write); revokt never fetches index.bin from a mirror. This makes renamed names over 32 bytes work. The maintainer chose the upki approach; it lands in spec revision 53.
- 2026-11-06: #170 x5u chain: match Firefox/webpki on a leaf with cA=TRUE, malformed leaf BC/KU, unknown critical extensions, and EKU on intermediates (maintainer).
- 2026-11-07: #170 x5u floor: accept only the three RSA-PSS encodings that Firefox and webpki accept (SHA-256/384/512, matching MGF1 hash, salt = hash length, trailer 1) and only rsaEncryption/id-ecPublicKey keys; the general TLS verifier (§3, rev51) keeps any SHA-2 pair (maintainer). The ECDSA r/s range check (CVE-2022-21449) is still open.
- 2026-11-07: ECDSA r/s range check (1 ≤ r,s ≤ n−1, before the provider) in JcaSignatureVerifier, as ring does; guards JDK 17.0.0–17.0.2 (CVE-2022-21449). Issue #172; the spec lands in revision 54 (maintainer).
- 2026-11-07, #173 review: the x5u chain follows mozilla::pkix, with webpki divergences listed. The lead applied the maintainer's 'match Firefox' rule: nameConstraints use mozpkix dNSName semantics and fail closed only on a directoryName subtree (other forms cannot affect a dNSName-only leaf), with the new reason NAME_CONSTRAINTS; mozpkix leniencies are accepted (explicit FALSE, empty Extensions, negative serials, mozpkix time forms); CheckSubjectPublicKeyInfo is adopted; any duplicate OID is rejected (stricter, RFC 5280 MUST NOT); ECDSA n comes from the key's params.order (brainpool included); the CVE range is Java 15–18 GA per the reporter's write-up.
- 2026-11-07: CEL readiness for the types lane (#120, #122, #123, #133). Facts are plain data with no JVM-only types in commonMain; enum constant names are the policy vocabulary, frozen within a major, with a golden list; rules are table-driven, with fired rules an explicit intermediate result so #84's Rule.POLICY is one more row; exemptions stay pure and cached. #81 notes the 60 s TTL for time-based exemptions (maintainer asked; lead's criteria).
- 2026-11-08: PresentedChain keeps every presented certificate in order (index = AlgorithmIdMismatch.certIndex); an unparseable entry keeps its DER with empty parsed fields; parsed(i) tells them apart (maintainer, #120/#180). Needs a §4 spec line.
- 2026-11-08: buildIndex record selection follows Firefox (RemoteSecuritySettings.sys.mjs:646-659 at cac25a6): a channel must have exactly one full filter, otherwise the install is refused (sync FAILED/INDEX_INCONSISTENT/INDEX; seed SEED_UNREADABLE) and the previous generation stays live. Every delta of the channel is placed, ordered by time; parent is not read. Fails closed (an extra delta only adds revocations). Delta-chain logic stays in #141 (maintainer; differs from upki-mirror's parent walk, so a DIVERGENCES row is needed).
- 2026-11-08: Exemption and/or follow CEL's &&/||: short-circuiting but commutative. The side that decides the result wins whatever the other side did; an error is absorbed (and not recorded) when the other side decides, otherwise it is rethrown and recorded as not exempt plus EngineError(EXEMPTION). Fatal errors propagate. The outcome and findings never depend on operand order (maintainer; #122/#182).
- 2026-11-08: #133 readings R1–R5 accepted (maintainer). R1: a non-firing engine error is recorded in Finding.Crlite, and EngineError(ENGINE) is attached only when ENGINE_ERROR fires. R2: no exemption runs after a boundary catch. R3: Verdict.dataStates = requiredDatasets ∪ configured datasets, independent of the path. R4: a throwing clock gives BOUNDARY with nothing walked, no staleness and no exemptions. R5: engine.query throwing is a BOUNDARY error; earlier keys keep their findings, later keys are not queried. #112 folds into #133.
- 2026-11-08: #131 readings R1–R4 accepted (maintainer). R1: CLOCK_SKEW and STORE_FAILED count as feed failures, like FAILED; ROLLBACK_REFUSED does not; BACKOFF and DEFERRED leave the count unchanged. R2: every successful poll (INSTALLED, including clock-behind, and UNCHANGED) resets consecutiveFailures. R3: Backoff and Retry-After are honoured on every response, 2xx included (Firefox and Kinto). R4: UNCHANGED writes only the attempt fields plus the R2/R3 effects; the crash-repair rewrite is 0.3's. The lead: the coverage bound compares against the signed <ts>, per §6.3.
- 2026-11-08: the #119 ClusterFuzzLite nightly runs on GitHub-hosted ubuntu runners (free compute for the public repo); storage is protected by the separate corpus repository and short artifact retention. #185's dispatch-only self-hosted workflow stays for ad-hoc runs (maintainer).
- 2026-11-08: #175 skipped. No bcprov test dependency; the spec's BC brainpool range-check rows are dropped, relying on the curve-agnostic n = params.order and the NIST-curve tests. The BC path gets tested when revokt-bc is built (maintainer).
- 2026-11-08: §9 rows (e) with 63 junk, (s1) and (y2) are marked harness-only; their trust-manager expectation is "cut at step 3 (PATH_BUDGET_EXCEEDED)", as (ag) (maintainer; from the #171 review).
- 2026-11-08: §9 row (ac) keeps its purpose but moves the oddity off the leaf: the Teletex encoding goes on the issuer certificate's subject, and the leaf gets a non-matching keyIdentifier AKI instead of issuer-and-serial. New §9 rule: a row's leaf stays within K1–K8 unless the row tests PRODUCER_UNKEYABLE (maintainer; from the #171 review).
- 2026-11-08: add per-package Kover floors for walker/ and store/ (variants plus the koverExternalArtifactsWalker/Store lockfile lines), with floors a little under today's coverage (walker 99.4%, store 91%). Lockfile change approved (maintainer; #161).
- 2026-11-08: MozillaRemoteSettings.build() also rejects an x5uHosts entry or a rewrite target that isn't a bare ASCII DNS name (':', '@', '/', '?', '#', '[' or non-ASCII); this is a second throw case (maintainer; from the #177 review).
- 2026-11-08: the #160 spec pass is approved as one revision (56) covering every queued item; decided items are written as decided, open ones flagged. It runs when work resumes after the pause (maintainer).
- 2026-11-13: #185's dispatch workflow runs on GitHub-hosted runners too, not self-hosted, which removes the fork-PR runner risk (this replaces DECISIONS #11's runs-on). Fuzz findings file a private DRAFT repository security advisory through the API (a token secret with advisory-write from the maintainer), not a public issue; no public reproducer artifact. Private vulnerability reporting is already enabled (maintainer).
- 2026-11-13: #185 keeps one fuzz job, hardened. Java and Gradle processes are killed before the token step, the advisory script runs from the committed copy, crash inputs are minimised before inlining, and dedup uses the finding hash. Residual risk is recorded in the PR (maintainer chose this over the split job plus age-encrypted artifacts).
- 2026-11-13: rollback watermark floor. The effective watermark is max(stored, the live SIGNED generation's sourceTimestampMillis) unless that generation is clockBehind; it lives in SyncRules (maintainer; #190).
- 2026-11-13, rev56 (#188) decisions (maintainer):
  - B1: a MIRROR/SYSTEM coverage end beyond now + clockSkew is rejected (§6.3 stands). Within (now, now + clockSkew] it installs with ageMillis 0 and clockBehind false.
  - The empty MIRROR/SYSTEM generation warning gets a new DiagnosticCode, SOURCE_EMPTY: for a mirror it goes on SyncResult.warnings with FAILED at stage INDEX; for a system cache it is a start-time warning.
  - A mirror's If-Modified-Since is the local file time, as upki does: the time the live MIRROR generation's manifest was stored.
  - No c2spCache helper: the caller passes the directory.
  - validate() warns when ioDispatcher is exactly Dispatchers.Unconfined (#139).
  - Read metadata.signatures[] like Firefox and accept any entry that verifies under the pinned chain (a code change to #181's client).
  - The compat memory figure is measured from the corpus's signed attachment.size values.
  - Redirects are followed in the fetch layer by one shared RedirectingFetcher that wraps any HttpFetcher and runs every per-hop check: https; no userinfo or port rules; FetcherTls and the host checks; 301/302/303/307/308 on GET only; relative Location; at most 10 hops and no loops; one 30 s deadline for the chain; cross-origin header stripping; the body cap on the final response. The underlying client never follows redirects.
- 2026-11-13 (lead, under the maintainer's decisions): each redirect hop applies the same URL rule as the initial source URL; signatures[] is capped at 4 entries tried, in order, reusing an x5u URL already fetched in the same sync, with more than 4 SCHEMA-rejected; the mirror's If-Modified-Since timestamp lives in the MIRROR generation's meta.json; the memory figures come from the live 2026-11-12 changeset (52 deltas per channel).
- 2026-11-13 (lead, #188 follow-up): a mirror redirect hop is https, no userinfo, query allowed, fragment dropped, no port rule; more than 4 signatures[] entries, or none tried, is FAILED at stage SIGNATURE; a malformed updater.json's dataset members read as absent and count as a store failure.
- 2026-11-13: setup done. FUZZ_ADVISORY_TOKEN and CFL_CORPUS_TOKEN are revokt secrets; geota/revokt-fuzz-corpus is private, with Actions and issues off (maintainer).
- 2026-11-13, #196 F1, revised after the upki/Firefox audit (maintainer): follow Firefox. Any non-anchor certificate's own unsupported signature algorithm counts toward ISSUER_UNVERIFIED, as mozpkix's CheckIssuerIndependentProperties does (pkixcheck.cpp:993; pkixbuild.cpp:106-117). In exchange, ISSUER_UNVERIFIED and NO_ISSUER can no longer be exempted separately, as Firefox puts both errors in one override category (SSLServerCertVerification.cpp:247-252). So a decoy that relabels one as the other changes only the diagnostic. Lead's reading, to confirm in the spec pass: the two share one outcome and one exemption (an exempt() or rule() on either applies to both). This replaces the "leaf only" answer given earlier the same day.
- 2026-11-13 (standing, maintainer): every decision question shows how upki/webpki and Firefox handle the case, and answers are audited against them. An audit of that session's other decisions was kept in the maintainer's notes.
- 2026-11-13, #195 (maintainer): EvaluationRequest takes one platform-verified path, like upki's single webpki VerifiedPath (rustls-upki lib.rs:95-127); Firefox checks revocation inside path building, so it never has a leaf/issuer mismatch either (pkixbuild.cpp:237-247). verifiedPaths(List<List<ByteArray>>) becomes verifiedPath(List<ByteArray>). build() throws IllegalArgumentException when presented is set and presented[0] differs from the verified leaf. This closes r171's fail-open (mismatched leaves accepted under STRICT). Nothing is released, so there is no compatibility concern. Spec line for rev57 (#160).
- 2026-11-13, #196 F2 (maintainer, after the Firefox comparison): anchorIn matches the reported, first-found path, as Firefox applies its anchor-dependent rules (CT, CertVerifier.cpp:312-315) to the one chain it built. "Every found path" is dropped. Candidate order is still open: Firefox's order at every depth (roots, presented, preloaded) versus revokt's (below the leaf, store first, then presented).
- 2026-11-13, #196 F2 order (maintainer): the walker tries candidates in Firefox's order at every depth: store anchors, then presented certificates in index order, then store non-anchors (preloaded). This replaces related()'s per-depth split. The builder first measures the §9 padded-chain fixtures; any new PATH_BUDGET_EXCEEDED is reported before merge.
- 2026-11-14, #195 (maintainer, after the r171 follow-up): a one-certificate verified path skips the keyability gate only when its leaf is byte-equal to an anchor in the snapshot read at entry (step 2's rule); otherwise it is gated like any leaf. Like Firefox (GetCertTrust) and upki (webpki roots), anchor status comes from the library's own store, never from the caller. anchorSnapshotId is non-zero on that route.
- 2026-11-14 (lead, under the maintainer's "follow Firefox" for F1): labels follow pkix's literal order. Any related name-matching candidate with an unsupported own signature algorithm counts, verified or not (CheckIssuerIndependentProperties runs before VerifySignedData). The leaf's own algorithm counts only when an issuer was otherwise found (pkix defers end-entity errors, pkixbuild.cpp:281-292, 354-357). pkix's collapse to UNKNOWN_ISSUER on mixed candidate errors is not mirrored, a divergence. Labels only; verdicts are unchanged because of the shared slot. Order measurement: 66 §9 rows show no change.
- 2026-11-14, #197 (maintainer, after r197's must-fix): on a trust-manager binding (and Revokt.evaluate), any walk NotFound whose fallback failed reads NO_ISSUER(PLATFORM_ONLY), whatever the label; ISSUER_UNVERIFIED appears only on Evaluator.evaluate. UnsupportedAlgorithm still names the OID. Neither reference has a platform layer; this keeps F1 verdict-neutral, as Firefox's single override category is.
- 2026-11-14 (maintainer): #8 closed and #7 not planned. The clubcard port stays 1:1 with upstream, as upki (clubcard 0.3.3 / clubcard-crlite 0.6) and Firefox cert_storage (0.3 / 0.4) use it unmodified.
- 2026-11-14 (lead, under "read signatures[] like Firefox", from r198 on #198): an empty x5u or signature string is skipped like a missing one (Firefox `!x5u`). A null signatures[] element is FAILED at SIGNATURE, as Firefox throws there. Verified carries the records and timestamp it verified, and #137 installs from those.
- 2026-11-14, #137 (maintainer, after the upki/Firefox comparison):
  - Q1: MAX_SYNC_BYTES is removed, as neither upki nor Firefox has a per-sync total. Only the per-file caps and the count caps (MAX_MANIFEST_ENTRIES, MAX_CHANGESET_RECORDS) remain; worst case about 4 GiB from a malicious mirror, accepted.
  - Q2: prune after every INSTALLED (once the flip and updater.json are written), never after a failure. Matches upki (Delete steps after a successful plan) and Firefox (old deltas dropped when a new full installs).
  - Q4: mixed filter encodings are allowed. meta.format is the full's encoding, and each filter is read in its own. Matches Firefox cert_storage and upki.
  - Q5: until #141, #137 always fetches the whole changeset (no _since, no If-None-Match); the cursor is written but not read.
- 2026-11-14 (lead, #137 Q3): generationId's "last applied record" is the last filter in buildIndex placement order (the full, then deltas by (effectiveTimestamp, id)). Neither reference has a generation id. Narrow fixes approved: SignedMeta accepts any non-empty even-length signature (any EC leaf curve per #163), and DatasetGeneration publishes the loader-decoded maximum coverage.
- 2026-11-14 (lead, from r199 on #199): the format check applies to every placed filter. A full or delta whose encoding isn't in engine.formats is FAILED, FORMAT_UNSUPPORTED, at PREPARE, and the previous generation stays. This follows from 'each filter is read in its own encoding' plus the existing refusal of an unsupported full. Firefox would install the files and lose coverage (cert_storage decode failure → NO_FILTER); upki errors on read.
- 2026-11-15, #185 (maintainer): after a security review of the token route, the fuzz job ran as a second user (later replaced by the two-job design). It stays one job. Neither reference runs fuzzing in CI with a write token.
- 2026-11-15 (lead, from r200 on #200): following §6.5's literal text (install is the whole sequence from the body fetch on), an OOM during the body phase also counts storeFailures++. Neither reference has a store-failure counter. Prune with an Absent pointer deletes nothing (a data-loss guard).
- 2026-11-15, #200 (maintainer): a same-<ts> re-sign during the activated-STORE_FAILED retry reuses the stored directory when meta.json differs only in `signed` and index.bin and records.json are byte-equal; it then finishes the flip and the updater.json write. Matches Firefox's equal-timestamp rule (RemoteSettingsClient.sys.mjs:778).
- 2026-11-15, #185 (maintainer): findings go out as an age-encrypted artifact, and the workflow holds no secret at all. A finding fails the run and uploads each minimised crash, encrypted to the maintainer's public key (repo variable FUZZ_AGE_RECIPIENT). The maintainer decrypts locally with rage and files any advisory by hand. The second user, the isolation check, the path locks, the advisory script and FUZZ_ADVISORY_TOKEN are all removed. This replaces the 2026-11-15 separate-user decision.
- 2026-11-15, #185 (maintainer, replaces the same-day encrypted-artifact-only entry, whose notification could go unnoticed): two jobs. Job 1 fuzzes with no secrets. It uploads each minimised finding age-encrypted (ASCII armour) to FUZZ_AGE_RECIPIENT, with its finding hash, and fails. Job 2 runs on a fresh VM with FUZZ_ADVISORY_TOKEN and no checkout of anything but the committed advisory script at github.sha, with no Gradle and no project code. It validates the artifact (names, sizes, armour format, at most 8 findings) and files one private draft advisory per new hash, with the armoured ciphertext inline. Encryption is needed because the artifact moving between the jobs is downloadable on a public repo.
- 2026-11-15, #192 (maintainer): Q2: a strict RFC 3986 parse of Location with no repair; anything malformed fails the hop. It reuses revokt's commonMain X5uUrl grammar as the one shared strict parser (no KMP library exists; OkHttp HttpUrl and ktor Url are lenient WHATWG-style). The fetcher is handed the URL revokt serialised, never the raw header. Q3: hops and the configured mirror URL may use IPv4 and [IPv6] literals as well as DNS names, as reqwest and Firefox allow.
- 2026-11-15 (lead, #192): Q1: a 3xx without Location is returned unchanged, as both references do. Q4: differing duplicate Location headers fail, identical ones collapse (Firefox nsHttpHeaderArray). Q5: the loop key is the resolved URL without the fragment, with scheme and host lowercased and :443 dropped; the path and query compare exactly; the initial URL counts. b192's other readings are accepted: unfollowed statuses are returned unchanged, maxBodyBytes applies per hop, the five named headers are stripped and stay stripped, no Referer, and each hop gets the time left.
- 2026-11-15 (lead, #185, from the security review): FUZZ_ADVISORY_TOKEN moves into a GitHub Environment `fuzz-advisory` restricted to the default branch. The advisory job declares it and runs only when github.ref == refs/heads/main, so a dispatch on another branch can't reach the token.
- 2026-11-15, #141 (maintainer): Q1: every verification failure of a `_since` changeset triggers the one reset-and-retry. That includes an x5u network error, CLOCK_SKEW at X5U, and a change list that can't be merged. The retry reuses the sync's x5u cache, and a failed retry ends with its own outcome and stage. This is broader than Firefox, which retries only on InvalidSignatureError. Q2: with no CRLITE staleness entry there is no metered deferral, and the full downloads; neither Firefox nor upki defers on metered. b141's listed readings are accepted. The corpus-tier acceptance item waits for #113.

- 2026-11-15 #119: crash reports follow #185 (age-encrypted, private draft advisory via the fuzz-advisory environment), not the public security issue and artifacts in the issue text. References, from general knowledge and not checked in-session: OSS-Fuzz keeps crash reports restricted until they are fixed, and Firefox files fuzzing crashes as hidden security bugs. upki at 9821cce has no fuzzing workflow to compare with (checked: .github/workflows has only bench, build, lints, mirror and release).
- 2026-11-15 #194/#207 (maintainer): Q1, when the bootstrap condition fails, MirrorSync returns an internal "not run" value that the loader never publishes, not UNCHANGED (upki has no bootstrap rule; Firefox has no mirror client). Q2, the manifest fetch, a malformed manifest and an over-cap manifest are stage CHANGESET, and spec §7.3 says so in rev58 (upki splits manifest and file errors only by URL, fetch.rs:82-104 vs 290-319). Lead, from r207: bootstrapHolds fails closed (a malformed pointer, an unreadable pointed meta, or any SIGNED gen-*/meta.json); mirror files get §4's body CAP_NEAR_LIMIT; a generated_at past 9999-12-31 is refused, as upki does; the mirror client fails any 3xx except the manifest's 304 (a 304 to a filter request included).
- 2026-11-15 (lead, rev58 from r208): revokt keeps credential headers dropped for the rest of a chain, which is stricter than reqwest (it rebuilds each hop's headers from the original request); no Referer, unlike reqwest's default, which upki doesn't turn off.
- 2026-11-15 (lead, #207 from b194): Q3, spec §9's built-index row says "over 1 MiB" (a built index is always even; rev58). Q4, partly done fixtures use `fixture (x)` test names so specStatus doesn't mark them done.
- 2026-11-15 (lead, #205 from r205/r205b): a directory nothing holds (not live, not pointed) is always completed afresh, keeping only files that re-hash to a placed delta; a held directory with a mismatch stays "holds another generation". This narrows the maintainer-accepted reuse reading. The 304/snapshot note for a persisted store is on #147.
- 2026-11-16 (lead, #205 round 3-4): `StoreLayout.reopen` fails closed. It proceeds only when the pointer is Absent, or Found and not naming the directory, and throws on a Malformed pointer. Accepted trade-off: with a corrupt pointer, a complete orphan at the same `<ts>` fails each sync (FAILED at STORE) until the next `<ts>`. That costs availability, never data, and is preferred over possibly deleting the pointer's `previous`.
- 2026-11-16 (maintainer, after the 2026-11-16 design audit): finish #207 and stop new mirror work (#148); pause #119 and schedule fuzz.yml as the nightly tier; put builders on the 0.2 vertical slice, #110 → #127/#128 → #139 → #143, plus #138. The audit's other recommendations are not decided yet.
- 2026-11-16, later (maintainer): **accept every recommendation of the Fable 5.2 audit.** This supersedes the entry
  above on #207: the MIRROR source is cut (#218), so #207 is parked and closed unmerged, and #194 and #148 are closed
  as not planned. The follow-ups are #210 to #229, tracked with their order in #230. Decisions this reverses or
  narrows:
  - #141 Q1, retry on every verification failure → retry only on a signature mismatch or an unmergeable change list,
    as Firefox does (#224);
  - 2026-11-13, the NO_ISSUER/ISSUER_UNVERIFIED shared slot → one NO_ISSUER rule with a reason (#225);
  - #198, more than 4 `signatures[]` entries fails → try the first 4 and ignore the rest (#223);
  - the exact x5u host and attachment URL → a suffix rule over Mozilla's CDN, reading `base_url` from the server
    (#223);
  - the 24 h rollback window → refuse anything older than the watermark, as Firefox does (#224);
  - #141's metered deferral → dropped until Android (#224);
  - the walker → requires a CA issuer, as webpki and mozilla::pkix do (#225).
- 2026-11-16 (lead, store recovery principle, #236 and #138): **heal, never brick, never delete.** Neither upki nor
  Firefox has a pointer file or an updater record; both heal by fetching again.
  - A malformed `updater.json` reads as absent (§6.5), counted.
  - A read that *throws* writes nothing (#209).
  - With a malformed pointer, a complete target directory is treated as held: compared and reused if it is the same,
    never reopened, rewritten or deleted. The next flip writes a valid pointer.
  - A seed load with a malformed pointer scans the complete directories and skips if any signed generation is not
    older than the seed. Otherwise it installs, and doesn't prune in that load.
  - This replaces the 11-16 trade-off above, where a corrupt pointer blocked every sync until the next `<ts>`.
- 2026-11-16 (lead, #234): the walker follows webpki on anchors: no basicConstraints check on a trust anchor, where
  mozilla::pkix does check one. `pathLenConstraint` and `keyCertSign` are filed as #237. Rule removal before the first
  release is unblocked by #211 pausing RuleGrowability.
- 2026-11-16 (maintainer, #110): trust PGP key CE4B22DFBAE4458F43D3D5D3AD228764EA2E4BE9 (Toast Open Source, rsa4096, 2023-01-05), scoped to com.toasttab.android:gummy-bears-api-26, for animal-sniffer in revokt-jsse. The lead verified it on keyserver.ubuntu.com, with a good signature on the Maven Central 0.16.0 POM; the same key signed 0.15.0. The trust is pinned to version 0.16.0 in verification-metadata.xml, so each gummy-bears bump needs a new trusted-key line.
- 2026-11-16 (lead, #235): a seed load with a malformed or unreadable pointed meta.json gets the same no-delete treatment as a malformed pointer. A store fault is counted once, by Install.previous, not again by the loader. An archive over SeedArchive.MAX_BYTES (256 MiB) is SEED_UNREADABLE, a source fault, not a store failure.
- 2026-11-16 (lead, #242 from r242): beside a malformed pointer, a directory whose meta.json is present but malformed is held (never rewritten or deleted; STORE_FAILED at that <ts>, healed by the next <ts>), matching #178 beside a valid pointer. Only an absent meta.json is staged. A running loader offers liveDirectory() as the healed pointer's previous, when it qualifies, so its fallback survives the heal; a fresh loader's healed pointer has no previous.
- 2026-11-16 (lead, #234 second review): a PKIX fallback path's intermediates must also pass isCa, checked in Decide.path(), so a consumer fallback that skips basicConstraints cannot reopen the non-CA-issuer route. The JDK's CertPathBuilder enforces cA anyway. #237 widened to name constraints and EKU nesting.
- 2026-11-16 (lead, #235 from r235): a seed always compares against every complete directory's timestamp (pointed or not), so it never prunes a newer complete generation. Under an unknown store, a complete directory with the seed's own name is the same generation, so it is installed as it stands (re-hashed, prepared without reopening, flipped, which heals the pointer) instead of Skipped, which would leave nothing live. A seed-named directory with a present but malformed meta.json may be rewritten by the seed (same generation, freshly verified), unlike the sync (#242), which holds it until the next <ts>, because a seed's <ts> only changes with an app update. Store faults are counted once, where they are found.
- 2026-11-16 (lead, #237): the walker enforces pathLenConstraint and name constraints on issuers (both references); keyCertSign when keyUsage is present (mozilla::pkix and the JDK's KeyChecker; webpki ignores it on purpose, so this is stricter than webpki); and EKU on issuers by webpki's rule (none passes, one present must include the request's purpose, internal, default serverAuth).
- 2026-11-16 (lead, #237 R1/R2/R6/R7): the anchor's nameConstraints apply; webpki's name-constraint rule exactly (directoryName/URI fail closed, CN fallback a residual); all issuer checks apply to fallback-path intermediates; a 250,000-comparison name-constraint budget per walk, as webpki's default.
- 2026-11-16 (lead, #235 follow-up): one seed-load rule. (a) A valid pointer whose live generation reads and is not older: Skipped. (b) Otherwise, adopt the newest complete re-verifying directory if it is newer than the seed (flip only), else install the seed; a same-generation seed-named directory is installed as it stands (compared on everything except freshness and signed); a (b) load never prunes or deletes. A valid seed always leaves a live generation.
- 2026-11-19 (lead, #235 third review): a seed adopt never goes below the generation the engine serves; the adopted
  directory must be newer than the seed, not the watermark. An adopt writes `updater.json` with the watermark at its
  max, and re-verifies the signature when the signer leaf matches the seed's. A same-name directory that fails
  re-verification is rewritten from the verified seed, and a rejected directory counts once.
- 2026-11-19 (lead, #249): when a flip fails after activation, the next install's `previous` is the generation the
  engine served before it (when that one qualifies and differs from the new live), not the stale pointer's live, so
  prune never deletes the served generation. It matches #242's malformed-pointer branch. Neither reference keeps a
  fallback generation, so there is nothing to compare with.
- 2026-11-19 (maintainer, #215): trust PGP key 18CD85CBC5C1DB1684C5E59FA8E3B39F19E1CCE7 (Henry Coles, ed25519,
  2023-01-03 to 2029-01-01), scoped to `org.pitest` `pitest`, `pitest-entry` and `pitest-junit5-plugin`; the lead
  verified good signatures on the Central jars. Pitest runs through a `pitest-entry` runner (the Gradle plugin does not
  handle KMP, and the CLI pulls an unsigned jar and a DSA-1024 key), weekly or on dispatch, never as a PR gate.
- 2026-11-19 (lead, #256 from r256): a heal flip (the pointer `Malformed` before the install) never prunes; the next
  install with a valid pointer prunes. Nothing a damaged pointer may have named is deleted by a heal, the same as the
  seed's (b) loads.
- 2026-11-19 (lead, #223 under the maintainer's A-1 acceptance): the x5u and attachment hosts become `allowedDomains`
  (default `cdn.mozilla.net`, matched on a label boundary), with `base_url` read from the server when
  `attachmentBaseUrl` is null, failing closed at ATTACHMENT (rows S1 and S2 in DIVERGENCES.md). An absent or `null`
  signature `mode` passes; a present mode other than `p384ecdsa` still fails (reverses #163; row C1). The positional
  x5u chain is kept, so there is no path search over an unsigned body (X2). The leaf matches any dNSName with no
  wildcard, and only dNSNames are allowed in its SAN (X4). An absent leaf EKU passes; a present one must include
  codeSigning (X5).
- 2026-11-19 (maintainer, #253 review, #261): issuer name constraints in directoryName and rfc822Name form match
  Firefox. webpki refuses an issuer that carries such subtrees (`NameConstraintViolation`; x509-limbo
  `permitted-dn-match`, `nc-permits-email-*`), so the path is `NO_ISSUER`, which `DEFAULT` allows unchecked: a revoked
  leaf below such an issuer was accepted. mozilla::pkix (`pkixnames.cpp`) evaluates them: directoryName as an RDN
  prefix of the subject, rfc822Name against the presented mailboxes. URI and unknown forms still fail closed. R4a, the
  subject `emailAddress` fallback when there is no subjectAltName, and R4b, pkix's CN-ID fallback for a serverAuth
  leaf whose subjectAltName holds no dNSName or iPAddress, are both ported (maintainer); webpki and upki ignore the CN.
  W14 in DIVERGENCES.md.
- 2026-11-19 (lead, #261): the other readings of `pkixnames.cpp` at `cac25a6` posted on #261 are accepted as posted.
  Among them, R3: the iPAddress constraint keeps webpki's mask check, which refuses a mask that is not ones then zeros,
  where pkix applies the mask as written. §10 residual 15 lists it with the other two places revokt stays stricter
  than Firefox there (the 250,000-comparison bound, and a subjectAltName revokt's reader refuses).
- 2026-11-19 (maintainer, #224): the sync rules follow Firefox.
  - **Rollback floor:** when no stored generation loads, the stored watermark is ignored and older signed data
    installs. Firefox imports when its local data does not verify ("prefer stale data over corrupt"); upki has no
    rollback check. With a generation loaded, the floor is max(watermark, live `<ts>`), with no `rollbackWindow`.
    This reverses part of #190.
  - **Retry set:** retry once, as the whole collection, on a signature mismatch, `NO_SIGNATURES`, `NONE_TRIED`,
    `NULL_ENTRY`, or an unmergeable change list. All but `NULL_ENTRY` are Firefox's InvalidSignatureError family. In
    Firefox a null entry throws a TypeError and is not retried, so `NULL_ENTRY` is revokt's addition, harmless because
    the retry must verify. Never on an x5u failure, which narrows Firefox: it retries an x5u HTTP-error body (S6).
    upki never retries.
  - **Dropped:** the metered deferral and the clock rules on signed data, which neither reference has. `CLOCK_SKEW`
    stays for x5u validity only. The far-future `<ts>` residual (STALE fires late) is in §10 and DIVERGENCES.md.
  - **S13:** after a recovery install (no generation loaded, older data accepted), the watermark is lowered to that
    install's `<ts>`, as Firefox's floor is the local data's timestamp. The #273 review noted the alternative: keeping
    the high-water mark would refuse newer-than-held data until the server passed the old watermark.
- 2026-11-19 (lead, #224):
  - **S14, under S13:** a seed installed with no generation loaded also sets the watermark to its `<ts>`, as Firefox
    does after a dump import.
  - **"No stored generation loads" (from the #273 review):** it means the stored generation is absent or malformed,
    never that a read threw. A read that throws writes nothing (#209), so a transient fault never lowers the floor.
    Spec §6.5 and §7.1, row S4.
- 2026-11-21 (lead, #266): `fetch/` and `store/` move to jvmMain with their public types (`MozillaRemoteSettings`,
  `RevoktStorage`), unedited, so their FQNs and the JVM API dump are unchanged. Phase 1 (#267) moved
  `KotlinRevocationEngine` the same way. The walker and `verify/` stay in commonMain (W1), so the linuxX64 compile
  keeps checking the purity of the walker and the content-signature and x5u logic. `LruMap` becomes an internal
  interface made by `expect fun lruMap`, so no expect class remains. The pairs left (`lruMap`,
  `isFatal`/`restoreInterrupt`, `canonicalSubject`) are there for that compile. Rejected:
  - keeping both public types common, which leaves `ReadWriteGuard` behind and splits `StrictUrl` for no target;
  - W2, moving the walker and `verify/` too, which removes two pairs and loses that coverage.

  Source-set layout has no observable behaviour, so no reference comparison applies.
- 2026-11-21 (lead, #222 under the maintainer's B-F9 acceptance):
  - **`SyncFailure`:** one public code per step a sync stops at (22), so the code names the stage and `SyncStage`
    goes. `SyncOutcome` is `INSTALLED`, `UNCHANGED`, `SKIPPED` and `FAILED`. `ClientFailure`, `SignatureFailure` and
    `IndexRefusal` are removed. The leaf verifier and parser enums stay internal, and their value is in the detail
    text and the log. upki has one coarse `FetchError` of about 11 variants with the cause attached. Firefox reports a
    flat UptakeTelemetry status of about 15. A throw outside the store is `INTERNAL_ERROR`, with its cause kept.
  - **`STORE_LOCKED` dropped:** nothing produces it, and neither reference has an equivalent. The enum is growable.
  - **Failures leave `warnings`:** `SyncResult.failure` and its cause replace `SYNC_FAILED`, `SYNC_SCHEMA_REJECTED`,
    `INDEX_INCONSISTENT`, sync-time `FORMAT_UNSUPPORTED` and an over-cap `CAP_NEAR_LIMIT`. `DiagnosticCode` keeps the 6
    configuration codes main produces. Runtime conditions are a new `WarningCode` (`CAP_NEAR_LIMIT`,
    `SEED_UNREADABLE`, `SEED_CHANNEL_MISMATCH`) on `RevoktWarning` (code, dataset, message).
  - **`Finding.Path`:** keeps `status`, one `reason` (`PathReason`: the no-issuer, parse and budget reasons, set only
    for `NO_ISSUER`, `PARSE_FAILED` and `PATH_BUDGET_EXCEEDED`), the issuer keys, the anchor and the source. The walk
    counters go to one DEBUG line. webpki reports one error per failed build, with no counters.
  - **Two PRs:** split by area, both from `main`. #284 has the sync vocabulary and the `DiagnosticCode` split; the
    `Finding.Path` change follows in its own PR.
- 2026-11-21 (lead, then maintainer, #222 §4): the 21 §4 diagnostic bullets main does not produce yet
  (`NO_FETCHING_SOURCE`, `CHANNEL_UNSET`, `STORE_MIGRATED`, `RULE_FLIPPED_THIS_MINOR` and the rest) stay as specified
  behaviour. The enum lines list only produced codes, and a code joins its enum when its producer is built.
  Configuration codes join `DiagnosticCode`; store and seed state codes join `WarningCode`. The maintainer decided not
  to cut those bullets from the spec yet. Neither upki nor Firefox has a configuration-lint vocabulary, so the
  references give no guidance.
- 2026-11-22 (lead, #280 C): when every stored unit of a fuzz target is over its `-max_len`, the weekly prune fails
  closed. `stage --prune` leaves the target out with `::error::` and exit 3, the prune job fails the run once the other
  targets are pushed, and CONTRIBUTING §6 has the hand-trim step. There is no new delete path. When a target has any
  unit within `-max_len`, its over-length units are dropped, with no cut-down copies kept. ClusterFuzz's
  `corpus_pruning_task` replaces the corpus with the `-max_len` merge output, which adds cut-down prefixes, and raises
  `CorpusPruningError` on an empty merge without syncing. ClusterFuzzLite's prune passes no `-max_len` and keeps such
  units. revokt's prune can only delete, so it takes ClusterFuzz's drop and its fail-on-empty.
- 2026-11-22 (#229, design note `docs/design/content-addressed-store.md`, #289):
  - **Q1 (lead):** the pointer keeps `{live, previous}`, as #249 decided. upki keeps the old manifest's files on
    disk; Firefox keeps nothing.
  - **Q2 (maintainer):** the seed-load rule (b) adopt scan stays (#256). An offline start adopts a complete, verified
    generation already on disk, and the watermark is max(stored, adopted `<ts>`). Neither reference scans: Firefox
    falls back to its dump and syncs again, and upki has no pointer. Keeping the scan avoids the rollback window a
    lost pointer would otherwise open.
  - **Q3 (maintainer):** on a lock collision, an unreadable store or a newer layout, the instance runs in memory for
    the process, with the warning and no retry. The accepted costs are the seed's rollback floor and a full fetch in
    every such process. Rejected: throwing, as Firefox's profile lock does (from memory, not checked in source), and
    read-only instances, which the audit deferred. upki takes no lock.
- 2026-11-22 (lead, #226 under the maintainer's B-F7/A-9 acceptance; security review agreed, #291):
  - **One budget:** one count of candidate explorations at 256, charged for each candidate that passes the loop
    check. Each charged exploration makes at most one verifier call. Name-constraint comparisons keep an internal
    250,000 bound in the same budget. `MAX_VERIFICATIONS`, `MAX_RELATED_PER_LEVEL`, `RELATED_BUDGET`,
    `VERIFICATION_BUDGET` and the public `WalkEnd` are removed. An exhausted budget is `PATH_BUDGET_EXCEEDED`, which
    fails closed. webpki has three fatal counters (signatures 100, build calls 200,000, name constraints 250,000).
    mozilla::pkix has one build-call budget (200,000) and reports exhaustion as an unknown issuer.
  - **The first sound path at every depth, the leaf included:** as mozilla::pkix, which stops on a failed revocation
    check because "all paths through this certificate will fail". This is stricter than webpki, where `CertRevoked`
    is not fatal and the next candidate is tried. §10 residual 15 widens: when an unconstrained CA certificate
    holding a recovered key comes first in candidate order, only its key is queried. It also covers a second SPKI
    encoding of one honest key. A holder of such a key can mint a fresh leaf anyway. M2's order, with presented
    certificates before the preload as in Firefox's `FindIssuer`, does not close it.
  - **No unrelated-candidate loop and no `customCanonicaliser`:** neither reference has a relatedness class. A
    misclassified honest issuer goes to the PKIX fallback, then `FALLBACK_LIMIT` or `PLATFORM_ONLY`.
  - **Loop skip:** a candidate whose raw subject and raw SPKI match a certificate already on the path is skipped
    before the budget is charged, as both references do.
- 2026-11-22 (lead, #128, PR #290): `JdkHttpFetcher()` runs over the platform default TLS (#219 superseded the
  issue's `FetcherTls`).
  - **Host check:** each connection gets a hostname verifier that always refuses, and endpoint identification is left
    unset, so `HttpsURLConnection` matches the host against the peer certificate after every handshake, resumed ones
    included. A socket that arrives with an algorithm preset is refused. The first design forced endpoint
    identification instead. The #290 review showed that on Conscrypt a session resumed from a laxer connection then
    skipped the SAN check.
  - **Authentication:** a per-connection authenticator answers proxies only, so a 401 is never answered. upki
    (reqwest) takes proxy credentials only from the proxy URL.
  - **Connections and bodies:** `useCaches` is false and `Connection: close` is sent. Only gzip, x-gzip and identity
    bodies are accepted, and the cap applies while inflating.
  - **Residuals:** JDK transparent Negotiate/NTLM, and the process `CookieHandler`.
- 2026-11-22 (lead, #139 under rev61, PR #293): `dev.revokt.jsse.Revokt` and its builder.
  - **Where the issue and the spec differ, the spec wins:** no `fetcherDelegate`, `FetcherTls`, `Factory` or
    extended-delegate check (#219), and `http` defaults to `JdkHttpFetcher()`. No `meteredNetwork` (#224) and no
    `maxTrustManagers` (0.3). `revocationEngine` is `@RevoktInternalApi` (#220). The URL check covers `baseUrl` and
    a pinned `attachmentBaseUrl`, since the x5u host list is gone (#223). `IO_DISPATCHER_UNCONFINED` joins
    `validate()`.
  - **API:** no `storage(…)` setter in 0.2 (always in memory until the 0.3 store, #221) and no `platformTrust`
    member. `pkixFallback(enabled)` is public. Java gets flat fluent members, and the `sources {}` and `limits {}`
    DSL is `@JvmSynthetic`. There is one remote-settings source and one seed per `Revokt`, as upki has one
    `fetch_url` and Firefox one server pref. `clock` takes a kotlin.time clock or a `java.time.Clock`, and
    `timeSource` is internal. `close()` is #143's.
  - **Engines:** an injected engine may back only one `Revokt` ever, tracked in a weak identity set that `build()`
    registers last.
  - **Behaviour:** `CHANNEL_UNSET` counts the implicit bundled seed, so `Revokt {}` with no channel throws. The spec
    has no default channel, where Firefox picks one by platform. A local data source is a seed that is not `none()`
    after resolution. A cap below its constant throws at `build()`. The seven V and R codes join `DiagnosticCode`.
    `pkixFallback(false)` needs a policy that rejects `NO_ISSUER`.
  - **Source URLs:** `build()` refuses every URL the default fetch path would refuse, so a configuration can't build
    and then fail every sync. A source URL is `https` with a host read by `java.net.URI`, no userinfo, no query or
    fragment, and no port or one from 1 to 65535. A host outside a DNS name, such as one with an underscore, is
    refused, since public CAs issue no certificate for it. Messages name the field and the rule, never the URL,
    which may carry credentials. upki checks nothing, and Firefox accepts any server pref.
  - **`awaitData`:** one rule in Kotlin and Java: a negative duration, `INFINITE`, or one too long for a `Long` count
    of milliseconds throws. The default is an internal 2 s (§5.1), and the per-channel constants are 0.3.
- 2026-11-22 (lead, #127, PR #295; security review approved): `JvmPlatformTrust`, the PKIX fallback and the read
  fallback.
  - **Canonical subjects:** `CandidateIndex` takes `platformTrust::canonicalSubject` (no `customCanonicaliser`,
    which #226 removed).
  - **Bytes:** a fallback path's element 0 is the presented leaf's exact bytes, intermediates map by identity to
    their presented bytes, and the anchor is the snapshot's bytes read. `getEncoded()` is used only for a certificate
    outside the presented set, that is an AIA fetch. In 0.2 the read fallback serves only the anchor snapshot; the
    presented-chain wiring is 0.3.
  - **Internal in 0.2:** `PlatformTrust`, `PkixPathBuilderFallback` and `JvmPlatformTrust` are
    `@RevoktInternalApi`, with no public `platformTrust(…)` setter, under #221's first-consumer rule (as #139 did for
    storage). This changed from the builder's public proposal.
  - **Read fallback:** the §9.2 canon runs only on a `STRUCTURE` parse failure, keeps the `MAX_CERT_BYTES` checks
    and has a Jazzer target. An anchor whose `getEncoded()` throws is dropped. Firefox and webpki require strict DER
    and have no equivalent.
  - **Builder parameters:** the spec's list, otherwise JDK defaults (`maxPathLength` 5, as SunJSSE's
    `PKIXValidator` uses). A malformed presented non-leaf certificate is skipped rather than making the fallback
    null: a null fallback means `PLATFORM_ONLY`, which `DEFAULT` allows unchecked, while a found path still has its
    issuer checked. webpki and mozilla::pkix also skip a bad candidate.
  - **The snapshot fails closed:** an empty, null or throwing `getAcceptedIssuers()`, a null element, or no
    parseable anchor throws `IllegalStateException`, for #143's `start()` to catch (§4's start()-throws line is
    scoped [0.3]). The snapshot's sha256 is over the distinct bytes read, sorted.
  - **AIA** follows the JDK property, untouched and asserted, with a DIVERGENCES row (W16). Firefox preloads
    intermediates, and webpki never fetches. `defaultDelegate` is the default `TrustManagerFactory` algorithm and
    provider, so FIPS providers are respected.
  - **Review follow-ups:** a two-intermediate test pins the bytes mapping, which step 6 doesn't re-check. Keying the
    anchor memo on the snapshot's sha256 and guarding an empty JDK path are #296.
- 2026-11-23 (lead, #143, PR #298; security review approved after one fix): `Revokt.start()` and `close()`. Firefox's
  cert_storage loads CRLite on one serial background queue, and a query before the load gets `STATE_NO_FILTER`.
  `RemoteSecuritySettings.init()` is idempotent and logs its errors. upki's `Verifier::new` reads synchronously, fails
  on no data, and has no thread or close.
  - **Where the issue and the spec differ, the spec wins:** no `CLOCK_BEHIND` (§7.1) and no §6.5 self-check.
    `SEED_PAST_REJECT_THRESHOLD`, `UNVERIFIED_REJECTS_WITH_CLASSICAL_GAP` and `RULE_FLIPPED_THIS_MINOR` join
    `DiagnosticCode`, and nothing joins `WarningCode`. The pre-start trust-manager, storage-identity and factory-lock
    throws are 0.3.
  - **start():** returns `List<PolicyDiagnostic>` (§11), logs runtime `RevoktWarning`s at WARN, and has no
    `StartResult`. One private monitor guards it. A `start()` or `close()` called back from the start thread throws,
    from the CREATED check onwards, the anchor step included: the review found that a logger calling back during the
    anchor step could otherwise reopen a closed instance. `SEED_CHANNEL_MISMATCH` always throws. In the sole-seed
    `ENFORCE` configuration (`ENFORCE`, `NO_DATA` rejected, a seed configured), an unreadable, absent or failed
    un-activated seed throws.
  - **Loader:** one daemon `revokt-loader-<n>` thread, created at `start()`. The join is a bounded wait on the start
    task's latch, up to `awaitData`, and keeps the caller's interrupt. `pending` is cleared at the end of the start
    task. A store read the start task couldn't resolve is re-read by #147's first sync.
  - **close():** flips to CLOSED, stops scheduling, cancels the loader and waits for it with no bound, clears the
    reference, and calls `engine.close()` last. A non-fatal `engine.close()` throw is rethrown after every step,
    since try-with-resources and `use {}` attach it as suppressed; an earlier step's throw wins and carries the
    engine's as suppressed. A second `close()` is a no-op that waits for the first. Firefox's shutdown blocker also
    waits without a bound. The accepted residual is a seed opener that ignores interrupts, which `close()` waits for.
    The okio-backed sources end the load at the next read.
- 2026-11-23 (lead, #221, PR #301, under the maintainer's 2026-11-16 acceptance of audit B-F3 and B-F10): the 0.2
  public API is what a caller of `evaluate` reaches. A type, member or enum value is public once a public member
  produces or consumes it; until then it is `internal`, or `@RevoktInternalApi` where another revokt module uses it.
  webpki keeps a small public surface with private constructors and limits, and Firefox exposes no sync status.
  - **Sync types internal in 0.2:** `SyncResult`, `SyncOutcome`, `SyncFailure`, `RevoktWarning` and `WarningCode`
    go public with `sync()` in 0.3. This supersedes the "ship public" part of #2 (2026-11-05). upki's `FetchError` is
    public only because `fetch()` is.
  - **Construction:** output types have internal builders. `FetchRequest.Builder` stays `@RevoktTestingApi` for
    fetcher tests. Test factories come with a `revokt-testing` module in 0.3, since a new published module is
    ask-first.
  - **Storage:** `RevoktStorage` is `@RevoktInternalApi`, and `StoreLockedException` is internal. In 0.3 the store is
    a sealed type built by factories and never implemented by a consumer. The #229 store design is unchanged. upki
    takes only a cache directory, and Firefox uses the profile directory.
  - **Limits:** only the four caps the builder raises stay public (`MAX_FILTER_BYTES`, `MAX_JSON_BYTES`,
    `MAX_X5U_BYTES`, `MAX_CHANGESET_RECORDS`). `MAX_DEPTH` and the other limits are internal, and constants for
    features not built yet are gone.
  - **Removed until they have a producer:** `CredentialType` and `ExemptionContext.credentialType` (M5),
    `ChainSource.PRESENTED`, and three `Freshness` values (M2). `MozillaRemoteSettings` has no public getters.
  - **Internal for good:** `NoIssuerReason`, `ParseReason`, `KeyabilityClause` and `TerminalKind`, the DEBUG line's
    vocabulary. The 0.3 status counters are keyed by `PathReason`.
  - **Kept:** `Exemptions.and` and `or`. The engine seam's data types and `PathBuilderFallback` are
    `@RevoktInternalApi` with the seam, as #127 did for `PlatformTrust`.
- 2026-11-23 (lead, #147, PR #303; security review approved): polling Remote Settings on the `Revokt` loader.
  Firefox polls every 24 h with no jitter and relies on Push, with a 120 s floor. upki leaves scheduling to the
  packager.
  - **First sync:** it runs in the start task after the seed (§5.1), and `start()`'s join stays bounded by
    `awaitData`, so an instance with no seed can wait briefly for its first data. `pending` clears after it. The
    builder proposed a separate task; the lead kept the spec.
  - **Schedule:** after a poll that didn't fail, the next is 6 h plus U[0, 36 min), and the jitter only lengthens the
    wait. A `FAILED` sync waits exactly the backoff #131 persists. `INSTALLED`, `UNCHANGED` and `ROLLBACK_REFUSED`
    wait the longer of the interval and the backoff. Every delay is clamped to [60 s, 24 h]; the floor stops a
    `Retry-After: 0` loop. The target is computed on the wall clock and waited for on the monotonic one. A sync that
    writes nothing retries in 15 min, in memory only.
  - **Fail closed on an unresolved store read:** while the start task's store read is unresolved, each sync re-runs
    the seed load first and syncs only if that load installs. 0.3's stored-generation load must clear the flag
    (#287).
  - **Conditional requests:** `_since` and `If-None-Match` are sent only when the cursor equals the live
    generation's timestamp; otherwise the whole collection is fetched. This closes the #205 review's case of a 304
    keeping an instance on a fallback. Firefox keys `_since` on its own database, and upki sends
    `If-Modified-Since` only when its local manifest parses. *Superseded 2026-11-26 by #319 (PR #341), below.*
  - **STALE gate:** after the first completed attempt, the seed generation is republished with the gate open (§8).
  - **close():** it blocks the reschedule and interrupts the running sync. A sync waiting on a fetch ends `FAILED`
    and installs nothing, and one in prepare or activate is waited for (#143's residual).
  - **Failures never end polling:** the schedule catches every throwable and reschedules in a `finally`. A fatal
    error is logged at ERROR and then rethrown, since the scheduled task swallows it. A consumer clock that throws
    is a logged failure. The accepted residual is a fatal error inside the timer's own `schedule` call.
  - **Open for 0.3:** after a stale cursor, send the live generation's timestamp as `_since` instead of a full fetch,
    which keeps the delta path, as Firefox does. 0.2 fetches the whole collection.
- 2026-11-23 (#145, PR #306; supply-chain review approved): the seed writer and the `data/seed` build. Firefox ships
  no `cert-revocations` dump and takes CRLite on the first sync, and its periodic Remote Settings dump job verifies
  nothing, relying on human review. upki-mirror checks hash and size only and deploys raw files to Pages.
  - **No Maven for seeds yet (maintainer):** in 0.2 a seed is a `revokt-seed-<channel>` jar attached to a GitHub
    release with attestations, and an app bundles it itself. CONTRIBUTING §9 wanted a separate Portal account that
    owns only a data namespace, but `dev.revokt:revokt-seed-*` would have given that account's token the code
    namespace too, and neither reference publishes its data to Maven. Maven publishing, with its own namespace and
    account, is a later decision. The data licence is in the jar's manifest and a `META-INF/LICENSE-DATA` entry, so
    `verifyPomLicenses` gains no exception.
  - **Verify before write (lead):** the job fetches and verifies as a whole-collection sync does, builds, self-loads
    the archive in memory, then writes it through a temporary file in the same directory, so the final path holds
    either the previous file or the whole new archive. The signed `<ts>` must fall between the default CRLite
    `staleAfter` (3 days) before the version day and that day's end; the review added the lower bound. #149 is to add the
    check that a seed is no older than the last release's.
  - **The archive (lead):** `seed.json` is compact, first and stored, and `filterFormat` comes from the decoded full
    filter (the loader's cross-check is #305). A minimal writer of its own, since `ZipOutputStream` always writes
    data descriptors for deflated entries, gives a fixed entry order, a fixed DOS time and level-9 deflate. The bytes
    are reproducible for the same Temurin 21 build.
  - **Mixed encodings (lead, on the builder's evidence):** allowed, as the sync and the loader read each filter as
    served (the maintainer's #137 decision, as Firefox and upki do). Refusing them would fail the weekly job during
    a V3-to-V4 transition that a live sync installs. Only an encoding the engine doesn't list is refused.
  - **Placement (lead):** `buildSeed`, `SeedJob` and `SeedZip` are internal code in revokt-engine, reached only by an
    explicit call. The job's entry in `data/seed` ships nowhere. The version is `-Prevokt.seedVersion=YYYY.MM.DD`,
    and the attachment base is discovered as a live sync does.
- 2026-11-23 (lead, #149, PR #310; supply-chain review approved): the weekly seed release job, `release-seed.yml`,
  so cooling's `release` prefix covers it. Firefox's periodic Remote Settings dump job runs weekly, verifies nothing
  and gates on human review, and its client ignores an older changeset. upki-mirror builds with `contents: read` and
  deploys with `pages` and `id-token`, with no rollback check or attestation.
  - **Off by default:** a release happens only from main, in the `seed-publish` environment, with
    `SEED_PUBLISH_ENABLED` true and the `dry-run` input false. The maintainer creates the environment and sets the
    variable last; a missing environment would be created with no protection.
  - **One release per run:** the tag is `seed-YYYY.MM.DD`. The draft is created through the API, and its id is kept
    for the upload, the read-back and the publish, with `make_latest=false`. The assets are read back and checked
    against the smoke-loaded jars (`sha256sum -c --strict`) and both attestations, each attached bundle included,
    before publishing. The tag is re-checked before attesting, and its commit is compared with `GITHUB_SHA` after.
  - **Attestations:** SLSA provenance, also attached as `.intoto.jsonl`, plus a seed predicate. The predicate holds
    the signed `<ts>`, each placed record with its hash, the zip's hash and the JDK build, and its type is a document
    in the repository, not `revokt.dev`, which nothing shows the project owns. The predicate is the build's own
    account of its output; what stays independent is Mozilla's content signature, which every load checks.
  - **Monotonic floor:** the job verifies the last published seed's attestation (signer workflow, source ref main)
    and refuses an older `<ts>`. An equal one skips the publish, the first release passes, and a missing or
    unverifiable previous release, or a seed tag without a published release, fails closed. The Gradle re-check of
    the previous content signature is #308, and the smoke load against the oldest published minor is #309.
  - **Runner:** the JDK is a Temurin 21 tarball pinned by SHA-256, with Gradle's auto-detect off. Each job has
    harden-runner egress in block mode. The schedule is Monday 05:41 UTC, with concurrency per ref and no cancel.
- 2026-11-24 (lead, #144, PR #316; independent review approved after one fix): the §9.1 walker fuzzer, the 0.2
  release gate. Neither webpki nor mozilla::pkix fuzzes path building: their fuzz targets are parsers. Both
  unit-test budget exhaustion and detect loops by subject plus SPKI.
  - **§9.1 follows the code after #226:** P2's Budget clause is stated on the decision's keys. P3's limit hit is any
    walk `Budget` or any `PATH_BUDGET_EXCEEDED`, `FALLBACK_LIMIT` included. P8's clauses hold at the decision level
    only up to `FALLBACK_MAX_PRESENTED` (8) presented certificates. `DropIntermediate` gives `NO_CANDIDATE` only
    when the leaf's own issuer is dropped, and `UNANCHORED` otherwise.
  - **The certified bridge:** a mutation holding an anchor-certified CA key can complete a broken path. P3 excludes
    that case only when the honest walk is `NotFound` and the mutated walk is `Found`, and then asserts that the
    verdict follows the CRLite answer for the honest key, which P2 requires. Such a key holder can mint a fresh leaf
    anyway (§10 residual 15).
  - **Residual 16 (corrected by the review):** `FALLBACK_MAX_PRESENTED` counts presented certificates, while
    mozilla::pkix's `MAX_SUBCA_COUNT` caps the path it builds. So a padded chain, with more than 8 presented and a
    short real path the walker can't build, is accepted by Firefox and rejected under `DEFAULT`, even on a
    trust-manager binding. Example causes are an unsupported algorithm, a missing intermediate that Firefox's preload
    would supply, or a misclassified issuer. It follows from #226's limit, and the lead's first comparison, which
    called revokt narrower, was wrong.
  - **Tests only:** the stronger P6 (verifications equal depth + 1) and P2's issuer-identity clause stay out of the
    spec. The gate record is the nightly fuzz batch after merge.
- 2026-11-24 (lead, #322, PR #323; independent review approved after one fix), from the maintainer-authorised fuzz
  triage of GHSA-m4x5-jjf8-642j: an x5u host, and a Builder host, is a run of labels that each start and end with a
  letter or digit, and the last label starts with a letter. The old rule let `java.net.URI` read no host where the
  oracle read one (for example a label of `-`). The fetcher still reached the checked host, so the fix restores the
  invariant that every JDK parser reads that host.
  - **References:** webpki also refuses a leading or trailing hyphen, and refuses only an all-numeric last label.
    WHATWG URL parsing, and so Firefox, accepts more. The binding parser is `java.net.URI` (RFC 2396 `toplabel`),
    which `JdkHttpFetcher` uses, so revokt follows it.
- 2026-11-24 (maintainer, #321, PR #324; independent review approved after one fix): "only report it if its an
  actual issue and not a failure to run the tests".
  - **The memory limit:** the fuzz job's `-rss_limit_mb` goes from 1024 to 2560, ClusterFuzz's libFuzzer
    `DEFAULT_RSS_LIMIT_MB` and OSS-Fuzz's documented 2.5 GB per-input limit. It is not a default for every engine:
    OSS-Fuzz's Centipede uses 4096. Kover is off while fuzzing. The 16 drafts of 2026-11-21 and 2026-11-22 were
    RSS-limit OOMs at the JVM's own footprint (1107–1804 MB) and were closed as not vulnerabilities.
  - **Reproduce before filing:** the job replays the empty input as a control, then each crash, timeout or OOM input
    alone. An advisory is filed only for an input that fails again while the control passes, as ClusterFuzz re-runs
    a crash to check that it reproduces. Anything else is a run failure: a red job and sealed logs, no advisory.
  - **Gate record:** the 0.2 walker-fuzzer gate (#144) passed in the nightly runs of 2026-11-24 (45412705975) and
    2026-11-25 (45624833898) on 4714c68, all 17 targets clean, `WalkerFuzzTest.walk` included.
- 2026-11-25 (lead, #305, PR #326; independent review approved, two nits applied): a seed's `seed.json`
  `filterFormat` must name the decoded full filter's encoding, else `SEED_UNREADABLE`, like every other header check.
  A delta may still be in another listed encoding (#137). The check runs only on a seed that installs, as the existing
  listed-encoding rule does. The writer derives the field from the same full, so the seeds we write are unchanged.
- 2026-11-25 (lead, #296, PR #327; lead review): three fail-closed checks on the PKIX fallback's output. The anchor
  memo is keyed on the snapshot's id and `sha256`, so a hand-built snapshot that reuses an id is parsed again. The
  JDK's empty path for a target that is itself an anchor is no path. Each element's issuer must equal the next
  element's subject under `X500Principal` equality. webpki and mozilla::pkix build linked paths by name; the last
  check holds the JDK's builder to the same shape.
- 2026-11-25 (lead, #308, PR #328; independent review should-fix, then approved): the weekly seed job re-verifies
  the previous seed release before it trusts its `<ts>` as the floor, as Firefox's `RemoteSettingsClient`
  `_importChanges` re-verifies its local data (`verifySignatureLocalData`) before it ignores an older changeset.
  - **What it checks:** only what does not depend on the format, so a `seedFormat`, schema or `filterFormat` change
    cannot strand the job. That is `seed.json`'s `channel` alone, the content signature with the archived x5u
    validated to the pins, validity at the signed `<ts>`, and the canonical payload, through the engine's own
    functions (`verifySignedRecords`, shared with the seed loader). The review found that the first version's full
    seed load would have made every earlier release unreadable after such a change.
  - **Divergences from Firefox:** a previous release that does not verify fails the run, where Firefox imports the
    older data ("we prefer stale data over corrupt/tempered"). Validity is checked at the signed `<ts>` against the
    archived x5u, where Firefox checks at `Now()` against an x5u it fetches.
  - **Signer scope:** the content signature names no collection, since one signer serves every security-state
    collection, and Firefox binds the collection only by the URL it fetched. The floor adds no schema check. The
    attestation binds the jar to the job that fetched `cert-revocations` and schema-checked it in its full
    self-load, and a compromised publisher could only raise the floor, which stops publishing.
  - **Also:** the job's `GH_TOKEN` is kept out of Gradle. A pin rotation makes the previous release unverifiable,
    and recovery is then the maintainer's.
- 2026-11-25 (lead, #287, the implementation of the #229 design; spec PR first, per CONTRIBUTING §1.2): the store
  becomes content-addressed: blobs named by their signed SHA-256, one generation file named by its own SHA-256, and
  `current` as the one write that makes a generation live (§6.5; DIVERGENCES T1, T2). Q1 to Q3 stand as recorded for
  #229 above.
  - **Moot:** #200 (a same-`<ts>` re-sign reused): a re-signed collection is another file. #205 and its rounds 3 and 4
    (an orphan completed afresh; `reopen` failing closed): nothing is reopened. #236 and #242 (directories held beside
    a malformed pointer): nothing is rewritten, and prune deletes nothing there.
  - **Widened:** #201's re-hash before reuse covers every blob, deltas included. **Restated:** #235 (the adopt scan,
    now over generation files; "a (b) load never prunes or deletes", now every seed load at `start()`). **Kept:** #249
    (the served generation is the first `previous` candidate), #256 (no prune after a heal flip), #209 and #224.
  - **Prune beside an unreadable pre-install pointer (B2):** a sync install whose pointer read `Found` before it, but
    named a generation that fails Load's steps 1 and 2, does not prune; the next install over a pointer that loads
    does. This diverges on purpose from upki, which reads the old manifest with `.ok()` (`fetch.rs:64` at `9821cce`),
    and from Firefox, which clears local data that fails verification (`RemoteSettingsClient.sys.mjs:1286-1291` at
    `cac25a6`), under the fail-closed rule (#230). A newer generation file is kept when it passes steps 1 and 2 (B3).
  - **Start (B4, B5):** the recovery chain decides on each candidate's `<ts>` against the seed's and loads only the
    winner in full, as Firefox compares its local timestamp with the dump's before importing (RSC:460-461, 520-546).
    Residual: a stored generation older than the seed is not decoded at `start()`. The sole-seed `ENFORCE` check reads
    the pointer and its `live` file through steps 1 and 2 on the calling thread, as Firefox's `hasLocalData` reads only
    a timestamp.
  - **The generation file (B6, B8):** an optional hashed `seedFormat`, present exactly for a seed's generation, so
    `DataState.seedFormat` survives a restart. A file over `maxJsonBytes` + 64 KiB is `FAILED` with `STORE_FAILED`,
    counted, with a `WARN` naming the cap; the cap at read is the reading process's. Neither reference caps local state.
  - **Install and sync (B7, B9):** the load-back re-reads and re-hashes the file and every blob and keeps the index
    built from the same bytes, so an install still decodes its filters once beside the index build (Firefox's
    cert_storage loads a filter back once after writing it, `cert_storage/src/lib.rs:513-517`). The delta base is the
    served generation's file, re-read at each sync, as Firefox merges over what it serves (RSC:740-748).
  - **Kept as §8 states (B10):** a `SKIPPED`/`BACKOFF` sync is an attempt and opens the seed's `STALE` gate. Firefox's
    backoff records no check (`remote-settings.sys.mjs:381-396`), but opening the gate only lets `STALE` fire.
  - **Deferred to #330 (B11 to B13):** `JvmStorage` (directory fsync at open and on create, the temp sweep, the lock,
    `store.version`) and the in-memory entry points; #287 writes the §3 and §4 text only. `RevoktState.readOnly`,
    `READONLY_POLL_INTERVAL` and the `STORE_LOCKED` sync result go. §6.4's `MAX_CHANGESET_RECORDS` reads 1,024, and
    §6.3's reserved attachment names stay (B14).
  - **Process (B1, B15):** the spec lands first, as its own PR (CONTRIBUTING §1.2; the issue had it in the code PR), then
    the codec, the store switch and the `start()` recovery chain, each on `main`. The air-gapped `sync()` of a replaced
    seed prunes as a sync install does, which is spec text only until that path is built.
  - **From the independent review of the spec PR:** a damaged pointer counts `storeFailures` and raises no warning, and
    `STORE_UNREADABLE` means only that the instance runs in memory (the lead's option (a); neither reference warns
    there). Any read prune makes that throws stops it with nothing deleted. A start counts each fault once: the adopt
    scan passes over a generation the chain already failed to load. A generation file reads only as its own canonical
    bytes, so a change to the canonical encoder's output is a `store.version` change.
- 2026-11-26 (lead, #287, PRs #332, #335 and #336; each with an independent review and fix rounds): decisions from
  building the store switch and the `start()` recovery chain.
  - **Load time (B16):** `start()`'s load runs over §6.4's columns: 25 ms on `compat` and 43 ms on `default` under
    HotSpot's JIT, about 1.5 to 2.5 times the estimate, with ART not yet measured. As design note §16 planned, the
    fallbacks are a follow-up, #333, which measures on ART first. §6.4's numbers stay until then. upki persists
    `index.bin` (`fetch.rs:337-376`, `index.rs:69-80`); Firefox keeps no index, and each filter carries its own coverage
    (cert_storage `lib.rs:521-534`).
  - **The repairs (B17):** an `UNCHANGED` whose pointer does not name the served generation re-flips it, to
    `{live: served, previous: by the candidate rule}`, after Load's steps 1 to 3, and never prunes. When the served file
    fails those steps, the sync heal-installs the collection as served instead: it reuses every blob that re-hashes and
    publishes epoch + 1 with the same `generationId`, since a re-signed collection can rebuild to another file name.
    Both report `UNCHANGED`, since what is served does not change, and both write the cursor, `lastVerified*` and the
    watermark as the install of that `<ts>` does. A repair that fails is `FAILED` with its own failure. Firefox
    re-imports a full changeset when its local data does not verify (RSC:1286-1300); upki has no pointer.
  - **Counting and the pointer (B18):** a store fault is counted once, where it is first found, at sync and at
    `start()`. A sync records the delta-base fault, the step-3 fault of a re-flip that falls through, and the blobs of a
    generation it rewrites. A `start()` counts across all its passes with one shared fault set, and `recover` returns
    the count. A pointed `UNCHANGED` rewrites `updater.json` when the cursor or the watermark is behind `<ts>`, which
    repairs a crash between the flip and that write. A re-flip never replaces a pointed `live` that is newer than the
    served generation and passes steps 1 and 2, so the pointer never moves back. Neither reference keeps a pointer:
    this follows revokt's no-rollback rule.
  - **The `start()` chain (B19):** a `previous` older than the seed is never decoded at `start()`; it is left to the
    seed. When the pointed `live` fails to load, the seed's install lowers the watermark to the seed's `<ts>`, as
    Firefox's floor drops after a dump import (RSC:1292-1300) and as §6.5 says. Residual: a one-off engine refusal at
    start lowers the floor too, and once #330 lands that persists. The chain's bound is the number of stored
    generations plus 2, and running out leaves the read unresolved, which fails closed. Once the chain has served a
    `previous` not older than the seed, the seed's second pass still runs rule (b), but over the other generations
    only. Residual: in that case `previous` and the adopted generation are both decoded, which needs a failed flip and
    rolls nothing back. The review's other start points are follow-up #338.
  - **From the independent review of #337 (#334):** `close()` waits for the loader thread itself to exit as well as
    the pool's termination, which the JDK signals first. The remaining wait on consumer code is the JVM's
    uncaught-exception handler, after a JDK-internal `Error` kills the worker. That is a residual, since no revokt
    path reaches it.
- 2026-11-26 (maintainer, #338): B19 is confirmed as built. When the pointed `live` fails to load at `start()`, the
  seed's install lowers the watermark to the seed's `<ts>`, as Firefox's floor drops after a dump import
  (RSC:1292-1300). Once the store is durable, that lowered floor persists. This is the intended behaviour, not a
  residual.
- 2026-11-26 (lead, #319, PR #341; independent review, one fix round): `_since` is the served file's own `<ts>`, read
  from the same file that is the merge base. It is sent only while that file loads, its `<ts>` equals the snapshot's
  live `<ts>`, and the pointer names it. The `updater.json` cursor is never sent, so the #205 hazard cannot occur.
  `If-None-Match` is sent only while `updater.json`'s cursor and watermark are at or past that `<ts>`, so an unsigned
  304 never stands in for B18's repair, which is written only from a changeset that verified. The first sync after
  every seed install is now a delta. Firefox keys `_since` on its local data's own timestamp, the dump's after an
  import (RSC:744-769, 1164). upki keys `If-Modified-Since` on its local manifest (`fetch.rs:64-80`). The review's
  live check found that production answers `If-None-Match` with a 200 and no `ETag` (Appendix A).
- 2026-11-26 (lead, #330, PRs #342 and #344; independent review of each, with three fix rounds on #342 and two on
  #344): the durable `JvmStorage` and its start integration. The public surface is #340.
  - **Durability:** stricter than both references, neither of which fsyncs (upki `fetch.rs:430-447`; Firefox's rkv
    SafeMode writes and renames with no fsync). Each write goes to a temp file, which is forced, atomically renamed
    and followed by a fsync of its parent. Every directory under the root is fsynced at open, and the parent of each
    directory created. The Windows rename retry is bounded at 1 s.
  - **Temp files:** `<segment>~<32 hex>`, with no pid, since `ProcessHandle` is missing from the API-26 signature.
    `lock()` sweeps them before `store.version` is read.
  - **The lock:** `FileChannel.tryLock` on `.lock`, tried every 100 ms for 1 s and never deleted, as Firefox keeps
    `.parentlock` (`nsProfileLock.cpp:206-241`). A second process runs in memory with `STORE_LOCKED`, where Firefox
    refuses to start. `.lock` is checked with lstat and must be a regular file, then opened for reading and writing,
    which closes a FIFO race. The in-process lock table and the store registry key on `.lock`'s `fileKey()`, so a
    hard link or a bind mount cannot drop a held lock.
  - **Trust:** the root's mode, then its owner, are checked before the probe is written. Every directory under the
    root follows the same rule and is checked before it is swept. Any other failure in `lock()` is
    `STORE_UNREADABLE`. Below the root's real path no link is followed, and a read through one throws (#236). Keys
    are lowercase only. A directory that holds a `.lock` is another store: `names()` and the sweep skip it, and every
    read, write or delete through it throws. Residual: a check-then-use window that only the owner, or the group
    under `OWNER_OR_GROUP`, can race.
  - **`store.version` (fail closed, #230):** an empty root gets `1` written. A non-empty root with no
    `store.version`, or with one that is malformed or cannot be read, is `STORE_UNREADABLE`, and the store is left
    untouched but for `.lock`. The spec's earlier rebuild would have deleted files in a caller's directory that is not revokt's.
    Higher is `STORE_NEWER_LAYOUT`, then `IN_MEMORY` or `REBUILD`. Lower is `STORE_MIGRATED`. A rebuild deletes the
    other keys first and writes the version last, so an interrupted rebuild runs again at the next start. Firefox
    opens a newer IndexedDB as unusable and reads its dump (IDB:189, RSC:571-597). upki's `index.bin` magic refuses
    an unknown version without deleting anything (`index.rs:84-94`).
  - **Lifecycle:** once the loader has started, only `close()` releases the store, after the loader has stopped. If
    the loader's stop throws, the lock stays held. 0.3 has no read-only, promotion or storage-fallback modes: the
    in-memory fallback covers a second instance.
  - **CI:** every test's result is printed in the CI logs (#343), so a matrix leg shows which tests ran. Builders
    never pass `--no-verify` (#345).
- 2026-11-27 (maintainer, PR #348; independent supply-chain review, two nits): Gradle 9.7.0 → 9.9.2. Kotlin stays at
  2.4.21, the latest stable. Gradle Inc.'s new signing subkey `F3FF33E96F18AA62DD580F9651FBF517CE6D6B80` (primary
  `EA96F38569C044AAEF7FCF732887F479B0B9771A`, created 2026-08-14) is trusted, scoped to
  `org.gradle.kotlin:gradle-kotlin-dsl-plugins:6.7.13`. The old key `1BD97A6A…` is revoked as superseded (gradle/gradle
  `KEYS.md`). Because the trust is version-scoped, each later bump that moves `kotlin-dsl` needs a new version entry and
  a key check. The build runs ahead of KGP 2.4.21's tested range, whose newest is 9.7.0, with no compatibility warning;
  revisit at Kotlin 2.5. The stale 6.7.3 and Kotlin 2.4.0 verification entries are pruned, after a regeneration from
  empty on both versions. 9.9.2's embedded Kotlin 2.4.21 also removes the Kotlin 2.4.0 behind Dependabot alert #1,
  which #275's constraint had already fixed.
- 2026-11-27 (maintainer, #338, PR #350): the start chain's three follow-ups from #336's review, each as the builder
  recommended. upki is `9821cce`; Firefox is `cac25a6` (CS = `security/manager/ssl/cert_storage/src/lib.rs`, RSC =
  `services/settings/RemoteSettingsClient.sys.mjs`).
  - **A restart is a first start for the seed's age (B24):** when the start task's store step ends on a stored
    `fromSeed` generation (`live`, `previous` or adopted), its signed `<ts>` becomes the seed's for
    `SEED_PAST_REJECT_THRESHOLD`, which `start()` returns and the loader logs, as for a seed this start installed. It
    is taken once, from the generation the step leaves served, so a step that serves a seed `previous` and then adopts
    a synced generation reports none (r350's review). A stored synced generation does not trigger it; `STALE` covers it.
    Firefox checks CRLite's freshness on every query against the stored time of its last update (`is_crlite_fresh`,
    CS:464-483, 10 days), so a restart behaves as a first start, and it has no start-up diagnostic. upki has no age
    rule and logs the manifest's `generated_at` at `INFO` (`upki/src/revocation/mod.rs:124-141`).
  - **The unresolved re-read backs off (B25):** while the start task's store read stays unresolved, each sync's re-read
    that leaves it so waits §7.1's computed failure backoff over the consecutive re-reads, 15 min doubled up to 6 h,
    held in memory and reset once the read resolves. Every retry is still a full re-read, and nothing is remembered
    between them, so no candidate is skipped on remembered state. Remembering the failures was rejected: a blob that a
    failed seed install rewrote, or an engine refusal that was transient, would then fall to the seed, whose install
    lowers the floor (B19). It does not wait for #333: it bounds the number of re-reads, not their cost. The trade:
    nothing is live while the read is unresolved, so `NO_DATA` rejects, and a transient fault heals up to the current
    wait later (at most 6 h; a restart re-reads at once). Firefox reopens a cert_storage database that fails to open on
    every query (`get_security_state!`, CS:1288-1300), decodes a filter once per open (CS:216-250, 521-533) and never
    retries one that fails to decode until the next download (CS:527-532); its sync, whose local read throws, fails
    (RSC:743-751) and is retried at the next 24 h poll. upki keeps no retry state and re-reads the index and every
    filter it consults on each check (`index.rs:69-155`, 311-323).
  - **The sole-seed `ENFORCE` cost stays (B26, B5):** a `live` that passes Load's steps 1 and 2 on the calling thread
    but fails step 3 or 4 on the loader, beside a seed that does not install, leaves no generation after `start()`
    returned. The start task logs one `ERROR` naming `SEED_UNREADABLE` and `NO_DATA`, also when its store read threw
    and stays unresolved (r350's review: `NO_DATA` rejects there too), but not while `close()` interrupts the loader.
    With 0.3's `state` it is
    `SEED_UNREADABLE` on `RevoktState.warnings` beside `generationId == null` and `pending == false`, the triple
    `NO_DATA_AT_FLIP` already reads, so no new code value. With a fetching source the first sync installs the collection
    and heals it. Reading steps 3 and 4 on the calling thread (undoing B5 and B16) and a JVM `start()` that throws after
    its join (after the flip, and Android does not join) were rejected. upki matches: `rustls-upki`'s
    `ServerVerifier::new` reads only `index.bin`'s header and fails only on `NoData` (`rustls-upki/src/lib.rs:70-75`),
    and a damaged filter fails each check as a hard error (`index.rs:311-323`, `lib.rs:132-136`). Firefox drops a
    filter that does not decode with no log (CS:527-532) and answers `STATE_NO_FILTER` (CS:557-563).
- 2026-11-28 (maintainer, #333): `start()`'s load after the store switch, measured on ART and brought down. upki is
  v1.0.1 `9821cce`; Firefox is main `86c8e13` (CS = `security/manager/ssl/cert_storage/src/lib.rs`).
  - **Load reads coverage alone (B27, fallback (a) of design note §16):** on an API 31 arm64 emulator, #287's Load,
    which decoded every filter for `buildIndex` and again in `prepare`, ran 86 ms cold and 360 ms interpreted on
    `compat` and 112 and 621 ms on `default` (the 2026-11-27 measurement: 91, 370, 113 and 631; before #287 61, 199,
    76 and 338), over §6.4's estimate. Load at `start()` now reads each filter's coverage alone, the first field after
    the 2-byte prefix in v3 and v4, through a coverage-only read in revokt-clubcard's Apache glue that reuses the
    port's v4 `CRLiteCoverage` reader and the v3 reader's coverage map, so no MPL file changes. It has its own Jazzer
    target, `ClubcardCoverageFuzzTest`, differential against the whole decode. `prepare` is the one decode; a body
    that does not decode past its coverage fails there, in the `Failed` arm `serveStored` already had, and the chain
    falls down as for a failed load. The result, the same shapes measured interleaved with the old Load: `compat` 73
    ms cold, 28 warm, 190 interpreted; `default` 86, 51 and 332. §6.4's load columns are these numbers, labelled
    emulator lower bounds. HotSpot's JIT total drops from 25 to 18 ms on `compat` and 43 to 31 ms on `default`
    (`StoreLoadTimeTest`). Fallback (b), storing `index.bin` as a blob the generation file names, was not taken, so
    `index.bin` stays derived. upki persists an unhashed `index.bin` built by fully decoding each filter at fetch
    (`Index::write`, `index.rs:156-235`; `PlanStep::SaveIndex`, `fetch.rs:337-376`) and has no start load:
    `Store::check` (`mod.rs:75-78`) reopens `index.bin` per check, reads its header (`index.rs:69-150`) and decodes
    only the filters that match (`index.rs:245-350`). Firefox keeps no index: `Filter::load` decodes each filter once
    (CS:132-149) and reads coverage from the decoded filter at query time (`in_universe(clubcard.universe())`,
    CS:151-178), loading the full filter at database open (CS:247, 520-533) and the deltas on a background queue
    (`BackgroundReadDeltasTask`, CS:1084-1135, 1152-1167); its per-filter SHA-256 is for reporting only
    (`get_crlite_filter_hashes`, CS:335).
  - **The adopt scan and installs decode whole (B27, adopt scan (i)):** the adopt scan writes `updater.json` and flips
    `current` before anything is prepared, so it keeps the whole-decode `buildIndex` and never adopts a generation
    `prepare` would refuse. Installs (sync, seed, heal) keep it too, so this binary never writes a generation whose
    filter does not decode; such a filter fails a sync with `FILTER_UNREADABLE`, and a seed with `SEED_UNREADABLE`,
    before the generation file is written, as upki builds its `index.bin` only from filters it has fully decoded
    (`index.rs:156-235`).
- 2026-11-28 (maintainer, #354): the 0.3 scope of the trust manager, sync and state, D1 to D7 of #354, which #356 to
  #362 build. upki is `9821cce`, where the `rustls-upki/src/lib.rs` and `upki/src/revocation/mod.rs` line numbers
  below were checked for this entry. The Firefox points marked "fetch summary" come from summaries of mozilla-central's
  `RemoteSettingsClient.sys.mjs` and `remote-settings.sys.mjs`, with no line numbers, and were not read as source.
  - **The trust manager is 0.3 scope (B28, D1):** §11's 0.3 row names `RevoktTrustManager` (flow steps 0 to 4),
    `RevoktCertificateException`, `sslContext()`, the enforcement and policy setters, `resetState()`, listeners and
    `refreshAnchors()`, which §4 already specified and no row scheduled. Nothing is cut and §4's text is unchanged.
    upki ships its check as a rustls `ServerCertVerifier` (`ServerVerifier`, `lib.rs:23, 140`, with the check at
    `:92-137`), the trust-manager equivalent, and Firefox checks CRLite inside its certificate verifier: both make the
    verifier the product, not a separate evaluate call.
  - **The clock-behind fixture reference is dropped (B29, D2, option (a)):** §11 and `test-plan.md` no longer cite a
    [0.3] content-signature item "the restart with the clock behind", which #273 deleted with `clockBehind`.
    Restating it as a plain row (b) was declined for the smaller core. Neither reference reads the local clock against
    signed data (DIVERGENCES S11): upki only logs the manifest's `generated_at` (`mod.rs:124-141`), and Firefox
    compares only the x5u validity with `Now()`.
  - **`start()` returns `Unit` from 0.3 (B30, D3, option (a)):** its diagnostics are only on `state.diagnostics` and
    `state.warnings`. Keeping `List<PolicyDiagnostic>` (b) would duplicate `state`; 0.x allows the break and nothing is
    released. Firefox's `RemoteSecuritySettings.init()` returns nothing, is idempotent and logs its errors (#143,
    above). upki's `ServerVerifier::new` returns a `Result` and fails only on `NoData` (`lib.rs:44, 70-75`; B26).
  - **A `sync()` during a sync gets that sync's result (B31, D4):** like Firefox's `maybeSync()`, a `sync()` that
    arrives while a sync is running gets that sync's `SyncResult`, and no extra sync is queued. This replaces the
    draft's "at most one pending" recommendation, which queued one more sync after a running one. The spec reads
    "queued or running", the start task's first sync included, so a call that finds a sync waiting joins it too (#356's
    row: a `sync()` during the start task returns after it, with one fetch). The trade: a call that arrives after a
    sync started gets a result that may not reflect data changed since (a replaced seed, #363). Firefox (fetch
    summary): `RemoteSettingsClient.maybeSync()` returns at once with a warning while `_syncRunning`, so a second call
    is neither queued nor awaited, and `pollChanges()` has no in-progress guard. revokt differs in one point: the
    joining call returns the running sync's `SyncResult`, where Firefox's dropped call has no result of its own. upki
    has no in-process sync: `upki fetch` is a CLI the packager runs, and two fetchers on one directory race
    (DIVERGENCES T4).
  - **`Evaluator.evaluate` counts and emits nothing (B32, D5, option (a)):** `Revokt.evaluate` and the trust-manager
    paths count, emit and run the shadow policy; counting both (b) was declined. rustls-upki has no counters, status,
    callbacks or report-only mode (fetch summary of `lib.rs` on `main`): at `9821cce` its `Policy` is `{missing_data,
    cert_not_covered, cert_has_no_scts}`, each an `Outcome` of `Allowed`, `TreatAsRevoked` or `Error`
    (`lib.rs:243-287`). Firefox records CRLite results as telemetry inside its certificate verifier, so every
    verification it performs is counted; which callers that includes was not verified.
  - **`onStateChanged` is conflated and distinct (B33, D6, option (a)):** it is delivered as the `StateFlow` is, so a
    slow listener gets the latest state and may skip intermediate ones, and the Java and Kotlin views agree; every
    state in order through a queue like the event ring (b) was declined, since `state` holds slow-changing fields
    only. upki has no listener. Firefox (fetch summary) sends observer notifications per poll
    (`remote-settings:changes-poll-start`, `remote-settings:sync-error`, `remote-settings:broken-sync-error`,
    `remote-settings:changes-poll-end`) and a per-client `sync` event `{current, created, updated, deleted}`, emitted
    only when listeners exist; its state is read on demand through `RemoteSettings.inspect()`, not pushed. Events per
    change and state on request is closest to (a).
  - **`RevoktStatus.unsignedData` is removed (B34, D7):** every generation is Mozilla-signed since #218 cut the MIRROR
    and SYSTEM sources, and under the first-consumer rule (#221) a member nothing produces is not public. A future
    unsigned source adds it back, which is not a break. Firefox serves only signed Remote Settings data; upki's mirror
    data is unsigned, and it has no such counter.
