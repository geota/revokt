# revokt decision log

Every maintainer and lead decision on an ask-first question, newest last, with the references (upki and webpki, and
Firefox) each was compared against. Spec text follows from these through the next spec revision. Moved here from the
maintainer's working notes on 2026-11-16 (#217); earlier entries keep their wording, except where noted below.

**Conventions.**
- Numbers such as "#1" and "A1" in the first sections are items of the 0.2 plan (its ask-first list and its critique),
  which is not in the repository.
- "The 2026-11-16 design audit" is the Fable 5.2 audit of decisions, architecture and process, tracked in #230.
- Divergences from the references are in [DIVERGENCES.md](DIVERGENCES.md).
- Rewritten on the move: entries about another project's security findings are stated in generic terms, and the
  reproduction detail of a CI hardening finding is summarised.

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
- `endDepth`: null on a completed walk; set only on Budget, and 0 on the step-3 cut. A `maxDepth` in WalkStats was considered and dropped: nothing reads it, and upki/webpki report no depth either.
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
- Q15: validate every mirror and index filename per C2SP filename rules before it is used, whatever the reference does.
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
- 2026-11-15, #185 (maintainer): after a security review found that code running in the fuzzed JVM could influence the later token step through the runner's environment files, the fuzz job runs Gradle and the fuzzer as an unprivileged second user. That user can't write $GITHUB_ENV, $GITHUB_PATH, $GITHUB_OUTPUT or the committed scripts, and has no sudo. It stays one job. Neither reference runs fuzzing in CI with a write token.
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
- 2026-11-16 (maintainer, #110): trust PGP key CE4B22DFBAE4458F43D3D5D3AD228764EA2E4BE9 (Toast Open Source, rsa4096, 2023-01-05), scoped to com.toasttab.android:gummy-bears-api-26, for animal-sniffer in revokt-jsse. The lead verified it on keyserver.ubuntu.com, with a good signature on the Maven Central 0.16.0 POM; the same key signed 0.15.0.
- 2026-11-16 (lead, #235): a seed load with a malformed or unreadable pointed meta.json gets the same no-delete treatment as a malformed pointer. A store fault is counted once, by Install.previous, not again by the loader. An archive over SeedArchive.MAX_BYTES (256 MiB) is SEED_UNREADABLE, a source fault, not a store failure.
- 2026-11-16 (lead, #242 from r242): beside a malformed pointer, a directory whose meta.json is present but malformed is held (never rewritten or deleted; STORE_FAILED at that <ts>, healed by the next <ts>), matching #178 beside a valid pointer. Only an absent meta.json is staged. A running loader offers liveDirectory() as the healed pointer's previous, when it qualifies, so its fallback survives the heal; a fresh loader's healed pointer has no previous.
