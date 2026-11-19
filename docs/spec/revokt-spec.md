# revokt: a pure-Kotlin CRLite engine with JVM and Android bindings, growing into a WebPKI client-policy library

Status: **draft spec, revision 60** · Target: JVM 17+ and Android API 26+, Kotlin 2.3+ consumers · Date: 2026-11-19

> **Name: `revokt`.** Maven group `dev.revokt`, GitHub repository under the maintainer's own account, domain
> `revokt.dev`. `revokt.com` is an unrelated SaaS and the GitHub handle `Revokt` is taken; §13 gives the
> disambiguation rules that follow from that.

**This file is the normative core.** It states the behaviour of the current milestone (0.2) and what the next one
builds on. Its companions:
- [test-plan.md](test-plan.md): §9, the fixture rows, §9.1 fuzzing and the walker properties, §9.2 the differential
  parser oracle (normative);
- [references.md](references.md): Appendix A, the verification log;
- [CHANGELOG.md](CHANGELOG.md): what each revision changed, and why;
- [`docs/design/`](../design/): non-normative notes for later milestones and cut features, each promoted into this
  file when its milestone starts;
- [`docs/decisions/`](../decisions/): the decision log and the divergences from the references.

From revision 59, a new sentence enters this file only with a fixture id or a test name that checks it. Rationale goes
to an ADR, and pseudocode for an internal function gives way to the code and its property tests (CONTRIBUTING §1).

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
   `upki-revocation@v1.0.0` conformant: the store keeps every generation as a directory image any C2SP reader accepts.
2. **Authenticated data only.** Every generation the engine installs is Mozilla-signed, from the feed or from a seed
   whose signed records are re-verified, so a generation's age is the only data-quality dimension.
3. **Additive-only rejection.** The platform verdict runs first and is final for acceptance. revokt
   never rejects because of its own failures (`NO_ISSUER`, `PARSE_FAILED`,
   `ENGINE_ERROR` in `DEFAULT`). **Two stated exceptions**: `PATH_BUDGET_EXCEEDED` rejects in
   `DEFAULT`; it is reachable only by a chain carrying more same-name or same-key-identifier
   candidates for one certificate, or more verifying junk overall, than any honest chain has (§5.1).
   And `NO_DATA` rejects in `DEFAULT`, only after the consumer has promised local data and
   `validate()`/`start()` have confirmed it is loadable (§4; an unreadable sole seed fails `start()`).
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
| `revokt-engine-upki` *(CI-only, unpublished)* | jvm 22+ | `RevocationEngine` over `revokt-upki-shim` via Panama (test-plan.md §9.3) | `revokt-engine`, `revokt-upki-shim` |
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
interface PathBuilderFallback { fun build(chainDer: List<ByteArray>, anchors: AnchorSnapshot, nowMillis: Long): List<ByteArray>? }   // leaf first, trust anchor's certificate appended last; null = no path; a throw counts as a failed build: FallbackNotUsed(FAILED), cached in neither the path nor the verdict cache, every VirtualMachineError except StackOverflowError rethrown (§5.1 decision step 6)
internal expect fun canonicalSubject(nameDer: ByteArray): String?     // JVM/Android: X500Principal(der).getName(CANONICAL), null on a construction failure; linuxX64 gate: an empty actual stub returning null (the gate only compiles); the public seam is PlatformTrust.canonicalSubject
class StoreLockedException @JvmOverloads constructor(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
enum class NewerLayout { IN_MEMORY, REBUILD }   // growable; what a store whose `store.version` is higher than this engine's gets (§6.5)
fun interface RevoktLogger { fun log(level: LogLevel, message: String, cause: Throwable?) }   // commonMain; every "logged" in this document names its level. jvmMain: object RevoktLoggers { @JvmStatic fun jul(): RevoktLogger } (java.util.logging "dev.revokt"; DEBUG → FINE, INFO → INFO, WARN → WARNING, ERROR → SEVERE, the slf4j-jdk14 and log4j mapping, so DEBUG is hidden under JUL's default INFO level); revokt-android: RevoktAndroid.logger() (android.util.Log, tag "revokt"; kept by the consumer R8 rules); builder default: RevoktAndroid.logger() when revokt-android resolves by class name, else RevoktLoggers.jul() (a commonMain fun interface cannot gain companion members in another source set); a throwing logger is swallowed (never on a handshake path's verdict)
enum class LogLevel { DEBUG, INFO, WARN, ERROR }   // closed
enum class OwnershipCheck { STRICT, OWNER_OR_GROUP }   // growable
interface RevoktStorage {                                   // flat key space; the engine owns the layout (§6.5)
    fun read(name: String): ByteArray?                     // null = absent; a read that fails throws, never returns null
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
    val status: Int; val headers: Map<String, List<String>>; val body: ByteArray /* decoded, buffered; the fetcher stops at maxBodyBytes while inflating (gzip bomb) and throws; a fetcher never follows a 3xx and returns it as is, and a 3xx is FAILED; the engine re-checks and hashes */ }
fun interface HttpFetcher { fun fetch(request: FetchRequest): FetchResponse /* synchronous; one HttpFetcher per configured source, created by one Factory.create(tls) call per source at build() with that source's FetcherTls (a throwing factory propagates from build()); the contract: every TLS handshake the returned fetcher performs goes through the given tls and nothing else, one factory call serves one source only, and the shipped factories are the supported ones (§8 fetcher policy); runs on ioDispatcher, never the loader; never follows a redirect, its underlying client configured not to, and nothing above it follows one either; must honour thread interruption so a timed-out fetch does not pile up; the body is handed to the loader, which alone writes the store; any Throwable = SyncOutcome.FAILED for that sync; a 401 or 407 is FAILED on every platform and no fetcher ever answers a challenge */; fun interface Factory { fun create(tls: FetcherTls): HttpFetcher } }   // a fetcher-policy reject and a 401/407 carry the stage of the fetch they interrupted (CHANGESET, X5U or ATTACHMENT)
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
the signed TBS `signature` field. An implementation must not modify its arguments: the engine passes a certificate's
own arrays, shared by every handshake on the anchor snapshot. `JcaSignatureVerifier(provider: Provider? = null)` selects
`KeyFactory` by the SPKI key OID, creates `Signature`/`KeyFactory` per call, honours RSASSA-PSS
parameters, caches parsed `PublicKey`s by SPKI hash in an LRU of 1,024 entries holding only keys that
produced `VERIFIED` (presented junk keys are server-chosen; entry count exposed), and classifies by the startup probe, never by a
server-chosen exception: an OID in `unsupportedOids()` → `UNSUPPORTED`; any
`GeneralSecurityException` on a supported OID → `INVALID`; any `RuntimeException` from the provider
→ `INVALID` plus `Finding.VerifierError`. Signature OIDs: RSA PKCS#1 SHA-2, `id-RSASSA-PSS`, ECDSA
SHA-2, Ed25519/448, ML-DSA-44/65/87 (RFC 9881), SLH-DSA, composite as drafts settle. An OID outside these tables
is never in `unsupportedOids()` and is `INVALID`, as `sha1WithRSAEncryption` is. Key OIDs:
`rsaEncryption`, `id-RSASSA-PSS`, `id-ecPublicKey` with named curves, Ed25519/448, ML-DSA, SLH-DSA.
Key families (ordering only, used by `CandidateIndex.related()`, §5.1): RSA = {`rsaEncryption`, `id-RSASSA-PSS`} ↔ {RSA PKCS#1, PSS}; EC ↔
ECDSA; EdDSA, ML-DSA, SLH-DSA, composite: key OID equals signature OID; unknown compatible with
everything. Composite signatures are delegated to a provider owning the composite OID (BC; Conscrypt 2.7.0 and
2.8.0 register 15 of them, Appendix A) or `UNSUPPORTED`.

**`id-RSASSA-PSS` parameters**. The `RSASSA-PSS-params` must be present. The message hash and the
MGF1 hash must each be a SHA-2 hash, the family RSA PKCS#1 takes above. The mask generation function must be
`id-mgf1`, and `trailerField` must be 1. A field left out takes its RFC 4055 DEFAULT, so an omitted hash or
mask-generation field means SHA-1.

**Salt length:** a salt longer than 2,048 bytes is `INVALID`, decided before the provider is called (`MAX_SALT_LENGTH`). 2,048 bytes, the modulus bits / 8 at SunRsaSign's
largest modulus of 16,384 bits, is an upper bound on any RSA key's salt. The real maximum is `emLen - hLen - 2`
(RFC 8017 §9.1.1, `emLen >= hLen + sLen + 2`). The JDK refuses a
longer salt for the key on its own, with a `GeneralSecurityException`, except near `Int.MAX_VALUE`. There its
`hLen + sLen + 2` overflows into an `ArithmeticException`, which would otherwise become a `VerifierError` for a
CA-chosen length. On JDK 21.0.13 with SHA-256, the overflow starts at 2,147,483,614.

A PSS signature with other parameters is `INVALID`, whatever the provider would answer. That covers:
- a SHA-1 message or MGF1 hash, including the all-default parameters (SHA-1, MGF1 with SHA-1);
- a SHA-2 message hash under MGF1 with SHA-1, which the JDK verifies;
- any mask generation function other than `id-mgf1`;
- absent parameters.

The probe decides first. When `id-RSASSA-PSS` is in `unsupportedOids()`, every PSS signature is `UNSUPPORTED`,
whatever its parameters, a SHA-1 one included. A verifier over the Conscrypt provider alone is such a case
(Appendix A).

**ECDSA range check**. The curve probe decides first, as for PSS: a
curve the provider does not support is `UNSUPPORTED`, never `INVALID`. Then, after the provider's `KeyFactory` has
decoded the key and before `Signature` is called, the verifier decodes the signature's `ECDSA-Sig-Value` and answers
`INVALID` unless 1 ≤ r ≤ n − 1 and 1 ≤ s ≤ n − 1.
- **n** is the order of the decoded key's own curve, `ECPublicKey.params.order`, so every curve the provider supports
  is covered: P-256, P-384 and P-521, and the brainpool curves under BC (tested with `revokt-bc`). A key whose order cannot be read is
  `INVALID`.
- **The `ECDSA-Sig-Value` profile:** a SEQUENCE of exactly two INTEGERs, with minimal definite lengths, each INTEGER
  in minimal two's complement and positive, and no bytes after the SEQUENCE. Anything else is `INVALID`. This can be
  stricter than the provider: SunEC verifies a negative INTEGER read as unsigned (checked on JDK 17.0.21, 21.0.13
  and 27, Appendix A).
- **Why:** SEC 1 §4.1.4 step 1, which ring's verifier also performs. The JDK's own check was missing from JDK 15 to
  17.0.2 and in 18 GA (CVE-2022-21449), which within revokt's JVM 17+ target is 17.0.0 to 17.0.2 and 18 GA.
- **High s** (s > n/2) stays accepted: Mozilla's `ct-logs` collection signature has s > n/2,
  and SEC 1 and NSS accept it.
- **Scope:** every standalone ECDSA signature that reaches the verifier: a TLS chain's links, the x5u chain's links
  (§7.1) and the content signature after its raw-to-DER conversion. A composite ML-DSA + ECDSA signature verifies as
  one provider operation, so its ECDSA component is the owning provider's responsibility; both owning providers range-check it (BC's `ECDSASigner`, and BoringSSL under Conscrypt; Appendix A).

**From OID to JCA service** (as `JcaSignatureVerifier`'s tables do). The probe and `verify` resolve each
signature and key OID through the same table, to one `Signature` name and one `KeyFactory` name. The probe marks an
OID unsupported when the provider has no service under that name. A named curve is probed separately: it is
unsupported unless a key on it decodes through the provider's EC `KeyFactory` and its ECDSA `Signature` runs over
that key. The names are:
- RSA PKCS#1 and ECDSA: their standard names, such as `SHA256withRSA` and `SHA256withECDSA`.
- `id-RSASSA-PSS`: `RSASSA-PSS`.
- Ed25519/448, ML-DSA and SLH-DSA: their names, such as `ML-DSA-44` and `SLH-DSA-SHA2-128s`.
- Each composite: its bare OID string, so only a provider registering that OID verifies one.

Conscrypt 2.7.0 and 2.8.0 (Appendix A) register ML-DSA under its name, its bare OID and its `OID.`-prefixed OID.
They register the composites under a name and a bare OID (an `OID.` lookup throws), and SLH-DSA-SHA2-128s under its
name only. So under Conscrypt, the probe reports these as supported:
- ML-DSA-44/65/87;
- SLH-DSA-SHA2-128s, found by name, the lookup the table makes;
- the 15 registered composites.

Everything else in the tables is supported as well. The complete `unsupportedOids()` is 21 OIDs, the same under
both releases (37 table entries, since several OIDs fill both the signature and the key role):
- **RSA PKCS#1:** `SHA512/224withRSA` (`1.2.840.113549.1.1.15`) and `SHA512/256withRSA` (`.16`), signature only.
- **`id-RSASSA-PSS`** (`1.2.840.113549.1.1.10`), as signature and key. Conscrypt registers PSS only as
  `SHA1withRSA/PSS` to `SHA512withRSA/PSS`, with no `RSASSA-PSS` `Signature` or `KeyFactory`.
- **Ed448** (`1.3.101.113`), as signature and key.
- **The other 11 SLH-DSA sets**, `2.16.840.1.101.3.4.3.21`–`.31`, as signature and key.
- **The composites** `1.3.6.1.5.5.7.6.47`, `.50` and `.51`, as signature and key.
- **brainpoolP256r1, P384r1 and P512r1** (`1.3.36.3.3.2.8.1.1.7`, `.11`, `.13`), through the curve probe.

**Composite encoding, unverified:** the probe checks only that a service exists. Conscrypt's composite key and
signature encodings have not been checked against draft -19. If they differ, the probe reports the OID supported,
and a real draft-19 certificate is `INVALID` (its key does not decode or its signature does not verify), not
`UNSUPPORTED`.

**Purity gate.** `linuxX64()` only when `revokt.purityGate` is present; never published; BCV
`klib { enabled = false }`. Generation publication is a `@Volatile` reference whose only writers are
the single-parallelism loader dispatcher and, in the sole-seed synchronous path of §4 S, the `start()`
caller's thread before any loader task exists; never two at once.

Dependency and version choices: Okio internal only; no JSON library (§7.1); Kotlin floor 2.3; stable stdlib types in
Kotlin-facing signatures with `java.time` and `long` overloads; no third-party or unstable stdlib types in public
signatures; minSdk 26; JVM bytecode 17, which Android consumers dex with the AGP that revokt's Kotlin
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
    val formats: Set<FilterFormat>                                   // a generation with any filter (the full or a delta) in another format is never offered to prepare() (§6.5 format check)
    val name: String get() = this::class.simpleName ?: "anonymous"   // the class's simple name, or "anonymous" when the class has none; Finding.EngineError.engineName on every ENGINE_ERROR whose producer is ENGINE (§4, §5.5), so never null there; the Kotlin engine returns "kotlin", the upki engine "upki"; must not throw, and revokt reads it once per instance; on Android under R8, which renames classes, an engine overrides it with a stable string
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
class GenerationFiles internal constructor(…) {                      // always C2SP layout: "index.bin" plus the files it names; @RevoktTestingApi Builder; jvmMain: object JvmGenerationFiles { @RevoktTestingApi @JvmStatic fun fromDirectory(dir: java.nio.file.Path, dataset: Dataset, format: FilterFormat): GenerationFiles }, so a third-party engine is testable against the §9 corpus images from revokt-engine alone
    val generationId: String; val dataset: Dataset; val format: FilterFormat   // the full filter's encoding; each filter is read in its own (mixed encodings allowed), and every one is in the engine's formats (§6.5 format check)
    val names: Set<String>; fun bytes(name: String): ByteArray /* fresh copy; a disk-backed implementation later is not a break */; fun sha256(name: String): ByteArray /* content hash, computed once by the loader */; val sourceTimestampMillis: Long }
class CrliteSct private constructor(…) { val logId: ByteArray /* 32 bytes */; val timestampMillis: Long /* RFC 6962 u64 carried in Long; compared with java.lang.Long.compareUnsigned */ }   // @RevoktTestingApi Builder
class CrliteQuery private constructor(…) {                           // growable value-semantics class (builder, @RevoktTestingApi); a field added in a minor does not break engines
    val issuerSpkiHash: ByteArray /* SHA-256 of the issuer's SPKI TLV */; val serial: ByteArray /* rawSerial: DER INTEGER content bytes as encoded (the producer's RawValue.Bytes, §9.2) */; val scts: List<CrliteSct> /* order not significant; empty when no SCT extension has a list that parses under §9.2 (absent, or for example empty, a first item that fails, an inner identifier other than 0x04; §9.2 states every case); a list that fails later keeps the items before the failure */ }
```

**Seam.** `Revokt.Builder.revocationEngine(engine: RevocationEngine)` is public from 0.2 (the first `Revokt`; the engine-side types are public from 0.1) and
defaults to the Kotlin engine (`formats = {V3, V4}`, `name = "kotlin"`). The
updater builds `index.bin` itself for Remote Settings generations (the channel's one full filter and every delta,
ordered by time, with their coverage; `parent` is not read, §6.5), so every `GenerationFiles` is a directory image any C2SP reader accepts; the
only engine-specific property is `format`. **`index.bin` consistency.** The loader builds every `index.bin` it
installs, so each is **selection-equivalent** by construction: for every log id and every timestamp (inclusive at both
ends, overlapping windows allowed), the set of filters the `index.bin` log directory names for that
(log id, timestamp) equals the set of referenced filters whose own coverage map contains it, i.e. every
directory entry lies within its filter's window and every filter's window is exactly covered by its entries. A
seed's `index.bin` is rebuilt and byte-compared, and a mismatch installs nothing (`SEED_UNREADABLE`). **Every
`index.bin` revokt's loader reads (a seed's, a stored generation's) is at most 1 MiB, checked before it is parsed;
revokt never fetches an `index.bin`** (the seed's cap, §6.5, applied to every source; an injected engine's own reads
are its concern): over the cap, a seed is `SEED_UNREADABLE`, and a stored generation is a failed load in the §6.5
recovery chain (`STORE_UNREADABLE`). **An `index.bin` the loader builds** (a Remote Settings generation's)
that is over 1 MiB fails the install before the generation directory is written: `SyncOutcome.FAILED` with
`INDEX_INCONSISTENT`, stage `INDEX`, so the loader never writes a generation it could not reload. **revokt's index reader takes only the magic `upkiidx1`**
(C2SP `upki-revocation@v1.0.0`); the legacy `upkiidx0` that upki v1.0.1 also reads is rejected as malformed, with the
outcome of a mismatch (Appendix A). This is what makes the Kotlin engine's
coverage-driven filter selection (§6.2, every filter consulted by its own coverage) equal to C2SP's
`index.bin`-driven selection (upki binary-searches the log directory and loads only the filters it names)
on every generation the suite admits; upki's `Index::write` writes one entry per (log, filter), the filter's
coverage window for that log, so overlapping windows (a full and its deltas sharing boundary timestamps) are
separate entries, which the check admits (Appendix A), and a legitimate Mozilla generation
passes by construction. **A fetched generation with any placed filter (the full or a delta) whose encoding the
engine does not list is `SyncOutcome.FAILED` with `DiagnosticCode.FORMAT_UNSUPPORTED`** (stage `PREPARE`;
every filter, not only the full, is checked, and the previous generation stays live), counts toward `consecutiveFailures`
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
no SCT extension, or none whose list parses under §9.2 (for example an empty list, a first item that fails, an inner identifier other than `0x04`; §9.2 states every case;
§10 item 7); revokt's parser passes an empty `scts` list in each case before the engine is called; the Kotlin engine answers
`NO_SCTS` on it, the upki engine `NOT_COVERED` (one equivalence class, test-plan.md §9.3).

The upki adapter (`revokt-engine-upki`) and the cross-engine equivalence classes are CI-only test infrastructure:
[test-plan.md §9.3](test-plan.md#93-the-upki-backed-engine-and-the-cross-engine-suite-ci-only).

## 4. Public API (sketch, M1 surface)

One configuration surface: fluent `Builder` classes (`fun channel(c: CrliteChannel): Builder`, …);
`Revokt(block)`, `sources { }` and the assignment-style `var`s shown below are `@JvmSynthetic` sugar
over the same builder. Every public value or output type, including every `Finding` subclass, is a final class with a private
constructor, content-based `equals`/`hashCode`/`toString` (timing fields excluded: a timing field is a measured duration, such as
`Verdict.elapsedNanos`; timestamps such as `atMillis` and `createdMillis` take part), a nested `Builder` and
`newBuilder()` (service types such as `KotlinRevocationEngine()`, `AndroidPlatformTrust()`, `JcaSignatureVerifier()` and exceptions have public constructors); on output types (`Verdict.*`, every `Finding`, `RevoktEvent`, `RevoktStatus`,
`RevoktState`, `AnchorSnapshot`, `ExemptionContext`, `PolicyDiagnostic`, `SyncResult`) the builder is `@RevoktTestingApi` (opt-in,
`WARNING` level, outside the 1.0 promise). `Finding` is a sealed class, **growable** (a subtype may be added in a minor; use `else`); `Verdict` is closed. No data classes, no inline value classes. **Public type rule**: stable stdlib types
in Kotlin-facing signatures; `java.time` and `long` overloads for Java; one functional type per
member; kotlinx-coroutines is the one non-stdlib dependency in signatures, with a listener or
`CompletableFuture` alternative for each member. `Revokt` is the JVM facade in `revokt-jsse`.

```kotlin
val revokt = Revokt {
    channel = CrliteChannel.COMPAT                      // enum class CrliteChannel { COMPAT, DEFAULT } (growable); mandatory iff a CRLite source is configured (a seed counts); R: build() throws when unset (the consumer chooses); channel-less datasets (M2+) use the literal store segment `all`
    storage = AndroidStorage.noBackup(context, "revokt")
    platformTrust = AndroidPlatformTrust()              // default: auto-detected (AndroidPlatformTrust when android.os.Build resolves, else JvmPlatformTrust); R: on Android a platformTrust that is not AndroidPlatformTrust throws
    fetcherDelegate = corpTrustManager                   // the delegate fetcherTrustManager wraps; default platformTrust.defaultDelegate(); R: where requiresExtendedDelegate() is true a plain X509TrustManager throws IllegalArgumentException from build(), as trustManager(d) does at wiring; R: a RevoktTrustManager as fetcherDelegate throws IllegalArgumentException (the fetch would wait on the data it is supposed to produce); its snapshot is attempted inside start() when a fetching source is configured (§5.1 "Anchor snapshot"); with remoteSettings(MozillaRemoteSettings.DEFAULT) the fetcher contacts firefox.settings.services.mozilla.com, firefox-settings-attachments.cdn.mozilla.net and content-signature-2.cdn.mozilla.net (the NSC and egress allowlist, §7.1)
    signatureVerifier = JcaSignatureVerifier()
    revocationEngine = KotlinRevocationEngine()           // default; §3.2 seam
    clock = Clock.System                                // Java: clock(java.time.Clock); timeSource(TimeSource) for the monotonic deadlines (testable)
    sources { remoteSettings(MozillaRemoteSettings.DEFAULT); seed(SeedSource.fromResource("/revokt/seed-compat.zip")) }   // seed default when none is configured: SeedSource.bundled(), resolved at build(): /revokt/seed-<channel>.zip from the revokt-seed-<channel> artifact (§6.5; the quickstarts declare it); absent from the classpath → no seed source, and validate() emits NO_DATA_REJECTS_WITHOUT_LOCAL_DATA; present but unreadable → SEED_UNREADABLE at start() (§4 S bullet); seed(SeedSource.none()) opts out explicitly. No fetching source is configured by default (a library never opens the network unasked); a required dataset with local data and no fetching source is V NO_FETCHING_SOURCE, a WARNING under both enforcements (the instance updates only through sync()'s seed re-check, below; air-gapped seed-by-deploy fleets are legitimate). R: every source URL (baseUrl, attachmentBaseUrl, x5uHosts) is https with no userinfo, else build() throws (NSC blocks cleartext on API 28+, the JVM does not).
    meteredNetwork { false }                             // BooleanSupplier; revokt-android: RevoktAndroid.meteredNetwork(context) over ConnectivityManager.isActiveNetworkMetered(); sampled once per sync before a full download; a throw reads as false (§7.2)
    logger = RevoktLoggers.jul()                        // RevoktLogger; default auto-detected (§3)
    policy = RevoktPolicy.DEFAULT                       // or STRICT; RevoktPolicy.DEFAULT.newBuilder().rule(Rule.NO_SCTS, REJECT).exempt(Rule.NO_SCTS, …).staleness(Dataset.CRLITE, Staleness.ofMillis(3.days.inWholeMilliseconds, null))
    enforcement = Enforcement.ENFORCE
    awaitData(2.seconds)                                // Java: awaitData(java.time.Duration) / awaitDataMillis(long); defaults RevoktLimits.AWAIT_DATA_<CHANNEL>
    caches { pathEntries = 256; verdictEntries = 1024 }
    ioDispatcher = Dispatchers.IO                       // fetch I/O; Java: ioExecutor(Executor). The loader dispatcher is internal, single-parallelism. The dispatcher or executor must not run tasks inline (Dispatchers.Unconfined, Executor { it.run() }, Guava's directExecutor()): an inline one runs each fetch on the loader thread, which blocks before the per-fetch timeout (FetchRequest.timeoutMillis) can be applied
    limits { maxFilterBytes = 32 * MiB; maxTrustManagers = 64 }   // MiB = 1 shl 20 (a RevoktLimits constant); download and record caps (MAX_FILTER_BYTES, MAX_JSON_BYTES, MAX_X5U_BYTES, MAX_CHANGESET_RECORDS) are overridable upward only (R: a lower value throws IllegalArgumentException from build()); maxTrustManagers in both directions, ≥ 1; walker budgets are constants. MAX_FILTER_BYTES also caps SIGNED bodies (limits table below), so raising it is the recovery for a larger Mozilla filter; maxTrustManagers is the multi-tenant case (per-tenant trust stores), one CandidateIndex and two small caches per instance
    http = OkHttpFetcher.Factory(baseClient)             // default on the JVM: JdkHttpFetcher.Factory (ProxySelector.getDefault() and a per-connection HttpURLConnection.setAuthenticator that answers RequestorType.PROXY only, JDK 9+, so a trusted intercepting proxy cannot harvest default credentials; a 401/407 is FAILED; revokt configures no proxy; Basic auth to an HTTPS tunnel is disabled by the JDK unless jdk.http.auth.tunneling.disabledSchemes is cleared; proxy-authenticated fleets use OkHttpFetcher.Factory with proxyAuthenticator; setInstanceFollowRedirects(false)). Default on Android (AndroidPlatformTrust): OkHttpFetcher.Factory over a fresh OkHttpClient() when revokt-okhttp resolves (detected by class name), else AndroidHttpFetcher.Factory from revokt-android (HttpURLConnection.setAuthenticator does not exist in Android's libcore, so JdkHttpFetcher is never used there; Android's HttpsURLConnection answers a 407 from the VM-global Authenticator.getDefault() with no per-connection suppression, the §10 residual, which is why the OkHttp fetcher is preferred). OkHttp: sslSocketFactory and x509TrustManager are replaced from FetcherTls unconditionally, the base client's hostnameVerifier is kept (R: must be OkHttp's default), and followRedirects(false), followSslRedirects(false), authenticator(NONE), cookieJar(NO_COOKIES) and cache(null) are forced (a consumer disk cache would serve the first ETag-less request, on a fresh install or after resetState(), from its own max-age) (§7.1 "redirects are never followed" holds at the transport); proxy, dns, interceptors and certificatePinner are inherited and consumer-owned: application and network interceptors see every revokt request, so the consumer must not attach credential-adding interceptors to the base client (the README warns)
}
revokt.start(); revokt.close()                          // Revokt : AutoCloseable; Java entry Revokt.builder(); DSL vars carry @get:JvmSynthetic @set:JvmSynthetic; idempotent; lifecycle CREATED → STARTED → CLOSED (§5.1). start() throws IllegalStateException on a validate() ERROR, SEED_CHANNEL_MISMATCH, a consumer trust manager's pre-start anchor snapshot build failure (fetcherTrustManager's is the FETCHER_TRUST_UNAVAILABLE warning), a second instance on the same storage identity in this process, a call from a thread holding the factory lock, or, under ENFORCE with outcome(NO_DATA) == REJECT, SEED_UNREADABLE when the seed is the only local data source (verified synchronously inside start() in that configuration, §4 S bullet); stays CREATED and may be retried. close() on the loader thread throws IllegalStateException (listener executors are never the loader; syncAsync(), resetStateAsync() and readyFuture() are completed by `ioExecutor.execute { future.complete(v) }` / `completeExceptionally(t)`, the Java 8 shape (never `CompletableFuture.completeAsync`, `orTimeout` or any other API-31+ member: minSdk is 26, core-library desugaring does not cover them, and an API-26 instrumented fixture plus an Android Lint `NewApi` check on a minSdk-26 consumer of revokt-jsse guard it), so dependent stages never run on the loader; each call returns a fresh dependent future (`internal.thenApply { it }`), so a consumer's cancel()/complete() cannot corrupt readiness; close() completes a pending syncAsync()/resetStateAsync() exceptionally as it does readyFuture()); a start() whose loader join observes CLOSED returns normally on a CLOSED instance whose readyFuture() has failed
suspend fun Revokt.awaitReady(); fun readyFuture(): CompletableFuture<Void>          // completes when RevoktState.ready first becomes true; no internal deadline; close() completes it exceptionally with IllegalStateException("closed") and the suspend form throws CancellationException
fun interface Revokt.Provider { fun revokt(): Revokt }       // may return a CREATED or STARTED instance (the WorkManager worker starts a CREATED one itself, §3; a CLOSED one is Result.failure()); a direct sync() in CREATED or CLOSED throws IllegalStateException
suspend fun Revokt.sync(): SyncResult; fun syncAsync(): CompletableFuture<SyncResult>; fun syncBlocking(): SyncResult   // with no fetching source configured, sync() re-opens the seed source and, when the seed is newer than the live generation, installs it under the seed-vs-stored rule with writes (an air-gapped refresh: replace the seed artifact, call sync(); the watermark is intact), else UNCHANGED; either way it is a completed attempt (§8 STALE gate, datasetLastAttemptAtMillis)
suspend fun resetState(); fun resetStateBlocking(); fun resetStateAsync(): CompletableFuture<Void>   // STARTED only; read-only → IllegalStateException; runs on the loader after any in-flight install; deletes every key names() lists except store.version (never `.lock`; updater.json included: the rollback watermark restarts from the seed's timestamp, or from zero with SeedSource.none(), §10) while the published generation and the engine's installed generation stay live (DataState.pending stays false while a generation is published), re-runs the loader start task (the seed) and swaps old → new atomically (generationEpoch++ then); only when no local source yields a generation does it publish the empty snapshot (generationEpoch++) and **then** engine.clear(), in that order, so a handshake holding the old snapshot still finds data in the engine (step 7 never queries without a generation); a concurrent handshake is never NO_DATA while the previous generation existed; schedules the first sync before completing; anchor snapshots are untouched
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
val revokt.fetcherTrustManager: RevoktTrustManager          // created at build() over fetcherDelegate; snapshot attempted inside start() when a fetching source (remoteSettings) is configured (a failure is S FETCHER_TRUST_UNAVAILABLE, a WARNING: syncs return FAILED until the build succeeds, retried per sync; never a start() throw), else under the factory lock on its first checkServerTrusted in STARTED (§5.1 "Anchor snapshot"); status() reports null snapshot fields until then
expect class SeedSource internal constructor(…) { companion object { fun none(): SeedSource } }   // commonMain; internal open(): okio.Source? (Okio never appears in a public signature)
// jvmMain: fun interface SeedOpener { fun open(): java.io.InputStream? }   // one functional type, usable from Java as a lambda; the actual companion adds @JvmStatic fun of(opener: SeedOpener): SeedSource /* asset packs, a downloaded seed; re-opened on every start task and sync() seed re-check; wrapped into okio internally */, @JvmStatic fun fromResource(path: String): SeedSource and @JvmStatic fun bundled(): SeedSource /* resolve through SeedSource::class.java.classLoader, then the thread context loader, in that order (app servers) */
// jvmMain: object JvmSeedSource { @JvmStatic fun fromPath(path: java.nio.file.Path): SeedSource }   // mirrors JvmStorage
class MozillaRemoteSettings private constructor(…) { class Builder { fun baseUrl(url: String): Builder; fun bucket(name: String): Builder /* security-state */; fun collection(dataset: Dataset, name: String): Builder /* cert-revocations */; fun attachmentBaseUrl(url: String): Builder /* default https://firefox-settings-attachments.cdn.mozilla.net/, §7.1 */; fun x5uHosts(hosts: Set<String>): Builder; fun x5uHostRewrite(from: String, to: String): Builder /* applied to the parsed x5u URI host before the x5uHosts check; hosts and rewrite targets are compared exactly, ASCII case included; makes a byte-for-byte reverse proxy of the three Mozilla hosts a supported mirror, §7.1. MozillaRemoteSettings.Builder.build() throws IllegalArgumentException when `to` is not in x5uHosts, and when an x5uHosts entry, or either side of an x5uHostRewrite, is not a host name in the grammar X5uUrl checks at fetch time: labels of 1 to 63 ASCII letters, digits and '-', separated by single dots, a name of at most 253 characters, no trailing dot, and a last label that is neither all digits nor 0x-hex (so no IP literal); upper case is allowed, since comparison is exact; so build() and the fetch-time check accept the same set  */; fun pinnedRootSpkiSha256s(hashes: Collection<ByteArray>): Builder /* compared by content */; fun userAgent(ua: String): Builder; fun sourceId(id: String): Builder /* default "mozilla-remote-settings"; the updater.json key */; fun build(): MozillaRemoteSettings }; companion object { @JvmField val DEFAULT: MozillaRemoteSettings } }   // the content signature is read from metadata.signatures[], each entry's signature, x5u and mode (an entry is tried only when its mode equals "p384ecdsa"; the algorithm is never derived from it); metadata.signature is not read (§7.1)
@JvmOverloads fun revokt.sslContext(delegate: X509TrustManager? = null, keyManagers: Array<KeyManager>? = null): SSLContext
fun RevoktTrustManager.status(): TrustManagerStatus; suspend fun RevoktTrustManager.awaitReady(); fun RevoktTrustManager.readyFuture(): CompletableFuture<Void>   // = the owning Revokt's; kept so a binding that holds only the trust manager can wait
fun RevoktTrustManager.refreshAnchors(): CompletableFuture<Void>   // rebuilds the anchor snapshot on the loader (rate-limited by ANCHOR_REFRESH_MIN_INTERVAL; a failed rebuild keeps the snapshot); for delegates that reload their trust store
@JvmOverloads fun OkHttpClient.Builder.revokt(revokt: Revokt, delegate: X509TrustManager? = null): OkHttpClient.Builder   // a null delegate on every binding resolves to revokt.trustManager, the single memoised instance over platformTrust.defaultDelegate() (captured once per Revokt at build(); on Android ApplicationConfig holds exactly one RootTrustManager per process, so a default trust manager obtained through TrustManagerFactory and passed explicitly is === the captured delegate and resolves to the same instance, counting once); only distinct explicit delegates create further instances, so the cap counts delegates, not clients. Call it last on the builder: a later sslSocketFactory(...) from a debug-proxy or pinning module silently replaces it (evaluations and unevaluated both stay 0); withRevokt(client) is the terminal form
fun OkHttpClient.withRevokt(revokt: Revokt): OkHttpClient; fun OkHttpClient.revoktTrustManager(): RevoktTrustManager?   // the client's x509TrustManager when it is revokt's, else null; for a startup assertion
class EvaluationRequest private constructor(…) { class Builder {
    fun presented(chain: List<ByteArray>): Builder            // leaf first, as sent; walked (decision steps 2–6)
    fun verifiedPath(path: List<ByteArray>): Builder  // one platform-verified path, leaf → anchor (upki's single webpki VerifiedPath), at most MAX_DEPTH + 1 certificates, trusted without re-verification; source = PLATFORM; the walk is skipped; it is both the reported path and the exemptions' chain; a one-certificate path is FOUND under its own key and skips step 3's keyability check only when its leaf is an anchor by bytes in the snapshot read at entry (step 2's rule), else its leaf is gated like any leaf
    fun host(host: String?): Builder; fun nowMillis(nowMillis: Long): Builder; fun build(): EvaluationRequest } }   // at least one of presented/verifiedPath; build() also throws IllegalArgumentException when presented is set and empty, verifiedPath is set and empty, verifiedPath holds more than MAX_DEPTH + 1 certificates, or both are set and verifiedPath's first certificate is not byte-equal to presented[0]; with both set the verified path wins and the walk is skipped; chainSource is derived. M5 adds credentialType(CredentialType) (growable, default X509), routed before decision step 3 with PathStatus.NOT_APPLICABLE; JSSE never delivers an MTC credential to an X509TrustManager, so M5 is Evaluator.evaluate-only
sealed interface Evaluator { fun evaluate(request: EvaluationRequest): Verdict }   // sealed, never consumer-implemented, so members can be added; not named `Engine`, so it cannot collide with RevocationEngine
@Throws(CertificateException::class) @JvmOverloads fun Revokt.evaluate(chain: List<X509Certificate>, host: String? = null, delegate: X509TrustManager? = null): Verdict   // never waits; always runs step 1 (a null delegate resolves to platformTrust.defaultDelegate()) as `delegate.checkServerTrusted(chain.toTypedArray(), "UNKNOWN")`, the 2-arg call with SunJSSE's own TLS 1.3 authType (a signature-capable key-usage check, no endpoint identification since there is no peer; Conscrypt only requires a non-empty authType), host being used for host' only; a step-1 reject propagates the delegate's CertificateException unchanged, no Verdict (the annotation is what lets a Java caller catch it); with a delegate it uses (and if needed creates, counting toward MAX_TRUST_MANAGERS) the registry instance for that delegate and shares its caches; Evaluator.evaluate shares no trust-manager path or verdict cache
// Raw DER in EvaluationRequest is presumed to come from a platform-accepted chain; PARSE_FAILED on caller-fabricated bytes is the caller's to police (§9.2). The JVM binding applies the §9.2 read fallback before it builds the request; raw bytes passed here get none
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
    PARSE_FAILED(UNEVALUABLE, PATH, false), NO_ISSUER(UNEVALUABLE, PATH, true),
    NOT_ENROLLED(NON_ANSWER, CRLITE, true), NO_SCTS(NON_ANSWER, CRLITE, true), NOT_COVERED(NON_ANSWER, CRLITE, false),
                                                                        /* M2: ISSUER_UNKNOWN_TO_MOZILLA(NON_ANSWER, PATH, true); M3: CT_UNVERIFIED */
    STALE(DATA_QUALITY, null, true);   // Rule.NO_DATA is driven by requiredDatasets, never by CrliteQueryResult.NO_DATA. The two data rules (NO_DATA, STALE) are exemptable: under STRICT a feed outage must not take down traffic under a private anchor the operator already exempted from CRLite; ExemptionContext carries path.anchorSha256 and host for the data rules too (the walk still runs)
    companion object { @JvmField val PRECEDENCE: List<Rule> = entries }                 // declaration order; a test asserts entries == entries.sortedBy { it.ruleClass }
}
enum class Outcome { ALLOW, REJECT }                     // closed
enum class Enforcement { ENFORCE, OBSERVE, OFF }         // closed. OFF: platform only; steps 2–4 do not run; no events; evaluations does not advance, unevaluated[OFF] does
enum class Severity { WARNING, ERROR }                   // closed
enum class DiagnosticCode /* one per validate()/start()/sync/setter bullet */ { METERED_DEFERRED, CLOCK_BEHIND, NO_FETCHING_SOURCE, INDEX_INCONSISTENT, STORE_MIGRATED, STORE_NEWER_LAYOUT, STORAGE_UNSET, FORMAT_UNSUPPORTED, NO_DATA_AT_FLIP, NO_REQUIRED_DATASETS, ENGINE_SELF_CHECK_FAILED, FEED_HOST_REVOKED, FETCHER_TRUST_UNAVAILABLE, IN_MEMORY_STORE_WITH_FETCHING_SOURCE, RULE_FLIPPED_THIS_MINOR, EXEMPTION_ON_EVIDENCE_RULE, NO_DATA_REJECTS_WITHOUT_LOCAL_DATA, STALE_REJECTS_WITHOUT_THRESHOLD, SEED_PAST_REJECT_THRESHOLD, EXEMPT_ON_ALLOW, UNVERIFIED_REJECTS_WITH_CLASSICAL_GAP, STRICT_ON_ANDROID_WITHOUT_NO_ISSUER_EXEMPTION, BUDGET_ALLOWS, EVIDENCE_LOWERED_BELOW_PRESET, STALENESS_CLEARED_FOR_REQUIRED_DATASET, SEED_UNREADABLE, SEED_CHANNEL_MISMATCH, STORE_UNREADABLE, STORE_LOCKED, CHANNEL_UNSET, PLATFORM_TRUST_MISMATCH, CAP_NEAR_LIMIT, SYNC_FAILED, SYNC_SCHEMA_REJECTED, IO_DISPATCHER_UNCONFINED }   // growable
enum class EngineErrorProducer { BOUNDARY, ENGINE, EXEMPTION }   // growable; exactly these three in M1
enum class Layer { PATH, CRLITE }                        // growable; M2: ONECRL, CRLSET, DENYLIST (L1/L2); M3: CT (L4); M4: DISTRUST (L5)
enum class Dataset { CRLITE /* M2: INTERMEDIATES, ONECRL, CRLSET, DENYLIST; M3: CT_LOGS; M4: DISTRUST */ }   // growable; the freshness rule per dataset and source is §7.2 prose
enum class Freshness { RECORD_LAST_MODIFIED, LAST_VERIFIED_POLL, SEED_SIGNED_TIME, SEQUENCE_TIME, ARTIFACT_DATE }   // growable; what a generation's sourceTimestamp means
enum class PathStatus { FOUND, NO_ISSUER, PATH_BUDGET_EXCEEDED, PARSE_FAILED, NOT_WALKED }   // growable; M5: NOT_APPLICABLE
enum class ParseReason { STRUCTURE, OVERSIZE, PRODUCER_UNKEYABLE }   // growable; parseReason != null ⇔ path.status == PARSE_FAILED (§5.1 step 3, §9.2 D8)
enum class KeyabilityClause { HEADER, TBS_SHAPE, INTEGER, OID, NAME, TIME, KEY, EXTENSION }   // growable; the first failing §9.2 keyability clause, K1 to K8 in order; keyabilityClause != null ⇔ parseReason == PRODUCER_UNKEYABLE
enum class TerminalKind { ANCHOR /* M2: PRELOAD */ }   // growable; the reported path's terminal (§5.1 invariant)
enum class NoIssuerReason { NO_CANDIDATE, ALL_CANDIDATES_INVALID, UNANCHORED, UNSUPPORTED_ALGORITHM, PLATFORM_ONLY }   // growable; noIssuerReason != null ⇔ path.status == NO_ISSUER
enum class FallbackReason { SKIPPED /* presented chain over FALLBACK_MAX_PRESENTED, fallback enabled */, DISABLED /* pkixFallback(false), or the walker-only harness's disabled path */, FAILED /* ran and found no path: build returned null or threw; a thrown result is neither path- nor verdict-cached */ }   // growable; why decision step 6 evaluated no fallback path (§5.1)
enum class CredentialType { X509 /* M5: MTC */ }   // growable
enum class RevoktLifecycle { CREATED, STARTED, CLOSED }   // closed; commonMain
enum class WalkEnd { COMPLETE, RELATED_BUDGET, VERIFICATION_BUDGET, EXPLORATION_BUDGET }   // growable
enum class ChainSource { PLATFORM, RECONSTRUCTED, PRESENTED /* reserved; produced by no M1 path */ }   // growable; PLATFORM: a platform-verified chain, §5.1 decision step 4 or EvaluationRequest.verifiedPath; M2: MIXED (paths from both a PLATFORM chain and the re-walk)
enum class SyncOutcome { INSTALLED, UNCHANGED, DEFERRED /* a metered-deferred full (§7.2); not UNCHANGED, which reads as healthy */, FAILED, CLOCK_SKEW, ROLLBACK_REFUSED, BACKOFF, STORE_FAILED, STORE_LOCKED, BLOCKED_BY_SELF }   // growable
enum class SyncStage { FETCHER_TRUST, CHANGESET, X5U, ATTACHMENT, SIGNATURE, SCHEMA, INDEX, PREPARE, SELF_CHECK, ACTIVATE, STORE }   // growable; where a sync failed: FETCHER_TRUST = the §5.1 build retry failed (no fetch); CHANGESET = the changeset fetch or its last_modified CLOCK_SKEW; X5U = the x5u fetch or a validity CLOCK_SKEW; SIGNATURE = the metadata.signatures[] entries (none, more than 4, none tried, a null entry), any x5u PEM or chain failure other than validity (which is CLOCK_SKEW at X5U), or the content signature (§7.1); ATTACHMENT = a body fetch or the over-cap signed record, and a mirror file's fetch or a body whose size or SHA-256 differs from the manifest's (§7.3); each producing bullet names its stage

/** jvmMain. Time fields are stored as millis. Java: *Millis properties and java.time.Duration accessors/factories (API 26+). Kotlin: kotlin.time.Duration via @JvmSynthetic extensions. No inline value class on the surface. commonMain sees only an internal PolicyTable these compile to. */
class Staleness private constructor(…) { val staleAfterMillis: Long; val rejectStaleAfterMillis: Long?   // staleAfter: loud threshold only (DataState.stale). rejectStaleAfter: the only threshold at which Rule.STALE fires; null = STALE never fires for this dataset
    fun staleAfter(): java.time.Duration; fun rejectStaleAfter(): java.time.Duration?
    companion object { @JvmStatic fun ofMillis(staleAfter: Long, rejectStaleAfter: Long?): Staleness; @JvmStatic fun of(staleAfter: java.time.Duration, rejectStaleAfter: java.time.Duration?): Staleness } }
class PolicyDiagnostic private constructor(…) { val code: DiagnosticCode; val severity: Severity; val rule: Rule?; val dataset: Dataset?; val message: String }   // tests and consumers match on code, never on message
class RevoktPolicy private constructor(…) {           // newBuilder() on any policy, keeping the preset it derives from; no from-scratch builder; companion object { @JvmField val DEFAULT; @JvmField val STRICT }; fun exemption(rule: Rule): Exemption?
    fun outcome(rule: Rule): Outcome; val requiredDatasets: Set<Dataset>; fun staleness(dataset: Dataset): Staleness?
    val rollbackWindowMillis: Long; val clockSkewMillis: Long; val signedSourceFailingAfterMillis: Long   // plus java.time accessors
    class Builder {                                      // every method returns Builder; build() returns RevoktPolicy and runs the build()-time checks below; every duration and millis argument is ≥ 0, else IllegalArgumentException, and so is a java.time.Duration whose milliseconds overflow Long
        fun rule(rule: Rule, outcome: Outcome): Builder                       //
        fun exempt(rule: Rule, exemption: Exemption): Builder                 // a second call for the same rule replaces the first; clearExemption(rule)
        fun exemptAnchors(sha256s: Collection<ByteArray>): Builder             // = exempt(rule, anchorIn(sha256s)) for every exemptable rule that is not EVIDENCE, is not marked "empty path" in the §8 table, and whose outcome in the builder at this call is REJECT; applied at its call position over the rule set as it stands then (a later rule() or exempt() on the same builder wins, so a narrower explicit exempt() written after it is kept): EVIDENCE rules (M2 ONECRL, M4 DISTRUST) need an explicit exempt(), so an M1 call never widens to evidence on upgrade, while a non-EVIDENCE rule that flips to REJECT in a later minor (M3 CT_UNVERIFIED) is covered by a call made after the flip, as a private CA wants; the "empty path" rule (NO_ISSUER; a column of the golden fixture, so a future rule must declare it) fire only on an empty reported path, where anchorIn can never match (use hostSuffixIn, platformOnly), whereas M2's ISSUER_UNKNOWN_TO_MOZILLA fires on a Found path and is covered; sha256s are of each anchor's DER as revokt reads it (§5.3), which is getEncoded() unless the §9.2 read fallback applies
        fun requiredDatasets(set: Set<Dataset>): Builder
        fun staleness(dataset: Dataset, s: Staleness): Builder; fun clearStaleness(dataset: Dataset): Builder   // clearing a required dataset's entry → validate() WARNING STALENESS_CLEARED_FOR_REQUIRED_DATASET
        fun rejectStaleAfter(dataset: Dataset, d: java.time.Duration?): Builder; fun rejectStaleAfterMillis(dataset: Dataset, millis: Long?): Builder   // null clears only the reject threshold; the loud flag stays; on a dataset with no entry, creates one with staleAfter = rejectStaleAfter
        fun rollbackWindow(d: java.time.Duration): Builder; fun rollbackWindowMillis(millis: Long): Builder
        fun clockSkew(d: java.time.Duration): Builder; fun clockSkewMillis(millis: Long): Builder
        fun signedSourceFailingAfter(d: java.time.Duration): Builder; fun signedSourceFailingAfterMillis(millis: Long): Builder
        fun build(): RevoktPolicy }                       // Kotlin: kotlin.time.Duration overloads as @JvmSynthetic extensions
}
sealed interface Verdict {
    val rules: Set<Rule>                                 // every rule that fired, whatever its outcome; iterates in Rule.PRECEDENCE order (an ordered set sorted by Rule.PRECEDENCE; a LinkedHashSet in commonMain)
    val rule: Rule?                                      // Rejected: first fired, non-exempted REJECT rule in Rule.PRECEDENCE. Accepted: null
    val findings: List<Finding>; val elapsedNanos: Long   // generationEpoch is @RevoktInternalApi (cache key only; not stable across processes) and, like elapsedNanos, not part of equality, hashing or toString
    val path: Finding.Path                               // non-null; status NOT_WALKED when the engine did not reach the walk (catch boundary)
    val crlite: Finding.Crlite?                          // the first Finding.Crlite with result REVOKED in issuerSpkiSha256s order; else the finding for issuerSpkiSha256s[0]; else null
    val dataStates: Map<Dataset, Finding.DataState>      // an entry for every required dataset and every dataset consulted; generationId == null ⇔ no generation; Rule.NO_DATA fires only when the dataset is required and not pending. Computed before the catch boundary: present on every verdict, ENGINE_ERROR included
    class Accepted private constructor(…) : Verdict { class Builder { … } }
    class Rejected private constructor(…) : Verdict { override val rule: Rule; class Builder { … } }   // non-null narrowing; Java getRule() is @NotNull on Rejected
}
sealed class Finding {
    class Path : Finding() { val status: PathStatus; val source: ChainSource; val noIssuerReason: NoIssuerReason?; val walkerReason: NoIssuerReason?   // the walker's own reason before any PLATFORM_ONLY promotion; set on every walk NotFound, whatever the reported status (so a fallback Found after UNANCHORED still carries it), null otherwise
        val parseReason: ParseReason?                    // non-null ⇔ status == PARSE_FAILED
        val keyabilityClause: KeyabilityClause?          // non-null ⇔ parseReason == PRODUCER_UNKEYABLE (§9.2 K1–K8)
        val terminalKind: TerminalKind?                  // null when the reported path is empty; else ANCHOR in M1; M2: PRELOAD for a preload-only path (a terminal of last resort), where anchorSha256 is null
        val rewalkEnd: WalkEnd?                          // null unless a re-walk ran; M2: the re-walk's WalkEnd (COMPLETE or its exhaustion), which never demotes the first walk's Found
        val endReason: WalkEnd?                          // COMPLETE on Found/NotFound (the step-6 fallback-skipped exit included), the Budget's end on Budget, EXPLORATION_BUDGET with endDepth = 0 for the step-3 no-walk cut, null only when no walk ran (NOT_WALKED, PLATFORM, the step-2 anchor leaf)
        val endDepth: Int?                               // path size at which the walk ended (1 = leaf level); null on a completed walk (Found, NotFound) and when no walk ran; set only on Budget, and 0 on the step-3 no-walk cut
        val cacheHit: Boolean; val anchorSnapshotId: Long /* id of the snapshot read once at flow step 2 (Evaluator.evaluate: at its entry) and consumed at decision step 1; 0 when none was consulted (Evaluator.evaluate with a verifiedPath of two or more certificates, presented also set or not; a one-certificate verifiedPath consults the snapshot read at entry for step 2's anchor test and reports its id); the walker harness assigns ids to its fixture snapshots */; val usedFallback: Boolean   // true whenever a fallback path was evaluated, Found or Budget
        val pathsFound: Int                              // on Found: the paths found (M2: first walk plus completed re-walk paths); on Budget: the partial paths
        val reportedPathSha256s: List<ByteArray>         // DER hashes leaf → terminal of the reported path: the first found path, else the first partial path, else empty; on a Budget walk with a fallback path and no partial path, the fallback path, with terminalKind and anchorSha256 following it, so issuerSpkiSha256s[0] stays the reported path's key
        val issuerSpkiSha256s: List<ByteArray>           // every distinct leaf-issuer key evaluated: walker keys in candidate order, then the fallback key if new; first is the reported path's
        val candidatesDropped: Int                       // presented or platform-built certificates the parser rejected and the walker never saw (§9.2 issuer corpus); also RevoktStatus.candidatesDropped
        val anchorSha256: ByteArray?                     // SHA-256 of the reported path's anchor DER; null when the reported path is empty or (M2) terminalKind == PRELOAD
        @RevoktInternalApi val walkStats: WalkStats      // @RevoktInternalApi class WalkStats(val verifications: Int, val candidatesExplored: Int, val relatedExploredAtLeaf: Int, val unrelatedExploredAtLeaf: Int), annotated at class level so it stays out of the dump; walker internals, opt-in
        val credentialType: CredentialType               // growable enum, X509 in M1; M5 adds MTC (reserved now so M5 lands additively) }
    class Crlite : Finding() { val result: CrliteQueryResult; val issuerSpkiSha256: ByteArray?; val coverageEndMillis: Long? }
    class DataState : Finding() { val dataset: Dataset; val generationId: String?   // "<changeset timestamp>/<last applied record id>", the last filter in buildIndex placement order (the full, then deltas by (effectiveTimestamp, id)); seed: seed id; null ⇔ no generation
        val freshness: Freshness?; val fromSeed: Boolean; val sourceTimestampMillis: Long?; val ageMillis: Long?
        val pending: Boolean                             // true while the loader's start task has not passed the seed step for this dataset (in-process; the §8 STALE gate is the persisted one); false at the end of the start task whatever it found, a fetching source configured or not; Rule.NO_DATA never fires while pending (§5.1 overload table)
        val clockBehind: Boolean                         // sourceTimestampMillis > now + clockSkew, recomputed at every publish (a load after restart included) and never persisted (a future-dated seed, or a changeset installed under the §6.3 clock-behind rule): ageMillis is clamped at 0 and the CLOCK_BEHIND warning is on RevoktState.warnings while any dataset has it
        val seedFormat: Int?                             // when fromSeed
        val stale: Boolean                               // loud flag: ageMillis > staleAfter
        val rules: Set<Rule>                             // the data rules that fired for this dataset: NO_DATA, STALE }
    /* M2, reserved shape: class PathHit : Finding() { val rule: Rule; val dataset: Dataset; val certSha256: ByteArray; val onReportedPath: Boolean; val recordId: String? }  // M4: certSha256 == anchorSha256 */
    class UnsupportedAlgorithm : Finding() { val oid: String; val where: Layer; val outcomeDepended: Boolean }
    class VerifierError : Finding() { val oid: String; val message: String }   // a verifier or algorithm failure only: oid is the signature algorithm whose verification failed; never the PKIX fallback, which is FallbackNotUsed
    class FallbackNotUsed : Finding() { val reason: FallbackReason }   // exactly one ⇔ the step-5 walk ended NotFound or Budget and usedFallback == false (§5.1 decision step 6); named "not used" because a FAILED fallback did run
    class AlgorithmIdMismatch : Finding() { val certIndex: Int }
    class EngineError : Finding() { val message: String; val producer: EngineErrorProducer; val engineName: String? /* the engine's RevocationEngine.name (§3.2) when producer == ENGINE, so never null there: "kotlin" and "upki" for the two shipped engines */ }
    class Exempted : Finding() { val rule: Rule }
}
class PresentedChain private constructor(…) { val size: Int; fun der(i: Int): ByteArray; fun parsed(i: Int): Boolean; fun subject(i: Int): ByteArray; fun issuer(i: Int): ByteArray; fun spkiSha256(i: Int): ByteArray /* SHA-256 of the SPKI TLV */; fun serial(i: Int): ByteArray /* rawSerial: INTEGER content bytes as encoded, sign byte and leading zeros preserved */; fun dnsNames(i: Int): List<String> }   // every presented certificate in presented order, so index i is AlgorithmIdMismatch.certIndex's; an entry revokt did not parse keeps its raw der(i), has parsed(i) false, and empty subject, issuer, spkiSha256 and serial and an empty dnsNames, so nothing matches it; equality is by each entry's bytes and parsed flag; ByteArray getters return copies; an index outside 0 until size throws IndexOutOfBoundsException
fun interface Exemption { fun isExempt(context: ExemptionContext): Boolean   // pure; runs after policy mapping for fired REJECT rules on exemptable rules; cached with the verdict; a throw = not exempt + Finding.EngineError(EXEMPTION)
    companion object {                                                        // shipped helpers, commonMain, in the same file as Exemption (a companion cannot straddle source sets; they need only ByteArray, String and okio.ByteString); the enterprise-CA and §5.2-gap cases without hand-written lambdas
        @JvmStatic fun anchorIn(sha256s: Collection<ByteArray>): Exemption   // copied into a Set<okio.ByteString> at construction; matches context.path.anchorSha256 by content, the anchor of the reported path (reportedPathSha256s; M1: the first path found in §5.1's candidate order, as Firefox applies its anchor-dependent rules to the one chain it built)
        @JvmStatic fun hostIn(hosts: Collection<String>): Exemption          // each entry normalised as host' (§5.1 flow step 2); matches context.host, which on an HTTP/2-coalesced connection is the host OkHttp handshook for (§5.1); an entry that is not ASCII (pass the A-label), is empty after normalisation, starts with '.' or holds a '*' throws IllegalArgumentException when the exemption is made; an empty or null context.host never matches
        @JvmStatic fun hostSuffixIn(suffixes: Collection<String>): Exemption // host' equals a suffix or ends with "." + suffix; private CAs serve many subdomains; entries normalised and checked as for hostIn
        @JvmStatic fun platformOnly(): Exemption } }                         // context.path.noIssuerReason == PLATFORM_ONLY; a null host or anchorSha256 never matches hostIn/anchorIn
// Exemptions.kt, @file:JvmName("Exemptions"): infix fun Exemption.and(other: Exemption): Exemption; infix fun Exemption.or(other: Exemption): Exemption   // Java: Exemptions.and(a, b). CEL's && and ||: short-circuiting but commutative; the side that decides the result wins whatever the other side did (true or broken = broken or true = exempt; false and broken = broken and false = not exempt), and its partner's throw is absorbed and not recorded; with no deciding side the first throw propagates and is recorded as not exempt plus the EXEMPTION engine error (when both throw, the left operand's); a fatal error (§5.5's catch rule) propagates at once; the outcome and findings never depend on operand order
class ExemptionContext private constructor(…) { val rule: Rule; val chain: PresentedChain? /* null for a non-X.509 credential (M5) */; val credentialType: CredentialType; val path: Finding.Path; val host: String? /* normalised */; val nowMillis: Long; val dataStates: Map<Dataset, Finding.DataState> }   // growable: new evidence (M3 SCTs, M4 distrust record) lands as new nullable properties; builder @RevoktTestingApi on the type
class AnchorSnapshot private constructor(…) { val id: Long /* process-local counter, like generationEpoch; not stable across processes */; val sha256: ByteArray /* of the sorted anchor DERs only (the bytes read, §5.3); stable */; val anchors: List<ByteArray> /* each anchor's bytes read (§5.3); the snapshot also keeps the platform's anchor objects, whose getEncoded() the PKIX fallback is given */; val createdMillis: Long; val preloadGenerationId: String? /* null in M1; M2: the INTERMEDIATES generation the index holds; an INTERMEDIATES install rebuilds every live index and advances id, so both caches miss */ }
class SyncResult private constructor(…) { val outcome: SyncOutcome; val atMillis: Long; val installed: Map<Dataset, String> /* each dataset this sync installed, with the installed generation's id */; val sourceId: String? /* the source the outcome is about */; val stage: SyncStage? /* where a FAILED/STORE_FAILED/CLOCK_SKEW sync stopped */; val httpStatus: Int? /* the last response status when a fetch was involved */; @Transient val cause: Throwable? /* the fetcher's or loader's throwable; not persisted, null when read back; not part of equality or toString */; val blockedSource: String? /* BLOCKED_BY_SELF: which source */; val blockedChainSha256: ByteArray?; val blockedLeafSerial: ByteArray? /* BLOCKED_BY_SELF only */; val warnings: List<PolicyDiagnostic> }
class RevoktEvent private constructor(…) { val sequence: Long; val atMillis: Long; val policyEpoch: Long; val credentialType: CredentialType; val host: String?; val chainSha256: ByteArray; val leafSerial: ByteArray? /* rawSerial */; val verdict: Verdict; val shadowVerdict: Verdict? /* null when no shadowPolicy is set, and when the enforced evaluate threw before the shadow ran */; val enforcement: Enforcement; val enforced: Boolean /* = verdict is Rejected && enforcement == ENFORCE */ }
interface RevoktListener { fun onVerdict(event: RevoktEvent); fun onStateChanged(state: RevoktState) {} }   // second method has a default body; Java alternative to the state flow
class RevoktStatus private constructor(…) {            // snapshot; counters monotonic since build() for unevaluated, since start() for every other; maps zero-filled over Rule.entries
    val evaluations: Long; val rejects: Map<Rule, Long> /* ENFORCE only */; val wouldRejects: Map<Rule, Long> /* OBSERVE only */; val shadowWouldRejects: Map<Rule, Long> /* the shadow policy's Rejected verdicts by rule, under ENFORCE and OBSERVE */; val fired: Map<Rule, Long>; val exempted: Map<Rule, Long>
    val noData: Map<Dataset, Long>; val stale: Map<Dataset, Long> /* loud flag seen */; val unsignedData: Map<Dataset, Long>; val noIssuer: Map<NoIssuerReason, Long> /* keyed by the reported (promoted) reason */; val parseFailed: Map<ParseReason, Long> /* fired[PARSE_FAILED] split by reason, zero-filled */; val walkEnds: Map<WalkEnd, Long>; val chainSources: Map<ChainSource, Long>; val fallbackUsed: Long
    val verifierErrors: Long /* Finding.VerifierError only; FallbackNotUsed is not counted */; val candidatesDropped: Long; val verdictCacheHits: Long; val storeFailures: Long; val trustManagerCount: Int; val droppedEvents: Long; val droppedRejectedEvents: Long; val listenerFailures: Long
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
holding public top-level `kotlin.time` extensions carries `@file:JvmName`. Interface members with bodies are default
methods for Java implementers: `-jvm-default=enable` is the Kotlin compiler's default at the build's Kotlin version, and
build-logic does not override it.
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
| `PATH_BUDGET_EXCEEDED`, `PARSE_FAILED` | the same-named rule |

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
as the re-walk and the verdict's `source` is `MIXED`; on `Evaluator.evaluate` with a `verifiedPath` there is no re-walk and the rule is evaluated over that path alone) and only when a hit lies on a found path; it
reuses the first walk's memo under its own fresh budgets; a `Budget` on the re-walk **never demotes**
the first walk's `Found`: the rule is evaluated over the paths found so far (the hit path plus any
clean path the re-walk completed), the re-walk's `WalkEnd` is recorded on `Finding.Path.rewalkEnd`,
and `PATH_BUDGET_EXCEEDED` fires only from the first walk; the §9.1 properties cover the re-walk from 0.4. **Data
rules (`NO_DATA`, `STALE`)** are map lookups over the generation snapshot taken at
flow step 2, computed **before** the catch boundary and merged into every verdict,
`ENGINE_ERROR` included.

**Growability contract.** `newBuilder()` works on any policy and keeps the preset it derives from, so every policy
derives from a preset. A `Rule` added in a minor
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
three time fields, precedence)` whose CI diff accepts only: a new rule with
`ALLOW` when `introducedIn == current minor`; a preset outcome `ALLOW → REJECT` when
`introducedIn == current minor − 1` and `flippedIn` is null, setting `flippedIn = current minor`
(at most once per rule and preset); `exemptable` false → true; existing precedence entries
remaining a subsequence.

**`build()`, `validate(enforcement)` and `start()`**
- V `NO_DATA_REJECTS_WITHOUT_LOCAL_DATA`: `requiredDatasets.isNotEmpty() && outcome(NO_DATA) == REJECT && no local data source` (a seed):
  a `WARNING` under `OBSERVE`, an `ERROR` under `ENFORCE`, emitted once per required dataset with no
  local source (`PolicyDiagnostic.dataset` set); the setter throws iff any `ERROR`;
  `validate(enforcement)` returns the diagnostics. With `requiredDatasets` empty, `NO_DATA` can never
  fire and readiness never waits for data; V `NO_REQUIRED_DATASETS`: a CRLite source configured and
  `CRLITE ∉ requiredDatasets` → `WARNING` (data loss would be silent). V `IN_MEMORY_STORE_WITH_FETCHING_SOURCE`:
  `RevoktStorage.inMemory()` with a fetching source → `WARNING` (a full re-download per restart, no crash recovery).
  V `FORMAT_UNSUPPORTED`: a `remoteSettings` source while `V3 ∉ revocationEngine.formats` → `WARNING` under
  `OBSERVE`, `ERROR` under `ENFORCE` (Mozilla serves v3; both shipped engines list it, so it fires only for a
  third-party engine). V `NO_FETCHING_SOURCE`: a required dataset with a local data source and no fetching source → `WARNING` under both enforcements (the instance updates only through `sync()`'s seed re-check, §4).
- **Under `Enforcement.OFF` every V diagnostic is a `WARNING`**, so an `ERROR` can never block the switch
  to the kill switch; this binds every `ERROR`-capable V code, the ones `validate()` adds in `revokt-jsse` included.
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
- S `UNVERIFIED_REJECTS_WITH_CLASSICAL_GAP`: `outcome(NO_ISSUER) == REJECT && unsupportedOids() ∩ classicalOids ≠ ∅` → `WARNING`; `classicalOids` = RSA PKCS#1 with SHA-256/384/512, ECDSA P-256/P-384 with SHA-2, Ed25519.
- S `RULE_FLIPPED_THIS_MINOR`: for every rule with `flippedIn == current minor` whose outcome in the consumer's policy is `REJECT` by inheritance → `WARNING` on `RevoktState.warnings` (a runtime signal that this build enforces a newly flipped rule; a rule in its grace minor is visible only in `fired`).
- S `FETCHER_TRUST_UNAVAILABLE`: `fetcherTrustManager`'s snapshot build failed in `start()` → `WARNING` (cleared by the first successful build); each sync first retries the build on the loader (under the factory lock) and, while it fails, is `FAILED` without a fetch (stage `FETCHER_TRUST`, `sourceId` null, every configured fetching source's `consecutiveFailures` advancing; counting toward `signedSourceFailing` and the failure backoff as any `FAILED`); with a fetching source configured the public instance never attempts the lazy build itself, a handshake on it counts `unevaluated[FETCHER_SNAPSHOT_UNAVAILABLE]` until the loader's retry succeeds.
- V `NO_DATA_AT_FLIP` (the one state-dependent V code): in `STARTED`, `validate(ENFORCE)` (the enforcement setter, and the policy setter against the current enforcement) returns `ERROR` when `outcome(NO_DATA) == REJECT` and a required dataset has `generationId == null`, `pending == false` and a `SEED_UNREADABLE`/`STORE_UNREADABLE` warning for its sole local source; while `pending == true` the flip is accepted and the dataset becomes `NO_DATA` if the start task finds nothing, which `validate()` cannot see.
- Sync `FEED_HOST_REVOKED` (on `SyncResult.warnings`, and carried on `RevoktState.warnings` while `feedHostRevoked`): the signed source's hold expired and fetches proceed (§8). Sync `CLOCK_BEHIND` (and on `RevoktState.warnings` while any dataset has `clockBehind`): a future-dated seed or changeset was installed under the §6.3 rule, so the local clock is behind the signed data.
- V `STRICT_ON_ANDROID_WITHOUT_NO_ISSUER_EXEMPTION`: `STRICT` on `AndroidPlatformTrust` with no `NO_ISSUER` exemption → `WARNING` citing the §5.2 gap.
- V `BUDGET_ALLOWS`: `outcome(PATH_BUDGET_EXCEEDED) == ALLOW` → `WARNING` (re-opens the stuffing evasion).
- V `IO_DISPATCHER_UNCONFINED`: `ioDispatcher` is exactly
  `Dispatchers.Unconfined` → `WARNING` under both enforcements (fetches would run on the loader thread, defeating the
  per-fetch timeout, §4). Other inline executors are covered by §4's sentence only.
- R: `outcome(NO_ISSUER) == ALLOW` with the PKIX fallback disabled (§5.1: the fallback is load-bearing).
- (not a diagnostic) An empty anchor set, a throwing `getAcceptedIssuers()` or a failed index build throws `IllegalStateException` from `trustManager(delegate)` in `STARTED` and from `start()` for consumer trust managers created in `CREATED`, on both platforms (§5.1 "Anchor snapshot"); `fetcherTrustManager`'s failure is the S `FETCHER_TRUST_UNAVAILABLE` warning instead.
- S `SEED_UNREADABLE` / `SEED_CHANNEL_MISMATCH` / `STORE_UNREADABLE` / `STORE_MIGRATED` / `STORE_NEWER_LAYOUT` (per §6.5) / `STORE_LOCKED` (per §5.1 read-only mode); S→`ERROR` thrown by `start()` under `ENFORCE` with `outcome(NO_DATA) == REJECT` when the seed is the only local data source and is unreadable: **in that configuration, and only when the synchronous `meta.json` read finds no complete stored generation (first run, a rebuild, corruption), the seed's verification, `index.bin` rebuild, `prepare`, the §6.5 self-check and `activate` run synchronously inside `start()` on the calling thread, before the flip and before any loader task exists (the one exception to "loader dispatcher only"; a self-check failure is `SEED_UNREADABLE` and throws here; the factory lock is released around this work, §5.1 lifecycle)**; with a complete stored generation the loader decodes it as §5.1 states (falling to `previous`, then the seed, so a readable store masks a bad seed and the common cold start never decodes on the calling thread), otherwise on the loader task (a loud failure in `CREATED`, platform-only, instead of a silent reject-all); `STORE_UNREADABLE` never throws (§6.5); a seed
  channel mismatch is an `ERROR` thrown synchronously by `start()` on both platforms (the `seed.json`
  header is read synchronously).
- `NOT_STARTED` is not a warning: a trust manager or `sslContext()` obtained before `start()` runs step 1 only until `start()` and counts `unevaluated[NOT_STARTED]` (creating trust managers before `start()` is the recommended main-thread pattern, so it cannot be a stuck alert).
- R `CHANNEL_UNSET`: no `channel` configured while a CRLite source (a seed included) is. R `PLATFORM_TRUST_MISMATCH`: Android runtime with a non-Android `platformTrust`. R `STORAGE_UNSET`: `AndroidPlatformTrust` with no explicit `storage` (§3).
- Sync-time diagnostics on `SyncResult.warnings`: `SYNC_FAILED` (any `FAILED`/`STORE_FAILED`/`CLOCK_SKEW` sync, with the cause), `SYNC_SCHEMA_REJECTED` (a verified changeset whose records fail the collection schema), `CAP_NEAR_LIMIT` (a body or record count above half the `RevoktLimits` constant, not the overridden value, the signed size notwithstanding, and the code on the over-cap `FAILED` of a signed record, §5.1 limits table; the §9 live check warns on it), `METERED_DEFERRED` (§7.2, with `SyncOutcome.DEFERRED`), `ENGINE_SELF_CHECK_FAILED` (the §6.5 self-check mismatch, `SyncOutcome.FAILED`), `INDEX_INCONSISTENT` (§3.2's over-cap built index and §6.5's index-name collision), `FORMAT_UNSUPPORTED` (§3.2), `FEED_HOST_REVOKED` (§8) and `CLOCK_BEHIND` (§6.3). `SyncResult.stage`, `httpStatus` and `cause` say where and why without parsing `message`.

## 5. Trust manager [M1]

### 5.1 Common flow

**Limits** (`object RevoktLimits`; walker budgets are documented constants; download and record caps are builder-overridable upward; cache sizes are builder-configurable):

| Constant | Value | Meaning |
|---|---|---|
| `MAX_DEPTH` | 16 | a path holds at most `MAX_DEPTH + 1` certificates including the terminal; deeper is a dead end, not exhaustion (same convention in the reference walker) |
| `MAX_PRESENTED` / `MAX_PRESENTED_BYTES` | 64 / 1 MiB | presented certificates and their summed DER; beyond either the chain is `Budget(EXPLORATION_BUDGET)` without a walk (honest chains are under 20 KB; bounds per-handshake memory independently of `MAX_CERT_BYTES`) |
| `MAX_RELATED_PER_LEVEL` | 64 | related candidates explored at one node; the 65th triggers `RELATED_BUDGET` without being explored |
| `MAX_VERIFICATIONS` | 256 | verifier calls per walk (memo hits excluded; the guard-tripping attempt not counted) |
| `MAX_EXPLORED` | 1,024 | candidates explored per walk, a candidate refused by the CA check and memo hits included |
| `FALLBACK_MAX_PRESENTED` | 8 | the PKIX fallback is skipped for longer presented chains; a `NotFound` on such a chain is `PATH_BUDGET_EXCEEDED`, never `NO_ISSUER`, whether the platform accepted it in step 1 or step 1 did not run (the walker-only harness, `Evaluator.evaluate`), and with the fallback enabled or disabled (decision step 6) |
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
| `MAX_CERT_BYTES` | 262144 | per-certificate DER size (measured max over the seed corpus with margin), of `getEncoded()` before any parse and again of the bytes read (§5.3, §9.2); a larger certificate is a dropped candidate (`candidatesDropped`; leaf: `PARSE_FAILED(OVERSIZE)`); §9.2 fuzzes to the cap + 1 and asserts the over-cap behaviour |
| `MAX_FILTER_BYTES`, `MAX_JSON_BYTES`, `MAX_X5U_BYTES` | 16 MiB, 4 MiB, 64 KiB | caps for **unsigned** bodies (the changeset JSON itself, x5u; a stored or seed `index.bin` is read only up to 1 MiB, §3.2); for a `SIGNED` attachment the cap is `min(attachment.size, MAX_FILTER_BYTES)` (hash and size both verified; a signed record declaring more is `SyncOutcome.FAILED` with `CAP_NEAR_LIMIT` (stage `ATTACHMENT`) and advances nothing: a 16 MiB freeze is recoverable by raising the cap, a crash loop from one bad signed record is not); enforced while inflating; bodies are fetched, verified and written **one at a time**, so heap peak is one body plus its decode |
| `MAX_CHANGESET_RECORDS` | 256 (Remote Settings listed 53 records a channel on 2026-11-12) | record cap per changeset after channel filtering; a changeset over it is rejected before any body fetch. There is no per-sync total (neither upki nor Firefox has one), so a sync is bounded by these counts and the per-file caps, about 4 GiB from a malicious mirror (256 × 16 MiB), which is accepted |
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
     chainHash = sha256(for each cert in order: u32be(len) ‖ DER); host' = host (argument, socket.handshakeSession.peerHost or engine.peerHost) with ASCII A–Z folded to lowercase, never Unicode case folding (RFC 4343), and one trailing dot stripped, applied once (it is not idempotent) when ExemptionContext.host is filled; an empty result is no host
     (policy, policyEpoch) = the pair step 0 read, else one @Volatile read now; threaded through steps 3, 7, 8, the exemptions and the cache put
     (shadowPolicy, shadowPolicyEpoch) = likewise, read beside the policy pair at step 0 or here; threaded through step 3a and the cache put
     for a Socket or SSLEngine overload: acceptanceMemo.put(chainHash, host')   // flow step 1 returned, so the platform accepted this chain and host; written before any lifecycle or Enforcement check (under OFF, in CREATED and in CLOSED the write still happens right after flow step 1)
     index = trustManager.candidateIndex (the one @Volatile read of the anchor snapshot per handshake; its id is anchorSnapshotId; decision step 1 uses this reference and performs no read of its own)
     verdictCache[(chainHash, host', gen.epoch, anchorSnapshotId, policyEpoch, shadowPolicyEpoch)]?.let { return apply(it) }   // no parse, no event; counters (evaluations, fired, exempted, rejects/wouldRejects, shadowWouldRejects, per-dataset and per-reason maps) advance exactly as on a miss; verdictCacheHits++; the Android 3-arg overload still calls the extension for its return value
     pathKey = (chainHash, anchorSnapshotId, host' if step 4 would run on this platform and host' != null)
     walk = pathCache[pathKey] ?: decide(chain, index).also { cache unless decide threw or step 6's build threw }               // decide = decision steps 1–6 only (the path result; no CRLite query, so the path cache is valid across installs)
  3. verdict = evaluate(walk, gen, policy)                                                            // decision steps 7–8; the enforced catch boundary closes here: the verdict is final before any event work
  3a. shadowVerdict = evaluate(walk, gen, shadowPolicy) under its own boundary (the §5.5 catch rule) when set, skipped (null) when verdict carries EngineError(BOUNDARY)   // after the enforced boundary closed: a throw yields a shadow Verdict carrying Finding.EngineError(BOUNDARY) and never touches `verdict`; verdictCache.put(verdict, shadowVerdict) unless `verdict` is ENGINE_ERROR or step 6's build threw (a throw's outcome is cached nowhere), with shadowVerdict stored as null when it is a shadow-only ENGINE_ERROR (never cached, counted once on this miss); counters (`rejects`/`wouldRejects`/`fired`/`exempted`, per-dataset and per-reason maps from `verdict`; `shadowWouldRejects` from `shadowVerdict`) are applied by `apply()` here, after 3a, never inside `evaluate`. Runs on every trust-manager path and in `Revokt.evaluate` (which shares the registry caches); `Evaluator.evaluate` evaluates the enforced policy only, `shadowVerdict` null
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
6. `fallback = pathBuilder.build(presented, anchors, now)` if the fallback is enabled and `presented.size ≤ FALLBACK_MAX_PRESENTED`,
   cached under the path key; a `build` that returns null, throws, or returns a path decide cannot use (empty, holding a
   null element, not starting with the presented leaf's bytes, with an intermediate that does not parse or is not a
   CA, or with a leaf-issuer key that cannot be read) is a **failed** fallback. A throw is caught here
   and is never an engine error, except that every `VirtualMachineError` other than `StackOverflowError` is rethrown,
   as at §5.5's catch boundary. A result produced by a throw is **not** cached, neither in the path cache nor, through
   its verdict, in the verdict cache (flow step 3a), so a transient error is not remembered; a null return is:
   - walk `NotFound` and the fallback finds a path → `Found([fallback], usedFallback = true)`.
   - walk `NotFound`, the fallback was **skipped** (chain too long) and the platform accepted in
     step 1 (or step 1 did not run: the walker-only harness and `Evaluator.evaluate`) → `PATH_BUDGET_EXCEEDED` with `endReason = COMPLETE` (the walk itself completed) and `FallbackNotUsed(SKIPPED)`:
     no honest Web PKI chain is longer than 8 certificates and unreproducible by the walker, and the
     server controls chain length.
   - walk `NotFound` and the fallback failed (`FallbackNotUsed(FAILED)`): on a trust-manager binding (and `Revokt.evaluate`, which always runs step 1), **any** such walk
     `NotFound` is `NO_ISSUER(PLATFORM_ONLY)`, whatever the walk recorded: the platform trusts a chain neither revokt's
     walker nor its PKIX builder can reproduce (divergent canonicalisation, constraints, verifier or anchors). The
     walker's own reason is kept in `Finding.Path.walkerReason`, and every recorded OID in an `UnsupportedAlgorithm`
     finding. In the walker-only harness and `Evaluator.evaluate` it is `NO_ISSUER(UNSUPPORTED_ALGORITHM)` when the walk recorded an
     own signature OID (`tbsSigOid`) in `unsupportedOids()`, in mozilla::pkix's order (`CheckIssuerIndependentProperties`
     runs before `VerifySignedData`):
     - every related candidate that is not an anchor, when explored, whether or not it verifies its child;
     - a node reached through the unrelated loop, when visited;
     - the leaf only once a related candidate was found for it (pkix's end-entity deferral), so a leaf presented
       alone is `NO_ISSUER(NO_CANDIDATE)`.

     A candidate's key or curve OID never counts. Otherwise it is `NO_ISSUER` with the walker's reason. A server can
     steer the reason there, which is why it is a reason of one rule and not a rule of its own; `walkerReason` keeps
     the walk's reason.
     Unlike pkix, there is no collapse to one error when candidates fail differently.
   - walk `Budget`: the fallback path's issuer key (appended last) and the walk's partial leaf keys
     are evaluated in step 7 **only so that `REVOKED` is reported when reachable**; the path status
     is `PATH_BUDGET_EXCEEDED` regardless; `usedFallback = true` when a fallback path was evaluated.
   - **fallback disabled** (`pkixFallback(false)`, and the walker-only harness's disabled path):
     `pathBuilder.build` is never called, and step 6 gives what the branches above give when no fallback path
     exists, with `FallbackNotUsed(DISABLED)` wherever the fallback did not run because it is configured off
     (`SKIPPED` is the enabled, too-long case only). Walk `Budget` → `PATH_BUDGET_EXCEEDED`, the same
     as with the fallback enabled, with only the walk's partial leaf keys evaluated and `usedFallback = false`; walk
     `NotFound` with `presented.size > FALLBACK_MAX_PRESENTED` → `PATH_BUDGET_EXCEEDED` with `endReason = COMPLETE`,
     whether or not step 1 ran; any other walk `NotFound` → `NO_ISSUER`, its reason under the
     fallback-failed branch's rule. On a trust-manager binding any such walk `NotFound` is `NO_ISSUER(PLATFORM_ONLY)`,
     whatever the reason: the platform trusts a chain the walker cannot reproduce, and no PKIX builder ran;
     `walkerReason` keeps the walker's reason.
   - **The fallback finding**: exactly one `Finding.FallbackNotUsed` when the walk ended `NotFound` or
     `Budget` and no fallback path was evaluated (`usedFallback = false`), on every branch above: `DISABLED` with the
     fallback disabled; else `SKIPPED` when `presented.size > FALLBACK_MAX_PRESENTED`; else `FAILED`. A fallback
     path evaluated, a walk `Found`, and every exit before step 5 carry none. It never changes the path status or a
     rule.
7. Data: the data rules (`NO_DATA` for each required dataset with no generation and not `pending`,
   never with a generation installed from a seed for that dataset; `STALE`) were computed from the generation
   snapshot (read at flow step 2) before decision step 1, outside the catch boundary (the one clock read is itself guarded: a
   throwing consumer `Clock` is `ENGINE_ERROR(BOUNDARY)`, never an escape), and are merged into every verdict whatever
   the path status or any exception. Then evaluate CRLite once per distinct leaf-issuer key; `REVOKED` wins; every evaluated key
   gets a `Finding.Crlite`; on `Budget` only `REVOKED` fires a rule, other results are findings only.
8. Rules fire from the path status, the CRLite results, the `DataState`s and an exemption that throws; outcomes from the
   policy; exemptions for fired exemptable `REJECT` rules; `Verdict.rule` is the first fired,
   non-exempted `REJECT` rule in `Rule.PRECEDENCE`; `rejects`/`wouldRejects` increment once on it;
   `fired` and `exempted` increment per rule.
   **Steps 7 and 8, in detail**:
   - **Engine results:** an engine `ERROR`, or a published `NO_DATA` that does not fire `ENGINE_ERROR` (another key is
     `REVOKED`, for example), is recorded in that key's `Finding.Crlite`; `Finding.EngineError(ENGINE)` is attached
     only when `ENGINE_ERROR` fires from the engine.
   - **After a boundary catch** no exemption runs: exemptions completed before it stand, and the verdict is the rules
     fired so far plus `ENGINE_ERROR(BOUNDARY)`.
   - **`Verdict.dataStates`** covers `requiredDatasets` ∪ the snapshot's configured datasets, independent of the path.
     A required dataset the snapshot lacks gets `generationId` null, so `NO_DATA` fires.
   - **A throwing consumer clock** gives `ENGINE_ERROR(BOUNDARY)`, the path `NOT_WALKED`, `ageMillis` null and
     `stale` false everywhere (no `STALE`); `NO_DATA` is still computed, and no exemption runs.
   - **`engine.query` throwing** (a breach of its never-throws contract) is caught at the boundary: producer
     `BOUNDARY`, `engineName` null. Keys answered before it keep their findings and rules, and later keys are not
     queried.
   - **No key**: a decision whose status fires no rule of its own
     (`FOUND`, `NOT_WALKED`) and that has no leaf-issuer key is the boundary's `ENGINE_ERROR`, so an empty key set is
     never a clean answer. `Evaluator.evaluate` with a `verifiedPath` whose second certificate revokt cannot parse
     reaches it: the path is `FOUND` with no key.

| Overload | Who calls it | Waits? | Before readiness |
|---|---|---|---|
| `(chain, authType, Socket)` | OkHttp, HttpsURLConnection, Ktor OkHttp/Android; Conscrypt's `ConscryptEngineSocket` forwards here | yes | waits |
| `(chain, authType, String host)` 3-arg | OkHttp's Android chain cleaner, lazily after the socket overload (flow step 1) | yes | its step 1 is defined at flow step 1: the extension call with host', with the null-host retry only for a chain and host a socket or engine overload already accepted (acceptance memo entry present, flow step 1; never a path-cache lookup); at most two platform validations per call, the second only the null-host retry, the last one's returned list being the call's return value and its step-4 result; declared on the final `RevoktTrustManager` in `revokt-jsse` (`revokt-android` cannot subclass it); on the JVM, where `verifiedChain` is null, it returns the presented chain as a list |
| `(chain, authType, SSLEngine)` | `java.net.http`, Netty, Ktor Java | no | seed if loaded; while the start task has not passed the seed step the dataset is `pending` and `NO_DATA` does not fire (allow), so the Android seed load never rejects on a non-waiting overload; `NO_DATA` only once the start task found nothing local; the anchor snapshot always exists in `STARTED` |
| `(chain, authType)` 2-arg | Ktor CIO, casts to `X509TrustManager` | no | as above; step 5 runs via `reconstruct` |

**Lifecycle.** `RevoktLifecycle`: `CREATED → STARTED → CLOSED`; `start()` and `close()` are
idempotent; `start()` after `close()` throws. **`start()`, synchronous on both platforms** (may throw;
performs small disk reads, calls each delegate's `getAcceptedIssuers()` and takes the factory lock
and the store lock, so call it off the main thread or under `StrictMode.allowThreadDiskReads`;
`seed.json` is the first, stored entry of the seed zip's central directory, §6.5, so the header read is a few small reads: the end-of-central-directory record, the central directory, then the first local header). **The
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
`previous` → nothing, each `storeFailures++`), verify and install the seed (unless `start()` already did so synchronously, §4 S bullet) under the **seed-load rule**
(§6.5: skipped beside a trusted pointer whose `live` generation is not older, a newer complete generation adopted
when no pointer can be trusted; the watermark becomes `max(watermark, seed timestamp)` taken from the verified
`records.json`; a blob whose key exists and re-hashes to its name is never rewritten, a mismatch rewritten from the seed,
`storeFailures++`), schedule the first sync (under a persisted `backoffUntilMillis` it runs at once and completes as `BACKOFF`, setting `lastSync` and both `lastAttemptAtMillis` fields (per source and `datasetLastAttemptAtMillis`), then reschedules at the backoff). The JVM `start()`
joins that task up to `awaitData` (after the factory lock is released) and then returns (the
readiness future covers the rest); Android returns after the synchronous part without joining the
loader and its waiting bindings cover the gap; while `STARTED`
the loader is the only publisher of the generation reference. The loader thread is a daemon named
`revokt-loader-<identity or build sequence>` (two channels in one process are told apart). The loader runs under every `Enforcement`, `OFF` included, so a runtime flip is
immediate. An explicit `sync()` queues behind the start task and any in-flight install, ignores
the poll interval and honours `backoffUntilMillis` (`BACKOFF`).

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
duplicate is yielded once, at the earliest position in the node's order: the store position for a duplicate of
an anchor, since anchors come first at every depth, and in M2 the presented position for a duplicate of a preload
certificate, since presented certificates come before the preload**). A candidate may be deferred
or capped only by its own relation to the child. A candidate is **related** when its subject equals
the child's issuer (raw bytes, or under `canonicalSubject`, which on the JVM and Android is the
platform's own `X500Principal` canonical form) or its SKI equals the child's AKI `keyIdentifier` (an
AKI carrying only the issuer-and-serial form, or an issuer without an SKI, makes the test name-only).
Every honest issuer is related under the platform's own canonicalisation, which is why the engine
delegates canonicalisation to the platform; on both default delegates every honest issuer is
therefore related, and the misclassification residue is confined to custom delegates whose name
equality differs from `X500Principal`'s. **Unrelated candidates are the presented certificates not
related to the child**, are explored only while no path exists through the node (checked before
every candidate), and are not capped; **at the leaf, the unrelated loop runs regardless of `foundHere` when
`CandidateIndex.customCanonicaliser` is set** (`platformTrust` is not one of the two shipped final classes, or the delegate is not `platformTrust.defaultDelegate()`; §3). Otherwise an honest issuer misclassified as
unrelated could be hidden by a related decoy path (§10 residual 1). **It also runs regardless of `foundHere` when no
related path exists at the leaf**: every unrelated certificate that verifies the leaf and terminates
is then collected, so `leafKeys` does not depend on the presented order and every such key is evaluated. In both
cases `unrelatedExploredAtLeaf ≤ presented − 1`, each subtree stays under `MAX_VERIFICATIONS` and `MAX_EXPLORED`, and
P6 holds on the default delegates, where an honest issuer is always related. Store certificates are never unrelated candidates.

*Termination rule.* At the leaf, every related candidate is explored, so every related key that verifies the leaf
and terminates is collected; every unrelated one is too when no related path exists there or under a custom
canonicaliser; below the leaf, the first sound path through a node
suffices in M1 (M2 re-walks exhaustively when a layer hits, under the re-walk rule of step 8: fresh
budgets, shared memo, never demoting the first walk's `Found`). **Any limit exceeded at any node
aborts the whole walk with `Budget`**; only `MAX_DEPTH` is a local dead end. `Found` is returned
only when the walk completed without exhaustion; a `Budget` may carry partial paths.

*Why this is sound.* Every path member below the leaf that is not an anchor must be a CA: its one basicConstraints
extension reads `cA = TRUE`. An absent, FALSE or unreadable basicConstraints is a dead end before the link is
verified, as webpki (`EndEntityUsedAsCa`) and mozilla::pkix (`CheckBasicConstraints`, `ERROR_CA_CERT_INVALID`)
require of an issuer. Anyone can obtain an end-entity certificate under a real anchor, and its key can sign a
certificate for any other key, a recovered one included; the CA check removes that route. A recovered key can then
terminate only through a certificate chain that a holder of a CA key under a real anchor signed. An
`UNSUPPORTED` link is never trusted. Nothing is excluded for a shared property, so a
same-key decoy or a cross-certificate to a non-anchor listed first cannot hide the real certificate,
which is related and is explored. The honest issuer's key is the only key that verifies a
real leaf's signature, other than a recovered key. A recovered key terminates only through CA certificates up to a
real anchor, so a `Found` carrying only benign keys needs the cooperation of some CA key holder under a real anchor
(§10 residual "constrained sub-CA"). Stuffing related junk past the cap, or verifying junk past the
guards, yields `Budget`, which rejects; an exhaustion in any subtree also yields `Budget`, so a
stuffed subtree cannot starve the honest key out of a `Found`. Every terminating
leaf-issuer key is evaluated and `REVOKED` wins. The PKIX fallback covers one residue the walker
does not: a `NotFound` on a chain of at most `FALLBACK_MAX_PRESENTED` certificates whose honest link
the walker could not reproduce (a custom delegate's constraints or verifier divergence; canonicalisation alone never yields `NotFound`, §10 residual 1). Beyond the
guards the walk is `Budget`, which rejects whatever the fallback does, and a `NotFound` too long for
the fallback is `PATH_BUDGET_EXCEEDED`. A policy may not disable the fallback while `NO_ISSUER` allows.

The pseudocode of `reconstruct` is explanatory, not normative: [docs/design/walker-pseudocode.md](../design/walker-pseudocode.md). The code and the §9.1 properties are normative.

- **Explored** means the walker requested the candidate's verification (memo hits included);
  **verifications** counts calls into the injected verifier. `related` counts related candidates
  for which exploration was requested at that node; exactly 64 completes, the 65th aborts.
- **Cost.** An honest leaf → I → root chain: at the leaf, related = I (one verification, recurse);
  at I, related store-first = the store anchor (one verification, terminal, stop). Two
  verifications. A presented cross-certificate of the root sorts after the store anchor and is never
  reached below the leaf once the anchor verifies, and even when reached it is a memo hit (same key); a root-issued
  leaf is one verification, or two when a cross-certificate X of the root is presented and its issuer R′ is in the
  snapshot: every related candidate is explored at the leaf, so the walk is L/R, then an L/X memo hit, then X/R′
  (depth + 1 on the path found); a chain whose snapshot holds the other root of a cross-sign costs
  depth + 1 (three). A verifying decoy costs one extra verification per presented certificate not on
  the path, since the unrelated loop runs at every node without a path. Honest bound: **≤ depth + 1**;
  fixture (v) asserts ≤ 4 against a 200-anchor snapshot. **Worst case is bounded by `MAX_VERIFICATIONS` and `MAX_EXPLORED`, not by the
  per-level cap**: a nested subtree of verifying junk (RSA duplicate-signature keys make junk verify)
  can reach the guard in two levels, about 250 ms of RSA-4096 verification on a mid-range ART device,
  and ends in `Budget`, never an allow. Per-candidate sub-budgets treated as dead ends must not be
  introduced: they would let a stuffed subtree starve the honest key out of a `Found`.
- **Findings.** `AlgorithmIdMismatch` comes once per presented certificate that `decide` parsed, which at the
  step-2, `PRODUCER_UNKEYABLE` and `MAX_PRESENTED` exits is the leaf only; the parser computes its flag
  after NULL/absent normalisation (none for a certificate read through the §9.2 platform canon whose TBS
  AlgorithmIdentifier is minimal DER), and `decide` derives the finding from that flag. Only `VerifierError` rides on
  the `Walk`; its `oid` is the child's TBS signature OID, `""` when the TBS AlgorithmIdentifier does
  not decode.
  `UnsupportedAlgorithm(oid, PATH, outcomeDepended)` is emitted once per OID in `Walk.unsupportedOids`
  on **every** outcome, with `outcomeDepended = (noIssuerReason == UNSUPPORTED_ALGORITHM)`; fixture (n) asserts the
  `false` case on a `Found`.
- **PKIX fallback contract** (`PathBuilderFallback`; the fallback re-parses the snapshot's anchors' `getEncoded()` with `CertificateFactory` once per `AnchorSnapshot.id`, memoised, and its `CollectionCertStore` holds every presented certificate): result lists the leaf first and **appends the
  trust anchor's certificate**; the leaf must be in the `CollectionCertStore`; one base
  `PKIXBuilderParameters` per snapshot, `clone()` per call; `CertPathBuilder.getInstance("PKIX")` per
  call; `setRevocationEnabled(false)`, `setPolicyQualifiersRejected(false)`, `setDate(now)`,
  `X509CertSelector().apply { certificate = leaf }`; Android resolves to ojluni's `SunCertPathBuilder`
  with Conscrypt doing signatures. The builder verifies every link under the platform's providers,
  so its path satisfies the invariant's intent. Every certificate of a returned path between the leaf and the anchor must
  be a CA under RFC 5280 basicConstraints (`cA = TRUE`), as `CertPathBuilder("PKIX")` requires; decision step 6
  checks it again, so a path with an intermediate that does not parse or is not a CA is a failed build,
  `FallbackNotUsed(FAILED)` (the JDK's builder already enforces it, so only a consumer builder is affected); `jdk.certpath.disabledAlgorithms` and provider
  divergence from the delegate fail the build, and like every failed build (null or a throw) are reported as
  `Finding.FallbackNotUsed(FAILED)` and surface as `PLATFORM_ONLY` on a walk `NotFound` at a trust-manager binding.
  It is skipped above `FALLBACK_MAX_PRESENTED` presented certificates (no candidate
  budget; exponential on stuffed chains) with `FallbackNotUsed(SKIPPED)`, which cannot change
  a `Budget` outcome. With `pkixFallback(false)` it never runs, and step 6 reports `FallbackNotUsed(DISABLED)`
  instead.

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
fetching source (`remoteSettings`) is configured; a failure there is the
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
fetcher policy (§8), never waits, and runs step 2 from M1 against the installed generation.

`checkClientTrusted` and `getAcceptedIssuers` delegate to the platform unchanged.

**Moved to design notes** (not normative before 0.3): "Trust managers per delegate" and "Caches"
([trust-managers.md](../design/trust-managers.md)); "Readiness", "Read-only mode" and "Storage fallback"
([readiness-and-store-modes.md](../design/readiness-and-store-modes.md)); "Listeners"
([listeners.md](../design/listeners.md)); "HTTP/2 coalescing" ([okhttp-and-ktor.md](../design/okhttp-and-ktor.md)).
A reference in this file to one of these names that note.

### 5.2 Android (`AndroidPlatformTrust`)
Not normative before 0.3: [docs/design/android.md](../design/android.md).

### 5.3 JVM (`JvmPlatformTrust`)
- Default delegate: SunJSSE's `X509ExtendedTrustManager`. `requiresExtendedDelegate()` is **true**
  for every JVM binding (SunJSSE's `AbstractTrustManagerWrapper.checkAdditionalTrust` applies algorithm constraints on both the socket and the engine path and endpoint identification on the engine path; fronting a plain delegate removes them).
- `pathBuilder` is `CertPathBuilder("PKIX")`; `PlatformTrust.canonicalSubject` defaults to `X500Principal.getName(CANONICAL)`,
  which is what SunJSSE's `X500Name.equals` compares. Every M1 chain is `RECONSTRUCTED`.
- Certificates are read through the §9.2 read fallback where the engine parses them: `getEncoded()`, or the platform
  canon where revokt's parse of that is `ParseFailed(STRUCTURE)`. Presented and platform-built certificates are read
  inside `decide`: the leaf at decision step 2 (one certificate, whose parse step 3 reuses), the others after step 3's
  `MAX_PRESENTED` and `MAX_PRESENTED_BYTES` checks; anchors when the `AnchorSnapshot` is built (`start()`,
  `refreshAnchors()`). The identity keys stay over `getEncoded()`: `chainHash` and with it the verdict-cache,
  path-cache and acceptance-memo keys, which on a fixed JDK determine the bytes read. The bytes read are the
  certificate's DER only where the engine needs it: `Cert.der` and `bytesHash`, the anchor-by-bytes check,
  `reportedPathSha256s`, `anchorSha256`, `AnchorSnapshot.sha256`, `PresentedChain.der` and `MAX_CERT_BYTES`, which is
  checked on `getEncoded()` before any parse and again on the bytes read. The PKIX fallback is given the platform's
  own anchor objects' `getEncoded()`.

### 5.4 Ktor engine caveats (verified against Ktor 3.6.0 source)
Not normative before 0.3: [docs/design/okhttp-and-ktor.md](../design/okhttp-and-ktor.md).

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
is published; with `engineName`, the engine's `RevocationEngine.name`), and an exemption that throws;
each attaches `Finding.EngineError`. **Interrupts** (JVM): at every catch of consumer code (verifier,
canonicaliser, fallback, exemption, logger, a throwable's `toString`, the install self-check's engine `query` and
`coverageEndMillis`) and at the boundary, a caught `InterruptedException` sets the thread's interrupt flag again. The
fetch timeout path keeps its own interrupt handling.

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
query(q): if q.scts.isEmpty(): return NO_SCTS   // revokt's parser passes an empty list when no SCT extension's list parses under §9.2 (§3.2, §6.1; §10 item 7); never reaches a filter
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
- **Decode strictness, stated per rule** (decode-only; a violation is `SyncOutcome.FAILED`, never a verdict): v3 trailing bytes are accepted (bincode 1.x legacy `deserialize` allows them), v4 trailing bytes rejected; a row window past the end of a column reads as zero (C2SP lets a builder omit trailing all-zero words; `Equation::eval` bounds the same way), so `offset + 256 > 64·words` is **not** rejected; `rank > columns` is rejected at `prepare()` (unchecked by `clubcard-crlite`, where it panics → upki `ENGINE_ERROR`); `inverted ∉ {0, 1}` is rejected (C2SP MUST; `clubcard-crlite` reads `!= 0`); a v3 filter is held to v4's ranges:
`approx_m`, `exact_m` and both offsets fit `u32`, the rank and the column count fit `u8` (≤ 255),
and no other v4 limit is imposed on v3; the sorted-index and distinct-log-id MUSTs are checked. The resulting decode-only asymmetries against upki are recorded in the cross-engine suite as `FAILED`-vs-loaded, never as verdict classes.
- **Observed 2026-10-21:** Mozilla serves v3 on both channels; `upki.rustls.dev` serves a v4 transcode.
- **Validated 2026-10-21:** prototype matched `clubcard-crlite 0.6.2` on 43,510 / 43,510 queries.
- **Coverage sanity at install**: coverage `high` later than the signed
  record's `last_modified` + `clockSkew` is rejected (`SyncOutcome.FAILED`, stage `INDEX`; cursor and watermark unchanged); **inside the rollback window** (changeset
  `timestamp ≤ watermark`; **the effective watermark** is max(the stored watermark, the live generation's
  `sourceTimestampMillis`), except while that generation is `clockBehind`, when the stored one alone applies,
  so a malformed or absent `updater.json` beside a live
  generation cannot reopen a rollback, and a far-future `clockBehind` generation cannot freeze the feed) a
  maximum coverage below the active generation's is
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
  cursor stays, so the next poll re-fetches from the last verified cursor (§7.1; a 200 with a full body every poll
  while the clock is behind, the accepted cost) and finds the same changeset
  **`UNCHANGED`-by-timestamp**: a verified changeset whose signed `<ts>` equals the live generation's
  `sourceTimestampMillis` is `UNCHANGED`, updating the attempt fields only, and that test precedes the
  `CLOCK_SKEW` test; "the live generation is `clockBehind`" is recomputed at the sync decision as
  `sourceTimestampMillis > now + clockSkew`, never read from the last publish, so a clock corrected
  between publishes closes the carve-out at once). The timestamp compared everywhere here (watermark, coverage
  bound, `CLOCK_SKEW`) is the signed `<ts>`, the value the verified payload was built from (§7.1; a live sync's
  envelope `timestamp`, a seed's `records.json` value), never `monitor/changes`' unsigned `last_modified`.

**Hardening**: every length and offset checked before allocation with an explicit allocation budget
per decoder; filenames validated against `^(?!\.{1,2}$)[A-Za-z0-9._-]{1,64}$` (today's attachment names are 31 characters; a three-digit daily index must not fail the rule; a name longer than C2SP's 32 bytes is renamed in `index.bin`, §6.5) and never a reserved name (`index.bin`, `meta.json`, `records.json`, `current`, `updater.json`, `store.version`, `.lock`; `index.bin` among them since a filter of that name cannot sit beside the index in a C2SP image; a mirror's manifest names are compared with them ignoring ASCII case, §7.3); downloads capped at `min(attachment.size, MAX_FILTER_BYTES)` for signed bodies and at the per-kind fixed cap for unsigned bodies (§5.1 limits).

### 6.4 Filter storage
`LongArray` columns padded with one zero word in an immutable `Generation`. No mmap.

| Channel | Full | Resident, 8 deltas | Resident, 52 deltas (measured) | Load, JIT-compiled | Load, interpreted |
|---|---|---|---|---|---|
| `compat` | 1.57 MB | ~2.5 MB | 8.56 MB (8,558,354 B) | ~5–10 ms | ~50–100 ms plus seed verification |
| `default` | 6.0 MB | ~7.8 MB | 18.59 MB (18,593,366 B) | ~15–30 ms | ~150–300 ms plus seed verification |

The measured column is the sum of the signed `attachment.size` values per channel in the live
`cert-revocations` changeset of 2026-11-12 (`timestamp` 1794499022363, 106 records: per channel 1 full and 52 deltas;
deltas average 134 KB on `compat` and 242 KB on `default`; Appendix A). The delta count varies: 8 per channel on
2026-10-21, 52 per channel on 2026-11-12.
`MAX_CHANGESET_RECORDS` (256) admits a full and 255 deltas, about 68 MB at `default`'s ~242 KB a delta; no per-sync
total caps it, only the count and the per-file caps.

Baseline Profile covering the decoder, seed verification, the TBS parser, the walker and `evaluate`,
with `androidx.profileinstaller` as `api`. `AWAIT_DATA_<CHANNEL>` from a physical ARM device at API
26 without a profile, including the `start()` anchor build, with a ceiling; on the JVM both constants
are a fixed 2 s.

### 6.5 Store, persistence and seeds

**Layout over `RevoktStorage`'s key space** (each generation is materialisable into a C2SP directory
image). **A file's name in a generation** is derived from its §6.3-validated Remote Settings
`attachment.filename`: the
filename itself when it is at most 32 bytes (a C2SP filename: 1 to 32 bytes of
`[A-Za-z0-9._-]`), otherwise its first 15 characters, `-` and the first 16 lowercase hex characters of the SHA-256 of
the filename's ASCII bytes (not `attachment.hash`), 32 characters in all, since §6.3 admits names of up to 64
characters and C2SP up to 32. That name is the file's name everywhere in a generation: `index.bin`,
`GenerationFiles.names`, the generation directory and `meta.json`. The attachment filename appears only in the signed
records (`records.json`); a seed's
`attachments/<f>` entry keeps the attachment filename f, is looked up by it (Seed archive, below) and is mapped by this
rule at load. Two attachments that map to one name
fail the generation before any body is fetched: `SyncOutcome.FAILED` with
`INDEX_INCONSISTENT`, stage `INDEX`, and `SEED_UNREADABLE` for a seed (`buildIndex` refuses it). `meta.json` maps each
name to its blob. Path segments for dataset and channel are lowercase enum names; persisted enum
values are names, never ordinals:
- `store.version`: integer, `1` in 0.3, read before anything else; an empty store is initialised
  silently by the owner (never by a read-only instance); a non-empty store with a missing or **lower** version is treated as empty and rebuilt
  (`STORE_MIGRATED` warning, a planned migration, not a corruption alert, `storeFailures` unchanged; the rebuild writes `store.version` first, then deletes every other key `names()` lists, then runs the start task as on an empty store, so an older co-tenant cannot mistake a half-written new layout for its own empty store and no old-layout `current` or `updater.json` survives), never an error and never `NO_DATA` beyond what an
  empty store already implies; a **higher** version is `STORE_NEWER_LAYOUT` and follows the storage's `NewerLayout` (§3): `IN_MEMORY` (the `JvmStorage` default: a newer co-tenant's store is left untouched, the store lock taken by `start()` is released, the identity deregistered, and the instance runs on the in-memory fallback, `RevoktState.storageFallback`, which for this code is never retried) or `REBUILD` (the `AndroidStorage` default: one package owns its directory and Android kills every process of the package on replace, so a higher version there is a rollback of the binary and is rebuilt exactly as a lower one).
- `<dataset>/<channel>/current`: a small pointer file `{live, previous}` naming generation
  directories, read strictly: a JSON object of `live` and an optional `previous` and no other member, anything else
  being malformed. `previous` is only ever a complete generation that reads back as the loader reads one
  (`records.json` included), so recovery never falls to a generation that cannot load; a candidate that does not read
  back counts a store failure.
  **Beside a `current` that is present but malformed**, which may name any directory, a generation directory whose
  `meta.json` is present is held: a complete one is compared, reused when it holds this generation, and never
  reopened, rewritten or deleted; one whose `meta.json` is malformed (a torn write, or another `metaVersion`) is
  kept, and the sync is `STORE_FAILED` at that `<ts>`, which a new `<ts>` heals. Only a directory with no
  `meta.json` (incomplete, or not yet written) is staged. When an install flips beside a malformed pointer, the new
  pointer's `previous` is the generation the running loader's engine held live, if that generation is complete, is
  and is another directory; a fresh loader has no `previous`. A flip that heals a
  malformed pointer is not followed by a prune, so nothing the damaged pointer named is deleted; the next install over
  a valid pointer prunes.
- `<dataset>/<channel>/gen-<timestamp>-<hash16>/` (`timestamp` = `sourceTimestampMillis` zero-padded to
  13 digits so lexical order is chronological; `hash16` = the first 16 lowercase hex characters of
  `SHA-256(generationId)`; `generationId` itself may contain `/`): immutable; `index.bin`, delta files, `records.json`, and `meta.json` **written last as
  the completeness marker** (engine's own JSON tree): `metaVersion`, `dataset`, `channel`,
  `generationId`, `format` (the full filter's encoding; each filter is read in its own, so a channel
  may mix encodings, as Firefox's cert_storage and upki allow),
  `freshness`, `sourceTimestampMillis`, `collection`, a map from
  each full-filter name to `blobs/<sha256>`, and the changeset timestamp, signer leaf
  SHA-256 and signature bytes (the raw pair, any non-empty even length, since §7.1 admits any EC leaf curve), all
  three required: a `meta.json` without them is malformed. A `channel` mismatch is no generation.
  A generation directory also holds `records.json`, the full verified record set (the same bytes as the seed's `records.json`: the canonical-JSON signed payload), so a
  `_since` changeset can be verified against it (tombstones merged) without a full re-fetch. A `_since` changeset is
  merged over the pointed generation's `records.json`; the whole collection, fetched with no cursor, is verified as
  served.
- `<dataset>/<channel>/blobs/<sha256>` (64 lowercase hex): content-addressed full-filter files referenced from
  `meta.json`; when the key exists the stored blob is re-hashed and reused on a match (a mismatch rewrites it, `storeFailures++`; on the delta path, where the full is not being fetched, the full attachment is fetched again in the same sync, subject to the metered rule), so a daily delta install never rewrites the 6 MB full and a bit-rotted blob is never decoded; prune removes unreferenced
  blobs. The upki CI adapter materialises a C2SP directory image from a generation (it already
  copies into a fresh directory, §3.2).
- `<dataset>/<channel>/updater.json`: **the rollback watermark is per dataset and channel, stored once outside the per-source map** (the effective watermark is floored by the live generation's timestamp unless it is `clockBehind`, §6.3; a malformed file's dataset-level members are read as absent and count a store failure, so the floor applies) together with `seedInstalledAtMillis` (written with the watermark when the seed install flips the pointer) and a dataset-level `datasetLastAttemptAtMillis` (written at the end of every sync whatever its outcome, with two exceptions: `STORE_LOCKED`, and a sync whose read of
  `updater.json` threw, which writes nothing; the §8 `STALE` gate; the loader evaluates the gate when it writes this file and carries the boolean in the published `DataState`, internal field, so handshakes read the snapshot only, never the store) (a changeset installs only if its timestamp passes the dataset watermark, whichever source delivered it, so a relabelled `sourceId` on a private mirror cannot start a fresh watermark and roll back; the coverage-monotonic bound is the live generation's maximum coverage, read from the published generation, never from this file); the per-source map is keyed by a **stable source id** (not the URL, so overriding a
  base URL keeps the cursor): `lastVerifiedLastModified` (the `_since` cursor),
  `lastVerifiedAtMillis`, `lastAttemptAtMillis`, `backoffUntilMillis` (clamped to now + `MAX_BACKOFF` on write and again on read, so a clock that was far ahead at write time cannot leave a years-long backoff),
  `consecutiveFailures`, `feedHostBlock: {sinceMillis, chainSha256s}` (the §8 signed-source hold, **per source, not per chain**: `sinceMillis` is set on the first `BLOCKED_BY_SELF` of any host of the source and cleared only by a hit-free sync that completes after `sinceMillis + FEED_HOST_HOLD`, never earlier and never by an install alone, so an episode lasts at least the hold and expires exactly once (an alternating hit/clean chain cannot reset it); `chainSha256s` is the set of hit chains, for reporting; the hold is measured from the persisted value, so restarts do not extend it; with `RevoktStorage.inMemory()` it restarts per process); written atomically. A sync whose read of `updater.json` throws
  writes nothing to it: no attempt is recorded, `consecutiveFailures` does not rise and no backoff is written;
  `storeFailures` is the only persisted signal (the sync still returns `STORE_FAILED` with `SYNC_FAILED`). **The cursor, `lastVerified*`
  and the watermark advance only after the pointer flip of a successful install** (one carve-out: the §6.3 clock-behind install advances `lastVerifiedAtMillis` only); a failure-path
  write (`consecutiveFailures`, `backoffUntilMillis`) leaves those three untouched; [0.3] `UNCHANGED`
  against the pointed generation rewrites the file (repairing a crash between flip and write); in 0.2, whose store is
  in memory, `UNCHANGED` writes only the attempt fields, the `consecutiveFailures` reset and the backoff headers'
  effect (§7.1). The
  delta parent is derived from the pointed generation's `meta.json` at `start()`, never from this
  file.
- **Prune keeps exactly the directories the pointer names** (`live`, `previous`) and deletes every
  other directory, complete or not, and every unreferenced blob; it runs at `start()` and after every `INSTALLED`
  sync but one whose flip healed a malformed pointer, never after a failed one; on a failed `prepare()`, self-check or `activate()` the loader deletes
  the directory it was given before returning (blobs stay, content-addressed); an interrupted install
  (process death; no `meta.json`) is deleted by prune at the next `start()`; a sync-time `prepare()`/`activate()`
  throw and a self-check mismatch increment `storeFailures` and are `SyncOutcome.FAILED` (stage `PREPARE`, `ACTIVATE` or `SELF_CHECK`; cursor and watermark do not advance, so the same changeset is retried under backoff); a store write or pointer-flip failure during an install is `SyncOutcome.STORE_FAILED` (stage `STORE`, `storeFailures++`); "newest" is pointer order, never directory timestamp.
**Order of an install** (an *install* anywhere in this document means this whole sequence): fetch, verify and write **one body at a time** (hash against the signed
record, write the blob unless the key exists, drop the body) → build `index.bin` (≤ 1 MiB, §3.2) → the format check (on every placed filter, the full
and each delta, each in its own encoding; a filter whose encoding the engine does not list fails the install,
`FAILED`, `FORMAT_UNSUPPORTED`, stage `PREPARE`, §3.2, the previous generation stays live, and nothing is offered to
`prepare`) →
write the generation
directory (`meta.json` last) → `prepared = engine.prepare(files)` (validates and decodes into an inactive
state; the live generation is untouched) → **engine self-check on `prepared.query`** (deterministic,
never probabilistic, every input named: the absent issuer hash is `SHA-256("revokt-self-check")`,
incremented in its last byte until absent from every filter's index; the inside SCT is (`logId`, `low`)
of the first coverage entry of the filter under test in `index.bin` order; the outside probe is
(`logId`, `high + 1` unsigned, or `low − 1` when `high` is the maximum); filters are iterated in
`index.bin` order and index entries by ascending issuer hash, so "some block" is reproducible. The absent
issuer hash with the inside SCT must answer in the `NOT_ENROLLED` class (`{NOT_COVERED, NOT_ENROLLED,
NO_SCTS}`, the equivalence class of test-plan.md §9.3, so the upki engine passes); the outside SCT must answer
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
the verdict-cache TTL) → flip the pointer → write `updater.json` → prune (after every `INSTALLED`, once the flip and `updater.json` are written, never after a failure, as upki deletes
after a successful plan and Firefox drops old deltas when a new full installs). Decision step 7 never queries an
engine for a dataset whose snapshot has no generation; `CrliteQueryResult.NO_DATA` from an engine
while the snapshot holds a generation for that dataset is reported as `ENGINE_ERROR(ENGINE)`, never
as nothing, so an injected engine's install failure is visible, not silent (in `DEFAULT` it allows, loudly). **Every loader task catches `Throwable`**: an `OutOfMemoryError` during an install is `SyncOutcome.FAILED` for that sync, `storeFailures++`; nothing escapes the loader thread. **Crash recovery at
`start()`**: `live` → `previous` → seed (per the §5.1 rule) → nothing, each failure
counted. **The store is trusted
at the OS level**: a stored generation is not re-verified at load (the seed is, since it
ships inside the APK); `JvmStorage` enforces ownership and owner-only write permission on POSIX. Temp
names carry pid and random bytes and are excluded from `names()`; only the owning loader writes, under
the lock `start()` holds; readers re-read the pointer once on a missing key. Install-time memory peak
≤ 3× resident + one body; decoded immutable filters are shared across generations by
`GenerationFiles.sha256(name)`; decoding uses bulk
`ByteBuffer.asLongBuffer().get(LongArray)`. Allocation budgets per decoder: filter ≤ len + 1 MiB +
entries × 128 B; JSON ≤ 20·len + 64 KiB on any input, asserted on every fuzz and replay input, and ≤ 4·len + 64 KiB on
Remote Settings data, asserted on named fixtures (a committed CRLite-shaped changeset, and the pinned corpus's real
Remote Settings changeset in the corpus tier) (a tree with one object per value cannot hold 4·len on
every input, `[1.5,…]` alone needing about 6·len, and a bound needs a constant term); DER ≤ 2·len; asserted in the §9.1
replay by `com.sun.management.ThreadMXBean.getThreadAllocatedBytes` deltas (HotSpot), after one warm-up decode, on the same thread,
of a fixed small document that contains every value kind (for example `{"a":[0,-1.5e3,18446744073709551616,"é😀\u00e9\ud83d\ude00",true,false,null,{}]}`, covering exponents, negative and beyond-`Long` numbers, multi-byte UTF-8 and `\u` escapes with a surrogate pair), and of one fixed rejected input such as `[`
(the error path loads its own classes), so that per-process class loading does not count; every buffer a decoder keeps across calls counts toward its budget. The
transient worst case is therefore about 20 × `MAX_JSON_BYTES` (80 MiB at the default cap) for a changeset, which is
decoded before its signature can be checked (the signature is over the canonical form of the decoded records) and is
accepted: every loader task catches `Throwable`, an `OutOfMemoryError` included (above); a seed's `records.json` is verified as raw bytes
(the seed verifier hashes the file unchanged) **before** it is decoded: the signature over the file and the x5u chain to
the pinned content-signature root (signatures, names and every check except validity periods) pass first, and validity
periods are then checked at the decoded `<ts>` (§7.2), so only JSON signed under Mozilla's root is decoded inside
`start()`. The budgets are measured on HotSpot only; ART is not asserted.

**Seed archive** (`revokt-seed-<channel>`, weekly; **shipped by default**: `SeedSource.bundled()`, the builder default, resolves `/revokt/seed-<channel>.zip` from that artifact on the classpath, and the OkHttp and Android quickstarts declare the dependency): a zip with `seed.json` {`seedFormat`, `channel`,
`dataset`, `filterFormat`, `recordsLastModified`, `engineFloor`}, `records.json` (byte-for-byte the canonical-JSON signed payload `{"data": records sorted by id, tombstones removed, "last_modified": "<ts>"}`, so the seed verifier hashes the file unchanged; the `<ts>` inside it, verified, is the seed's timestamp for every rule below, the unsigned `seed.json.recordsLastModified` being a hint for the header read only), `signature` (the `signature` field as served, of the `metadata.signatures[]` entry that verified when the seed was
built, whose `x5u` body is `x5u.pem`: unpadded base64url of the raw r‖s pair, any non-empty even length, a
wrong-size pair failing verification, §7.1; for today's P-384 leaf the 128-character text of 96 bytes), `x5u.pem` (the x5u body as served, leaf first), `attachments/<f>`, `index.bin` (produced by one engine function `buildIndex(records, channel)` with entries ordered by `(effectiveTimestamp, record id)`, full before deltas; it places exactly the channel's one full filter, a channel with none or more than one being refused
(`SyncOutcome.FAILED`, `INDEX_INCONSISTENT`, stage `INDEX`, or `SEED_UNREADABLE` for a seed; the previous generation
stays live), plus every delta of the channel, ordered by time, without reading `parent`, as Firefox does (upki-mirror walks the `parent` chain instead, Appendix A; an extra delta can only add
revocations, so the rule fails closed); a placed filter that does not decode is `FAILED` at stage `PREPARE`; its
output bytes are frozen per `seedFormat`, a change bumps `seedFormat`, which is what makes the load-time byte compare valid across minors; the weekly job calls that function from the oldest supported minor). **Entry names** (a zip entry's name is outside the signature): the loader never derives a name or a path from a zip entry. It accepts exactly the fixed entries `seed.json`, `records.json`, `signature`, `x5u.pem` and `index.bin`, plus `attachments/<f>` for each §6.3-checked `attachment.filename` f of a record in the verified `records.json` that `buildIndex(records, channel)` places in the generation, and reads each entry by that exact name. The entries are the zip's central directory: every read goes through a central-directory entry whose local header names the same file, and the first entry is `seed.json`; otherwise the seed is `SEED_UNREADABLE`. A duplicate, extra or missing entry is `SEED_UNREADABLE`; an entry that differs from an expected name only in letter case is an extra entry, and so is a directory entry. The fixed entries are checked before any entry but `seed.json` is read, and at that check every name that is neither a fixed entry nor under `attachments/` is already extra; the attachment entries are checked once `records.json` is verified and before any of them is inflated. **Entry caps, enforced while inflating** (zip-declared sizes are untrusted; `fromResource`/`fromPath`/`of` accept any file, and the sole-seed `ENFORCE` path inflates inside `start()`, where an `OutOfMemoryError` would crash-loop an app): `records.json` ≤ `MAX_JSON_BYTES`, `x5u.pem` ≤ `MAX_X5U_BYTES`, each attachment ≤ `min(signed size, MAX_FILTER_BYTES)`, `index.bin` ≤ 1 MiB, `seed.json` ≤ 64 KiB, `signature` ≤ 64 KiB, and the whole archive ≤ 256 MiB (`SeedArchive.MAX_BYTES`, so a source that never ends fails closed); over any cap → `SEED_UNREADABLE`, never a store failure (§10 supply chain; `SeedArchiveTest`, `SeedLoaderTest`). **The zip the loader reads** (`SeedArchiveTest`, `SeedArchiveFuzzTest`): one disk, no zip64, an end record with no comment as the archive's last bytes, right after a central directory of at most 1 MiB and at most 5 + `MAX_CHANGESET_RECORDS` entries; each entry stored or deflated, never encrypted, its local header naming the same file with the same method and flags (and, without a data descriptor, the same CRC-32 and sizes), its data ending before the central directory, no two entries overlapping, and each inflating to exactly its declared size and CRC-32; anything else is `SEED_UNREADABLE`. The source is re-opened for each read (the central directory, `seed.json`, the fixed entries, the attachments), and each read must find the same size and central directory, else `SEED_UNREADABLE`. **`seed.json`** is a JSON object whose `seedFormat`, `recordsLastModified` and `engineFloor` are integers and whose `channel`, `dataset` and `filterFormat` are enum names (`"COMPAT"`, `"CRLITE"`, `"V3"`), other members ignored; `seedFormat` must be 1, and an `engineFloor` above the engine's level (1) is unreadable (`SeedHeaderTest`, `SeedLoaderTest`). `records.json` must be the canonical payload of its own records and `<ts>`; the coverage bound applies at `<ts>`, and every placed filter's encoding must be listed by the engine; each is `SEED_UNREADABLE` otherwise. The seed's generation id is `"<ts>/<last placed record id>"`, a sync's shape. Engine rules: `seedFormat` or
`engineFloor` above what this engine supports, or `filterFormat ∉ revocationEngine.formats`, → `SEED_UNREADABLE` warning and the seed is ignored (so in the sole-seed `ENFORCE` configuration `start()` throws, §4 S bullet); **a seed whose signed timestamp exceeds local now + `clockSkew` is installed** (the timestamp is Mozilla-signed and its x5u checks run at that signed time, so "future" can only mean the local clock is behind, which the spec calls routine; refusing it put the default preset at `NO_DATA` on every device whose clock was a day behind) with `DataState.clockBehind = true`, `ageMillis` clamped at 0, the sticky-while-true `CLOCK_BEHIND` warning, and the watermark at the signed timestamp as for any seed (rollback comparisons are server time against server time and never involve the local clock);
`channel` ≠ configured channel → `SEED_CHANNEL_MISMATCH` `ERROR` thrown by `start()`; the shipped
`index.bin` is **rebuilt from `records.json` and byte-compared** at load (the signature binds records
and attachment hashes, not parentage), a mismatch → `SEED_UNREADABLE`; the weekly job publishes
every `seedFormat` the oldest supported minor lists, in the filter format Mozilla signs.
**Seed-load rule** (the seed always leaves a live generation behind; `SeedLoaderTest`, `SeedLoaderStoreTest`,
`SeedAdoptTest`). The store is read first: a read that throws fails the load with nothing written (`STORE_FAILED`); a
malformed `updater.json` reads as absent. Each store fault is counted once, where it is found.
- **(a) A valid pointer whose `live` `meta.json` reads.** When that generation, or the one the engine serves, is not
  older than the seed's `<ts>`, the seed is skipped and nothing is written. Otherwise it installs, and the install
  never prunes past a pointed directory whose `meta.json` does not read or a complete directory newer than the seed.
- **(b) Anything else** (no pointer, a malformed one, or a `live` that does not read). The newest complete directory
  newer than the seed, and not older than the generation the engine serves, whose stored files re-verify (its index
  and every file it names re-hashing, its placed records exactly the index's files, its timestamps agreeing with its
  `records.json`, and its signature over `records.json` when its signer leaf is the seed's) is adopted: `updater.json`
  is written from the record read with the watermark raised to its `<ts>`, then the pointer is flipped to it, and the
  seed is not installed. A complete directory that does not re-verify counts one store failure. With none to adopt, a
  generation the engine serves that is newer than the seed is kept and the seed skipped. Otherwise the seed installs:
  its own complete directory that re-verifies is installed as it stands (compared on everything but `freshness` and
  the signed members), one that does not is completed again from the verified seed with only its rotted files
  re-staged, and one whose `meta.json` is absent or does not read is completed from the seed; the directory the engine
  serves is never rewritten. A (b) load never prunes, never deletes a directory it found, and its flip heals the
  pointer.

`DataState.fromSeed`, `ageMillis`, `stale` and `seedFormat` are loud. **Seed artifacts declare no code dependency**: the floor lives in `seed.json` (`engineFloor`, enforced at load as above). A POM dependency would let a seed bump drag `revokt-engine` above the BOM-pinned bindings (Gradle resolves the highest version; BOM constraints are not strict) and the `@RevoktInternalApi` plumbing between artifacts carries no compatibility promise; instead every code artifact's Gradle module metadata depends on `revokt-bom` as an aligning platform, so a single-artifact bump aligns the set.

## 7. Data sources

| Sources | Integrity | Authenticity |
|---|---|---|
| Mozilla Remote Settings (CRLite [M1]; intermediates, OneCRL [M2]; ct-logs [M3]; root-store distrust-after dates and CCADB export [M4]); Chrome CRLSet [M2]; seeds [M1] | signed record hash / CRX proof | Mozilla content-signature roots / Google CRX key |
| denylist artifact [M2] | reproducible from signed public inputs, attested | project-attested, availability-only |

### 7.1 Mozilla Remote Settings protocol and verification [M1]
All constants live in `MozillaRemoteSettings` (per source, overridable), including the pinned root
SPKI hash set and the three fields read from each `metadata.signatures[]` entry (`signature`, `x5u`, `mode`). `MozillaRemoteSettings.Builder` exposes `baseUrl`, `attachmentBaseUrl` and `x5uHosts` (§4): `attachmentBaseUrl` defaults to `https://firefox-settings-attachments.cdn.mozilla.net/`, Mozilla's live
`capabilities.attachments.base_url` with its trailing `/` (Appendix A). `x5uHosts` entries and rewrite
targets are compared exactly, ASCII case included. **a private mirror that serves the changeset, attachment and x5u bytes unchanged (a byte-for-byte reverse proxy of the three Mozilla hosts) with the builder's `baseUrl`, `attachmentBaseUrl` and `x5uHostRewrite("content-signature-2.cdn.mozilla.net", mirrorHost)` pointing at it (`attachment.location` is relative, so `attachmentBaseUrl` suffices; the rewrite is applied to the parsed x5u URI host before the `x5uHosts` check, so no JSON is rewritten on the wire; x5u is outside the signed payload; the https-only, port-443 and no-userinfo rules apply to the mirror host too), verifies and installs as `SIGNED` under the default `sourceId`, so the `_since` cursor carries over (the watermark is per dataset and channel and carries over whatever the `sourceId`, §6.5); this is the supported offline-fleet path** (`c2spMirror` is bootstrap-only and never updates a seeded client, §7.3). Base `https://firefox.settings.services.mozilla.com/v1` (the Kinto API, Firefox's own `services.settings.server`; `/v2`, a distinct newer server that was hours old at verification, serves the same changeset shape and is the documented alternative value of `MozillaRemoteSettings.baseUrl`; both verified 2026-10-22, Appendix A);
only `monitor/changes` and per-collection `changeset`; `_expected` mandatory; a delta poll sends `_since=<cursor>`
bare in the changeset query, as Firefox does, beside the quoted `If-None-Match` (§3); `User-Agent`; gzip;
honour `Backoff` and `Retry-After` up to `MAX_BACKOFF` (24 h; transport headers are unsigned), on every response, 2xx included (revokt's own rule, stricter than Firefox, which keeps `Backoff` only from a `/changes` response that is not a server error and carries the expected JSON, and never reads `Retry-After`; Appendix A): a response with such a header waits the header, a failure too even when that is shorter than its computed backoff; a success without one clears `backoffUntilMillis`; a failure without one waits the computed failure backoff, 15 min × 2^(n − 1) for the n-th consecutive feed failure, capped at the 6 h poll interval; poll at most every 6 h with jitter. **Feed failures**: `FAILED` (`FORMAT_UNSUPPORTED`, which a placed full or delta in an encoding the engine does not list gives at stage `PREPARE`, the previous generation staying live (§6.5), and a `FETCHER_TRUST` failure included), `CLOCK_SKEW` and `STORE_FAILED` advance `consecutiveFailures` and take the failure backoff, except a `STORE_FAILED` sync whose read of `updater.json` threw, which writes nothing (§6.5); `ROLLBACK_REFUSED` is not a feed failure; `BACKOFF` and `DEFERRED` leave the count unchanged; every successful poll resets it to 0: `INSTALLED`, a clock-behind install included, and `UNCHANGED`, by a 304 or by a timestamp match. **Verify** every collection
state (`"Content-Signature:\0"` + canonical JSON of `{"data": records sorted by id (deleted removed),
"last_modified": "<ts>"}`; merge `_since` tombstones first; reset-and-retry once; canonical JSON per `canonical_json` 0.7.0 escape rules, over integers only: a number is an integer within `u64` (or `i64` when negative, `-0` excluded), as serde_json classifies it, and any other number (a fraction, an exponent, or an integer outside that range) has no canonical form, so a payload holding one is refused (`RECORDS`: `FAILED` at stage `SIGNATURE`) and never serialised; a record's `deleted` reads such a number as zero exactly when every mantissa digit is `0`; pinned by the §9 differential test; the `signature` field is unpadded base64url of the raw pair r‖s, two equal halves of any non-empty even length (a pair of the wrong size for the leaf's key fails verification), the leaf on any EC curve the floor admits (Firefox parity; P-384 today), converted to DER and verified as `SHA384withECDSA`). **`<ts>`** is the value the verified payload was built from: a live sync builds it from the changeset envelope's `timestamp`, as Firefox's `RemoteSettingsClient` does, so that value is signed exactly when verification succeeds; a seed's is the one inside `records.json`. The unsigned value is `monitor/changes`' `last_modified`, used only as `_expected`. **`metadata.signatures[]` is read, as Firefox reads it**: the array must be non-empty; at most 4 entries are tried, in array order, and a changeset with more than 4, or with no entry tried (every entry skipped, for example for a missing `mode`), is `SyncOutcome.FAILED` at stage `SIGNATURE`, since it concerns signature metadata, not records; so is a JSON `null` element that the loop reaches, as Firefox's destructuring throws on it (an earlier entry that verifies is accepted first); each tried entry's `x5u` is fetched and validated under the pinned chain (§7.1 "x5u chain"), an `x5u` URL already fetched and validated in the same sync being reused, not fetched again, and one whose fetch or validation failed not being retried by a later entry in the same sync; the first entry that verifies is accepted, and the records installed are exactly the records it verified, at the `<ts>` it verified; an entry with no `signature` or `x5u`, an empty string included (Firefox's `!x5u || !signature`), or whose `mode` is not `p384ecdsa`, is skipped; any failure of a tried entry, a failed `x5u` fetch included, moves on to the next entry (Firefox leaves the loop when the fetch itself is rejected, Appendix A); when none verifies, the last tried entry's failure is the outcome (Firefox throws its first error): a failed `x5u` fetch is `FAILED` at stage `X5U`, a validity failure `CLOCK_SKEW` at stage `X5U`, and every other PEM or chain failure (`NOT_PINNED`, `EKU` and `SAN` included) and a content-signature failure `FAILED` at stage `SIGNATURE`; `metadata.signature` is not read (Appendix A). **The signed
payload does not bind the collection id**, and every security-state collection shares a signer, so
before any state change every record is schema-validated for the requested collection (CRLite:
`channel`, `incremental`, `attachment.{filename,hash,size,location}` (the filename under §6.3's rule), `effectiveTimestamp`, and `parent` on deltas only, since live full records carry none; M2
schemas likewise); a verified changeset whose records fail validation is `SyncOutcome.FAILED` with
`SYNC_SCHEMA_REJECTED` (stage `SCHEMA`), counts as a feed failure, and advances nothing. Redirects are never followed. **JSON**: the
engine's own tree and tokenizer; duplicate keys and unpaired surrogates rejected; keys sorted by code
point. **Content signature**: each entry's `mode` is read and must equal `p384ecdsa` for the entry to be tried (an entry with none is skipped), a deliberate narrowing: Firefox accepts an entry with no `mode`; the algorithm is never derived from it; the attachment
base URL pinned in `MozillaRemoteSettings`, never taken from the server root response. **x5u chain**: the body is
read as `rustls-pki-types` 1.15.1 reads it (upki v1.0.1's pin): text and blank lines outside a block are skipped; a block whose label `rustls-pki-types` knows (`CERTIFICATE`,
`PUBLIC KEY`, `RSA PRIVATE KEY`, `PRIVATE KEY`, `EC PRIVATE KEY`, `X509 CRL`, `CERTIFICATE REQUEST`, `ECHCONFIG`) is
decoded, only `CERTIFICATE` blocks are kept and the others dropped, and a decode error in any of them fails the body;
a block with an unknown label is skipped undecoded; the base64 decoder skips whitespace (HT, LF, VT, FF, CR, space)
and needs no padding; a body that ends inside a block, or has no `CERTIFICATE` block, fails; HTTPS from the allowlist (today `content-signature-2.cdn.mozilla.net`; the parsed URI host after rejecting userinfo, a non-https scheme and a port other than 443; `_expected` is validated as an integer before it enters a query string). **The x5u URL grammar**, strict and never repaired: `https://` in lowercase, so `HTTPS://` is refused; an authority with no userinfo; a host that is a DNS host name (labels of ASCII letters, digits and `-` of 1 to 63 characters, at most 253 in all, no trailing dot, a last label that is not a number), never an IP literal and never a percent-encoded or non-ASCII host; no port, or port 443; then a path and an optional query of RFC 3986 `pchar`s, `/` and `?`, every `%` followed by two hex digits; and any fragment, which must be one RFC 3986 allows and is dropped. Anything else is `FAILED` at stage `X5U`, never repaired, `MAX_X5U_BYTES` (64 KiB) cap; **algorithm floor** for every link below the terminal (Firefox's `AppTrustDomain` set): a signature is RSA PKCS#1 v1.5 or ECDSA with SHA-256, SHA-384 or SHA-512 (an ECDSA AlgorithmIdentifier with NULL or absent parameters, as mozilla::pkix reads it), or `id-RSASSA-PSS` whose parameters are byte for byte one of mozilla::pkix's three encodings (SHA-256, SHA-384 or SHA-512 with NULL hash parameters, MGF1 with the same hash, a salt length equal to the hash length, `trailerField` omitted for its default 1); a link's key is `rsaEncryption` of at least 2048 bits or `id-ecPublicKey` on P-256, P-384 or P-521, so an `id-RSASSA-PSS` key fails; anything else `FAILED` (`ALGORITHM`; the JCA verifier is called directly, so `jdk.certpath.disabledAlgorithms` does not apply). This floor is the x5u chain's own: §3's `id-RSASSA-PSS` rule for the TLS verifier is unchanged; validity at verification time for the leaf
and every non-terminal link; for every non-leaf link below the terminal: basicConstraints `cA = TRUE`,
`pathLenConstraint` honoured, subject name equal to the child's issuer (raw or canonical), keyUsage
`keyCertSign` when present (`KEY_USAGE`);
links verified with the signed TBS algorithm; root SPKI hash in the pinned set (today one entry, the SPKI SHA-256 of
`CN=root-ca-production-amo`, `3317FA45154AC7DA55694D3782316056471FC147C04AED3E03FFE99565B1E2E7`, which
`MozillaRemoteSettings.DEFAULT` pins; certificate SHA-256 `C8A80E9A…A106DB`; both verified in Appendix A;
the set is additive while any seed references a root); **the terminal is a trust anchor**: the first certificate after the leaf whose SPKI is
pinned, anything after it ignored (a pinned SPKI on the leaf pins nothing, so a chain pinned only there is `FAILED`,
`NOT_PINNED`; mozilla::pkix fails a pinned root used as the end entity with
`ERROR_CA_CERT_USED_AS_END_ENTITY`, and rustls-webpki never takes the end entity as an anchor); only its SPKI is checked, never its validity, CA bits, key usage
or subject. This is revokt's own rule, not Firefox's: `AppTrustDomain` matches the anchor by its whole DER and
mozilla::pkix still checks it. Pinning the key alone keeps a re-issued root working, and the wrapper around a pinned
key is attacker-choosable, so a check on it stops nothing, while root expiry would freeze every deployed client and
seed. **Order:** the pin lookup runs first, over each certificate after the leaf as read leniently (§9.2's parser);
the strict profile below then applies only to the links below the terminal, and the terminal is read for its SPKI
alone. Leaf EKU
codeSigning and never `id-kp-OCSPSigning` (`EKU`); leaf SAN exactly `onecrl.content-signature.mozilla.org` (`SAN`). Any non-terminal certificate
on the path outside its window at a live fetch is `SyncOutcome.CLOCK_SKEW` (stage `X5U`).

**The chain follows mozilla::pkix** (at Firefox
`cac25a6fa321b0051932359b84c4e2fe3caabdc5`, with rustls-webpki consulted: 0.104.0-alpha.7, the version upki builds paths
with (`upki/Cargo.toml:32` at 9821cce), its divergences listed in Appendix A and `docs/decisions/DIVERGENCES.md`). Every failure is
`SyncOutcome.FAILED` at stage `SIGNATURE`, and the parenthesis names the chain's failure reason. For every link below the terminal:
- **DER as mozilla::pkix reads it** (`PARSE` for the certificate's outer structure, `EXTENSION` inside an
  extension value): in the outer structure, minimal tag and length headers; no indefinite length, the
  TBS and the outer `signatureAlgorithm` included; no element the certificate grammar does not place (a TLV after the
  SPKI other than the optional unique IDs, which are primitive, and `[3]`, a second SEQUENCE inside `[3]`, bytes after
  an extension's `extnValue`); a minimally encoded serial; the `critical` BOOLEAN `00` or `FF`; zero unused bits in
  the signature BIT STRING. Each extension value revokt reads (basicConstraints, keyUsage, extKeyUsage, subjectAltName,
  nameConstraints, the leaf's embedded SCT list) is parsed first and to its end, and anything malformed is
  `EXTENSION`: bytes after the value, a BOOLEAN other than `00` or `FF`, a non-minimal length, an empty keyUsage BIT
  STRING (`03 00`) or one with no named-bit byte (`03 01 00`), an empty extKeyUsage SEQUENCE (`30 00`) or a non-OID
  element in it, an unknown GeneralName tag. Only a well-formed value reaches the `SAN`, `EKU` and `KEY_USAGE` checks,
  so a SAN with an unknown GeneralName tag is `EXTENSION`, not `SAN`. An empty `extnValue` is the understood-empty rule
  below. The TLS feature is compared byte for byte and never parsed. Times are read
  as mozilla::pkix reads them: `UTCTime` as `YYMMDDHHMMSSZ` and `GeneralizedTime` as `YYYYMMDDHHMMSSZ`, either type
  for any year (Mozilla's `Content Signing Intermediate` uses GeneralizedTime `20150317000000Z`), a year of 1970 or
  later, and notBefore ≤ notAfter. **What mozilla::pkix accepts and revokt accepts too, although DER or RFC 5280
  forbids it:** an explicitly encoded v1 version (bug 1031093), an explicit DEFAULT FALSE for `critical` and for
  `cA`, an empty Extensions SEQUENCE, a negative or zero serial, and a keyUsage BIT STRING without the minimal
  named-bit encoding. This is the x5u chain's profile only: §9.2's TLS parser stays as lenient as the platforms.
- **Version and names:** the version INTEGER is 0 to 3 (`PARSE` otherwise; 3 is v4), and `[3]` is read whatever the
  version, an implicit v1 included, as mozilla::pkix does; an issuer name with no RDN fails (`NAME`).
- **Outer algorithm** (`ALGORITHM`): the outer `signatureAlgorithm` equals the TBS `signature` as parsed algorithms,
  with a NULL and an absent parameter comparing equal. The link is still verified with the signed TBS algorithm.
- **SubjectPublicKeyInfo** (`ALGORITHM`), as mozilla::pkix's `CheckSubjectPublicKeyInfo`: zero unused bits in its
  BIT STRING; `id-ecPublicKey` with a namedCurve OID only and an uncompressed point, the bytes after `04` exactly twice the
  field length in bytes; `rsaEncryption` with NULL parameters (absent fails) and a minimally encoded positive modulus and
  exponent.
- **Extensions** (`EXTENSION`): an OID that occurs twice fails, whatever it is (RFC 5280's MUST NOT; stricter than
  mozilla::pkix, which rejects only a repeated extension it understands, Appendix A); an understood extension with
  an empty value fails, except `id-pkix-ocsp-nocheck`; a malformed basicConstraints or keyUsage on the leaf fails as
  on every link; a `pathLenConstraint` above 127 fails, as mozilla::pkix's integer reader does. **The leaf's
  embedded SCT list** (as Firefox): when the leaf carries the extension, its `extnValue` is exactly one
  OCTET STRING with nothing after it (`pkixbuild.cpp` lines 218 to 229 at `cac25a6fa321b0051932359b84c4e2fe3caabdc5`,
  `ExtractSignedCertificateTimestampListFromExtension`); anything else fails. The list's content is not read.
- **Critical extensions** (`EXTENSION`): a critical extension outside mozilla::pkix's understood set
  (`BackCert::RememberExtension`: keyUsage, subjectAltName, basicConstraints, nameConstraints, certificatePolicies,
  policyConstraints, extKeyUsage, inhibitAnyPolicy, authorityInfoAccess, the TLS feature extension, the embedded SCT
  list and qcStatements, and, when critical, `id-pkix-ocsp-nocheck` and the Netscape certificate type) fails on any
  link. A critical Netscape certificate type is accepted only when basicConstraints and extKeyUsage are both present,
  whose own checks then decide (mozilla::pkix does not read the type bits).
- **TLS feature** (`EXTENSION`), enforced between the links below the terminal, as mozilla::pkix's
  `CheckTLSFeatures`: when a non-leaf link below the terminal carries the TLS feature extension, its child carries one
  with the same value, its `extnValue` compared byte for byte. The terminal's TLS feature is never read: the root is pinned, and a TLS feature there could only
  add a constraint.
- **Leaf basicConstraints:** `cA = TRUE` on the leaf fails (`LEAF_CA`; Firefox `ERROR_CA_CERT_USED_AS_END_ENTITY`,
  webpki `CaUsedAsEndEntity`).
- **EKU below the leaf** (`EKU`): every non-leaf link below the terminal that has an extKeyUsage includes codeSigning
  (anyExtendedKeyUsage alone does not). The terminal's is never read.
- **nameConstraints**, critical or not, as mozilla::pkix enforces them (`pkixbuild.cpp`, `pkixnames.cpp`), on every
  non-leaf link below the terminal and checked against the leaf's one dNSName:
  - a dNSName in no permitted dNSName subtree, when any permitted dNSName subtree is listed, or in an excluded one,
    fails (`NAME_CONSTRAINTS`). Permitted applies per name type, so permitted subtrees of other types alone do not
    restrict the dNSName;
  - a subtree matches on label boundaries, ignoring ASCII case: a base without a leading dot covers the name and its
    subdomains (`bigfoo.bar.com` is not under `foo.bar.com`), one with a leading dot only the subdomains, and the
    empty base `""` matches every name, so it permits all when permitted and rejects all when excluded;
  - a malformed or unsupported constraint fails (`EXTENSION`): an invalid dNSName base (an absolute `x.`, `.`, a
    wildcard), an encoded `minimum` or `maximum`, an empty NameConstraints, an empty GeneralSubtrees, and any
    directoryName subtree, which mozilla::pkix checks against the subject and revokt does not evaluate (fail closed).
    Each GeneralSubtree is still parsed: an unknown GeneralName tag is malformed (`EXTENSION`), and an encoded
    `minimum` or `maximum` fails whatever the form. Only the base of a form revokt does not evaluate is left
    unevaluated: such a subtree cannot affect a leaf whose only name is a dNSName. An rfc822Name subtree has no
    effect, as in mozilla::pkix: its fallback to the subject's emailAddress (`pkixnames.cpp` `SearchNames`) runs
    only for a certificate with no subjectAltName, and the leaf must carry one.
  - Only the leaf's name is checked; mozilla::pkix and webpki check every descendant (Appendix A).

**Rollback guard**: high-water mark on
the signed `last_modified` (`<ts>`, the value the verified payload was built from, §7.1; never `monitor/changes`' unsigned `last_modified`), persisted in `updater.json`; older by less than `rollbackWindow`
(default = `clockSkew`, 24 h; collection timestamps are server-assigned and monotone) may still
install subject to the §6.3 coverage-monotonic rule, which applies only inside the window;
`ROLLBACK_REFUSED` is not a feed failure, never advances `consecutiveFailures`, and never updates
`lastVerified*`; `ROLLBACK_REFUSED` on every poll for longer than `signedSourceFailingAfter` does set
`signedSourceFailing`, so a stuck watermark is visible.

### 7.2 Mozilla CRLite, channels, seeds and data artifacts [M1]
Channel is top-level (`DEFAULT`: all reasons, a 6.0 MB full and 242 KB a delta on average (measured 2026-11-12,
§6.4), Firefox desktop and the public mirrors; `COMPAT`: keyCompromise, cessationOfOperation, privilegeWithdrawn, a
1.57 MB full and 134 KB a delta (the same measurement),
Firefox for Android, no public mirror). Recommended: `DEFAULT` for backends, `COMPAT` for Android apps (APK and metered cost, §12). Delta chain depth varies: 8 deltas per channel on Remote Settings on 2026-10-21, 52 on 2026-11-12 (§6.4); Phase-0 task: observe
two full-filter cuts for re-parenting. When the stored full is no longer the delta parent, a full
download is deferred while `meteredNetwork` (§4; sampled once per sync; Android: `ConnectivityManager.isActiveNetworkMetered()`) reports true, until `staleAfter`, then proceeds; a deferred full is `SyncOutcome.DEFERRED` with the `METERED_DEFERRED` warning; missing data always
downloads. **Seeds** verified like a live fetch except x5u validity at the seed's signed
`last_modified`; a seed-backed generation is never `NO_DATA`; a future-dated seed installs with `clockBehind` (§6.5); `DataState.fromSeed`, `ageMillis` and
`stale` are loud. **Data artifacts**: date-versioned, weekly, attested, not in the BOM, no
build-time plugin. **Freshness per dataset** (`Freshness`, reported on `DataState`): CRLite ages from the filter
record's `last_modified`; OneCRL and intermediates (M2) age from the last **verified poll**, since
their content changes only when a CA is listed; CRLSet from its sequence time; the denylist from the
artifact date; seeds from their signed timestamp.

### 7.3 C2SP manifest mirrors and system cache
Cut: not a source. [docs/design/mirror-and-system-cache.md](../design/mirror-and-system-cache.md) keeps the design. Only
the Remote Settings source and seeds are configurable; the store's generation directories stay a C2SP image (§6.5).

### 7.4 Mozilla intermediate preloading [M2]
Not normative before M2: [docs/design/m2-sources.md](../design/m2-sources.md).

### 7.5 OneCRL, bundled denylist and Chrome CRLSet [M2]
Not normative before M2: [docs/design/m2-sources.md](../design/m2-sources.md).

## 8. Policy

`RevoktPolicy` is a map from `Rule` to `Outcome`, per-rule exemptions, `requiredDatasets`, a
per-dataset staleness map and three time fields. Presets: `DEFAULT`, `STRICT`. **`Enforcement.OBSERVE`
runs the configured policy, emits events, and never throws.** The Firefox, Chrome and upki columns give each
reference's handling of the same condition, Firefox at `cac25a6fa321b0051932359b84c4e2fe3caabdc5` and upki at v1.0.1
(`9821cce`); "n/a" means the reference has no counterpart, and the sources are in `docs/decisions/DIVERGENCES.md`.

| `Rule` | Class | `DEFAULT` | `STRICT` | Firefox | Chrome | upki | Produced by |
|---|---|---|---|---|---|---|---|
| `REVOKED` | evidence | reject | reject | reject | reject | reject | CRLite, any evaluated key |
| `PATH_BUDGET_EXCEEDED` | unevaluable; one of goal 3's two stated exceptions | **reject** | reject | reject: exhaustion is `ERROR_UNKNOWN_ISSUER` | n/a | reject: webpki's budget error is fatal | decision steps 3, 5, 6 |
| `NO_DATA` | unevaluable | **reject** (exemptable) | reject (exemptable) | → OCSP: no filter is `Success` | n/a | reject: `missing_data = Error` | decision step 7, per required dataset |
| `ENGINE_ERROR` | unevaluable | allow | reject | reject: `FATAL_ERROR_LIBRARY_FAILURE` | n/a | reject: a hard error, and rustls-upki fails closed | boundary, engine result, exemption throw |
| `PARSE_FAILED` | unevaluable (goal 3) | allow | reject | n/a | n/a | n/a | decision step 3 |
| `NO_ISSUER` | unevaluable (goal 3) | allow | reject (exemptable; **empty path**: `anchorIn` never matches; reason on `Finding.Path`, including `UNSUPPORTED_ALGORITHM` and `PLATFORM_ONLY`) | n/a | n/a | n/a | decision step 6 |
| `NOT_ENROLLED` | non-answer | allow | reject (exemptable) | not compared | n/a | collapsed into `NOT_COVERED` (allow) | CRLite |
| `NO_SCTS` | non-answer | allow | reject (exemptable) | → OCSP | n/a | allow | CRLite |
| `NOT_COVERED` | non-answer | allow | allow | → OCSP | n/a | allow | CRLite (the coverage gap: a certificate issued after the live filter's coverage `high` is unchecked by every preset; §10) |
| `STALE` | data quality | allow; never fires (`rejectStaleAfter` null; loud via `DataState.stale` and `RevoktStatus.stale`) | reject at 30 d, after a sync attempt has completed since the seed was installed (persisted gate, bullet below; exemptable) | → OCSP | drops an expired CRLSet | keeps old data | `DataState`, per dataset |
| [M2] `DENYLIST`, `ONECRL`, `CRLSET` | evidence (`ONECRL` exemptable per anchor through `ExemptionContext.path.anchorSha256`, the enterprise-CA case; `CRLSET`, `DENYLIST` not exemptable) | reject | reject | reject (OneCRL) | reject (CRLSet) | n/a | L1/L2 (the 0.4 → 1.0 transition; not subject to the one-minor rule) |
| [M2] `ISSUER_UNKNOWN_TO_MOZILLA` | non-answer | allow | reject (exemptable) | n/a | n/a | n/a | preload |
| [M3] `CT` | evidence | allow | reject (ships `ALLOW` for one minor in `STRICT`) | reject | reject | n/a | L4: CT policy verified and not met |
| [M3] `CT_UNVERIFIED` | non-answer | allow | reject (exemptable; ships `ALLOW` for one minor) | n/a | n/a | n/a | L4: log list missing, SCTs unverifiable, or the only SCTs delivered outside the certificate (TLS extension, OCSP), which an `X509TrustManager` cannot observe; this is why `CT` ships `ALLOW` in `DEFAULT`. M3 adds `EvaluationRequest.Builder.tlsScts(...)`, a full-SCT type separate from `CrliteSct`, and the path cache keeps the raw extension bytes |
| [M4] `DISTRUST` | evidence | reject (ships `ALLOW` for one minor in both presets) | reject (same; exemptable per anchor) | reject | reject | n/a | L5 |

- **Data rules are per dataset.** `NO_DATA` fires for a dataset in `requiredDatasets` with no
  generation and `DataState.pending == false` (the start task has passed the seed step; `pending` is false at the end of the start task whether or not a fetching source is configured, with `generationEpoch++` when it clears without a generation, so a seed-only configuration can never sit in `pending`); presets' `requiredDatasets` is `{CRLITE}`. `STALE` fires for a dataset present in the staleness map
  (presets: `CRLITE` only) iff `rejectStaleAfter != null && ageMillis > rejectStaleAfter`;
  `DataState.stale` (the loud flag) is `ageMillis > staleAfter` and never fires a rule.
  In `DEFAULT`, `STALE` allows: setting a `rejectStaleAfter` makes the rule fire and report, and rejecting takes
  `rule(…, REJECT)` as well. `ageMillis = now − sourceTimestampMillis` per the dataset's
  `Freshness`. Preset defaults: `CRLITE` `staleAfter` 3 d, `rejectStaleAfter` null in `DEFAULT`, 30 d
  in `STRICT`. **Stated plainly:** `DEFAULT` with stale data is "reject what the stale filter says is
  revoked, allow the rest", with `STALE` never firing; `DEFAULT.newBuilder().rule(STALE, REJECT)`
  alone changes nothing until a `rejectStaleAfter` is set. **`STALE` does not fire for a dataset whose
  generation is `fromSeed` until a sync attempt has completed since the seed was installed** (the persisted
  `updater.json.datasetLastAttemptAtMillis ≥ updater.json.seedInstalledAtMillis`, both per dataset (§6.5), never the in-process `lastSync`; the loader carries the boolean in the published `DataState`;
  a read-only instance (§5.1) makes no attempt and writes nothing, so its in-memory seed stays gated until it
  promotes itself to writer and the owner start task's first sync completes, `STORE_LOCKED` results and a sync whose `updater.json` read threw (§6.5) not being attempts; a backoffed
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
- **Exemptions** register per exemptable rule and run after policy mapping for fired `REJECT` rules only. **Enterprise-CA recipe under `STRICT`**: exempt `NO_SCTS`, `NOT_ENROLLED` **and the data rules** (`NO_DATA`, `STALE`) with the same `anchorIn(privateCa)` (`RevoktPolicy.Builder.exemptAnchors(sha256s)` does exactly that, §4), and `NO_ISSUER` with `hostSuffixIn(corpDomains) and platformOnly()` (it fires only on an empty reported path, where `anchorIn` never matches; `platformOnly()` alone would exempt every chain the §5.2 intermediate-omission residual produces on Android, for every host, turning `STRICT` into `DEFAULT` for a revoked public leaf presented without its intermediate), so a feed outage never takes down traffic CRLite cannot evaluate anyway ( on the JVM the supported private-CA delegate is a `TrustManagerFactory` over a merged `KeyStore`, never a hand-written `X509ExtendedTrustManager` composite, which passes `requiresExtendedDelegate()` but drops SunJSSE's constraints; call `refreshAnchors()` on rotation).
- **`outcomeDepended`** (M1): `outcomeDepended = (noIssuerReason == UNSUPPORTED_ALGORITHM)` (§5.1 "Findings"): the
  walk recorded an own signature OID and the result is `NO_ISSUER(UNSUPPORTED_ALGORITHM)`; false on `Found`, `Budget` and, on the
  bindings, `NO_ISSUER(PLATFORM_ONLY)`.
- **Established connections**: a rejection applies to new handshakes; pooled connections already established are not torn down (the README says so); an HTTP/2 connection coalesced onto another host inherits that host's verdict (§5.1).
- **What `OBSERVE` yields**: `wouldRejects` over `evaluations` by rule from `status()`; by host, policy epoch,
  anchor, issuer key and generation from events. **What `shadowPolicy` yields while `ENFORCE` stays on**: `shadowWouldRejects` by rule and `RevoktEvent.shadowVerdict` per event, so `STRICT` (or a rule in its grace minor set to `REJECT` in the shadow) is measured for weeks without lifting `REVOKED`, `NO_DATA` or `PATH_BUDGET_EXCEEDED` enforcement; the migration procedure is: shadow `STRICT`, drive `shadowWouldRejects` to the exemptions above, then set `policy = STRICT`.

## 9. Correctness and testing

The test plan, with the §9 fixture rows, §9.1 (fuzzing) and §9.2 (the differential parser oracle), is [test-plan.md](test-plan.md), with its section numbers kept.

## 10. Security considerations

- Platform verdict first and final for acceptance; revokt's own failures never reject in `DEFAULT`,
  with the two stated exceptions of `PATH_BUDGET_EXCEEDED` and `NO_DATA` (goal 3).
- **Issuer identity is pinned by a path of `VERIFIED` links to a known anchor by bytes.** No
  candidate is excluded for a shared property; deferral is by the candidate's own relation, which the
  server cannot forge for a real certificate; related candidates at the leaf are fully explored or
  the result is not an allow; every terminating related leaf-issuer key, and every unrelated one when the leaf has no
  related path or the delegate has a custom canonicaliser, is evaluated, and `REVOKED` wins;
  any exhaustion anywhere rejects.
- **Residual risks recorded from the sixth and seventh review rounds:**
  1. On a custom delegate whose name equality differs from `X500Principal`'s, an honest issuer may
     be classified unrelated; at the leaf it is then explored regardless of a related path (§5.1
     deferral rule, custom canonicaliser), below the leaf only while no related path exists at that
     node (a related path there is itself sound: only the honest key verifies a real certificate and
     a recovered key cannot reach an anchor), so misclassification alone never yields `NotFound`;
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
  3. **Closed.** The anchor snapshot is built synchronously before any handshake can
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
     unknown in the Web PKI, possible in bridge PKIs, which are out of scope for TLS clients. Since store anchors come
     first at every depth, 64 snapshot anchors named like a node's issuer push a presented issuer past
     the cap at that node, the leaf or below it; the trust store controls that, not the server, as in Firefox, where roots come first.
  5. CRLite's (issuer key, serial) model: a certificate revoked under one issuer key and re-presented
     under a cross-issuing key with a different serial is a data-model limit, not a walker defect.
  6. The named M1 Android residual (§5.2), including any app whose NSC carries a `<domain-config>`, where `RootTrustManager` rejects a null host: the plain-delegate binding and any path where the
     null-host extension call is unavailable.
  7. **Kept, narrower than Firefox.** A certificate issued without
     embedded SCTs, or whose every SCT list fails under §9.2 (for example an empty list, a first item that fails, an inner identifier other than `0x04`; §9.2 states every case), yields `NO_SCTS`, which allows in `DEFAULT`: an issuance-time
     opt-out from checking. Firefox skips CRLite without usable SCT timestamps and falls to OCSP, which
     revokt does not do. Firefox rejects the certificate outright where the SCT extension's `extnValue` is not exactly
     one DER OCTET STRING, as with an inner identifier other than `0x04`. `STRICT` rejects; the `rustls-upki` verifier rejects a malformed list (test-plan.md §9.3
     divergence). A list §9.2 accepts in part, which Firefox and webpki fail whole, is queried, so `STRICT`
     then sees the CRLite answer, not `NO_SCTS`. A list in an inner OCTET STRING with a non-minimal length, or followed
     by bytes in `extnValue`, is also queried, and so are two SCT extensions; Firefox rejects such a certificate.
     SCTs are not verified in M1: a forged covered SCT on a key
     outside a filter's universe gets an arbitrary answer, a residual.
  8. **Kept, with `PRODUCER_UNKEYABLE` widened.** `PARSE_FAILED` on the leaf allows in
     `DEFAULT`, so a leaf encoding the platform accepts and the Kotlin parser rejects is unchecked. The subscriber
     controls leaf content only at issuance, under CA linting, and the §9.2 differential parser oracle (D1, a 0.1
     gate) and, on the JDK, the §9.2 read fallback are the mitigation.

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
     the pinned seed corpus's leaves of index issuers (0 of 117 603 unexpired leaves, Appendix A).

     The profile reads only the signed content of `tbsCertificate`, and the parser accepts every unsigned header form
     the JDK verifies (§9.2), including the indefinite chain the JDK re-encodes and the cleared signature padding,
     so a network attacker re-encoding the envelope or the TBS headers reaches neither
     `PRODUCER_UNKEYABLE` nor `STRUCTURE`.

     Firefox has no keyability notion. mozilla::pkix rejects most gap encodings before CRLite, and accepts the serial
     forms (negative, zero, long) and the explicit `FALSE` that the profile also accepts.

     Considered and not adopted: deciding keyability at the query, after the walk. That would make the
     outcome exemptable under `anchorIn`, and `NOT_ENROLLED` under an unenrolled issuer. The profile already accepts
     the private-PKI serial forms, so the remaining unkeyable leaves are encodings that mozilla::pkix and BoringSSL
     also reject. This reopens if a gap entry under a private anchor is reported.
  9. Walker CPU per uncached connection is bounded by `MAX_VERIFICATIONS`, about 250 ms of RSA-4096
     on a mid-range ART device, and both caches are defeated by one varying junk byte per connection;
     `MAX_PRESENTED` bounds parsing (counted over the raw chain, before dropping). The PKIX fallback's build is outside
     these budgets: `CertPathBuilder` has no candidate budget and backtracks through every name-matching
     candidate (§5.1 "PKIX fallback contract", Appendix A). It runs at most once per uncached decision, only after a
     walk `NotFound` or `Budget`, and only on a chain of at most `FALLBACK_MAX_PRESENTED` (8) presented certificates,
     which bounds what a server can stuff in front of it; its result is cached under the path key, which the same
     varying byte defeats. `pkixFallback(false)` removes it where the policy allows (item 1).
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
  14. **Keyability is a prediction.** The producer keys the logged precertificate (about half of CT entries). It also
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
  15. **Constrained sub-CA.** A holder of a CA key under a real anchor can certify a recovered key, and the walker then
     reports only that benign key as long as the honest intermediate is not presented. This includes a technically
     constrained sub-CA whose `pathLenConstraint`, name constraints or EKU should forbid it: the walker checks
     `cA = TRUE` on an issuer and enforces none of `pathLenConstraint`, keyUsage `keyCertSign`, name constraints or EKU
     nesting there. So the holder of a `pathLen 0` sub-CA S under a real root can sign C, a CA certificate for a key
     recovered from a revoked leaf's signature, and `[L, C, S]` walks to `Found([L, C, S, R])` with C's benign key as
     the only leaf-issuer key; x509-limbo's `pathlen::intermediate-violates-pathlen-0` likewise walks to `Found`. On
     the bindings the platform validates the chain first (step 1), and a chain that breaks those constraints does not
     reach the walker.
- Feed authenticity: every generation is verified against Mozilla's content-signature roots, from the feed or from a
  seed (§7.1); there is no unsigned source. The M2 denylist is project-attested and availability-only.
- Rollback and freeze: a persisted non-decreasing watermark with a 24 h tolerance and a
  coverage-monotonic rule inside that window; a newer signed changeset always installs and the
  pinned terminal's validity is never checked; **no signed record can freeze the signed source**: a
  signed revocation of the feed host holds fetches for at most 24 h, then they proceed with
  `feedHostRevoked` loud; handshakes are attributed structurally (one internal trust manager per source), so a consumer's unrelated traffic on the public `fetcherTrustManager` can neither start the hold nor inherit `feedHostRevoked`; the cursor and watermark move only on a
  successful install after collection-schema validation, so a replayed sibling-collection changeset
  cannot freeze them; the content signature binds neither bucket nor collection, so a party the fetcher's TLS trusts (a private mirror) can serve `security-state-preview`'s `cert-revocations` as production data (residual: Mozilla data pending review, low impact; recorded beside the collection-id note); unsigned transport headers cannot persist a backoff beyond 24 h;
  staleness always visible; no ceiling in `DEFAULT` (upki's model); `rejectStaleAfter` is the
  optional ceiling; a changeset dated beyond local now + `clockSkew` is refused while a generation that is not itself `clockBehind` exists, and installed without advancing the watermark or cursor when none does or the live one is `clockBehind` (§6.3), so a single
  future-dated signed record cannot pin the watermark in either case; a future-dated seed installs with the watermark at its signed timestamp, which only a newer signed changeset can pass, as for any seed. The effective watermark is never below the live
  generation's timestamp unless that generation is `clockBehind` (§6.3), so losing `updater.json` reopens
  no rollback. After `resetState()` the rollback bound is the
  seed's timestamp once the start task has swapped the live generation; until then the watermark floor still holds it
  at the old live generation's timestamp, which is stricter (residual: `updater.json` is deleted with the store).
- Self-lockout bounded: a signed revocation of the signed source's own certificate holds fetches 24 h and is
  then reported as `feedHostRevoked` while fetches proceed (the payload is authenticated end to end, so
  TLS authenticity to that host protects nothing an attacker could exploit); this is the one deliberate departure
  from Firefox's behaviour on the feed path; untrusted bytes (the changeset JSON, the x5u chain) are hardened with
  allocation budgets and per-kind download caps, so an unsigned body cannot exhaust the heap; no fetch follows a
  redirect (§7.1);
  x5u allowlisted, capped and path-validated, following mozilla::pkix's chain checks (§7.1); the
  TLS parser is at least as lenient as the platforms,
  verified differentially (§9.2), and `PARSE_FAILED` applies to the leaf only.
- Crypto never implemented in Kotlin except the raw-to-DER ECDSA conversion, the `ECDSA-Sig-Value` decode and the r and s range comparison (§3) and the §9.2 profile's EC on-curve check (public field arithmetic over P-256, P-384 and P-521, no secret data); `UNSUPPORTED` is decided
  by a startup probe, never by a server-chosen exception; provider exceptions never escape the
  trust manager.
- Privacy: no per-connection lookups. Blast radius mitigated by `Enforcement.OBSERVE`, `shadowPolicy`, the runtime
  switch, seeds, the fixed fetcher policy (which ignores `Enforcement`), dated data artifacts, and `ENGINE_ERROR = allow` in `DEFAULT`;
  an engine exception never masks a data rule, which is computed outside the catch boundary.
- Supply chain: reproducible builds, publishing from CI only (a protected release environment with a second maintainer's approval, PGP-signed artefacts, SLSA provenance attestations; Central Portal has no OIDC trusted publishing), SBOM, `dependencyLocking`,
  `SECURITY.md`, two-person review on the clubcard module, the verifiers, the walker,
  `RevoktTrustManager` and the §9.2 parser; seed archive entries are capped while inflating (§6.5) and
  everything in a seed outside `seed.json` is Mozilla-signed or hashed; the entry names are not, so the loader reads
  only the fixed entries and the attachments the verified records name, and derives no name or path from an entry
  (§6.5); seed artifacts carry no code
  dependency, so a data bump cannot desynchronise the code set.

## 11. Milestones and versioning

0.x until M2; from 1.0 BCV dumps (the 1.0 promise covers revokt's own API; the OkHttp and Ktor bindings pin those libraries' majors and follow them), deprecation `WARNING` → `ERROR` → removal in a major, opt-in
APIs outside the promise, the growability contract in §4.

| Release | Scope | Estimate |
|---|---|---|
| 0.1 | engine scaffold, `RevocationEngine`, `Rule`/precedence model with the one-to-one tests, purity gate, BCV, POM assertions; `SymVerifier`, the reference walker and the §9.1 chain generator in `revokt-engine`'s test source set (they move to the published `revokt-testing` in 0.3; the walker fuzzer itself is 0.2, with the walker); TBS/SCT parser (incl. `producerKeyable`, `notBefore`/`notAfter`) with the D7 corpus, the issuer corpus and the §9.2 differential parser oracle (0.1 gate: oracles 1, 2 uber, 3a/3b, 4, properties D1–D3, D5, D6, D8 (gated direction; D8 gap reported)); JSON tree and canonical JSON (§7.1; the content-signature payload builder is 0.2); clubcard port (v3 + v4); the C2SP `index.bin` reader/writer and `GenerationFiles` (`KotlinRevocationEngine.prepare` needs them); the `revokt-engine` jvmMain `Rule → BasicReason` map; oracle CI | 5 weeks |
| 0.2 | a minimal `Revokt` (`build()`, a synchronous `start()` that builds one `CandidateIndex` over `platformTrust.anchors(platformTrust.defaultDelegate())`, loads the seed, runs the in-memory updater on the loader dispatcher and publishes the generation reference, `close()`; no readiness future, caches, factory lock, per-delegate instances or `state`; start diagnostics returned from `start()` as `List<PolicyDiagnostic>` until `state` exists; `start()` over an empty or throwing default trust store succeeds, and `evaluator.evaluate` throws `IllegalStateException` until an index exists; `sync()`, `syncAsync()` and `syncBlocking()` are internal and the updater syncs only on its schedule, while `SyncResult`, `SyncOutcome` and `SyncStage` ship public; each source's `FetcherTls` carries the platform `fetcherDelegate` only, so the §8 fetcher policy does not run in 0.2); candidate index and walker per §5.1, the PKIX fallback (the jvmMain `PkixPathBuilderFallback`, which Android also runs through ojluni, tested on the JVM; the Android instrumented run is 0.3), the §9.2 read fallback in the JVM binding, the walker-only harness, `Evaluator.evaluate` over that one index (decision steps 2–3 and 5–8, walker reason reported directly; `Revokt.evaluate(…, delegate)` is 0.3) with the §9 `Rule` model's [0.2] tests and the §9 API rows; **the §9.1 walker fuzzer is built and runs against the implementation here (P1–P8 gate)** and the walker's adversarial review precedes it; Remote Settings protocol and content-signature verification with x5u path validation (the §9 content-signature fixtures less the three tagged [0.3]); CRLite updater and the updater record over `RevoktStorage.inMemory()` (the §6.5 key layout in memory; durability, `store.version`, pointer flip, crash recovery and the lock are 0.3); seeds with `seed.json`; data artifacts job; coverage sanity and rollback; the §9 data-path fixtures (a), (b), (d) and (g) less its `BLOCKED_BY_SELF` item and its Android and OkHttp fetcher halves; CI-only upki engine and the cross-engine suite (the issuer taken from the corpus chain's presented order, no walk needed); benchmarks | 4 weeks |
| 0.3 | §6.5 store (`store.version`, `meta.json`, pointer flip, crash recovery, lock); the §9 data-path fixtures (e), (f), (h) and the (g) items deferred from 0.2 (`BLOCKED_BY_SELF`, and the Android and OkHttp fetcher halves); the §9 content-signature fixtures tagged [0.3] (the restart with the clock behind); caches; per-delegate trust managers and `Revokt.evaluate(…, delegate)`; the fetcher trust managers (`fetcherTrustManager` and the per-source instances in `FetcherTls`) with the §8 fetcher policy, `FETCHER_TRUST_UNAVAILABLE` and the `BLOCKED_BY_SELF` hold; public `sync()`, `syncAsync()` and `syncBlocking()`; lifecycle state machine and readiness future; OkHttp and per-engine Ktor bindings; `OBSERVE` events, `shadowPolicy`, `status()` and `state`, with the §9 `Rule` model's [0.3] tests; Android instrumented suite including the PKIX fallback, the null-host probe and the main-thread wiring probe under `StrictMode.detectDiskReads` on API 26/31/34/36, cold process and after a trust-store change (induced by `am broadcast -a android.security.STORE_CHANGED` as root on AOSP userdebug images, or by installing a user CA through `KeyChain.createInstallIntent()` under UiAutomator on images without root; the mirrored image matrix carries a userdebug variant for this); a consumer fixture built with AGP 8.5.2 that dexes the published artifacts (the Android floor; Appendix A); Baseline Profile and measured `AWAIT_DATA` (JVM default 2 s); WorkManager (`RevoktSyncWorker`, `Revokt.Provider`); system images mirrored into project storage for the emulator matrix; `revokt-testing`; optional `revokt-bc` | 5 weeks |

About 14 weeks. **M2** (0.4, then 1.0): preloading as a second candidate set, exhaustive re-walk on L1/L2
hits, OneCRL including anchors, denylist, CRLSet, `NOT_ENROLLED` split, the §5.2 residual closed,
eMudhra suite; new `REJECT` rows ship `ALLOW` for one minor. **M3**: CT with `CT_UNVERIFIED`. **M4**:
per-anchor distrust over every walker path. **M5**: MTC through `Evaluator.evaluate` only, routed by `EvaluationRequest.credentialType` before decision step 3, evaluated by its own seam (never a `RevocationEngine`, §3.2).

## 12. Approach 1 vs approach 2 for crema

Not normative: [docs/design/crema-approach.md](../design/crema-approach.md).

## 13. Naming and publishing

**Decision: `revokt`.** Verified 2026-10-21: Maven Central `dev.revokt` free;
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
dedicated adversarial review once they are implemented (after the walker, `reconstruct` and decision steps 1–8
merge) and before the §9.1 walker fuzzer runs against them**, since every review round so far found its hole there.
**Before 0.2 ships, the §9.1 walker fuzzer must pass P1–P8 against the implementation.**

## Appendix A. Verification log (2026-10-21, additions 2026-10-22)

The verification log is [references.md](references.md).
