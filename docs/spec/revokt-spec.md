# revokt: a pure-Kotlin CRLite engine with JVM and Android bindings, growing into a WebPKI client-policy library

Status: **draft spec, revision 61** · Target: JVM 17+ and Android API 26+, Kotlin 2.3+ consumers · Date: 2026-11-20

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
| `revokt-engine` | common | DER/TBS parser, `EvaluationRequest` and `Evaluator` (sealed; its single implementation lives beside it and is what `Revokt.evaluator` returns), candidate index and path walker, coverage index, generation model, policy and precedence, `Verdict`, JSON tree and canonical JSON, content-signature logic, C2SP cache reader/writer, `RevocationEngine` (Kotlin), the `SignatureVerifier`, `HttpFetcher`, `PathBuilderFallback` interfaces, `expect fun canonicalSubject`, `RevoktLimits`, the internal policy table; **no public type with a `java.time` member** | `revokt-clubcard`, Okio, kotlinx-coroutines |
| `revokt-engine` `jvmMain` | jvm | `KotlinRevocationEngine` (the default engine) and its CRLite evaluation, the updater state machine and sync, the Remote Settings protocol and `MozillaRemoteSettings`, `RevoktStorage` (`@RevoktInternalApi` in 0.2; [0.3] a sealed type built by its factories), `RevoktStorage.inMemory()` and the store layout, `OwnershipCheck` and `NewerLayout`, the seed loader and archive reader, JVM-only until a second target is planned (the native compile checks the common parts only), `Staleness`, `RevoktPolicy` and its `Builder` (the public policy surface, with `java.time` members), `JvmStorage`, `actual canonicalSubject` (`X500Principal.getName(CANONICAL)`), `SeedSource` (`none`, `of`, `fromResource`, `bundled`), `SeedOpener` and `JvmSeedSource`, `JcaSignatureVerifier(provider)`, `PkixPathBuilderFallback`, `PlatformTrust` (both `@RevoktInternalApi` in 0.2), the `Rule → BasicReason` map (`java.security.cert`, so jvmMain; total over `Rule.entries`, asserted by the 0.1 golden fixture), `RevoktLoggers.jul()` | JDK |
| `revokt-jsse` | jvm | `Revokt` facade and `Builder`, `RevoktTrustManager`, `JvmPlatformTrust`, `X509Certificate` adapters, `JdkHttpFetcher` (HttpsURLConnection over the platform's default TLS, the default `http` on the JVM; never on Android, §4) | `revokt-engine` |
| `revokt-bc` *(optional)* | jvm | BouncyCastle `SignatureVerifier` for ML-DSA, SLH-DSA, composite OIDs and BC-only curves | `revokt-engine`, bcprov |
| `revokt-okhttp` | jvm | `RevoktOkHttp.install(builder, revokt, delegate?)`, `OkHttpClient.Builder.revokt(…)`, `OkHttpClient.withRevokt(…)`, `OkHttpClient.revoktTrustManager()`, OkHttp-backed `HttpFetcher` | `revokt-jsse`, OkHttp 4.12+ / 5.x |
| `revokt-ktor-core` | jvm | Ktor-backed `HttpFetcher` (refuses CIO on Android) | `revokt-jsse`, ktor-client-core |
| `revokt-ktor-okhttp`, `-ktor-cio`, `-ktor-java`, `-ktor-android` | jvm | One adapter per engine (Ktor's Android engine is a JVM artifact) | `revokt-ktor-core`, that engine |
| `revokt-android` | android | `AndroidPlatformTrust` (final), `AndroidStorage.noBackup(context, name)` / `deviceProtected(context, name)`, `RevoktAndroid.observeLifecycle(provider)` (the §5.2 lifecycle observer, for consumers without WorkManager), `AndroidHttpFetcher` (HttpsURLConnection without the JDK-only `setAuthenticator`; the fallback default `http` on Android, §4), `RevoktAndroid.logger()`, consumer R8 rules, Baseline Profile; the Android PKIX fallback | `revokt-jsse` |
| `revokt-android-work` | android | WorkManager periodic sync: worker class `dev.revokt.android.work.RevoktSyncWorker` and unique work name `dev.revokt.sync.<name>` (one per instance, `name` carried in the worker's input data) are fixed from 0.3 (WorkManager persists both across upgrades); `object RevoktWork { @JvmStatic @JvmOverloads fun install(context: Context, provider: Revokt.Provider, name: String = "default"); @JvmStatic @JvmOverloads fun uninstall(context: Context, name: String = "default") }` (`uninstall` also removes the §5.2 lifecycle observer `install` registered), called in `Application.onCreate`, registers the provider by name in a static map; the worker takes the instance from it (`Provider.revokt()` runs on the worker thread, off the main thread), calls `start()` itself when the instance is `CREATED` (idempotent, under the factory lock; a `start()` throw is `Result.retry()` with the exception logged at `WARN`, except `SEED_CHANNEL_MISMATCH` and a validate() `ERROR`, which cannot change between periods and are `Result.failure()` that cancels the unique work, logged at `ERROR`), then `syncBlocking()`, which queues behind the start task; a worker with no registered provider returns `Result.failure()` and cancels its own unique work; `RevoktWork.uninstall(context, name)` cancels the unique work and removes the provider (an app that drops the library must call it once, or WorkManager keeps instantiating the missing class every period); **stop semantics**: on `onStopped` or interruption the worker returns (WorkManager ignores its result), the in-flight sync completes on the loader, the next period re-runs; the worst-case fetch sum of one signed sync (≈ 11 fetches × `FETCH_TIMEOUT`) is under WorkManager's 10-minute limit by construction; outcome mapping: `INSTALLED`/`UNCHANGED`/`SKIPPED` → success, `FAILED` → retry. An instance running in memory (`RevoktState.storageFallback`, §3) may still host the worker | `revokt-android`, WorkManager; `RevoktWork.install` enqueues `PeriodicWorkRequest(6 h, flex 1 h)` with `NetworkType.CONNECTED`, exponential backoff and `ExistingPeriodicWorkPolicy.UPDATE` (so a library upgrade can change them); consumer rules in this artifact keep `RevoktSyncWorker` and its `(Context, WorkerParameters)` constructor (WorkManager instantiates it by name, an obfuscated class fails silently); a provider that throws is `Result.retry()` with the exception logged at `WARN`; a `CLOSED` instance is `Result.failure()` and cancels the unique work (it can never become `STARTED`); an instance running on the in-memory fallback (`RevoktState.storageFallback`, §6.5) **syncs as any other** (the 6 h poll interval bounds the cost; it syncs from its seed's `<ts>` each start (§7.1) and never retries its configured storage, §3), so a direct-boot or rolled-back process still receives data; the §5.2 lifecycle observer's foreground `sync()` queues behind and honours `backoffUntilMillis`, so overlap with the worker is harmless |
| `revokt-testing` | jvm | `FakeRevokt` (a builder preset, `object FakeRevokt { @JvmStatic fun builder(): Revokt.Builder }`, since `Revokt` is final), `SymVerifier`, the reference walker (takes `List<ByteArray>`, returns `Set<String>` of lowercase-hex leaf-issuer SPKI hashes, so P2's equality is by value), recorded fixtures, the §9.1 chain generator; from 0.1 to 0.3 these live in `revokt-engine`'s test source set and move here in 0.3. Built from public API only, plus the test factories for output types, whose constructors and builders are internal to `revokt-engine` (§4); `FetchRequest`'s builder is `@RevoktTestingApi` until then. | `revokt-engine`, `revokt-jsse` |
| `revokt-bom` | — | Code artifacts only, including both `revokt-engine` (KMP root) and `revokt-engine-jvm`; the Maven consumer test references both | — |
| `revokt-seed-compat`, `revokt-seed-default`, `revokt-denylist` *(M2)* | data | Date-versioned, weekly, not in the BOM; in 0.2 a GitHub release asset with attestations, not on Maven Central (§7.2) | — |
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
@RevoktInternalApi interface PathBuilderFallback { fun build(chainDer: List<ByteArray>, anchors: AnchorSnapshot, nowMillis: Long): List<ByteArray>? }   // leaf first, trust anchor's certificate appended last; null = no path; a throw counts as a failed build: FallbackNotUsed(FAILED), cached in neither the path nor the verdict cache, every VirtualMachineError except StackOverflowError rethrown (§5.1 decision step 6); `@RevoktInternalApi` with its only consumer, PlatformTrust, in 0.2, and public with it in 0.3 (the Android binding)
internal expect fun canonicalSubject(nameDer: ByteArray): String?     // JVM/Android: X500Principal(der).getName(CANONICAL), null on a construction failure; linuxX64 gate: an empty actual stub returning null (the gate only compiles); the public seam is PlatformTrust.canonicalSubject
enum class NewerLayout { IN_MEMORY, REBUILD }   // jvmMain, beside JvmStorage; growable; what a store whose `store.version` is higher than this engine's gets (§6.5)
fun interface RevoktLogger { fun log(level: LogLevel, message: String, cause: Throwable?) }   // commonMain; every "logged" in this document names its level. jvmMain: object RevoktLoggers { @JvmStatic fun jul(): RevoktLogger } (java.util.logging "dev.revokt"; DEBUG → FINE, INFO → INFO, WARN → WARNING, ERROR → SEVERE, the slf4j-jdk14 and log4j mapping, so DEBUG is hidden under JUL's default INFO level); revokt-android: RevoktAndroid.logger() (android.util.Log, tag "revokt"; kept by the consumer R8 rules); builder default: RevoktAndroid.logger() when revokt-android resolves by class name, else RevoktLoggers.jul() (a commonMain fun interface cannot gain companion members in another source set); a throwing logger is swallowed (never on a handshake path's verdict)
enum class LogLevel { DEBUG, INFO, WARN, ERROR }   // closed
enum class OwnershipCheck { STRICT, OWNER_OR_GROUP }   // jvmMain, beside JvmStorage; growable
sealed class RevoktStorage {                                // [0.3] flat key space; the engine owns the layout (§6.5). Built only by inMemory(), JvmStorage.directory(…) and AndroidStorage's factories, never implemented by a consumer (upki takes a cache directory, Firefox its profile directory); its members below are internal: those of the `@RevoktInternalApi` interface StorageBackend it wraps, so a consumer cannot implement one, and revokt's own tests wrap a recording backend through the `@RevoktInternalApi` RevoktStorage.of(backend), in memory only when the backend is the in-memory one; the `@RevoktInternalApi` isInMemory is what revokt-jsse's V IN_MEMORY_STORE_WITH_FETCHING_SOURCE reads (`RevoktStorageTest`); one value serves one started instance at a time, a second start() on it in the process throwing (`RevoktStoreTest`). 0.2 has no storage(…) setter and runs on inMemory() (§11), so in 0.2 RevoktStorage is a @RevoktInternalApi interface
    internal fun read(name: String): ByteArray?                     // null = absent; a read that fails throws, never returns null
    internal fun write(name: String, bytes: ByteArray)              // atomic replace, durable (fsync) before return; visible to read() only when complete
    internal fun delete(name: String); internal fun names(): Set<String>     // keys: segments of [a-z0-9._-]{1,96} joined by '/', never '.' or '..', lowercase so that no two keys are one file on a case-insensitive file system (macOS, Windows) and no key is `.lock` there (`RevoktStorageContract`); no segment is `.lock`, and `store.version` is a key only as the whole key, so no key names a store nested inside this one (`StoreKeysTest`); a key resolving outside the root is rejected; delete() removes directories left empty; names() excludes the lock, temp files and every entry whose path is not a key (JvmStorage lists regular files only and follows no symbolic link below its root's real path, the root itself being the caller's choice: a link, or anything but a directory or a regular file, anywhere in a key's path makes it not a key, so names() skips it and read(), write() and delete() of it throw; `JvmStorageTest`; a directory below the root that holds a `.lock` is another store's root: names() does not enter it and lock()'s sweep deletes no temp file in it, so an outer store's rebuild or sweep never deletes an inner one's files, while lock()'s ownership check and directory fsync still visit it, so a planted `.lock` hides no directory from the check; in a key's path it is treated as a link, so read(), write() and delete() through it throw and an outer store never writes into an inner one, `StoreOpenTest`)
    internal fun isEmpty(): Boolean                                 // §6.5 "empty": no key, and for JvmStorage no entry in its root but `.lock` and temp files, so a directory holding files that are not keys is not empty (`JvmStorageTest`)
    internal fun identity(): Any? = null                            // stable key for the per-process single-instance registry, read by start(), never by build(); JvmStorage: the root's file key (device and inode), or its real path where the file system has none, read after creating the root as lock() does, so a symbolic link, a bind mount or another spelling of the path meets the same entry, and a failure is STORE_UNREADABLE (`JvmStorageTest`, `StoreOpenTest`); inMemory(): the instance itself, so one in-memory value given to two instances throws at the second start() as one directory does, while the builder default and a fallback's store, each fresh, never meet another (`RevoktStorageTest`, `RevoktStoreTest`); null = not registered
    internal fun lock(): AutoCloseable                              // exclusive; acquired in start() and held to close(); bounded wait ≤ 1 s then the internal StoreLockedException (JvmStorage: FileChannel.tryLock on `.lock`, tried every 100 ms for 1 s; one channel per `.lock` file in a process, keyed on its file key (device and inode, as the JDK's own lock table; its path where the file system has none), so a second lock() in the process, through any path to the file, a hard link or a bind mount included, waits for the first to close and never opens `.lock` itself, whose close would drop the process's fcntl lock; OverlappingFileLockException maps to it; lock() creates the root, resolves its real path once, checks ownership, and only then lstats `.lock`, creating it when absent, refuses anything but a regular file (a planted link or a FIFO is STORE_UNREADABLE within the bound), and opens it for reading and writing with no link followed, since a write-only open blocks on a FIFO; `.lock` is created rw------- and never deleted; any other failure in lock(), creating the root or `.lock`, the ownership check, the sweep or a directory fsync, is the internal StoreUnreadableException, STORE_UNREADABLE, handled as the ownership failure is; `JvmStorageLockTest`, its second-process tests over a child JVM); on it the instance runs on inMemory() for the life of the process with the STORE_LOCKED warning, its identity deregistered, and the lock is never tried again; never called per write
    companion object { @JvmStatic fun inMemory(): RevoktStorage } }   // methods are thread-safe for concurrent reads; every write() fsyncs the file, renames into place, then fsyncs the parent directory, new key or not (a rename over an existing name is otherwise not durable), and a write whose fsync, directory fsync or rename throws throws (on Windows, where a directory cannot be opened, the directory fsync is skipped); JvmStorage's lock(), once it holds the lock, deletes every temp file under its root and then fsyncs every directory under its root, the root included, and JvmStorage fsyncs the parent of every directory it creates, the root's included, so a key another process renamed into place before its parent's fsync is durable before a pointer names it (§6.5; test-plan.md (e), `JvmStorageTest`); delete() need not be durable; the lock lives under the reserved key `.lock`, which no path other than lock() ever opens, lists or deletes (names()/delete() exclude it), so the POSIX fcntl lock cannot be dropped by a stray close; JvmStorage's ownership check, in lock(), compares the directory's unix:uid attribute with that of a probe file it creates under a temp name and deletes (the JVM has no getuid; a probe that cannot be deleted is STORE_UNREADABLE), and is skipped where the file system has no unix view; the root's mode is checked before the probe is written into it; every directory under the root, in lock()'s walk, must have the same uid and pass the same mode rule, checked as the walk enters it and so before the sweep deletes anything there, else STORE_UNREADABLE, so no one but the owner can swap a directory on a key's path for a link between a check and its use (`JvmStorageTest`, `JvmStorageLockTest`)
// jvmMain [0.3]: object JvmStorage { @JvmStatic @JvmOverloads fun directory(dir: java.nio.file.Path, ownership: OwnershipCheck = OwnershipCheck.STRICT, onNewerLayout: NewerLayout = NewerLayout.IN_MEMORY): RevoktStorage }   // Java sees (dir), (dir, ownership) and the full form, so a REBUILD caller spells out STRICT; does no I/O: start() creates the directory, through identity() and lock(), and close() releases it (`RevoktStorageTest`, `RevoktStoreTest`); every directory JvmStorage creates is rwx------ and every file rw-------; on POSIX the directory must be owned by the process uid and, under STRICT, not group/other-writable (OwnershipCheck.OWNER_OR_GROUP tolerates group-writable, the Kubernetes fsGroup case, documented in the README), else STORE_UNREADABLE and the instance runs on inMemory() for the life of the process (no read, no write, never chmod, never retried; the store lock is released and the identity deregistered, as for STORE_NEWER_LAYOUT, §6.5, and RevoktState.storageFallback = true; residuals: every start of such a process floors at its seed's watermark and syncs from its seed's `<ts>` each start (§7.1)); the lock is per directory while the layout is per channel, so two channels on one directory in two processes run the second in memory with STORE_LOCKED, and in one process the registry throws (use one directory per channel); never share a directory across hosts (advisory fcntl over NFS); Windows: ATOMIC_MOVE over an open `current` is retried every 10 ms for up to 1 s, then the write throws (`JvmStorageTest`)
// revokt-android: AndroidStorage.noBackup(context, name) = JvmStorage.directory(context.noBackupFilesDir.toPath().resolve(name), STRICT, onNewerLayout = REBUILD) (one package owns its directory, so a higher store.version there can only be a Play rollback to an older binary, which must keep working: rebuilt from the seed with STORE_NEWER_LAYOUT); credential-encrypted, so unavailable before the first unlock: an instance started from a direct-boot-aware component gets STORE_UNREADABLE and runs on inMemory() until its process restarts; AndroidStorage.deviceProtected(context, name) is the recommended value for anything started before unlock (the data is public Mozilla data). Builder default: a fresh RevoktStorage.inMemory() at each build(), so two builds from one builder never share a store (the `storage` property is null until set; `RevoktBuilderTest`, `RevoktStoreTest`), meant for tests and 0.2; on AndroidPlatformTrust build() throws R STORAGE_UNSET unless storage was set, inMemory() included (an explicit inMemory() is a decision; the default would silently age the seed); on the JVM V IN_MEMORY_STORE_WITH_FETCHING_SOURCE warns, for the default and an explicit inMemory() alike (§4)
class FetchRequest private constructor(…) {   // @RevoktTestingApi Builder, so fetcher tests can construct requests; val url: String; val headers: Map<String, String> /* engine sets User-Agent and If-None-Match, the latter synthesised as the quoted `<ts>` of the generation served (§7.1), never an echoed server ETag (a persisted ETag the transport rejects would fail every later request); a 304 is UNCHANGED and updates lastAttemptAtMillis only; never Accept-Encoding, which a fetcher that inflates sets itself (JdkHttpFetcher asks for gzip, §4) */; val maxBodyBytes: Long /* min(attachment.size, MAX_FILTER_BYTES) for a SIGNED body, else the per-kind RevoktLimits cap */; val timeoutMillis: Long /* enforced by the engine: each fetch runs under Future.get(timeoutMillis) on ioDispatcher; expiry is FAILED and the next sync proceeds, so a hung injected fetcher cannot block later syncs */ }
class FetchResponse private constructor(…) { class Builder { fun status(status: Int): Builder; fun header(name: String, value: String): Builder; fun headers(headers: Map<String, List<String>>): Builder; fun body(body: ByteArray): Builder; fun build(): FetchResponse }; companion object { @JvmStatic fun of(status: Int, headers: Map<String, List<String>>, body: ByteArray): FetchResponse }   // public, not testing-API: an HttpFetcher must construct one
    val status: Int; val headers: Map<String, List<String>>; val body: ByteArray /* decoded, buffered; the fetcher stops at maxBodyBytes while inflating (gzip bomb) and throws; a fetcher never follows a 3xx and returns it as is, and a 3xx is FAILED; the engine re-checks and hashes */ }
fun interface HttpFetcher { fun fetch(request: FetchRequest): FetchResponse /* synchronous; the consumer supplies it (or takes the platform default, §4), and it handshakes over the platform's TLS and trust manager, or its own client's: revokt adds no trust policy to a fetch; TLS and hostname verification are the fetcher's (HttpsURLConnection's endpoint identification; OkHttp's default hostnameVerifier); runs on ioDispatcher, never the loader; never follows a redirect, its underlying client configured not to, and nothing above it follows one either; must honour thread interruption so a timed-out fetch does not pile up; the body is handed to the loader, which alone writes the store; any Throwable = SyncOutcome.FAILED for that sync; a 401 or 407 is FAILED on every platform and no fetcher ever answers a challenge */ }   // a 401/407 is the SyncFailure of the fetch it interrupted (CHANGESET_FETCH, X5U_FETCH or ATTACHMENT_FETCH)
// jvmMain (JVM types, so not in commonMain). PlatformTrust, PkixPathBuilderFallback and JvmPlatformTrust are @RevoktInternalApi in 0.2: the JVM binding wires JvmPlatformTrust() itself and Revokt.Builder has no platformTrust(…) member; they go public with their first consumer outside revokt's own modules, the 0.3 Android binding
interface PlatformTrust {
    fun defaultDelegate(): X509TrustManager
    fun requiresExtendedDelegate(): Boolean
    fun verifiedChain(delegate: X509TrustManager, chain: Array<X509Certificate>, host: String?): List<X509Certificate>?   // null = unavailable on this binding; a throw = decision step 4 failure
    fun pathBuilder(): PathBuilderFallback
    fun anchors(delegate: X509TrustManager): List<X509Certificate>    // getAcceptedIssuers()
    fun canonicalSubject(nameDer: ByteArray): String? = dev.revokt.canonicalSubject(nameDer) }   // the internal expect, qualified. JvmPlatformTrust and AndroidPlatformTrust are final; an override changes which certificates are related, and an issuer it misclassifies is left to the PKIX fallback (§5.1 deferral rule, §10 residual 1)
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
`klib { enabled = false }`. The expect/actual pairs left in commonMain (`lruMap`, `isFatal` and `restoreInterrupt`,
`canonicalSubject`) exist so that this compile covers the walker and the content-signature and x5u logic.
Generation publication is a `@Volatile` reference whose only writers are
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
Remote Settings data", carried in the seed jar as its manifest's `Revokt-Data-License` and as `META-INF/LICENSE-DATA`
(`DataArtifactPluginFunctionalTest`); in 0.2 they are GitHub release assets with attestations, not on Maven Central, so
they have no POM. Apache over MIT: explicit patent grant and retaliation, contribution
licensing without a CLA, name protection, JVM scanner expectations.

**`revokt-clubcard`: MPL-2.0 port**, about 44 KB of Rust, contained per §3.1, replaceable later.

### 3.1 Containing the MPL port

MPL-2.0 is file-level copyleft. Upstream files carry the Exhibit A header only, **no Exhibit B**.
1. One module, own `LICENSE` and `NOTICE`; every publication's POM lists MPL-2.0 only; CI asserts.
2. 1:1 translation files in `…clubcard.port` with SPDX and provenance headers; glue in `…clubcard.api` under Apache.
3. `reuse lint` on every PR plus the header-location rule.
4. `public` + `@RevoktInternalApi` (error-level opt-in, engine only), BCV `nonPublicMarkers = ["dev.revokt.RevoktInternalApi", "dev.revokt.RevoktTestingApi"]` (so testing builders never enter the 1.0 dump), `implementation` scope. The cross-artifact plumbing `Revokt` (revokt-jsse) drives in revokt-engine (identity registry, store lock, loader, `generationEpoch`/`policyEpoch`, the `RevocationEngine` seam of §3.2) is public under `@RevoktInternalApi`; a Kotlin consumer compile runs beside the Java one in CI, since `@JvmSynthetic` members are invisible to BCV.
5. No `inline fun`, no `const val` in the port.
6. Never shaded or merged into another Apache artifact.
7. `UPSTREAM.md`; weekly drift job; re-syncs translate the upstream diff.
8. `-sources.jar` on Central; POM license picked up by notice tooling.
9. Contributions under MPL-2.0; DCO.
10. Exit path: nothing MPL is supported API; the oracle corpus is the acceptance test.

### 3.2 `RevocationEngine` and the upki-backed engine

```kotlin
@RevoktInternalApi interface RevocationEngine : AutoCloseable {
    val formats: Set<FilterFormat>                                   // a generation with any filter (the full or a delta) in another format is never offered to prepare() (§6.5 format check)
    val name: String get() = this::class.simpleName ?: "anonymous"   // the class's simple name, or "anonymous" when the class has none; Finding.EngineError.engineName on every ENGINE_ERROR whose producer is ENGINE (§4, §5.5), so never null there; the Kotlin engine returns "kotlin", the upki engine "upki"; must not throw, and revokt reads it once per instance; on Android under R8, which renames classes, an engine overrides it with a stable string
    fun prepare(generation: GenerationFiles): PreparedGeneration     // serialised: the loader dispatcher, or the start() caller's thread in the sole-seed synchronous path (§4 S), never concurrently; builds an inactive state (decode, validate); throws on a corrupt generation; the engine's live generation is untouched
    fun activate(prepared: PreparedGeneration)                        // loader only; atomic swap with respect to concurrent query(); the previous generation is released once in-flight queries drain; a throw leaves the live generation in place
    fun install(generation: GenerationFiles): String = prepare(generation).use { activate(it); it.generationId }   // convenience (use {} so an activate() throw closes the prepared generation; close() after activate() is a no-op); the loader never calls it: it calls prepare() and activate() as separate §6.5 steps, so a prepare() failure leaves the engine untouched
    fun clear() {}                                                   // default body is a no-op for an engine that holds no state; an engine holding a live generation must override: drops it, query() then returns NO_DATA
    fun query(q: CrliteQuery): CrliteQueryResult                        // the only engine input, extracted by revokt's parser from the path-verified leaf and issuer (§5.1) for every engine, so an engine swap cannot change what is looked up; never throws; precedence, fixed for every engine: after close() → ENGINE_ERROR; no generation → NO_DATA; q.scts empty → NO_SCTS; else the §6.2 aggregate
    val coverageEndMillis: Long?                                     // null when the engine cannot tell
}
@RevoktInternalApi interface PreparedGeneration : AutoCloseable { val generationId: String; fun query(q: CrliteQuery): CrliteQueryResult }   // inactive; query() answers against it alone (the engine probes of test-plan.md §9.3 use it); close() without activate() discards it; after activate() the engine owns it and close() is a no-op. RevocationEngine.close() is idempotent; an engine instance may be injected into one Revokt only, ever (R: build() throws on a second; a weak identity registry, so an engine's own equals is not consulted; a build() that throws registers nothing)
@RevoktInternalApi enum class FilterFormat { V3, V4 }                                          // growable; with the seam's other data types (GenerationFiles, CrliteQuery, CrliteSct), @RevoktInternalApi, since only the seam uses them (#221)
enum class CrliteQueryResult { NOT_REVOKED, REVOKED, NOT_COVERED, NOT_ENROLLED, NO_SCTS, NO_DATA, ENGINE_ERROR }   // growable; the only CRLite status type
@RevoktInternalApi class GenerationFiles internal constructor(…) {   // always C2SP layout: "index.bin" plus the files it names; internal Builder; jvmMain: @RevoktInternalApi object JvmGenerationFiles { @JvmStatic fun fromDirectory(dir: java.nio.file.Path, dataset: Dataset, format: FilterFormat): GenerationFiles }, so an engine is testable against the §9 corpus images from revokt-engine alone
    val generationId: String; val dataset: Dataset; val format: FilterFormat   // the full filter's encoding; each filter is read in its own (mixed encodings allowed), and every one is in the engine's formats (§6.5 format check)
    val names: Set<String>; fun bytes(name: String): ByteArray /* fresh copy; a disk-backed implementation later is not a break */; fun sha256(name: String): ByteArray /* content hash, computed once by the loader */; val sourceTimestampMillis: Long }
@RevoktInternalApi class CrliteSct private constructor(…) { val logId: ByteArray /* 32 bytes */; val timestampMillis: Long /* RFC 6962 u64 carried in Long; compared with java.lang.Long.compareUnsigned */ }   // internal Builder
@RevoktInternalApi class CrliteQuery private constructor(…) {        // growable value-semantics class (internal builder); a field added in a minor does not break engines
    val issuerSpkiHash: ByteArray /* SHA-256 of the issuer's SPKI TLV */; val serial: ByteArray /* rawSerial: DER INTEGER content bytes as encoded (the producer's RawValue.Bytes, §9.2) */; val scts: List<CrliteSct> /* order not significant; empty when no SCT extension has a list that parses under §9.2 (absent, or for example empty, a first item that fails, an inner identifier other than 0x04; §9.2 states every case); a list that fails later keeps the items before the failure */ }
```

**Seam.** The seam is internal: `RevocationEngine`, `PreparedGeneration`, `KotlinRevocationEngine` and
`Revokt.Builder.revocationEngine(engine: RevocationEngine)` are `@RevoktInternalApi` (§3.1 item 4), for revokt's own
tests and the CI-only upki engine, which is the differential test of test-plan.md §9.3. The builder defaults to the
Kotlin engine (`formats = {V3, V4}`, `name = "kotlin"`). Publishing the seam is revisited only if a real second engine
appears. The
updater builds `index.bin` itself for Remote Settings generations (the channel's one full filter and every delta,
ordered by time, with their coverage; `parent` is not read, §6.5), so every `GenerationFiles` is a directory image any C2SP reader accepts; the
only engine-specific property is `format`. **`index.bin` consistency.** The loader builds every `index.bin` it
installs, so each is **selection-equivalent** by construction: for every log id and every timestamp (inclusive at both
ends, overlapping windows allowed), the set of filters the `index.bin` log directory names for that
(log id, timestamp) equals the set of referenced filters whose own coverage map contains it, i.e. every
directory entry lies within its filter's window and every filter's window is exactly covered by its entries. A
seed's `index.bin` is rebuilt and byte-compared, and a mismatch installs nothing (`SEED_UNREADABLE`). **Every
`index.bin` revokt's loader reads (a seed's) is at most 1 MiB, checked before it is parsed;
revokt never fetches an `index.bin`** (the seed's cap, §6.5, applied to every source; an injected engine's own reads
are its concern): over the cap, a seed is `SEED_UNREADABLE`. **An `index.bin` the loader builds** for a Remote Settings
generation that is over 1 MiB fails the install before the generation file is written: `SyncOutcome.FAILED` with
`SyncFailure.INDEX_INCONSISTENT`, so the loader never writes a generation it could not reload. A stored generation's
`index.bin`, rebuilt at every load (§6.5 Load), that is over 1 MiB is a failed load in the recovery chain. **revokt's index reader takes only the magic `upkiidx1`**
(C2SP `upki-revocation@v1.0.0`); the legacy `upkiidx0` that upki v1.0.1 also reads is rejected as malformed, with the
outcome of a mismatch (Appendix A). This is what makes the Kotlin engine's
coverage-driven filter selection (§6.2, every filter consulted by its own coverage) equal to C2SP's
`index.bin`-driven selection (upki binary-searches the log directory and loads only the filters it names)
on every generation the suite admits; upki's `Index::write` writes one entry per (log, filter), the filter's
coverage window for that log, so overlapping windows (a full and its deltas sharing boundary timestamps) are
separate entries, which the check admits (Appendix A), and a legitimate Mozilla generation
passes by construction. **A fetched generation with any placed filter (the full or a delta) whose encoding the
engine does not list is `SyncOutcome.FAILED` with `SyncFailure.FORMAT_UNSUPPORTED`**
(every filter, not only the full, is checked, and the previous generation stays live), counts toward `consecutiveFailures`
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
`Revokt(block)`, `sources { }`, `limits { }` and the assignment-style `var`s shown below are `@JvmSynthetic` sugar
over the same builder; the Java forms of the two blocks are `Revokt.Builder`'s flat `remoteSettings(…)`, `seed(…)`, `maxFilterBytes(…)`, `maxJsonBytes(…)`, `maxX5uBytes(…)` and `maxChangesetRecords(…)`, one source of each kind, a later call replacing an earlier one (`RevoktBuilderTest`). Every public value or output type, including every `Finding` subclass, is a final class with a private
constructor, content-based `equals`/`hashCode`/`toString` (timing fields excluded: a timing field is a measured duration, such as
`Verdict.elapsedNanos`; timestamps such as `atMillis` and `createdMillis` take part). An input type (`RevoktPolicy`,
`MozillaRemoteSettings`, `EvaluationRequest`, `FetchResponse`) has a nested `Builder` and `newBuilder()` (`Staleness` has
factories); service types such as `AndroidPlatformTrust()`, `JcaSignatureVerifier()` and exceptions have public
constructors. An output type (`Verdict.*`, every `Finding`, `ExemptionContext`, `PresentedChain`, `PolicyDiagnostic`,
`FetchRequest`; [0.3] `RevoktEvent`, `RevoktStatus`, `RevoktState`, `TrustManagerStatus`, `SyncResult`, `RevoktWarning`) is
built only by revokt: its builder and `newBuilder()` are internal, and the test factories a consumer's fakes need come
with `revokt-testing` (0.3, §3). Until then `FetchRequest`'s builder is `@RevoktTestingApi` (opt-in, `WARNING` level,
outside the 1.0 promise), so a fetcher's tests can build requests. **First-consumer rule** (#221): a type, member or
enum value is public only once a public member produces or consumes it; until then it is `internal`, or
`@RevoktInternalApi` where another revokt module or the CI-only upki engine uses it, and making it public later is
never a break. The API dumps (`apiCheck`) and the vocabulary pins (`PolicyVocabularyTest`, `FindingTest`) record it. `Finding` is a sealed class, **growable** (a subtype may be added in a minor; use `else`); `Verdict` is closed. No data classes, no inline value classes. **Public type rule**: stable stdlib types
in Kotlin-facing signatures; `java.time` and `long` overloads for Java; one functional type per
member; kotlinx-coroutines is the one non-stdlib dependency in signatures, with a listener or
`CompletableFuture` alternative for each member. `Revokt` is the JVM facade in `revokt-jsse`.

```kotlin
val revokt = Revokt {
    channel = CrliteChannel.COMPAT                      // enum class CrliteChannel { COMPAT, DEFAULT } (growable); mandatory iff a CRLite source is configured (a seed counts, the default SeedSource.bundled() included, so only seed(SeedSource.none()) with no remoteSettings builds without a channel); R: build() throws when unset (the consumer chooses); channel-less datasets (M2+) use the literal store segment `all`
    storage = AndroidStorage.noBackup(context, "revokt")   // [0.3] a RevoktStorage? (Java: storage(RevoktStorage)); on the JVM JvmStorage.directory(path); null, the default, is a fresh RevoktStorage.inMemory() at each build() (§3); 0.2 has no member and runs on RevoktStorage.inMemory() (§11)
    platformTrust = AndroidPlatformTrust()              // [0.3]; 0.2 has no member and always uses JvmPlatformTrust(); default: auto-detected (AndroidPlatformTrust when android.os.Build resolves, else JvmPlatformTrust); R: on Android a platformTrust that is not AndroidPlatformTrust throws
    signatureVerifier = JcaSignatureVerifier()
    revocationEngine = KotlinRevocationEngine()           // default; @RevoktInternalApi, the §3.2 seam
    clock = Clock.System                                // kotlin.time.Clock, stable from Kotlin 2.3; Java: clock(java.time.Clock); the monotonic deadlines read an internal TimeSource (a test seam)
    sources { remoteSettings(MozillaRemoteSettings.DEFAULT); seed(SeedSource.fromResource("/revokt/seed-compat.zip")) }   // seed default when none is configured: SeedSource.bundled(), resolved at build(): /revokt/seed-<channel>.zip from the revokt-seed-<channel> jar (§6.5; the quickstarts bundle it); absent from the classpath → no seed source, and validate() emits NO_DATA_REJECTS_WITHOUT_LOCAL_DATA; present but unreadable → SEED_UNREADABLE at start() (§4 S bullet); seed(SeedSource.none()) opts out explicitly. No fetching source is configured by default (a library never opens the network unasked); a required dataset with local data and no fetching source is V NO_FETCHING_SOURCE, a WARNING under both enforcements (the instance updates only through sync()'s seed re-check, below; air-gapped seed-by-deploy fleets are legitimate). R: every source URL (baseUrl, a pinned attachmentBaseUrl) is an absolute https URL (the scheme in any case, as JdkHttpFetcher reads it) whose host is a DNS name or an IP literal (java.net.URI's server authority, so a name with an underscore is refused: public CAs issue no certificate for one, and the fetch would fail its host check), no userinfo, no query or fragment (the client appends each request's path to it) and any port from 1 to 65535 or none, read by java.net.URI, else build() throws, its message naming the field and the rule, never the URL or any part of it (a rejected URL may carry credentials) (NSC blocks cleartext on API 28+, the JVM does not; `RevoktBuilderTest`).
    logger = RevoktLoggers.jul()                        // RevoktLogger; default auto-detected (§3)
    policy = RevoktPolicy.DEFAULT                       // or STRICT; RevoktPolicy.DEFAULT.newBuilder().rule(Rule.NO_SCTS, REJECT).exempt(Rule.NO_SCTS, …).staleness(Dataset.CRLITE, Staleness.ofMillis(3.days.inWholeMilliseconds, null))
    enforcement = Enforcement.ENFORCE
    awaitData(2.seconds)                                // Java: awaitData(java.time.Duration) / awaitDataMillis(long); default 2 s on the JVM; on Android RevoktLimits.AWAIT_DATA_<CHANNEL>, measured (§5.1); a deadline in whole milliseconds, truncated toward zero, and both forms throw IllegalArgumentException for any negative duration (a sub-millisecond one included), an infinite one, and one beyond Long milliseconds
    caches { pathEntries = 256; verdictEntries = 1024 }
    ioDispatcher = Dispatchers.IO                       // fetch I/O; Java: ioExecutor(Executor). The loader dispatcher is internal, single-parallelism. The dispatcher or executor must not run tasks inline (Dispatchers.Unconfined, Executor { it.run() }, Guava's directExecutor()): an inline one runs each fetch on the loader thread, which blocks before the per-fetch timeout (FetchRequest.timeoutMillis) can be applied
    limits { maxFilterBytes = 32L shl 20; maxTrustManagers = 64 }   // download and record caps (MAX_FILTER_BYTES, MAX_JSON_BYTES, MAX_X5U_BYTES, MAX_CHANGESET_RECORDS, the four public RevoktLimits members) are overridable upward only (R: a lower value throws IllegalArgumentException from build()); maxTrustManagers [0.3] in both directions, ≥ 1; walker budgets are internal constants. MAX_FILTER_BYTES also caps SIGNED bodies (limits table below), so raising it is the recovery for a larger Mozilla filter; maxTrustManagers is the multi-tenant case (per-tenant trust stores), one CandidateIndex and two small caches per instance
    http = OkHttpFetcher(baseClient)                     // an HttpFetcher, over the platform's TLS and trust manager or the base client's; default on the JVM: JdkHttpFetcher (ProxySelector.getDefault() and a per-connection HttpURLConnection.setAuthenticator that answers RequestorType.PROXY only, JDK 9+, so a trusted intercepting proxy cannot harvest default credentials; a 401/407 is FAILED; revokt configures no proxy; Basic auth to an HTTPS tunnel is disabled by the JDK unless jdk.http.auth.tunneling.disabledSchemes is cleared; proxy-authenticated fleets use OkHttpFetcher with proxyAuthenticator; setInstanceFollowRedirects(false); setUseCaches(false); https only; every handshake over HttpsURLConnection.getDefaultSSLSocketFactory(), read at each fetch; the host is matched against the peer certificate by HttpsURLConnection after every handshake, resumed ones included, with a per-connection hostname verifier that refuses any mismatch, so neither a global HttpsURLConnection.setDefaultHostnameVerifier nor a session another connection cached turns the check off, and a default factory whose sockets come with an endpoint identification algorithm already set, which would skip that check, is refused; it sends Accept-Encoding: gzip whatever the request's headers say, inflates a gzip body under maxBodyBytes and drops Content-Encoding and Content-Length from the response it returns, and any other Content-Encoding throws; timeoutMillis is its connect and read timeout, and an interrupt seen before connecting or between body reads disconnects and throws InterruptedIOException; it sends Connection: close and disconnects after each fetch, so no connection outlives its fetch where the server honours the header; a JVM default CookieHandler and the JDK's transparent Negotiate or NTLM answer to a 401 have no per-connection switch, and stay residuals). Default on Android (AndroidPlatformTrust): OkHttpFetcher over a fresh OkHttpClient() when revokt-okhttp resolves (detected by class name), else AndroidHttpFetcher from revokt-android (HttpURLConnection.setAuthenticator does not exist in Android's libcore, so JdkHttpFetcher is never used there; Android's HttpsURLConnection answers a 407 from the VM-global Authenticator.getDefault() with no per-connection suppression, the §10 residual, which is why the OkHttp fetcher is preferred). OkHttp: the base client's TLS and hostnameVerifier are kept (R: the verifier must be OkHttp's default), and followRedirects(false), followSslRedirects(false), authenticator(NONE), cookieJar(NO_COOKIES) and cache(null) are forced (a consumer disk cache would serve the first ETag-less request, on a fresh install or after resetState(), from its own max-age) (§7.1 "redirects are never followed" holds at the transport); proxy, dns, interceptors and certificatePinner are inherited and consumer-owned: application and network interceptors see every revokt request, so the consumer must not attach credential-adding interceptors to the base client (the README warns). With remoteSettings(MozillaRemoteSettings.DEFAULT) the fetcher contacts firefox.settings.services.mozilla.com and hosts under cdn.mozilla.net, today firefox-settings-attachments.cdn.mozilla.net and content-signature-2.cdn.mozilla.net (the NSC and egress allowlist, §7.1)
    // R [0.3]: build() throws IllegalArgumentException when the fetcher would put the feed behind a revokt trust manager: a base client wired with .revokt(...) (an OkHttpClient whose x509TrustManager is a RevoktTrustManager), or any RevoktTrustManager as the fetcher's trust manager; the feed would then wait on the data it produces, and a revocation of the feed host would stop its own fetches (§10 "No self-lockout")
}
revokt.start(); revokt.close()                          // Revokt : AutoCloseable; Java entry Revokt.builder(); DSL vars carry @get:JvmSynthetic @set:JvmSynthetic; idempotent; lifecycle CREATED → STARTED → CLOSED (§5.1). [0.3] start() returns Unit, its diagnostics only on state (RevoktState.diagnostics and warnings, `RevoktStateTest`). start() throws IllegalStateException on a validate() ERROR, SEED_CHANNEL_MISMATCH, a consumer trust manager's pre-start anchor snapshot build failure, a second instance on the same storage identity in this process, a call from a thread holding the factory lock, or, under ENFORCE with outcome(NO_DATA) == REJECT, SEED_UNREADABLE when the seed is the only local data source (verified synchronously inside start() in that configuration, §4 S bullet); stays CREATED and may be retried. close() on the loader thread throws IllegalStateException (listener executors are never the loader; syncAsync(), resetStateAsync() and readyFuture() are completed by `ioExecutor.execute { future.complete(v) }` / `completeExceptionally(t)`, the Java 8 shape (never `CompletableFuture.completeAsync`, `orTimeout` or any other API-31+ member: minSdk is 26, core-library desugaring does not cover them, and an API-26 instrumented fixture plus an Android Lint `NewApi` check on a minSdk-26 consumer of revokt-jsse guard it), so dependent stages never run on the loader; each call returns a fresh dependent future (`internal.thenApply { it }`), so a consumer's cancel()/complete() cannot corrupt readiness; close() completes a pending syncAsync()/resetStateAsync() exceptionally as it does readyFuture()); a start() whose loader join observes CLOSED returns normally on a CLOSED instance whose readyFuture() has failed
suspend fun Revokt.awaitReady(); fun readyFuture(): CompletableFuture<Void>          // completes when RevoktState.ready first becomes true; no internal deadline; close() completes it exceptionally with IllegalStateException("closed") and the suspend form throws CancellationException
fun interface Revokt.Provider { fun revokt(): Revokt }       // may return a CREATED or STARTED instance (the WorkManager worker starts a CREATED one itself, §3; a CLOSED one is Result.failure()); a direct sync() in CREATED or CLOSED throws IllegalStateException
suspend fun Revokt.sync(): SyncResult; fun syncAsync(): CompletableFuture<SyncResult>; fun syncBlocking(): SyncResult   // with no fetching source configured, sync() re-opens the seed source and, when the seed is newer than the live generation, installs it under the seed-vs-stored rule with writes (an air-gapped refresh: replace the seed artifact, call sync(); the watermark is intact), else UNCHANGED; either way it is a completed attempt (§8 STALE gate, datasetLastAttemptAtMillis); a call that arrives while a sync is queued or running, the start task's first sync included, gets that sync's SyncResult and queues no sync of its own (`RevoktSyncTest`)
suspend fun resetState(); fun resetStateBlocking(); fun resetStateAsync(): CompletableFuture<Void>   // STARTED only; runs on the loader after any in-flight install; deletes every key names() lists except store.version (never `.lock`; updater.json included: the rollback watermark restarts from the seed's timestamp, or from zero with SeedSource.none(), §10) while the published generation and the engine's installed generation stay live (DataState.pending stays false while a generation is published), re-runs the loader start task (the seed) and swaps old → new atomically (generationEpoch++ then); only when no local source yields a generation does it publish the empty snapshot (generationEpoch++) and **then** engine.clear(), in that order, so a handshake holding the old snapshot still finds data in the engine (step 7 never queries without a generation); a concurrent handshake is never NO_DATA while the previous generation existed; schedules the first sync before completing; anchor snapshots are untouched
var revokt.enforcement: Enforcement                     // @Volatile, read once per handshake (that one value drives step 0, step 4 and RevoktEvent.enforced); the enforcement and policy setters serialise under one lock and validate the (enforcement, policy) pair that will be published; setter runs validate(); throws IllegalStateException with the same messages; allowed in any lifecycle state, takes effect at the next handshake in STARTED; in STARTED a flip to ENFORCE with outcome(NO_DATA) == REJECT and a required dataset whose DataState has generationId == null, pending == false and a SEED_UNREADABLE/STORE_UNREADABLE warning for its sole local source is refused with ERROR NO_DATA_AT_FLIP (V bullet below); while pending == true the flip is accepted
var revokt.policy: RevoktPolicy                         // runtime-replaceable with the enforcement setter's contract (runs validate(enforcement), throws on ERROR, any lifecycle state, next handshake); the per-rule kill switch for non-exemptable rules; the setter runs the NO_DATA_AT_FLIP check against (current enforcement, new policy) and is refused under the same conditions; the setter recomputes and publishes RevoktState.ready (awaitReady() must not hang after a change that empties requiredDatasets); flow step 0's needsData is recomputed at the next handshake; the setter publishes (policy, policyEpoch) as one @Volatile pair, read once per handshake (at flow step 0 when it runs, else at step 2) and threaded through steps 3, 7, 8, the exemptions and the cache put, like enforcement; policyEpoch (public on RevoktEvent; process-local, not stable across processes, like AnchorSnapshot.id) is part of the verdict-cache key, so a change is a cache miss and OBSERVE would-rejects can be attributed across it
var revokt.shadowPolicy: RevoktPolicy?                  // builder shadowPolicy(p) too; default null. The measurement path from DEFAULT to STRICT (or to a new rule's REJECT) without OBSERVE: on every verdict-cache miss, after the enforced verdict is final, decision steps 7–8 are re-run under the shadow policy over the same path status, CRLite results and generation snapshot (no second walk, no second engine query; the shadow policy's own requiredDatasets, staleness map, outcomes and exemptions apply; a throwing shadow exemption is not exempt plus a shadow-only EngineError), yielding RevoktEvent.shadowVerdict (cached beside the verdict, so hits count too) and RevoktStatus.shadowWouldRejects: Map<Rule, Long> keyed by the shadow verdict's rule; the shadow never throws, never waits (step 0 is the enforced policy's) and never changes the enforced verdict; shadowPolicyEpoch is part of the verdict-cache key; the (shadowPolicy, shadowPolicyEpoch) pair is published and read exactly as the policy pair (one @Volatile pair, read at flow step 0 or 2 beside it, threaded through step 3 and the cache put); every setter call bumps shadowPolicyEpoch, setting null included; the setter takes the same lock as the two setters; the shadow is validated under OBSERVE semantics (its diagnostics are WARNINGs, never thrown and never copied to RevoktState.diagnostics, logged at WARN through RevoktLogger by the setter: a shadow must be measurable on a fleet that has not yet shipped the seed STRICT would require); the shadow runs under ENFORCE and OBSERVE (not OFF, where steps 2–4 do not run), after the enforced catch boundary has closed, under its own boundary (§5.5), and touches nothing but shadowWouldRejects and RevoktEvent.shadowVerdict (never fired, exempted, the per-dataset maps or event priority); it computes its own data rules from the same generation snapshot under its own requiredDatasets and staleness map
fun revokt.validate(enforcement: Enforcement): List<PolicyDiagnostic>   // the setter throws iff any ERROR; validateOrThrow(enforcement) for Java, IllegalStateException iff any ERROR; the configuration's codes first, in the order the V bullets below list them, then the policy's own, then IO_DISPATCHER_UNCONFINED (`RevoktValidateTest`)
fun revokt.status(): RevoktStatus                       // cheap snapshot; counters monotonic since build() for unevaluated, since start() for every other
val revokt.state: StateFlow<RevoktState>                // slow-changing fields only; Java: RevoktListener.onStateChanged
fun addListener(listener: RevoktListener, executor: Executor); fun removeListener(listener: RevoktListener)
val revokt.trustManager: RevoktTrustManager               // the single memoised instance over platformTrust.defaultDelegate(); the delegate is captured at build(), the RevoktTrustManager is created on the first read of this property or the first null-delegate wiring (lazily, under the factory lock; in STARTED with its snapshot), so a seed-only configuration over an empty default trust store starts (fixture (h)) and throws only once something asks for the instance
fun revokt.trustManager(delegate: X509TrustManager): RevoktTrustManager   // RevoktTrustManager is a final class extending X509ExtendedTrustManager. In STARTED builds the anchor snapshot synchronously inside the factory lock (§5.1 "Anchor snapshot"); a plain delegate (JVM) → IllegalArgumentException; a throwing getAcceptedIssuers() or an empty anchor set → IllegalStateException; nothing registered in either case
val revokt.evaluator: Evaluator; fun Revokt.Builder.pkixFallback(enabled: Boolean): Builder   // default true; Evaluator.evaluate walks against revokt.trustManager's anchor snapshot (created lazily as above; one @Volatile read at entry, its id reported as anchorSnapshotId) and shares no path or verdict cache; outside STARTED it throws IllegalStateException (there is no step 1 to fall back to)
class SeedSource internal constructor(…) { companion object { fun none(): SeedSource } }   // jvmMain; internal open(): okio.Source? (Okio never appears in a public signature)
// jvmMain: fun interface SeedOpener { fun open(): java.io.InputStream? }   // one functional type, usable from Java as a lambda; the companion also has @JvmStatic fun of(opener: SeedOpener): SeedSource /* asset packs, a downloaded seed; re-opened on every start task and sync() seed re-check; wrapped into okio internally */, @JvmStatic fun fromResource(path: String): SeedSource and @JvmStatic fun bundled(): SeedSource /* resolve through SeedSource::class.java.classLoader, then the thread context loader, in that order (app servers) */
// jvmMain: object JvmSeedSource { @JvmStatic fun fromPath(path: java.nio.file.Path): SeedSource }   // mirrors JvmStorage
class MozillaRemoteSettings private constructor(…) { class Builder { fun baseUrl(url: String): Builder; fun bucket(name: String): Builder /* security-state */; fun collection(dataset: Dataset, name: String): Builder /* cert-revocations */; fun attachmentBaseUrl(url: String?): Builder /* default null: read from the server root's capabilities.attachments.base_url once per sync; a value pins it, §7.1 */; fun allowedDomains(domains: Set<String>): Builder /* default cdn.mozilla.net; a host is allowed when it equals a domain or ends with '.' and one, §7.1 */; fun x5uHostRewrite(from: String, to: String): Builder /* applied to the parsed x5u URI host before the allowedDomains check; domains and rewrite targets are compared exactly, ASCII case included; makes a byte-for-byte reverse proxy of the three Mozilla hosts a supported mirror, §7.1. MozillaRemoteSettings.Builder.build() throws IllegalArgumentException when allowedDomains does not allow `to`, when an allowedDomains entry is a single label (such as `net`, which would allow a whole top-level domain), and when an allowedDomains entry, or either side of an x5uHostRewrite, is not a host name in the grammar X5uUrl checks at fetch time: labels of 1 to 63 ASCII letters, digits and '-' that start and end with a letter or digit, separated by single dots, a name of at most 253 characters, no trailing dot, and a last label that starts with a letter (so no IP literal, and java.net.URI reads the host); upper case is allowed, since comparison is exact; so build() and the fetch-time check accept the same set  */; fun pinnedRootSpkiSha256s(hashes: Collection<ByteArray>): Builder /* compared by content */; fun userAgent(ua: String): Builder; fun sourceId(id: String): Builder /* default "mozilla-remote-settings"; the updater.json key */; fun build(): MozillaRemoteSettings }; companion object { @JvmField val DEFAULT: MozillaRemoteSettings }; fun newBuilder(): Builder }   // a configuration input with no public getters (the engine reads it; upki's fetch_url is private too, #221), so a mirror is DEFAULT.newBuilder() plus its overrides; the content signature is read from metadata.signatures[], each entry's signature, x5u and mode (an entry is tried when its mode is absent, null or "p384ecdsa", and skipped for any other value; the algorithm is never derived from it); metadata.signature is not read (§7.1)
@JvmOverloads fun revokt.sslContext(delegate: X509TrustManager? = null, keyManagers: Array<KeyManager>? = null): SSLContext
fun RevoktTrustManager.status(): TrustManagerStatus; suspend fun RevoktTrustManager.awaitReady(); fun RevoktTrustManager.readyFuture(): CompletableFuture<Void>   // = the owning Revokt's; kept so a binding that holds only the trust manager can wait
fun RevoktTrustManager.refreshAnchors(): CompletableFuture<Void>   // rebuilds the anchor snapshot on the loader (rate-limited by ANCHOR_REFRESH_MIN_INTERVAL; a failed rebuild keeps the snapshot); for delegates that reload their trust store
@JvmOverloads fun OkHttpClient.Builder.revokt(revokt: Revokt, delegate: X509TrustManager? = null): OkHttpClient.Builder   // a null delegate on every binding resolves to revokt.trustManager, the single memoised instance over platformTrust.defaultDelegate() (captured once per Revokt at build(); on Android ApplicationConfig holds exactly one RootTrustManager per process, so a default trust manager obtained through TrustManagerFactory and passed explicitly is === the captured delegate and resolves to the same instance, counting once); only distinct explicit delegates create further instances, so the cap counts delegates, not clients. Call it last on the builder: a later sslSocketFactory(...) from a debug-proxy or pinning module silently replaces it (evaluations and unevaluated both stay 0); withRevokt(client) is the terminal form
fun OkHttpClient.withRevokt(revokt: Revokt): OkHttpClient; fun OkHttpClient.revoktTrustManager(): RevoktTrustManager?   // the client's x509TrustManager when it is revokt's, else null; for a startup assertion
class EvaluationRequest private constructor(…) { class Builder {
    fun presented(chain: List<ByteArray>): Builder            // leaf first, as sent; walked (decision steps 2–6)
    fun verifiedPath(path: List<ByteArray>): Builder  // one platform-verified path, leaf → anchor (upki's single webpki VerifiedPath), at most MAX_DEPTH + 1 (17) certificates (MAX_DEPTH is internal; build()'s message states the number), trusted without re-verification; source = PLATFORM; the walk is skipped; it is both the reported path and the exemptions' chain; a one-certificate path is FOUND under its own key and skips step 3's keyability check only when its leaf is an anchor by bytes in the snapshot read at entry (step 2's rule), else its leaf is gated like any leaf
    fun host(host: String?): Builder; fun nowMillis(nowMillis: Long): Builder; fun build(): EvaluationRequest } }   // at least one of presented/verifiedPath; build() also throws IllegalArgumentException when presented is set and empty, verifiedPath is set and empty, verifiedPath holds more than MAX_DEPTH + 1 certificates, or both are set and verifiedPath's first certificate is not byte-equal to presented[0]; with both set the verified path wins and the walk is skipped; chainSource is derived. M5 adds credentialType(CredentialType) (growable, default X509), routed before decision step 3 with PathStatus.NOT_APPLICABLE; JSSE never delivers an MTC credential to an X509TrustManager, so M5 is Evaluator.evaluate-only
sealed interface Evaluator { fun evaluate(request: EvaluationRequest): Verdict }   // sealed, never consumer-implemented, so members can be added; not named `Engine`, so it cannot collide with RevocationEngine
@Throws(CertificateException::class) @JvmOverloads fun Revokt.evaluate(chain: List<X509Certificate>, host: String? = null, delegate: X509TrustManager? = null): Verdict   // never waits; always runs step 1 (a null delegate resolves to platformTrust.defaultDelegate()) as `delegate.checkServerTrusted(chain.toTypedArray(), "UNKNOWN")`, the 2-arg call with SunJSSE's own TLS 1.3 authType (a signature-capable key-usage check, no endpoint identification since there is no peer; Conscrypt only requires a non-empty authType), host being used for host' only; a step-1 reject propagates the delegate's CertificateException unchanged, no Verdict (the annotation is what lets a Java caller catch it); with a delegate it uses (and if needed creates, counting toward MAX_TRUST_MANAGERS) the registry instance for that delegate and shares its caches; Evaluator.evaluate shares no trust-manager path or verdict cache, advances no RevoktStatus counter and emits no event, while Revokt.evaluate counts, emits and runs the shadow as a handshake does (`RevoktStatusTest`)
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
enum class DiagnosticCode /* a configuration diagnostic, one per B/R/V/S bullet whose producer is built */ { EXEMPTION_ON_EVIDENCE_RULE, STALE_REJECTS_WITHOUT_THRESHOLD, EXEMPT_ON_ALLOW, BUDGET_ALLOWS, EVIDENCE_LOWERED_BELOW_PRESET, STALENESS_CLEARED_FOR_REQUIRED_DATASET, CHANNEL_UNSET, NO_DATA_REJECTS_WITHOUT_LOCAL_DATA, NO_REQUIRED_DATASETS, IN_MEMORY_STORE_WITH_FETCHING_SOURCE, FORMAT_UNSUPPORTED, NO_FETCHING_SOURCE, IO_DISPATCHER_UNCONFINED, SEED_PAST_REJECT_THRESHOLD, UNVERIFIED_REJECTS_WITH_CLASSICAL_GAP, RULE_FLIPPED_THIS_MINOR }   // growable; a bullet's code joins its enum when its producer is built
internal enum class WarningCode /* a runtime condition, found by a sync, the seed load or the store, not by reading the configuration */ { CAP_NEAR_LIMIT, SEED_UNREADABLE, SEED_CHANNEL_MISMATCH, STORE_UNREADABLE, STORE_MIGRATED, STORE_NEWER_LAYOUT, STORE_LOCKED }   // growable; a bullet's code joins its enum when its producer is built; internal in 0.2 with RevoktWarning, SyncResult, SyncOutcome and SyncFailure, public with the 0.3 sync() and state (§11)
enum class EngineErrorProducer { BOUNDARY, ENGINE, EXEMPTION }   // growable; exactly these three in M1
enum class Layer { PATH, CRLITE }                        // growable; M2: ONECRL, CRLSET, DENYLIST (L1/L2); M3: CT (L4); M4: DISTRUST (L5)
enum class Dataset { CRLITE /* M2: INTERMEDIATES, ONECRL, CRLSET, DENYLIST; M3: CT_LOGS; M4: DISTRUST */ }   // growable; the freshness rule per dataset and source is §7.2 prose
enum class Freshness { RECORD_LAST_MODIFIED, SEED_SIGNED_TIME /* M2: LAST_VERIFIED_POLL, SEQUENCE_TIME, ARTIFACT_DATE (§7.2) */ }   // growable; what a generation's sourceTimestamp means; a value joins when its producer is built
enum class PathStatus { FOUND, NO_ISSUER, PATH_BUDGET_EXCEEDED, PARSE_FAILED, NOT_WALKED }   // growable; M5: NOT_APPLICABLE
enum class PathReason(val status: PathStatus) { NO_CANDIDATE, ALL_CANDIDATES_INVALID, UNANCHORED, UNSUPPORTED_ALGORITHM, PLATFORM_ONLY /* NO_ISSUER */, STRUCTURE, OVERSIZE, PRODUCER_UNKEYABLE /* PARSE_FAILED */, EXPLORATION_BUDGET /* the walk's work budget spent, or the step-3 presented cut */, FALLBACK_LIMIT /* a completed NotFound over FALLBACK_MAX_PRESENTED, §5.1 step 6 */ /* PATH_BUDGET_EXCEEDED */ }   // growable; the union of NoIssuerReason, ParseReason and the walk's budget; Finding.Path.reason
internal enum class ParseReason { STRUCTURE, OVERSIZE, PRODUCER_UNKEYABLE }   // internal, with NoIssuerReason, KeyabilityClause and TerminalKind: the DEBUG line's vocabulary, which no public member carries (PathReason is the one public reason type, #221); growable; why the leaf is PARSE_FAILED, reported as the PathReason of its name (§5.1 step 3, §9.2 D8)
internal enum class KeyabilityClause { HEADER, TBS_SHAPE, INTEGER, OID, NAME, TIME, KEY, EXTENSION }   // growable; the first failing §9.2 keyability clause, K1 to K8 in order; on the DEBUG line ⇔ reason == PRODUCER_UNKEYABLE
internal enum class TerminalKind { ANCHOR /* M2: PRELOAD */ }   // growable; the reported path's terminal (§5.1 invariant)
internal enum class NoIssuerReason { NO_CANDIDATE, ALL_CANDIDATES_INVALID, UNANCHORED, UNSUPPORTED_ALGORITHM, PLATFORM_ONLY }   // growable; the walker's reason (walkerReason on the DEBUG line); a NO_ISSUER path reports the PathReason of its name
enum class FallbackReason { SKIPPED /* presented chain over FALLBACK_MAX_PRESENTED, fallback enabled */, DISABLED /* pkixFallback(false), or the walker-only harness's disabled path */, FAILED /* ran and found no path: build returned null or threw; a thrown result is neither path- nor verdict-cached */ }   // growable; why decision step 6 evaluated no fallback path (§5.1)
@RevoktInternalApi enum class RevoktLifecycle { CREATED, STARTED, CLOSED }   // closed; commonMain; @RevoktInternalApi in 0.2 (revokt-jsse's lifecycle), public with RevoktState in 0.3
enum class ChainSource { PLATFORM, RECONSTRUCTED }   // growable; a value joins when its producer is built; PLATFORM: a platform-verified chain, §5.1 decision step 4 or EvaluationRequest.verifiedPath; M2: MIXED (paths from both a PLATFORM chain and the re-walk)
internal enum class SyncOutcome { INSTALLED, UNCHANGED, SKIPPED /* stopped short of an install, and not a feed failure */, FAILED /* a feed failure (§7.1) */ }   // growable; a SKIPPED or FAILED sync carries its SyncFailure
internal enum class SyncFailure(val outcome: SyncOutcome) { BACKOFF, ROLLBACK_REFUSED /* the two SKIPPED codes */, CHANGESET_FETCH, CHANGESET_MALFORMED, TOO_MANY_RECORDS, NO_SIGNATURE, X5U_URL, X5U_FETCH, X5U_CHAIN, CLOCK_SKEW, SIGNATURE_INVALID, SCHEMA_REJECTED, INDEX_INCONSISTENT, ATTACHMENT_BASE, ATTACHMENT_OVER_CAP, ATTACHMENT_FETCH, ATTACHMENT_MISMATCH, FILTER_UNREADABLE, FORMAT_UNSUPPORTED, ENGINE_FAILED, STORE_FAILED, INTERNAL_ERROR /* FAILED */ }   // growable; why a SKIPPED or FAILED sync stopped, one code per step a sync can stop at, so the code says where; BACKOFF = under a persisted backoffUntilMillis, nothing fetched; ROLLBACK_REFUSED = the verified <ts> below the floor (§7.1); *_FETCH = that fetch failed: the fetcher threw or returned null, a timeout, a status other than 200 (or a 304 to an unconditional request), a body over its cap, or a header or query value that cannot be sent (CHANGESET_FETCH covers monitor/changes and the changeset, X5U_FETCH the x5u, ATTACHMENT_FETCH a body, a mirror file's included, §7.3); CHANGESET_MALFORMED = monitor/changes or the changeset is not the JSON envelope, or monitor/changes does not list the collection once; TOO_MANY_RECORDS = over MAX_CHANGESET_RECORDS; NO_SIGNATURE = metadata.signatures[] gives nothing to verify (none, none tried, a null entry reached); X5U_URL = the x5u URL breaks a §7.1 rule, nothing fetched; X5U_CHAIN = any x5u PEM or chain failure other than validity; CLOCK_SKEW = an x5u link outside its validity window at the local clock (§7.1); SIGNATURE_INVALID = the content signature, or a payload with no canonical form; SCHEMA_REJECTED = a verified changeset whose records fail the collection schema; INDEX_INCONSISTENT = not exactly one full filter, two names that collide, or a built index over 1 MiB (§3.2, §6.5); ATTACHMENT_BASE = the server root's attachment base, its fetch included; ATTACHMENT_OVER_CAP = a signed record over MAX_FILTER_BYTES, before any body; ATTACHMENT_MISMATCH = a body whose size or SHA-256 differs from the signed record's or the manifest's (§7.3); FILTER_UNREADABLE = a placed filter that does not decode (§6.3); FORMAT_UNSUPPORTED = a placed filter in an encoding the engine does not list (§3.2); ENGINE_FAILED = the engine's prepare or activate threw; STORE_FAILED = a store read, write or pointer flip failed (§6.5); INTERNAL_ERROR = any other throwable the loader caught; each producing bullet names its code, and a bullet's code joins the enum when its producer is built

/** jvmMain. Time fields are stored as millis. Java: *Millis properties and java.time.Duration accessors/factories (API 26+). Kotlin: kotlin.time.Duration via @JvmSynthetic extensions. No inline value class on the surface. commonMain sees only an internal PolicyTable these compile to. The split stays: the rules evaluate in commonMain over PolicyForm and PolicyTable, which carry no java.time, while RevoktPolicy's java.time surface needs jvmMain; merging them would move the rules out of commonMain. */
class Staleness private constructor(…) { val staleAfterMillis: Long; val rejectStaleAfterMillis: Long?   // staleAfter: loud threshold only (DataState.stale). rejectStaleAfter: the only threshold at which Rule.STALE fires; null = STALE never fires for this dataset
    fun staleAfter(): java.time.Duration; fun rejectStaleAfter(): java.time.Duration?
    companion object { @JvmStatic fun ofMillis(staleAfter: Long, rejectStaleAfter: Long?): Staleness; @JvmStatic fun of(staleAfter: java.time.Duration, rejectStaleAfter: java.time.Duration?): Staleness } }
class PolicyDiagnostic private constructor(…) { val code: DiagnosticCode; val severity: Severity; val rule: Rule?; val dataset: Dataset?; val message: String }   // tests and consumers match on code, never on message
internal class RevoktWarning private constructor(…) { val code: WarningCode; val dataset: Dataset?; val message: String }   // a runtime warning, on SyncResult.warnings, the seed load and RevoktState.warnings; tests and consumers match on code, never on message
class RevoktPolicy private constructor(…) {           // newBuilder() on any policy, keeping the preset it derives from; no from-scratch builder; companion object { @JvmField val DEFAULT; @JvmField val STRICT }; fun exemption(rule: Rule): Exemption?
    fun outcome(rule: Rule): Outcome; val requiredDatasets: Set<Dataset>; fun staleness(dataset: Dataset): Staleness?
    val signedSourceFailingAfterMillis: Long   // plus a java.time accessor
    class Builder {                                      // every method returns Builder; build() returns RevoktPolicy and runs the build()-time checks below; every duration and millis argument is ≥ 0, else IllegalArgumentException, and so is a java.time.Duration whose milliseconds overflow Long
        fun rule(rule: Rule, outcome: Outcome): Builder                       //
        fun exempt(rule: Rule, exemption: Exemption): Builder                 // a second call for the same rule replaces the first; clearExemption(rule)
        fun exemptAnchors(sha256s: Collection<ByteArray>): Builder             // = exempt(rule, anchorIn(sha256s)) for every exemptable rule that is not EVIDENCE, is not marked "empty path" in the §8 table, and whose outcome in the builder at this call is REJECT; applied at its call position over the rule set as it stands then (a later rule() or exempt() on the same builder wins, so a narrower explicit exempt() written after it is kept): EVIDENCE rules (M2 ONECRL, M4 DISTRUST) need an explicit exempt(), so an M1 call never widens to evidence on upgrade, while a non-EVIDENCE rule that flips to REJECT in a later minor (M3 CT_UNVERIFIED) is covered by a call made after the flip, as a private CA wants; the "empty path" rule (NO_ISSUER; a column of the golden fixture, so a future rule must declare it) fire only on an empty reported path, where anchorIn can never match (use hostSuffixIn, platformOnly), whereas M2's ISSUER_UNKNOWN_TO_MOZILLA fires on a Found path and is covered; sha256s are of each anchor's DER as revokt reads it (§5.3), which is getEncoded() unless the §9.2 read fallback applies
        fun requiredDatasets(set: Set<Dataset>): Builder
        fun staleness(dataset: Dataset, s: Staleness): Builder; fun clearStaleness(dataset: Dataset): Builder   // clearing a required dataset's entry → validate() WARNING STALENESS_CLEARED_FOR_REQUIRED_DATASET
        fun rejectStaleAfter(dataset: Dataset, d: java.time.Duration?): Builder; fun rejectStaleAfterMillis(dataset: Dataset, millis: Long?): Builder   // null clears only the reject threshold; the loud flag stays; on a dataset with no entry, creates one with staleAfter = rejectStaleAfter
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
    class Path : Finding() { val status: PathStatus; val source: ChainSource
        val reason: PathReason?                          // non-null ⇔ status ∈ {NO_ISSUER, PARSE_FAILED, PATH_BUDGET_EXCEEDED}, and reason.status == status; the reported reason, after decide's UNSUPPORTED_ALGORITHM label or PLATFORM_ONLY promotion
        val issuerSpkiSha256s: List<ByteArray>           // the leaf-issuer keys evaluated, first the reported path's: in M1 at most one, the key of the walk's first path, of step 2's anchor leaf or a PLATFORM chain, else of the fallback path; M2's re-walk adds the keys of the paths it completes
        val anchorSha256: ByteArray? }                   // SHA-256 of the reported path's anchor DER; null when the reported path is empty or (M2) terminalKind == PRELOAD
    // The rest of how the walk reached the path is not public: each evaluation writes one DEBUG line (RevoktLogger) naming these fields, and the tests read them from the decision:
    //   walkerReason: NoIssuerReason? — the walker's own reason before any UNSUPPORTED_ALGORITHM label or PLATFORM_ONLY promotion; set on every walk NotFound, whatever the reported status (so a fallback Found after UNANCHORED still carries it), null otherwise
    //   keyabilityClause: KeyabilityClause? — non-null ⇔ reason == PRODUCER_UNKEYABLE (§9.2 K1–K8)
    //   terminalKind: TerminalKind? — null when the reported path is empty; else ANCHOR in M1; M2: PRELOAD for a preload-only path (a terminal of last resort), where anchorSha256 is null
    //   rewalkEnd (M2) — whether the re-walk completed or spent its budget, which never demotes the first walk's Found
    //   cacheHit (0.3); anchorSnapshotId: Long — id of the snapshot read once at flow step 2 (Evaluator.evaluate: at its entry) and consumed at decision step 1; 0 when none was consulted (Evaluator.evaluate with a verifiedPath of two or more certificates, presented also set or not; a one-certificate verifiedPath consults the snapshot read at entry for step 2's anchor test and reports its id; an evaluation that reached no decision logs the id it would have consulted); the walker harness assigns ids to its fixture snapshots
    //   usedFallback: Boolean — true whenever a fallback path was evaluated, Found or Budget
    //   pathsFound: Int — 1 when the decision found a path (step 2, the walk, or the fallback after a walk NotFound), else 0; M2: first walk plus completed re-walk paths
    //   reportedPathSha256s — DER hashes leaf → terminal of the reported path: the walk's path, else the fallback path (on a walk Budget too, with terminalKind and anchorSha256 following it, so issuerSpkiSha256s[0] stays the reported path's key), else empty
    //   candidatesDropped: Int — presented or platform-built certificates the parser rejected and the walker never saw (§9.2 issuer corpus); also RevoktStatus.candidatesDropped
    //   walkStats — verifications (verifier calls) and candidatesExplored (the work budget's count): the walker's counters
    class Crlite : Finding() { val result: CrliteQueryResult; val issuerSpkiSha256: ByteArray?; val coverageEndMillis: Long? }
    class DataState : Finding() { val dataset: Dataset; val generationId: String?   // "<changeset timestamp>/<last applied record id>", the last filter in buildIndex placement order (the full, then deltas by (effectiveTimestamp, id)); seed: seed id; null ⇔ no generation
        val freshness: Freshness?; val fromSeed: Boolean; val sourceTimestampMillis: Long?; val ageMillis: Long?   // now − sourceTimestampMillis, clamped at 0 when the signed timestamp is ahead of the local clock (§7.1: no rule reads the local clock against signed data)
        val pending: Boolean                             // true until the loader's start task installs a generation for this dataset or ends (the seed step, then the first sync when a fetching source is configured, §5.1; in-process; the §8 STALE gate is the persisted one); false at the end of the start task whatever it found, a fetching source configured or not (`CrliteRuntimePollTest` "with no seed pending holds through the first sync"); Rule.NO_DATA never fires while pending (§5.1 overload table)
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
        @JvmStatic fun platformOnly(): Exemption } }                         // context.path.reason == PLATFORM_ONLY; a null host or anchorSha256 never matches hostIn/anchorIn
// Exemptions.kt, @file:JvmName("Exemptions"): infix fun Exemption.and(other: Exemption): Exemption; infix fun Exemption.or(other: Exemption): Exemption   // Java: Exemptions.and(a, b). CEL's && and ||: short-circuiting but commutative; the side that decides the result wins whatever the other side did (true or broken = broken or true = exempt; false and broken = broken and false = not exempt), and its partner's throw is absorbed and not recorded; with no deciding side the first throw propagates and is recorded as not exempt plus the EXEMPTION engine error (when both throw, the left operand's); a fatal error (§5.5's catch rule) propagates at once; the outcome and findings never depend on operand order
class ExemptionContext private constructor(…) { val rule: Rule; val chain: PresentedChain? /* never null before M5; null for a non-X.509 credential */; val path: Finding.Path; val host: String? /* normalised */; val nowMillis: Long; val dataStates: Map<Dataset, Finding.DataState> }   // growable: new evidence (M3 SCTs, M4 distrust record) lands as new nullable properties, and M5 adds credentialType: CredentialType with enum class CredentialType { X509, MTC } (growable), the enum M5's EvaluationRequest.credentialType takes; internal builder
@RevoktInternalApi class AnchorSnapshot private constructor(…) { val id: Long /* process-local counter, like generationEpoch; not stable across processes */; val sha256: ByteArray /* SHA-256 of the distinct anchor DERs as read (§5.3), sorted as unsigned bytes and concatenated, so neither the platform's order nor a duplicate changes it; stable */; val anchors: List<ByteArray> /* each anchor's bytes read (§5.3), in the platform's order, duplicates and anchors the parser rejects kept (the index drops them), an anchor whose getEncoded() throws left out; the snapshot also keeps each anchor's getEncoded(), which the PKIX fallback re-parses */; val createdMillis: Long; val preloadGenerationId: String? /* null in M1; M2: the INTERMEDIATES generation the index holds; an INTERMEDIATES install rebuilds every live index and advances id, so both caches miss */ }   // @RevoktInternalApi with PathBuilderFallback, its one consumer (§3)
internal class SyncResult private constructor(…) { val outcome: SyncOutcome; val atMillis: Long; val installed: Map<Dataset, String> /* each dataset this sync installed, with the installed generation's id */; val sourceId: String? /* the source the outcome is about */; val failure: SyncFailure? /* why a SKIPPED or FAILED sync stopped; set exactly for those outcomes, and a code of that outcome */; val httpStatus: Int? /* the last response status when a fetch was involved */; @Transient val cause: Throwable? /* the fetcher's or loader's throwable; not persisted, null when read back; not part of equality or toString */; val warnings: List<RevoktWarning> /* CAP_NEAR_LIMIT */ }   // internal in 0.2, public with the 0.3 sync() (§11, #221)
class RevoktEvent private constructor(…) { val sequence: Long; val atMillis: Long; val policyEpoch: Long; val host: String? /* M5 adds credentialType */; val chainSha256: ByteArray; val leafSerial: ByteArray? /* rawSerial */; val verdict: Verdict; val shadowVerdict: Verdict? /* null when no shadowPolicy is set, and when the enforced evaluate threw before the shadow ran */; val enforcement: Enforcement; val enforced: Boolean /* = verdict is Rejected && enforcement == ENFORCE */ }
interface RevoktListener { fun onVerdict(event: RevoktEvent); fun onStateChanged(state: RevoktState) {} }   // second method has a default body; Java alternative to the state flow, delivered as it is: conflated and distinct, so a slow listener gets the latest state and may skip intermediate ones (`RevoktListenerTest`)
class RevoktStatus private constructor(…) {            // snapshot; counters monotonic since build() for unevaluated, since start() for every other; maps zero-filled over Rule.entries
    val evaluations: Long; val rejects: Map<Rule, Long> /* ENFORCE only */; val wouldRejects: Map<Rule, Long> /* OBSERVE only */; val shadowWouldRejects: Map<Rule, Long> /* the shadow policy's Rejected verdicts by rule, under ENFORCE and OBSERVE */; val fired: Map<Rule, Long>; val exempted: Map<Rule, Long>
    val noData: Map<Dataset, Long>; val stale: Map<Dataset, Long> /* loud flag seen */; val noIssuer: Map<PathReason, Long> /* fired[NO_ISSUER] keyed by the reported (promoted) reason, zero-filled over the NO_ISSUER reasons */; val parseFailed: Map<PathReason, Long> /* fired[PARSE_FAILED] split by reason, zero-filled over the PARSE_FAILED reasons */; val chainSources: Map<ChainSource, Long>; val fallbackUsed: Long
    val verifierErrors: Long /* Finding.VerifierError only; FallbackNotUsed is not counted */; val candidatesDropped: Long; val verdictCacheHits: Long; val storeFailures: Long; val trustManagerCount: Int; val droppedEvents: Long; val droppedRejectedEvents: Long; val listenerFailures: Long
    val unevaluated: Map<UnevaluatedReason, Long>        // handshakes that returned after flow step 1 without reaching step 2, on every trust manager; the one counter group that still advances in CREATED, after close() and under OFF, so an operator can tell "no traffic" from "not checking"
    val readinessWaits: Long; val readinessTimeouts: Long; val readinessWaitNanosTotal: Long   // flow step 0
    val pendingAllows: Map<Dataset, Long> }               // verdicts computed (verdict-cache misses only) while the dataset was pending (allowed without data); separates "checked" from "pending-allow"
enum class UnevaluatedReason { NOT_STARTED, CLOSED, OFF }   // growable
// Counters increment per applied verdict, cache hit or miss (§5.1 step 2); events are emitted on misses only. ByteArray getters return copies; Verdict.rules is an unmodifiable view.
class TrustManagerStatus private constructor(…) { val anchorCount: Int; val anchorSnapshotId: Long?; val anchorSnapshotAgeMillis: Long?; val pathCacheHits: Long; val verdictCacheHits: Long; val anchorRefreshFailures: Long; val lastAnchorRefreshFailedAtMillis: Long? /* a failed refreshAnchors() rebuild is a status, not only a WARN log line */ }   // null only while the owning Revokt is CREATED or CLOSED (flow step 1 only); non-null for every instance that can go past flow step 1
class RevoktState private constructor(…) { val lifecycle: RevoktLifecycle /* top-level enum in commonMain (RevoktState is an engine output type; Revokt lives in revokt-jsse): CREATED, STARTED, CLOSED; named to avoid androidx.lifecycle.Lifecycle */; val storageFallback: Boolean /* running on inMemory() for the life of the process instead of the configured storage (the lock held by another process, ownership, direct boot, STORE_NEWER_LAYOUT under IN_MEMORY); never retried, §3 */; val ready: Boolean /* lifecycle == STARTED && every required dataset has a generation (true at once when requiredDatasets is empty); anchor snapshots exist before any handshake can go past flow step 1 (§5.1 "Anchor snapshot") and play no part */; val enforcement: Enforcement
    val dataStates: Map<Dataset, Finding.DataState>      // an entry for every configured dataset; fromSeed and freshness say where the generation came from
    val unsupportedOids: Set<String>; val signedSourceFailing: Boolean; val signedSourceFailingSinceMillis: Long?
    val lastSync: SyncResult?; val nextSyncAtMillis: Long?; val warnings: List<RevoktWarning>; val diagnostics: List<PolicyDiagnostic> }   // consumers match on code, never on message. `warnings` (the WarningCode conditions) and `diagnostics` (the configuration WARNINGs in effect) are the conditions currently true, recomputed on every publish: session-sticky codes stay until close() (warnings SEED_UNREADABLE, SEED_CHANNEL_MISMATCH, STORE_MIGRATED, STORE_NEWER_LAYOUT, STORE_UNREADABLE, STORE_LOCKED; the diagnostic SEED_PAST_REJECT_THRESHOLD); cleared codes leave when their condition does (the diagnostics NO_FETCHING_SOURCE, RULE_FLIPPED_THIS_MINOR, UNVERIFIED_REJECTS_WITH_CLASSICAL_GAP and every other V or S WARNING that is a function of the published (enforcement, policy) pair, copied in by start() and the two setters, when a later pair no longer emits it); NOT_STARTED is never on it (it is the unevaluated counter). dataStates[…].ageMillis is frozen at publish time, compute a live age from sourceTimestampMillis
```

Growable enums are labelled above; closed ones are `Outcome`, `Enforcement`, `RuleClass`,
`Severity`, `RevoktLifecycle`, `VerifyResult`, `LogLevel`. `RevoktLimits`' public members are the four caps the builder raises (`MAX_FILTER_BYTES`, `MAX_JSON_BYTES`, `MAX_X5U_BYTES`, `MAX_CHANGESET_RECORDS`), `@JvmField val`, never `const val`; every other §5.1 limit is internal, and a limit no built feature reads is not declared (#221). Members
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
budget, CT, distrust or `STRICT` rejection is never triaged as a revocation.

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
clean path the re-walk completed), whether the re-walk completed is recorded as `rewalkEnd` on the evaluation's `DEBUG` line,
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
  an in-memory store, the default or an explicit `RevoktStorage.inMemory()`, with a fetching source → `WARNING` under
  every enforcement (a full re-download per restart, no crash recovery); a `JvmStorage.directory(…)` store never fires it
  (`RevoktValidateTest`).
  V `FORMAT_UNSUPPORTED`: a `remoteSettings` source while `V3 ∉ revocationEngine.formats` → `WARNING` under
  `OBSERVE`, `ERROR` under `ENFORCE` (Mozilla serves v3; the Kotlin and upki engines both list it, so it fires only for
  another engine injected through the internal seam; `formats` is read once, at `build()`; `PolicyDiagnostic.dataset` = `CRLITE`). V `NO_FETCHING_SOURCE`: a required dataset with a local data source and no fetching source → `WARNING` under both enforcements (the instance updates only through `sync()`'s seed re-check, §4).
- **Under `Enforcement.OFF` every V diagnostic is a `WARNING`**, so an `ERROR` can never block the switch
  to the kill switch; this binds every `ERROR`-capable V code, the ones `validate()` adds in `revokt-jsse` included.
- Each bullet names its code and the call that emits it. A code is a `DiagnosticCode` (on `PolicyDiagnostic`) when it reads the configuration: every B, R and V code, and the S codes `SEED_PAST_REJECT_THRESHOLD`, `UNVERIFIED_REJECTS_WITH_CLASSICAL_GAP` and `RULE_FLIPPED_THIS_MINOR`; it is a `WarningCode` (on `RevoktWarning`) when it reports the store's or the seed's state: `SEED_UNREADABLE`, `SEED_CHANNEL_MISMATCH`, `STORE_UNREADABLE`, `STORE_MIGRATED`, `STORE_NEWER_LAYOUT` and `STORE_LOCKED`, and the sync's `CAP_NEAR_LIMIT`. The enums list the codes whose producer is built; a bullet's code joins its enum when its producer is built. **B** = `RevoktPolicy.Builder`
  method throws `IllegalArgumentException`; **R** = `Revokt.Builder.build()` throws `IllegalArgumentException`; **V** = `validate(enforcement)` returns it (the setter and
  `start()` throw `IllegalStateException` iff any `ERROR`); **S** = `start()` appends it to
  `RevoktState.warnings`, or to `RevoktState.diagnostics` for a `DiagnosticCode`.
- B: `rejectStaleAfter < staleAfter` for any dataset.
- V `STALE_REJECTS_WITHOUT_THRESHOLD`: `outcome(STALE) == REJECT` and no dataset has a
  `rejectStaleAfter` → `WARNING` (the rule can never fire).
- S `SEED_PAST_REJECT_THRESHOLD`: `outcome(STALE) == REJECT` and the seed already past a dataset's
  `rejectStaleAfter` → `WARNING`. The seed is the seed generation the instance serves once the start task's store step
  ends: one this start installed, or one an earlier process stored that the recovery chain loads as `live`, as
  `previous` or by adopting it (§6.5), so a restart reports it as a first start does, measured from that generation's
  signed `<ts>`; a synced generation the step ends on reports none, even after the step served a seed generation first
  (`CrliteRuntimeStartTest` "a restart serving a stored seed generation past rejectStaleAfter reports
  SEED_PAST_REJECT_THRESHOLD", "a restart reports SEED_PAST_REJECT_THRESHOLD from a stored seed generation the chain
  reaches as previous", "… from an adopted stored seed generation, at its own ts"; `CrliteRuntimePollTest` "a restart
  serving a seed previous, then adopting a synced generation, reports no seed age").
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
- S `UNVERIFIED_REJECTS_WITH_CLASSICAL_GAP`: `outcome(NO_ISSUER) == REJECT && unsupportedOids() ∩ classicalOids ≠ ∅` → `WARNING`; `classicalOids` = RSA PKCS#1 with SHA-256/384/512, ECDSA P-256/P-384 with SHA-2, Ed25519, as the startup probe names them in its signature, key and curve tables (`sha256/384/512WithRSAEncryption`, `rsaEncryption`, `ecdsa-with-SHA256/384/512`, `id-ecPublicKey`, P-256, P-384, Ed25519).
- S `RULE_FLIPPED_THIS_MINOR`: for every rule with `flippedIn == current minor` whose outcome in the consumer's policy is `REJECT` by inheritance (the policy and the preset it derives from both reject it; an explicit `REJECT` equal to the preset's counts, since it enforces the flipped rule all the same) → `WARNING` on `RevoktState.diagnostics` (a runtime signal that this build enforces a newly flipped rule; a rule in its grace minor is visible only in `fired`).
- V `NO_DATA_AT_FLIP` (the one state-dependent V code): in `STARTED`, `validate(ENFORCE)` (the enforcement setter, and the policy setter against the current enforcement) returns `ERROR` when `outcome(NO_DATA) == REJECT` and a required dataset has `generationId == null`, `pending == false` and a `SEED_UNREADABLE`/`STORE_UNREADABLE` warning for its sole local source; while `pending == true` the flip is accepted and the dataset becomes `NO_DATA` if the start task finds nothing, which `validate()` cannot see.
-
- V `STRICT_ON_ANDROID_WITHOUT_NO_ISSUER_EXEMPTION`: `STRICT` on `AndroidPlatformTrust` with no `NO_ISSUER` exemption → `WARNING` citing the §5.2 gap.
- V `BUDGET_ALLOWS`: `outcome(PATH_BUDGET_EXCEEDED) == ALLOW` → `WARNING` (re-opens the stuffing evasion).
- V `IO_DISPATCHER_UNCONFINED`: `ioDispatcher` is exactly
  `Dispatchers.Unconfined` → `WARNING` under both enforcements (fetches would run on the loader thread, defeating the
  per-fetch timeout, §4). Other inline executors are covered by §4's sentence only.
- R: `outcome(NO_ISSUER) == ALLOW` with the PKIX fallback disabled (§5.1: the fallback is load-bearing).
- (not a diagnostic) [0.3] An empty anchor set, a throwing `getAcceptedIssuers()` or a failed index build throws `IllegalStateException` from `trustManager(delegate)` in `STARTED` and from `start()` for consumer trust managers created in `CREATED`, on both platforms (§5.1 "Anchor snapshot"). In 0.2 the anchor snapshot build throws it, `start()` succeeds and `Evaluator.evaluate` throws it until an index exists (§11).
- S `SEED_UNREADABLE` / `SEED_CHANNEL_MISMATCH` / `STORE_UNREADABLE` / `STORE_MIGRATED` / `STORE_NEWER_LAYOUT` (per §6.5) / `STORE_LOCKED` (§3: another process holds the store lock); S→`ERROR` thrown by `start()` under `ENFORCE` with `outcome(NO_DATA) == REJECT` when the seed is the only local data source and is unreadable: **in that configuration, and only when the synchronous read of the pointer and its `live` generation file (§6.5 Load's steps 1 and 2) finds no stored generation (first run, a rebuild, corruption), the seed's verification, `index.bin` rebuild, `prepare` and `activate` run synchronously inside `start()` on the calling thread, before the flip and before any loader task exists (the one exception to "loader dispatcher only"; a `prepare` or `activate` failure is `SEED_UNREADABLE` and throws here; the factory lock is released around this work, §5.1 lifecycle)**; with a pointer and `live` that pass Load's steps 1 and 2 (§6.5) the loader decodes it as §5.1 states (falling to `previous`, then the seed, so a readable store masks a bad seed and the common cold start never decodes on the calling thread), otherwise on the loader task (a loud failure in `CREATED`, platform-only, instead of a silent reject-all); when the start task's store step then leaves no generation (that `live` fails Load's step 3 or 4 on the loader and the seed does not install either, or a store read throws there and the read stays unresolved), `start()` has already returned and does not throw: `NO_DATA` rejects every handshake until a generation installs, and the condition is logged at `ERROR` naming `SEED_UNREADABLE` and `NO_DATA`, except while the loader thread is interrupted (`close()` stopping it) (`CrliteRuntimeStartTest` "a sole-seed start whose live fails step 3 beside a seed that does not verify logs SEED_UNREADABLE", "a sole-seed start whose store read throws on the loader logs SEED_UNREADABLE, unless it is interrupted"); [0.3] with `state` it is `SEED_UNREADABLE` on `RevoktState.warnings` beside `generationId == null` and `pending == false` for the dataset, the triple `NO_DATA_AT_FLIP` reads (`RevoktStateTest`); `STORE_UNREADABLE` never throws (§6.5); a seed
  channel mismatch is an `ERROR` thrown synchronously by `start()` on both platforms (the `seed.json`
  header is read synchronously).
- `NOT_STARTED` is not a warning: a trust manager or `sslContext()` obtained before `start()` runs step 1 only until `start()` and counts `unevaluated[NOT_STARTED]` (creating trust managers before `start()` is the recommended main-thread pattern, so it cannot be a stuck alert).
- R `CHANNEL_UNSET`: no `channel` configured while a CRLite source (a seed included, the default `bundled()` too) is; `build()`'s message names the code, and no `PolicyDiagnostic` carries an R code. R `PLATFORM_TRUST_MISMATCH`: Android runtime with a non-Android `platformTrust`. R `STORAGE_UNSET`: `AndroidPlatformTrust` with no explicit `storage` (§3).
- Runtime warnings on `SyncResult.warnings` (`WarningCode`): `CAP_NEAR_LIMIT` (a body or record count above half the `RevoktLimits` constant, not the overridden value, the signed size notwithstanding; the §9 live check warns on it). Why a sync stopped is its `SyncFailure`, never a warning: `SCHEMA_REJECTED` (a verified changeset whose records fail the collection schema), `ATTACHMENT_OVER_CAP` (a signed record over the cap, §5.1 limits table), `INDEX_INCONSISTENT` (§3.2's over-cap built index and §6.5's index-name collision), `FORMAT_UNSUPPORTED` (§3.2). `SyncResult.failure`, `httpStatus` and `cause` say where and why without parsing `message`.

## 5. Trust manager [M1]

### 5.1 Common flow

**Limits** (`object RevoktLimits`; walker budgets are documented constants; download and record caps are builder-overridable upward; cache sizes are builder-configurable):

| Constant | Value | Meaning |
|---|---|---|
| `MAX_DEPTH` | 16 | a path holds at most `MAX_DEPTH + 1` certificates including the terminal; deeper is a dead end, not exhaustion (same convention in the reference walker) |
| `MAX_PRESENTED` / `MAX_PRESENTED_BYTES` | 64 / 1 MiB | presented certificates and their summed DER; beyond either the chain is `Budget(EXPLORATION_BUDGET)` without a walk (honest chains are under 20 KB; bounds per-handshake memory independently of `MAX_CERT_BYTES`) |
| `MAX_EXPLORED` | 256 | the walk's one work budget, as webpki's `Budget` and mozilla::pkix's `buildForwardCallBudget`: candidates explored per walk, at every depth, an anchor, a memo hit and a candidate the issuer rules refuse included, a loop not (it is skipped uncharged); the 257th is not explored and ends the walk `Budget(EXPLORATION_BUDGET)`. Each exploration makes at most one verifier call, so it bounds the verifications too |
| `FALLBACK_MAX_PRESENTED` | 8 | the PKIX fallback is skipped for longer presented chains; a `NotFound` on such a chain is `PATH_BUDGET_EXCEEDED`, never `NO_ISSUER`, whether the platform accepted it in step 1 or step 1 did not run (the walker-only harness, `Evaluator.evaluate`), and with the fallback enabled or disabled (decision step 6) |
| `PATH_CACHE_ENTRIES` / `PATH_CACHE_TTL` | 256 / 10 min | per trust manager; TTLs are absolute from insertion on the monotonic `TimeSource`, not sliding; entries hold the leaf's DER, `serial` and `scts` only, never the presented chain |
| `CROSS_CALL_MEMO_ENTRIES` | 1,024 | per `Revokt`; `VERIFIED` only; synchronized, shared by concurrent handshake threads across trust managers |
| `ACCEPTANCE_MEMO_ENTRIES` / `ACCEPTANCE_MEMO_TTL` | 1,024 / 24 h | per trust manager; the 3-arg null-host retry memo (flow step 1), keyed (chain hash, host'), written only after a Socket/SSLEngine overload's flow step 1 returned; absolute TTL; an expired entry costs a failed lazy cleaner on a long-lived connection and buys no safety, hence long |
| `ENGINE_CLOSE_DRAIN` | 5 s | `RevocationEngine.close()` waits this long for in-flight queries (§3.2) |
| `FETCH_TIMEOUT` | 30 s | default `FetchRequest.timeoutMillis`, enforced by the engine (§3), so "a sync attempt completed" is bounded |

| `VERDICT_CACHE_ENTRIES` / `VERDICT_CACHE_TTL` | 1,024 / 60 s | per trust manager |
| `ANCHOR_REFRESH_MIN_INTERVAL` | 60 s | |
| `EVENT_RING_CAPACITY` / `REJECTED_QUEUE_CAPACITY` | 64 / 4,096 | |
| `MAX_TRUST_MANAGERS` | 16 | live instances per `Revokt`, builder-overridable in both directions, ≥ 1 (`limits { maxTrustManagers }`); live referents are counted through `WeakReference`, and before the cap throws every entry whose referent has cleared is evicted regardless of `ReferenceQueue` delivery, so a rebuilt client's dropped instance never counts |
| `MAX_CERT_BYTES` | 262144 | per-certificate DER size (measured max over the seed corpus with margin), of `getEncoded()` before any parse and again of the bytes read (§5.3, §9.2); a larger certificate is a dropped candidate (`candidatesDropped`; leaf: `PARSE_FAILED(OVERSIZE)`); §9.2 fuzzes to the cap + 1 and asserts the over-cap behaviour |
| `MAX_FILTER_BYTES`, `MAX_JSON_BYTES`, `MAX_X5U_BYTES` | 16 MiB, 4 MiB, 64 KiB | caps for **unsigned** bodies (the changeset JSON itself, x5u; a stored or seed `index.bin` is read only up to 1 MiB, §3.2); for a `SIGNED` attachment the cap is `min(attachment.size, MAX_FILTER_BYTES)` (hash and size both verified; a signed record declaring more is `SyncOutcome.FAILED` with `ATTACHMENT_OVER_CAP` and advances nothing: a 16 MiB freeze is recoverable by raising the cap, a crash loop from one bad signed record is not); enforced while inflating; bodies are fetched, verified and written **one at a time**, so heap peak is one body plus its decode |
| `MAX_CHANGESET_RECORDS` | 1,024 (Remote Settings listed 53 records a channel on 2026-11-12; about four deltas a day reach 256 in 64 days, so a lower cap would freeze a shipped client) | record cap per changeset after channel filtering; a changeset over it is rejected before any body fetch. There is no per-sync total (neither upki nor Firefox has one), so a sync is bounded by these counts and the per-file caps, about 16 GiB from a malicious server holding a valid signature (1,024 × 16 MiB), which is accepted |
| `MAX_BACKOFF` | 24 h | cap on honoured `Backoff`/`Retry-After` and on persisted `backoffUntilMillis`; computed failure backoff ≤ the 6 h poll interval; the longest wait between two scheduled syncs |
| `POLL_INTERVAL` / `POLL_JITTER` | 6 h / 36 min | the wait after a sync that did not fail, plus a jitter uniform in `[0, POLL_JITTER)` (§5.1 "The sync schedule"; `RevoktLimitsTest`) |
| `MIN_POLL_DELAY` | 60 s | the shortest wait between two scheduled syncs, so a `Retry-After: 0` or a backoff already past never re-polls at once (§7.1) |
| `AWAIT_DATA_COMPAT`, `AWAIT_DATA_DEFAULT` | measured (§6.4) on Android; a fixed 2 s on the JVM (§11) | readiness deadline per channel |

The name-constraint comparisons of one walk, and of one fallback path, are bounded at 250,000, webpki's
`name_constraint_comparisons` (fixture (as), "the comparison budget shared by two candidates";
`DecideFallbackTest`). The bound is internal, not a `RevoktLimits` constant, and a separate unit in the walk's one
budget, as webpki counts it: spending it ends the walk as `MAX_EXPLORED` does.

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
   cached under the path key; a `build` that returns null, throws, or returns a path decide cannot use (shorter than
   the leaf and its issuer, holding a null element, not starting with the presented leaf's bytes, not ending at an
   anchor of the index by exact bytes, holding a certificate that does not parse, or failing the issuer rules of
   "Why this is sound" below, nameConstraints and the comparison bound included; `DecideFallbackTest`) is a
   **failed** fallback. A throw is caught here
   and is never an engine error, except that every `VirtualMachineError` other than `StackOverflowError` is rethrown,
   as at §5.5's catch boundary. A result produced by a throw is **not** cached, neither in the path cache nor, through
   its verdict, in the verdict cache (flow step 3a), so a transient error is not remembered; a null return is:
   - walk `NotFound` and the fallback finds a path → `Found([fallback], usedFallback = true)`.
   - walk `NotFound`, the fallback was **skipped** (chain too long) and the platform accepted in
     step 1 (or step 1 did not run: the walker-only harness and `Evaluator.evaluate`) → `PATH_BUDGET_EXCEEDED(FALLBACK_LIMIT)` (the walk itself completed) and `FallbackNotUsed(SKIPPED)`:
     no honest Web PKI chain is longer than 8 certificates and unreproducible by the walker, and the
     server controls chain length.
   - walk `NotFound` and the fallback failed (`FallbackNotUsed(FAILED)`): on a trust-manager binding (and `Revokt.evaluate`, which always runs step 1), **any** such walk
     `NotFound` is `NO_ISSUER(PLATFORM_ONLY)`, whatever the walk recorded: the platform trusts a chain neither revokt's
     walker nor its PKIX builder can reproduce (divergent canonicalisation, constraints, verifier or anchors). The
     walker's own reason is kept as `walkerReason` on the evaluation's `DEBUG` line, and every recorded OID in an `UnsupportedAlgorithm`
     finding. In the walker-only harness and `Evaluator.evaluate` it is `NO_ISSUER(UNSUPPORTED_ALGORITHM)` when the walk recorded an
     own signature OID (`tbsSigOid`) in `unsupportedOids()`, in mozilla::pkix's order (`CheckIssuerIndependentProperties`
     runs before `VerifySignedData`):
     - every candidate that is not an anchor, when explored, whether or not it verifies its child;
     - the leaf only once a candidate was found for it (pkix's end-entity deferral), so a leaf presented
       alone is `NO_ISSUER(NO_CANDIDATE)`.

     A candidate's key or curve OID never counts. Otherwise it is `NO_ISSUER` with the walker's reason. A server can
     steer the reason there, which is why it is a reason of one rule and not a rule of its own; `walkerReason` keeps
     the walk's reason.
     Unlike pkix, there is no collapse to one error when candidates fail differently.
   - walk `Budget`: the walk carries no path (it stops at its first), so only the fallback path's issuer key is
     evaluated in step 7, **only so that `REVOKED` is reported when reachable**; the path status
     is `PATH_BUDGET_EXCEEDED(EXPLORATION_BUDGET)` regardless; `usedFallback = true` when a fallback path was evaluated.
   - **fallback disabled** (`pkixFallback(false)`, and the walker-only harness's disabled path):
     `pathBuilder.build` is never called, and step 6 gives what the branches above give when no fallback path
     exists, with `FallbackNotUsed(DISABLED)` wherever the fallback did not run because it is configured off
     (`SKIPPED` is the enabled, too-long case only). Walk `Budget` → `PATH_BUDGET_EXCEEDED`, the same
     as with the fallback enabled, with no key evaluated and `usedFallback = false`; walk
     `NotFound` with `presented.size > FALLBACK_MAX_PRESENTED` → `PATH_BUDGET_EXCEEDED(FALLBACK_LIMIT)`,
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
| `(chain, authType, SSLEngine)` | `java.net.http`, Netty, Ktor Java | no | seed if loaded; until the start task has installed a generation or ended (the seed, then the first sync) the dataset is `pending` and `NO_DATA` does not fire (allow), so the Android seed load never rejects on a non-waiting overload; `NO_DATA` only once the start task found nothing local; the anchor snapshot always exists in `STARTED` |
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
it has been created; on Android this is also the warm-up of the NSC certificate sources);
a failure throws `IllegalStateException` before any registry entry or store lock is taken. Then register `storage.identity()` in the in-process registry when non-null
(a second instance on one store throws `IllegalStateException` before any lock is taken, `StoreOpenTest`,
`RevoktStoreTest`), `storage.lock()` (the internal `StoreLockedException` → `STORE_LOCKED`, and the instance runs on
`inMemory()` for the life of the process, §3), read `store.version` (an empty store is initialised silently; lower →
`STORE_MIGRATED`, higher → `STORE_NEWER_LAYOUT`; a malformed or unreadable one, or none beside other entries →
`STORE_UNREADABLE`, §6.5); a `start()` that throws after the lock and before its loader runs releases it and
deregisters the identity; once the loader runs it owns the store, and only `close()`, after stopping the loader, releases
it (`RevoktStoreTest`), the
pointer and its `live` generation file through §6.5 Load's steps 1 and 2 (a failure → treated as no stored generation,
`storeFailures++` and no warning: the next install heals it, and `STORE_UNREADABLE` means only that the instance runs
in memory, §3; test-plan.md (e), `CrliteRuntimeStartTest`), and the `seed.json` header (`SEED_CHANNEL_MISMATCH` →
`IllegalStateException`). **When the sole-seed `ENFORCE` configuration finds no pointer and `live` that pass Load's
steps 1 and 2** (§4 S bullet) the factory lock is now released, the seed is verified, rebuilt, prepared
and activated on the calling thread (150–300 ms interpreted on the default channel, §6.4),
the lock is re-taken, snapshots are built for any trust manager created in the gap (it saw `CREATED`
and built nothing), and the flip follows; a `trustManager(d)` racing this therefore blocks only for the
lock's short holds, never for the decode. **The other two racers in the gap, stated**: a second `start()`
that finds `STARTING` under the lock waits on the lock's condition until the first completes and then
returns or throws per the first's outcome (it never registers, locks or decodes a second time, so
`prepare`/`activate` stay serialised; the WorkManager worker's `start()` racing the app's is this case);
`close()` that finds `STARTING` sets a cancel flag and **waits, unconditionally, until the decoding
thread has re-taken the lock and left** (the wait's duration is bounded by the decode; it is not a
timeout); `close()` never releases a store lock it did not take and never calls
`engine.close()` while a `prepare`/`activate` is in flight. The three outcomes: (i) the
decoder sees the flag before `activate`: it closes the prepared generation, releases the store lock,
deregisters the identity, and `start()` throws `IllegalStateException("closed")`, lifecycle `CLOSED`;
(ii) the decoder missed the flag: `activate`, the pointer flip and `updater.json` complete, the
decoder publishes the generation reference, re-takes the lock, sees `CLOSED`, releases the store lock
and throws the same exception; the written generation stays on disk and `close()` then clears the
reference and runs `engine.close()` in its usual order; (iii) no `close()` raced: a `start()` that
throws **after** `activate` (a gap trust manager's snapshot build fails) leaves the live engine
generation, the written seed generation and the flipped pointer in place and the lifecycle unchanged
(`CREATED`, or `CLOSED` when `close()` raced); the retry finds a pointer and `live` that pass Load's steps 1 and 2 and loads
it on the loader without a second seed verification. The decoding thread is recorded: a `start()` or
`close()` from it (consumer code inside an injected engine's `prepare`, a `SeedOpener` or a verifier)
throws `IllegalStateException("re-entrant start()/close() from the start() thread")` instead of
waiting on itself. The worker maps a cancelled `start()` (`"closed"`) to `Result.failure()` like a
`CLOSED` instance. **A `start()` that throws** releases the store lock and deregisters the
identity if it had taken them, leaves the lifecycle at `CREATED` (never flipped), submits no loader
task, discards the snapshots it built in that call (no handshake can have keyed a cache on them: in
`CREATED` every trust manager runs step 1 only; ids are not reused), and may be called again once
the cause is fixed, when it rebuilds every pre-start instance; a pre-start instance whose delegate
keeps failing therefore fails every retry until the consumer drops it and it is collected. Then **one loader task**: load the stored generation (unless `start()` found none synchronously and installed the seed instead; deciding on each
candidate's `<ts>` against the seed's first and loading in full only the winner, §6.5 crash recovery; failure →
`previous` → nothing, each `storeFailures++`), verify and install the seed (unless `start()` already did so synchronously, §4 S bullet) under the **seed-load rule**
(§6.5: skipped beside a trusted pointer whose `live` generation is not older, a newer complete generation adopted
when no pointer can be trusted; the watermark becomes `max(watermark, seed timestamp)` taken from the verified
`records.json` beside a loaded generation, and the seed timestamp itself when none loaded, §7.1; a blob whose key exists and re-hashes to its name is never rewritten, a mismatch rewritten from the seed,
`storeFailures++`), then, when a fetching source is configured, the first sync in the same task (under a persisted `backoffUntilMillis` it runs at once and completes as `SKIPPED` with `BACKOFF`, setting `lastSync` and both `lastAttemptAtMillis` fields (per source and `datasetLastAttemptAtMillis`), then reschedules at the backoff), then `pending` cleared (`CrliteRuntimePollTest` "the start task installs the seed then the first sync's newer generation"). The JVM `start()`
joins that task up to `awaitData` (after the factory lock is released), so a slow first sync never holds `start()` past it (`RevoktPollTest` "close cancels a sync in flight"), and then returns (the
readiness future covers the rest); Android returns after the synchronous part without joining the
loader and its waiting bindings cover the gap; while `STARTED`
the loader is the only publisher of the generation reference. The loader thread is a daemon named
`revokt-loader-<identity or build sequence>` (two channels in one process are told apart). The loader runs under every `Enforcement`, `OFF` included, so a runtime flip is
immediate. An explicit `sync()` queues behind the start task and any in-flight install, ignores
the poll interval and honours `backoffUntilMillis` (`SKIPPED` with `BACKOFF`).

**The sync schedule** (#147). After each sync the loader schedules the next one on its own thread, one at a time, at a
wall-clock time on the builder's `clock`, waited as a delay on a monotonic timer (`PollScheduleTest`, `RevoktPollTest`):
- after a sync that did not fail (`INSTALLED`, `UNCHANGED`, `SKIPPED` with `ROLLBACK_REFUSED`): `now + POLL_INTERVAL +
  jitter`, the jitter uniform in `[0, POLL_JITTER)` from an internal random source, so it only lengthens the wait, or the
  source's `backoffUntilMillis` when that is later ("after a poll that did not fail the next is 6 h plus the jitter",
  "a Backoff on a poll that did not fail waits the longer of it and the interval, up to 24 h");
- after a `FAILED` sync: its `backoffUntilMillis` exactly, with no jitter (§7.1: the server's `Backoff` or `Retry-After`,
  else the computed failure backoff; "a FAILED sync waits its backoff exactly");
- after a `SKIPPED` sync with `BACKOFF`: the `backoffUntilMillis` it honoured;
- after a sync that wrote no `updater.json` (its read or its write threw, §6.5), or a sync step that threw: 15 min, the
  first failure backoff, held in memory ("a sync that wrote no updater json retries in 15 min", "a sync step that throws
  is logged and retried in 15 min");
- after a sync whose re-read leaves the start task's store read unresolved (below): §7.1's computed failure backoff over
  the consecutive re-reads that left it so, 15 min doubled per re-read up to 6 h, held in memory and reset once the read
  resolves, since each re-read decodes again what failed ("each unresolved re-read waits the failure backoff, up to 6 h,
  reset once the read resolves");
- every delay is clamped to `[MIN_POLL_DELAY, MAX_BACKOFF]`, 60 s to 24 h ("every delay is between 60 s and 24 h").

Firefox polls on a 24 h timer (`services.settings.poll_interval`) and on Push broadcasts, without jitter, and retries
no failure before the next one; upki leaves the schedule to its packager (Appendix A). `now` is the sync's own clock
read. The task catches every throwable and schedules the next sync in a `finally`; a fatal error is rethrown after that,
so the schedule never stops ("a fatal error in a scheduled sync is rethrown after the next sync is scheduled"). The
scheduled sync never re-opens the seed. **While the start task's store read is unresolved** (the seed load's read
threw, its install failed before `activate`, or it found a stored generation 0.2 does not load: `Skipped`, `Adopted`),
every sync first runs the seed load again, and syncs only once that load leaves the seed live; otherwise it fetches
nothing, writes nothing and is retried after that backoff (§7.1 "no sync runs after a stored-generation read that threw until
that read resolves"; `CrliteRuntimePollTest` "an unresolved store read is re-read by the first sync, which is
refused below the watermark", "while the store read stays unresolved nothing is fetched or written").

**`close()`** (never on the Android main thread, and never on the loader thread, where it throws
`IllegalStateException`; it blocks): take the factory lock **only** to flip the state to `CLOSED`
(serialised with `start()`'s flip and `trustManager(d)`'s lifecycle read; a `start()` that then sees
`CLOSED` under the lock throws; a `start()` already past its flip whose loader join observes `CLOSED`
returns normally) and release it before anything else → stop scheduling (a sync that ends after the flip schedules
nothing, and a timer the loader's shutdown refuses drops the task: `RevoktPollTest` "a sync scheduled before close never
runs") → complete the internal
`dataReady` future and the public `readyFuture()` (the public one exceptionally) → cancel the
loader and await an in-flight install (a sync waiting on a fetch ends `FAILED` at the interrupt and installs nothing; a
cancelled install never flips the pointer, closes an un-activated `PreparedGeneration` and deletes its own directory
before returning), then the loader thread's exit, so no loader thread outlives `close()` (`RevoktPollTest` "close
cancels a sync in flight, and nothing runs after it returns") → drain in-flight handshakes (a handshake thread
increments the in-flight counter **before** it reads the lifecycle state and decrements after, so the drain cannot
miss a thread that has passed the check) → release the store lock → deregister the identity (both after the loader's
exit and before `engine.close()`, `RevoktStoreTest`; if stopping the loader throws, the lock stays held, since the loader
may still write, and a later instance in the process on that store throws for the life of the process) → clear the generation
reference (the loader is stopped, so this is the only post-loader write) → `engine.close()` (always; `Revokt`
owns the engine; a throw from it is rethrown once every other step has run, so an engine that did not close is never hidden, and a later `close()` is a no-op). **After `close()`, and in `CREATED`, every trust manager, existing ones included,
runs step 1 only**, as `OFF`, with no events and frozen counters other than `unevaluated`; `trustManager(d)` in `CLOSED`
returns such an instance. Clients that outlive `close()` therefore keep working on the platform verdict alone.
`dataDeadline` is measured from the lifecycle flip to `STARTED`, not from the call to `start()`, which may block on the store lock's try and the NSC warm-up first. Every handshake that returns after flow step 1 without reaching step 2 (in `CREATED`, after `close()` or under `OFF`) increments `RevoktStatus.unevaluated[reason]`, the one counter group that is never frozen.

**`reconstruct`: invariant, deferral rule, termination rule and argument.**

*Invariant.* A returned path is leaf → … → terminal in which every link's signature was
`VERIFIED` by the injected verifier under the next certificate's key and whose terminal is in the
anchor snapshot by exact bytes. **M2**: a candidate found in Mozilla's signed preload by Mozilla's
bytes is a *candidate*, not a terminal: the walk continues from it toward an anchor; a preload-only
path with no anchor reachable is reported with `terminalKind = PRELOAD` on the `DEBUG` line and
`anchorSha256 = null`, counts as `Found` for L3 CRLite, and is `DISTRUST`-unevaluable at M4 (a
`Finding`, never an allow of a listed anchor). The leaf's
issuer keys are taken only from such paths. Platform-verified chains are trusted without re-verification.

*Deferral rule.* No candidate may be excluded because of a property it shares with another
candidate (no deduplication by key, name or key identifier; only exact byte duplicates, across
presented and store, certificates already on the current path, and loops are skipped; **an exact-byte
duplicate is yielded once, at the earliest position in the node's order: the store position for a duplicate of
an anchor, since anchors come first at every depth, and in M2 the presented position for a duplicate of a preload
certificate, since presented certificates come before the preload**). A candidate may be deferred
or capped only by its own relation to the child. A candidate is **related** when its subject equals
the child's issuer (raw bytes, or under `canonicalSubject`, which on the JVM and Android is the
platform's own `X500Principal` canonical form) or its SKI equals the child's AKI `keyIdentifier` (an
AKI carrying only the issuer-and-serial form, or an issuer without an SKI, makes the test name-only).
**Only related certificates are candidates**, at every depth, as webpki and mozilla::pkix offer only
name-matched issuers: a presented certificate that is not related to the child is never explored. Every honest
issuer is related under the platform's own canonicalisation, which is why the engine delegates canonicalisation to
the platform; on both default delegates every honest issuer is therefore related, and a delegate whose name equality
differs from `X500Principal`'s leaves its misclassified issuers to the PKIX fallback (§10 residual 1). A **loop** is a
candidate whose raw subject and raw SPKI equal those of a certificate already on the path, the leaf and the child
included (RFC 4158 §5.2, as webpki and mozilla::pkix compare); it is skipped as a certificate on the path is: it is not
explored, not charged to the budget, and does not count as a candidate for the leaf's `NoIssuerReason`.

*Termination rule.* **The first sound path ends the walk**, at every depth, the leaf included, as both references
stop: `Found` carries that one path and its leaf-issuer key (M2 re-walks exhaustively when a layer hits, under the
re-walk rule of step 8: fresh budgets, shared memo, never demoting the first walk's `Found`). **The work budget is the
walk's, not a node's**: spending `MAX_EXPLORED`, or the name-constraint comparison bound, at any node aborts the whole
walk with `Budget`; only `MAX_DEPTH` is a local dead end. Since the walk stops at its first path, a `Budget` carries
no path.

*Why this is sound.* Every path member below the leaf that is not an anchor must be able to issue (fixtures (aq),
(ar)): its one basicConstraints reads `cA = TRUE` with a `pathLenConstraint` of at most 127; it is
within that `pathLenConstraint`, counting every CA between it and the leaf, self-issued ones included; it sets
`keyCertSign` when it has keyUsage; and it lists the request's purpose (`serverAuth`, or `clientAuth` for a client
certificate) when it has extKeyUsage, `anyExtendedKeyUsage` not counting. Every nameConstraints on the path, an
anchor's included, must admit each certificate below it, under mozilla::pkix's rule (`pkixnames.cpp` at Firefox
`cac25a6`, Appendix A; fixture (as)), stated in full here:

- **The names a certificate presents:** each subjectAltName entry; its subject as a directoryName, always; when it has
  no subjectAltName extension at all, each subject `emailAddress` attribute as an rfc822Name, one that is not an
  IA5String failing; and, for the leaf of a `serverAuth` request whose subjectAltName holds no dNSName or iPAddress,
  its CN-ID. The CN-ID is the subject's last commonName: a dNSName when its value is a PrintableString, UTF8String or
  TeletexString that is a valid presented DNS name (a wildcard allowed), else an iPAddress when it is a dotted IPv4
  address (four decimal components of 0 to 255 without leading zeros); a last commonName of another string type, or
  that is neither, presents nothing. A subject read for these attributes must be a well-formed `Name` with no empty
  RDN.
- **The subtrees:** a permitted list binds a name only when it holds a subtree of the name's form, and one of those
  must then match; an excluded subtree that matches is a violation. By form:
  - **dNSName:** on label boundaries, ignoring ASCII case; `""` matches every name and a leading dot only subdomains;
    a wildcard name is inside a permitted subtree only when every expansion is, and inside an excluded one when any
    expansion could be.
  - **iPAddress:** address and mask of the same family; a mask that is not ones then zeros fails.
  - **directoryName:** a permitted subtree's RDNs must be a prefix of the name's, so the empty Name admits every name
    and a non-empty Name never admits an empty subject. RDNs at the same position hold as many AVAs, compared in
    encoded order, not as sets; two AVAs match when their type OIDs and value bytes are equal and their value tags
    are equal, a UTF8String and a PrintableString counting as one, with no case or whitespace folding. Any excluded
    directoryName subtree, the empty Name included, refuses every certificate below it.
  - **rfc822Name:** a presented mailbox must be valid: dot-separated atoms of RFC 2822 `atext`, no quoted string,
    `@`, and a valid DNS name without a wildcard. A subtree with an `@` is one mailbox, valid too, and matches the
    same mailbox ignoring ASCII case. One without is a host: `example.com` matches the mailboxes at that host only,
    not its subdomains, `.example.com` those at its subdomains only, and `""` every mailbox.
  - **URI and any other form** that a name and a subtree share: a violation.
- **Failing closed:** a value that does not read, a duplicated extension, a malformed name or subtree met in a
  comparison, and a subject that must be read and does not, all fail.

Each rule is a dead end before the link is verified, as pkix checks an issuer before `VerifySignedData`; an anchor by
bytes is exempt from all but its nameConstraints, as webpki's `TrustAnchor` has no other extension. The
name-constraint comparisons of one walk are bounded at webpki's 250,000: one per name and subtree compared, and one
more per AVA pair a directoryName comparison compares. Spending them ends the walk `Budget(EXPLORATION_BUDGET)`
(fixture (as), "the comparison budget shared by two candidates"). Anyone can obtain an end-entity certificate under a
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
verifier divergence, §10 residual 1). Beyond the budget the walk is `Budget`, which rejects whatever the fallback does, and a `NotFound` too long for the fallback is
`PATH_BUDGET_EXCEEDED`. A policy may not disable the fallback while `NO_ISSUER` allows.

The pseudocode of `reconstruct` is explanatory, not normative: [docs/design/walker-pseudocode.md](../design/walker-pseudocode.md). The code and the §9.1 properties are normative.

- **Explored** means the walker charged the candidate to the work budget and requested its verification (memo hits
  included); **verifications** counts calls into the injected verifier, at most one per exploration.
- **Cost.** An honest leaf → I → root chain: at the leaf, I (one verification, recurse); at I, the store anchor first
  (one verification, terminal, stop). Two verifications. A presented cross-certificate of the root sorts after the
  store anchor and is never reached once the anchor verifies, and even when reached it is a memo hit (same key); a
  root-issued leaf is one verification, its presented cross-certificates included, since the walk stops at the store
  root; a chain whose snapshot holds the other root of a cross-sign costs depth + 1 (three). A related decoy ahead of
  the honest issuer costs one exploration. Honest bound: **≤ depth + 1**; fixture (v) asserts ≤ 4 against a 200-anchor
  snapshot. **Worst case is bounded by `MAX_EXPLORED`**: junk ahead of the honest issuer, or a nested subtree of
  verifying junk (RSA duplicate-signature keys make junk verify), reaches it in one or two levels, about 250 ms of
  RSA-4096 verification on a mid-range ART device, and ends in `Budget`, never an allow. Per-candidate sub-budgets
  treated as dead ends must not be introduced: they would let a stuffed subtree starve the honest key out of a
  `Found`.
- **Findings.** `AlgorithmIdMismatch` comes once per presented certificate that `decide` parsed, which at the
  step-2, `PRODUCER_UNKEYABLE` and `MAX_PRESENTED` exits is the leaf only; the parser computes its flag
  after NULL/absent normalisation (none for a certificate read through the §9.2 platform canon whose TBS
  AlgorithmIdentifier is minimal DER), and `decide` derives the finding from that flag. Only `VerifierError` rides on
  the `Walk`; its `oid` is the child's TBS signature OID, `""` when the TBS AlgorithmIdentifier does
  not decode.
  `UnsupportedAlgorithm(oid, PATH, outcomeDepended)` is emitted once per OID in `Walk.unsupportedOids`
  on **every** outcome, with `outcomeDepended = (reason == UNSUPPORTED_ALGORITHM)`; fixture (n) asserts the
  `false` case on a `Found`.
- **PKIX fallback contract** (`PathBuilderFallback`; the fallback re-parses the snapshot's anchors' `getEncoded()` with `CertificateFactory` once per `AnchorSnapshot.id`, memoised with the snapshot's `sha256`, a reused id with another `sha256` being a miss, and its `CollectionCertStore` holds every presented certificate the factory reads): result lists the presented leaf's exact bytes first, each
  intermediate as the bytes presented for it (its `getEncoded()` only for one the builder found elsewhere, through AIA,
  §10 item 13), and **appends the trust anchor's certificate** as the snapshot's bytes read for it
  (`AnchorSnapshot.anchors`), which step 6 matches by exact bytes; the leaf must be in the `CollectionCertStore`, and a
  leaf the factory rejects, an anchor set none of which it reads, no path (`CertPathBuilderException`), the JDK's
  empty path for a leaf that is itself an anchor, and a result in which an element's issuer is not the next element's
  subject under `X500Principal` equality are null, while a presented intermediate or an anchor it rejects is left out, as webpki and mozilla::pkix skip a candidate that
  does not parse; one base
  `PKIXBuilderParameters` per snapshot, `clone()` per call; `CertPathBuilder.getInstance("PKIX")` per
  call; `setRevocationEnabled(false)`, `setPolicyQualifiersRejected(false)`, `setDate(now)`, every other parameter the
  JDK default as SunJSSE's `PKIXValidator` leaves it (`maxPathLength` 5),
  `X509CertSelector().apply { certificate = leaf }`; Android resolves to ojluni's `SunCertPathBuilder`
  with Conscrypt doing signatures. The builder verifies every link under the platform's providers,
  so its path satisfies the invariant's intent. A returned path must end at the trust anchor's certificate, and meet
  the issuer rules and nameConstraints of "Why this is sound"; decision step 6 checks them again, so a path that does
  not end at an anchor of the index by exact bytes (a builder returning `CertPath.getCertificates()`, which leaves the
  anchor out), holds a certificate that does not parse, fails a rule, or spends the 250,000-comparison bound is a
  failed build, `FallbackNotUsed(FAILED)` (`DecideFallbackTest`). The JDK's builder enforces less: it exempts
  self-issued certificates from `pathLenConstraint` and name constraints, does not apply the anchor certificate's own
  nameConstraints, and does not read a CA's extKeyUsage, so a JDK path through an EKU-limited intermediate is
  refused, as Firefox refuses it. A `verifiedPath` (`EvaluationRequest`, `decideVerified`) is trusted as the platform
  built it: no issuer rule is applied to it; `jdk.certpath.disabledAlgorithms` and provider
  divergence from the delegate fail the build, and like every failed build (null or a throw) are reported as
  `Finding.FallbackNotUsed(FAILED)` and surface as `PLATFORM_ONLY` on a walk `NotFound` at a trust-manager binding.
  It is skipped above `FALLBACK_MAX_PRESENTED` presented certificates (no candidate
  budget; exponential on stuffed chains) with `FallbackNotUsed(SKIPPED)`, which cannot change
  a `Budget` outcome. With `pkixFallback(false)` it never runs, and step 6 reports `FallbackNotUsed(DISABLED)`
  instead.

**Anchor snapshot, built where upki builds its state.** The snapshot (`getAcceptedIssuers()` plus
the `CandidateIndex` build over `platformTrust.anchors(delegate)`, i.e. `getAcceptedIssuers()`, ~10 ms for 140 anchors) exists before any handshake can go past step 1
on the trust manager, **on both platforms and regardless of the calling thread**: built synchronously
inside `start()` for every trust manager created in `CREATED` (the first synchronous step, under the
factory lock, before the registry and the store lock) and at wiring, inside the factory lock,
for a trust manager created in `STARTED`. A throw from `getAcceptedIssuers()`, a null or empty anchor set, a null
anchor, or a set none of whose anchors the parser reads (an index that could only answer `NO_ISSUER`) throws
`IllegalStateException` from `start()` (lifecycle stays `CREATED`, nothing
held, retryable) or from `trustManager(d)` (nothing registered). There is therefore no snapshot
future, no snapshot deadline and no `SNAPSHOT_UNAVAILABLE` verdict reason: a trust manager that can go
past **flow** step 1 has a snapshot (flow step 1 is the platform call; the snapshot id keys the
caches at flow step 2, where the snapshot is read, and decision step 1 consumes it; instances obtained in
`CREATED` before `start()` or in `CLOSED` run flow step 1 only and report null snapshot fields). **Android**: the NSC
`NetworkSecurityTrustManager.getAcceptedIssuers()` is lazy and cached per default config (one per
process) over process-wide directory sources (`DirectoryCertificateSource` lists the system and
user cacerts directories and reads one file per certificate on the first call per process; every
later call clones the cached array; the system clears these caches in every running process by its
own `handleTrustStorageUpdate()` push when the trust store changes, with no app receiver involved,
and revokt registers none), so `start()`, already off the main thread, warms it by building the
pre-start snapshots. `trustManager(d)` on Android runs the delegate's
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
only; refresh is disabled. **Fetches run no revokt trust manager**: the `HttpFetcher` handshakes over the
platform's TLS and trust manager, or its own client's (§4), so revokt's verdicts never gate its own feed, as in
Firefox and upki.

`checkClientTrusted` and `getAcceptedIssuers` delegate to the platform unchanged.

**Moved to design notes** (not normative before 0.3): "Trust managers per delegate" and "Caches"
([trust-managers.md](../design/trust-managers.md)); "Readiness", and the deferred "Read-only mode" and "Storage fallback" (an instance that cannot use its store runs in memory, §3)
([readiness-and-store-modes.md](../design/readiness-and-store-modes.md)); "Listeners"
([listeners.md](../design/listeners.md)); "HTTP/2 coalescing" ([okhttp-and-ktor.md](../design/okhttp-and-ktor.md)).
A reference in this file to one of these names that note.

### 5.2 Android (`AndroidPlatformTrust`)
Not normative before 0.3: [docs/design/android.md](../design/android.md).

### 5.3 JVM (`JvmPlatformTrust`)
- Default delegate: the default `TrustManagerFactory`'s `X509ExtendedTrustManager` (`getDefaultAlgorithm()` over the
  default trust store, the providers in their configured order: SunJSSE's on a stock JDK, as the JDK's own default
  `SSLContext` resolves it), one per `JvmPlatformTrust`. `anchors(d)` is `d.getAcceptedIssuers()`, a null array the
  empty set; `verifiedChain` is null. `requiresExtendedDelegate()` is **true**
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
  own anchor objects' `getEncoded()` and returns an anchor as its bytes read. A certificate whose `getEncoded()` throws
  has no bytes: an anchor is left out of the snapshot.

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
canonicaliser, fallback, exemption, logger, a throwable's `toString`, the engine's
`coverageEndMillis` read at an install) and at the boundary, a caught `InterruptedException` sets the thread's interrupt flag again. The
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
- **No coverage rule at install**: a filter's coverage is compared neither with the changeset's signed `<ts>` nor
  with the live generation's coverage, as neither Firefox nor upki compares them; what installs is decided by the
  rollback guard on the signed `<ts>` alone (§7.1).

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
`MAX_CHANGESET_RECORDS` (1,024) admits a full and 1,023 deltas, about 254 MB at `default`'s 6 MB full and ~242 KB a delta; no per-sync
total caps it, only the count and the per-file caps.

Baseline Profile covering the decoder, seed verification, the TBS parser, the walker and `evaluate`,
with `androidx.profileinstaller` as `api`. `AWAIT_DATA_<CHANNEL>` from a physical ARM device at API
26 without a profile, including the `start()` anchor build, with a ceiling; on the JVM both constants
are a fixed 2 s.

### 6.5 Store, persistence and seeds

**Layout over `RevoktStorage`'s key space.** Every key under `<dataset>/<channel>/` except `current` and
`updater.json` is named by the SHA-256 of its bytes, so a write there writes only the bytes its name promises and
nothing stored is ever changed into something else. **A file's name in a generation** is derived from its
§6.3-validated Remote Settings `attachment.filename`: the filename itself when it is at most 32 bytes (a C2SP filename:
1 to 32 bytes of `[A-Za-z0-9._-]`), otherwise its first 15 characters, `-` and the first 16 lowercase hex characters of
the SHA-256 of the filename's ASCII bytes (not `attachment.hash`), 32 characters in all, since §6.3 admits names of up
to 64 characters and C2SP up to 32. That name is the file's name in `index.bin` and `GenerationFiles.names`, derived
at load from the records; no key is named after an attachment. A seed's `attachments/<f>` entry keeps the attachment
filename f, is looked up by it (Seed archive, below) and is mapped by this rule at load. Two attachments that map to
one name fail the generation before any body is fetched: `SyncOutcome.FAILED` with `INDEX_INCONSISTENT`, and
`SEED_UNREADABLE` for a seed (`buildIndex` refuses it). 0.2's in-memory store keeps its generation directories with
`meta.json` until this layout replaces them in 0.3; no stored data depends on them. Path segments for dataset and
channel are lowercase enum names; persisted enum values are names, never ordinals:
- `store.version`: integer, `1` in 0.3, read before anything else, after the open's temp sweep (§3); the file holds
  ASCII decimal `[1-9][0-9]{0,8}` and nothing else, no newline (`StoreVersionTest`, `StoreVersionFuzzTest`); an empty
  store (its root holds no entry other than `.lock` and temp files) is initialised silently with `1`; a non-empty store
  with no `store.version` is not taken for a revokt store, since the root is the caller's directory: `STORE_UNREADABLE`,
  the instance runs in memory and the store is left untouched, as for one that does not parse or a read that throws
  (`StoreOpenTest`); a store with a **lower** version is rebuilt
  (`STORE_MIGRATED` warning, a planned migration, not a corruption alert, `storeFailures` unchanged; the rebuild deletes every key `names()` lists other than `store.version`, then writes `store.version`, then runs the start task as on an empty store, so no old-layout `current` or `updater.json` ever sits under the new version, and a rebuild that fails or is interrupted keeps the old version and runs again at the next start; a delete or write of the rebuild that throws is `STORE_UNREADABLE`; `StoreOpenTest`), never an error and never `NO_DATA` beyond what an
  empty store already implies; a **higher** version is `STORE_NEWER_LAYOUT` and follows the storage's `NewerLayout` (§3): `IN_MEMORY` (the `JvmStorage` default: a newer co-tenant's store is left untouched, the store lock taken by `start()` is released, the identity deregistered, and the instance runs on `inMemory()` for the life of the process, `RevoktState.storageFallback`, never retried, §3) or `REBUILD` (the `AndroidStorage` default: one package owns its directory and Android kills every process of the package on replace, so a higher version there is a rollback of the binary and is rebuilt exactly as a lower one); both arms `StoreOpenTest`, the fallback's in-memory install `CrliteRuntimeStoreTest`.
- `<dataset>/<channel>/blobs/<sha256>` (64 lowercase hex): every attachment, full or delta, under the SHA-256 its
  signed record gives, re-hashed against its key on every read. An install reuses a stored blob that re-hashes and
  rewrites one that does not with the verified bytes (`storeFailures++`), so a daily delta install writes only its new
  deltas and a bit-rotted blob is never decoded (`StoreLayoutTest`, `CrliteDeltaSyncTest`, `StoreModelTest`'s I6).
- `<dataset>/<channel>/generations/<sha256>` (64 lowercase hex): the **generation file**, one per generation, named by
  the SHA-256 of its own bytes and re-hashed against its name on every read (`GenerationFileTest`,
  `GenerationFileFuzzTest`). It is a JSON object in the engine's canonical encoding, read strictly, and only when its
  bytes are exactly the canonical encoding of what it decodes to (no other member, none twice, no whitespace, keys in
  order), so a change to the canonical encoder's output makes stored generation files unreadable and needs a
  `store.version` bump: `generationVersion` (`1`), `dataset`, `channel`,
  `freshness`, `seedFormat` (present exactly when `freshness` is `SEED_SIGNED_TIME`), `signature` (lowercase hex of the
  raw r‖s pair that verified, any non-empty even length, §7.1), `signerLeafSha256` (lowercase hex), and `records`, the
  verified collection payload `{"data": every channel's records sorted by id, tombstones removed, "last_modified":
  "<ts>"}`, whose canonical serialisation is the signed bytes (the seed's `records.json`). The rest is derived from
  `records` and the channel at load and never stored: the placed filters and their names, each blob's hash
  (`attachment.hash`), `generationId` (`"<ts>/<last placed record id>"`), `sourceTimestampMillis` (`<ts>`) and
  `format` (the full filter's encoding, read from its blob; each filter is read in its own, so a channel may mix
  encodings, as Firefox's cert_storage and upki allow). A `channel` mismatch, or a `generationVersion` this binary does
  not read, is no generation. Identical inputs give identical bytes and so the same name: an install of a generation
  already stored writes no new file, while a collection re-signed under one `<ts>`, or a seed and a sync of one `<ts>`,
  gives another file. **The size cap** is the configured `maxJsonBytes` plus 64 KiB, checked before the write and at
  every read. An install whose file is over it is `FAILED` with `STORE_FAILED` before the file is written,
  `storeFailures++`, logged at `WARN` naming `maxJsonBytes`, and retried under backoff until the cap is raised; the cap
  at read is the reading process's, so a file written under a higher cap than a later process's is a failed load
  there. A `_since` changeset is merged over the served generation's `records`; the whole collection, fetched with no
  `_since`, is verified as served.
- `<dataset>/<channel>/current`: the pointer `{"live": <name>, "previous": <name>}`, each a generation file's name,
  read strictly: a JSON object of `live` and an optional `previous` and no other member, anything else being
  malformed. It is written last in an install, only to a generation this process has loaded back, and it is the one
  write that makes a generation live. A damaged name fails the strict read or names a key that no stored file hashes
  to, so the pointer has no checksum of its own; an intact but stale `current` (restored from a backup, or a write the
  storage acknowledged and lost) serves its older generation until the next install, under the floor of §7.1.
  `previous` is only ever a generation that passes Load's steps 1 to 3 (below), so recovery never falls to one that
  cannot load; a candidate that does not counts a store failure. **The new `previous` is the first candidate other
  than the new `live` that passes of: the generation the engine served before the install, then the old `live`, then
  the old `previous`**, each read once. Served first, so a flip that failed after activation, which left the engine
  serving a generation `current` does not name, never loses it to the next prune. When an install flips beside a
  malformed pointer, its only candidate is the generation the engine served; a fresh loader has no `previous`
  (`InstallTest`, `CrliteDeltaBaseTest`, `StoreModelTest`'s I1 and I2).
- `<dataset>/<channel>/updater.json`: **the rollback watermark is per dataset and channel, stored once outside the per-source map** (while a generation is live the floor is the higher of the watermark and the live generation's timestamp, §7.1, so a malformed file, whose dataset-level members are read as absent and count a store failure, reopens no rollback; with no generation loaded, none stored or every stored one absent or malformed and never a read that threw, the watermark is not read, and the install sets it to its `<ts>`) together with `seedInstalledAtMillis` (written with the watermark when the seed install flips the pointer) and a dataset-level `datasetLastAttemptAtMillis` (written at the end of every sync whatever its outcome, except a sync whose read of
  `updater.json` threw, which writes nothing; the §8 `STALE` gate; the loader evaluates the gate when it writes this file and carries the boolean in the published `DataState`, internal field, so handshakes read the snapshot only, never the store) (while a generation is live, a changeset installs only if its timestamp passes the dataset watermark, whichever source delivered it, so a relabelled `sourceId` on a private mirror cannot start a fresh watermark and roll back); the per-source map is keyed by a **stable source id** (not the URL, so overriding a
  base URL keeps the cursor): `lastVerifiedLastModified` (the cursor; `_since` is the served generation's own `<ts>`, §7.1),
  `lastVerifiedAtMillis`, `lastAttemptAtMillis`, `backoffUntilMillis` (clamped to now + `MAX_BACKOFF` on write and again on read, so a clock that was far ahead at write time cannot leave a years-long backoff),
  `consecutiveFailures`; written atomically. A sync whose read of `updater.json` throws
  writes nothing to it: no attempt is recorded, `consecutiveFailures` does not rise and no backoff is written;
  `storeFailures` is the only persisted signal (the sync still returns `STORE_FAILED`). **The cursor, `lastVerified*`
  and the watermark advance only after the pointer flip of a successful install**, or in a repair at that install's
  `<ts>`; a failure-path write (`consecutiveFailures`, `backoffUntilMillis`) leaves those three untouched. `UNCHANGED`
  against the served generation, when the file's cursor or watermark is behind `<ts>`, rewrites it as the install of
  `<ts>` does, from a changeset that verified (no `If-None-Match` is sent then, §7.1; repairing a crash between flip
  and write; `StoreCrashTest` row 4); otherwise `UNCHANGED` writes only the
  attempt fields, the `consecutiveFailures` reset and the backoff headers' effect (§7.1). The
  delta base and parent are the served generation's file, read through Load at each sync, never this file;
  when it does not load, the sync fetches the whole collection, `storeFailures++`.

**Load** (one function for the `start()` recovery chain, an install's load-back and the adopt scan). To load the
generation `H`:
1. read `generations/H`, check the size cap, re-hash it against `H` and parse it, with this dataset and channel and a
   `generationVersion` this binary reads;
2. schema-check `records` for the channel (`CrliteSchema`, capped at `MAX_CHANGESET_RECORDS`) and place the filters
   (`buildIndex`'s placement, Seed archive below);
3. read each placed filter's blob and re-hash it against its record's `attachment.hash`;
4. rebuild `index.bin` with `buildIndex` (≤ 1 MiB, §3.2) and build `GenerationFiles` under the derived names.

Any failure is a failed load, counted once (`storeFailures++`; `StoreLoadTest`). Steps 1 and 3 make what a load returns (the
`GenerationFiles` handed to `prepare`, the `records` used as a delta base) byte-equal to a generation file and blobs
written from verified data: without step 1, a flipped byte inside `records` that still parses could drop a delta, and
its revocations, silently. **The store is trusted at the OS level**: a load does not re-verify the signature (the seed
is verified, since it ships inside the artifact, and so is a generation the adopt scan adopts, below); `JvmStorage`
enforces ownership and owner-only write permission on POSIX, a temp file sits in its key's directory, named by the key's last segment, `~` and
32 random hex digits; `~` is outside the key alphabet, so no temp name is a key and `names()` never lists one; no symbolic link below the store's real root is
followed, and one in a key's path fails closed (§3), and only the lock holder reads or writes the store.
**Order of an install** (an *install* anywhere in this document means this whole sequence): the bodies, **one at a
time** (for each placed attachment a stored blob that re-hashes is reused; otherwise the body is fetched, or read from
the seed archive, hashed against its signed record, written and dropped) → build `index.bin` (≤ 1 MiB, §3.2) → the
format check (on every placed filter, the full and each delta, each in its own encoding; a filter whose encoding the
engine does not list fails the install, `FAILED` with `FORMAT_UNSUPPORTED`, §3.2, the previous generation stays live,
and nothing is offered to `prepare`) → write the generation file (the cap first; not written again when its key holds a
file that re-hashes) → load it back (Load's steps 1 and 3, keeping the `index.bin` just built, which derives from the
same records and the same re-hashed bytes) → `prepared = engine.prepare(files)` (validates and decodes into an
inactive state, the install's only decode of the filters, while the `index.bin` build before it decodes each for its
coverage; the live generation is untouched; a throw is `SyncOutcome.FAILED` with `ENGINE_FAILED`, `prepared` is never
activated, `storeFailures++`, and the engine and the published snapshot are untouched; the same holds for every
`prepare`, the seed's and the `start()` recovery chain's included, where a failure is the corresponding load failure,
`SEED_UNREADABLE` for the seed; the loader never queries the prepared state: test-plan.md §9.3's engine probes check
each engine's answers in CI instead) → `engine.activate(prepared)` → publish the generation snapshot with that id
(`generationEpoch++`; the window between `activate` and publish, i.e. between install and publish is stated: a verdict
in it carries the new answer under the old epoch for at most the verdict-cache TTL) → flip the pointer → write
`updater.json` → prune (below) (`InstallTest`, its order trace). **A failed install deletes nothing**: its blobs, and its generation file when written,
are named by no pointer, so the next attempt reuses them by name (a changeset retried under backoff is the common
case) and the next prune deletes what stays unnamed (`InstallTest`, `StoreCrashTest`). The loader keeps the name of
the generation the engine serves beside the snapshot. **The re-flip**: a sync whose verified `<ts>` is the served
generation's (`UNCHANGED`) while `current` does not name that generation as `live` (a flip that failed after
activation, or a pointer that does not read) flips `current` to `{live: the served file, previous: per the candidate
rule above}`, once the served file and its blobs pass Load's steps 1 to 3, with no fetch, no `prepare` and no publish;
a `current` whose `live` is newer than the served generation and passes Load's steps 1 and 2 (one the start task fell
back from) is left as it is, so a re-flip never moves the pointer back (`CrliteSyncFailureTest`).
Else the **heal-install** installs the collection as served, reusing every stored blob and file that re-hashes
(Firefox re-imports a full changeset alike, Appendix A); its publish keeps the served `generationId`. Both are store
repairs that stay `UNCHANGED` (the served generation does not change) and write `updater.json` as the install of that
`<ts>` does (cursor, `lastVerified*` and watermark at `<ts>`), and heal flips: no prune follows
(`CrliteSyncFailureTest`'s re-flip cases assert `UNCHANGED`; `CrliteDeltaBaseTest`, `StoreModelTest`'s I2). A repair
that fails is `FAILED` with its failure, as an install's is. A sync-time `prepare()`/`activate()` throw increments `storeFailures` and is `SyncOutcome.FAILED`
with `ENGINE_FAILED` (cursor and watermark do not advance, so the same changeset is retried under backoff); a store
write or pointer-flip failure during an install is `FAILED` with `STORE_FAILED` (`storeFailures++`). Decision step 7
never queries an engine for a dataset whose snapshot has no generation; `CrliteQueryResult.NO_DATA` from an engine
while the snapshot holds a generation for that dataset is reported as `ENGINE_ERROR(ENGINE)`, never as nothing, so an
injected engine's install failure is visible, not silent (in `DEFAULT` it allows, loudly). **Every loader task catches
`Throwable`**: an `OutOfMemoryError` during an install is `SyncOutcome.FAILED` for that sync, `storeFailures++`;
nothing escapes the loader thread.
**Prune** keeps the generation files the pointer names, every generation file newer than its `live` that passes
Load's steps 1 and 2 (an install interrupted before its flip, when an older one installed afterwards with no
generation loaded, §7.1), and the blobs those files name; it deletes every other key under `generations/` and
`blobs/`, generation files first (the reverse of the write order, so that while deletes keep their order every
generation file on disk names only blobs on disk). It runs only as the last step of an `INSTALLED` sync install (the
air-gapped `sync()` of a replaced seed included, §4) whose pointer read `Found` before the install, with every
generation it named passing Load's steps 1 and 2; never after a failed install, after a flip that healed a malformed
pointer, after any seed load at `start()`, or at `start()` itself, where the only unnamed keys are those an
interrupted install left for the next sync to reuse. It deletes nothing, with `storeFailures++` and a `WARN`, unless
the pointer then reads back as the install's `live` with every generation it names passing Load's steps 1 and 2, and
nothing, likewise, when any read it makes throws (`names()`, `current`, or any generation file, a newer one's included),
since every read comes before its first delete, while a file that reads and fails Load's steps 1 and 2 stays
deletable; a blob that fails its re-hash does not stop it, since its name is known and kept, and the next install
rewrites it (`StoreLoadTest`; `StoreModelTest`'s I2, I7 and I8, its throw at the n-th storage operation landing on
prune's reads). So
nothing is deleted beside a pointer, or a pointed generation, that does not read, where upki deletes beside an old
manifest it cannot read and Firefox clears local data that does not verify (DIVERGENCES T2). Deletes need no
durability: a key a crash brings back is named by no pointer and goes at the next prune. One loader dispatcher runs
every install, the seed load and prune, so no prune falls between an install's first write and its flip; the engine
never reads the store after `prepare` (§6.4: no mmap), so deleting a served generation's keys cannot break serving.
**Crash recovery at `start()`**: `live` → `previous` → seed (per the §5.1 rule and the seed-load rule, below) →
nothing, each failure counted once (`StoreCrashTest`, one test per crash point; `StoreModelTest`'s I1). The chain decides on Load's step 1, each candidate's `<ts>` against the seed's, and
loads in full only the generation it serves, falling down the chain when that load fails; a stored generation older
than the seed is therefore not decoded at `start()`, and damage to it is counted only when the seed's install reads
it as a `previous` candidate. A blob or generation file is durable before the pointer names it, and only prune
deletes, so a `current` that reads names a generation whose file and blobs are on disk; only damage breaks that, and
the load then falls down the chain. Install-time memory peak
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

**Seed archive** (`revokt-seed-<channel>`, weekly; **shipped by default**: `SeedSource.bundled()`, the builder default, resolves `/revokt/seed-<channel>.zip` from that artifact's jar on the classpath, which an app bundles in 0.2 (a GitHub release asset, §7.2), and the OkHttp and Android quickstarts say so): a zip with `seed.json` {`seedFormat`, `channel`,
`dataset`, `filterFormat`, `recordsLastModified`, `engineFloor`}, `records.json` (byte-for-byte the canonical-JSON signed payload `{"data": records sorted by id, tombstones removed, "last_modified": "<ts>"}`, so the seed verifier hashes the file unchanged; the `<ts>` inside it, verified, is the seed's timestamp for every rule below, the unsigned `seed.json.recordsLastModified` being a hint for the header read only), `signature` (the `signature` field as served, of the `metadata.signatures[]` entry that verified when the seed was
built, whose `x5u` body is `x5u.pem`: unpadded base64url of the raw r‖s pair, any non-empty even length, a
wrong-size pair failing verification, §7.1; for today's P-384 leaf the 128-character text of 96 bytes), `x5u.pem` (the x5u body as served, leaf first), `attachments/<f>`, `index.bin` (produced by one engine function `buildIndex(records, channel)` with entries ordered by `(effectiveTimestamp, record id)`, full before deltas; it places exactly the channel's one full filter, a channel with none or more than one being refused
(`SyncOutcome.FAILED` with `INDEX_INCONSISTENT`, or `SEED_UNREADABLE` for a seed; the previous generation
stays live), plus every delta of the channel, ordered by time, without reading `parent`, as Firefox does (upki-mirror walks the `parent` chain instead, Appendix A; an extra delta can only add
revocations, so the rule fails closed); a placed filter that does not decode is `FAILED` with `FILTER_UNREADABLE`; its
output bytes are frozen per `seedFormat`, a change bumps `seedFormat`, which is what makes the load-time byte compare valid across minors; the weekly job calls that function from the oldest supported minor). **Entry names** (a zip entry's name is outside the signature): the loader never derives a name or a path from a zip entry. It accepts exactly the fixed entries `seed.json`, `records.json`, `signature`, `x5u.pem` and `index.bin`, plus `attachments/<f>` for each §6.3-checked `attachment.filename` f of a record in the verified `records.json` that `buildIndex(records, channel)` places in the generation, and reads each entry by that exact name. The entries are the zip's central directory: every read goes through a central-directory entry whose local header names the same file, and the first entry is `seed.json`; otherwise the seed is `SEED_UNREADABLE`. A duplicate, extra or missing entry is `SEED_UNREADABLE`; an entry that differs from an expected name only in letter case is an extra entry, and so is a directory entry. The fixed entries are checked before any entry but `seed.json` is read, and at that check every name that is neither a fixed entry nor under `attachments/` is already extra; the attachment entries are checked once `records.json` is verified and before any of them is inflated. **Entry caps, enforced while inflating** (zip-declared sizes are untrusted; `fromResource`/`fromPath`/`of` accept any file, and the sole-seed `ENFORCE` path inflates inside `start()`, where an `OutOfMemoryError` would crash-loop an app): `records.json` ≤ `MAX_JSON_BYTES`, `x5u.pem` ≤ `MAX_X5U_BYTES`, each attachment ≤ `min(signed size, MAX_FILTER_BYTES)`, `index.bin` ≤ 1 MiB, `seed.json` ≤ 64 KiB, `signature` ≤ 64 KiB, and the whole archive ≤ 256 MiB (`SeedArchive.MAX_BYTES`: a channel at today's sizes, a 6 MB full and deltas of about 242 KB, holds about 254 MB even at the full `MAX_CHANGESET_RECORDS` of 1,024 records, and a real seed is far below that; the cap is what makes a source that never ends fail closed, and a larger archive is refused whole, never truncated or partly read); over any cap → `SEED_UNREADABLE`, never a store failure (§10 supply chain; `SeedArchiveTest`, `SeedLoaderTest`). **The zip the loader reads** (`SeedArchiveTest`, `SeedArchiveFuzzTest`): one disk, no zip64, an end record with no comment as the archive's last bytes, right after a central directory of at most 1 MiB and at most 5 + `MAX_CHANGESET_RECORDS` entries; each entry stored or deflated, never encrypted, its local header naming the same file with the same method and flags (and, without a data descriptor, the same CRC-32 and sizes), its data ending before the central directory, no two entries overlapping, and each inflating to exactly its declared size and CRC-32; anything else is `SEED_UNREADABLE`. The source is re-opened for each read (the central directory, `seed.json`, the fixed entries, the attachments), and each read must find the same size and central directory, else `SEED_UNREADABLE`. **`seed.json`** is a JSON object whose `seedFormat`, `recordsLastModified` and `engineFloor` are integers and whose `channel`, `dataset` and `filterFormat` are enum names (`"COMPAT"`, `"CRLITE"`, `"V3"`), other members ignored; `seedFormat` must be 1, and an `engineFloor` above the engine's level (1) is unreadable (`SeedHeaderTest`, `SeedLoaderTest`). `records.json` must be the canonical payload of its own records and `<ts>`; every placed filter's encoding must be listed by the engine, and `filterFormat` must name the full filter's decoded encoding (a delta may be in another listed encoding, `SeedLoaderTest`); each is `SEED_UNREADABLE` otherwise. The seed's generation id is `"<ts>/<last placed record id>"`, a sync's shape. Engine rules: `seedFormat` or
`engineFloor` above what this engine supports, or `filterFormat ∉ revocationEngine.formats`, → `SEED_UNREADABLE` warning and the seed is ignored (so in the sole-seed `ENFORCE` configuration `start()` throws, §4 S bullet); **a seed whose signed timestamp is ahead of the local clock installs like any other** (the timestamp is Mozilla-signed and its x5u checks run at that signed time, so "future" can only mean the local clock is behind; no rule on signed data reads the local clock, §7.1), with `ageMillis` clamped at 0 and the watermark set as for any seed;
`channel` ≠ configured channel → `SEED_CHANNEL_MISMATCH` `ERROR` thrown by `start()`; the shipped
`index.bin` is **rebuilt from `records.json` and byte-compared** at load (the signature binds records
and attachment hashes, not parentage), a mismatch → `SEED_UNREADABLE`; the weekly job publishes
every `seedFormat` the oldest supported minor lists, in the filter format Mozilla signs.
**The writer** (`buildSeed` and the job's core `SeedJob`, internal to revokt-engine; `SeedWriterTest`): the entries in
the order `seed.json`, `records.json`, `signature`, `x5u.pem`, `index.bin`, then `attachments/<f>` in placement order;
`seed.json` stored (the reader accepts it deflated too) and every other entry raw deflate at level 9; each entry dated
1980-02-01 00:00, with flags 0, no extra field, no comment and no data descriptor; `seed.json` compact JSON with its
members in the order listed above and `filterFormat` the full filter's decoded encoding (a delta may be in another
encoding the engine lists, as a sync installs it). It refuses whatever the loader would refuse. The job fetches and
verifies as a sync verifies the whole collection (`monitor/changes`, the changeset with no `_since`, the server root's
attachment base, each placed attachment by size and SHA-256), loads the archive once from memory under the source's
pins, and only then writes it, through a temporary file moved into place. One changeset gives one archive on the same
Temurin 21 build, whose zlib deflates it; the weekly job pins that build and records it in its attestation.
**Seed-load rule** (the seed always leaves a live generation behind; `SeedLoaderTest`, `SeedLoaderStoreTest`,
`SeedAdoptTest`). The store is read first: a read that throws fails the load with nothing written (`STORE_FAILED`); a
malformed `updater.json` reads as absent. Each store fault is counted once, where it is found. A seed load at
`start()` never prunes and never deletes.
- **(a) A trustworthy pointer**: `current` reads, its `live` passes Load's steps 1 and 2, and, when it is not older
  than the seed's `<ts>`, it loads. When the generation the engine serves is not older than the seed, the seed is
  skipped and nothing is written. Otherwise the seed installs.
- **(b) Anything else** (no pointer, a malformed one, or a `live` that does not load): **the adopt scan**. Every key
  under `generations/` whose last segment is 64 lowercase hex characters goes through Load's step 1, and a file that
  fails it counts one store failure, unless the same start already counted it (a `live` or `previous` the chain failed
  to load is passed over, never counted twice). The candidates are the files whose `<ts>` is newer than the seed's and not older
  than the generation the engine serves, the `previous` the chain fell back to apart (it stays
  served, and the scan passes over it without counting it); from the newest down, ties broken by name, each runs Load's steps 2 to 4 and,
  when its `signerLeafSha256` is the SHA-256 of the seed's verified leaf, its `signature` must verify over the
  canonical serialisation of its `records` (a generation signed by another leaf is trusted at the OS level, as every
  stored generation is). The first that passes is adopted: `updater.json` is written from the record read (an absent or
  malformed one replaced) with its watermark raised to max(the stored watermark, the adopted `<ts>`), then `current` is
  flipped to `{live: <it>}`; nothing else is written, and the seed is not installed. Each candidate that fails counts
  one store failure; a file not newer than the seed is not counted. With none to adopt, a generation the engine serves
  that is newer than the seed (or, for the `previous` the chain fell back to, not older) is kept and the seed skipped. Otherwise the seed installs, reusing every stored blob that
  re-hashes, and its flip heals the pointer (`SeedAdoptTest`, `CrliteRuntimeStartTest`, `StoreModelTest`'s I10).
- A seed's install writes `updater.json` in its own write with `seedInstalledAtMillis` and the watermark: beside a
  loaded generation (a trustworthy pointer, or one the engine serves) the higher of the stored watermark and the seed's
  `<ts>`; with none loaded the seed's `<ts>`, lowered if the stored one was higher, as Firefox's floor after a dump
  import is the dump's timestamp (§7.1).

`DataState.fromSeed`, `ageMillis`, `stale` and `seedFormat` are loud. **Seed artifacts declare no code dependency** (in 0.2 they have no POM at all, §7.2): the floor lives in `seed.json` (`engineFloor`, enforced at load as above). A POM dependency would let a seed bump drag `revokt-engine` above the BOM-pinned bindings (Gradle resolves the highest version; BOM constraints are not strict) and the `@RevoktInternalApi` plumbing between artifacts carries no compatibility promise; instead every code artifact's Gradle module metadata depends on `revokt-bom` as an aligning platform, so a single-artifact bump aligns the set.

## 7. Data sources

| Sources | Integrity | Authenticity |
|---|---|---|
| Mozilla Remote Settings (CRLite [M1]; intermediates, OneCRL [M2]; ct-logs [M3]; root-store distrust-after dates and CCADB export [M4]); Chrome CRLSet [M2]; seeds [M1] | signed record hash / CRX proof | Mozilla content-signature roots / Google CRX key |
| denylist artifact [M2] | reproducible from signed public inputs, attested | project-attested, availability-only |

### 7.1 Mozilla Remote Settings protocol and verification [M1]
All constants live in `MozillaRemoteSettings` (per source, overridable), including the pinned root
SPKI hash set and the three fields read from each `metadata.signatures[]` entry (`signature`, `x5u`, `mode`). `MozillaRemoteSettings.Builder` exposes `baseUrl`, `attachmentBaseUrl` and `allowedDomains` (§4). **Hosts:** `allowedDomains` (default `cdn.mozilla.net`, Mozilla's CDN) governs every host revokt takes from unsigned input: a host is allowed when it equals a domain or ends with `.` and a domain, on a label boundary, so `evilcdn.mozilla.net` is not; domains and rewrite targets are compared exactly, ASCII case included. It applies to an `x5u` host after the rewrite and to the server's attachment base. Firefox checks neither host; the rule stays because the server root response is unsigned, and it is what keeps a compromised settings host from pointing clients at arbitrary hosts, while integrity rests on the pinned root and the signed hashes. **The attachment base:** `attachmentBaseUrl` is null by default, and the base is then the server root's `capabilities.attachments.base_url`, as Firefox reads it: `GET <baseUrl>/` once per sync, only before the first attachment the sync fetches (a sync that fetches none makes no such request), under `MAX_JSON_BYTES`, never persisted. The value must be a string read by the x5u URL grammar below (`https://` in lowercase, no userinfo, a DNS host name, no port or port 443), with no path or a path of `pchar`s and `/` and no query or fragment, and a host `allowedDomains` allows; Mozilla's is `https://firefox-settings-attachments.cdn.mozilla.net/` (Appendix A). Anything else, a failed fetch included, is `SyncOutcome.FAILED` with `ATTACHMENT_BASE`, a feed failure that advances nothing, with no fallback to a built-in URL. A configured `attachmentBaseUrl` pins the base: it is not fetched and not checked against `allowedDomains`. **a private mirror that serves the changeset, attachment and x5u bytes unchanged (a byte-for-byte reverse proxy of the three Mozilla hosts) with the builder's `baseUrl` and a pinned `attachmentBaseUrl` pointing at it, `allowedDomains` holding the mirror host, and `x5uHostRewrite("content-signature-2.cdn.mozilla.net", mirrorHost)` (`attachment.location` is relative, so `attachmentBaseUrl` suffices, and pinned because a byte-for-byte proxy serves Mozilla's `base_url`; the rewrite is applied to the parsed x5u URI host before the `allowedDomains` check, so no JSON is rewritten on the wire; x5u is outside the signed payload; the https-only, port-443 and no-userinfo rules apply to the mirror host too), verifies and installs as `SIGNED` under the default `sourceId`, so the delta path carries over (`_since` is the served generation's own `<ts>`, §7.1, and the watermark is per dataset and channel and carries over whatever the `sourceId`, §6.5); this is the supported offline-fleet path** (`c2spMirror` is bootstrap-only and never updates a seeded client, §7.3). Base `https://firefox.settings.services.mozilla.com/v1` (the Kinto API, Firefox's own `services.settings.server`; `/v2`, a distinct newer server that was hours old at verification, serves the same changeset shape and is the documented alternative value of `MozillaRemoteSettings.baseUrl`; both verified 2026-10-22, Appendix A);
only `monitor/changes` and per-collection `changeset`; `_expected` mandatory; a delta poll sends `_since=<ts>`
bare in the changeset query, as Firefox does, where `<ts>` is the served
generation's own, read from the file that is the merge base (§6.5), **only while that file loads, its `<ts>` is the live
generation's `sourceTimestampMillis`, and the pointer names it as `live`**, and otherwise fetches the whole collection
(beside a pointer that does not name the served generation, a flip that failed or a malformed pointer, the whole
collection's `UNCHANGED` re-flips or heal-installs it, §6.5); the `updater.json` cursor is never sent, so after a
fallback (the seed or `previous` live while the cursor names a newer generation) a 304 speaks for the generation served,
and the first sync after a seed install is a delta from the seed's `<ts>` (`CrliteRuntimePollTest` "after a seed
fallback the seed's ts is sent, never the cursor", "the first sync after a seed install sends the seed's ts with no
If-None-Match", "a served file whose ts is not the snapshot's sends no _since"); the quoted `If-None-Match: "<ts>"` (§3)
is sent beside it only while `updater.json`'s cursor and watermark are at or past `<ts>`, so an unsigned 304 never stands
in for §6.5's repair, which an `UNCHANGED` writes only from a changeset that verified (`CrliteDeltaSyncTest` "a cursor
older than the live generation sends its ts with no If-None-Match", `CrliteDeltaBaseTest` "with no cursor the served ts
is sent with no If-None-Match", `StoreCrashTest` row 4); Firefox's `_since` is its local data's own timestamp, the
dump's after a dump import, and upki sends `If-Modified-Since` only when its local manifest reads (Appendix A);
`User-Agent`; gzip;
honour `Backoff` and `Retry-After` up to `MAX_BACKOFF` (24 h; transport headers are unsigned), on every response, 2xx included (revokt's own rule, stricter than Firefox, which keeps `Backoff` only from a `/changes` response that is not a server error and carries the expected JSON, and never reads `Retry-After`; Appendix A): a response with such a header waits the header, a failure too even when that is shorter than its computed backoff; a success without one clears `backoffUntilMillis`; a failure without one waits the computed failure backoff, 15 min × 2^(n − 1) for the n-th consecutive feed failure, capped at the 6 h poll interval; poll at most every 6 h with jitter: `POLL_INTERVAL` plus a jitter in `[0, POLL_JITTER)`
after a poll that did not fail, while a failure waits its backoff, which may be shorter (§5.1 "The sync schedule"); no
wait between two syncs is shorter than `MIN_POLL_DELAY` (60 s), so a `503` with `Retry-After: 0` cannot loop the loader
(Firefox's update timer waits at least 120 s between two fires, Appendix A; `PollScheduleTest` "every delay is between
60 s and 24 h, so a Retry-After of 0 cannot loop the loader"). **Feed failures**: every `FAILED` sync, whatever its `SyncFailure` (`FORMAT_UNSUPPORTED`, which a placed full or delta in an encoding the engine does not list gives, the previous generation staying live (§6.5), `CLOCK_SKEW` and `STORE_FAILED` included), advances `consecutiveFailures` and takes the failure backoff, except a `STORE_FAILED` sync whose read of `updater.json` threw, which writes nothing (§6.5); a `SKIPPED` sync is not a feed failure: `ROLLBACK_REFUSED` and `BACKOFF` leave the count unchanged; every successful poll resets it to 0: `INSTALLED` and `UNCHANGED`, by a 304 or by a timestamp match. **Verify** every collection
state (`"Content-Signature:\0"` + canonical JSON of `{"data": records sorted by id (deleted removed),
"last_modified": "<ts>"}`; merge `_since` tombstones first; reset-and-retry once, as Firefox retries an `InvalidSignatureError` from scratch (Appendix A): a `_since` changeset whose changes do not merge with the stored records (a change with no string `id`), or whose last tried entry fails the content signature, or that has no entry to try (`metadata.signatures` empty, every entry skipped, or a `null` element reached), is fetched once more as the whole collection, which must verify, and an x5u failure (its fetch, PEM, chain or validity) is never retried, since the sync holds one x5u result per URL and the retry would fail the same way; the whole collection is never fetched twice; canonical JSON per `canonical_json` 0.7.0 escape rules, over integers only: a number is an integer within `u64` (or `i64` when negative, `-0` excluded), as serde_json classifies it, and any other number (a fraction, an exponent, or an integer outside that range) has no canonical form, so a payload holding one is refused (`RECORDS`: `FAILED` with `SIGNATURE_INVALID`) and never serialised; a record's `deleted` reads such a number as zero exactly when every mantissa digit is `0`; pinned by the §9 differential test; the `signature` field is unpadded base64url of the raw pair r‖s, two equal halves of any non-empty even length (a pair of the wrong size for the leaf's key fails verification), the leaf on any EC curve the floor admits (Firefox parity; P-384 today), converted to DER and verified as `SHA384withECDSA`). **`<ts>`** is the value the verified payload was built from: a live sync builds it from the changeset envelope's `timestamp`, as Firefox's `RemoteSettingsClient` does, so that value is signed exactly when verification succeeds; a seed's is the one inside `records.json`. The unsigned value is `monitor/changes`' `last_modified`, used only as `_expected`. **`metadata.signatures[]` is read, as Firefox reads it**: the array must be non-empty; the first 4 entries are tried, in array order, and any after them are never read (Firefox tries every entry; the cap bounds the `x5u` fetches one changeset can cause); a changeset with no entry tried (every entry skipped, for example for a missing `signature`) is `SyncOutcome.FAILED` with `NO_SIGNATURE`, since it concerns signature metadata, not records; so is a JSON `null` element that the loop reaches, as Firefox's destructuring throws on it (an earlier entry that verifies is accepted first); each tried entry's `x5u` is fetched and validated under the pinned chain (§7.1 "x5u chain"), an `x5u` URL already fetched and validated in the same sync being reused, not fetched again, and one whose fetch or validation failed not being retried by a later entry in the same sync; the first entry that verifies is accepted, and the records installed are exactly the records it verified, at the `<ts>` it verified; an entry with no `signature` or `x5u`, an empty string included (Firefox's `!x5u || !signature`), or whose `mode` is present and not the string `p384ecdsa`, is skipped (an absent or `null` `mode` is tried, as Firefox's `mode && mode !== "p384ecdsa"` reads it; a non-string or `""` `mode`, which Firefox tries when it is falsy, is skipped: revokt verifies P-384 only, so an unknown mode gains nothing); any failure of a tried entry, a failed `x5u` fetch included, moves on to the next entry (Firefox leaves the loop when the fetch itself is rejected, Appendix A); when none verifies, the last tried entry's failure is the outcome (Firefox throws its first error): a failed `x5u` fetch is `X5U_FETCH` (and an x5u URL the rules below refuse `X5U_URL`), a validity failure `CLOCK_SKEW`, every other PEM or chain failure (`NOT_PINNED`, `EKU` and `SAN` included) `X5U_CHAIN`, and a content-signature failure `SIGNATURE_INVALID`, each `FAILED`; `metadata.signature` is not read (Appendix A). **The signed
payload does not bind the collection id**, and every security-state collection shares a signer, so
before any state change every record is schema-validated for the requested collection (CRLite:
`channel`, `incremental`, `attachment.{filename,hash,size,location}` (the filename under §6.3's rule), `effectiveTimestamp`, and `parent` on deltas only, since live full records carry none; M2
schemas likewise); a verified changeset whose records fail validation is `SyncOutcome.FAILED` with
`SCHEMA_REJECTED`, counts as a feed failure, and advances nothing. Redirects are never followed. **JSON**: the
engine's own tree and tokenizer; duplicate keys and unpaired surrogates rejected; keys sorted by code
point. **Content signature**: each entry's `mode` is read, and an entry is tried when it is absent, `null` or `p384ecdsa`; the algorithm is never derived from it. **x5u chain**: the body is
read as `rustls-pki-types` 1.15.1 reads it (upki v1.0.1's pin): text and blank lines outside a block are skipped; a block whose label `rustls-pki-types` knows (`CERTIFICATE`,
`PUBLIC KEY`, `RSA PRIVATE KEY`, `PRIVATE KEY`, `EC PRIVATE KEY`, `X509 CRL`, `CERTIFICATE REQUEST`, `ECHCONFIG`) is
decoded, only `CERTIFICATE` blocks are kept and the others dropped, and a decode error in any of them fails the body;
a block with an unknown label is skipped undecoded; the base64 decoder skips whitespace (HT, LF, VT, FF, CR, space)
and needs no padding; a body that ends inside a block, or has no `CERTIFICATE` block, fails; HTTPS from a host `allowedDomains` allows (today `content-signature-2.cdn.mozilla.net`; the parsed URI host after rejecting userinfo, a non-https scheme and a port other than 443; `_expected` is validated as an integer before it enters a query string). **The x5u URL grammar**, strict and never repaired: `https://` in lowercase, so `HTTPS://` is refused; an authority with no userinfo; a host that is a DNS host name (labels of ASCII letters, digits and `-` of 1 to 63 characters that start and end with a letter or digit, at most 253 in all, no trailing dot, a last label that starts with a letter, as `java.net.URI` reads a host), never an IP literal and never a percent-encoded or non-ASCII host; no port, or port 443; then a path and an optional query of RFC 3986 `pchar`s, `/` and `?`, every `%` followed by two hex digits; and any fragment, which must be one RFC 3986 allows and is dropped. Anything else is `FAILED` with `X5U_URL`, never repaired, `MAX_X5U_BYTES` (64 KiB) cap; **algorithm floor** for every link below the terminal (Firefox's `AppTrustDomain` set): a signature is RSA PKCS#1 v1.5 or ECDSA with SHA-256, SHA-384 or SHA-512 (an ECDSA AlgorithmIdentifier with NULL or absent parameters, as mozilla::pkix reads it), or `id-RSASSA-PSS` whose parameters are byte for byte one of mozilla::pkix's three encodings (SHA-256, SHA-384 or SHA-512 with NULL hash parameters, MGF1 with the same hash, a salt length equal to the hash length, `trailerField` omitted for its default 1); a link's key is `rsaEncryption` of at least 2048 bits or `id-ecPublicKey` on P-256, P-384 or P-521, so an `id-RSASSA-PSS` key fails; anything else `FAILED` (`ALGORITHM`; the JCA verifier is called directly, so `jdk.certpath.disabledAlgorithms` does not apply). This floor is the x5u chain's own: §3's `id-RSASSA-PSS` rule for the TLS verifier is unchanged; validity at verification time for the leaf
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
seed. **The path is the x5u order:** the leaf first, each certificate verified under the next one's key, with no path search or reordering, where Firefox builds the path by issuer name over the certificates after the leaf. This stays because no path search ever runs over an unsigned body: each link is verified once, so the cost is linear in the chain under the 64 KiB cap; Mozilla's chains are served leaf first. **Order:** the pin lookup runs first, over each certificate after the leaf as read leniently (§9.2's parser);
the strict profile below then applies only to the links below the terminal, and the terminal is read for its SPKI
alone. Leaf EKU,
when present, codeSigning and never `id-kp-OCSPSigning` (`EKU`); an absent one passes, as mozilla::pkix's `requiredEKUIfPresent` reads it. Leaf SAN (`SAN`): present, of dNSNames only, each a plain DNS host name (no wildcard, no empty or malformed name), one of them `onecrl.content-signature.mozilla.org` with ASCII case ignored, as Firefox matches it; other dNSNames are allowed. Two narrowings from Firefox stay: a wildcard never matches, since the signer name is exact and a wildcard leaf would sign for every content-signature signer; and a name of another form fails, since nameConstraints are evaluated for dNSNames only and such a name could escape a CA's constraint. Any non-terminal certificate
on the path outside its window at a live fetch is `SyncOutcome.FAILED` with `CLOCK_SKEW`.

**The chain follows mozilla::pkix** (at Firefox
`cac25a6fa321b0051932359b84c4e2fe3caabdc5`, with rustls-webpki consulted: 0.104.0-alpha.7, the version upki builds paths
with (`upki/Cargo.toml:32` at 9821cce), its divergences listed in Appendix A and `docs/decisions/DIVERGENCES.md`). Every failure is
`SyncOutcome.FAILED` with `X5U_CHAIN`, and the parenthesis names the chain's failure reason. For every link below the terminal:
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
  non-leaf link below the terminal and checked against every one of the leaf's dNSNames:
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

**Rollback guard**, as Firefox's `RemoteSettingsClient` compares a changeset's timestamp with its local data's (Appendix A):
a high-water mark (the watermark) on the signed `last_modified` (`<ts>`, the value the verified payload was built
from, §7.1: a live sync's envelope `timestamp`, a seed's `records.json` value; never `monitor/changes`' unsigned
`last_modified`), persisted per dataset and channel in `updater.json` (§6.5) and raised by every install to the
higher of it and `<ts>` in the same write as the install. A verified changeset whose `<ts>` equals the live generation's `sourceTimestampMillis` is
`UNCHANGED`, updating the attempt fields only; when the pointer does not name it, §6.5's re-flip or heal-install also
writes the cursor, `lastVerified*` and the watermark at `<ts>`, and so does an `UNCHANGED` whose cursor or watermark is
behind `<ts>` (§6.5). While a generation is live (stored or seed), the **floor** is the
higher of the stored watermark and the live `sourceTimestampMillis`, so a malformed or absent `updater.json`
beside a live generation cannot reopen a rollback to anything older than what is installed; a changeset older
than the floor is `SKIPPED` with `ROLLBACK_REFUSED`, decided before any body is fetched, and one equal to it installs. With no
generation loaded (none stored, none readable, no seed) the stored watermark is not read and the changeset
installs, as Firefox imports older data when its local data does not verify, and its install sets the watermark to
its `<ts>`, lowered if it was higher, as Firefox's local timestamp becomes the imported data's; that write is the
install's own (§6.5), so an install that fails leaves the watermark as it was. "None readable" means a stored
generation that is absent or malformed, never one whose read threw: a store read that throws is not an empty store,
and no sync runs after a stored-generation read that threw until that read resolves (Firefox fails its sync when its
local read throws). No rule on signed data reads the local clock: a
`<ts>` ahead of it installs and advances the watermark and the cursor (§10), and the one clock check of a sync is
the x5u validity (`CLOCK_SKEW`).
`ROLLBACK_REFUSED` is not a feed failure, never advances `consecutiveFailures`, and never updates
`lastVerified*`; `ROLLBACK_REFUSED` on every poll for longer than `signedSourceFailingAfter` does set
`signedSourceFailing`, so a stuck watermark is visible.

### 7.2 Mozilla CRLite, channels, seeds and data artifacts [M1]
Channel is top-level (`DEFAULT`: all reasons, a 6.0 MB full and 242 KB a delta on average (measured 2026-11-12,
§6.4), Firefox desktop and the public mirrors; `COMPAT`: keyCompromise, cessationOfOperation, privilegeWithdrawn, a
1.57 MB full and 134 KB a delta (the same measurement),
Firefox for Android, no public mirror). Recommended: `DEFAULT` for backends, `COMPAT` for Android apps (APK and metered cost, §12). Delta chain depth varies: 8 deltas per channel on Remote Settings on 2026-10-21, 52 on 2026-11-12 (§6.4); Phase-0 task: observe
two full-filter cuts for re-parenting. When the stored full is no longer the delta parent, the new full downloads
in the same sync, on any network: neither Firefox nor upki defers a download on a metered network. **Seeds** verified like a live fetch except x5u validity at the seed's signed
`last_modified`; a seed-backed generation is never `NO_DATA`; a future-dated seed installs like any other (§6.5); `DataState.fromSeed`, `ageMillis` and
`stale` are loud. **Data artifacts**: date-versioned (`YYYY.MM.DD`, the run's UTC date; the signed `<ts>` is not
after that day, nor more than the default CRLite `staleAfter` of 3 days before it; `SeedWriterTest`), never older than the
last released seed of its channel (the weekly job verifies that release's content signature again, only the parts
that do not depend on the seed format: `seed.json`'s channel, the x5u chain inside the archive to Mozilla's pins, the
raw signature over `records.json`, the canonical payload, and the x5u validity at its signed `<ts>`, and no schema,
since the content signature names no collection: the attestation binds the jar to the job that fetched
`cert-revocations` and schema-checked it in its full self-load; it requires that `<ts>` to equal the attested one,
refuses a signed `<ts>` older than it, and releases nothing when every channel's equals it, as Firefox ignores a
changeset older than its local data once that data verifies; a previous release that does not verify fails the job,
where Firefox imports the older changeset; `SeedSignatureTest`, `SeedTimestampTest`, `test_seed_scripts.py`
`FloorTest`),
weekly, attested, not in the BOM, no build-time plugin for a consumer (`data-artifact` is
revokt's own build's): a jar holding only the manifest, `META-INF/LICENSE-DATA` and the stored
`/revokt/seed-<channel>.zip` (`DataArtifactPluginFunctionalTest`). **In 0.2 a seed is a GitHub release asset with
attestations, not on Maven Central** (the maintainer's decision, 2026-11-23): an app bundles the jar itself, and Maven
publishing, with its separate namespace and Portal account, is a later decision. **Freshness per dataset** (`Freshness`, reported on `DataState`; a dataset's value joins the enum with the dataset): CRLite ages from the filter
record's `last_modified`; OneCRL and intermediates (M2) age from the last **verified poll**, since
their content changes only when a CA is listed; CRLSet from its sequence time; the denylist from the
artifact date; seeds from their signed timestamp.

### 7.3 C2SP manifest mirrors and system cache
Cut: not a source. [docs/design/mirror-and-system-cache.md](../design/mirror-and-system-cache.md) keeps the design. Only
the Remote Settings source and seeds are configurable; a stored generation still loads as a C2SP image (`GenerationFiles`, §6.5).

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
  generation and `DataState.pending == false` (the start task has installed a generation or ended; `pending` is false at the end of the start task whether or not a fetching source is configured, with `generationEpoch++` when it clears without a generation, so a seed-only configuration can never sit in `pending`); presets' `requiredDatasets` is `{CRLITE}`. `STALE` fires for a dataset present in the staleness map
  (presets: `CRLITE` only) iff `rejectStaleAfter != null && ageMillis > rejectStaleAfter`;
  `DataState.stale` (the loud flag) is `ageMillis > staleAfter` and never fires a rule.
  In `DEFAULT`, `STALE` allows: setting a `rejectStaleAfter` makes the rule fire and report, and rejecting takes
  `rule(…, REJECT)` as well. `ageMillis = now − sourceTimestampMillis` per the dataset's
  `Freshness`. Preset defaults: `CRLITE` `staleAfter` 3 d, `rejectStaleAfter` null in `DEFAULT`, 30 d
  in `STRICT`. **Stated plainly:** `DEFAULT` with stale data is "reject what the stale filter says is
  revoked, allow the rest", with `STALE` never firing; `DEFAULT.newBuilder().rule(STALE, REJECT)`
  alone changes nothing until a `rejectStaleAfter` is set. **`STALE` does not fire for a dataset whose
  generation is `fromSeed` until a sync attempt has completed since the seed was installed** (the persisted
  `updater.json.datasetLastAttemptAtMillis ≥ updater.json.seedInstalledAtMillis`, both per dataset (§6.5), never the in-process `lastSync`; the loader carries the boolean in the published `DataState`, and once a sync's `updater.json` write records such an attempt it publishes the seed generation again with the gate open and `generationEpoch++` (`CrliteRuntimePollTest` "the seed's STALE gate opens once a sync attempt completed, even a failed one", "a sync that wrote no updater json is no attempt");
  an instance running in memory (§3) records its attempts in its own in-memory `updater.json`, and a sync whose `updater.json` read threw (§6.5) is not an attempt; a backoffed
  first sync completes at once as `SKIPPED` with `BACKOFF`, §5.1, and `FETCH_TIMEOUT` bounds "completed", so an on-path
  attacker answering `503 + Retry-After` cannot keep the gate shut across restarts),
  or at once when no fetching source is configured (there is no fetch to race; `sync()`'s seed re-check is still an attempt; `SEED_PAST_REJECT_THRESHOLD` is still emitted), because installs happen months after a build and the first
  handshakes race the first sync; after that attempt `STRICT` with no reachable signed source and a seed older
  than 30 days rejects everything until a sync succeeds, by design.
- **One time field** on the policy plus the per-dataset map, all stored as millis with
  `java.time.Duration` accessors: `signedSourceFailingAfter` (24 h). There is no rollback window and no clock skew
  tolerance: the rollback guard compares signed timestamps only (§7.1). `wouldRejects` advances only under `OBSERVE` and
  `rejects` only under `ENFORCE`, so the two columns compare cleanly after a flip.
- **`ENGINE_ERROR` allows in `DEFAULT`** and rejects in `STRICT`.
- **Exemptions** register per exemptable rule and run after policy mapping for fired `REJECT` rules only. **Enterprise-CA recipe under `STRICT`**: exempt `NO_SCTS`, `NOT_ENROLLED` **and the data rules** (`NO_DATA`, `STALE`) with the same `anchorIn(privateCa)` (`RevoktPolicy.Builder.exemptAnchors(sha256s)` does exactly that, §4), and `NO_ISSUER` with `hostSuffixIn(corpDomains) and platformOnly()` (it fires only on an empty reported path, where `anchorIn` never matches; `platformOnly()` alone would exempt every chain the §5.2 intermediate-omission residual produces on Android, for every host, turning `STRICT` into `DEFAULT` for a revoked public leaf presented without its intermediate), so a feed outage never takes down traffic CRLite cannot evaluate anyway ( on the JVM the supported private-CA delegate is a `TrustManagerFactory` over a merged `KeyStore`, never a hand-written `X509ExtendedTrustManager` composite, which passes `requiresExtendedDelegate()` but drops SunJSSE's constraints; call `refreshAnchors()` on rotation).
- **`outcomeDepended`** (M1): `outcomeDepended = (reason == UNSUPPORTED_ALGORITHM)` (§5.1 "Findings"): the
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
  server cannot forge for a real certificate; the walk stops at its first sound path, as webpki and mozilla::pkix do,
  and that path's leaf-issuer key is evaluated; a second terminating key for the same leaf needs an unconstrained CA
  key holder under a real anchor, or an honest issuer with a second SPKI encoding of its key (residual 15); any
  exhaustion anywhere rejects.
- **Residual risks recorded from the sixth and seventh review rounds:**
  1. On a custom delegate whose name equality differs from `X500Principal`'s, an honest issuer may
     be classified unrelated, and an unrelated certificate is never a candidate (§5.1 deferral rule), so the walk
     misses that link: `NotFound`, which the PKIX fallback covers for chains of at most 8 certificates, as it covers
     the constraints and verifier residue (`FALLBACK_LIMIT` beyond them, `NO_ISSUER(PLATFORM_ONLY)` on a binding with
     the fallback off). A related decoy path ahead of the misclassified issuer is found first and decides the key,
     as in residual 15. Neither reference explores an unrelated certificate either: webpki and mozilla::pkix offer
     only name-matched issuers. The fallback may not be disabled while `NO_ISSUER` allows. On both default delegates
     every honest issuer is related.
  1b. **Behind a TLS-intercepting proxy revokt sees the proxy's chain**: no SCTs, an issuer CRLite does
     not enroll, so every verdict is a non-answer and `STRICT` reduces to exempting the proxy's anchor;
     CRLite cannot evaluate such traffic, deploy revokt on the egress proxy instead (§8 `OBSERVE`
     shows `fired[NO_SCTS] / evaluations` near 100 % in that case).
  2. Divergence between the delegate's constraints and `CertPathBuilder("PKIX")` or the injected
     verifier can leave a chain the platform trusts unchecked in `DEFAULT`; it is reported as
     `NO_ISSUER(PLATFORM_ONLY)` and `STRICT` rejects it.
  3. **Closed.** The anchor snapshot is built synchronously before any handshake can
     go past flow step 1 on both platforms (inside `start()` or at wiring), so there is no startup window.
     What remains is operational: on Android the delegate's `getAcceptedIssuers()` at wiring runs
     under an unconditional `StrictMode.allowThreadDiskReads`, which hides the report, not the read:
     the default delegate reads the cacerts directories only when wired after a trust-store change,
     a Conscrypt `TrustManagerImpl` over `AndroidCAStore` on every wiring. A consumer that wants no
     main-thread disk read creates its trust managers before `start()`.
  4. `MAX_EXPLORED = 256` rejects an honest chain whose walk meets 256 failing candidates before its path: unknown in
     the Web PKI, possible in bridge PKIs, which are out of scope for TLS clients. Since store anchors come first at
     every depth, about 256 snapshot anchors named like a node's issuer push a presented issuer past the budget; the
     trust store controls that, not the server, as in Firefox, where roots come first. A server can spend the budget
     with junk ahead of its own issuer, which rejects its own chain.
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
  9. Walker CPU per uncached connection is bounded by `MAX_EXPLORED`, about 250 ms of RSA-4096
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
     handshake; the fallback may then find a path the walker called `NO_CANDIDATE`, returning a fetched issuer as its
     `getEncoded()`, to which step 6 applies its rules; revokt neither sets nor clears the property, which the JDK reads
     once, at class initialisation (`sun.security.provider.certpath.Builder.USE_AIA`).
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
  15. **Constrained sub-CA.** The holder of an unconstrained CA key under a real anchor, which is any public CA, can
     certify a recovered key, and the walker then reports only that benign key whenever its path comes first in
     candidate order, the store's anchors and then the presented order, which the server controls: with the honest
     intermediate presented after it too (fixtures (o) and (ar), "no limit, an unconstrained CA"). mozilla::pkix
     evaluates that one path as well: it checks revocation only for the issuer of the path it built, and a failing check
     ends the search. webpki goes on past a revoked path to the next candidate, so it accepts the attacker's path in
     either order. Such a key holder can mint a fresh leaf for the name anyway. M2's candidate order, presented
     certificates before the preload as in Firefox's `FindIssuer`, does not close this: a preloaded honest intermediate
     comes after the attacker's presented one. The same order also picks between two SPKI encodings of one honest
     issuer key (an RSA key with NULL or with absent parameters): both verify the leaf and terminate without any
     attacker CA, CRLite keys by the hash of the SPKI's bytes, and only the first path's encoding is queried, as in
     Firefox; such issuers are rare in the Web PKI. A limited sub-CA cannot do the first: `pathLenConstraint`,
     keyUsage `keyCertSign`, extKeyUsage and name constraints are enforced on every issuer (fixtures (ar), (as), and the
     (o)-shaped evaluate case where such a sub-CA certifies the recovered-key CA presented first).
     Name constraints follow Firefox's mozilla::pkix (§5.1 "Why this is sound", pinned to `pkixnames.cpp` at
     `cac25a6`): directoryName and rfc822Name subtrees are evaluated, the subject's emailAddress attributes stand in
     for a missing subjectAltName, and a serverAuth leaf's CN-ID is checked when its subjectAltName has no dNSName or
     iPAddress. Where revokt is stricter than Firefox:
      - the 250,000-comparison bound, which pkix does not have;
      - an iPAddress subtree whose mask is not ones then zeros fails, as in webpki, where pkix applies the mask as
        written;
      - a subjectAltName that revokt's reader refuses (an empty one, or a dNSName that is not ASCII) fails under any
        nameConstraints, where pkix reads it and checks each entry against the subtrees of its form only.

     Neither RFC 5280 self-issued exemption applies (from `pathLenConstraint`, and from the name constraints on a
     self-issued intermediate); neither reference applies them either.
     **What a refusal means for the verdict.** A `NotFound` caused by these rules is `NO_ISSUER`, which `DEFAULT`
     allows unchecked and `STRICT` rejects (§8). So a revoked leaf under a self-issued key-rollover CA that relies on
     the RFC 5280 exemption, under an EKU-limited issuer, or under an issuer whose nameConstraints refuse it (an
     excluded directoryName subtree refuses every certificate), is accepted under `DEFAULT` without a revocation
     check; the same holds for a fallback path that spends the comparison bound. What was checked: the walker test
     chains of github.com, letsencrypt.org, www.google.com and www.mozilla.org stay `Found` under the JDK verifier
     (`HonestCorpusWalkTest`); no root in the JDK 21 `cacerts` (118) or macOS `SystemRootCertificates` (158) carries
     nameConstraints; live Web PKI sub-CAs were not surveyed for directoryName or rfc822Name subtrees. On the bindings
     the platform validates the chain first (step 1).
  16. **A long chain the walker cannot build fails closed.** `FALLBACK_MAX_PRESENTED` (8) counts the presented
     certificates, and a walk without a path over more than 8 of them is `PATH_BUDGET_EXCEEDED(FALLBACK_LIMIT)`, which
     `DEFAULT` rejects (§5.1 step 6; P8 in test-plan.md §9.1). This follows from #226's `FALLBACK_MAX_PRESENTED`. It is
     not narrower than Firefox: mozilla::pkix caps the path it builds, at 6 intermediates (`MAX_SUBCA_COUNT` in
     `pkixbuild.cpp`), not the count presented. So a padded chain whose short path the walker cannot build, for
     example a leaf, an intermediate and a root sent with 6 extra certificates (old cross-signs), is accepted by Firefox
     and rejected here. Causes include an unsupported signature algorithm on the path, a missing intermediate that
     Firefox's preload would supply (M1 has no preload), and a misclassified honest issuer (residual 1, #226). On a
     trust-manager binding the platform has accepted the chain, but the 8-certificate check runs before the
     `PLATFORM_ONLY` promotion, so that does not help either. The holder of an anchor-certified CA key can supply the
     missing path and turn that rejection into an accept, as P3's certified bridge shows; such a key holder can mint a
     fresh leaf anyway (residual 15).
- Feed authenticity: every generation is verified against Mozilla's content-signature roots, from the feed or from a
  seed (§7.1); there is no unsigned source. The M2 denylist is project-attested and availability-only.
- Rollback and freeze: a persisted non-decreasing watermark with no tolerance, floored at the live generation's
  timestamp; a newer signed changeset always installs and the
  pinned terminal's validity is never checked; **no signed record can freeze the signed source**: revokt applies
  no verdict to its own fetches (§5.1); the cursor and watermark move only on a
  successful install after collection-schema validation, so a replayed sibling-collection changeset
  cannot freeze them; the content signature binds neither bucket nor collection, so a party the fetcher's TLS trusts (a private mirror) can serve `security-state-preview`'s `cert-revocations` as production data (residual: Mozilla data pending review, low impact; recorded beside the collection-id note); unsigned transport headers cannot persist a backoff beyond 24 h;
  staleness always visible; no ceiling in `DEFAULT` (upki's model); `rejectStaleAfter` is the
  optional ceiling. No rule on signed data reads the local clock (Firefox and upki have none): a changeset or seed
  dated ahead of it installs and advances the watermark and the cursor, which the next changeset passes, as Kinto
  assigns a collection's timestamps monotonically and Mozilla's signer publishes them unchanged (Appendix A).
  Residual: a far-future `<ts>` from a server bug reads as age 0 until local time passes it, so `stale` and `STALE`
  fire late by as much if the feed then stops; a leaked signing leaf can sign any `<ts>` and coverage, and no
  timestamp rule contains it. The floor is never below the live generation's timestamp, so losing `updater.json`
  reopens no rollback; with no generation loaded the stored watermark is not read and older signed data installs,
  setting the watermark to its `<ts>`, as Firefox imports when its local data does not verify (residual: a party
  that can serve stale signed data and damage the local store can roll back to any data Mozilla signed; and a fatal
  error after `activate` in a process's first install leaves the engine serving that generation with an empty
  snapshot, so the next sync, seeing no generation loaded, does not read the watermark either). After `resetState()` the rollback bound is the
  seed's timestamp once the start task has swapped the live generation; until then the watermark floor still holds it
  at the old live generation's timestamp, which is stricter (residual: `updater.json` is deleted with the store).
- No self-lockout: a signed revocation of the feed host's own certificate does not stop its fetches, which run over
  the platform's trust manager or the consumer's client's, which must not be revokt's (the §4 `http` R rule) (the payload is authenticated end to end, so TLS authenticity to that host protects
  nothing an attacker could exploit), as in Firefox and upki; untrusted bytes (the changeset JSON, the x5u chain) are hardened with
  allocation budgets and per-kind download caps, so an unsigned body cannot exhaust the heap; no fetch follows a
  redirect (§7.1);
  x5u host under `allowedDomains`, capped and path-validated, following mozilla::pkix's chain checks (§7.1); the
  TLS parser is at least as lenient as the platforms,
  verified differentially (§9.2), and `PARSE_FAILED` applies to the leaf only.
- Crypto never implemented in Kotlin except the raw-to-DER ECDSA conversion, the `ECDSA-Sig-Value` decode and the r and s range comparison (§3) and the §9.2 profile's EC on-curve check (public field arithmetic over P-256, P-384 and P-521, no secret data); `UNSUPPORTED` is decided
  by a startup probe, never by a server-chosen exception; provider exceptions never escape the
  trust manager.
- Privacy: no per-connection lookups. Blast radius mitigated by `Enforcement.OBSERVE`, `shadowPolicy`, the runtime
  switch, seeds, dated data artifacts, and `ENGINE_ERROR = allow` in `DEFAULT`;
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
| 0.2 | a minimal `Revokt` (`build()` and `validate()`, with no `storage` member: the store is `RevoktStorage.inMemory()`; a synchronous `start()` that builds one `CandidateIndex` over `platformTrust.anchors(platformTrust.defaultDelegate())`, loads the seed, runs the in-memory updater on the loader dispatcher and publishes the generation reference, `close()`; the updater syncs in the start task after the seed and then on §5.1's schedule, with the loader's timer and the jitter's random source internal test seams beside `clock` (`RevoktPollTest`), and the first sync can never meet a persisted backoff, the store being fresh at every `build()`; no readiness future, caches, factory lock, per-delegate instances or `state`; start diagnostics returned from `start()` as `List<PolicyDiagnostic>` until `state` exists (`validate()`'s `WARNING`s, then the S `DiagnosticCode`s; the S `WarningCode`s are logged at `WARN`, `SEED_PAST_REJECT_THRESHOLD` too when the loader installs or loads a seed generation after `start()` returned); the synchronous part runs under one internal lock with no `STARTING` flag (a racing `start()` or `close()` waits for it); in the sole-seed `ENFORCE` configuration a configured seed that opens no archive throws `SEED_UNREADABLE` like an unreadable one; the JVM join is a bounded wait on the start task, measured from the flip; `close()` is the flip, the loader cancelled (its running task interrupted) and awaited without a deadline, the generation reference cleared, then `engine.close()`, with no handshake drain, store lock or identity; the loader thread is `revokt-loader-<build sequence>`, the sequence counting `build()`s in the process from 1; `start()` over an empty or throwing default trust store succeeds, and `evaluator.evaluate` throws `IllegalStateException` until an index exists; `sync()`, `syncAsync()` and `syncBlocking()` are internal and the updater syncs only on its schedule, and so are `SyncResult`, `SyncOutcome`, `SyncFailure`, `RevoktWarning` and `WarningCode`, which have no public consumer before them (the first-consumer rule, §4, #221); `RevoktStorage`, `RevoktLifecycle`, `AnchorSnapshot`, `PathBuilderFallback` and the seam's data types are `@RevoktInternalApi`, and output types have internal builders); candidate index and walker per §5.1, the PKIX fallback (the jvmMain `PkixPathBuilderFallback`, which Android also runs through ojluni, tested on the JVM; the Android instrumented run is 0.3), the §9.2 read fallback in the JVM binding, the walker-only harness, `Evaluator.evaluate` over that one index (decision steps 2–3 and 5–8, walker reason reported directly; `Revokt.evaluate(…, delegate)` is 0.3) with the §9 `Rule` model's [0.2] tests and the §9 API rows; **the §9.1 walker fuzzer is built and runs against the implementation here (P1–P8 gate)** and the walker's adversarial review precedes it; Remote Settings protocol and content-signature verification with x5u path validation (the §9 content-signature fixtures); CRLite updater and the updater record over `RevoktStorage.inMemory()` (the §6.5 key layout in memory; durability, `store.version`, pointer flip, crash recovery and the lock are 0.3); seeds with `seed.json`; data artifacts job (GitHub release assets with attestations, not on Maven Central); coverage sanity and rollback; the §9 data-path fixtures (a), (b), (d) and (g) less its Android and OkHttp fetcher halves | 4 weeks |
| 0.3 | moved from 0.2 (#312): the CI-only upki engine and the cross-engine suite (the issuer taken from the corpus chain's presented order, no walk needed), and benchmarks; §6.5 store (`store.version`, blobs and generation files, pointer flip, crash recovery, lock); the §9 data-path fixtures (e), (f), (h) and the (g) items deferred from 0.2 (the Android and OkHttp fetcher halves); caches; `RevoktTrustManager` (flow steps 0 to 4), `RevoktCertificateException`, `sslContext()`, the enforcement and policy setters, `resetState()`, listeners and `refreshAnchors()`; per-delegate trust managers and `Revokt.evaluate(…, delegate)`; public `sync()`, `syncAsync()` and `syncBlocking()`, with `SyncResult`, `SyncOutcome`, `SyncFailure`, `RevoktWarning` and `WarningCode`; the `RevoktStorage` factories over its sealed type (§3); lifecycle state machine and readiness future; OkHttp and per-engine Ktor bindings; `OBSERVE` events, `shadowPolicy`, `status()` and `state`, with the §9 `Rule` model's [0.3] tests; Android instrumented suite including the PKIX fallback, the null-host probe and the main-thread wiring probe under `StrictMode.detectDiskReads` on API 26/31/34/36, cold process and after a trust-store change (induced by `am broadcast -a android.security.STORE_CHANGED` as root on AOSP userdebug images, or by installing a user CA through `KeyChain.createInstallIntent()` under UiAutomator on images without root; the mirrored image matrix carries a userdebug variant for this); a consumer fixture built with AGP 8.5.2 that dexes the published artifacts (the Android floor; Appendix A); Baseline Profile and measured `AWAIT_DATA` (JVM default 2 s); WorkManager (`RevoktSyncWorker`, `Revokt.Provider`); system images mirrored into project storage for the emulator matrix; `revokt-testing`, with the output-type test factories (§4); optional `revokt-bc` | 5 weeks |

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
5. The OkHttp and Android README quickstarts add the `revokt-seed-<channel>` jar (a GitHub release asset in 0.2,
   §7.2) beside the binding, so the `SeedSource.bundled()` default resolves (§4, §6.5).

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
