// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)
// The tests set the dispatcher under test explicitly; that is the injection.
@file:Suppress("InjectDispatcher")

package dev.revokt.jsse

import dev.revokt.CrliteChannel
import dev.revokt.Enforcement
import dev.revokt.FilterFormat
import dev.revokt.KotlinRevocationEngine
import dev.revokt.LogLevel
import dev.revokt.Outcome
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import dev.revokt.RevoktLogger
import dev.revokt.RevoktLoggers
import dev.revokt.RevoktPolicy
import dev.revokt.Rule
import dev.revokt.SeedSource
import dev.revokt.verify.JcaSignatureVerifier
import kotlinx.coroutines.Dispatchers
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.Executor
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotSame
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Duration.Companion.seconds

/** `Revokt.Builder.build()` (spec §4): the defaults, the seed resolution, the DSL, and each R check in its case. */
class RevoktBuilderTest {
    private fun assertRefused(
        expected: String,
        builder: Revokt.Builder,
    ): IllegalArgumentException {
        val e = assertFailsWith<IllegalArgumentException> { builder.build() }
        assertTrue(expected in e.message.orEmpty(), "\"$expected\" not in: ${e.message}")
        return e
    }

    @Test
    fun `the defaults are spec section 4's`() {
        val config = bare().build().config
        assertEquals(CrliteChannel.COMPAT, config.channel)
        assertNull(config.remoteSettings)
        assertIs<JcaSignatureVerifier>(config.signatureVerifier)
        assertIs<KotlinRevocationEngine>(config.engine)
        assertEquals("kotlin", config.engineName)
        assertSame(Clock.System, config.clock)
        assertSame(RevoktLoggers.jul(), config.logger)
        assertSame(RevoktPolicy.DEFAULT, config.policy)
        assertEquals(Enforcement.ENFORCE, config.enforcement)
        assertEquals(2_000L, config.awaitDataMillis)
        assertSame(Dispatchers.IO, config.ioDispatcher)
        assertIs<JdkHttpFetcher>(config.http)
        assertEquals(RevoktLimits.MAX_FILTER_BYTES, config.maxFilterBytes)
        assertEquals(RevoktLimits.MAX_JSON_BYTES, config.maxJsonBytes)
        assertEquals(RevoktLimits.MAX_X5U_BYTES, config.maxX5uBytes)
        assertEquals(RevoktLimits.MAX_CHANGESET_RECORDS, config.maxChangesetRecords)
        assertTrue(config.pkixFallback)
        assertIs<JvmPlatformTrust>(config.platformTrust)
        assertSame(config.platformTrust.defaultDelegate(), config.defaultDelegate)
        assertSame(config.platformTrust.pathBuilder(), config.pathBuilder)
        assertTrue(config.inMemoryStore)
        assertNull(config.storage.identity())
    }

    @Test
    fun `the bundled default resolves for the channel, and is no seed without the resource`() {
        withContextResources(setOf("revokt/seed-default.zip")) {
            assertEquals(null, Revokt { channel = CrliteChannel.COMPAT }.config.seed)
            val seed = Revokt { channel = CrliteChannel.DEFAULT }.config.seed
            assertTrue(seed != null && !seed.isNone)
            assertSame(seed, seed.resolve(CrliteChannel.COMPAT), "resolved to a resource, not the bundled() stand-in")
        }
    }

    @Test
    fun `none is no seed, and any other seed is itself`() {
        assertNull(bare().build().config.seed)
        assertSame(
            SOME_SEED,
            bare()
                .seed(SOME_SEED)
                .build()
                .config.seed,
        )
        val of = SeedSource.of { null }
        assertSame(
            of,
            bare()
                .seed(of)
                .build()
                .config.seed,
        )
    }

    @Test
    fun `a second source call replaces the first`() {
        val first = remoteSettings(baseUrl = "https://one.example/v1")
        val second = remoteSettings(baseUrl = "https://two.example/v1")
        val config =
            Revokt {
                channel = CrliteChannel.COMPAT
                sources {
                    remoteSettings(first)
                    remoteSettings(second)
                    seed(SOME_SEED)
                    seed(SeedSource.none())
                }
            }.config
        assertSame(second, config.remoteSettings)
        assertNull(config.seed)
    }

    @Test
    fun `the DSL and the Java builder build the same configuration`() {
        val verifier = JcaSignatureVerifier()
        val logger = RevoktLogger { _: LogLevel, _: String, _: Throwable? -> }
        val fetcher = JdkHttpFetcher()
        val source = remoteSettings(baseUrl = "https://mirror.example:8443/v1")
        val strict = RevoktPolicy.STRICT
        val dispatcher = Dispatchers.Default
        val fixed = Instant.parse("2026-11-22T00:00:00Z")
        val dsl =
            Revokt {
                channel = CrliteChannel.DEFAULT
                signatureVerifier = verifier
                clock = JavaClock(java.time.Clock.fixed(fixed, ZoneOffset.UTC))
                sources {
                    remoteSettings(source)
                    seed(SOME_SEED)
                }
                this.logger = logger
                policy = strict
                enforcement = Enforcement.OBSERVE
                awaitData(3.seconds)
                ioDispatcher = dispatcher
                limits {
                    maxFilterBytes = (32L shl 20)
                    maxJsonBytes = (8L shl 20)
                    maxX5uBytes = 128L shl 10
                    maxChangesetRecords = 4_096
                }
                http = fetcher
                pkixFallback(false)
            }.config
        val java =
            Revokt
                .builder()
                .channel(CrliteChannel.DEFAULT)
                .signatureVerifier(verifier)
                .clock(java.time.Clock.fixed(fixed, ZoneOffset.UTC))
                .remoteSettings(source)
                .seed(SOME_SEED)
                .logger(logger)
                .policy(strict)
                .enforcement(Enforcement.OBSERVE)
                .awaitData(java.time.Duration.ofSeconds(3))
                .ioDispatcherForTest(dispatcher)
                .maxFilterBytes((32L shl 20))
                .maxJsonBytes((8L shl 20))
                .maxX5uBytes(128L shl 10)
                .maxChangesetRecords(4_096)
                .http(fetcher)
                .pkixFallback(false)
                .build()
                .config
        for (config in listOf(dsl, java)) {
            assertEquals(CrliteChannel.DEFAULT, config.channel)
            assertSame(verifier, config.signatureVerifier)
            assertEquals(fixed.toEpochMilli(), config.clock.now().toEpochMilliseconds())
            assertSame(source, config.remoteSettings)
            assertSame(SOME_SEED, config.seed)
            assertSame(logger, config.logger)
            assertSame(strict, config.policy)
            assertEquals(Enforcement.OBSERVE, config.enforcement)
            assertEquals(3_000L, config.awaitDataMillis)
            assertSame(dispatcher, config.ioDispatcher)
            assertEquals((32L shl 20), config.maxFilterBytes)
            assertEquals((8L shl 20), config.maxJsonBytes)
            assertEquals(128L shl 10, config.maxX5uBytes)
            assertEquals(4_096, config.maxChangesetRecords)
            assertSame(fetcher, config.http)
            assertFalse(config.pkixFallback)
            assertNull(config.pathBuilder, "no PKIX builder with the fallback disabled")
        }
        assertNotSame(dsl.engine, java.engine, "each build without an injected engine creates its own")
    }

    // The Java form of ioDispatcher is ioExecutor; the DSL property is the same field.
    private fun Revokt.Builder.ioDispatcherForTest(dispatcher: kotlinx.coroutines.CoroutineDispatcher) =
        apply { ioDispatcher = dispatcher }

    @Test
    fun `ioExecutor wraps the executor`() {
        val ran = mutableListOf<Runnable>()
        val executor = Executor { ran += it }
        val config = bare().ioExecutor(executor).build().config
        config.ioDispatcher.dispatch(kotlin.coroutines.EmptyCoroutineContext) {}
        assertEquals(1, ran.size)
    }

    @Test
    fun `awaitData takes any non-negative duration, in each form`() {
        assertEquals(
            0L,
            bare()
                .awaitDataMillis(0)
                .build()
                .config.awaitDataMillis,
        )
        assertEquals(
            1_500L,
            bare()
                .awaitData(1_500.milliseconds)
                .build()
                .config.awaitDataMillis,
        )
        assertEquals(
            250L,
            bare()
                .awaitData(java.time.Duration.ofMillis(250))
                .build()
                .config.awaitDataMillis,
        )
        assertFailsWith<IllegalArgumentException> { bare().awaitDataMillis(-1) }
        assertFailsWith<IllegalArgumentException> { bare().awaitData((-1).milliseconds) }
        assertFailsWith<IllegalArgumentException> { bare().awaitData(java.time.Duration.ofMillis(-1)) }
        assertFailsWith<IllegalArgumentException> { bare().awaitData(java.time.Duration.ofSeconds(Long.MAX_VALUE)) }
        // One rule for both forms: a sub-millisecond negative throws rather than rounding to 0, and so does unbounded.
        assertFailsWith<IllegalArgumentException> { bare().awaitData((-1).nanoseconds) }
        assertFailsWith<IllegalArgumentException> { bare().awaitData(java.time.Duration.ofNanos(-1)) }
        assertFailsWith<IllegalArgumentException> { bare().awaitData(kotlin.time.Duration.INFINITE) }
        assertFailsWith<IllegalArgumentException> { bare().awaitData(-kotlin.time.Duration.INFINITE) }
        // A positive sub-millisecond duration truncates toward zero in both.
        assertEquals(
            0L,
            bare()
                .awaitData(999_999.nanoseconds)
                .build()
                .config.awaitDataMillis,
        )
        assertEquals(
            0L,
            bare()
                .awaitData(java.time.Duration.ofNanos(999_999))
                .build()
                .config.awaitDataMillis,
        )
        assertEquals(
            1L,
            bare()
                .awaitData(1_999_999.nanoseconds)
                .build()
                .config.awaitDataMillis,
        )
    }

    // R CHANNEL_UNSET (spec §4): a CRLite source, a seed counting, needs a channel.

    @Test
    fun `no channel with the default bundled seed throws CHANNEL_UNSET`() {
        assertRefused("CHANNEL_UNSET", Revokt.builder())
    }

    @Test
    fun `no channel with an explicit seed throws CHANNEL_UNSET`() {
        assertRefused("CHANNEL_UNSET", Revokt.builder().seed(SOME_SEED))
    }

    @Test
    fun `no channel with a remote settings source and no seed throws CHANNEL_UNSET`() {
        assertRefused("CHANNEL_UNSET", Revokt.builder().seed(SeedSource.none()).remoteSettings(remoteSettings()))
    }

    @Test
    fun `no channel and no CRLite source builds`() {
        val config =
            Revokt
                .builder()
                .seed(SeedSource.none())
                .build()
                .config
        assertNull(config.channel)
        assertNull(config.seed)
        assertFalse(config.hasCrliteSource)
    }

    // R source URLs (spec §4): https, a host, no userinfo; no port rule.

    @Test
    fun `an https base URL builds, with any port`() {
        for (url in listOf(
            "https://firefox.settings.services.mozilla.com/v1",
            "https://mirror.example:8443/v1",
            "HTTPS://mirror.example/v1",
            "https://10.0.0.5/v1",
            "https://[2001:db8::1]:9443/v1",
        )) {
            assertSame(
                url,
                bare()
                    .remoteSettings(remoteSettings(baseUrl = url))
                    .build()
                    .config.remoteSettings
                    ?.baseUrl,
            )
        }
    }

    @Test
    fun `a base URL that is not https throws`() {
        for (url in listOf(
            "http://firefox.settings.services.mozilla.com/v1",
            "ftp://mirror.example/v1",
            "https:mirror.example/v1",
            "/v1",
            "mirror.example/v1",
        )) {
            assertRefused("baseUrl", bare().remoteSettings(remoteSettings(baseUrl = url)))
        }
    }

    @Test
    fun `a base URL with userinfo throws, and the message does not repeat it`() {
        for (url in listOf(
            "https://user:secret-password@mirror.example/v1",
            "https://user@mirror.example/v1",
            "https://@mirror.example/v1",
        )) {
            val e = assertRefused("userinfo", bare().remoteSettings(remoteSettings(baseUrl = url)))
            assertFalse("secret-password" in e.message.orEmpty() || url in e.message.orEmpty(), e.message)
        }
    }

    @Test
    fun `a base URL with a port outside 1 to 65535, a query or a fragment throws`() {
        for (url in listOf(
            "https://mirror.example:0/v1",
            "https://mirror.example:65536/v1",
            "https://mirror.example:99999/v1",
        )) {
            assertRefused("outside 1 to 65535", bare().remoteSettings(remoteSettings(baseUrl = url)))
        }
        bare().remoteSettings(remoteSettings(baseUrl = "https://mirror.example:65535/v1")).build()
        bare().remoteSettings(remoteSettings(baseUrl = "https://mirror.example:1/v1")).build()
        bare().remoteSettings(remoteSettings(baseUrl = "https://mirror.example:/v1")).build()
        for (url in listOf(
            "https://mirror.example/v1?x=1",
            "https://mirror.example/v1#f",
            "https://mirror.example/v1?",
        )) {
            assertRefused("query or a fragment", bare().remoteSettings(remoteSettings(baseUrl = url)))
        }
        assertRefused(
            "query or a fragment",
            bare().remoteSettings(remoteSettings(attachmentBaseUrl = "https://cdn.example/a/#x")),
        )
    }

    @Test
    fun `no rejected source URL's message repeats the URL or its credentials`() {
        val rejected =
            listOf(
                "https://user:secret@host/",
                "http://user:secret@host/",
                "https:user:secret@host/",
                "https://host/v1?token=secret",
                "https://h/?token=SECRET",
                "https://h/secret?x=1",
                "https://user:secret@remote_settings.example/v1",
                "https://host/v1#secret",
                "https://host:99999/secret",
                "ftp://host/secret",
                "https://under_score/secret",
                "https:///secret",
                "https://user:secret@host/v 1",
            )
        for (url in rejected) {
            for (builder in listOf(
                bare().remoteSettings(remoteSettings(baseUrl = url)),
                bare().remoteSettings(remoteSettings(attachmentBaseUrl = url)),
            )) {
                val e = assertFailsWith<IllegalArgumentException> { builder.build() }
                val message = e.message.orEmpty()
                assertTrue(message.startsWith("remoteSettings."), message)
                assertFalse("secret" in message.lowercase() || url in message, "$url: $message")
                assertNull(e.cause, url)
            }
        }
        val e = assertRefused("userinfo", bare().remoteSettings(remoteSettings(baseUrl = "https://user:secret@host/")))
        assertEquals("remoteSettings.baseUrl has userinfo, which a source URL never carries (spec §4)", e.message)
    }

    @Test
    fun `a base URL with no host, or that is no URL at all, throws`() {
        assertRefused("no authority", bare().remoteSettings(remoteSettings(baseUrl = "https:///v1")))
        for (url in listOf(
            "https://under_score/v1",
            "https://remote_settings.corp.example/v1",
            "https://-leading.example/v1",
            "https://mirror.example:abc/v1",
        )) {
            assertRefused("not a DNS name or IP literal", bare().remoteSettings(remoteSettings(baseUrl = url)))
        }
        // The neighbours that are DNS names build.
        bare().remoteSettings(remoteSettings(baseUrl = "https://remote-settings.corp.example/v1")).build()
        bare().remoteSettings(remoteSettings(baseUrl = "https://a-1.b2.example/v1")).build()
        assertRefused("no authority", bare().remoteSettings(remoteSettings(baseUrl = "https:mirror.example/v1")))
        val e =
            assertRefused(
                "not a URL",
                bare().remoteSettings(remoteSettings(baseUrl = "https://u:pw-1@mirror.example/v 1")),
            )
        assertFalse("pw-1" in e.message.orEmpty(), e.message)
        assertNull(e.cause, "the parser's exception holds the input")
    }

    @Test
    fun `a pinned attachment base URL is checked as the base URL is, and an unpinned one is not checked`() {
        assertRefused(
            "attachmentBaseUrl",
            bare().remoteSettings(remoteSettings(attachmentBaseUrl = "http://cdn.example/attachments/")),
        )
        assertRefused(
            "attachmentBaseUrl has userinfo",
            bare().remoteSettings(remoteSettings(attachmentBaseUrl = "https://u:p@cdn.example/attachments/")),
        )
        val pinned = "https://cdn.example:8443/attachments/"
        assertEquals(
            pinned,
            bare()
                .remoteSettings(
                    remoteSettings(attachmentBaseUrl = pinned),
                ).build()
                .config.remoteSettings
                ?.attachmentBaseUrl,
        )
        assertNull(
            bare()
                .remoteSettings(remoteSettings())
                .build()
                .config.remoteSettings
                ?.attachmentBaseUrl,
        )
    }

    // R caps (spec §4 limits { }): raisable only.

    @Test
    fun `each cap at its default or above builds, and one below throws`() {
        val caps: List<Triple<String, Long, (Revokt.Builder, Long) -> Revokt.Builder>> =
            listOf(
                Triple("maxFilterBytes", RevoktLimits.MAX_FILTER_BYTES) { b, v -> b.maxFilterBytes(v) },
                Triple("maxJsonBytes", RevoktLimits.MAX_JSON_BYTES) { b, v -> b.maxJsonBytes(v) },
                Triple("maxX5uBytes", RevoktLimits.MAX_X5U_BYTES) { b, v -> b.maxX5uBytes(v) },
                Triple("maxChangesetRecords", RevoktLimits.MAX_CHANGESET_RECORDS.toLong()) { b, v ->
                    b.maxChangesetRecords(v.toInt())
                },
            )
        for ((name, floor, set) in caps) {
            set(bare(), floor).build()
            set(bare(), floor + 1).build()
            assertRefused(name, set(bare(), floor - 1))
            assertRefused(name, set(bare(), 0))
        }
    }

    @Test
    fun `a cap lowered in the DSL throws at build`() {
        assertRefused(
            "maxFilterBytes",
            Revokt
                .builder()
                .channel(
                    CrliteChannel.COMPAT,
                ).limits { maxFilterBytes = RevoktLimits.MAX_FILTER_BYTES - 1 },
        )
        assertRefused(
            "maxChangesetRecords",
            bare().limits { maxChangesetRecords = RevoktLimits.MAX_CHANGESET_RECORDS - 1 },
        )
    }

    // R the PKIX fallback is load-bearing where NO_ISSUER allows (spec §4, §5.1).

    @Test
    fun `disabling the fallback under a policy that allows NO_ISSUER throws`() {
        assertEquals(Outcome.ALLOW, RevoktPolicy.DEFAULT.outcome(Rule.NO_ISSUER))
        assertRefused("pkixFallback(false)", bare().pkixFallback(false))
        assertRefused(
            "pkixFallback(false)",
            bare()
                .policy(
                    RevoktPolicy.STRICT
                        .newBuilder()
                        .rule(Rule.NO_ISSUER, Outcome.ALLOW)
                        .build(),
                ).pkixFallback(false),
        )
    }

    @Test
    fun `disabling the fallback under a policy that rejects NO_ISSUER builds, and the fallback is on by default`() {
        assertFalse(
            bare()
                .policy(RevoktPolicy.STRICT)
                .pkixFallback(false)
                .build()
                .config.pkixFallback,
        )
        val rejecting =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .rule(Rule.NO_ISSUER, Outcome.REJECT)
                .build()
        assertFalse(
            bare()
                .policy(rejecting)
                .pkixFallback(false)
                .build()
                .config.pkixFallback,
        )
        assertTrue(
            bare()
                .pkixFallback(true)
                .build()
                .config.pkixFallback,
        )
    }

    // R an engine instance goes into one Revokt only (spec §3.2).

    @Test
    fun `an injected engine goes into one Revokt only`() {
        val engine = StubEngine()
        val builder = bare().revocationEngine(engine)
        assertSame(engine, builder.build().config.engine)
        assertRefused("one Revokt only", builder)
        assertRefused("one Revokt only", bare().revocationEngine(engine))
    }

    @Test
    fun `engines are told apart by identity, not equals`() {
        bare().revocationEngine(StubEngine(equalsEverything = true)).build()
        bare().revocationEngine(StubEngine(equalsEverything = true)).build()
    }

    @Test
    fun `a build that fails a check leaves the injected engine unregistered`() {
        val engine = StubEngine()
        assertRefused("CHANNEL_UNSET", Revokt.builder().revocationEngine(engine))
        assertRefused("maxJsonBytes", bare().revocationEngine(engine).maxJsonBytes(0))
        assertSame(
            engine,
            bare()
                .revocationEngine(engine)
                .build()
                .config.engine,
        )
    }

    @Test
    fun `the engine's formats are read once, at build`() {
        val engine = StubEngine(advertised = setOf(FilterFormat.V4))
        val revokt = bare().revocationEngine(engine).build()
        val reads = engine.formatReads
        engine.advertised = setOf(FilterFormat.V3)
        revokt.validate(Enforcement.ENFORCE)
        revokt.validate(Enforcement.OBSERVE)
        assertEquals(reads, engine.formatReads)
        assertEquals(setOf(FilterFormat.V4), revokt.config.engineFormats)
        assertEquals("stub", revokt.config.engineName)
    }
}
