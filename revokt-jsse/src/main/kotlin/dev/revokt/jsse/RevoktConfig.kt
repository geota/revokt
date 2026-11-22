// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.jsse

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.DiagnosticCode
import dev.revokt.FilterFormat
import dev.revokt.KotlinRevocationEngine
import dev.revokt.MozillaRemoteSettings
import dev.revokt.Outcome
import dev.revokt.PathBuilderFallback
import dev.revokt.PlatformTrust
import dev.revokt.RevocationEngine
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import dev.revokt.RevoktStorage
import dev.revokt.Rule
import dev.revokt.SeedSource
import java.lang.ref.WeakReference
import java.net.URI
import java.net.URISyntaxException
import javax.net.ssl.X509TrustManager

/**
 * A built `Revokt`'s configuration: the builder's values with every default resolved, after the spec §4 R checks.
 * Construction runs the checks first, then resolves the defaults and creates the default engine, and registers the
 * engine last, so a check that throws leaves nothing registered and creates nothing.
 */
internal class RevoktConfig(
    builder: Revokt.Builder,
) {
    init {
        requireBuildable(builder)
    }

    val channel: CrliteChannel? = builder.channel
    val remoteSettings: MozillaRemoteSettings? = builder.remoteSettings

    /**
     * The seed after resolution (spec §4): `bundled()` becomes the channel's resource, or null when the class path has
     * none; `none()` is null; any other source is itself. Null means no local data source.
     */
    val seed: SeedSource? =
        (builder.seed ?: SeedSource.bundled()).let {
            // A seed other than none() reaches here only with a channel: requireBuildable threw CHANNEL_UNSET otherwise.
            if (it.isNone) null else it.resolve(checkNotNull(channel))
        }

    /** The store: `RevoktStorage.inMemory()` in 0.2, the only store (spec §11). */
    val storage: RevoktStorage = RevoktStorage.inMemory()
    val inMemoryStore: Boolean = true

    val signatureVerifier = builder.signatureVerifier
    val clock = builder.clock
    val timeSource = builder.timeSource
    val logger = builder.logger
    val policy = builder.policy
    val enforcement = builder.enforcement
    val awaitDataMillis = builder.awaitDataMillis
    val ioDispatcher = builder.ioDispatcher
    val http = builder.http
    val maxFilterBytes = builder.maxFilterBytes
    val maxJsonBytes = builder.maxJsonBytes
    val maxX5uBytes = builder.maxX5uBytes
    val maxChangesetRecords = builder.maxChangesetRecords
    val pkixFallback = builder.pkixFallback

    /**
     * The platform trust (spec §3, §5.3): `JvmPlatformTrust()`, with no builder member in 0.2 (the §4 `platformTrust`
     * member is [0.3]). Its default delegate is captured here, at `build()` (§4), before the engine is registered.
     */
    val platformTrust: PlatformTrust = JvmPlatformTrust()
    val defaultDelegate: X509TrustManager = platformTrust.defaultDelegate()

    /** Decision step 6's PKIX builder: `platformTrust.pathBuilder()`, or null with `pkixFallback(false)`, never called. */
    val pathBuilder: PathBuilderFallback? = if (pkixFallback) platformTrust.pathBuilder() else null

    val engine: RevocationEngine = builder.revocationEngine ?: KotlinRevocationEngine()

    /** Read once per instance (spec §3.2): `formats` for `validate()`, `name` for every engine error. */
    val engineFormats: Set<FilterFormat> = engine.formats.toSet()
    val engineName: String = engine.name

    init {
        EngineRegistry.register(engine)
    }

    /** Whether [dataset] has a local data source: a seed, for `CRLITE`. */
    fun hasLocalSource(dataset: Dataset): Boolean = dataset == Dataset.CRLITE && seed != null

    /** Whether [dataset] has a fetching source: a Remote Settings source with a collection for it. */
    fun hasFetchingSource(dataset: Dataset): Boolean = remoteSettings?.collection(dataset) != null

    /** Whether a CRLite source is configured, a seed included. */
    val hasCrliteSource: Boolean get() = hasLocalSource(Dataset.CRLITE) || hasFetchingSource(Dataset.CRLITE)
}

/** The spec §4 R checks that read the builder alone, in the order `Revokt.Builder.build()` documents them. */
private fun requireBuildable(builder: Revokt.Builder) {
    // A seed counts, and so does the default bundled() seed, which cannot be resolved without a channel.
    val crliteSource = builder.remoteSettings != null || builder.seed?.isNone != true
    require(builder.channel != null || !crliteSource) {
        "${DiagnosticCode.CHANNEL_UNSET}: a CRLite source is configured (a seed counts, the default " +
            "SeedSource.bundled() included) and no channel is: set channel(CrliteChannel.COMPAT) or DEFAULT, or " +
            "configure seed(SeedSource.none()) and no remote settings (spec §4)"
    }
    builder.remoteSettings?.let { source ->
        requireSourceUrl("remoteSettings.baseUrl", source.baseUrl)
        source.attachmentBaseUrl?.let { requireSourceUrl("remoteSettings.attachmentBaseUrl", it) }
    }
    requireCap("maxFilterBytes", builder.maxFilterBytes, RevoktLimits.MAX_FILTER_BYTES)
    requireCap("maxJsonBytes", builder.maxJsonBytes, RevoktLimits.MAX_JSON_BYTES)
    requireCap("maxX5uBytes", builder.maxX5uBytes, RevoktLimits.MAX_X5U_BYTES)
    requireCap("maxChangesetRecords", builder.maxChangesetRecords.toLong(), RevoktLimits.MAX_CHANGESET_RECORDS.toLong())
    require(builder.pkixFallback || builder.policy.outcome(Rule.NO_ISSUER) != Outcome.ALLOW) {
        "pkixFallback(false) with a policy whose NO_ISSUER outcome is ALLOW: the PKIX fallback is load-bearing " +
            "there, so a chain the walker cannot build would pass unchecked; keep the fallback, or reject NO_ISSUER " +
            "(spec §4, §5.1)"
    }
}

/**
 * A source URL (spec §4): `https` (any case) with a host, no userinfo, no query or fragment, and a port from 1 to
 * 65535 or none, read by `java.net.URI`. That is what the default fetch path accepts: the client joins each request's
 * path to the base and hands the result to `JdkHttpFetcher`, which parses it with `java.net.URI` and fetches `https`
 * only, so a URL refused here would build and then fail every sync. A query or a fragment would swallow the joined
 * path. A message names the field and the rule that failed, never the URL or any part of it: a rejected URL may
 * carry credentials (userinfo, or a token in a query) that would otherwise reach the exception and the app's logs. Nor
 * does it chain the parser's exception, whose message holds the input. An opaque or authority-less URI is refused
 * first, before any part of it is read.
 */
internal fun requireSourceUrl(
    what: String,
    url: String,
) {
    val uri =
        try {
            URI(url)
        } catch (
            // Not chained on purpose: the parser's message holds the URL, credentials included.
            @Suppress("SwallowedException") e: URISyntaxException,
        ) {
            throw IllegalArgumentException("$what is not a URL (spec §4): ${e.reason} at index ${e.index}")
        }
    val authority = uri.rawAuthority
    require(authority != null) { "$what has no authority, so no host: not an https://host URL (spec §4)" }
    require('@' !in authority) { "$what has userinfo, which a source URL never carries (spec §4)" }
    require("https".equals(uri.scheme, ignoreCase = true)) { "$what is not an https URL (spec §4)" }
    // A registry-based authority has no URI host. With a non-numeric port the fetch's URL parse fails; with an
    // underscore or another character outside a DNS name it parses, but public CAs issue no certificate for such a
    // name (CA/Browser Forum, since 2019), so the fetch would fail its host check on every sync.
    require(uri.host != null) {
        "$what has no server host: the authority is not a DNS name or IP literal with an optional numeric port (spec §4)"
    }
    require(uri.port == -1 || uri.port in 1..MAX_PORT) {
        "$what has port ${uri.port}, outside 1 to $MAX_PORT (spec §4)"
    }
    require(uri.rawQuery == null && uri.rawFragment == null) {
        "$what has a query or a fragment, which the request path joined to it would end up in (spec §4)"
    }
}

private const val MAX_PORT = 65_535

/** A cap is raisable only (spec §4 `limits { }`): a value below its `RevoktLimits` constant throws. */
private fun requireCap(
    name: String,
    value: Long,
    floor: Long,
) {
    require(
        value >= floor,
    ) { "$name is $value, below its RevoktLimits default $floor: caps can only be raised (spec §4)" }
}

/**
 * Every engine that went into a `Revokt` in this process (spec §3.2: "an engine instance may be injected into one
 * Revokt only"), held weakly and compared by identity, so an engine's own `equals` cannot let one through.
 */
internal object EngineRegistry {
    private val engines = ArrayList<WeakReference<RevocationEngine>>()

    /** Registers [engine]; throws [IllegalArgumentException] when it is already registered. */
    fun register(engine: RevocationEngine) {
        synchronized(engines) {
            engines.removeAll { it.get() == null }
            require(engines.none { it.get() === engine }) {
                "this RevocationEngine is already in another Revokt, which owns and closes it: an engine instance " +
                    "goes into one Revokt only (spec §3.2)"
            }
            engines.add(WeakReference(engine))
        }
    }
}
