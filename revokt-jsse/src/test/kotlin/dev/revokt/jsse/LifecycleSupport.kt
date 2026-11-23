// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.jsse

import dev.revokt.AnchorSnapshot
import dev.revokt.PathBuilderFallback
import dev.revokt.PlatformTrust
import dev.revokt.RevoktInternalApi
import dev.revokt.SeedSource
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.security.cert.X509Certificate
import java.util.zip.CRC32
import javax.net.ssl.X509TrustManager

/** A platform trust whose delegate's `getAcceptedIssuers()` is [anchors] (the default trust store's state under test). */
internal class FakePlatformTrust(
    private val anchors: () -> List<X509Certificate>,
) : PlatformTrust {
    private val delegate =
        object : X509TrustManager {
            override fun checkClientTrusted(
                chain: Array<out X509Certificate>?,
                authType: String?,
            ) = error("not used")

            override fun checkServerTrusted(
                chain: Array<out X509Certificate>?,
                authType: String?,
            ) = error("not used")

            override fun getAcceptedIssuers(): Array<X509Certificate> = anchors().toTypedArray()
        }

    override fun defaultDelegate(): X509TrustManager = delegate

    override fun requiresExtendedDelegate(): Boolean = true

    override fun verifiedChain(
        delegate: X509TrustManager,
        chain: Array<X509Certificate>,
        host: String?,
    ): List<X509Certificate>? = null

    override fun pathBuilder(): PathBuilderFallback =
        object : PathBuilderFallback {
            override fun build(
                chainDer: List<ByteArray>,
                anchors: AnchorSnapshot,
                nowMillis: Long,
            ): List<ByteArray>? = null
        }

    override fun anchors(delegate: X509TrustManager): List<X509Certificate> = delegate.acceptedIssuers.toList()
}

/**
 * A seed archive's fixed entries with `seed.json` [header] first and the other four as placeholder bytes, all stored:
 * enough for `start()`'s synchronous header read (spec §5.1), never for a load, which fails its signature check.
 */
internal fun headerSeed(
    channel: String = "COMPAT",
    filterFormat: String = "V3",
): ByteArray {
    val header =
        """{"seedFormat":1,"channel":"$channel","dataset":"CRLITE","filterFormat":"$filterFormat",""" +
            """"recordsLastModified":1792587631204,"engineFloor":1}"""
    return storedZip(
        listOf(
            "seed.json" to header.encodeToByteArray(),
            "records.json" to "{}".encodeToByteArray(),
            "signature" to "x".encodeToByteArray(),
            "x5u.pem" to "x".encodeToByteArray(),
            "index.bin" to ByteArray(2),
        ),
    )
}

/** A zip of [entries], each stored (no compression, no data descriptor), in order. */
internal fun storedZip(entries: List<Pair<String, ByteArray>>): ByteArray {
    val out = Le()
    val offsets = ArrayList<Int>()
    for ((name, data) in entries) {
        offsets += out.size
        out
            .int(LOCAL)
            .short(VERSION)
            .short(0)
            .short(0)
            .int(0)
            .sizes(data)
        out
            .short(name.length)
            .short(0)
            .bytes(name.encodeToByteArray())
            .bytes(data)
    }
    val start = out.size
    entries.forEachIndexed { i, (name, data) ->
        out
            .int(CENTRAL)
            .short(VERSION)
            .short(VERSION)
            .short(0)
            .short(0)
            .int(0)
            .sizes(data)
        out
            .short(
                name.length,
            ).short(0)
            .short(0)
            .short(0)
            .short(0)
            .int(0)
            .int(offsets[i])
            .bytes(name.encodeToByteArray())
    }
    val size = out.size - start
    out
        .int(END)
        .short(0)
        .short(0)
        .short(entries.size)
        .short(entries.size)
        .int(size)
        .int(start)
        .short(0)
    return out.toByteArray()
}

/** Little-endian writes, as zip headers are. */
private class Le {
    private val out = ByteArrayOutputStream()
    val size: Int get() = out.size()

    fun short(v: Int): Le = apply { repeat(2) { out.write(v ushr (8 * it) and 0xff) } }

    fun int(v: Int): Le = apply { repeat(4) { out.write(v ushr (8 * it) and 0xff) } }

    fun bytes(b: ByteArray): Le = apply { out.write(b) }

    fun sizes(data: ByteArray): Le = int(CRC32().also { it.update(data) }.value.toInt()).int(data.size).int(data.size)

    fun toByteArray(): ByteArray = out.toByteArray()
}

private const val LOCAL = 0x04034b50
private const val CENTRAL = 0x02014b50
private const val END = 0x06054b50
private const val VERSION = 20

/** A seed source over [bytes] that runs [onOpen] on the opening thread first, and counts its opens. */
internal class ScriptedSeed(
    private val bytes: () -> ByteArray?,
    private val onOpen: () -> Unit = {},
) {
    @Volatile
    var opens = 0
        private set

    @Volatile
    var openedOn: Thread? = null
        private set

    val source: SeedSource =
        SeedSource.of {
            opens++
            openedOn = Thread.currentThread()
            onOpen()
            bytes()?.let { ByteArrayInputStream(it) as InputStream }
        }
}
