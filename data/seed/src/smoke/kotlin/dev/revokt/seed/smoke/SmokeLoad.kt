// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.seed.smoke

import dev.revokt.CrliteChannel
import dev.revokt.Enforcement
import dev.revokt.HttpFetcher
import dev.revokt.KotlinRevocationEngine
import dev.revokt.MozillaRemoteSettings
import dev.revokt.PreparedGeneration
import dev.revokt.RevocationEngine
import dev.revokt.SeedSource
import dev.revokt.jsse.Revokt
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.system.exitProcess

/**
 * The seed jar's smoke load (#145; `smokeLoadSeed<Channel>`): `--channel compat|default`. A `Revokt` on the class path
 * of revokt-jsse and the seed jar alone, through the public builder plus the `@RevoktInternalApi` engine seam (an engine
 * that records the generation it activates), in the sole-seed `ENFORCE` configuration (the
 * bundled seed, no fetching source, so `MozillaRemoteSettings.DEFAULT`'s pins and no network): `start()` throws on a seed
 * that is absent or unreadable, and the engine must then hold the seed's generation. Exit 0 on success, 1 otherwise.
 */
fun main(args: Array<String>) {
    val channel = channelOf(args.toList()).takeIf { args.size == 2 } ?: usage("--channel compat|default")
    exitProcess(smokeLoad(channel) { })
}

/**
 * The check path's smoke load (`smokeLoadTestSeed`): `--channel compat --pin-file <file>`, the seed jar built from the
 * committed test-signed fixture. The test root is pinned on a configured Remote Settings source (a seed's x5u chain
 * ends in the configured source's pins), whose fetcher fails every request, so nothing reaches the network and the
 * first sync fails; the seed must still be the generation the engine holds.
 */
object TestPinSmokeLoad {
    @JvmStatic
    fun main(args: Array<String>) {
        val list = args.toList()
        val channel = channelOf(list.take(2)) ?: usage("--channel compat --pin-file <file>")
        if (list.size != 4 || list[2] != "--pin-file") usage("--channel compat --pin-file <file>")
        val pin =
            Files
                .readString(Path.of(list[3]))
                .trim()
                .chunked(2)
                .map { it.toInt(16).toByte() }
                .toByteArray()
        val source =
            MozillaRemoteSettings.DEFAULT
                .newBuilder()
                .pinnedRootSpkiSha256s(listOf(pin))
                .build()
        exitProcess(
            smokeLoad(channel) {
                remoteSettings(source)
                http(HttpFetcher { throw IOException("the smoke load never fetches") })
            },
        )
    }
}

/** Starts a `Revokt` on the bundled seed of [channel], configured by [configure]; 0 when the seed is live. */
fun smokeLoad(
    channel: CrliteChannel,
    configure: Revokt.Builder.() -> Unit,
): Int {
    if (SeedSource.bundled().resolve(channel) == null) {
        System.err.println("smoke: no /revokt/seed-${channel.name.lowercase()}.zip on the class path")
        return 1
    }
    val engine = Recording(KotlinRevocationEngine())
    val revokt =
        Revokt
            .builder()
            .channel(channel)
            .seed(SeedSource.bundled())
            .enforcement(Enforcement.ENFORCE)
            .revocationEngine(engine)
            .apply(configure)
            .build()
    return revokt.use {
        try {
            it.start()
        } catch (e: IllegalStateException) {
            System.err.println("smoke: start() refused the seed: ${e.message}")
            return 1
        }
        if (!engine.activated.await(AWAIT_SECONDS, TimeUnit.SECONDS)) {
            System.err.println("smoke: no generation became live within $AWAIT_SECONDS s")
            return 1
        }
        val id = engine.live
        System.err.println("smoke: the seed is live: $id")
        if (id == null || !Regex("""\d+/.+""").matches(id)) 1 else 0
    }
}

/** An engine that records the generation it activates, delegating everything to [inner]. */
private class Recording(
    private val inner: RevocationEngine,
) : RevocationEngine by inner {
    val activated = CountDownLatch(1)

    @Volatile
    var live: String? = null

    override fun activate(prepared: PreparedGeneration) {
        inner.activate(prepared)
        live = prepared.generationId
        activated.countDown()
    }
}

private fun channelOf(args: List<String>): CrliteChannel? =
    if (args.size >= 2 &&
        args[0] == "--channel"
    ) {
        CrliteChannel.entries.firstOrNull { it.name.lowercase() == args[1] }
    } else {
        null
    }

private fun usage(text: String): Nothing {
    System.err.println("usage: $text")
    exitProcess(2)
}

private const val AWAIT_SECONDS = 60L
