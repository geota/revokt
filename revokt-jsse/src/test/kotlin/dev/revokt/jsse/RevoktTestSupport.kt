// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.jsse

import dev.revokt.CrliteChannel
import dev.revokt.MozillaRemoteSettings
import dev.revokt.RevoktInternalApi
import dev.revokt.SeedSource
import java.nio.file.Files
import java.nio.file.Path

/** A seed source that counts as local data whatever it opens (the builder never opens it). */
internal val SOME_SEED: SeedSource = SeedSource.fromResource("/revokt/test/absent-seed.zip")

/** Mozilla's source with [baseUrl] and a pinned [attachmentBaseUrl]. */
internal fun remoteSettings(
    baseUrl: String = "https://firefox.settings.services.mozilla.com/v1",
    attachmentBaseUrl: String? = null,
): MozillaRemoteSettings =
    MozillaRemoteSettings.DEFAULT
        .newBuilder()
        .baseUrl(baseUrl)
        .attachmentBaseUrl(attachmentBaseUrl)
        .build()

/** A builder with a channel and no seed, so it builds with nothing else configured. */
internal fun bare(): Revokt.Builder =
    Revokt
        .builder()
        .channel(CrliteChannel.COMPAT)
        .seed(SeedSource.none())

/** Runs [block] with a thread context class loader that serves [names] as (empty) resources from a temp directory. */
internal fun <T> withContextResources(
    names: Set<String>,
    block: () -> T,
): T {
    val dir = Files.createTempDirectory("revokt-139-loader")
    val thread = Thread.currentThread()
    val previous = thread.contextClassLoader
    try {
        for (name in names) {
            val file = dir.resolve(name)
            Files.createDirectories(file.parent)
            Files.write(file, ByteArray(0))
        }
        thread.contextClassLoader = DirLoader(dir, names)
        return block()
    } finally {
        thread.contextClassLoader = previous
        dir.toFile().deleteRecursively()
    }
}

private class DirLoader(
    private val dir: Path,
    private val names: Set<String>,
) : ClassLoader(null) {
    // A file URL, never a network one.
    override fun findResource(name: String) =
        dir
            .resolve(name)
            .takeIf { name in names }
            ?.toUri()
            ?.toURL()
}
