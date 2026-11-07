// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.Source
import okio.source
import java.net.URL

/**
 * The JVM's [SeedSource] (spec §4): the common [none] plus [of], [fromResource] and [bundled]; a file is
 * `JvmSeedSource.fromPath`. A resource is looked up through `SeedSource`'s own class loader, then the thread context
 * class loader captured when the source is created (app servers), in that order, on every open.
 */
public actual class SeedSource internal actual constructor(
    private val opening: SeedOpening,
) {
    internal actual fun open(): Source? = opening.open()

    @RevoktInternalApi
    public actual fun resolve(channel: CrliteChannel): SeedSource? =
        opening.resolve(channel)?.let { if (it === opening) this else SeedSource(it) }

    public actual companion object {
        @JvmStatic
        public actual fun none(): SeedSource = SeedSource { null }

        /**
         * The archive [opener] opens, re-opened on every start task and seed re-check (an asset pack, a downloaded
         * seed). A null stream means there is no archive to open.
         */
        @JvmStatic
        public fun of(opener: SeedOpener): SeedSource = SeedSource { opener.open()?.source() }

        /**
         * The class-path resource [path] (`/revokt/seed-compat.zip`; a leading `/` is optional, since a class loader
         * reads every name from the root). Absent from both class loaders, it opens null; present but unreadable, it
         * throws.
         */
        @JvmStatic
        public fun fromResource(path: String): SeedSource =
            SeedSource(ResourceOpening(path.removePrefix("/"), loaders()))

        /**
         * The seed artifact on the class path, `/revokt/seed-<channel>.zip` from `revokt-seed-<channel>` (spec §6.5),
         * resolved for the configured channel when the `Revokt` is built; with no such resource there is no seed
         * source. The default when no seed is configured. Opened before it is resolved, it throws
         * [IllegalStateException].
         */
        @JvmStatic
        public fun bundled(): SeedSource = SeedSource(BundledOpening(loaders()))

        private fun loaders(): List<ClassLoader> =
            listOfNotNull(SeedSource::class.java.classLoader, Thread.currentThread().contextClassLoader).distinct()
    }
}

/**
 * A class-path resource, looked up in [loaders] in order on every open. Presence is `getResource`, and the stream is the
 * URL's own, so a resource that is present but cannot be read throws (an unreadable seed) rather than opening null.
 */
internal class ResourceOpening(
    private val name: String,
    private val loaders: List<ClassLoader>,
) : SeedOpening {
    // Not url.openStream(): on a jar: URL that caches the JarFile, which keeps the seed jar locked across an app
    // server's redeploys.
    override fun open(): Source? =
        url()
            ?.openConnection()
            ?.apply { useCaches = false }
            ?.getInputStream()
            ?.source()

    private fun url(): URL? = loaders.firstNotNullOfOrNull { it.getResource(name) }

    /** Whether a class loader has the resource now. */
    fun exists(): Boolean = url() != null
}

/**
 * `SeedSource.bundled()` before a channel is known. Building the `Revokt` resolves it; opening it unresolved is a wiring
 * bug and throws, so it surfaces as an unreadable seed rather than as no seed.
 */
internal class BundledOpening(
    private val loaders: List<ClassLoader>,
) : SeedOpening {
    override fun open(): Source? =
        error("SeedSource.bundled() was opened before resolve(channel): resolve it for the configured channel first")

    override fun resolve(channel: CrliteChannel): SeedOpening? =
        ResourceOpening("revokt/seed-${channel.name.lowercase()}.zip", loaders).takeIf { it.exists() }
}
