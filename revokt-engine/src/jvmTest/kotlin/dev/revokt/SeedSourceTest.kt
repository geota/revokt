// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.Source
import okio.buffer
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame

/** The JVM's `SeedSource` factories as spec §4 declares them (#111): the two class loaders in order, and re-opening. */
@OptIn(RevoktInternalApi::class)
class SeedSourceTest {
    /** A class loader that serves only [resources], by name, and records every name asked for. */
    private class MapLoader(
        private val resources: Map<String, ByteArray>,
    ) : ClassLoader(null) {
        val asked = mutableListOf<String>()

        override fun getResourceAsStream(name: String): InputStream? {
            asked += name
            return resources[name]?.let(::ByteArrayInputStream)
        }
    }

    private fun <T> withContextLoader(
        loader: ClassLoader,
        block: () -> T,
    ): T {
        val thread = Thread.currentThread()
        val saved = thread.contextClassLoader
        thread.contextClassLoader = loader
        try {
            return block()
        } finally {
            thread.contextClassLoader = saved
        }
    }

    private fun Source?.bytes(): ByteArray? = this?.buffer()?.use { it.readByteArray() }

    private val seed = byteArrayOf(0x50, 0x4b, 3, 4)

    @Test
    fun `fromResource falls back to the thread context loader, captured when the source is created`() {
        val context = MapLoader(mapOf("revokt/test/seed.zip" to seed))
        val source = withContextLoader(context) { SeedSource.fromResource("/revokt/test/seed.zip") }
        // Opened outside: the context loader of the creating thread is the one asked.
        assertContentEquals(seed, source.open().bytes())
        assertEquals(listOf("revokt/test/seed.zip"), context.asked)
        // A leading '/' is optional: a class loader reads every name from the root.
        assertContentEquals(
            seed,
            withContextLoader(context) { SeedSource.fromResource("revokt/test/seed.zip") }.open().bytes(),
        )
    }

    @Test
    fun `fromResource asks SeedSource's own class loader first`() {
        // A name SeedSource's loader has (its own class file), served differently by the context loader.
        val name = "dev/revokt/SeedSource.class"
        val context = MapLoader(mapOf(name to seed))
        val bytes = assertNotNull(withContextLoader(context) { SeedSource.fromResource("/$name") }.open().bytes())
        assertContentEquals(byteArrayOf(0xCA.toByte(), 0xFE.toByte(), 0xBA.toByte(), 0xBE.toByte()), bytes.copyOf(4))
        assertEquals(emptyList(), context.asked)
    }

    @Test
    fun `a resource opens in loader order, and an absent one opens null`() {
        val first = MapLoader(mapOf("a" to byteArrayOf(1)))
        val second = MapLoader(mapOf("a" to byteArrayOf(2), "b" to byteArrayOf(3)))
        val loaders = listOf(first, second)
        assertContentEquals(byteArrayOf(1), ResourceOpening("a", loaders).open().bytes())
        assertEquals(emptyList(), second.asked)
        assertContentEquals(byteArrayOf(3), ResourceOpening("b", loaders).open().bytes())
        assertNull(ResourceOpening("c", loaders).open())
        assertEquals(listOf("a", "b", "c"), first.asked)
        assertNull(
            withContextLoader(MapLoader(emptyMap())) { SeedSource.fromResource("/revokt/test/absent.zip") }.open(),
        )
    }

    @Test
    fun `bundled resolves to the channel's resource through the class loaders, and to no source without one`() {
        val context = MapLoader(mapOf("revokt/seed-compat.zip" to seed))
        val bundled = withContextLoader(context) { SeedSource.bundled() }
        // Before a channel is known it opens nothing.
        assertNull(bundled.open())
        val compat = assertNotNull(bundled.resolve(CrliteChannel.COMPAT))
        assertContentEquals(seed, compat.open().bytes())
        assertSame(compat, compat.resolve(CrliteChannel.DEFAULT))
        // The test class path carries no seed artifact, so DEFAULT has no resource in either loader.
        assertNull(bundled.resolve(CrliteChannel.DEFAULT))
        assertEquals(
            listOf("revokt/seed-compat.zip", "revokt/seed-compat.zip", "revokt/seed-default.zip"),
            context.asked,
        )
        // The channel's resource, in loader order.
        val first = MapLoader(mapOf("revokt/seed-default.zip" to byteArrayOf(1)))
        val second = MapLoader(mapOf("revokt/seed-default.zip" to byteArrayOf(2)))
        val resolved = assertNotNull(BundledOpening(listOf(first, second)).resolve(CrliteChannel.DEFAULT))
        assertContentEquals(byteArrayOf(1), resolved.open().bytes())
        assertEquals(emptyList(), second.asked)
    }

    @Test
    fun `none opens null and resolves to itself, and every other source resolves to itself`() {
        val none = SeedSource.none()
        assertNull(none.open())
        for (channel in CrliteChannel.entries) assertSame(none, none.resolve(channel))
        val resource = SeedSource.fromResource("/revokt/test/absent.zip")
        assertSame(resource, resource.resolve(CrliteChannel.COMPAT))
        val of = SeedSource.of { null }
        assertSame(of, of.resolve(CrliteChannel.DEFAULT))
    }

    @Test
    fun `of re-opens its opener on every open`() {
        var opens = 0
        val source =
            SeedSource.of {
                opens++
                if (opens == 2) null else ByteArrayInputStream(byteArrayOf(opens.toByte()))
            }
        assertContentEquals(byteArrayOf(1), source.open().bytes())
        assertNull(source.open())
        assertContentEquals(byteArrayOf(3), source.open().bytes())
        assertEquals(3, opens)
    }

    @Test
    fun `fromPath re-opens the file, so a replaced archive is picked up, and a missing file opens null`() {
        val dir: Path = Files.createTempDirectory("revokt-seed")
        try {
            val file = dir.resolve("seed-compat.zip")
            val source = JvmSeedSource.fromPath(file)
            assertNull(source.open())
            Files.write(file, seed)
            assertContentEquals(seed, source.open().bytes())
            Files.write(file, byteArrayOf(9))
            assertContentEquals(byteArrayOf(9), source.open().bytes())
            assertSame(source, source.resolve(CrliteChannel.COMPAT))
        } finally {
            dir.toFile().deleteRecursively()
        }
    }
}
