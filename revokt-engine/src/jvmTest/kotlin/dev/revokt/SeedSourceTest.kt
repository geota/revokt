// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.Source
import okio.buffer
import java.io.ByteArrayInputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame

/** The JVM's `SeedSource` factories as spec §4 declares them (#111): the two class loaders in order, and re-opening. */
@OptIn(RevoktInternalApi::class)
class SeedSourceTest {
    /**
     * A class loader that serves only [resources], as files under its own directory in [root], and records every name
     * asked for. A name in [unreadable] is reported present, but its file does not exist, so opening it throws.
     */
    private class MapLoader(
        root: Path,
        private val resources: Map<String, ByteArray>,
        private val unreadable: Set<String> = emptySet(),
    ) : ClassLoader(null) {
        private val dir: Path = Files.createTempDirectory(root, "loader")
        val asked = mutableListOf<String>()

        init {
            for ((name, bytes) in resources) {
                val file = dir.resolve(name)
                Files.createDirectories(file.parent)
                Files.write(file, bytes)
            }
        }

        // A file URL, never a network one.
        override fun findResource(name: String) =
            dir
                .resolve(
                    name,
                ).takeIf { name in resources || name in unreadable }
                ?.toUri()
                ?.toURL()
                .also { asked += name }
    }

    /** Runs [block] over a fresh temporary directory, deleted afterwards. */
    private fun withRoot(block: (Path) -> Unit) {
        val root = Files.createTempDirectory("revokt-seed")
        try {
            block(root)
        } finally {
            root.toFile().deleteRecursively()
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
    fun `fromResource falls back to the thread context loader, captured when the source is created`() =
        withRoot { root ->
            val context = MapLoader(root, mapOf("revokt/test/seed.zip" to seed))
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
    fun `fromResource asks SeedSource's own class loader first`() =
        withRoot { root ->
            // A name SeedSource's loader has (its own class file), served differently by the context loader.
            val name = "dev/revokt/SeedSource.class"
            val context = MapLoader(root, mapOf(name to seed))
            val bytes = assertNotNull(withContextLoader(context) { SeedSource.fromResource("/$name") }.open().bytes())
            assertContentEquals(
                byteArrayOf(0xCA.toByte(), 0xFE.toByte(), 0xBA.toByte(), 0xBE.toByte()),
                bytes.copyOf(4),
            )
            assertEquals(emptyList(), context.asked)
        }

    @Test
    fun `a resource opens in loader order, and an absent one opens null`() =
        withRoot { root ->
            val first = MapLoader(root, mapOf("a" to byteArrayOf(1)))
            val second = MapLoader(root, mapOf("a" to byteArrayOf(2), "b" to byteArrayOf(3)))
            val loaders = listOf(first, second)
            assertContentEquals(byteArrayOf(1), ResourceOpening("a", loaders).open().bytes())
            assertEquals(emptyList(), second.asked)
            assertContentEquals(byteArrayOf(3), ResourceOpening("b", loaders).open().bytes())
            assertNull(ResourceOpening("c", loaders).open())
            assertEquals(listOf("a", "b", "c"), first.asked)
            assertNull(
                withContextLoader(
                    MapLoader(root, emptyMap()),
                ) { SeedSource.fromResource("/revokt/test/absent.zip") }.open(),
            )
        }

    @Test
    fun `bundled resolves to the channel's resource through the class loaders, and to no source without one`() =
        withRoot { root ->
            val context = MapLoader(root, mapOf("revokt/seed-compat.zip" to seed))
            val bundled = withContextLoader(context) { SeedSource.bundled() }
            // Opened before a channel is known, it throws: an unreadable seed, never a silent "no seed".
            assertFailsWith<IllegalStateException> { bundled.open() }
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
            val first = MapLoader(root, mapOf("revokt/seed-default.zip" to byteArrayOf(1)))
            val second = MapLoader(root, mapOf("revokt/seed-default.zip" to byteArrayOf(2)))
            val resolved = assertNotNull(BundledOpening(listOf(first, second)).resolve(CrliteChannel.DEFAULT))
            assertContentEquals(byteArrayOf(1), resolved.open().bytes())
            assertEquals(emptyList(), second.asked)
        }

    @Test
    fun `a resource that is present but unreadable throws rather than opening null`() =
        withRoot { root ->
            val loader = MapLoader(root, emptyMap(), unreadable = setOf("revokt/seed-compat.zip"))
            assertFailsWith<IOException> { ResourceOpening("revokt/seed-compat.zip", listOf(loader)).open() }
            // Present, so bundled() resolves to it, and the open then throws.
            val compat = assertNotNull(BundledOpening(listOf(loader)).resolve(CrliteChannel.COMPAT))
            assertFailsWith<IOException> { compat.open() }
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
