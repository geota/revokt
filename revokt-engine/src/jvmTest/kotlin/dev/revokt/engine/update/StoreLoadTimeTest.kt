// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.engine.update

import dev.revokt.ClubcardCorpus
import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.FilterFormat
import dev.revokt.KotlinRevocationEngine
import dev.revokt.engine.store.GenerationFileJson
import dev.revokt.engine.store.InMemoryStorage
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import okio.Buffer
import okio.ByteString.Companion.toByteString
import org.junit.jupiter.api.Assumptions
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The measurement #287 asks for, not a gate: `start()`'s load of a stored generation (Load's steps 1 to 4, which
 * re-hash the file and every blob and decode every filter for `buildIndex`, then `prepare`, which decodes them again)
 * against §6.4's load columns. Run with `REVOKT_LOAD_TIME=1` in the environment (`--rerun`); it prints the medians, JIT-compiled in this JVM and
 * interpreted in a child JVM under `-Xint`, and writes them to `build/load-time.txt`.
 *
 * `compat` is the corpus's real 1.5 MB full filter beside 52 synthetic deltas of §6.4's measured mean size (134 KB);
 * `default` is wholly synthetic (a 6 MB full and 52 deltas of 242 KB), since no default filter is committed and the
 * coordinator ruled out a live fetch. A synthetic v4 filter is ribbon columns of the right size, so its decode is the
 * bulk `LongArray` read that dominates a real one's.
 */
internal class StoreLoadTimeTest {
    @Test
    fun `the load of a stored generation, against the load columns of section 6_4`() {
        Assumptions.assumeTrue(
            System.getenv("REVOKT_LOAD_TIME") == "1",
            "run with REVOKT_LOAD_TIME=1 in the environment",
        )
        val jit = StoreLoadTime.measure(warmups = 5, runs = 10)
        val java = File(System.getProperty("java.home"), "bin/java").path
        val child =
            ProcessBuilder(
                java,
                "-Xint",
                "-Drevokt.clubcardCorpus=" + System.getProperty("revokt.clubcardCorpus"),
                "-cp",
                System.getProperty("java.class.path"),
                StoreLoadTime::class.java.name,
            ).redirectErrorStream(true)
                .start()
        val interpreted = child.inputStream.bufferedReader().readText()
        assertEquals(0, child.waitFor(), interpreted)
        val report =
            "JIT-compiled (median of 10 after 5 warm-ups):\n$jit\n" +
                "interpreted, -Xint (median of 3 after 1):\n$interpreted"
        println(report)
        File("build/load-time.txt").writeText(report)
    }
}

/** The measurement itself, also a `main` for the interpreted child JVM. */
internal object StoreLoadTime {
    @JvmStatic
    fun main(args: Array<String>) {
        print(measure(warmups = 1, runs = 3))
    }

    /** One line per channel: the median of [runs] loads after [warmups], split into Load and `prepare`. */
    fun measure(
        warmups: Int,
        runs: Int,
    ): String =
        buildString {
            val compatFull = ClubcardCorpus.file(UpdateFixtures.FULL_PATH).readBytes()
            for ((channel, full, deltaWords) in listOf(
                Triple(CrliteChannel.COMPAT, compatFull, 134_000 / 64),
                Triple(CrliteChannel.DEFAULT, synthetic(6_000_000 / 64, 1), 242_000 / 64),
            )) {
                val (store, name, bytes) = stored(channel, full, deltaWords)
                var loads = LongArray(0)
                var prepares = LongArray(0)
                var hashes = LongArray(0)
                repeat(warmups + runs) { i ->
                    val h0 = System.nanoTime()
                    val g = (store.stored(name) as StoreRead.Found).value
                    check(store.blobsMatch(g))
                    val t0 = System.nanoTime()
                    val loaded = (store.load(name) as GenerationLoad.Loaded).value
                    val t1 = System.nanoTime()
                    KotlinRevocationEngine().prepare(loaded.files).close()
                    val t2 = System.nanoTime()
                    if (i >= warmups) {
                        hashes += t0 - h0
                        loads += t1 - t0
                        prepares += t2 - t1
                    }
                }
                val load = ms(loads, runs)
                val prepare = ms(prepares, runs)
                val hash = ms(hashes, runs)
                val total = "%.1f".format(load + prepare)
                append(
                    "  ${channel.name.lowercase()}: $total ms over ${bytes / 1_000} KB: Load ${"%.1f".format(
                        load,
                    )} ms ",
                )
                append(
                    "(steps 1 to 3, the re-hashes, ${"%.1f".format(hash)} ms), prepare ${"%.1f".format(prepare)} ms\n",
                )
            }
        }

    /** The median of [samples], in milliseconds. */
    private fun ms(
        samples: LongArray,
        runs: Int,
    ): Double = samples.sorted()[runs / 2] / 1_000_000.0

    /** A store holding one generation of [full] and 52 synthetic deltas of [deltaWords] words a column. */
    private fun stored(
        channel: CrliteChannel,
        full: ByteArray,
        deltaWords: Int,
    ): Triple<StoreLayout, String, Long> {
        val store = StoreLayout(InMemoryStorage(), Dataset.CRLITE, channel)
        val wire = channel.wireName
        val records = ArrayList<FilterRecord>()
        val bodies = LinkedHashMap<String, ByteArray>()
        records += FilterRecord("full", wire, false, 1, "full.filter")
        bodies["full.filter"] = full
        for (i in 1..DELTAS) {
            records += FilterRecord("delta-%02d".format(i), wire, true, 1L + i, "delta-$i.filter.delta")
            bodies["delta-$i.filter.delta"] = synthetic(deltaWords, i + 1)
        }
        val json = UpdateFixtures.recordsJson(records, bodies)
        val format = if (full[0].toInt() == 3) FilterFormat.V3 else FilterFormat.V4
        val pending = UpdateFixtures.pending(store, records, bodies, format = format, json = json)
        val name = store.putGeneration(GenerationFileJson.write(pending.file))
        return Triple(store, name, bodies.values.sumOf { it.size.toLong() })
    }

    /**
     * A v4 clubcard (spec §6.3) of [RANK] ribbon columns of [words] words each, split over [BLOCKS] blocks: the shape of a
     * real filter's bulk, at a chosen size. Its coverage is one log, so [buildIndex] has a window to read.
     */
    private fun synthetic(
        words: Int,
        logIndex: Int,
    ): ByteArray {
        val b = Buffer().writeByte(4).writeByte(0)
        b.writeShort(1)
        b.write(UpdateFixtures.log(logIndex)).writeLong(1_000L).writeLong(2_000L)
        b.writeInt(BLOCKS)
        val per = words / BLOCKS
        for (k in 0 until BLOCKS) {
            val id =
                ByteArray(32).also {
                    it[0] = (k ushr 8).toByte()
                    it[1] = k.toByte()
                }
            b.write(id.toByteString())
            b.writeInt(per).writeByte(RANK).writeInt(k * per)
            b.writeInt(0).writeInt(0).writeByte(0)
            b.writeShort(0)
        }
        b.writeByte(RANK)
        repeat(RANK) { c ->
            b.writeInt(words)
            for (w in 0 until words) b.writeLong(w.toLong() * 0x9E3779B97F4A7C15uL.toLong() + c)
        }
        b.writeInt(0)
        return b.readByteArray()
    }

    private const val DELTAS = 52
    private const val RANK = 8
    private const val BLOCKS = 256
}
