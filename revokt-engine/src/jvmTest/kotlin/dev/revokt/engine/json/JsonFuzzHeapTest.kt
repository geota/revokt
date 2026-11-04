// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.json

import dev.revokt.RevoktLimits
import java.io.File
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * [JsonFuzzTest]'s property on inputs at its `-max_len` bound, in a JVM with the §9.1 harness heap (`-Xmx256m`):
 * adversarial shapes up to `RevoktLimits.MAX_JSON_BYTES` pass without an `OutOfMemoryError`, each within a generous
 * multiple of the measured time against the harness's `-timeout=10`.
 */
class JsonFuzzHeapTest {
    @Test
    fun `4 MiB adversarial inputs pass the fuzz property in 256 MiB`() {
        val java = File(System.getProperty("java.home"), "bin/java").path
        val process =
            ProcessBuilder(
                java,
                "-Xmx256m",
                "-cp",
                System.getProperty("java.class.path"),
                JsonFuzzHeapMain::class.java.name,
            ).redirectErrorStream(true)
                .start()
        val output = process.inputStream.bufferedReader().readText()
        assertTrue(process.waitFor(10, TimeUnit.MINUTES), output)
        println(output)
        assertEquals(0, process.exitValue(), output)
    }
}

/** The forked JVM of [JsonFuzzHeapTest]: exits non-zero on any finding or an input slower than [LIMIT_MILLIS]. */
object JsonFuzzHeapMain {
    /** Three times the harness's `-timeout=10`; the slowest shape takes under 3 s on the maintainer's machine. */
    private const val LIMIT_MILLIS = 30_000L

    @JvmStatic
    fun main(args: Array<String>) {
        val max = RevoktLimits.MAX_JSON_BYTES.toInt()
        for (item in listOf(
            "{\"a\":0}",
            "0",
            "\"é\"",
            "[".repeat(126) + "]".repeat(126),
            "5e-324",
            "1.7976931348623157e308",
            "4.9406564584124654e-324",
        )) {
            val input =
                generateSequence {
                    item
                }.take((max - 2) / (item.encodeToByteArray().size + 1)).joinToString(",", "[", "]").encodeToByteArray()
            check(input.size <= max)
            val start = System.nanoTime()
            JsonFuzzTest.fuzzerTestOneInput(input)
            val millis = (System.nanoTime() - start) / 1_000_000
            println("${item.take(16)}: ${input.size} bytes in $millis ms")
            check(millis < LIMIT_MILLIS) { "${item.take(16)} took $millis ms" }
        }
    }
}
