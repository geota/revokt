// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.json

import dev.revokt.engine.parse.producer.ExternalCorpus
import java.io.File
import java.util.Base64
import java.util.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Spec §6.5's allocation budget for JSON (#99): at most 4·len + 64 KiB on Remote Settings data and at most
 * 20·len + 64 KiB on any input, measured as [JsonBudget] states. The parser retains nothing across calls but
 * constants, so each measured parse carries every buffer it uses.
 */
class JsonAllocationTest {
    @BeforeTest
    fun warmUp() {
        assertTrue(JsonBudget.supported, "spec §6.5 measures with HotSpot's per-thread allocation counter")
        JsonBudget.warmUp()
    }

    /** The bytes one parse of [input] allocates, a rejected input included. */
    private fun allocated(input: ByteArray): Long =
        JsonBudget
            .allocated {
                try {
                    Json.parse(input, maxBytes = Long.MAX_VALUE)
                } catch (_: JsonParseException) {
                    // A rejection is a result; its allocation counts as well.
                }
            }.second

    private fun within(
        factor: Int,
        name: String,
        input: ByteArray,
        report: Boolean = true,
    ) {
        val bytes = allocated(input)
        if (report) {
            println(
                "JSON allocation: $name, ${input.size} bytes, %.2f·len".format(bytes.toDouble() / input.size),
            )
        }
        assertTrue(bytes <= JsonBudget.bound(factor, input.size), "$name allocated $bytes bytes for ${input.size}")
    }

    private fun resource(name: String): ByteArray =
        checkNotNull(
            javaClass.getResourceAsStream("/dev/revokt/engine/json/$name"),
        ) { "missing $name" }.use { it.readBytes() }

    /** About 1 MiB of [item], comma-separated in an array. */
    private fun array(item: String): ByteArray =
        generateSequence { item }
            .take((1 shl 20) / (item.encodeToByteArray().size + 1))
            .joinToString(",", "[", "]")
            .encodeToByteArray()

    @Test
    fun `Remote Settings data stays within 4·len + 64 KiB`() {
        within(4, "crlite-changeset.json", resource("crlite-changeset.json"))
        val dir = ExternalCorpus.dir ?: return println("JSON allocation: no large corpus on this run (-Prevokt.corpus)")
        val file = "issuer/mozilla-intermediates/changeset.json"
        within(4, file, File(dir, file).readBytes())
    }

    @Test
    fun `every replay input stays within 20·len + 64 KiB`() {
        val dir = File(checkNotNull(javaClass.getResource("/dev/revokt/engine/json/JsonFuzzTestInputs")).toURI())
        val inputs = checkNotNull(dir.listFiles()).sortedBy { it.name }
        for (f in inputs) within(20, "JsonFuzzTestInputs/${f.name}", f.readBytes())
        val vectors =
            resource("canonical-json.tsv").decodeToString().lines().filter { it.isNotEmpty() && !it.startsWith("#") }
        for (line in vectors) {
            val (name, input) = line.split("\t")
            within(20, "canonical-json $name", Base64.getDecoder().decode(input), report = false)
        }
        println(
            "JSON allocation: ${inputs.size} fuzz inputs and ${vectors.size} canonical-json vectors within 20·len + 64 KiB",
        )
    }

    @Test
    fun `adversarial shapes stay within 20·len + 64 KiB`() {
        for (item in listOf(
            "{\"a\":0}",
            "0",
            "1.5",
            "\"é\"",
            "[".repeat(126) + "]".repeat(126),
            "5e-324",
            "1.7976931348623157e308",
            "{\"a\":{\"b\":[1]}}",
            "\"\\n\"",
            "\"\\\"\"",
            "\"\\\\\"",
            "\"\\t\"",
            "{\"\\n\":0}",
        )) {
            within(20, item.take(16), array(item))
        }
        // Distinct numbers outside the exact fast path: large, small, tiny and subnormal.
        val rng = Random(92)

        fun digits16() = rng.nextLong(10_000_000_000_000_000L).toString().padStart(16, '0')
        for ((name, number) in listOf<Pair<String, () -> String>>(
            "17 digits e300" to { "1.${digits16()}e300" },
            "17 digits e-5" to { "1.${digits16()}e-5" },
            "6 digits e-40" to { "${100_000 + rng.nextInt(900_000)}e-40" },
            "17 digits e-320" to { "4.${digits16()}e-320" },
        )) {
            within(
                20,
                name,
                generateSequence { number() }.take((1 shl 20) / 24).joinToString(",", "[", "]").encodeToByteArray(),
            )
        }
        var i = 0
        within(
            20,
            "distinct keys",
            generateSequence {
                "\"k${i++}\":0"
            }.take(100_000).joinToString(",", "{", "}").encodeToByteArray(),
        )
        within(20, "a string of é", ("\"" + "é".repeat(1 shl 19) + "\"").encodeToByteArray())
        within(20, "a 1 MiB decimal", ("0." + "1".repeat((1 shl 20) - 2)).encodeToByteArray())
    }
}
