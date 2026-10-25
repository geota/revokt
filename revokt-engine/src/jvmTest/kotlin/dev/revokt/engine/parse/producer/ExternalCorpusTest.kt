// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.producer

import dev.revokt.engine.parse.records.Json
import okio.ByteString.Companion.toByteString
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ExternalCorpusTest {
    private val leaf = ProducerCorpus.resource("certs/letsencrypt.org-1.der")

    private val root = ProducerCorpus.resource("certs/letsencrypt.org-3.der")

    private fun pem(der: ByteArray): String =
        "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(der) +
            "\n-----END CERTIFICATE-----\n"

    private fun quoted(s: String) =
        Json
            .obj("v" to Json.Str(s))
            .write()
            .removePrefix("{\"v\":")
            .removeSuffix("}")

    @Test
    fun `limbo's certificates are read once each, named by their SHA-256, whatever testcase holds them`() {
        val text =
            """
            {"version": 1, "testcases": [
              {"id": "a", "max_chain_depth": null, "validation_time": 1.5e9, "trusted_certs": [${quoted(pem(root))}],
               "untrusted_intermediates": [], "peer_certificate": ${quoted(pem(leaf))}, "features": [-0, 0.25]},
              {"id": "b", "trusted_certs": [${quoted(pem(root))}], "untrusted_intermediates": [${quoted(pem(leaf))}]}
            ]}
            """.trimIndent()
        val inputs = ExternalCorpus.limbo(text)
        assertEquals(
            listOf(leaf, root).map { ExternalCorpus.LIMBO + it.toByteString().sha256().hex() }.sorted(),
            inputs.map { it.name },
        )
        assertContentEquals(leaf, inputs.first { it.name.endsWith(leaf.toByteString().sha256().hex()) }.der)
        assertTrue(inputs.all { ExternalCorpus.owns(it.name) })
        assertEquals(false, ExternalCorpus.owns("certs/letsencrypt.org-1"))
    }

    @Test
    fun `a PEM block other than one certificate fails`() {
        assertFailsWith<IllegalStateException> {
            ExternalCorpus.pemDer(
                pem(leaf).replace("CERTIFICATE", "PRIVATE KEY"),
            )
        }
    }

    @Test
    fun `numbers parse as their text and are never written`() {
        val o = Json.parse("""{"a": -12, "b": 0.5, "c": 1E+3, "d": 0}""") as Json.Obj
        assertEquals(listOf("-12", "0.5", "1E+3", "0"), listOf("a", "b", "c", "d").map { (o[it] as Json.Num).text })
        for (bad in listOf("01", "-", "1.", "1e", ".5", "+1")) {
            assertFailsWith<IllegalStateException>(bad) { Json.parse("""{"a": $bad}""") }
        }
        assertFailsWith<IllegalStateException> { o.write() }
    }
}
