// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.producer

import dev.revokt.engine.parse.records.Json
import okio.ByteString.Companion.toByteString
import java.io.File
import java.util.Base64
import java.util.zip.GZIPInputStream

/**
 * The large corpus of spec §9.2 (docs/dev/corpus.md): the revokt-corpus checkout `-Prevokt.corpus` names, which the build
 * passes to the tests as `revokt.corpus`. Its inputs join the replay corpus, and their goldens and records sit beside them
 * in its `replay/` directory, gzipped; without it the replay is the committed corpus alone.
 */
internal object ExternalCorpus {
    /** The checkout, or null when the run has none. */
    val dir: File? = System.getProperty("revokt.corpus")?.takeIf { it.isNotEmpty() }?.let(::File)

    /** The name prefix of every input from `x509-limbo/`, and of the bytes an oracle reads for one. */
    const val LIMBO = "x509-limbo/"

    /** Whether the input (or read) named [name] belongs to this corpus, so that its goldens and records live here. */
    fun owns(name: String): Boolean = name.startsWith(LIMBO)

    /** This corpus's inputs, none without a checkout. */
    fun inputs(): List<ProducerCorpus.Input> =
        dir?.let { limbo(File(it, "x509-limbo/limbo.json").readText()) }.orEmpty()

    /**
     * Every distinct certificate of `limbo.json`'s testcases (trusted, untrusted intermediates and peer), once each since
     * one certificate can serve many testcases, named `x509-limbo/<sha256>` and sorted by name.
     */
    fun limbo(text: String): List<ProducerCorpus.Input> {
        val testcases = (Json.parse(text) as Json.Obj).array("testcases")
        val ders = LinkedHashMap<String, ByteArray>()
        for (t in testcases) {
            val o = t as? Json.Obj ?: error("a limbo testcase is not an object")
            val pems =
                o.strings("trusted_certs") + o.strings("untrusted_intermediates") +
                    listOfNotNull(o.stringOrNull("peer_certificate"))
            for (pem in pems) {
                val der = pemDer(pem)
                ders.getOrPut(der.toByteString().sha256().hex()) { der }
            }
        }
        return ders.map { (sha, der) -> ProducerCorpus.Input("$LIMBO$sha", der) }.sortedBy { it.name }
    }

    /** One PEM `CERTIFICATE` block's DER; anything else fails. */
    fun pemDer(pem: String): ByteArray {
        val lines = pem.trim().lines().map { it.trim() }
        check(lines.first() == "-----BEGIN CERTIFICATE-----" && lines.last() == "-----END CERTIFICATE-----") {
            "not one PEM certificate: ${lines.first()}"
        }
        return Base64.getDecoder().decode(lines.subList(1, lines.size - 1).joinToString(""))
    }

    /** The gzipped TSV `replay/<name>.tsv.gz` as key → rest of line, empty without a checkout or before it is recorded. */
    fun tsv(name: String): Map<String, String> {
        val file = replay("$name.tsv.gz") ?: return emptyMap()
        if (!file.isFile) return emptyMap()
        return GZIPInputStream(file.inputStream()).bufferedReader().useLines { lines ->
            lines
                .filter { it.isNotBlank() && !it.startsWith("#") }
                .associate { line -> line.substringBefore('\t') to line.substringAfter('\t') }
        }
    }

    /** A file of `replay/`, or null without a checkout. */
    fun replay(name: String): File? = dir?.let { File(it, "replay/$name") }
}
