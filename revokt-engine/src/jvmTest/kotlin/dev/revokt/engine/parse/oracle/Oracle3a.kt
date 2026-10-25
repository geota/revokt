// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.oracle

import dev.revokt.engine.parse.producer.ProducerCorpus
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString
import java.io.File
import java.util.Base64

/**
 * Oracle 3a of spec §9.2 (`x509-parser` 0.18.1, `native/revokt-oracle x509`), read from its recorded goldens
 * (`oracle/3a.tsv`, keyed by the SHA-256 of the input) so the PR tier needs no Rust. Regenerate with
 * `native/revokt-oracle/record-goldens.sh` when the corpus changes.
 */
internal object Oracle3a {
    /** One extension as 3a reports it; [sct] is null for another OID, empty for a parse error, else its pairs. */
    class Extension(
        val oid: String,
        val critical: Boolean,
        val value: String,
        val sct: List<Pair<String, Long>>?,
        val sctError: Boolean,
    )

    /** The parts of `canon` as 3a slices them, and the `signatureValue`'s unused-bits count. */
    class CanonParts(
        val tbs: String,
        val tbsSignature: String,
        val signature: String,
        val unusedBits: Int,
    )

    /** 3a's `Ok` reply; every byte field is lower-case hex. */
    class Accepted(
        val serial: String,
        val spki: String,
        val subject: String,
        val issuer: String,
        val trailing: Int,
        val canon: CanonParts,
        val extensions: List<Extension>,
        val duplicateSct: Boolean,
    )

    /** sha256 of the input → 3a's reply line. */
    fun goldens(): Map<String, String> =
        String(ProducerCorpus.resource("oracle/3a.tsv"))
            .lineSequence()
            .filter { it.isNotBlank() && !it.startsWith("#") }
            .associate { line -> line.substringBefore('\t') to line.substringAfter('\t') }

    /** The reply parsed, or null for `ERR` and `PANIC`. */
    fun accepted(reply: String): Accepted? {
        val f = reply.split('\t')
        if (f[0] != "OK") return null
        val extensions =
            if (f[9].isEmpty()) {
                emptyList()
            } else {
                f[9].split(';').map { e ->
                    val parts = e.split(',')
                    val (oid, critical, value) = parts
                    val sct = parts[3]
                    val pairs =
                        when (sct) {
                            "-", "E" -> {
                                null
                            }

                            "" -> {
                                emptyList()
                            }

                            else -> {
                                sct.split('+').map {
                                    it.substringBefore('@') to
                                        it.substringAfter('@').toULong().toLong()
                                }
                            }
                        }
                    Extension(oid, critical == "1", value, if (sct == "E") emptyList() else pairs, sct == "E")
                }
            }
        return Accepted(
            f[1],
            f[2],
            f[3],
            f[4],
            f[5].toInt(),
            CanonParts(f[6], f[7], f[8], f[10].toInt()),
            extensions,
            f[11] == "1",
        )
    }

    fun hex(b: ByteArray): String = b.toByteString().hex()

    fun bytes(hex: String): ByteArray = hex.decodeHex().toByteArray()

    /** Writes every corpus input when `revokt.writeOracleInputs` names a file; returns whether it did. */
    fun writeInputsIfRequested(): Boolean {
        val path = System.getProperty("revokt.writeOracleInputs") ?: return false
        File(path).printWriter().use { w ->
            for (i in ProducerCorpus.inputs) {
                w.println("${i.der.toByteString().sha256().hex()}\t${Base64.getEncoder().encodeToString(i.der)}")
            }
        }
        return true
    }
}
