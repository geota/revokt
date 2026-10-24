// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.producer

import dev.revokt.engine.parse.DerNode
import dev.revokt.engine.parse.LengthForm
import okio.ByteString.Companion.toByteString
import java.io.File
import java.util.Base64

/**
 * The inputs of the D8 replay (spec §9.2, #11) and their oracle-4 goldens in `producer/goldens.tsv`, keyed by the
 * SHA-256 of `canon(input)` (oracle 4 reads `canon`, never the presented bytes). Recording: the writer test, given
 * `-Drevokt.writeProducerInputs=<file>`, writes each distinct `canon` once; `native/producer-oracle/record-goldens.sh`
 * runs them through the producer.
 */
internal object ProducerCorpus {
    val fixtures =
        listOf(
            "github.com-1",
            "github.com-2",
            "github.com-3",
            "letsencrypt.org-1",
            "letsencrypt.org-2",
            "letsencrypt.org-3",
            "letsencrypt.org-4",
            "www.google.com-1",
            "www.google.com-2",
            "www.google.com-3",
            "www.mozilla.org-1",
            "www.mozilla.org-2",
            "www.mozilla.org-3",
            "mozilla-content-signing-c0",
            "mozilla-content-signing-c1",
            "mozilla-content-signing-c2",
        )

    private val variants =
        listOf(
            "cert-null-after-signature",
            "ext3-null-after-sequence",
            "ext3-primitive-83",
            "extension-null-after-extnvalue",
            "extension-null-between-oid-and-value",
            "extensions-seq-with-null-element",
            "spki-then-null-then-uid",
            "tbs-junk-after-extensions",
            "tbs-junk-before-extensions",
            "tbs-null-after-extensions",
            "tbs-null-before-extensions",
            "tbs-two-ext3",
            "uid-81-twice",
            "uid-82-then-81",
            "uid-a2-constructed",
            "uid-constructed-a1",
            "validity-null-after-times",
            "version-wrapper-trailing",
        )

    /** One replay input; [base] names the certificate a mutant came from and [path] the mutated header. */
    class Input(
        val name: String,
        val der: ByteArray,
        val base: String? = null,
        val path: String? = null,
    ) {
        val canon: ByteArray? by lazy { Canon.of(der) }
        val canonSha256: String? by lazy { canon?.toByteString()?.sha256()?.hex() }
    }

    fun resource(path: String): ByteArray =
        checkNotNull(
            ProducerCorpus::class.java.getResourceAsStream("/dev/revokt/engine/parse/$path"),
        ) { "missing $path" }
            .use { it.readBytes() }

    /** The real RSA-2048 modulus of `www.mozilla.org-1`, for the boundary corpus's RSA entries. */
    private fun rsaModulus(): ByteArray {
        val spki = DerNode.parse(resource("certs/www.mozilla.org-1.der")).child(0, 6)
        return DerNode.parse(spki.child(1).content.copyOfRange(1, spki.child(1).content.size)).child(0).content
    }

    /** The replay corpus, built once per test run; [build] makes a fresh copy (the determinism check). */
    val inputs: List<Input> by lazy { build() }

    private val fuzzInputs =
        listOf(
            "empty",
            "huge-length",
            "indefinite",
            "indefinite-tbs",
            "leaf-with-scts",
            "root-2200",
            "trailing-byte",
            "truncated-leaf",
        )

    fun build(): List<Input> {
        val out = ArrayList<Input>()
        for (f in fixtures) out += Input("certs/$f", resource("certs/$f.der"))
        for (v in variants) out += Input("variants/$v", resource("certs/variants/$v.der"))
        for (leaf in listOf("letsencrypt.org-1", "www.google.com-1", "www.mozilla.org-1")) {
            for ((form, name) in listOf(
                LengthForm.Long(3) to "tbs-long-leading-zero",
                LengthForm.Indefinite to "tbs-indefinite",
            )) {
                val tree = DerNode.parse(resource("certs/$leaf.der"))
                tree.child(0).form = form
                out += Input("unsigned/$leaf/$name", tree.encode())
            }
        }
        for ((name, der) in BoundaryCorpus.inputs(rsaModulus())) out += Input("boundary/$name", der)
        for (f in fuzzInputs) out += Input("fuzz/$f", resource("CertificateParserFuzzTestInputs/$f"))
        val mutated =
            fixtures.map { "certs/$it" to resource("certs/$it.der") } + ("boundary/base" to BoundaryCorpus.base())
        for ((name, der) in mutated) {
            for (m in LengthMutants.of(der)) out += Input("mutant/$name${m.path}", m.der, name, m.path)
        }
        return out.distinctBy { it.der.toByteString() }
    }

    /** canon SHA-256 → the oracle's line (`OK <serial> <spki-sha256> <ct|lax|zc>` or `REJECT <error>`). */
    fun goldens(): Map<String, String> =
        String(resource("producer/goldens.tsv"))
            .lineSequence()
            .filter { it.isNotBlank() && !it.startsWith("#") }
            .associate { line -> line.substringBefore('\t') to line.substringAfter('\t') }

    /** Writes each distinct canon once when `revokt.writeProducerInputs` names a file; returns whether it did. */
    fun writeInputsIfRequested(): Boolean {
        val path = System.getProperty("revokt.writeProducerInputs") ?: return false
        File(path).printWriter().use { w ->
            for (i in inputs.filter { it.canon != null }.distinctBy { it.canonSha256 }) {
                w.println("${i.canonSha256}\t${Base64.getEncoder().encodeToString(i.canon)}")
            }
        }
        return true
    }
}
