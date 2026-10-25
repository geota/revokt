// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.producer

import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.api.ClubcardFilters
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.DerNode
import okio.ByteString.Companion.toByteString
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The producer SPKI check of spec §9.2 (revision 42), over the issuer corpus of the large corpus (ExternalCorpus) and
 * the committed fixture generation's filters (`corpus/clubcard`: the full filter and its delta, each with its own
 * index map). The producer enrols an issuer only through certificate-transparency-go's `ParseCertificate`, keyed by
 * `SHA-256(RawSubjectPublicKeyInfo)`; oracle 4's `ct` path is that parse, so its SPKI hash is the producer's key.
 */
class ProducerSpkiCheckTest {
    private val issuers = ExternalCorpus.issuer.inputs

    /** Every key of each index of the fixture generation (§6.2, §6.3), read with the clubcard port. */
    @OptIn(RevoktInternalApi::class)
    private val indexKeys: Set<String> by lazy {
        val root = File(checkNotNull(System.getProperty("revokt.clubcardCorpus")) { "revokt.clubcardCorpus not set" })
        listOf("compat-full/20261017-1-compat.filter", "compat-delta/20261021-1-compat.filter.delta")
            .flatMap { ClubcardFilters.decode(File(root, it).readBytes()).index.keys }
            .map { it.hex() }
            .toSet()
    }

    /** Oracle 4's `ct`-path SPKI hash of [input], or null for another path or a rejection. */
    private fun producerKey(input: ProducerCorpus.Input): String? {
        val golden = ProducerCorpus.goldens()[input.canonSha256] ?: return null
        val f = golden.split(' ')
        return f[2].takeIf { f[0] == "OK" && f[3] == "ct" }
    }

    @Test
    fun `revokt keys every issuer-corpus certificate as the producer does`() {
        if (issuers.isEmpty()) return println("producer SPKI check: no issuer corpus on this run (-Prevokt.corpus)")
        val differences = ArrayList<String>()
        var agreed = 0
        val missing = issuers.filter { it.canon != null && ProducerCorpus.goldens()[it.canonSha256] == null }
        assertEquals(emptyList(), missing.map { it.name }, "issuer-corpus certificates with no oracle-4 golden")
        for (input in issuers) {
            val key = producerKey(input) ?: continue
            // Oracle 4 read canon; its TBS, and so the SPKI hashed, is the DER's on a ct-path input (spec §9.2, revision 43).
            if (!sameTbs(input.canon!!, input.der)) differences += "${input.name}: canon's TBS differs from the DER's"
            when (val p = CertificateParser.parse(input.der)) {
                is CertificateParse.Parsed -> {
                    val revokt =
                        p.certificate
                            .rawSpki()
                            .toByteString()
                            .sha256()
                            .hex()
                    if (revokt == key) agreed++ else differences += "${input.name}: revokt $revokt, producer $key"
                }

                is CertificateParse.Failed -> {
                    if (key in indexKeys) differences += "${input.name}: revokt ${p.reason}, an enrolled key"
                }
            }
        }
        println("producer SPKI check: ${issuers.size} issuer-corpus certificates, $agreed agree on the ct path")
        assertEquals(emptyList(), differences, "producer/revokt SPKI-byte divergences")
        assertTrue(agreed > 1000, "agreement exercised on only $agreed certificates")
    }

    /** Whether two certificates' first elements (their TBS) are the same bytes. */
    private fun sameTbs(
        a: ByteArray,
        b: ByteArray,
    ): Boolean =
        DerNode
            .parse(a)
            .child(0)
            .encode()
            .contentEquals(DerNode.parse(b).child(0).encode())

    @Test
    fun `every key of each index of the fixture generation is an issuer-corpus certificate's`() {
        if (issuers.isEmpty()) return println("producer SPKI check: no issuer corpus on this run (-Prevokt.corpus)")
        // Only a certificate the producer could read counts: ct-go rejects the DER where canon replaced an outer
        // signatureAlgorithm the TBS does not name (spec §9.2, revision 43), so canon must be the DER.
        val covered = issuers.filter { it.canon?.contentEquals(it.der) == true }.mapNotNull(::producerKey).toSet()
        val uncovered = indexKeys - covered
        println("producer SPKI check: ${indexKeys.size} index keys, ${uncovered.size} uncovered")
        assertEquals(emptySet(), uncovered, "index keys no issuer-corpus certificate covers (spec §9.2: fetch from CT)")
    }
}
