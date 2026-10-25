// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

/**
 * The envelope forms of spec §9.2 "The unsigned headers", built from a real leaf: the JDK cross-check
 * ([CertificateParserEnvelopeJdkTest]) asserts each one's outcome, and the replay corpus carries them so oracle 3b's
 * converter is exercised on every nested indefinite chain and every length form it rejects.
 */
internal object EnvelopeVariants {
    enum class Expected {
        /** Parsed with the base certificate's fields; the JDK verifies it (asserted on JDK 17 and later, Appendix A). */
        SAME_AS_BASE,

        /** `STRUCTURE`; the JDK rejects it or fails to verify it. */
        STRUCTURE,

        /** Parsed (a form the JDK rejects, harmless for D1); the JDK does not verify it. */
        PARSED_JDK_REJECTS,
    }

    class Variant(
        val name: String,
        val expected: Expected,
        val algorithmIdMismatch: Boolean = false,
        val build: (DerNode) -> ByteArray,
    )

    private fun DerNode.tbs() = child(0)

    private fun DerNode.alg() = child(1)

    private fun DerNode.sig() = child(2)

    private val ind = LengthForm.Indefinite

    /**
     * Forms the JDK cross-check does not assert, for oracle 3b only: an `85` length and `00 00` inside a definite child
     * under an indefinite TBS, an indefinite `signatureValue` holding a nested one (`STRUCTURE` since revision 38), and
     * long definite lengths on the `Certificate`, `[0]` and TBS `signature` headers, which 3a and 3b must both read.
     */
    fun converterForms(): List<Pair<String, (DerNode) -> ByteArray>> =
        listOf(
            "tbs-indefinite-serial-85" to { c ->
                c.tbs().form = ind
                c.tbs().child(1).form = LengthForm.Long(5)
                c.encode()
            },
            "tbs-indefinite-serial-eoc-content" to { c ->
                c.tbs().form = ind
                c.tbs().child(1).content = TestDer.bytes(0, 0) + c.tbs().child(1).content
                c.encode()
            },
            "sig-indefinite-nested" to { c ->
                val bits = c.sig().content
                val inner = DerNode(0x04, bits.copyOfRange(1, bits.size), null).encode()
                c.sig().content = TestDer.bytes(0x00, 0x80) + inner + TestDer.bytes(0, 0)
                c.sig().form = ind
                c.encode()
            },
            "certificate-long5" to { c ->
                c.form = LengthForm.Long(5)
                c.encode()
            },
            "certificate-long8" to { c ->
                c.form = LengthForm.Long(8)
                c.encode()
            },
            "version-long5" to { c ->
                c.tbs().child(0).form = LengthForm.Long(5)
                c.encode()
            },
            "tbs-signature-long5" to { c ->
                c.tbs().child(2).form = LengthForm.Long(5)
                c.encode()
            },
        )

    /** Every form for a leaf; [rsa] adds the forms only an RSA signature has (NULL parameters, padding bits). */
    fun of(rsa: Boolean): List<Variant> =
        tbsVariants() + algorithmVariants() + signatureVariants() + if (rsa) rsaVariants() else emptyList()

    private fun tbsVariants(): List<Variant> =
        listOf(
            Variant("tbs-long-leading-zero", Expected.SAME_AS_BASE) { c ->
                c.tbs().form = LengthForm.Long(3)
                c.encode()
            },
            Variant("tbs-indefinite", Expected.SAME_AS_BASE) { c ->
                c.tbs().form = ind
                c.encode()
            },
            Variant("tbs-indefinite-version", Expected.SAME_AS_BASE) { c ->
                c.tbs().form = ind
                c.tbs().child(0).form = ind
                c.encode()
            },
            Variant("tbs-indefinite-validity", Expected.SAME_AS_BASE) { c ->
                c.tbs().form = ind
                c.tbs().child(4).form = ind
                c.encode()
            },
            Variant("tbs-indefinite-subject-chain", Expected.SAME_AS_BASE) { c ->
                c.tbs().form = ind
                val subject = c.tbs().child(5)
                subject.form = ind
                for (rdn in subject.children!!) {
                    rdn.form = ind
                    rdn.children!!.forEach { it.form = ind }
                }
                c.encode()
            },
            Variant("tbs-indefinite-extension-chain", Expected.SAME_AS_BASE) { c ->
                c.tbs().form = ind
                val wrapper = c.tbs().child(7)
                wrapper.form = ind
                wrapper.child(0).form = ind
                val extension = wrapper.child(0, 0)
                extension.form = ind
                extension.children!!.last().form = ind // extnValue as 04 80 … 00 00
                c.encode()
            },
        ) + tbsRejectVariants()

    private fun algorithmVariants(): List<Variant> =
        listOf(
            Variant("alg-long", Expected.SAME_AS_BASE, algorithmIdMismatch = true) { c ->
                c.alg().form = LengthForm.Long(1)
                c.encode()
            },
            Variant("alg-indefinite", Expected.SAME_AS_BASE, algorithmIdMismatch = true) { c ->
                c.alg().form = ind
                c.encode()
            },
            Variant("alg-oid-header-81", Expected.SAME_AS_BASE, algorithmIdMismatch = true) { c ->
                c.alg().child(0).form = LengthForm.Long(1)
                c.encode()
            },
            Variant("alg-null-flipped", Expected.SAME_AS_BASE) { c ->
                val params = c.alg().children!!
                if (params.size == 2) params.removeAt(1) else params.add(DerNode(0x05, ByteArray(0), null))
                c.encode()
            },
            Variant("alg-indefinite-oid-header-81", Expected.STRUCTURE) { c ->
                c.alg().form = ind
                c.alg().child(0).form = LengthForm.Long(1)
                c.encode()
            },
        )

    private fun signatureVariants(): List<Variant> =
        listOf(
            Variant("sig-long-4", Expected.SAME_AS_BASE) { c ->
                c.sig().form = LengthForm.Long(4)
                c.encode()
            },
            Variant("sig-length-85", Expected.PARSED_JDK_REJECTS) { c ->
                c.sig().form = LengthForm.Long(5)
                c.encode()
            },
        )

    private fun tbsRejectVariants(): List<Variant> =
        listOf(
            Variant("tbs-indefinite-serial-81", Expected.STRUCTURE) { c ->
                c.tbs().form = ind
                c.tbs().child(1).form = LengthForm.Long(1)
                c.encode()
            },
            Variant("tbs-indefinite-serial-84", Expected.STRUCTURE) { c ->
                c.tbs().form = ind
                c.tbs().child(1).form = LengthForm.Long(4)
                c.encode()
            },
            Variant("tbs-indefinite-spki-83", Expected.STRUCTURE) { c ->
                c.tbs().form = ind
                c.tbs().child(6).form = LengthForm.Long(3)
                c.encode()
            },
            Variant("tbs-indefinite-double-eoc", Expected.STRUCTURE) { c ->
                c.tbs().form = ind
                TestDer.seq(c.tbs().encode(), TestDer.bytes(0, 0), c.alg().encode(), c.sig().encode())
            },
            Variant("tbs-definite-validity-indefinite", Expected.STRUCTURE) { c ->
                c.tbs().child(4).form = ind
                c.encode()
            },
            Variant("tbs-length-85", Expected.PARSED_JDK_REJECTS) { c ->
                c.tbs().form = LengthForm.Long(5)
                c.encode()
            },
            // A definite subject holding an indefinite RDN under an indefinite TBS: the converter skips the subject
            // whole, so the JDK verifies over bytes the CA did not sign; revokt does not descend into names.
            Variant("tbs-indefinite-definite-subject-indefinite-rdn", Expected.PARSED_JDK_REJECTS) { c ->
                c.tbs().form = ind
                c.tbs().child(5, 0).form = ind
                c.encode()
            },
        )

    private fun rsaVariants(): List<Variant> =
        listOf(
            Variant("alg-indefinite-null-indefinite", Expected.SAME_AS_BASE, algorithmIdMismatch = true) { c ->
                c.alg().form = ind
                c.alg().child(1).form = ind
                c.encode()
            },
            Variant("alg-null-81", Expected.SAME_AS_BASE, algorithmIdMismatch = true) { c ->
                c.alg().child(1).form = LengthForm.Long(1)
                c.encode()
            },
            Variant("sig-unused-bits-1-padding-set", Expected.SAME_AS_BASE) { c ->
                val bits = c.sig().content
                check(bits[bits.lastIndex].toInt() and 1 == 0) { "the fixture's last signature bit must be 0" }
                bits[0] = 1
                bits[bits.lastIndex] = (bits[bits.lastIndex].toInt() or 1).toByte()
                c.encode()
            },
        )
}
