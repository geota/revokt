// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.engine.walker.WalkerCerts.der
import dev.revokt.testing.SymKey
import dev.revokt.testing.SymName
import java.security.Security
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Spec §3 "Verifier contract": the key families, ordering only. */
class KeyFamilyTest {
    private val rsaSignatures =
        listOf(2, 3, 4, 5, 10, 11, 12, 13, 14, 15, 16).map { "1.2.840.113549.1.1.$it" } +
            (13..16).map { "2.16.840.1.101.3.4.3.$it" }
    private val ecdsaSignatures =
        listOf("1.2.840.10045.4.1") + (1..4).map { "1.2.840.10045.4.3.$it" } +
            (9..12).map { "2.16.840.1.101.3.4.3.$it" }
    private val sameOid =
        mapOf("1.3.101.112" to KeyFamily.EDDSA, "1.3.101.113" to KeyFamily.EDDSA) +
            (17..19).associate { "2.16.840.1.101.3.4.3.$it" to KeyFamily.ML_DSA } +
            (20..31).associate { "2.16.840.1.101.3.4.3.$it" to KeyFamily.SLH_DSA }

    private fun keyed(keyOid: String): Cert =
        WalkerCerts.cert(der(SymName("Root"), SymName("Root"), key = SymKey(11, keyOid.hashCode(), keyOid)))

    @Test
    fun `key family tables name the spec's keys and signatures`() {
        assertEquals(KeyFamily.RSA, KeyFamily.ofKey("1.2.840.113549.1.1.1"))
        assertEquals(KeyFamily.RSA, KeyFamily.ofKey("1.2.840.113549.1.1.10"))
        assertEquals(KeyFamily.EC, KeyFamily.ofKey("1.2.840.10045.2.1"))
        for (oid in rsaSignatures) assertEquals(KeyFamily.RSA, KeyFamily.ofSignature(oid), oid)
        for (oid in ecdsaSignatures) assertEquals(KeyFamily.EC, KeyFamily.ofSignature(oid), oid)
        for ((oid, family) in sameOid) {
            assertEquals(family, KeyFamily.ofKey(oid), oid)
            assertEquals(family, KeyFamily.ofSignature(oid), oid)
        }
        for (oid in listOf(
            "",
            "1.2.840.10040.4.1",
            "1.2.840.113549.1.1.7",
            "1.3.6.1.5.5.7.6.37",
            "2.16.840.1.101.3.4.3.32",
        )) {
            assertEquals(KeyFamily.UNKNOWN, KeyFamily.ofKey(oid), oid)
            assertEquals(KeyFamily.UNKNOWN, KeyFamily.ofSignature(oid), oid)
        }
        // A signature OID is never a key OID of the RSA or EC family, and the reverse.
        assertEquals(KeyFamily.UNKNOWN, KeyFamily.ofKey("1.2.840.113549.1.1.11"))
        assertEquals(KeyFamily.UNKNOWN, KeyFamily.ofSignature("1.2.840.113549.1.1.1"))
        assertEquals(KeyFamily.UNKNOWN, KeyFamily.ofSignature("1.2.840.10045.2.1"))
    }

    @Test
    fun `key family tables agree with the JDK's algorithm names where it knows the OID`() {
        val providers = Security.getProviders().toList()

        fun jdkName(
            type: String,
            oid: String,
        ): String? =
            providers.firstNotNullOfOrNull { p ->
                p.getProperty("Alg.Alias.$type.$oid") ?: p.getProperty("Alg.Alias.$type.OID.$oid")
                    ?: p.services.firstOrNull { it.type == type && it.algorithm == oid }?.algorithm
            }
        val expected =
            rsaSignatures.associateWith { listOf("RSA") } + ecdsaSignatures.associateWith { listOf("ECDSA") } +
                sameOid.mapValues { (_, f) ->
                    when (f) {
                        KeyFamily.EDDSA -> listOf("ED25519", "ED448")
                        KeyFamily.ML_DSA -> listOf("ML-DSA")
                        else -> listOf("SLH-DSA")
                    }
                }
        var known = 0
        for ((oid, names) in expected) {
            val name = jdkName("Signature", oid)?.uppercase() ?: continue
            known++
            assertTrue(names.any { it in name }, "$oid is $name in the JDK")
        }
        // JDK 17 already knows every RSA and ECDSA OID listed and EdDSA; later JDKs add ML-DSA and SLH-DSA.
        assertTrue(known >= rsaSignatures.size + ecdsaSignatures.size - 2, "the JDK named only $known OIDs")
        assertEquals("RSA", jdkName("KeyFactory", "1.2.840.113549.1.1.1")?.uppercase())
        assertEquals("EC", jdkName("KeyFactory", "1.2.840.10045.2.1")?.uppercase())
    }

    @Test
    fun `key family compatibility by family for RSA and EC, by exact OID for the others, unknown with everything`() {
        val rsa = keyed("1.2.840.113549.1.1.1")
        val pss = keyed("1.2.840.113549.1.1.10")
        val ec = keyed("1.2.840.10045.2.1")
        val ed25519 = keyed("1.3.101.112")
        val mlDsa44 = keyed("2.16.840.1.101.3.4.3.17")
        val slhDsa = keyed("2.16.840.1.101.3.4.3.20")
        val unknown = keyed("1.3.6.1.4.1.99999.91.1")
        val sha256Rsa = "1.2.840.113549.1.1.11"
        val pssSig = "1.2.840.113549.1.1.10"
        val ecdsa = "1.2.840.10045.4.3.2"
        val keys = listOf(rsa, pss, ec, ed25519, mlDsa44, slhDsa, unknown)
        val table =
            mapOf(
                sha256Rsa to setOf(rsa, pss, unknown),
                pssSig to setOf(rsa, pss, unknown),
                ecdsa to setOf(ec, unknown),
                "1.3.101.112" to setOf(ed25519, unknown),
                "1.3.101.113" to setOf(unknown),
                "2.16.840.1.101.3.4.3.17" to setOf(mlDsa44, unknown),
                "2.16.840.1.101.3.4.3.18" to setOf(unknown),
                "2.16.840.1.101.3.4.3.20" to setOf(slhDsa, unknown),
                "2.16.840.1.101.3.4.3.21" to setOf(unknown),
                "1.3.6.1.4.1.99999.91.2" to keys.toSet(),
                "" to keys.toSet(),
            )
        for ((signature, compatible) in table) {
            for (k in keys) {
                assertEquals(k in compatible, KeyFamily.compatible(k, signature), "${k.keyOid} under $signature")
            }
        }
        assertFalse(KeyFamily.compatible(ec, sha256Rsa))
    }
}
