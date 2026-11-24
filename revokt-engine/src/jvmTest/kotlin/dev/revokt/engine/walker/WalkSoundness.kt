// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.RevoktLimits
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Spec §9.1 P1, shared by `ReconstructWorldTest` and `WalkerFuzzTest`: a walk's path is sound. It starts at the leaf,
 * holds 2 to `MAX_DEPTH + 1` certificates and repeats none, ends at an anchor of the index by exact bytes, and every
 * link verifies under the next certificate's key ([verifies]). Every certificate between the leaf and the anchor is a
 * CA as the JDK reads it (`getBasicConstraints() >= 0`), the reference walker's test rather than revokt's reader.
 */
internal object WalkSoundness {
    fun assertSound(
        path: WalkPath,
        leaf: Cert,
        index: CandidateIndex,
        verifies: (child: Cert, issuer: Cert) -> Boolean,
        at: String,
    ) {
        val certs = path.certs
        assertTrue(certs.size in 2..RevoktLimits.MAX_DEPTH + 1, "$at: path size ${certs.size}")
        assertEquals(leaf.bytesHash, certs[0].bytesHash, "$at: path starts at the leaf")
        assertEquals(certs.size, certs.map { it.bytesHash }.toSet().size, "$at: a path repeats a certificate")
        for ((child, issuer) in certs.zipWithNext()) assertTrue(verifies(child, issuer), "$at: unverified link")
        assertTrue(index.isAnchorBytes(certs.last()), "$at: the terminal is not an anchor")
        for (c in certs.subList(1, certs.size - 1)) assertTrue(jdkIsCa(c.der), "$at: a non-CA issuer ${c.bytesHash}")
    }

    private fun jdkIsCa(der: ByteArray): Boolean =
        try {
            val x509 = CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream())
            (x509 as X509Certificate).basicConstraints >= 0
        } catch (_: CertificateException) {
            false
        }
}
