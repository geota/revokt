// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.oracle

import dev.revokt.engine.parse.producer.ProducerCorpus
import java.io.ByteArrayInputStream
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * A platform oracle of spec §9.2, run live: a `CertificateFactory` whose acceptance defines D1's premise and whose
 * `getEncoded()` (oracle 1: or its platform canon) is the `encoded` D1, D2 and D6 read.
 */
internal interface PlatformOracle {
    sealed class Outcome {
        class Accept(
            val certificate: X509Certificate,
        ) : Outcome()

        object Reject : Outcome()

        /** Any other exception; an `Error` is fatal to the JVM run and propagates. */
        class Crash(
            val error: Exception,
        ) : Outcome()
    }

    /** The §9.2 oracle number, as the records name it. */
    val id: String

    /** The version on this run: the JDK's feature release for oracle 1, the Conscrypt release for oracle 2. */
    val version: String

    /** How failures name it. */
    val label: String get() = "oracle $id ($version)"

    /**
     * The D3 divergence class a difference between `Cert.tbs` and this oracle's `getTBSCertificate()` is recorded under,
     * or null where it is a D2 violation (spec §9.2 D2: oracle 1's message is `Cert.tbs`; Conscrypt verifies over the
     * presented TBS TLV, so a difference marks an input it cannot verify).
     */
    val tbsDivergence: String? get() = null

    /**
     * The D3 divergence class a `getNotBefore()`/`getNotAfter()` difference is recorded under where this oracle drops a
     * `UTCTime` differential (spec §9.2 D2, revision 41), or null where every time difference is a violation.
     */
    val timeDivergence: String? get() = null

    /**
     * The D3 divergence class a time difference is recorded under where this oracle reads a time before the Gregorian
     * reform (1582-10-15) in the Julian calendar (spec §9.2 D2, revision 44), or null where that is a violation.
     */
    val julianDivergence: String? get() = null

    /**
     * Whether this oracle's `getExtensionValue` reports `id-pkix-ocsp-nocheck` with empty content whatever the certificate
     * carries (the JDK's `OCSPNoCheckExtension` keeps no value), so D2 expects that extension's value empty, in effect
     * comparing its presence only (spec §9.2 revision 44).
     */
    val ocspNoCheckEmpty: Boolean get() = false

    /** The `CertificateFactory` [run] parses with. */
    val factory: CertificateFactory

    /** [factory]'s parse of [b]: a `CertificateException` is `Reject`, any other exception a `Crash`. */
    @Suppress("TooGenericExceptionCaught") // §9.2: every exception other than CertificateException is a Crash
    fun run(b: ByteArray): Outcome =
        try {
            Outcome.Accept(factory.generateCertificate(ByteArrayInputStream(b)) as X509Certificate)
        } catch (_: CertificateException) {
            Outcome.Reject
        } catch (e: Exception) {
            Outcome.Crash(e)
        }

    /** The bytes revokt reads for an accepted [certificate] as a replay input, or null when there are none. */
    fun read(
        name: String,
        certificate: X509Certificate,
    ): ProducerCorpus.Input?

    companion object {
        /** Every platform oracle on this run, oracle 1 first; lazy, so a run that needs only oracle 1 never loads Conscrypt. */
        val all: List<PlatformOracle> by lazy { listOf(Oracle1, Oracle2) }
    }
}
