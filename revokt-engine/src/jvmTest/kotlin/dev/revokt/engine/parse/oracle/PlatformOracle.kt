// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.oracle

import dev.revokt.engine.parse.producer.ProducerCorpus
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

    fun run(b: ByteArray): Outcome

    /** The bytes revokt reads for an accepted [certificate] as a replay input, or null when there are none. */
    fun read(
        name: String,
        certificate: X509Certificate,
    ): ProducerCorpus.Input?

    companion object {
        val all: List<PlatformOracle> = listOf(Oracle1, Oracle2)
    }
}
