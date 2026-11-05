// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.verify

/** Spec Appendix A's facts about the JDK providers, as functions of the test JDK's version. */
internal object JdkFacts {
    private const val ML_DSA_FEATURE = 24
    private val ML_DSA_BACKPORTS = mapOf(17 to 21, 21 to 13)

    /** ML-DSA ships in JDK 24 and is backported in 17.0.21 and 21.0.13 (Appendix A, revision 41 probes). */
    fun shipsMlDsa(version: Runtime.Version = Runtime.version()): Boolean =
        version.feature() >= ML_DSA_FEATURE ||
            ML_DSA_BACKPORTS[version.feature()]?.let { version.update() >= it } == true
}
