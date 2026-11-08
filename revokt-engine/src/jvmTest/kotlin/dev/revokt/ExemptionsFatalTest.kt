// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.parse.TestCert
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * `and` and `or` never absorb a fatal error (§5.5's catch rule: a `VirtualMachineError` other than
 * `StackOverflowError`), even where the other side would decide. JVM only: Kotlin/Native has no such error (#122).
 */
@OptIn(RevoktTestingApi::class)
class ExemptionsFatalTest {
    private val context =
        ExemptionContext
            .Builder()
            .rule(Rule.NO_ISSUER)
            .chain(PresentedChain.Builder().certificates(listOf(TestCert().der)).build())
            .path(
                Finding.Path
                    .Builder()
                    .status(PathStatus.FOUND)
                    .source(ChainSource.RECONSTRUCTED)
                    .build(),
            ).host("corp")
            .nowMillis(0)
            .build()

    private val fatal = Exemption { throw OutOfMemoryError("fatal") }
    private val yes = Exemption { true }
    private val no = Exemption { false }

    @Test
    fun `a fatal error propagates even where the other side decides`() {
        assertFailsWith<OutOfMemoryError> { (fatal and no).isExempt(context) }
        assertFailsWith<OutOfMemoryError> { (fatal or yes).isExempt(context) }
        assertFailsWith<OutOfMemoryError> { (yes and fatal).isExempt(context) }
        assertFailsWith<OutOfMemoryError> { (no or fatal).isExempt(context) }
    }

    @Test
    fun `a StackOverflowError is not fatal, so it is absorbed like any other throw`() {
        val overflow = Exemption { throw StackOverflowError("deep") }
        assertTrue((overflow or yes).isExempt(context))
        assertFailsWith<StackOverflowError> { (overflow and yes).isExempt(context) }
    }
}
