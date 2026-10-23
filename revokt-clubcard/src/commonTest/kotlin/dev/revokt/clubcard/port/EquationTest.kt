// SPDX-FileCopyrightText: Mozilla Foundation and clubcard contributors; translation 2026 revokt contributors
// SPDX-License-Identifier: MPL-2.0
// Translation of the tests in clubcard 0.3.4 src/equation.rs (git ecca8d1a9e92f9f3b4b910c05fe11c190836501e).
// Upstream's `test_equation_add` first case uses W = 1; with W fixed at 4 it is written over four limbs.
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
// distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dev.revokt.clubcard.port

import dev.revokt.clubcard.RevoktInternalApi
import kotlin.test.Test
import kotlin.test.assertEquals

@OptIn(RevoktInternalApi::class)
class EquationTest {
    @Test
    fun `equation add shifts to the first non-zero bit`() {
        val e1 = Equation(127, longArrayOf(0b11, 0, 0, 0), 1)
        val e2 = Equation(127, longArrayOf(0b01, 0, 0, 0), 1)
        e1.add(e2)
        assertEquals(128, e1.s)
        assertEquals(0b1, e1.a[0])
        assertEquals(0, e1.b)
    }

    @Test
    fun `equation add moves bits between limbs`() {
        val e1 = Equation(127, longArrayOf(0b11, 0b1110, 0b1, 0), 1)
        val e2 = Equation(127, longArrayOf(0b01, 0b0100, 0b0, 0), 1)
        e1.add(e2)
        assertEquals(128, e1.s)
        assertEquals(0b1, e1.a[0])
        assertEquals((1L shl 63) or 0b101, e1.a[1])
        assertEquals(0, e1.a[2])
        assertEquals(0, e1.a[3])
        assertEquals(0, e1.b)
    }

    @Test
    fun `equation eval reads the window at s across limb boundaries`() {
        for (s in 0 until 64) {
            val eq = Equation(s.toLong(), longArrayOf(-1L, 0, 0, 0), 0)
            assertEquals(0, eq.eval(LongArray(0)))
            for (i in 0 until 64) {
                assertEquals(if (i >= s) 1 else 0, eq.eval(longArrayOf(1L shl i, 0)), "s=$s i=$i first limb")
                assertEquals(if (i < s) 1 else 0, eq.eval(longArrayOf(0, 1L shl i)), "s=$s i=$i second limb")
                assertEquals(0, eq.eval(longArrayOf(0, 0, 1L shl i)), "s=$s i=$i third limb")
            }
        }
    }

    @Test
    fun `equation eval is the same with and without the pad word`() {
        val eq = Equation(70, longArrayOf(0x5a5a5a5a5a5a5a5aL, -1L, 1L, Long.MIN_VALUE), 0)
        val column = longArrayOf(0x123456789abcdef0L, -0x7f3a2b1cL, 0x0f0f0f0f0f0f0f0fL, 0x10L, 0x7aL)
        assertEquals(eq.eval(column), eq.eval(column + 0L))
        assertEquals(eq.eval(column), eq.eval(column + longArrayOf(0L, 0L)))
    }

    @Test
    fun `equation eval past the end of the column is zero`() {
        val eq = Equation(64L * 1000, longArrayOf(-1L, -1L, -1L, -1L), 0)
        assertEquals(0, eq.eval(longArrayOf(-1L, -1L, -1L)))
        val far = Equation(64L * 0xFFFF_FFFFL, longArrayOf(-1L, -1L, -1L, -1L), 0)
        assertEquals(0, far.eval(longArrayOf(-1L)))
    }
}
