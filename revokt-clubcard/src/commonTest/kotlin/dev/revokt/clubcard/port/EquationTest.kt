// SPDX-FileCopyrightText: Mozilla Foundation and clubcard contributors; translation 2026 revokt contributors
// SPDX-License-Identifier: MPL-2.0
// Translation of the tests in clubcard 0.3.4 src/equation.rs (git ecca8d1a9e92f9f3b4b910c05fe11c190836501e).
// Upstream's `test_equation_add` first case uses W = 1; with W fixed at 4 it is written over four limbs.
// revokt additions (#7): the `owning`/`asQuery` equivalence tests and `upstreamInhomogeneous`, a transcription of
// upstream `Equation::inhomogeneous` kept independent of the production code.
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
// distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dev.revokt.clubcard.port

import dev.revokt.clubcard.RevoktInternalApi
import okio.ByteString.Companion.toByteString
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertSame

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

    @Test
    fun `equation owning alignment equals upstream add of zero over random and edge-case limbs`() {
        val random = Random(20261023)
        val cases =
            mutableListOf(
                LongArray(4),
                longArrayOf(0, 0, 0, 1),
                longArrayOf(0, 0, 1L shl 63, 5),
                longArrayOf(0, -1, 0, 0),
            )
        for (k in 0 until 64) cases += longArrayOf(1L shl k, random.nextLong(), random.nextLong(), random.nextLong())
        repeat(2000) { cases += LongArray(4) { if (random.nextInt(4) == 0) 0 else random.nextLong() } }
        for (a in cases) {
            for (s in listOf(0L, 1L, 63L, 64L, 0xFFFF_FFFFL, random.nextLong(0, 1L shl 33))) {
                for (b in 0..1) {
                    val expected = upstreamInhomogeneous(s, a, b)
                    assertEquals(expected, Equation.inhomogeneous(s, a, b), "inhomogeneous s=$s a=${a.toList()} b=$b")
                    assertEquals(expected, Equation.owning(s, a.copyOf(), b), "owning s=$s a=${a.toList()} b=$b")
                }
            }
        }
    }

    @Test
    fun `query asQuery equals upstream homogeneous over the key hash limbs`() {
        val random = Random(7)
        repeat(200) {
            val issuer = IssuerSpkiHash(random.nextBytes(32).toByteString())
            val key = CrliteKey(issuer, random.nextBytes(1 + random.nextInt(20)).toByteString())
            val hash = key.issuerSerialHash.toByteArray()
            val limbs =
                LongArray(4) { i ->
                    (7 downTo 0).fold(0L) { acc, j ->
                        (acc shl 8) or
                            (hash[8 * i + j].toLong() and 0xff)
                    }
                }
            limbs[0] = limbs[0] or 1L
            for (m in listOf(0L, 1L, 1000L, 0xFFFF_FFFFL, random.nextLong(1, 1L shl 32))) {
                val s = (limbs[3].toULong() % maxOf(m.toULong(), 1uL)).toLong()
                assertEquals(upstreamInhomogeneous(s, limbs, 0), CrliteQuery(key, null).asQuery(m), "m=$m")
            }
        }
    }

    @Test
    fun `equation homogeneous copies its argument and owning takes it`() {
        val a = longArrayOf(0b1000, 3, 5, 7)
        val copied = Equation.homogeneous(0, a)
        assertContentEquals(longArrayOf(0b1000, 3, 5, 7), a)
        a[1] = 99
        assertEquals(Equation.homogeneous(0, longArrayOf(0b1000, 3, 5, 7)), copied)
        val owned = longArrayOf(0b1000, 3, 5, 7)
        assertSame(owned, Equation.owning(0, owned, 0).a)
    }

    /**
     * A literal transcription of upstream `Equation::inhomogeneous` (`eq.add(&Equation::zero()); eq.s += s`), kept
     * independent of the production code so the #7 deviation is checked against upstream, not against itself.
     */
    private fun upstreamInhomogeneous(
        s: Long,
        a0: LongArray,
        b0: Int,
    ): Equation {
        val a = a0.copyOf()
        var start = 0L
        val zero = LongArray(4)
        for (i in 0 until 4) a[i] = a[i] xor zero[i]
        val b = b0 xor 0
        if (a.any { it != 0L }) {
            while (a[0] == 0L) {
                val first = a[0]
                for (i in 0 until 3) a[i] = a[i + 1]
                a[3] = first
            }
            val k = a[0].countTrailingZeroBits()
            if (k != 0) {
                for (i in 0 until 3) {
                    a[i] = a[i] ushr k
                    a[i] = a[i] or (a[i + 1] shl (64 - k))
                }
                a[3] = a[3] ushr k
                start += k
            }
        }
        return Equation(start + s, a, b)
    }
}
