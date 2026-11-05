// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.parse.TestDer
import dev.revokt.testing.SymName
import javax.security.auth.x500.X500Principal
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull

/** Spec §3: the JVM `canonicalSubject` actual. */
class CanonicalSubjectTest {
    @Test
    fun `canonical subject is the X500Principal canonical name`() {
        val name =
            TestDer.seq(
                TestDer.tlv(0x31, TestDer.seq(TestDer.oid("2.5.4.6"), TestDer.tlv(0x13, TestDer.ascii("US")))),
                TestDer.tlv(
                    0x31,
                    TestDer.seq(TestDer.oid("2.5.4.3"), TestDer.tlv(0x0c, TestDer.ascii("  Some   CA "))),
                ),
            )
        assertEquals(X500Principal(name).getName(X500Principal.CANONICAL), canonicalSubject(name))
        assertEquals("cn=some ca,c=us", canonicalSubject(name))
    }

    @Test
    fun `canonical subject equates PrintableString and UTF8String values that raw bytes tell apart`() {
        val printable = SymName("Root CA", printable = true).der()
        val utf8 = SymName("Root CA").der()
        assertNotEquals(printable.toList(), utf8.toList())
        assertEquals(canonicalSubject(printable), canonicalSubject(utf8))
    }

    @Test
    fun `canonical subject is null when the platform cannot read the name`() {
        assertNull(canonicalSubject(byteArrayOf(0x30, 0x05, 0x31)))
        assertNull(canonicalSubject(byteArrayOf(0x04, 0x00)))
        assertEquals("", canonicalSubject(TestDer.seq()))
    }
}
