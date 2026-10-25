// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import kotlin.test.Test
import kotlin.test.assertEquals

class ConventionsTest {
    @Test
    fun `licence is derived from the module name, MPL only for the clubcard port`() {
        assertEquals("MPL-2.0", Conventions.licenseOf("revokt-clubcard"))
        assertEquals("Apache-2.0", Conventions.licenseOf("revokt-engine"))
        assertEquals("Apache-2.0", Conventions.licenseOf("revokt-jsse"))
        assertEquals("Apache-2.0", Conventions.licenseOf("revokt-bom"))
    }

    @Test
    fun `jdk facts match CONTRIBUTING`() {
        assertEquals(21, Conventions.JDK_BUILD)
        assertEquals(17, Conventions.JDK_RELEASE)
    }
}
