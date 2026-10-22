// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.clubcard.api

import dev.revokt.clubcard.RevoktInternalApi
import kotlin.test.Test
import kotlin.test.assertEquals

@OptIn(RevoktInternalApi::class)
class ClubcardTest {
    @Test
    fun `word width is four limbs as in the port`() {
        assertEquals(4, Clubcard.wordWidth)
    }
}
