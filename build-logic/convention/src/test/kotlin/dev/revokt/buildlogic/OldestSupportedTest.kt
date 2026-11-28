// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * [OldestSupported.problem] (spec §7.2; CONTRIBUTING §9): the weekly seed job falls back to the run's own commit only
 * while no release exists, and fails closed once one does and `revokt.oldestSupportedVersion` does not name it.
 */
class OldestSupportedTest {
    private fun fails(
        oldest: String,
        newest: String?,
        says: String,
    ) {
        val problem = assertNotNull(OldestSupported.problem(oldest, newest), "'$oldest' with newest '$newest' passes")
        assertTrue(says in problem, problem)
    }

    @Test
    fun `nothing named and nothing released is the same-commit fallback`() {
        assertNull(OldestSupported.problem("", ""))
        assertNull(OldestSupported.problem("  ", " "))
    }

    @Test
    fun `the job must say what the newest release is`() {
        fails("", null, "needs -P${OldestSupported.NEWEST_RELEASE_PROPERTY}")
        fails("0.2.0", null, "needs -P${OldestSupported.NEWEST_RELEASE_PROPERTY}")
    }

    @Test
    fun `a release that the property does not name fails rather than falling back`() {
        fails("", "0.2.0", "v0.2.0 is released, but ${OldestSupported.PROPERTY} in gradle.properties is empty")
        fails("", "1.0.0", "is empty")
    }

    @Test
    fun `a named version must be released`() {
        fails("0.2.0", "", "no vX.Y.Z tag exists")
        fails("0.2.1", "0.2.0", "newer than the newest release v0.2.0")
        fails("0.3.0", "0.2.9", "newer than the newest release")
        fails("1.0.0", "0.9.0", "newer than the newest release")
    }

    @Test
    fun `in 0_x only the latest minor is supported`() {
        assertNull(OldestSupported.problem("0.2.0", "0.2.0"))
        assertNull(OldestSupported.problem("0.2.0", "0.2.3"))
        assertNull(OldestSupported.problem("0.2.3", "0.2.3"))
        fails("0.2.3", "0.3.0", "only the latest 0.x minor is supported")
        fails("0.1.0", "0.10.0", "set it to a release of 0.10")
    }

    @Test
    fun `from 1_0 any released version up to the newest passes, the support window being the release PR's call`() {
        assertNull(OldestSupported.problem("0.9.2", "1.0.0"))
        assertNull(OldestSupported.problem("1.4.1", "2.1.0"))
        assertNull(OldestSupported.problem("2.1.0", "2.1.0"))
        assertNull(OldestSupported.problem("1.9.0", "1.10.0"))
    }

    @Test
    fun `versions are plain X_Y_Z`() {
        assertEquals(listOf(0, 2, 0), OldestSupported.parse("0.2.0"))
        assertEquals(listOf(1, 10, 3), OldestSupported.parse("1.10.3"))
        for (bad in listOf("v0.2.0", "0.2", "0.2.0-rc.1", "0.2.0-SNAPSHOT", "00.2.0", "0.02.0", "0.2.+", "latest.release", "", "1234567890.0.0")) {
            assertNull(OldestSupported.parse(bad), bad)
        }
        fails("0.2", "0.2.0", "'0.2' is not an X.Y.Z version")
        fails("", "v0.2.0", "-P${OldestSupported.NEWEST_RELEASE_PROPERTY}='v0.2.0' is not an X.Y.Z version")
        fails("0.2.0", "0.2.0-rc.1", "is not an X.Y.Z version")
    }
}
