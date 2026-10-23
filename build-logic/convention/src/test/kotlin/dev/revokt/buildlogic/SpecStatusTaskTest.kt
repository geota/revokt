// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import org.gradle.testfixtures.ProjectBuilder
import kotlin.test.Test
import kotlin.test.assertEquals

class SpecStatusTaskTest {
    private fun task(): SpecStatusTask {
        val project = ProjectBuilder.builder().build()
        return project.tasks.register("specStatusProbe", SpecStatusTask::class.java).get()
    }

    @Test
    fun `fixture ids are read from one §9 bullet in order, bold or plain, until the next bullet`() {
        val spec = """
            - **Data-path fixtures** ((a), (b) and (d) are 0.2 gates): (a) changeset older → x; (b) coverage; (c) mirror; **(s2)** stuffed;
              more text (d) again (a) repeated
            - **Verifier**: OID harvest (z) not part of the list
        """.trimIndent()
        assertEquals(listOf("a", "b", "d", "c", "s2"), task().fixtureIds(spec, "- **Data-path fixtures**"))
    }

    @Test
    fun `milestone rows come from the §11 table`() {
        val spec = """
            | Release | Scope | Estimate |
            |---|---|---|
            | 0.1 | engine scaffold | 5 weeks |
            | 0.2 | walker | 4 weeks |
            not a row
        """.trimIndent()
        assertEquals(listOf("0.1" to "engine scaffold", "0.2" to "walker"), task().milestoneRows(spec))
    }
}
