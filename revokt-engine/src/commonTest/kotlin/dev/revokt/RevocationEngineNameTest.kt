// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import kotlin.test.Test
import kotlin.test.assertEquals

/** `RevocationEngine.name` (spec §3.2, revision 49; #112): the engine's name in its `ENGINE_ERROR` findings. */
class RevocationEngineNameTest {
    /** Every member but `name` fails, and `name` is left to the default getter. Not delegated: `by` would forward it. */
    private open class Unimplemented : RevocationEngine {
        override val formats: Set<FilterFormat> get() = error("unused")

        override fun prepare(generation: GenerationFiles): PreparedGeneration = error("unused")

        override fun activate(prepared: PreparedGeneration): Unit = error("unused")

        override fun query(q: CrliteQuery): CrliteQueryResult = error("unused")

        override val coverageEndMillis: Long? get() = error("unused")

        override fun close(): Unit = error("unused")
    }

    private class NamedTestEngine : Unimplemented()

    @Test
    fun `the Kotlin engine is kotlin`() {
        KotlinRevocationEngine().use { assertEquals("kotlin", it.name) }
    }

    @Test
    fun `a named engine class reports its simple name`() {
        assertEquals("NamedTestEngine", NamedTestEngine().name)
    }

    @Test
    fun `an anonymous engine reports anonymous`() {
        assertEquals("anonymous", (object : Unimplemented() {}).name)
    }
}
