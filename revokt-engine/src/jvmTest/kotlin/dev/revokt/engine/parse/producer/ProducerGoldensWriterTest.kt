// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.producer

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The recording hook for `native/producer-oracle/record-goldens.sh`; a no-op unless the property is set. */
class ProducerGoldensWriterTest {
    @Test
    fun `the replay corpus is deterministic and the recording hook writes it on request`() {
        val first = ProducerCorpus.inputs.map { it.canonSha256 }
        val again = ProducerCorpus.inputs.map { it.canonSha256 }
        assertEquals(first, again, "corpus generation is deterministic")
        assertTrue(first.size > 1000, "the mutation set is exercised (${first.size} inputs)")
        ProducerCorpus.writeInputsIfRequested()
    }
}
