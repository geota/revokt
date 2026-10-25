// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.producer

import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The recording hook for `native/producer-oracle/record-goldens.sh`; a no-op unless the property is set. */
class ProducerGoldensWriterTest {
    @Test
    fun `the replay corpus is deterministic and the recording hook writes it on request`() {
        val first =
            ProducerCorpus.build().map {
                it.der
                    .toByteString()
                    .sha256()
                    .hex()
            }
        val again =
            ProducerCorpus.build().map {
                it.der
                    .toByteString()
                    .sha256()
                    .hex()
            }
        assertEquals(first, again, "corpus generation is deterministic")
        assertTrue(first.size > 1000, "the mutation set is exercised (${first.size} inputs)")
        ProducerCorpus.writeInputsIfRequested()
    }
}
