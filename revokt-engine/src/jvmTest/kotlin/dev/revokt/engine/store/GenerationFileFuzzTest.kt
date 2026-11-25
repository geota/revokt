// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import com.code_intelligence.jazzer.junit.FuzzTest
import dev.revokt.RevoktLimits
import dev.revokt.engine.verify.ContentSignature

/**
 * Spec §9.1 target "store readers": the generation file (§6.5), read from a disk that can rot. The reader returns a
 * file or null, never throws, and reads the same bytes the same way twice. Over the cap at the default `maxJsonBytes`
 * (`RevoktLimits.MAX_JSON_BYTES` + 64 KiB) it returns null. A file it reads is canonical: written back, it gives the same
 * bytes, so the same name. Read under its own name it reads the same; under any other name, never. `-max_len=4259841`,
 * the cap + 1, so the over-cap answer is reached. With `JAZZER_FUZZ` unset JUnit replays `GenerationFileFuzzTestInputs/`.
 */
class GenerationFileFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun read(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        private val CAP = GenerationFileJson.cap(RevoktLimits.MAX_JSON_BYTES)

        /** The static entry point a standalone Jazzer driver calls (CONTRIBUTING §6). */
        @JvmStatic
        fun fuzzerTestOneInput(data: ByteArray) {
            val name = GenerationFileJson.name(data)
            // Through the store's one read, under the file's own name.
            val file = GenerationFileJson.read(data, name, CAP)
            val again = GenerationFileJson.read(data, name, CAP)
            check((file == null) == (again == null)) { "a second read differs" }
            check(data.size <= CAP || file == null) { "a generation file over the cap" }
            val unhashed = GenerationFileJson.readUnhashed(data, CAP)
            check((unhashed == null) == (file == null)) { "a read under its own name differs from the unhashed one" }
            check(GenerationFileJson.read(data, OTHER, CAP) == null || name == OTHER) { "read under another name" }
            if (file == null) return
            val written = GenerationFileJson.write(file)
            check(written.contentEquals(data)) { "a file that reads is not canonical" }
            check(GenerationFileJson.write(checkNotNull(again)).contentEquals(written)) { "two reads decode apart" }
            val signed = checkNotNull(ContentSignature.recordsJson(file.records, file.lastModified))
            check(file.payload.contentEquals(signed)) {
                "the payload is not the signed serialisation of the records"
            }
        }

        private val OTHER = "0".repeat(64)
    }
}
