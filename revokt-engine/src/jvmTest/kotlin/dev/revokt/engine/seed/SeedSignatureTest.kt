// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.engine.seed

import dev.revokt.CrliteChannel
import dev.revokt.MozillaRemoteSettings
import dev.revokt.SeedSource
import dev.revokt.engine.seed.parse.SeedArchive
import java.io.ByteArrayInputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * [verifySeedSignature] (#308), the weekly job's floor check of the last released seed: the format-independent parts of
 * a seed load only (the header's channel, the x5u chain to the pins, the raw content signature, the canonical payload
 * and the x5u validity at the signed `<ts>`), with the loader's own [verifySignedRecords].
 */
internal class SeedSignatureTest : SeedFixture() {
    private fun check(
        bytes: ByteArray?,
        channel: CrliteChannel = CrliteChannel.COMPAT,
        under: MozillaRemoteSettings = source,
    ): SeedSignature =
        verifySeedSignature(SeedSource.of { bytes?.let(::ByteArrayInputStream) }, channel, under, verifier)

    private fun check(seed: Seed): SeedSignature = check(seed.bytes())

    private fun verified(result: SeedSignature): Long =
        assertIs<SeedSignature.Verified>(result, "$result").timestampMillis

    private fun refused(
        result: SeedSignature,
        says: String,
    ) {
        val refused = assertIs<SeedSignature.Refused>(result, "$result")
        assertTrue(says in refused.detail, "'${refused.detail}' does not say '$says'")
    }

    @Test
    fun `a seed that loads verifies at its signed ts`() {
        val bytes = Seed().bytes()
        assertEquals(ts, verified(check(bytes)))
        installed(loader(SeedSource.of { ByteArrayInputStream(bytes) }).load(ts + hour))
    }

    @Test
    fun `what a later seed format may change does not stop it verifying`() {
        // A loader refuses each of these; the floor check needs only a trusted <ts>.
        val header = Seed().header
        for ((name, value) in listOf(
            "seedFormat" to 2,
            "engineFloor" to 99,
            "filterFormat" to "V9",
            "dataset" to "X",
        )) {
            assertEquals(ts, verified(check(Seed().apply { this.header = header + (name to value) })), name)
        }
        val noIndex = Seed().apply { configure = { entries.removeAll { it.name == SeedArchive.INDEX } } }
        assertEquals(ts, verified(check(noIndex)))
        val extra = Seed().apply { configure = { add("notes.txt", "x".encodeToByteArray()) } }
        assertEquals(ts, verified(check(extra)))
        val noFilters =
            Seed().apply {
                configure = {
                    entries.removeAll {
                        it.name.startsWith(
                            SeedArchive.ATTACHMENTS,
                        )
                    }
                }
            }
        assertEquals(ts, verified(check(noFilters)))
    }

    @Test
    fun `an expired signer leaf verifies, one not yet valid at the signed ts does not`() {
        val expired = leaf(validity = window("20260101000000Z", "20261101000000Z"))
        assertEquals(ts, verified(check(Seed(chain = chain(leaf = expired)))))
        val notYet = leaf(validity = window("20261101000000Z", "20261201000000Z"))
        refused(check(Seed(chain = chain(leaf = notYet))), "outside its validity at $ts")
    }

    @Test
    fun `another root, another signer, a non-canonical payload or another channel is refused`() {
        val bytes = Seed().bytes()
        refused(check(bytes, under = MozillaRemoteSettings.DEFAULT), "the x5u chain fails")
        refused(check(Seed(key = intermediateKey.private)), "does not verify")
        val spaced =
            Seed().let {
                it
                    .payload()
                    .decodeToString()
                    .replaceFirst(",", ", ")
                    .encodeToByteArray()
            }
        refused(check(Seed().apply { payload = spaced }), "not the canonical payload")
        refused(check(bytes, channel = CrliteChannel.DEFAULT), "the seed is for COMPAT, not DEFAULT")
    }

    @Test
    fun `a missing entry, no archive, or a truncated one is refused`() {
        for (name in listOf(SeedArchive.SEED_JSON, SeedArchive.RECORDS, SeedArchive.SIGNATURE, SeedArchive.X5U)) {
            val missing = Seed().apply { configure = { entries.removeAll { it.name == name } } }
            refused(check(missing), "holds no $name")
        }
        refused(check(null), "there is no archive")
        val bytes = Seed().bytes()
        assertIs<SeedSignature.Refused>(check(bytes.copyOf(bytes.size - 1)))
        assertIs<SeedSignature.Refused>(check(bytes.copyOf(bytes.size / 2)))
    }
}
