// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.seed

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.SeedSource
import dev.revokt.engine.fetch.json
import dev.revokt.engine.seed.parse.SeedArchive
import dev.revokt.engine.seed.parse.TestZip
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.update.CrliteSyncFixture
import dev.revokt.engine.update.DatasetGeneration
import dev.revokt.engine.update.FilterRecord
import dev.revokt.engine.update.GenerationSnapshot
import dev.revokt.engine.update.IndexBuild
import dev.revokt.engine.update.UpdateFixtures.TestEngine
import dev.revokt.engine.update.buildIndex
import dev.revokt.engine.verify.ContentSignature
import dev.revokt.verify.JcaFixtures
import okio.ByteString
import java.io.ByteArrayInputStream
import java.security.PrivateKey
import java.util.Base64
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Seeds for the loader tests (#138), built in the test with [TestZip] over the sync fixture's records, filters and x5u
 * chain (#145's writer comes later and round-trips against the loader): every part replaceable, and the archive's
 * entries editable through [Seed.configure].
 */
internal open class SeedFixture : CrliteSyncFixture() {
    protected val collection = "security-state/cert-revocations"

    /** One seed: its records signed at [ts] under [key] with [chain] as `x5u.pem`, and each part's override. */
    protected inner class Seed(
        var records: List<Rec> = listOf(full, delta),
        var ts: Long = this@SeedFixture.ts,
        var chain: List<ByteArray> = served,
        var key: PrivateKey = leafKey.private,
    ) {
        var header: Map<String, Any> =
            linkedMapOf(
                "seedFormat" to 1,
                "channel" to "COMPAT",
                "dataset" to "CRLITE",
                "filterFormat" to "V3",
                "recordsLastModified" to ts,
                "engineFloor" to 1,
            )
        var payload: ByteArray? = null
        var signature: String? = null
        var index: ByteArray? = null

        /** The attachment bodies by filename, the records' own unless set. */
        var bodies: Map<String, ByteArray>? = null
        var configure: TestZip.() -> Unit = {}

        fun headerJson(): ByteArray =
            header.entries
                .joinToString(",", "{", "}") { (k, v) -> "\"$k\":" + if (v is String) "\"$v\"" else "$v" }
                .encodeToByteArray()

        fun payload(): ByteArray =
            payload ?: checkNotNull(ContentSignature.recordsJson(records.map { json(it.json()) }, ts))

        fun signature(): String =
            signature ?: Base64.getUrlEncoder().withoutPadding().encodeToString(
                JcaFixtures.sign(
                    "SHA384withECDSAinP1363Format",
                    key,
                    "Content-Signature:\u0000".encodeToByteArray() + payload(),
                ),
            )

        fun filterRecords(): List<FilterRecord> =
            records.map { FilterRecord(it.id, it.channel, it.incremental, it.effectiveTimestamp, it.filename) }

        fun index(): ByteArray =
            index ?: (
                buildIndex(filterRecords(), CrliteChannel.COMPAT) { r -> body(records.single { it.id == r.id }) }
                    as IndexBuild.Built
            ).index

        fun body(r: Rec): ByteArray = bodies?.get(r.filename) ?: r.body

        fun zip(): TestZip =
            TestZip()
                .add(SeedArchive.SEED_JSON, headerJson(), TestZip.STORED)
                .add(SeedArchive.RECORDS, payload())
                .add(SeedArchive.SIGNATURE, signature().encodeToByteArray())
                .add(SeedArchive.X5U, pem(chain).encodeToByteArray())
                .add(SeedArchive.INDEX, index())
                .apply {
                    for (r in records.filter { it.channel == "compat" }) {
                        add(
                            SeedArchive.ATTACHMENTS + r.filename,
                            body(r),
                        )
                    }
                }.apply(configure)

        fun bytes(): ByteArray = zip().bytes()
    }

    /** A source over [bytes] that counts its opens. */
    protected class Counted(
        private val bytes: () -> ByteArray?,
    ) {
        var opens = 0
        val source: SeedSource =
            SeedSource.of {
                opens++
                bytes()?.let(::ByteArrayInputStream)
            }
    }

    protected fun loader(
        source: SeedSource,
        engine: TestEngine = TestEngine(),
        fetchingSource: Boolean = true,
        pins: Set<ByteString> = pinned,
    ): SeedLoader =
        SeedLoader(source, store, engine, snapshot, verifier, SeedPolicy(pins, collection, day, fetchingSource), logger)

    protected fun load(
        seed: Seed,
        now: Long = ts + hour,
        engine: TestEngine = TestEngine(),
        fetchingSource: Boolean = true,
        pins: Set<ByteString> = pinned,
    ): SeedLoad {
        // Built once: each build signs afresh (ECDSA is randomised), and the loader reads one archive.
        val bytes = seed.bytes()
        return loader(Counted { bytes }.source, engine, fetchingSource, pins).load(now)
    }

    protected fun installed(load: SeedLoad): SeedLoad.Installed = assertIs<SeedLoad.Installed>(load, "$load")

    /** [load] is `SEED_UNREADABLE` and says [detail]; nothing is live, pointed or written but blobs. */
    protected fun assertUnreadable(
        load: SeedLoad,
        detail: String,
    ): SeedLoad.Unreadable {
        val unreadable = assertIs<SeedLoad.Unreadable>(load, "$load")
        assertTrue(detail in unreadable.detail, "'${unreadable.detail}' does not say '$detail'")
        assertTrue(unreadable.warnings.single().code == dev.revokt.DiagnosticCode.SEED_UNREADABLE)
        assertNothingInstalled()
        return unreadable
    }

    /** An empty snapshot again, as at a fresh `start()`, and an empty store unless [keepStore]. */
    protected fun reset(keepStore: Boolean = false) {
        if (!keepStore) storage.inner.names().forEach(storage.inner::delete)
        snapshot.publish(
            GenerationSnapshot(
                snapshot.snapshot.generationEpoch,
                mapOf(Dataset.CRLITE to DatasetGeneration(null, null, null, false, null, null, false, false, false)),
                null,
            ),
        )
    }

    /** No pointer, no `updater.json`, no generation directory and nothing live. */
    protected fun assertNothingInstalled() {
        assertIs<StoreRead.Absent>(store.pointer())
        assertIs<StoreRead.Absent>(store.updater(ts))
        assertTrue(storage.names().none { it.contains("/gen-") }, "${storage.names()}")
        assertTrue(
            snapshot.snapshot.datasets
                .getValue(Dataset.CRLITE)
                .generationId == null,
        )
    }
}
