// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.engine.seed

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.SeedSource
import dev.revokt.SyncFailure
import dev.revokt.WarningCode
import dev.revokt.engine.fetch.json
import dev.revokt.engine.generation.DatasetGeneration
import dev.revokt.engine.generation.GenerationSnapshot
import dev.revokt.engine.seed.parse.SeedArchive
import dev.revokt.engine.seed.parse.TestZip
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.update.CrliteSyncFixture
import dev.revokt.engine.update.FilterRecord
import dev.revokt.engine.update.IndexBuild
import dev.revokt.engine.update.UpdateFixtures.TestEngine
import dev.revokt.engine.update.buildIndex
import dev.revokt.engine.verify.ContentSignature
import dev.revokt.verify.JcaFixtures
import okio.ByteString
import java.io.ByteArrayInputStream
import java.security.PrivateKey
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Seeds for the loader tests (#138), built in the test with [TestZip] over the sync fixture's records, filters and x5u
 * chain (#145's writer comes later and round-trips against the loader): every part replaceable, and the archive's
 * entries editable through [Seed.configure].
 */
internal open class SeedFixture : CrliteSyncFixture() {
    /** Each payload and key's signature, so every build of one seed is the same archive. */
    private val seedSignatures = HashMap<Pair<List<Byte>, PrivateKey>, String>()

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

        /**
         * The signature over [payload] under [key], once per payload and key in this fixture: ECDSA signs with fresh
         * randomness, and a seed built twice must be the same archive, so the same generation file (spec §6.5).
         */
        fun signature(): String =
            signature ?: seedSignatures.getOrPut(payload().toList() to key) {
                Base64.getUrlEncoder().withoutPadding().encodeToString(
                    JcaFixtures.sign(
                        "SHA384withECDSAinP1363Format",
                        key,
                        "Content-Signature:\u0000".encodeToByteArray() + payload(),
                    ),
                )
            }

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
    ): SeedLoader = SeedLoader(source, store, engine, snapshot, verifier, SeedPolicy(pins, fetchingSource), logger)

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
        written: Boolean = false,
    ): SeedLoad.Unreadable {
        val unreadable = assertIs<SeedLoad.Unreadable>(load, "$load")
        assertTrue(detail in unreadable.detail, "'${unreadable.detail}' does not say '$detail'")
        assertTrue(unreadable.warnings.single().code == dev.revokt.WarningCode.SEED_UNREADABLE)
        assertNothingInstalled(written)
        return unreadable
    }

    protected val root = "crlite/compat"
    protected val updaterKey = "$root/updater.json"
    protected val pointerKey = "$root/current"

    /** Every key and its bytes, to show a failure left the store byte-identical. */
    protected fun contents(): Map<String, List<Byte>> =
        storage.inner.names().associateWith { checkNotNull(storage.inner.read(it)).toList() }

    protected fun failed(
        load: SeedLoad,
        detail: String,
        activated: Boolean = false,
    ): SeedLoad.Failed {
        val failed = assertIs<SeedLoad.Failed>(load, "$load")
        assertEquals(SyncFailure.STORE_FAILED, failed.failure)
        assertEquals(activated, failed.activated)
        assertTrue(detail in failed.detail, "'${failed.detail}' does not say '$detail'")
        return failed
    }

    /** A store holding the seed at [at] installed, live and pointed. */
    protected fun installedAt(at: Long): String = installed(load(Seed(ts = at))).name

    /** The generation file [name] and every blob it names, each with its bytes. */
    protected fun files(name: String): Map<String, List<Byte>> {
        val blobs = stored(name).blobNames.map { "${store.root}/blobs/$it" }
        return contents().filterKeys { it == store.generationKey(name) || it in blobs }
    }

    /** An empty snapshot again, as at a fresh `start()`, and an empty store unless [keepStore]. */
    protected fun reset(keepStore: Boolean = false) {
        if (!keepStore) storage.inner.names().forEach(storage.inner::delete)
        snapshot.publish(
            GenerationSnapshot(
                snapshot.snapshot.generationEpoch,
                mapOf(Dataset.CRLITE to DatasetGeneration(null, null, false, null, null, false, false)),
                null,
            ),
        )
    }

    /**
     * No pointer, no `updater.json` and nothing live; no generation file either, unless [written] (an install that wrote
     * its file and then failed, which deletes nothing, §6.5).
     */
    protected fun assertNothingInstalled(written: Boolean = false) {
        assertIs<StoreRead.Absent>(store.pointer())
        assertIs<StoreRead.Absent>(store.updater(ts))
        assertEquals(written, store.generationNames().isNotEmpty(), "${storage.names()}")
        assertTrue(
            snapshot.snapshot.datasets
                .getValue(Dataset.CRLITE)
                .generationId == null,
        )
    }
}
