// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.DiagnosticCode
import dev.revokt.FetchRequest
import dev.revokt.FetchResponse
import dev.revokt.FilterFormat
import dev.revokt.Freshness
import dev.revokt.RevoktLimits
import dev.revokt.RevoktStorage
import dev.revokt.Rule
import dev.revokt.SyncOutcome
import dev.revokt.SyncStage
import dev.revokt.TrustClass
import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.evaluate.dataStates
import dev.revokt.engine.fetch.C2spMirrorClient
import dev.revokt.engine.fetch.C2spMirrorSource
import dev.revokt.engine.fetch.ImfFixdate
import dev.revokt.engine.fetch.ScriptedFetcher
import dev.revokt.engine.fetch.ok
import dev.revokt.engine.fetch.response
import dev.revokt.engine.policy.PolicyForm
import dev.revokt.engine.policy.Preset
import dev.revokt.engine.store.GenerationNames
import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.SourceRecord
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.store.UpdaterRecord
import dev.revokt.engine.update.UpdateFixtures.TestEngine
import dev.revokt.engine.update.UpdateFixtures.log
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import okio.ByteString
import okio.ByteString.Companion.encodeUtf8
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The scripted C2SP mirror, store and helpers of [MirrorSyncTest] and [MirrorBootstrapTest] (#194). The filters are v4
 * files written field by field ([UpdateFixtures.v4]), so their coverage can sit at any time relative to the sync's clock.
 */
internal open class MirrorSyncFixture {
    protected val hour = 3_600_000L
    protected val day = 24 * hour

    /** The sync's clock: 2027-01-15T08:00:00Z. */
    protected val now = 1_800_000_000_000
    protected val base = "https://mirror.example/revocation/"

    /** The store's storage: in memory, its reads and writes failing where a test says. */
    protected class Failing(
        val inner: RevoktStorage = RevoktStorage.inMemory(),
    ) : RevoktStorage by inner {
        var failWrite: (String) -> Boolean = { false }
        var failRead: (String) -> Boolean = { false }

        override fun read(name: String): ByteArray? {
            if (failRead(name)) throw java.io.IOException("injected: $name")
            return inner.read(name)
        }

        override fun write(
            name: String,
            bytes: ByteArray,
        ) {
            if (failWrite(name)) throw java.io.IOException("injected: $name")
            inner.write(name, bytes)
        }
    }

    protected val storage = Failing()
    protected val store = StoreLayout(storage, Dataset.CRLITE, CrliteChannel.COMPAT)
    protected val empty = DatasetGeneration(null, null, null, false, null, null, false, false, false)
    protected val snapshot = SnapshotRef(GenerationSnapshot(0, mapOf(Dataset.CRLITE to empty), null))

    /** A v4 filter covering log [i] for a day up to [high]. */
    protected fun filter(
        i: Int,
        high: Long = now - 3 * hour,
    ): ByteArray = UpdateFixtures.v4(listOf(log(i) to (high - day to high)))

    protected fun hex(bytes: ByteArray): String = bytes.toByteString().sha256().hex()

    /**
     * The scripted mirror at [url]: `manifest.json` listing [files] (name to body), each served at the base followed by
     * its name; [entries] overrides the listed entries, [manifest] the manifest's answer.
     */
    protected inner class Mirror(
        var files: List<Pair<String, ByteArray>>,
        val url: String = base,
    ) {
        var entries: () -> String = {
            files.joinToString(",") { (name, body) ->
                """{"filename":"$name","size":${body.size},"hash":"${hex(body)}"}"""
            }
        }
        var manifest: ((FetchRequest) -> FetchResponse)? = null
        private val prefix = if (url.endsWith("/")) url else "$url/"
        val manifestUrl get() = prefix + "manifest.json"

        val json: String get() = """{"generated_at":1799990000,"comment":"test mirror","files":[${entries()}]}"""

        /** The generation id: the manifest's SHA-256. */
        val id: String get() = json.encodeUtf8().sha256().hex()

        val fetcher =
            ScriptedFetcher { r ->
                if (r.url == manifestUrl) {
                    manifest?.invoke(r) ?: ok(json)
                } else {
                    files.firstOrNull { prefix + it.first == r.url }?.let { response(200, it.second) } ?: response(404)
                }
            }

        fun fileRequests(): List<FetchRequest> = fetcher.requests.filter { it.url != manifestUrl }
    }

    protected fun client(
        url: String,
        fetcher: ScriptedFetcher,
        maxManifestEntries: Int = RevoktLimits.MAX_MANIFEST_ENTRIES,
        io: CoroutineDispatcher = Dispatchers.Default,
    ): C2spMirrorClient =
        C2spMirrorClient(C2spMirrorSource.Builder(url).build(), fetcher, io, maxManifestEntries = maxManifestEntries)

    protected fun sync(
        mirror: Mirror,
        at: Long = now,
        engine: TestEngine = TestEngine(),
        maxManifestEntries: Int = RevoktLimits.MAX_MANIFEST_ENTRIES,
        client: C2spMirrorClient = client(mirror.url, mirror.fetcher, maxManifestEntries),
    ): SyncRun = checkNotNull(attempt(mirror, at, engine, client)) { "the sync did not run" }

    /** The sync's run, or null when it does not run (the bootstrap condition does not hold, #207's Q1). */
    protected fun attempt(
        mirror: Mirror,
        at: Long = now,
        engine: TestEngine = TestEngine(),
        client: C2spMirrorClient = client(mirror.url, mirror.fetcher),
    ): SyncRun? = MirrorSync(client, store, engine, snapshot, day, UpdateFixtures.Recording()).syncOnce(at)

    protected fun SyncRun.assert(
        outcome: SyncOutcome,
        stage: SyncStage? = null,
        vararg codes: DiagnosticCode,
    ): SyncRun {
        assertEquals(outcome to stage, result.outcome to result.stage, "$result")
        assertEquals(codes.toList(), result.warnings.map { it.code }, "$result")
        return this
    }

    protected fun failed(vararg codes: DiagnosticCode): Array<DiagnosticCode> =
        arrayOf(DiagnosticCode.SYNC_FAILED, *codes)

    protected fun live(): DatasetGeneration = snapshot.snapshot.datasets.getValue(Dataset.CRLITE)

    protected fun pointer(): Pointer? = (store.pointer() as? StoreRead.Found)?.value

    protected fun updater(): UpdaterRecord = (store.updater(now) as? StoreRead.Found)?.value?.record ?: UpdaterRecord()

    /** Nothing but `updater.json` is stored: no blob, no directory, no pointer. */
    protected fun assertNothingWritten() {
        assertEquals(listOf("crlite/compat/updater.json"), storage.names().sorted())
        assertNull(live().generationId)
    }

    protected fun installed(mirror: Mirror): String {
        sync(mirror).assert(SyncOutcome.INSTALLED)
        return checkNotNull(pointer()).live
    }

    /** A stored generation of [trustClass] as [UpdateFixtures.pending] builds it, written but not pointed to. */
    protected fun stored(
        trustClass: TrustClass,
        id: String,
    ): String {
        val g = UpdateFixtures.pending(store, trustClass = trustClass, generationId = id)
        return store.writeGeneration(g.meta, g.index, staged(g), g.records)
    }

    /** [g]'s delta files as [UpdateFixtures.pending] staged them in its directory, by name. */
    protected fun staged(g: PendingGeneration): Map<String, ByteArray> =
        g.deltas.mapValues { (name, _) -> checkNotNull(store.file(g.meta.directory, name)) { "$name is not staged" } }

    /** Nothing fetched, the store's keys unchanged, and the `SIGNED` directory [signed] still complete. */
    protected fun assertStopped(
        mirror: Mirror,
        signed: String?,
        expect: (SyncRun?) -> Unit = { assertNull(it, "the sync does not run") },
    ) {
        val before = contents()
        expect(attempt(mirror))
        assertTrue(mirror.fetcher.requests.isEmpty(), "nothing fetched")
        assertEquals(before, contents(), "every key and its bytes unchanged, updater.json included")
        signed?.let { assertEquals(TrustClass.SIGNED, checkNotNull(store.meta(it)).trustClass) }
    }

    /** Every stored key and its bytes, read past any injected fault. */
    protected fun contents(): Map<String, ByteString> =
        storage.names().sorted().associateWith { checkNotNull(storage.inner.read(it)).toByteString() }

    /** An `updater.json` with a watermark, the seed's install time and another source's cursor, as a real one has. */
    protected fun realUpdater() {
        val source = SourceRecord(lastVerifiedLastModified = 1_792_587_631_204, consecutiveFailures = 2)
        store.writeUpdater(
            UpdaterRecord(
                watermarkMillis = 1_700_000_000_000,
                seedInstalledAtMillis = 456,
                sources = mapOf("mozilla-remote-settings" to source),
            ),
            now,
        )
    }
}
