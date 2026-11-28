// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.engine.seed

import dev.revokt.ClubcardCorpus
import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.FilterFormat
import dev.revokt.Freshness
import dev.revokt.RevoktLimits
import dev.revokt.SeedSource
import dev.revokt.SyncOutcome
import dev.revokt.WarningCode
import dev.revokt.engine.evaluate.dataStates
import dev.revokt.engine.policy.PolicyForm
import dev.revokt.engine.policy.Preset
import dev.revokt.engine.seed.parse.SeedArchive
import dev.revokt.engine.seed.parse.TestZip
import dev.revokt.engine.store.GenerationNames
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.update.FilterRead
import dev.revokt.engine.update.IndexBuild
import dev.revokt.engine.update.UpdateFixtures
import dev.revokt.engine.update.UpdateFixtures.TestEngine
import dev.revokt.engine.update.buildIndex
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Spec §6.5 "Seed archive" and §7.2 "Seeds", the loader (#138): its order (verified as raw bytes before any decode), its
 * header and engine rules, the entry names and caps, the timestamps it takes from the verified bytes, and the
 * generation it installs. The store's failure arms are [SeedLoaderStoreTest].
 */
internal class SeedLoaderTest : SeedFixture() {
    private val generationId = "$ts/${delta.id}"

    @Test
    fun `a seed installs as a SIGNED generation from the seed, with the watermark and seedInstalledAtMillis`() {
        val now = ts + hour
        val engine = TestEngine()
        val seed = Seed()
        val load = installed(load(seed, now, engine))
        assertEquals(listOf(generationId, ts), listOf(load.generationId, load.timestampMillis))
        assertEquals(load.name, live().generationFile)
        assertEquals(emptyList(), load.warnings)
        assertEquals(generationId, engine.live)
        val live = live()
        assertTrue(live.fromSeed)
        assertEquals(1, live.seedFormat)
        assertEquals(Freshness.SEED_SIGNED_TIME, live.freshness)
        assertEquals(ts, live.sourceTimestampMillis)
        assertFalse(live.staleGateOpen, "a fetching source: the gate opens once a sync attempt completes")
        assertEquals(load.name, liveName())
        val record = updater(now)
        assertEquals(ts, record.watermarkMillis)
        assertEquals(now, record.seedInstalledAtMillis)
        assertNull(record.datasetLastAttemptAtMillis)
        val stored = stored(load.name)
        assertEquals(Freshness.SEED_SIGNED_TIME, stored.file.freshness)
        assertEquals(1, stored.file.seedFormat)
        assertEquals(FilterFormat.V3, loaded(load.name).format)
        assertEquals(ts, stored.timestampMillis)
        assertContentEquals(seed.payload(), stored.file.payload)
        assertContentEquals(seed.index(), loaded(load.name).files.bytes(StoreLayout.INDEX))
    }

    @Test
    fun `a seed install decodes every filter whole, so one whose coverage alone reads is SEED_UNREADABLE, unwritten`() {
        // A v4 trailing byte (§6.3 rejects it) behind a coverage that reads, its record's hash over those bytes, and a
        // shipped index.bin built from coverage alone, so only the install's whole decode refuses it, before any file.
        val body = UpdateFixtures.v4(listOf(UpdateFixtures.log(2) to (1L to 2L))) + byteArrayOf(0)
        val bad = Rec("d2", true, delta.effectiveTimestamp + 1, "d2.filter.delta", body, parent = full.id)
        val seed = Seed(records = listOf(full, delta, bad))
        val coverageIndex =
            buildIndex(seed.filterRecords(), CrliteChannel.COMPAT, FilterRead.COVERAGE) { r ->
                seed.body(seed.records.single { it.id == r.id })
            }
        seed.index = assertIs<IndexBuild.Built>(coverageIndex).index
        assertUnreadable(load(seed), "index.bin cannot be rebuilt")
        assertIs<StoreRead.Absent>(store.pointer())
    }

    @Test
    fun `with no fetching source the STALE gate is open at once`() {
        installed(load(Seed(), fetchingSource = false))
        assertTrue(live().staleGateOpen)
    }

    @Test
    fun `100, nothing loadable, a seed at 80 sets the watermark to 80, then a sync at 90 installs`() {
        // ts stands for 80; the stored watermark is 100 and no generation is loadable (an empty store).
        store.writeUpdater(
            dev.revokt.engine.store
                .UpdaterRecord(watermarkMillis = ts + 20 * hour),
            ts,
        )
        val now = ts + hour
        installed(load(Seed(), now))
        assertEquals(ts, updater(now).watermarkMillis)
        // 90 is above the floor, max(80, 80), so it installs, where a kept watermark of 100 would refuse it.
        val ninety = ts + 10 * hour
        sync(Server(ts = ninety), now = ninety + hour).assert(dev.revokt.SyncOutcome.INSTALLED)
        assertEquals(ninety, updater(ninety + hour).watermarkMillis)
        assertEquals(ninety, live().sourceTimestampMillis)
    }

    @Test
    fun `a seed that installs beside a loaded generation keeps the higher watermark`() {
        val older = ts - hour
        installed(load(Seed(ts = older)))
        // The older seed is live and pointed: a loaded generation. A watermark above both is kept.
        store.writeUpdater(updater().copy(watermarkMillis = ts + day), ts)
        installed(load(Seed(), ts + 2 * hour))
        assertEquals(ts + day, updater(ts + 2 * hour).watermarkMillis)
    }

    @Test
    fun `a trusted stored generation counts as loaded at a fresh start, so the higher watermark is kept`() {
        installed(load(Seed(ts = ts - hour)))
        store.writeUpdater(updater().copy(watermarkMillis = ts + day), ts)
        // A fresh start: nothing is live in the snapshot, but the pointer and its older generation read.
        reset(keepStore = true)
        installed(load(Seed(), ts + 2 * hour))
        assertEquals(ts + day, updater(ts + 2 * hour).watermarkMillis)
    }

    @Test
    fun `a generation the engine serves beside a malformed pointer counts as loaded, keeping the higher watermark`() {
        installed(load(Seed(ts = ts - hour)))
        store.writeUpdater(updater().copy(watermarkMillis = ts + day), ts)
        // No trusted pointer, but the older seed is still live in the engine and the snapshot.
        storage.inner.write(pointerKey, "{".encodeToByteArray())
        installed(load(Seed(), ts + 2 * hour))
        assertEquals(ts + day, updater(ts + 2 * hour).watermarkMillis)
    }

    @Test
    fun `with nothing loaded the watermark becomes the seed's timestamp, and the rest of updater_json stays`() {
        val sourceRecord =
            dev.revokt.engine.store.SourceRecord(
                lastVerifiedLastModified = ts - day,
                consecutiveFailures = 2,
            )
        store.writeUpdater(
            dev.revokt.engine.store.UpdaterRecord(
                ts + day,
                null,
                ts - hour,
                mapOf("mozilla-remote-settings" to sourceRecord),
            ),
            ts,
        )
        installed(load(Seed()))
        val record = updater()
        // §7.1: no generation loaded, so the seed's install sets the watermark to its <ts>, lowered from ts + day.
        assertEquals(ts, record.watermarkMillis)
        assertEquals(ts - hour, record.datasetLastAttemptAtMillis)
        assertEquals(sourceRecord, record.sources["mozilla-remote-settings"])
        reset()
        store.writeUpdater(
            dev.revokt.engine.store
                .UpdaterRecord(ts - day),
            ts,
        )
        installed(load(Seed()))
        assertEquals(ts, updater().watermarkMillis)
    }

    @Test
    fun `a records_json whose signature fails is never decoded, nor one whose chain fails`() {
        // The signature is over other bytes and records.json is not JSON: a decode first would say "not JSON".
        val notJson = "not json {".encodeToByteArray()
        val badSignature =
            Seed().apply {
                payload = notJson
                signature = Seed().signature()
            }
        assertUnreadable(load(badSignature), "does not verify")
        val badChain = Seed().apply { payload = notJson }
        assertUnreadable(load(badChain, pins = setOf(hash(leafKey))), "the x5u chain fails")
        // The control: the same records.json, signed, is decoded and fails as JSON.
        assertUnreadable(load(Seed().apply { payload = notJson }), "records.json is not JSON")
    }

    @Test
    fun `a seed with an expired signer leaf loads, its validity checked at the signed timestamp (data-path d)`() {
        val expired = leaf(validity = window("20260101000000Z", "20261101000000Z"))
        val now = millis("2026-11-16T00:00:00Z")
        val engine = TestEngine()
        val load = installed(load(Seed(chain = chain(leaf = expired)), now, engine))
        assertEquals(generationId, engine.live)
        assertEquals(generationId, load.generationId)
        val notYet = leaf(validity = window("20261101000000Z", "20261201000000Z"))
        reset()
        assertUnreadable(load(Seed(chain = chain(leaf = notYet)), now), "outside its validity at $ts")
    }

    @Test
    fun `a seed 25 h ahead loads like any other, with ageMillis 0, no warning and the watermark at its timestamp`() {
        val now = ts - 25 * hour
        val load = installed(load(Seed(), now))
        assertEquals(emptyList(), load.warnings)
        assertEquals(ts, updater(now).watermarkMillis)
        val state = dataStates(snapshot.snapshot, PolicyForm.of(Preset.DEFAULT), now).getValue(Dataset.CRLITE)
        assertEquals(0, state.ageMillis)
        assertTrue(state.fromSeed)
    }

    @Test
    fun `a seed with a 70 MiB declared attachment is unreadable before any attachment is inflated`() {
        val huge =
            Rec(
                delta.id,
                true,
                delta.effectiveTimestamp,
                delta.filename,
                delta.body,
                size = 70L shl 20,
                parent = full.id,
            )
        val seed = Seed(records = listOf(full, huge)).apply { index = Seed().index() }
        val bytes = seed.bytes()
        val counted = Counted { bytes }
        assertUnreadable(loader(counted.source).load(ts + hour), "over MAX_FILTER_BYTES")
        assertEquals(3, counted.opens, "the central directory, seed.json and the fixed entries; no attachment pass")
    }

    @Test
    fun `attachment filenames of 33 and 64 characters load under their derived names`() {
        val name33 = "a".repeat(29) + ".flt"
        val name64 = "b".repeat(56) + ".delta.x"
        val fullLong = Rec(full.id, false, full.effectiveTimestamp, name33, full.body)
        val deltaLong = Rec(delta.id, true, delta.effectiveTimestamp, name64, delta.body, parent = full.id)
        val name = installed(load(Seed(records = listOf(fullLong, deltaLong)))).name
        val files = loaded(name).files
        assertEquals(
            setOf(StoreLayout.INDEX, GenerationNames.derive(name33), GenerationNames.derive(name64)),
            files.names,
        )
        assertEquals(32, GenerationNames.derive(name64).length)
    }

    @Test
    fun `two filenames that map to one name are unreadable`() {
        val long = "c".repeat(40)
        val fullLong = Rec(full.id, false, full.effectiveTimestamp, long, full.body)
        val deltaAsDerived =
            Rec(delta.id, true, delta.effectiveTimestamp, GenerationNames.derive(long), delta.body, parent = full.id)
        val seed = Seed(records = listOf(fullLong, deltaAsDerived)).apply { index = Seed().index() }
        assertUnreadable(load(seed), "INDEX_INCONSISTENT")
    }

    @Test
    fun `each entry cap is enforced while inflating, against a lying zip header`() {
        val caps =
            mapOf(
                SeedArchive.SEED_JSON to (64L shl 10),
                SeedArchive.RECORDS to RevoktLimits.MAX_JSON_BYTES,
                SeedArchive.SIGNATURE to SeedLoader.MAX_SIGNATURE_BYTES,
                SeedArchive.X5U to RevoktLimits.MAX_X5U_BYTES,
                SeedArchive.INDEX to (1L shl 20),
                SeedArchive.ATTACHMENTS + delta.filename to delta.body.size.toLong(),
            )
        for ((name, cap) in caps) {
            val seed =
                Seed().apply {
                    configure = {
                        val i = entries.indexOfFirst { it.name == name }
                        // The data is one byte over the cap; the headers declare the real entry's size.
                        val real = entries[i]
                        entries[i] =
                            TestZip.Entry(name, ByteArray(cap.toInt() + 1), TestZip.DEFLATED).apply {
                                size = real.data.size.toLong()
                                crc = real.realCrc
                            }
                    }
                }
            assertUnreadable(load(seed), "past its cap of $cap bytes")
        }
    }

    @Test
    fun `a mutated index_bin or records_json is unreadable`() {
        val index = Seed().index().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }
        assertUnreadable(load(Seed().apply { this.index = index }), "the shipped index.bin differs")
        val records = Seed().payload().also { it[10] = (it[10] + 1).toByte() }
        assertUnreadable(
            load(
                Seed().apply {
                    payload = records
                    signature = Seed().signature()
                },
            ),
            "does not verify",
        )
    }

    @Test
    fun `the header and engine rules, seedFormat 2, an engineFloor above this engine, another dataset or format`() {
        assertUnreadable(load(Seed().apply { header = header + ("seedFormat" to 2) }), "seedFormat 2")
        assertUnreadable(load(Seed().apply { header = header + ("seedFormat" to 0) }), "seedFormat 0")
        assertUnreadable(load(Seed().apply { header = header + ("engineFloor" to 2) }), "engineFloor 2")
        assertUnreadable(load(Seed().apply { header = header + ("dataset" to "ONECRL") }), "dataset ONECRL")
        assertUnreadable(load(Seed().apply { header = header + ("filterFormat" to "v3") }), "not a filter format")
        assertUnreadable(load(Seed(), engine = TestEngine(setOf(FilterFormat.V4))), "V3 is not in the engine's [V4]")
        assertUnreadable(load(Seed().apply { header = header - "recordsLastModified" }), "recordsLastModified")
        // seed.json's recordsLastModified is a hint: the verified <ts> decides.
        installed(load(Seed().apply { header = header + ("recordsLastModified" to 1) }))
        assertEquals(ts, live().sourceTimestampMillis)
    }

    @Test
    fun `a filterFormat other than the decoded full's is unreadable, a delta in another listed encoding is not`() {
        // Both formats listed, so the header read passes: the decoded full decides.
        assertUnreadable(
            load(Seed().apply { header = header + ("filterFormat" to "V4") }),
            "filterFormat V4 is not the full filter's encoding, V3",
        )
        val v4 = ClubcardCorpus.file(UpdateFixtures.DELTA_PATH + ".v4").readBytes()
        val mixed = Rec(delta.id, true, delta.effectiveTimestamp, delta.filename, v4, parent = full.id)
        assertEquals(FilterFormat.V3, loaded(installed(load(Seed(records = listOf(full, mixed)))).name).format)
        reset()
        assertUnreadable(
            load(Seed(records = listOf(full, mixed)).apply { header = header + ("filterFormat" to "V4") }),
            "filterFormat V4 is not the full filter's encoding, V3",
        )
    }

    @Test
    fun `a channel mismatch is SEED_CHANNEL_MISMATCH from the header read alone`() {
        val seed = Seed().apply { header = header + ("channel" to "DEFAULT") }
        val bytes = seed.bytes()
        val counted = Counted { bytes }
        val mismatch = assertIs<SeedLoad.ChannelMismatch>(loader(counted.source).load(ts))
        assertEquals("DEFAULT", mismatch.seedChannel)
        assertEquals(WarningCode.SEED_CHANNEL_MISMATCH, mismatch.warnings.single().code)
        assertEquals(2, counted.opens, "the central directory and seed.json only")
        assertIs<SeedLoad.ChannelMismatch>(loader(counted.source).checkHeader())
        assertNothingInstalled()
    }

    @Test
    fun `the header read alone passes a good seed and reads nothing else`() {
        val bytes = Seed().bytes()
        val counted = Counted { bytes }
        assertNull(loader(counted.source).checkHeader())
        assertEquals(2, counted.opens)
        assertIs<SeedLoad.Absent>(loader(SeedSource.none()).checkHeader())
        assertIs<SeedLoad.Unreadable>(loader(Counted { ByteArray(3) }.source).checkHeader())
    }

    @Test
    fun `no name comes from the zip, so traversal, nesting, absolute, backslash, duplicate, extra and case fail`() {
        for (name in listOf(
            "attachments/../x",
            "attachments/a/b",
            "/abs",
            "attachments\\x",
            "Attachments/x",
            "extra",
        )) {
            assertUnreadable(load(Seed().apply { configure = { add(name, ByteArray(1)) } }), "extra entry")
        }
        assertUnreadable(
            load(Seed().apply { configure = { add(SeedArchive.RECORDS, ByteArray(1)) } }),
            "duplicate entry",
        )
        val upper = delta.filename.uppercase()
        val cased =
            Seed().apply {
                configure =
                    {
                        entries.removeIf { it.name.endsWith(delta.filename) }
                        add("attachments/$upper", delta.body)
                    }
            }
        assertUnreadable(load(cased), "extra entry")
        val missing = Seed().apply { configure = { entries.removeIf { it.name.endsWith(delta.filename) } } }
        assertUnreadable(load(missing), "no attachments/${delta.filename}")
        val reordered = Seed().apply { configure = { directoryOrder = listOf(1, 0) + (2 until entries.size) } }
        assertUnreadable(load(reordered), "not seed.json")
    }

    @Test
    fun `the attachments are the channel's placed records only`() {
        // records.json holds every channel's records; the other channel's attachments are not entries of this seed.
        val other = Rec("d-other", false, full.effectiveTimestamp, "other.filter", full.body, channel = "default")
        installed(load(Seed(records = listOf(full, delta, other))))
        val withOther =
            Seed(records = listOf(full, delta, other)).apply {
                configure =
                    { add("attachments/other.filter", full.body) }
            }
        reset()
        assertUnreadable(load(withOther), "extra entry \"attachments/other.filter\"")
    }

    @Test
    fun `an attachment that does not match its signed record is unreadable, and its staged directory is deleted`() {
        val index = Seed().index()
        val seed =
            Seed().apply {
                bodies = mapOf(delta.filename to delta.body.copyOf().also { it[0] = (it[0] + 1).toByte() })
                this.index = index
            }
        assertUnreadable(load(seed), "does not match its signed size and hash")
    }

    @Test
    fun `records_json must be the canonical payload, timestamp and all`() {
        fun signed(payload: String) = Seed().apply { this.payload = payload.encodeToByteArray() }
        val canonical = Seed().payload().decodeToString()
        assertUnreadable(load(signed(canonical.replace("\"data\":", "\"data\" :"))), "not the canonical payload")
        assertUnreadable(load(signed("[]")), "no data array")
        assertUnreadable(load(signed("""{"data":[1],"last_modified":"1"}""")), "not an object")
        assertUnreadable(load(signed("""{"data":[],"last_modified":1}""")), "13-digit timestamp")
        assertUnreadable(load(signed("""{"data":[],"last_modified":"99999999999999"}""")), "13-digit timestamp")
        assertUnreadable(load(signed("""{"data":[],"last_modified":"-1"}""")), "13-digit timestamp")
        assertUnreadable(
            load(signed("""{"data":[{"id":"a","deleted":true}],"last_modified":"1"}""")),
            "not the canonical payload",
        )
        assertUnreadable(load(signed("""{"data":[{"id":"a"}],"last_modified":"$ts"}""")), "fails the schema")
        assertUnreadable(load(signed("""{"data":[],"last_modified":"$ts"}""")), "builds no generation")
    }

    @Test
    fun `x5u_pem and signature that do not read are unreadable`() {
        assertUnreadable(
            load(
                Seed().apply {
                    configure =
                        {
                            entry(
                                "x5u.pem",
                            ).let {
                                entries[
                                    entries.indexOf(
                                        it,
                                    ),
                                ] = TestZip.Entry("x5u.pem", "junk".encodeToByteArray())
                            }
                        }
                },
            ),
            "not a PEM chain",
        )
        assertUnreadable(load(Seed().apply { signature = "not base64url!" }), "does not verify")
    }

    @Test
    fun `a coverage end beyond the signed timestamp installs, as no rule compares the two`() {
        val early = ts - 400 * day
        assertEquals(early, installed(load(Seed(ts = early))).timestampMillis)
    }

    @Test
    fun `a stored SIGNED generation not older than the seed is kept and the seed skipped, with nothing written`() {
        installed(load(Seed()))
        val before = storage.inner.names().associateWith { checkNotNull(storage.inner.read(it)).toList() }
        val skipped = assertIs<SeedLoad.Skipped>(load(Seed()))
        assertEquals(ts to ts, skipped.seedTimestampMillis to skipped.storedTimestampMillis)
        assertEquals(before, storage.inner.names().associateWith { checkNotNull(storage.inner.read(it)).toList() })
        assertIs<SeedLoad.Skipped>(load(Seed(ts = ts - hour)))
    }

    @Test
    fun `a newer seed replaces an older stored SIGNED generation, which becomes previous`() {
        val older = Seed(ts = ts - hour)
        installed(load(older))
        val oldName = checkNotNull(liveName())
        val newName = installed(load(Seed())).name
        val pointer = assertIs<StoreRead.Found<dev.revokt.engine.store.Pointer>>(store.pointer()).value
        assertEquals(newName to oldName, pointer.live to pointer.previous)
    }

    @Test
    fun `an archive over its total cap fails closed, so a source that never ends ends`() {
        val endless =
            SeedSource.of {
                object : java.io.InputStream() {
                    override fun read(): Int = 0

                    override fun read(
                        b: ByteArray,
                        off: Int,
                        len: Int,
                    ): Int = len.also { b.fill(0, off, off + len) }
                }
            }
        // A source fault, not a store fault: no store failure (#138).
        val load = assertUnreadable(loader(endless).load(ts), "over its cap of ${SeedArchive.MAX_BYTES} bytes")
        assertEquals(0, load.storeFailures)
        assertEquals(0, assertIs<SeedLoad.Unreadable>(loader(endless).checkHeader()).storeFailures)
    }

    @Test
    fun `a failed prepare or activate is unreadable, counted, installs nothing and deletes nothing`() {
        val throwing = TestEngine().apply { onPrepare = { error("corrupt") } }
        val prepare = assertUnreadable(load(Seed(), engine = throwing), "the install failed", written = true)
        assertEquals(1, prepare.storeFailures)
        val activate = TestEngine().apply { onActivate = { error("activate") } }
        assertEquals(
            1,
            assertUnreadable(load(Seed(), engine = activate), "ENGINE_FAILED", written = true).storeFailures,
        )
    }

    @Test
    fun `no archive is Absent, and one that cannot be opened or read is unreadable`() {
        assertIs<SeedLoad.Absent>(loader(SeedSource.none()).load(ts))
        assertUnreadable(loader(SeedSource.of { error("unreadable") }).load(ts), "unreadable")
        var opens = 0
        val bytes = Seed().bytes()
        val vanishing = SeedSource.of { if (opens++ < 2) java.io.ByteArrayInputStream(bytes) else null }
        assertUnreadable(loader(vanishing).load(ts), "gone on a second open")
        val shrinking = SeedSource.of { java.io.ByteArrayInputStream(if (opens++ < 2) bytes else bytes.copyOf(100)) }
        opens = 0
        assertUnreadable(loader(shrinking).load(ts), "EOF")
    }
}
