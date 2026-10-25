// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.records

import dev.revokt.engine.parse.producer.ProducerCorpus
import java.io.File

/**
 * One corpus record of spec §9.2 ("Corpus record schema"): `{sha256, path, revokt, oracles, class, divergence?,
 * keyability?, justification, added}`. An input has one record per class it is admitted under. Committed one per line
 * in `parse/records.jsonl`, written by `RecordsTest`'s hook and checked by it against the replay.
 */
internal class CorpusRecord(
    val sha256: String,
    val path: String,
    val revokt: Revokt,
    val oracles: List<Oracle>,
    val recordClass: RecordClass,
    val divergence: String?,
    val keyability: Keyability?,
    val justification: String,
    val added: String,
) {
    /** revokt's outcome: `Parsed` or the `ParseReason`, with the key bytes and SCT pairs when parsed. */
    class Revokt(
        val outcome: String,
        val rawSerial: String?,
        val spkiSha256: String?,
        val scts: List<String>,
    )

    /**
     * One oracle's recorded outcome. Oracle 1 has one entry per matrix JDK, its version the feature release, with [read]
     * the SHA-256 of the bytes revokt reads where they differ from the input.
     */
    class Oracle(
        val id: String,
        val version: String,
        val outcome: String,
        val read: String? = null,
    )

    /** The D8-gap fields: oracle 4's path, the first failing `KeyabilityClause` and the pinned zlint errors. */
    class Keyability(
        val parser: String,
        val clause: String,
        val zlint: String,
    )

    enum class RecordClass {
        D7_LENIENCY,
        D2_REENCODE_ALLOW,
        D3_DIVERGENCE,
        D1_DOM,
        KEYABILITY_GAP,
        FUZZ_FINDING,
        ISSUER_CORPUS,
    }

    /** The record's identity: an input has at most one record per class. */
    val key: Pair<String, RecordClass> get() = sha256 to recordClass

    /** Whether oracle 1 of [version] accepts the input. */
    fun acceptedOn(version: String): Boolean =
        oracles.any {
            it.id == "1" && it.version == version &&
                it.outcome == "Accept"
        }

    fun toJson(): Json.Obj =
        Json.obj(
            "sha256" to Json.Str(sha256),
            "path" to Json.Str(path),
            "revokt" to
                Json.obj(
                    "outcome" to Json.Str(revokt.outcome),
                    "rawSerial" to Json.str(revokt.rawSerial),
                    "spkiSha256" to Json.str(revokt.spkiSha256),
                    "scts" to Json.strings(revokt.scts),
                ),
            "oracles" to
                Json.Arr(
                    oracles.map {
                        Json.obj(
                            "id" to Json.Str(it.id),
                            "version" to Json.Str(it.version),
                            "outcome" to Json.Str(it.outcome),
                            "read" to Json.str(it.read),
                        )
                    },
                ),
            "class" to Json.Str(recordClass.name),
            "divergence" to Json.str(divergence),
            "keyability" to
                keyability?.let {
                    Json.obj(
                        "parser" to Json.Str(it.parser),
                        "clause" to Json.Str(it.clause),
                        "zlint" to Json.Str(it.zlint),
                    )
                },
            "justification" to Json.Str(justification),
            "added" to Json.Str(added),
        )

    companion object {
        private const val RESOURCE = "records.jsonl"

        fun fromJson(j: Json.Obj): CorpusRecord {
            val r = j.child("revokt")
            val recordClass = RecordClass.valueOf(j.string("class"))
            val record =
                CorpusRecord(
                    j.string("sha256"),
                    j.string("path"),
                    Revokt(
                        r.string("outcome"),
                        r.stringOrNull("rawSerial"),
                        r.stringOrNull("spkiSha256"),
                        r.array("scts").map { (it as Json.Str).value },
                    ),
                    j.array("oracles").map {
                        val o = it as Json.Obj
                        Oracle(o.string("id"), o.string("version"), o.string("outcome"), o.stringOrNull("read"))
                    },
                    recordClass,
                    j.stringOrNull("divergence"),
                    j
                        .childOrNull(
                            "keyability",
                        )?.let { Keyability(it.string("parser"), it.string("clause"), it.string("zlint")) },
                    j.string("justification"),
                    j.string("added"),
                )
            check(
                recordClass != RecordClass.D3_DIVERGENCE || record.divergence != null,
            ) { "${record.path}: no divergence" }
            check(
                recordClass != RecordClass.KEYABILITY_GAP || record.keyability != null,
            ) { "${record.path}: no keyability" }
            return record
        }

        /** The committed records. */
        fun committed(): List<CorpusRecord> =
            String(ProducerCorpus.resource(RESOURCE))
                .lineSequence()
                .filter { it.isNotBlank() }
                .map { fromJson(Json.parse(it) as Json.Obj) }
                .toList()

        /** The committed D3_DIVERGENCE records: divergence class → input paths. */
        fun divergences(): Map<String, Set<String>> =
            committed()
                .filter { it.recordClass == RecordClass.D3_DIVERGENCE }
                .groupBy({ it.divergence!! }, { it.path })
                .mapValues { it.value.toSet() }

        /** Writes [records] sorted by path and class, one per line. */
        fun write(
            file: File,
            records: List<CorpusRecord>,
        ) {
            file.writeText(
                records
                    .sortedWith(compareBy({ it.path }, { it.recordClass }))
                    .joinToString("") { it.toJson().write() + "\n" },
            )
        }
    }
}
