// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.records

import dev.revokt.engine.parse.oracle.PlatformOracle
import dev.revokt.engine.parse.producer.ExternalCorpus
import dev.revokt.engine.parse.producer.ProducerCorpus
import java.io.File

/**
 * One corpus record of spec §9.2 ("Corpus record schema"): `{sha256, path, revokt, oracles, class, divergence?,
 * keyability?, justification, added}`. An input has one record per class it is admitted under. Committed one per line
 * in `parse/records.jsonl`, and the large corpus's in its `replay/records.jsonl` (ExternalCorpus), written by
 * `RecordsTest`'s hook and checked by it against the replay. The oracle entries
 * carry outcomes only: the replay fails on any platform getter that throws on the committed corpus, so the spec's
 * `fields | unavailable` arrive with the secondary corpus (#15).
 */
internal data class CorpusRecord(
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
    data class Revokt(
        val outcome: String,
        val rawSerial: String?,
        val spkiSha256: String?,
        val scts: List<String>,
    )

    /**
     * One oracle's recorded outcome. A platform oracle has one entry per version (oracle 1 per JDK feature release,
     * oracle 2 per Conscrypt release), with [read] the SHA-256 of the bytes revokt reads where they differ from the input
     * and, on an oracle-dependent record, [holds]: whether the record's class holds on that version.
     */
    data class Oracle(
        val id: String,
        val version: String,
        val outcome: String,
        val read: String? = null,
        val holds: Boolean? = null,
    )

    /**
     * The D8-gap fields: oracle 4's path, the first failing `KeyabilityClause` and the pinned zlint result (`<errors>
     * <fatals>`, or `unparseable`/`panic`).
     */
    data class Keyability(
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

    /** The record's identity: an input has at most one record per class and divergence. */
    val key: Triple<String, RecordClass, String?> get() = Triple(sha256, recordClass, divergence)

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
                            "holds" to it.holds?.let(Json::Bool),
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

        private val RECORD_KEYS =
            setOf("sha256", "path", "revokt", "oracles", "class", "divergence", "keyability", "justification", "added")

        private val ORACLE_KEYS = setOf("id", "version", "outcome", "read", "holds")

        /** A record from its JSON object; an unknown key or a value of the wrong type fails, so a typo cannot vanish. */
        fun fromJson(j: Json.Obj): CorpusRecord {
            j.only(RECORD_KEYS)
            val r = j.child("revokt").only(setOf("outcome", "rawSerial", "spkiSha256", "scts"))
            val recordClass = RecordClass.valueOf(j.string("class"))
            val record =
                CorpusRecord(
                    j.string("sha256"),
                    j.string("path"),
                    Revokt(
                        r.string("outcome"),
                        r.stringOrNull("rawSerial"),
                        r.stringOrNull("spkiSha256"),
                        r.strings("scts"),
                    ),
                    j.array("oracles").map { oracle(it) },
                    recordClass,
                    j.stringOrNull("divergence"),
                    j.childOrNull("keyability")?.only(setOf("parser", "clause", "zlint"))?.let {
                        Keyability(it.string("parser"), it.string("clause"), it.string("zlint"))
                    },
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

        private fun oracle(j: Json): Oracle {
            val o = (j as? Json.Obj ?: error("an oracle entry is not an object")).only(ORACLE_KEYS)
            return Oracle(
                o.string("id"),
                o.string("version"),
                o.string("outcome"),
                o.stringOrNull("read"),
                o.boolOrNull("holds"),
            )
        }

        /** The large corpus's records file, or null without a checkout. */
        val external: File? get() = ExternalCorpus.replay("records.jsonl")

        private val cached: List<CorpusRecord> by lazy {
            parse(String(ProducerCorpus.resource(RESOURCE))) +
                external
                    ?.takeIf { it.isFile }
                    ?.readText()
                    ?.let(::parse)
                    .orEmpty()
        }

        /** The committed records, and the large corpus's on a run with its checkout. */
        fun committed(): List<CorpusRecord> = cached

        /** Records one per line. */
        fun parse(text: String): List<CorpusRecord> =
            text
                .lineSequence()
                .filter { it.isNotBlank() }
                .map { fromJson(Json.parse(it) as Json.Obj) }
                .toList()

        /** D3 divergence classes that depend on a platform oracle's version (holding per oracle entry, like D1_DOM). */
        val ORACLE_DIVERGENCES = setOf("CONSCRYPT_TBS")

        /**
         * The D3_DIVERGENCE records of [records] (the committed ones by default): divergence class → input paths. A class in
         * [ORACLE_DIVERGENCES] counts only where it holds on [on] (its id and version); with [on] null, it is left out.
         */
        fun divergences(
            records: List<CorpusRecord> = committed(),
            on: PlatformOracle? = null,
        ): Map<String, Set<String>> =
            records
                .filter { it.recordClass == RecordClass.D3_DIVERGENCE }
                .filter { r ->
                    r.divergence !in ORACLE_DIVERGENCES ||
                        r.oracles.any { on != null && it.id == on.id && it.version == on.version && it.holds == true }
                }.groupBy({ it.divergence!! }, { it.path })
                .mapValues { it.value.toSet() }

        /** Writes [records] sorted by path, class and divergence, one per line. */
        fun write(
            file: File,
            records: List<CorpusRecord>,
        ) {
            file.writeText(
                records
                    .sortedWith(compareBy({ it.path }, { it.recordClass }, { it.divergence }))
                    .joinToString("") { it.toJson().write() + "\n" },
            )
        }
    }
}
