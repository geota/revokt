// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.producer

import dev.revokt.engine.parse.records.Json
import okio.ByteString.Companion.toByteString
import java.io.File
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The CT seed corpus of spec §9.2 (revision 45) against the fixture generation's index: the log sample without CT test
 * traffic (`ct-seed/logs/`) and the crt.sh top-up of every index issuer (`ct-seed/crtsh/`, `crtsh.json`). A leaf counts
 * for an index key only when the test JDK reads it and its signature verifies under an issuer-corpus certificate's key
 * whose SPKI hashes to that index key: for a top-up leaf, the key `crtsh.json` kept it for; for a log-sample leaf, a key
 * of a certificate whose subject is the leaf's issuer.
 */
class CtSeedTest {
    private val dir = ExternalCorpus.dir

    /** `crtsh.json`'s kept crt.sh ids, each to the index key it was kept for. */
    private fun kept(dir: File): Map<String, String> {
        val keys = (Json.parse(File(dir, "ct-seed/crtsh.json").readText()) as Json.Obj).child("keys")
        assertEquals(FixtureIndex.keys, keys.fields.keys, "crtsh.json does not name exactly the index keys")
        val out = HashMap<String, String>()
        for ((key, rec) in keys.fields) {
            for (id in (rec as Json.Obj).array("kept")) {
                val text = (id as? Json.Num ?: error("$key: a kept id is not a number")).text
                check(out.put(text, key) == null) { "crt.sh id $text kept twice" }
            }
        }
        return out
    }

    @Test
    fun `the seed's index keys are the fixture generation's`() {
        val dir = dir ?: return println("CT seed: no CT seed corpus on this run (-Prevokt.corpus)")
        val listed =
            File(dir, "ct-seed/index-keys.txt")
                .readLines()
                .filter { it.isNotBlank() }
                .map {
                    Base64
                        .getUrlDecoder()
                        .decode(it.trim())
                        .toByteString()
                        .hex()
                }
        assertEquals(listed.size, listed.toSet().size, "index-keys.txt lists a key twice")
        assertEquals(FixtureIndex.keys, listed.toSet())
    }

    @Test
    fun `top-up leaves are crtsh json's, signed by their index issuer, and the seed has 100 000 such leaves`() {
        val dir = dir ?: return println("CT seed: no CT seed corpus on this run (-Prevokt.corpus)")
        val kept = kept(dir)
        val byKey = IndexIssuers.certificates.groupBy({ it.first }, { it.third })
        val covered = HashMap<String, Int>()
        val unverified = ArrayList<String>()
        var unread = 0
        val lines = ExternalCorpus.ctSeedLines(dir, "crtsh")
        assertEquals(kept.keys, lines.map { it[2] }.toSet(), "crtsh shards and crtsh.json's kept ids differ")
        for (f in lines) {
            assertEquals("crt.sh", f[1], "ct-seed leaf ${f[0]}: a top-up leaf's source")
            val key = kept.getValue(f[2])
            val leaf = IndexIssuers.jdk(Base64.getDecoder().decode(f[4]))
            if (leaf == null) {
                unread++
                continue
            }
            if (byKey[key].orEmpty().any { IndexIssuers.signedBy(leaf, it) }) {
                covered.merge(key, 1, Int::plus)
            } else {
                unverified += "${f[0]} (crt.sh ${f[2]})"
            }
        }
        assertEquals(emptyList(), unverified, "top-up leaves whose kept index key did not sign them")
        val topUp = covered.values.sum()
        val topUpKeys = covered.size
        val logKeys = HashSet<String>()
        var logs = 0
        for (f in ExternalCorpus.ctSeedLines(dir, "logs")) {
            val leaf = IndexIssuers.jdk(Base64.getDecoder().decode(f[4])) ?: continue
            val key = IndexIssuers.keyOf(leaf)
            if (key != null) {
                covered.merge(key, 1, Int::plus)
                logKeys += key
                logs++
            }
        }
        println(
            "CT seed: ${logs + topUp} leaves of ${covered.size} of ${FixtureIndex.keys.size} index keys " +
                "($logs of ${logKeys.size} keys from the log sample, $topUp of $topUpKeys keys from crt.sh; " +
                "$unread top-up leaves the test JDK does not read)",
        )
        assertTrue(logs + topUp >= 100_000, "the seed has only ${logs + topUp} leaves of index issuers (spec §9.2)")
    }
}
