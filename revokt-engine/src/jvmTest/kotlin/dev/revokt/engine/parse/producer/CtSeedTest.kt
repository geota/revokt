// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.producer

import dev.revokt.engine.parse.records.Json
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.File
import java.math.BigInteger
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The CT seed corpus of spec §9.2 (revision 45) against the fixture generation's index: the log sample without CT test
 * traffic (`ct-seed/logs/`) and the crt.sh top-up of every index issuer (`ct-seed/crtsh/`, `crtsh.json`). A leaf counts
 * for an index key only when the test JDK reads it and its signature verifies under an issuer-corpus certificate's key
 * whose SPKI hashes to that index key, a certificate whose subject is the leaf's issuer ([IndexIssuers], as the D8 gap
 * counts); a top-up leaf's key must be the one `crtsh.json` kept it for, and the leaf must meet §9.2's definition.
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

    /** The seed's leaves of index issuers as they are counted: per key, as issuances, and by TBSCertificate. */
    private class Tally(
        val start: Instant,
    ) {
        val covered = HashMap<String, Int>()
        val issuances = HashSet<Pair<String, BigInteger>>()

        /** The D8 gap's denominator (RecordsTest: unexpired at the start), as distinct issuances. */
        val current = HashSet<Pair<String, BigInteger>>()
        private val tbs = HashSet<ByteString>()

        fun add(
            sha256: String,
            key: String,
            leaf: X509Certificate,
        ) {
            assertTrue(tbs.add(leaf.tbsCertificate.toByteString().sha256()), "ct-seed leaf $sha256: its TBS twice")
            covered.merge(key, 1, Int::plus)
            issuances += key to leaf.serialNumber
            if (leaf.notAfter.toInstant() > start) current += key to leaf.serialNumber
        }
    }

    /**
     * Whether a top-up leaf meets §9.2's definition: its key by issuer name and signature is [key] (the D8 gap's
     * predicate), valid at [start], issued in the 400 days before it, unable to issue certificates, v3.
     */
    private fun meetsDefinition(
        leaf: X509Certificate,
        key: String,
        start: Instant,
    ): Boolean =
        IndexIssuers.keyOf(leaf) == key &&
            leaf.notBefore.toInstant() <= start &&
            leaf.notAfter.toInstant() > start &&
            leaf.notBefore.toInstant() > start.minus(Duration.ofDays(400)) &&
            leaf.basicConstraints == -1 &&
            leaf.version == 3

    @Test
    fun `top-up leaves are crtsh json's, signed by their index issuer, and the seed has 100 000 such leaves`() {
        val dir = dir ?: return println("CT seed: no CT seed corpus on this run (-Prevokt.corpus)")
        val json = Json.parse(File(dir, "ct-seed/crtsh.json").readText()) as Json.Obj
        val perIssuer = (json["per_issuer"] as Json.Num).text.toInt()
        val tally = Tally(Instant.parse(json.string("started")))
        val kept = kept(dir)
        // One predicate for both counts and the D8 gap (RecordsTest): every index key has a certificate the JDK reads.
        assertEquals(
            FixtureIndex.keys,
            IndexIssuers.certificates.map { it.first }.toSet(),
            "index keys without a JDK read",
        )
        val lines = ExternalCorpus.ctSeedLines(dir, "crtsh")
        assertEquals(kept.size, lines.size, "crtsh shards and crtsh.json's kept ids differ in number")
        assertEquals(kept.keys, lines.map { it[2] }.toSet(), "crtsh shards and crtsh.json's kept ids differ")
        val wrong = ArrayList<String>()
        for (f in lines) {
            assertEquals("crt.sh", f[1], "ct-seed leaf ${f[0]}: a top-up leaf's source")
            val key = kept.getValue(f[2])
            val leaf =
                IndexIssuers.jdk(Base64.getDecoder().decode(f[4])) ?: fail("ct-seed leaf ${f[0]}: the JDK rejects it")
            if (!meetsDefinition(leaf, key, tally.start)) wrong += "${f[0]} (crt.sh ${f[2]})"
            tally.add(f[0], key, leaf)
        }
        assertEquals(
            emptyList(),
            wrong,
            "top-up leaves outside §9.2's definition or not signed by their kept index key",
        )
        assertTrue(tally.covered.values.all { it <= perIssuer }, "an index key past the cap of $perIssuer")
        val topUp = tally.covered.values.sum()
        val topUpKeys = tally.covered.size
        val logKeys = HashSet<String>()
        var logs = 0
        for (f in ExternalCorpus.ctSeedLines(dir, "logs")) {
            val leaf = IndexIssuers.jdk(Base64.getDecoder().decode(f[4]))
            val key = leaf?.let(IndexIssuers::keyOf) ?: continue
            tally.add(f[0], key, leaf)
            logKeys += key
            logs++
        }
        println(
            "CT seed: ${logs + topUp} leaves of ${tally.covered.size} of ${FixtureIndex.keys.size} index keys " +
                "($logs of ${logKeys.size} keys from the log sample, $topUp of $topUpKeys keys from crt.sh), " +
                "${tally.issuances.size} distinct (index key, serial), " +
                "${tally.current.size} of them unexpired at the start",
        )
        assertTrue(logs + topUp >= 100_000, "the seed has only ${logs + topUp} leaves of index issuers (spec §9.2)")
    }
}
