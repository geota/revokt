// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.oracle

import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.DerNode
import dev.revokt.engine.parse.ParsedCertificate
import dev.revokt.engine.parse.Span
import dev.revokt.engine.parse.producer.ProducerCorpus
import okio.ByteString.Companion.toByteString
import java.security.cert.X509Certificate
import kotlin.test.fail

/**
 * One platform oracle's side of the replay corpus (spec §9.2), computed once for the replay tests and the corpus
 * records: each input [oracle] accepts, with the bytes revokt reads, their reference view and parse, and why it is
 * outside the D1 domain.
 */
internal class PlatformReplay(
    val oracle: PlatformOracle,
) {
    /**
     * One platform-accepted input: [read] is the bytes revokt reads (`getEncoded()`, or oracle 1's platform canon, spec
     * §9.2 revision 39), null when no platform canon can be built; with its reference view and parse.
     */
    class Accepted(
        val name: String,
        val presented: ByteArray,
        val x509: X509Certificate,
        val read: ProducerCorpus.Input?,
        val reference: ReferenceView?,
        val parse: CertificateParse,
    ) {
        val certificate: ParsedCertificate? get() = (parse as? CertificateParse.Parsed)?.certificate

        val platformCanon: Boolean get() = read?.name?.endsWith(Oracle1.PLATFORM_CANON) == true

        /** The bytes read, which revokt parsed. */
        val readInput: ProducerCorpus.Input get() = checkNotNull(read) { "$name: no bytes read" }
    }

    /** The platform-accepted inputs of the replay corpus, in corpus order. */
    val accepted: List<Accepted> by lazy {
        ProducerCorpus.inputs.mapNotNull { input ->
            when (val o = oracle.run(input.der)) {
                is PlatformOracle.Outcome.Accept -> {
                    accepted(input, o.certificate)
                }

                is PlatformOracle.Outcome.Reject -> {
                    null
                }

                // Stricter than §9.2, where a crash never fails the gate: the committed corpus must not crash an oracle.
                is PlatformOracle.Outcome.Crash -> {
                    fail(
                        "${input.name}: ${oracle.label} crashed on the committed corpus: ${o.error}",
                    )
                }
            }
        }
    }

    val acceptedByName: Map<String, Accepted> by lazy { accepted.associateBy { it.name } }

    private fun accepted(
        input: ProducerCorpus.Input,
        x509: X509Certificate,
    ): Accepted {
        val name = input.name
        val read = oracle.read(name, x509)
        val reference =
            try {
                read?.let { ReferenceView.of(sha(it.der)) }
            } catch (e: IllegalStateException) {
                fail("$name: ${e.message}; run native/revokt-oracle/record-goldens.sh with ${oracle.label}")
            }
        return Accepted(name, input.der, x509, read, reference, CertificateParser.parse(read?.der ?: x509.encoded))
    }

    /** Why a platform-accepted input is outside the D1 domain, or null when it is inside. */
    fun outsideDomain(a: Accepted): String? {
        val read = a.read ?: return NO_PLATFORM_CANON
        // canon exists for every read: a platform canon is its own, and every other read is located by 3a or 3b.
        val parts = read.canonParts ?: fail("${a.name}: canon cannot be located for the bytes read")
        return if (versionTrailing(Oracle3a.bytes(parts.tbs))) {
            VERSION_TRAILING
        } else {
            producerOutside(a, producerGolden(a))
        }
    }

    /** The parsed inputs whose `Cert.tbs` differs from [oracle]'s `getTBSCertificate()`. */
    val tbsDiffering: Set<String> by lazy {
        accepted
            .filter { a ->
                a.certificate?.let { !a.x509.tbsCertificate.contentEquals(it.tbsBytes) } == true
            }.map { it.name }
            .toSet()
    }

    /** The parsed inputs whose SPKI [oracle] reports re-encoded, under the allow-list's first rule (spec §9.2). */
    val spkiReencoded: Set<String> by lazy {
        accepted
            .mapNotNull { a ->
                a.certificate?.let { c -> a.name.takeIf { reencoded(c.rawSpki(), a.x509.publicKey.encoded) } }
            }.toSet()
    }

    /** The parsed inputs whose SPKI [oracle] reports with NULL parameters added, the allow-list's second rule. */
    val spkiNullParameters: Set<String> by lazy {
        accepted
            .mapNotNull { a ->
                a.certificate?.let { c -> a.name.takeIf { addsNullParameters(c.rawSpki(), a.x509.publicKey.encoded) } }
            }.toSet()
    }

    /**
     * The parsed inputs whose validity times [oracle] reads with a `UTCTime` differential dropped (spec §9.2 D2,
     * revision 41): the time carries one, revokt's value equals the test JDK's, and the platform's differs by exactly
     * that differential. Input name → the fields (`notBefore`, `notAfter`) so read; empty for an oracle with no
     * [PlatformOracle.timeDivergence].
     */
    val timeOffsetDropped: Map<String, Set<String>> by lazy {
        if (oracle.timeDivergence == null) emptyMap() else accepted.mapNotNull(::droppedTimes).toMap()
    }

    /** [a]'s name and the validity fields [oracle] reads with a `UTCTime` differential dropped, or null for none. */
    private fun droppedTimes(a: Accepted): Pair<String, Set<String>>? {
        val c = a.certificate
        val oracle1 = jdk.acceptedByName[a.name]?.x509
        if (c == null || oracle1 == null) return null
        val v = c.tbs.validity
        val fields = HashSet<String>()
        if (dropped(c.tbsBytes, v.notBefore, v.notBeforeMillis, a.x509.notBefore.time, oracle1.notBefore.time)) {
            fields += "notBefore"
        }
        if (dropped(c.tbsBytes, v.notAfter, v.notAfterMillis, a.x509.notAfter.time, oracle1.notAfter.time)) {
            fields += "notAfter"
        }
        return if (fields.isEmpty()) null else a.name to fields
    }

    private fun dropped(
        tbs: ByteArray,
        span: Span,
        revokt: Long?,
        platform: Long,
        oracle1: Long,
    ): Boolean = revokt != null && platform != revokt && droppedDifferential(span.bytes(tbs), revokt, platform, oracle1)

    companion object {
        const val PRODUCER_REJECTS = "oracle 4 rejects"

        const val PRODUCER_KEYS_OTHER_BYTES = "oracle 4 keys other bytes"

        const val VERSION_TRAILING = "rule: content after the INTEGER inside [0]"

        /** D1-dom by rule (spec §9.2 revision 39): the producer cannot key a TBS whose AlgorithmIdentifier is not located. */
        const val NO_PLATFORM_CANON = "rule: no platform canon"

        val jdk = PlatformReplay(Oracle1)

        /** Lazy, so a run that needs only oracle 1 never loads Conscrypt's native library. */
        val conscrypt by lazy { PlatformReplay(Oracle2) }

        /** Every platform oracle on this run, oracle 1 first. */
        val all by lazy { listOf(jdk, conscrypt) }

        /**
         * The platform oracles in the order a record's rule-based fields are taken from when several hold: oracle 2 first,
         * since its view does not depend on the test JDK, so every JDK's run derives the same fields.
         */
        val preferred by lazy { listOf(conscrypt, jdk) }

        val producer: Map<String, String> by lazy { ProducerCorpus.goldens() }

        /** Oracle 4's golden for canon of the bytes read. */
        fun producerGolden(a: Accepted): String =
            producer[a.readInput.canonSha256] ?: fail("${a.name}: no oracle-4 golden for canon")

        private fun producerOutside(
            a: Accepted,
            golden: String,
        ): String? {
            if (!golden.startsWith("OK ")) return PRODUCER_REJECTS
            val (_, serial, spki) = golden.split(' ')
            val r = a.reference ?: return null
            return if (serial == r.serial && spki == sha(Oracle3a.bytes(r.spki))) null else PRODUCER_KEYS_OTHER_BYTES
        }

        /**
         * Whether a platform time [platform] is revokt's [revokt] with the differential of the `UTCTime` TLV [time]
         * dropped, revokt agreeing with oracle 1's [oracle1] (spec §9.2 D2, `CONSCRYPT_TIME_OFFSET`).
         */
        fun droppedDifferential(
            time: ByteArray,
            revokt: Long,
            platform: Long,
            oracle1: Long,
        ): Boolean {
            if (time.size < 2 || time[0] != 0x17.toByte() || revokt != oracle1) return false
            val text =
                String(time.copyOfRange(Oracle1.header(time, 0)?.size ?: return false, time.size), Charsets.US_ASCII)
            val m = Regex("^\\d{10}(\\d{2})?([+-])(\\d{2})(\\d{2})$").matchEntire(text) ?: return false
            val g = m.groupValues
            val minutes = (g[3].toInt() * 60 + g[4].toInt()) * if (g[2] == "+") 1 else -1
            // Local time read as UTC: the platform is ahead of the true time by the differential.
            return platform - revokt == minutes * 60_000L
        }

        /**
         * The allow-list's second rule (revision 41), on the bytes alone: [platform] is [rawSpki] with every header minimal
         * and NULL parameters added to an AlgorithmIdentifier that has none, nothing else differing (a generic key of an
         * algorithm the platform does not know).
         */
        fun addsNullParameters(
            rawSpki: ByteArray,
            platform: ByteArray,
        ): Boolean =
            try {
                // rawSpki with every header minimal and NULL added to an AlgorithmIdentifier that holds only its OID.
                val expected = DerNode.parse(rawSpki)
                val alg = expected.child(0).children!!
                alg.size == 1 &&
                    run {
                        alg += DerNode(0x05, ByteArray(0), null)
                        expected.encode().contentEquals(platform)
                    }
            } catch (_: RuntimeException) {
                false
            }

        /** The re-encoding allow-list's rule: the platform's `getPublicKey().getEncoded()` is [rawSpki] with every header minimal. */
        fun reencodesSpki(
            rawSpki: ByteArray,
            platform: ByteArray,
        ): Boolean = DerNode.parse(rawSpki).encode().contentEquals(platform)

        private fun reencoded(
            rawSpki: ByteArray,
            platform: ByteArray,
        ): Boolean = !platform.contentEquals(rawSpki) && reencodesSpki(rawSpki, platform)

        /** Whether the TBS's `[0]` holds more than its first element (any definite header form). */
        private fun versionTrailing(tbs: ByteArray): Boolean {
            val p = Oracle1.header(tbs, 0)?.size ?: return false
            if (p >= tbs.size || tbs[p] != 0xa0.toByte()) return false
            val wrapper = Oracle1.header(tbs, p) ?: return false
            val inner = Oracle1.header(tbs, p + wrapper.size) ?: return false
            return inner.end(p + wrapper.size) < wrapper.end(p)
        }

        fun sha(b: ByteArray): String = b.toByteString().sha256().hex()
    }
}
