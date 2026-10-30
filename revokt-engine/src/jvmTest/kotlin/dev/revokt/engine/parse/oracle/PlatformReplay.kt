// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.oracle

import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.DerNode
import dev.revokt.engine.parse.ParsedCertificate
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
        val view: PlatformView,
        val read: ProducerCorpus.Input?,
        val parse: CertificateParse,
    ) {
        /** The reference view of the bytes read, built on each access from the goldens (#64: not retained). */
        val reference: ReferenceView? get() = read?.let { ReferenceView.of(sha(it.der)) }

        val certificate: ParsedCertificate? get() = (parse as? CertificateParse.Parsed)?.certificate

        val platformCanon: Boolean get() = read?.name?.endsWith(Oracle1.PLATFORM_CANON) == true

        /** The bytes read, which revokt parsed. */
        val readInput: ProducerCorpus.Input get() = checkNotNull(read) { "$name: no bytes read" }
    }

    /**
     * What the replay reads from a platform's `X509Certificate`, taken once at acceptance so that the certificate itself
     * is not retained (#64): the normalised Java fields against revokt's parse (empty where revokt does not parse), and
     * the bytes behind the D2 checks only where they differ from revokt's.
     */
    class PlatformView(
        val javaFields: List<JavaFields.Field>,
        /** `getTBSCertificate()` where it differs from `Cert.tbs`, else null; null too where revokt does not parse. */
        val tbs: ByteArray?,
        /** `getPublicKey().getEncoded()` where it differs from `rawSpki` (or the getter threw: null), else null. */
        val publicKey: ByteArray?,
        /** `getNotBefore()` in epoch milliseconds, null where the getter threw. */
        val notBefore: Long?,
        /** `getNotAfter()` in epoch milliseconds, null where the getter threw. */
        val notAfter: Long?,
        /** The notBefore and notAfter TLVs of `getTBSCertificate()`, where a platform time differs from revokt's. */
        val times: Pair<ByteArray, ByteArray>?,
    ) {
        companion object {
            @Suppress("TooGenericExceptionCaught") // §9.2: a getter that throws marks its field unavailable
            fun of(
                x509: X509Certificate,
                c: ParsedCertificate?,
                ocspNoCheckEmpty: Boolean,
            ): PlatformView {
                // Where revokt does not parse, nothing is compared: the TBS and key getters are not called.
                val tbs = c?.let { x509.tbsCertificate }
                val key =
                    try {
                        c?.let { x509.publicKey.encoded }
                    } catch (_: RuntimeException) {
                        null
                    }
                val notBefore =
                    try {
                        x509.notBefore.time
                    } catch (_: RuntimeException) {
                        null
                    }
                val notAfter =
                    try {
                        x509.notAfter.time
                    } catch (_: RuntimeException) {
                        null
                    }
                val v = c?.tbs?.validity
                val timesDiffer = v != null && (v.notBeforeMillis != notBefore || v.notAfterMillis != notAfter)
                return PlatformView(
                    // Only the fields that differ or are unavailable: an agreeing field carries nothing.
                    javaFields =
                        c?.let { JavaFields.compare(x509, it, ocspNoCheckEmpty) }.orEmpty().filter {
                            it.mismatch !=
                                null
                        },
                    tbs = tbs?.takeIf { !it.contentEquals(c.tbsBytes) },
                    publicKey = key.takeIf { c != null && !(it?.contentEquals(c.rawSpki()) ?: false) },
                    notBefore = notBefore,
                    notAfter = notAfter,
                    times = if (timesDiffer && tbs != null) validityTimes(tbs) else null,
                )
            }
        }
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
        // A read of the bytes presented is the input itself, so that its canon and parts are held once, not once per
        // platform (#15: the v5 corpus did not fit the test heap otherwise). Its goldens are keyed by SHA-256, so only
        // the read's name, which failure messages show, changes.
        val read =
            oracle.read(name, x509)?.let {
                if (!it.name.endsWith(Oracle1.PLATFORM_CANON) && it.der.contentEquals(input.der)) input else it
            }
        // A missing golden fails here, at acceptance, with its fix; the view itself is rebuilt on access.
        try {
            read?.let { ReferenceView.of(sha(it.der)) }
        } catch (e: IllegalStateException) {
            fail("$name: ${e.message}; run native/revokt-oracle/record-goldens.sh with ${oracle.label}")
        }
        val bytes = read?.der ?: x509.encoded
        // Both platform oracles usually read the same bytes: one parse serves both (#64).
        val parse = parses.getOrPut(sha(bytes)) { CertificateParser.parse(bytes) }
        val view = PlatformView.of(x509, (parse as? CertificateParse.Parsed)?.certificate, oracle.ocspNoCheckEmpty)
        return Accepted(name, input.der, view, read, parse)
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
                a.certificate != null && a.view.tbs != null
            }.map { it.name }
            .toSet()
    }

    /** The parsed inputs whose SPKI [oracle] reports re-encoded, under the allow-list's first rule (spec §9.2). */
    val spkiReencoded: Set<String> by lazy {
        accepted
            .mapNotNull { a ->
                a.certificate?.let { c ->
                    a.name.takeIf { a.view.publicKey?.let { reencoded(c.rawSpki(), it) } == true }
                }
            }.toSet()
    }

    /** The parsed inputs whose SPKI [oracle] reports with NULL parameters added, the allow-list's second rule. */
    val spkiNullParameters: Set<String> by lazy {
        accepted
            .mapNotNull { a ->
                a.certificate?.let { c ->
                    a.name.takeIf { a.view.publicKey?.let { addsNullParameters(c.rawSpki(), it) } == true }
                }
            }.toSet()
    }

    /**
     * The parsed inputs whose validity times [oracle] reads with a `UTCTime` differential dropped (spec §9.2 D2,
     * revision 41): the time carries one, revokt's value equals the test JDK's, and the platform's differs by exactly
     * that differential. Input name → the fields (`notBefore`, `notAfter`) so read; empty for an oracle with no
     * [PlatformOracle.timeDivergence].
     */
    val timeOffsetDropped: Map<String, Set<String>> by lazy {
        if (oracle.timeDivergence ==
            null
        ) {
            emptyMap()
        } else {
            accepted.mapNotNull { timesWhere(it, ::droppedDifferential) }.toMap()
        }
    }

    /**
     * The parsed inputs whose validity times [oracle] reads in the Julian calendar before 1582-10-15 (spec §9.2 D2,
     * revision 44): its value is the time's fields read in `java.util.GregorianCalendar`'s hybrid calendar, revokt's is
     * the proleptic Gregorian reading and equals the test JDK's. Input name → the fields so read.
     */
    val julianTimes: Map<String, Set<String>> by lazy {
        if (oracle.julianDivergence ==
            null
        ) {
            emptyMap()
        } else {
            accepted.mapNotNull { timesWhere(it, ::julianReading) }.toMap()
        }
    }

    /** [a]'s name and the validity fields where [rule] (time TLV, revokt, platform, oracle 1) holds, or null for none. */
    private fun timesWhere(
        a: Accepted,
        rule: (ByteArray, Long, Long, Long) -> Boolean,
    ): Pair<String, Set<String>>? {
        val c = a.certificate
        val oracle1 = jdk.acceptedByName[a.name]?.view
        val times = a.view.times
        if (c == null || oracle1 == null || times == null) return null
        val v = c.tbs.validity
        val fields = HashSet<String>()
        if (differsBy(rule, times.first, v.notBeforeMillis, a.view.notBefore, oracle1.notBefore)) fields += "notBefore"
        if (differsBy(rule, times.second, v.notAfterMillis, a.view.notAfter, oracle1.notAfter)) fields += "notAfter"
        return if (fields.isEmpty()) null else a.name to fields
    }

    /** Whether the platform's [platform] differs from revokt's [revokt] and [rule] holds; never where a value is missing. */
    private fun differsBy(
        rule: (ByteArray, Long, Long, Long) -> Boolean,
        time: ByteArray,
        revokt: Long?,
        platform: Long?,
        oracle1: Long?,
    ): Boolean {
        if (revokt == null || platform == null || oracle1 == null) return false
        return revokt != platform && rule(time, revokt, platform, oracle1)
    }

    companion object {
        const val PRODUCER_REJECTS = "oracle 4 rejects"

        const val PRODUCER_KEYS_OTHER_BYTES = "oracle 4 keys other bytes"

        const val VERSION_TRAILING = "rule: content after the INTEGER inside [0]"

        /** D1-dom by rule (spec §9.2 revision 39): the producer cannot key a TBS whose AlgorithmIdentifier is not located. */
        const val NO_PLATFORM_CANON = "rule: no platform canon"

        /** revokt's parse of each byte string a platform oracle reads, by its SHA-256, shared across the oracles. */
        private val parses = HashMap<String, CertificateParse>()

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

        /** The notBefore and notAfter TLVs of a TBS (after `[0]` if present, serial, signature, issuer), or null. */
        fun validityTimes(tbs: ByteArray): Pair<ByteArray, ByteArray>? =
            try {
                val fields = DerNode.parse(tbs).children!!
                val validity = fields[if (fields[0].tag == 0xa0) 4 else 3]
                validity.child(0).encode() to validity.child(1).encode()
            } catch (_: RuntimeException) {
                null
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

        /**
         * Whether a platform time [platform] is the time TLV [time]'s fields read in `java.util.GregorianCalendar`'s
         * Julian–Gregorian hybrid, the time being before 1582-10-15, while revokt's [revokt] is their proleptic Gregorian
         * reading and equals oracle 1's [oracle1] (spec §9.2 D2, `CONSCRYPT_TIME_JULIAN`). Only a GeneralizedTime `Z` time
         * without fractional seconds: a `UTCTime` is never before the reform.
         */
        fun julianReading(
            time: ByteArray,
            revokt: Long,
            platform: Long,
            oracle1: Long,
        ): Boolean {
            if (time.size < 2 || time[0] != 0x18.toByte() || revokt != oracle1) return false
            val text =
                String(time.copyOfRange(Oracle1.header(time, 0)?.size ?: return false, time.size), Charsets.US_ASCII)
            val g =
                Regex("^(\\d{4})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})?Z$").matchEntire(text)?.groupValues
                    ?: return false
            val f = listOf(g[1], g[2], g[3], g[4], g[5], g[6].ifEmpty { "0" }).map { it.toInt() }
            val proleptic = prolepticMillis(f) ?: return false
            if (revokt != proleptic || proleptic >=
                java.util
                    .GregorianCalendar()
                    .gregorianChange.time
            ) {
                return false
            }
            val hybrid =
                java.util
                    .GregorianCalendar(java.util.TimeZone.getTimeZone("UTC"))
                    .apply {
                        clear()
                        isLenient = true
                        set(f[0], f[1] - 1, f[2], f[3], f[4], f[5])
                    }.timeInMillis
            return hybrid != proleptic && platform == hybrid
        }

        /** The time fields [f] (year, month, day, hour, minute, second) in the proleptic Gregorian calendar, or null if invalid. */
        private fun prolepticMillis(f: List<Int>): Long? =
            try {
                java.time.LocalDateTime
                    .of(f[0], f[1], f[2], f[3], f[4], f[5])
                    .toEpochSecond(java.time.ZoneOffset.UTC) * 1000
            } catch (_: java.time.DateTimeException) {
                null
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
