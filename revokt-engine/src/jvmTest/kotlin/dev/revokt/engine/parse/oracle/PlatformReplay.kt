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

    /** The parsed inputs whose SPKI [oracle] reports re-encoded, under the allow-list's rule (spec §9.2). */
    val spkiReencoded: Set<String> by lazy {
        accepted
            .mapNotNull { a ->
                a.certificate?.let { c -> a.name.takeIf { reencoded(c.rawSpki(), a.x509.publicKey.encoded) } }
            }.toSet()
    }

    companion object {
        const val PRODUCER_REJECTS = "oracle 4 rejects"

        const val PRODUCER_KEYS_OTHER_BYTES = "oracle 4 keys other bytes"

        const val VERSION_TRAILING = "rule: content after the INTEGER inside [0]"

        /** D1-dom by rule (spec §9.2 revision 39): the producer cannot key a TBS whose AlgorithmIdentifier is not located. */
        const val NO_PLATFORM_CANON = "rule: no platform canon"

        val jdk = PlatformReplay(Oracle1)

        val conscrypt = PlatformReplay(Oracle2)

        /** Every platform oracle on this run, oracle 1 first. */
        val all = listOf(jdk, conscrypt)

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
