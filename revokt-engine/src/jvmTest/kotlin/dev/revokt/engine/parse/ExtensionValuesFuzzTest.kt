// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import com.code_intelligence.jazzer.junit.FuzzTest
import dev.revokt.RevoktLimits

/**
 * Spec §9.1 target "the TBS/DER parser", over the x5u extension readers (#106): the first octet picks basicConstraints,
 * keyUsage, extKeyUsage or subjectAltName and the rest is the `extnValue` content. The readers return only `Value` or
 * `Failed`; a read value keeps its grammar's invariants; the certificate-level read of the value as the one extension
 * of a certificate equals the direct read (its failure details aside, which name offsets); a strict read value is the
 * lenient read's; and K8's verdict equals the 0.1 grammar's (kept below as the reference), so
 * the readers left K8 unchanged. With `JAZZER_FUZZ` unset JUnit replays `ExtensionValuesFuzzTestInputs/`; the nightly
 * job runs it with `-max_len=65537`.
 */
class ExtensionValuesFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun read(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        private val OIDS =
            listOf(
                ExtensionValues.BASIC_CONSTRAINTS,
                ExtensionValues.KEY_USAGE,
                ExtensionValues.EXT_KEY_USAGE,
                ExtensionValues.SUBJECT_ALT_NAME,
            )

        /** The static entry point ClusterFuzzLite drives (CONTRIBUTING §6). */
        @JvmStatic
        fun fuzzerTestOneInput(data: ByteArray) {
            if (data.isEmpty()) return
            val oid = OIDS[(data[0].toInt() and 0xff) % OIDS.size]
            val value = data.copyOfRange(1, data.size)
            val span = Span(0, value.size)
            val direct = read(oid, value, span)
            check(same(direct, read(oid, value, span))) { "a second read differs" }
            if (direct is ExtensionRead.Value) invariants(direct.value, value)
            val der = TestCert(extensions = listOf(TestDer.extension(oid, value))).der
            val c =
                (CertificateParser.parse(der) as? CertificateParse.Parsed)?.certificate
                    ?: return check(
                        der.size > RevoktLimits.MAX_CERT_BYTES,
                    ) { "the wrapping certificate does not parse" }
            // The details name offsets, which differ between the value alone and the value inside a certificate.
            check(same(direct, lookup(oid, c), details = false)) { "the certificate-level read differs" }
            val lenient = read(oid, value, span, strict = false)
            check(
                direct !is ExtensionRead.Value || same(direct, lenient),
            ) { "strict read a value the lenient read did not" }
            val e = c.tbs.extensions.single()
            check(ExtensionGrammars.valid(c.tbsBytes, e) == K8Reference.valid(c.tbsBytes, e)) { "K8 changed" }
        }

        private fun read(
            oid: String,
            b: ByteArray,
            v: Span,
            strict: Boolean = true,
        ): ExtensionRead<Any> =
            when (oid) {
                ExtensionValues.BASIC_CONSTRAINTS -> ExtensionValues.basicConstraints(b, v, strict)
                ExtensionValues.KEY_USAGE -> ExtensionValues.keyUsage(b, v, strict)
                ExtensionValues.EXT_KEY_USAGE -> ExtensionValues.extendedKeyUsage(b, v, strict)
                else -> ExtensionValues.subjectAltName(b, v, strict)
            }

        private fun lookup(
            oid: String,
            c: ParsedCertificate,
        ): ExtensionRead<Any> =
            when (oid) {
                ExtensionValues.BASIC_CONSTRAINTS -> ExtensionValues.basicConstraints(c)
                ExtensionValues.KEY_USAGE -> ExtensionValues.keyUsage(c)
                ExtensionValues.EXT_KEY_USAGE -> ExtensionValues.extendedKeyUsage(c)
                else -> ExtensionValues.subjectAltName(c)
            }

        private fun invariants(
            v: Any,
            value: ByteArray,
        ) {
            when (v) {
                is BasicConstraints -> {
                    check(v.pathLen == null || v.pathLen >= 0) { "negative pathLen" }
                }

                is KeyUsage -> {
                    check(v.bits.size <= (value.size - 3) * 8) { "${v.bits.size} bits" }
                }

                is ExtendedKeyUsage -> {
                    check(v.purposes.isNotEmpty()) { "no purpose" }
                }

                is SubjectAltNames -> {
                    check(v.names.isNotEmpty()) { "no name" }
                    check(v.dnsNames.all { name -> name.all { it.code < 0x80 } }) { "a non-ASCII dNSName" }
                }

                else -> {
                    error("unexpected value $v")
                }
            }
        }

        private fun same(
            a: ExtensionRead<Any>,
            b: ExtensionRead<Any>,
            details: Boolean = true,
        ): Boolean =
            when (a) {
                is ExtensionRead.Failed -> {
                    b is ExtensionRead.Failed && a.reason == b.reason &&
                        (!details || a.detail == b.detail)
                }

                is ExtensionRead.Value -> {
                    b is ExtensionRead.Value && fields(a.value) == fields(b.value)
                }

                ExtensionRead.Absent -> {
                    b == ExtensionRead.Absent
                }
            }

        private fun fields(v: Any): Any? =
            when (v) {
                is BasicConstraints -> v.ca to v.pathLen
                is KeyUsage -> v.bits
                is ExtendedKeyUsage -> v.purposes
                is SubjectAltNames -> v.names.map { it.tag to it.content }
                else -> v
            }
    }
}

/**
 * K8's four grammars as 0.1 shipped them (before #106 built them on [ExtensionValues]), the reference the fuzz target
 * compares [ExtensionGrammars.valid] with. The other listed extensions did not change and are delegated.
 */
private object K8Reference {
    private val SITE = HeaderSite.EXTENSION_VALUE

    fun valid(
        b: ByteArray,
        e: Extension,
    ): Boolean {
        val grammar: (ByteArray, Span) -> Boolean =
            when {
                Oid.matches(b, e.oid, Oid.KEY_USAGE_CONTENT) -> {
                    x,
                    v,
                    ->
                    only(x, v, 0x03) { Keyability.bitStringPadding(x, it.content) }
                }

                Oid.matches(
                    b,
                    e.oid,
                    Oid.BASIC_CONSTRAINTS_CONTENT,
                ) -> { x, v -> sequence(x, v) { basicConstraints(x, it) } }

                Oid.matches(b, e.oid, Oid.SUBJECT_ALT_NAME_CONTENT) -> { x, v ->
                    sequence(x, v) { r ->
                        r.hasMore() &&
                            all(r) { sanName(x, it) }
                    }
                }

                Oid.matches(b, e.oid, Oid.EXT_KEY_USAGE_CONTENT) -> { x, v ->
                    sequence(x, v) { r ->
                        r.hasMore() &&
                            all(r) { it.tag == 0x06 }
                    }
                }

                else -> return ExtensionGrammars.valid(b, e)
            }
        return try {
            grammar(b, e.value) && booleans(b, e.value)
        } catch (_: DerException) {
            false
        }
    }

    private fun reader(
        b: ByteArray,
        span: Span,
    ) = DerReader(b, span.start, span.end, ParseContext())

    private inline fun only(
        b: ByteArray,
        value: Span,
        tag: Int,
        check: (Tlv) -> Boolean,
    ): Boolean {
        val r = reader(b, value)
        val t = r.read(tag, SITE)
        r.requireEnd("extension value")
        return check(t)
    }

    private inline fun sequence(
        b: ByteArray,
        value: Span,
        check: (DerReader) -> Boolean,
    ): Boolean = only(b, value, 0x30) { check(reader(b, it.content)) }

    private inline fun all(
        r: DerReader,
        check: (Tlv) -> Boolean,
    ): Boolean {
        while (r.hasMore()) if (!check(r.readAny(SITE))) return false
        return true
    }

    private fun booleans(
        b: ByteArray,
        value: Span,
    ): Boolean {
        val stack = arrayListOf(reader(b, value))
        while (stack.isNotEmpty()) {
            val r = stack.last()
            if (!r.hasMore()) {
                stack.removeAt(stack.lastIndex)
                continue
            }
            val t = r.readAny(SITE)
            if (t.tag == 0x01 && !boolean(b, t.content)) return false
            if (t.tag and 0x20 != 0) stack.add(reader(b, t.content))
        }
        return true
    }

    private fun basicConstraints(
        b: ByteArray,
        r: DerReader,
    ): Boolean {
        val ca = r.readOptional(0x01, SITE)
        val pathLen = r.readOptional(0x02, SITE)
        r.requireEnd("basicConstraints")
        val caOk = ca == null || boolean(b, ca.content)
        val pathLenOk =
            pathLen == null ||
                (
                    Keyability.minimalInteger(b, pathLen.content) && b[pathLen.content.start] >= 0 &&
                        pathLen.content.length <= 4
                )
        return caOk && pathLenOk
    }

    private fun boolean(
        b: ByteArray,
        content: Span,
    ): Boolean = content.length == 1 && b[content.start].toInt() and 0xff in setOf(0x00, 0xff)

    private fun sanName(
        b: ByteArray,
        t: Tlv,
    ): Boolean =
        when (t.tag) {
            0x82, 0x81 -> (t.content.start until t.content.end).all { b[it] >= 0 }
            0x87 -> t.content.length == 4 || t.content.length == 16
            else -> false
        }
}
