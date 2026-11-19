// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.engine.parse.DerException
import dev.revokt.engine.parse.DerReader
import dev.revokt.engine.parse.ExtensionRead
import dev.revokt.engine.parse.ExtensionValues
import dev.revokt.engine.parse.HeaderSite
import dev.revokt.engine.parse.Oid
import dev.revokt.engine.parse.ParseContext
import dev.revokt.engine.parse.ParsedCertificate
import dev.revokt.engine.parse.Span

/**
 * One name a certificate presents to a name constraint (#237), as webpki's `GeneralName` reads it
 * (`subject_name/mod.rs` 287–315): a dNSName, an iPAddress or a URI with its content; a directoryName (the subject,
 * and any in subjectAltName) without it, since no directoryName constraint is evaluated; any other form by its tag
 * number alone.
 */
internal sealed interface PresentedName {
    class Dns(
        val id: ByteArray,
    ) : PresentedName

    class Ip(
        val address: ByteArray,
    ) : PresentedName

    data object Uri : PresentedName

    data object Directory : PresentedName

    data class Unsupported(
        val tagNumber: Int,
    ) : PresentedName

    companion object {
        /**
         * The names [p] presents: each subjectAltName entry, then its subject as a directoryName, as webpki's
         * `check_name_constraints` iterates them (`subject_name/mod.rs` 54–82). Null when the subjectAltName cannot
         * be read, which no name constraint admits.
         */
        fun of(p: ParsedCertificate): List<PresentedName>? {
            val san =
                when (val r = ExtensionValues.subjectAltName(p)) {
                    is ExtensionRead.Absent -> emptyList()
                    is ExtensionRead.Value -> r.value.names
                    is ExtensionRead.Failed -> return null
                }
            return san.map { general(it.tag, it.content.toByteArray()) ?: return null } + Directory
        }

        /** webpki's `GeneralName::from_der` over identifier octet [tag]; null for a form it does not read. */
        fun general(
            tag: Int,
            content: ByteArray,
        ): PresentedName? =
            when (tag) {
                DNS_NAME -> Dns(content)
                DIRECTORY_NAME -> Directory
                IP_ADDRESS -> Ip(content)
                URI -> Uri
                OTHER_NAME, RFC822_NAME, X400_ADDRESS, EDI_PARTY_NAME, REGISTERED_ID -> Unsupported(tag and TAG_NUMBER)
                else -> null
            }

        private const val OTHER_NAME = 0xa0
        private const val RFC822_NAME = 0x81
        const val DNS_NAME = 0x82
        private const val X400_ADDRESS = 0xa3
        const val DIRECTORY_NAME = 0xa4
        private const val EDI_PARTY_NAME = 0xa5
        private const val URI = 0x86
        private const val IP_ADDRESS = 0x87
        private const val REGISTERED_ID = 0x88
        private const val TAG_NUMBER = 0x1f
    }
}

/** A name-constraint comparison budget, webpki's `consume_name_constraint_comparison`. */
internal fun interface ComparisonBudget {
    /** False when the budget is spent; the comparison is then not made. */
    fun consume(): Boolean
}

/**
 * A `NameConstraints` extension as webpki applies it (`subject_name/mod.rs` 32–200, rustls-webpki 0.104.0-alpha.7):
 * for each presented name, every permitted and then every excluded subtree is compared, a subtree of another form
 * skipped. A permitted list binds a form only when it holds a subtree of that form (one must match); an excluded
 * subtree that matches is a violation. By form:
 *
 * - **dNSName:** [DnsNameConstraint], webpki's `presented_id_matches_reference_id` in the name-constraint role.
 * - **iPAddress:** address and mask, IPv4 against IPv4 only, IPv6 against IPv6 only (`ip_address.rs` 110–180).
 * - **directoryName and URI:** not evaluated, so they fail closed: a permitted one never matches and an excluded one
 *   always does. Every certificate presents its subject, so any directoryName subtree rejects (webpki leaves
 *   them unimplemented, rustls/webpki#19).
 * - **Any other form** present in both the name and a subtree: a violation.
 * - A comparison error (a malformed dNSName or constraint, a bad mask) is a violation, as webpki returns it.
 *
 * Every comparison consumes one unit of the [ComparisonBudget]; when it is spent the answer is [Result.EXHAUSTED].
 */
internal class NameConstraints private constructor(
    private val permitted: List<Base>?,
    private val excluded: List<Base>?,
) {
    /** One subtree's base: its form's identifier octet and content as encoded. */
    private class Base(
        val tag: Int,
        val content: ByteArray,
    )

    enum class Result { CONFORMS, VIOLATION, EXHAUSTED }

    /** Whether every one of [names] conforms; a null list (an unreadable subjectAltName) never does. */
    fun check(
        names: List<PresentedName>?,
        budget: ComparisonBudget,
    ): Result {
        if (names == null) return Result.VIOLATION
        for (name in names) {
            val r = conforms(name, budget)
            if (r != Result.CONFORMS) return r
        }
        return Result.CONFORMS
    }

    private fun conforms(
        name: PresentedName,
        budget: ComparisonBudget,
    ): Result {
        val permittedResult = permitted?.let { within(name, it, budget) } ?: Result.CONFORMS
        if (permittedResult != Result.CONFORMS) return permittedResult
        return excluded?.let { outside(name, it, budget) } ?: Result.CONFORMS
    }

    /** One permitted list: a subtree of [name]'s form must match when the list holds any. */
    private fun within(
        name: PresentedName,
        subtrees: List<Base>,
        budget: ComparisonBudget,
    ): Result {
        var matched = false
        var mismatched = false
        for (base in subtrees) {
            if (!budget.consume()) return Result.EXHAUSTED
            when (matches(name, base, Role.PERMITTED)) {
                null -> {}

                Match.ERROR -> {
                    return Result.VIOLATION
                }

                Match.YES -> {
                    matched = true
                }

                Match.NO -> {
                    mismatched = true
                }
            }
        }
        return if (mismatched && !matched) Result.VIOLATION else Result.CONFORMS
    }

    /** One excluded list: no subtree may match [name]. */
    private fun outside(
        name: PresentedName,
        subtrees: List<Base>,
        budget: ComparisonBudget,
    ): Result {
        for (base in subtrees) {
            if (!budget.consume()) return Result.EXHAUSTED
            val m = matches(name, base, Role.EXCLUDED)
            if (m == Match.ERROR || m == Match.YES) return Result.VIOLATION
        }
        return Result.CONFORMS
    }

    private enum class Role { PERMITTED, EXCLUDED }

    private enum class Match { YES, NO, ERROR }

    /** A comparison's answer, null being webpki's error. */
    private fun match(b: Boolean?): Match =
        when (b) {
            true -> Match.YES
            false -> Match.NO
            null -> Match.ERROR
        }

    /** null when [base] is of another form than [name], which webpki skips (`continue`). */
    private fun matches(
        name: PresentedName,
        base: Base,
        role: Role,
    ): Match? {
        val baseName = PresentedName.general(base.tag, base.content) ?: return Match.ERROR
        val notEvaluated = if (role == Role.PERMITTED) Match.NO else Match.YES
        return when (name) {
            is PresentedName.Dns -> {
                (baseName as? PresentedName.Dns)?.let {
                    match(DnsNameConstraint.matches(name.id, it.id, excluded = role == Role.EXCLUDED))
                }
            }

            is PresentedName.Ip -> {
                (baseName as? PresentedName.Ip)?.let { match(ipMatches(name.address, it.address)) }
            }

            PresentedName.Directory -> {
                if (baseName == PresentedName.Directory) notEvaluated else null
            }

            PresentedName.Uri -> {
                if (baseName == PresentedName.Uri) notEvaluated else null
            }

            is PresentedName.Unsupported -> {
                if (baseName == name) Match.ERROR else null
            }
        }
    }

    internal companion object {
        private const val SEQUENCE = 0x30
        private const val PERMITTED = 0xa0
        private const val EXCLUDED = 0xa1
        private const val IPV4 = 4
        private const val IPV6 = 16
        private const val BITS = 8
        private val SITE = HeaderSite.EXTENSION_VALUE

        /**
         * The constraints of [p]'s one nameConstraints extension: null when it has none, [UNREADABLE] when it is
         * malformed, duplicated or spelled with a non-minimal OID arc, so that it fails closed.
         */
        fun of(p: ParsedCertificate): NameConstraints? {
            val found = p.extensions(NAME_CONSTRAINTS)
            if (found.isEmpty()) return null
            if (found.size > 1) return UNREADABLE
            val e = found[0]
            if (!Oid.matches(p.tbsBytes, e.oid, NAME_CONSTRAINTS_CONTENT)) return UNREADABLE
            return read(p.tbsBytes, e.value) ?: UNREADABLE
        }

        /**
         * `NameConstraints ::= SEQUENCE { permittedSubtrees [0] OPTIONAL, excludedSubtrees [1] OPTIONAL }` over the
         * `extnValue` content [value], each `GeneralSubtree` a SEQUENCE holding its base alone (webpki's
         * `general_subtree`: a `minimum` or `maximum` written is an error). Null when malformed: not DER, trailing
         * data, a base webpki does not read, neither field, or an empty `GeneralSubtrees` (mozilla::pkix
         * `ERROR_BAD_DER` on both; webpki accepts them, but they constrain nothing, so failing closed is stricter only
         * on what no CA should issue).
         */
        fun read(
            b: ByteArray,
            value: Span,
        ): NameConstraints? =
            try {
                val ctx = ParseContext()
                val r = DerReader(b, value.start, value.end, ctx)
                val fields = r.child(r.read(SEQUENCE, SITE))
                r.requireEnd("nameConstraints")
                val permitted =
                    fields
                        .readOptional(
                            PERMITTED,
                            SITE,
                        )?.let { subtrees(b, fields.child(it)) ?: return null }
                val excluded = fields.readOptional(EXCLUDED, SITE)?.let { subtrees(b, fields.child(it)) ?: return null }
                fields.requireEnd("nameConstraints")
                if (ctx.nonMinimal.isNotEmpty() || (permitted == null && excluded == null)) {
                    null
                } else {
                    NameConstraints(permitted, excluded)
                }
            } catch (_: DerException) {
                null
            }

        private fun subtrees(
            b: ByteArray,
            r: DerReader,
        ): List<Base>? {
            if (!r.hasMore()) return null
            val out = ArrayList<Base>()
            while (r.hasMore()) {
                val subtree = r.child(r.read(SEQUENCE, SITE))
                val base = subtree.readAny(SITE)
                if (subtree.hasMore()) return null
                val content = base.content.bytes(b)
                if (PresentedName.general(base.tag, content) == null) return null
                out += Base(base.tag, content)
            }
            return out
        }

        /** webpki's `ip_address::presented_id_matches_constraint`: null on a malformed name or constraint. */
        private fun ipMatches(
            name: ByteArray,
            constraint: ByteArray,
        ): Boolean? {
            val family = sameFamily(name.size, constraint.size) ?: return null
            if (!family) return false
            var seenZeroBit = false
            for (i in name.indices) {
                val n = name[i].toInt() and 0xff
                val a = constraint[i].toInt() and 0xff
                val m = constraint[name.size + i].toInt() and 0xff
                // A valid mask octet is ones then zeros, and no bit is set after the first octet with a zero bit.
                if (leadingOnes(m) + trailingZeros(m) != BITS) return null
                if (seenZeroBit && m != 0) return null
                if (m != 0xff) seenZeroBit = true
                if ((n xor a) and m != 0) return false
            }
            return true
        }

        /**
         * True for an IPv4 name and constraint, or an IPv6 pair; false for one of each, which never matches; null for
         * any other length, which is malformed.
         */
        private fun sameFamily(
            nameSize: Int,
            constraintSize: Int,
        ): Boolean? {
            val name = nameSize == IPV4 || nameSize == IPV6
            val constraint = constraintSize == 2 * IPV4 || constraintSize == 2 * IPV6
            return if (name && constraint) constraintSize == 2 * nameSize else null
        }

        private fun leadingOnes(octet: Int): Int {
            var n = 0
            while (n < BITS && octet and (0x80 ushr n) != 0) n++
            return n
        }

        private fun trailingZeros(octet: Int): Int {
            var n = 0
            while (n < BITS && octet and (1 shl n) == 0) n++
            return n
        }

        /** webpki's bound on the comparisons of one build (`verify_cert.rs` 353, from Go's `crypto/x509`). */
        const val MAX_COMPARISONS: Int = 250_000

        const val NAME_CONSTRAINTS: String = "2.5.29.30"
        private val NAME_CONSTRAINTS_CONTENT = byteArrayOf(0x55, 0x1d, 0x1e)

        /** A nameConstraints extension that cannot be read: it admits no name. */
        val UNREADABLE: NameConstraints = NameConstraints(listOf(Base(-1, ByteArray(0))), null)
    }
}

/**
 * webpki's dNSName matching in the name-constraint role (`dns_name.rs` 238–360) and its `is_valid_dns_id`
 * (400–531), ported line for line. A presented ID may hold a wildcard label (`*` alone, followed by at least two
 * labels); a constraint may not, may be empty (it covers every name) and may start with a dot (subdomains only).
 */
internal object DnsNameConstraint {
    private const val MAX_NAME = 253
    private const val MAX_LABEL = 63
    private const val MIN_WILDCARD_LABELS = 3

    /**
     * Whether [presented] is within the subtree [constraint]; null when either is malformed (webpki's
     * `MalformedDnsIdentifier` and `MalformedNameConstraint`). In an [excluded] subtree a wildcard label is expanded,
     * so a wildcard that could reach into it matches (CVE-2025-61727); in a permitted one it never does.
     */
    @Suppress("CyclomaticComplexMethod", "ReturnCount") // a line-for-line port of webpki's branching
    fun matches(
        presented: ByteArray,
        constraint: ByteArray,
        excluded: Boolean,
    ): Boolean? {
        if (!valid(presented, constraintRole = false, wildcards = true)) return null
        if (!valid(constraint, constraintRole = true, wildcards = false)) return null
        var p = 0
        var r = 0
        if (presented.size > constraint.size) {
            if (constraint.isEmpty()) return true
            if (constraint[0] == DOT) {
                p = presented.size - constraint.size
            } else {
                p = presented.size - constraint.size - 1
                if (presented[p++] != DOT) return false
            }
        }
        if (excluded && p < presented.size && presented[p] == STAR) {
            p++
            while (true) {
                if (r >= constraint.size) return false
                r++
                if (r < constraint.size && constraint[r] == DOT) break
            }
        }
        while (true) {
            if (p >= presented.size || r >= constraint.size) return false
            val pb = presented[p++]
            val rb = constraint[r++]
            if (lower(pb) != lower(rb)) return false
            if (p == presented.size) {
                if (pb == DOT) return null
                break
            }
        }
        return r == constraint.size
    }

    private fun lower(b: Byte): Int =
        (b.toInt() and 0xff).let {
            if (it in
                'A'.code..'Z'.code
            ) {
                it + ('a' - 'A')
            } else {
                it
            }
        }

    /** `is_valid_dns_id` for a presented ID or a name constraint (the two roles this check uses). */
    @Suppress("CyclomaticComplexMethod", "ReturnCount", "LoopWithTooManyJumpStatements") // a port of webpki
    fun valid(
        id: ByteArray,
        constraintRole: Boolean,
        wildcards: Boolean,
    ): Boolean {
        if (id.size > MAX_NAME) return false
        if (constraintRole && id.isEmpty()) return true
        var i = 0
        var dots = 0
        var labelLength = 0
        var allNumeric = false
        var endsWithHyphen = false
        val isWildcard = wildcards && id.isNotEmpty() && id[0] == STAR
        var isFirstByte = !isWildcard
        if (isWildcard) {
            if (id.size < 2 || id[1] != DOT) return false
            i = 2
            dots++
        }
        if (i >= id.size) return false
        while (i < id.size) {
            val c = id[i++].toInt() and 0xff
            when {
                c == '-'.code -> {
                    if (labelLength == 0) return false
                    allNumeric = false
                    endsWithHyphen = true
                    if (++labelLength > MAX_LABEL) return false
                }

                c in '0'.code..'9'.code -> {
                    if (labelLength == 0) allNumeric = true
                    endsWithHyphen = false
                    if (++labelLength > MAX_LABEL) return false
                }

                c in 'a'.code..'z'.code || c in 'A'.code..'Z'.code || c == '_'.code -> {
                    allNumeric = false
                    endsWithHyphen = false
                    if (++labelLength > MAX_LABEL) return false
                }

                c == '.'.code -> {
                    dots++
                    if (labelLength == 0 && (!constraintRole || !isFirstByte)) return false
                    if (endsWithHyphen) return false
                    labelLength = 0
                }

                else -> {
                    return false
                }
            }
            isFirstByte = false
        }
        if (labelLength == 0) return false
        if (endsWithHyphen || allNumeric) return false
        if (isWildcard) {
            val labels = if (labelLength == 0) dots else dots + 1
            if (labels < MIN_WILDCARD_LABELS) return false
        }
        return true
    }

    private const val DOT = '.'.code.toByte()
    private const val STAR = '*'.code.toByte()
}
