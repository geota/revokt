// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.verify

import dev.revokt.engine.parse.DerException
import dev.revokt.engine.parse.DerReader
import dev.revokt.engine.parse.ExtensionValues
import dev.revokt.engine.parse.HeaderSite
import dev.revokt.engine.parse.ParseContext
import dev.revokt.engine.parse.Span

/**
 * A CA's nameConstraints as mozilla::pkix's `CheckNameConstraints` applies them to the leaf's dNSName (`pkixnames.cpp`
 * at `cac25a6`; revision 54, pending), critical or not. Only the dNSName subtrees bind:
 *
 * - The name must match a [permitted] dNSName subtree when any is listed (the check is per name type, so a permitted
 *   list without a dNSName constrains nothing) and no [excluded] one.
 * - A subtree matches at a label boundary, ignoring ASCII case: without a leading dot it covers the name and its
 *   subdomains, with one only the subdomains. An empty subtree covers every name, so a permitted one admits all and an
 *   excluded one rejects all (`MatchPresentedDNSIDWithReferenceDNSID` in the name-constraint role).
 * - A directoryName subtree applies to every subject below the CA, which revokt does not evaluate, so [read] fails
 *   closed on one. Other name forms are ignored, as mozilla::pkix ignores them for a dNSName.
 */
internal class DnsSubtrees private constructor(
    private val permitted: List<String>,
    private val excluded: List<String>,
) {
    fun permits(name: String): Boolean =
        (permitted.isEmpty() || permitted.any { covers(it, name) }) && excluded.none { covers(it, name) }

    internal companion object {
        private const val SEQUENCE = 0x30
        private const val PERMITTED = 0xa0
        private const val EXCLUDED = 0xa1
        private const val DIRECTORY_NAME = 0xa4
        private val SITE = HeaderSite.EXTENSION_VALUE

        /**
         * `ReadGeneralName`'s forms: otherName, rfc822Name, dNSName, x400Address, directoryName, ediPartyName, URI,
         * iPAddress, registeredID.
         */
        private val GENERAL_NAMES =
            setOf(0xa0, 0x81, ExtensionValues.DNS_NAME, 0xa3, DIRECTORY_NAME, 0xa5, 0x86, 0x87, 0x88)

        /**
         * The subtrees of the `extnValue` content [value], or null when they are malformed or cannot be evaluated, so that
         * the chain fails closed. That covers: not DER; neither field (`ERROR_BAD_DER`); an empty `GeneralSubtrees`; a
         * `minimum` or `maximum` written (the subtree is its base alone, RFC 5280 §4.2.1.10); a base that is not a
         * `GeneralName`; a dNSName that is not a valid name-constraint DNS ID ([DnsId]); a directoryName.
         */
        fun read(
            b: ByteArray,
            value: Span,
        ): DnsSubtrees? =
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
                val readable = ctx.nonMinimal.isEmpty() && (permitted != null || excluded != null)
                if (readable) DnsSubtrees(permitted.orEmpty(), excluded.orEmpty()) else null
            } catch (_: DerException) {
                null
            }

        /** The dNSName bases of one `GeneralSubtrees`, or null when [read] must fail. */
        private fun subtrees(
            b: ByteArray,
            r: DerReader,
        ): List<String>? {
            val out = ArrayList<String>()
            if (!r.hasMore()) return null
            while (r.hasMore()) {
                val subtree = r.child(r.read(SEQUENCE, SITE))
                val base = subtree.readAny(SITE)
                if (subtree.hasMore() || base.tag !in GENERAL_NAMES || base.tag == DIRECTORY_NAME) return null
                if (base.tag != ExtensionValues.DNS_NAME) continue
                val name = base.content.bytes(b).decodeToString()
                if (!DnsId.validConstraint(name)) return null
                out += name
            }
            return out
        }

        private fun covers(
            constraint: String,
            name: String,
        ): Boolean {
            val c = constraint.lowercase()
            val n = name.lowercase()
            return when {
                c.isEmpty() -> true
                c.startsWith('.') -> n.endsWith(c)
                else -> n == c || n.endsWith(".$c")
            }
        }
    }
}

/**
 * mozilla::pkix's `IsValidDNSID` in the name-constraint role, wildcards not allowed: at most 253 octets; empty, or
 * labels of letters, digits, `-` and `_`, each 1 to 63 octets, none starting or ending with `-`, separated by single
 * dots, with one optional leading dot; the last label not all digits. So `x.`, `.`, `*.example` and `-x.example` fail.
 */
internal object DnsId {
    private const val MAX_NAME = 253
    private const val MAX_LABEL = 63

    fun validConstraint(name: String): Boolean {
        if (name.length > MAX_NAME) return false
        if (name.isEmpty()) return true
        val labels = (if (name.startsWith('.')) name.substring(1) else name).split('.')
        return labels.all(::validLabel) && !labels.last().all { it in '0'..'9' }
    }

    private fun validLabel(label: String): Boolean =
        label.length in 1..MAX_LABEL && !label.startsWith('-') && !label.endsWith('-') &&
            label.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' || it == '_' }
}
