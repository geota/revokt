// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.oracle

/**
 * The raw-byte reference of spec §9.2 D2 for one input, read from the recorded goldens: oracle 3a where it accepts,
 * else oracle 3b's TBS walk. [extensions] is the reference extension table (`oid,critical,value`, hex) and [scts] the
 * expected SCT pair set: the union over SCT extensions of the reference's pairs, or ∅ where the value's first octet, as
 * 3b locates it, is not `0x04`. [divergences] names the D3 classes the input falls in.
 */
internal class ReferenceView(
    val source: String,
    val serial: String,
    val spki: String,
    val subject: String,
    val issuer: String,
    val extensions: List<String>,
    val scts: Set<Pair<String, Long>>,
    val unusedBits: Int,
    val divergences: Set<String>,
) {
    companion object {
        /** The reference for the input whose SHA-256 is [sha], or null when neither 3a nor 3b's walk locates it. */
        fun of(sha: String): ReferenceView? {
            val a = Oracle3a.accepted(checkNotNull(Oracle3a.reply(sha)) { "no 3a golden for $sha" })
            val b = Oracle3b.located(checkNotNull(Oracle3b.reply(sha)) { "no 3b golden for $sha" })
            return when {
                a != null -> fromThreeA(a, b)
                b != null -> fromThreeB(b)
                else -> null
            }
        }

        private fun fromThreeA(
            a: Oracle3a.Accepted,
            b: Oracle3b.Located?,
        ): ReferenceView {
            val divergences = HashSet<String>()
            if (a.duplicateSct) divergences += "DUPLICATE_EXTENSION"
            // 3A_TBS_LAX: 3a takes an element with tag number 3 other than a constructed context [3] as extensions;
            // the §9.2 read, decided by 3b's walk, has none.
            if (b != null && b.tagThreeIgnored) {
                divergences += "3A_TBS_LAX"
                return ReferenceView(
                    "3a",
                    a.serial,
                    a.spki,
                    a.subject,
                    a.issuer,
                    emptyList(),
                    emptySet(),
                    a.canon.unusedBits,
                    divergences,
                )
            }
            val scts = HashSet<Pair<String, Long>>()
            for ((index, e) in a.extensions.withIndex().filter { it.value.sct != null }) {
                // The inner identifier octet is read by 3b's locator (3a's value where 3b's walk fails), never by revokt.
                val located = b?.extensions?.getOrNull(index)
                check(located == null || located.oid == e.oid) { "3b's extension $index is not 3a's" }
                val value = located?.value ?: e.value
                if (value.startsWith("04")) {
                    scts += e.sct.orEmpty()
                } else if (!e.sct.isNullOrEmpty()) {
                    divergences += "3A_HEADER_LAX"
                }
            }
            return ReferenceView(
                "3a",
                a.serial,
                a.spki,
                a.subject,
                a.issuer,
                a.extensions.map(::row),
                scts,
                a.canon.unusedBits,
                divergences,
            )
        }

        private fun fromThreeB(b: Oracle3b.Located): ReferenceView =
            ReferenceView(
                "3b",
                b.serial,
                b.spki,
                b.subject,
                b.issuer,
                b.extensions.map(::row),
                b.extensions.flatMap { it.sct.orEmpty() }.toSet(),
                checkNotNull(b.unusedBits) { "3b's LOCATED reply has no unused-bits octet" },
                emptySet(),
            )

        private fun row(e: Oracle3a.Extension) = "${e.oid},${e.critical},${e.value}"
    }
}
