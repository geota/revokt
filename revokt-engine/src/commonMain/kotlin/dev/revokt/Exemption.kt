// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.ByteString
import okio.ByteString.Companion.toByteString
import kotlin.jvm.JvmStatic

/**
 * Lifts one fired `REJECT` rule (spec §4, §8 exemptions). An exemption runs after policy mapping, for fired `REJECT`
 * rules on exemptable rules only, and its answer is cached with the verdict, so it must be pure: a deterministic,
 * synchronous function of its [ExemptionContext]. A throw counts as not exempt and adds a `Finding.EngineError` whose
 * producer is `EXEMPTION`.
 */
public fun interface Exemption {
    public fun isExempt(context: ExemptionContext): Boolean

    /**
     * The shipped helpers (§4), for the enterprise-CA and §5.2-gap cases without a hand-written lambda; combine them
     * with `and` and `or` (Exemptions.kt). They live in this commonMain file because a companion cannot straddle
     * source sets.
     */
    public companion object {
        /**
         * Exempt when the reported path's anchor is one of [sha256s] (each the SHA-256 of an anchor's DER as revokt
         * reads it, §5.3), compared by content. [sha256s] is copied when the exemption is made, so a later change to an
         * array does not change what matches. A null `context.path.anchorSha256`, an empty reported path, never
         * matches.
         */
        @JvmStatic
        public fun anchorIn(sha256s: Collection<ByteArray>): Exemption {
            val anchors: Set<ByteString> = buildSet { sha256s.forEach { add(it.toByteString()) } }
            return Exemption { context -> context.path.anchorSha256?.toByteString() in anchors }
        }

        /**
         * Exempt when `context.host` is one of [hosts]. Each entry is compared as host' (§5.1 flow step 2: ASCII
         * lowercased, one trailing dot stripped), the form `context.host` already has. [hosts] is copied when the
         * exemption is made, and an entry that is not ASCII (a U-label: pass the A-label), is empty after
         * normalisation, starts with a dot or holds a `*` (use [hostSuffixIn] for a wildcard) throws
         * `IllegalArgumentException` then. A null `context.host` never
         * matches. On an HTTP/2-coalesced connection the host is the one OkHttp handshook for (§5.1).
         */
        @JvmStatic
        public fun hostIn(hosts: Collection<String>): Exemption {
            val names = entries(hosts, "hostIn")
            return Exemption { context -> context.host in names }
        }

        /**
         * Exempt when `context.host` equals one of [suffixes] or ends with `"." + suffix`: a private CA serves many
         * subdomains, so `"corp"` matches `"a.corp"` but not `"acorp"`. Entries are normalised and checked as for
         * [hostIn]. A null `context.host` never matches.
         */
        @JvmStatic
        public fun hostSuffixIn(suffixes: Collection<String>): Exemption {
            val names = entries(suffixes, "hostSuffixIn")
            return Exemption { context -> context.host?.let { hasSuffixIn(it, names) } == true }
        }

        /**
         * Exempt when the reported reason is `NoIssuerReason.PLATFORM_ONLY`: the platform accepted a chain revokt's
         * walker could not anchor (§5.2). On its own it exempts every such chain for every host, so the enterprise
         * recipe pairs it with [hostSuffixIn] (§8).
         */
        @JvmStatic
        public fun platformOnly(): Exemption = PLATFORM_ONLY

        private val PLATFORM_ONLY = Exemption { context -> context.path.noIssuerReason == NoIssuerReason.PLATFORM_ONLY }

        /** [hosts] as host', copied into a set; rejects an entry no normalised host could equal (spec §4, #160). */
        private fun entries(
            hosts: Collection<String>,
            helper: String,
        ): Set<String> =
            buildSet {
                hosts.forEach { host ->
                    require(host.all { it < '\u0080' }) { "$helper: \"$host\" is not ASCII; pass the A-label" }
                    val name = hostPrime(host)
                    require(name.isNotEmpty() && !name.startsWith('.')) {
                        "$helper: \"$host\" is empty or starts with a dot"
                    }
                    require('*' !in name) { "$helper: \"$host\" holds a '*'; hostSuffixIn is the wildcard form" }
                    add(name)
                }
            }

        /**
         * Whether [host] equals a suffix in [suffixes] or ends with `"." + suffix`. [host] itself, then what follows
         * each of its dots, is looked up, so the cost is one lookup per label whatever the number of suffixes.
         */
        private fun hasSuffixIn(
            host: String,
            suffixes: Set<String>,
        ): Boolean {
            var dot = -1
            do {
                if (host.substring(dot + 1) in suffixes) return true
                dot = host.indexOf('.', dot + 1)
            } while (dot >= 0)
            return false
        }
    }
}
