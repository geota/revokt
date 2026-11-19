// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import com.code_intelligence.jazzer.junit.FuzzTest
import java.net.URI
import java.net.URL
import kotlin.random.Random

/**
 * Spec §9.1 target "x5u URL" (#213): [X5uUrl] and the [StrictUrl] grammar under it, differential against the JDK's URL
 * parsers, as [X5uUrlDifferentialTest] checks them with fixed seeds. Every URL [X5uUrl] lets through must read, to
 * `java.net.URI` and `java.net.URL` (which `HttpsURLConnection` connects with), as https to an allowlisted host on port
 * 443 with no userinfo or fragment, and two checks of one input must agree. Nothing may throw.
 *
 * The first input byte's low bit turns on the rewrite of the allowlisted host to the mirror; the rest is the URL,
 * decoded as UTF-8. An input of the form `seed:<decimal>` instead runs [SEED_CASES] URLs of the differential test's
 * generator under `Random(<decimal>)`; the committed inputs hold its seed, `seed:129`. The URL is a string inside the
 * changeset JSON, whose only bound is `RevoktLimits.MAX_JSON_BYTES`, so the fuzz job runs with
 * `-max_len=4194305`. With `JAZZER_FUZZ` unset JUnit replays `X5uUrlFuzzTestInputs/`.
 */
class X5uUrlFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun check(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        const val HOST = "content-signature-2.cdn.mozilla.net"
        const val MIRROR = "x5u.mirror.example"

        /** The generator's URLs per `seed:` input: enough to reach the accepting grammar, few enough to fuzz quickly. */
        private const val SEED_CASES = 64

        private val SEED = Regex("seed:(-?[0-9]{1,19})")

        /** The differential test's pieces, joined at random into URLs. */
        val PIECES =
            listOf(
                "https://",
                "http://",
                "HTTPS://",
                HOST,
                MIRROR,
                "evil.example",
                "@",
                ":",
                "443",
                "8443",
                "/",
                "//",
                "?",
                "#",
                "\\",
                "%2e",
                "%40",
                "%2F",
                "%",
                ".",
                "..",
                "a",
                " ",
                "[",
                "]",
                "[::1]",
                "\t",
                "ü",
                "%00",
                ";",
                "&",
                "=",
                "'",
                "user",
                "-",
                "_",
                "~",
                "\r\n",
                "\u0000",
                "*",
                "!",
                "$",
                "(",
                ")",
            )

        /** The static entry point a standalone Jazzer driver calls (CONTRIBUTING §6). */
        @JvmStatic
        fun fuzzerTestOneInput(data: ByteArray) {
            val seed =
                SEED
                    .matchEntire(String(data, Charsets.ISO_8859_1))
                    ?.groupValues
                    ?.get(1)
                    ?.toLongOrNull()
            if (seed != null) {
                val random = Random(seed)
                repeat(SEED_CASES) { generated(random) }
                return
            }
            if (data.isEmpty()) return
            val rewrites = if (data[0].toInt() and 1 == 1) mapOf(HOST to MIRROR) else emptyMap()
            checkOne(String(data, 1, data.size - 1, Charsets.UTF_8), rewrites)
        }

        /** One URL of the differential test's generator, checked; true when [X5uUrl] let it through. */
        fun generated(random: Random): Boolean {
            val (url, rewrites) = case(random)
            return checkOne(url, rewrites)
        }

        /** One URL and rewrite map of the generator, drawing from [random] exactly as the differential test always has. */
        fun case(random: Random): Pair<String, Map<String, String>> {
            val prefix =
                when (random.nextInt(3)) {
                    0 -> ""
                    1 -> "https://" + (if (random.nextBoolean()) HOST else MIRROR)
                    else -> "https://" + (if (random.nextBoolean()) HOST else MIRROR) + "/"
                }
            val url = prefix + List(random.nextInt(1, 8)) { PIECES[random.nextInt(PIECES.size)] }.joinToString("")
            val rewrites = if (random.nextBoolean()) mapOf(HOST to MIRROR) else emptyMap()
            return url to rewrites
        }

        /** [url] through [X5uUrl] twice; when it is let through, the JDK must read it as the rules did. */
        fun checkOne(
            url: String,
            rewrites: Map<String, String>,
        ): Boolean {
            val first = X5uUrl.check(url, setOf(HOST, MIRROR), rewrites)
            val second = X5uUrl.check(url, setOf(HOST, MIRROR), rewrites)
            check(first.url == second.url && first.failure == second.failure) { "a second check differs" }
            check((first.url == null) == (first.failure != null)) { "neither allowed nor refused" }
            val fetched = first.url ?: return false
            jdkAgrees(fetched)
            // The input itself reads the same way wherever the JDK accepts it.
            val original = runCatching { URI(url) }.getOrNull()
            if (original != null) {
                check(
                    fetched.substringAfter("://").substringBefore('/').substringBefore('?') ==
                        (rewrites[original.host] ?: original.host),
                ) { "the JDK reads another host in the input than the rules let through" }
            }
            return true
        }

        /** [fetched], as the fetcher would request it, reads to `URI` and `URL` as https to an allowlisted host on 443. */
        fun jdkAgrees(fetched: String) {
            val uri = URI(fetched)
            check(uri.scheme == "https") { "URI scheme" }
            check(uri.host == HOST || uri.host == MIRROR) { "URI host" }
            check(uri.port == -1 || uri.port == 443) { "URI port" }
            check(uri.rawUserInfo == null) { "URI userinfo" }
            check(uri.rawFragment == null) { "URI fragment" }
            val url = URL(fetched)
            check(url.host == uri.host) { "URL host" }
            check((if (url.port == -1) url.defaultPort else url.port) == 443) { "URL port" }
            check(url.userInfo == null) { "URL userinfo" }
        }
    }
}
