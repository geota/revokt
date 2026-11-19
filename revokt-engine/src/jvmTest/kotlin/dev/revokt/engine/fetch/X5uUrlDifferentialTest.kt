// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import java.net.URI
import java.net.URL
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * [StrictUrl]'s narrow grammar against the JDK's URL parsers (spec §7.1 "the parsed URI host" and "The x5u URL
 * grammar", #177): every x5u URL [X5uUrl] lets through is one `java.net.URI` and `java.net.URL`, which
 * `HttpsURLConnection` connects with, read as https to the allowlisted host on port 443 with no userinfo, so no
 * fetcher can be pointed at another host than the one checked.
 */
class X5uUrlDifferentialTest {
    private val host = X5uUrlFuzzTest.HOST

    private val pieces = X5uUrlFuzzTest.PIECES

    /** The fuzz target's generator and oracle (`X5uUrlFuzzTest`), over 200,000 URLs from the fixed seed. */
    @Test
    fun `every URL the x5u rules let through is the allowlisted host on 443 to java_net_URI and java_net_URL`() {
        val random = Random(129)
        var allowed = 0
        repeat(200_000) { if (X5uUrlFuzzTest.generated(random)) allowed++ }
        assertTrue(allowed > 10_000, "the generator reached the accepting grammar: $allowed")
    }

    @Test
    fun `known parser-differential shapes are refused`() {
        for (url in listOf(
            "https://$host\\@evil.example/x",
            "https://evil.example\\@$host/x",
            "https://evil.example#@$host/x",
            "https://evil.example?@$host/x",
            "https://$host%2F@evil.example/x",
            "https://$host:443@evil.example/x",
            "https://evil.example%2F$host/x",
            "https://$host%00.evil.example/x",
            "https://$host./x",
            "https://$host\t/x",
            "https://$host /x",
            "https:/$host/x",
            "https:$host/x",
            "https://[$host]/x",
            "https://0x7f.0.0.1/x",
        )) {
            assertNull(X5uUrl.check(url, setOf(host), emptyMap()).url, url)
        }
    }
}
