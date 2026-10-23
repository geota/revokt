// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.detekt

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.TestConfig
import io.gitlab.arturbosch.detekt.test.lint
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RulesTest {
    @Test
    fun `public constructor on final class is reported with a remediation message`() {
        val findings = PublicConstructorOnFinalClass(Config.empty).lint(
            """
            package dev.revokt
            public class Verdict(public val x: Int)
            """.trimIndent(),
        )
        assertEquals(1, findings.size)
        assertTrue(findings[0].message.contains("private constructor and a nested Builder"))
    }

    @Test
    fun `private constructor, Builder, exception, internal, marker and allow-list are exempt`() {
        val rule = PublicConstructorOnFinalClass(TestConfig("allowedClasses" to listOf("dev.revokt.KotlinRevocationEngine")))
        val findings = rule.lint(
            """
            package dev.revokt
            public annotation class RevoktInternalApi
            public class Verdict private constructor(public val x: Int) { public class Builder { public fun build(): Verdict = Verdict(1) } }
            public class RevoktCertificateException(message: String) : RuntimeException(message)
            internal class Hidden(public val x: Int)
            @RevoktInternalApi public class Plumbing(public val x: Int)
            public class KotlinRevocationEngine
            public object Limits
            public enum class Outcome { ALLOW }
            public interface Seam
            """.trimIndent(),
        )
        assertEquals(emptyList(), findings.map { it.message })
    }

    @Test
    fun `data and value classes are reported only on the public surface`() {
        val findings = NoDataOrValueClassOnPublicSurface(Config.empty).lint(
            """
            package dev.revokt
            public data class Pair2(val a: Int)
            @JvmInline public value class Serial(val bytes: ByteArray)
            internal data class Ok(val a: Int)
            """.trimIndent(),
        )
        assertEquals(2, findings.size)
    }

    @Test
    fun `port rules forbid inline and const only inside the port package`() {
        val port = ClubcardPortRules(Config.empty).lint(
            """
            package dev.revokt.clubcard.port
            public inline fun f(): Int = 1
            public const val W: Int = 4
            """.trimIndent(),
        )
        assertEquals(2, port.size)
        val api = ClubcardPortRules(Config.empty).lint(
            """
            package dev.revokt.clubcard.api
            public inline fun f(): Int = 1
            public const val W: Int = 4
            """.trimIndent(),
        )
        assertEquals(0, api.size)
    }

    @Test
    fun `http client imports are reported in test files`() {
        val findings = NoHttpClientInTests(Config.empty).lint(
            """
            package dev.revokt
            import java.net.URL
            import java.net.URI
            class FetcherTest
            """.trimIndent(),
        )
        assertEquals(1, findings.size)
        assertTrue(findings[0].message.contains("java.net.URL"))
    }
}
