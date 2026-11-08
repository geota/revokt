// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import org.gradle.api.GradleException
import org.gradle.testfixtures.ProjectBuilder
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class FuzzTargetsTest {
    private fun tree(files: Map<String, String>, body: (File) -> Unit) {
        val dir = Files.createTempDirectory("fuzz-targets").toFile()
        try {
            for ((path, text) in files) dir.resolve(path).apply { parentFile.mkdirs() }.writeText(text.trimIndent())
            body(dir)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `the task lists exactly the @FuzzTest methods of the modules' jvmTest sources`() {
        val files = mapOf(
            "mod-a/src/jvmTest/kotlin/x/y/AFuzzTest.kt" to """
                package x.y

                /**
                 * Not a target: a KDoc @FuzzTest mention. The nightly job runs it with `-max_len=4097 -timeout=1`.
                 */
                class AFuzzTest {
                    @FuzzTest(maxDuration = "60s")
                    fun one(data: ByteArray) {
                        fuzzerTestOneInput(data)
                    }

                    @FuzzTest
                    fun two(data: ByteArray) = Unit

                    @Test
                    fun notOne() = Unit
                }
            """,
            "mod-a/src/jvmTest/kotlin/x/y/Plain.kt" to """
                package x.y

                // see @FuzzTest in AFuzzTest
                class Plain {
                    fun helper() = Unit
                }
            """,
            "mod-a/src/jvmMain/kotlin/x/Main.kt" to """
                package x

                class Main {
                    @FuzzTest
                    fun notInJvmTest(data: ByteArray) = Unit
                }
            """,
            "mod-b/src/jvmTest/kotlin/BFuzzTest.kt" to """
                internal class BFuzzTest {
                    @FuzzTest fun go(data: ByteArray) = Unit
                }
            """,
        )
        tree(files) { dir ->
            val root = ProjectBuilder.builder().withProjectDir(dir).build()
            for (name in listOf("mod-a", "mod-b")) ProjectBuilder.builder().withParent(root).withName(name).withProjectDir(dir.resolve(name)).build()
            root.registerFuzzTargets().get().write()
            assertEquals(
                """
                    [
                      {"name": "AFuzzTest.one", "project": ":mod-a", "module": "mod-a", "class": "x.y.AFuzzTest", "method": "one", "source": "mod-a/src/jvmTest/kotlin/x/y/AFuzzTest.kt", "maxLen": 4097, "timeout": 1},
                      {"name": "AFuzzTest.two", "project": ":mod-a", "module": "mod-a", "class": "x.y.AFuzzTest", "method": "two", "source": "mod-a/src/jvmTest/kotlin/x/y/AFuzzTest.kt", "maxLen": 4097, "timeout": 1},
                      {"name": "BFuzzTest.go", "project": ":mod-b", "module": "mod-b", "class": "BFuzzTest", "method": "go", "source": "mod-b/src/jvmTest/kotlin/BFuzzTest.kt", "maxLen": null, "timeout": 10}
                    ]

                """.trimIndent(),
                dir.resolve("build/fuzz/targets.json").readText(),
            )
        }
    }

    @Test
    fun `a file naming two values of one flag fails`() {
        val text = "class T {\n    @FuzzTest\n    fun a(data: ByteArray) = Unit\n}\n// -max_len=4097 and -max_len=65537\n"
        assertFailsWith<GradleException> { FuzzTargets.read("m", "m/src/jvmTest/kotlin/T.kt", text) }
    }

    @Test
    fun `two targets with one Class·method name fail`() {
        val files = mapOf(
            "m/src/jvmTest/kotlin/p/T.kt" to "package p\nclass T {\n    @FuzzTest\n    fun a(data: ByteArray) = Unit\n}\n",
            "m/src/jvmTest/kotlin/q/T.kt" to "package q\nclass T {\n    @FuzzTest\n    fun a(data: ByteArray) = Unit\n}\n",
        )
        tree(files) { dir ->
            assertFailsWith<GradleException> { FuzzTargets.scan(dir, dir.walk().filter { it.isFile }.toList()) }
        }
    }
}
