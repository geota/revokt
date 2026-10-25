// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

import kotlinx.kover.gradle.plugin.dsl.CoverageUnit

plugins {
    id("revokt.kmp-library")
}

kotlin {
    sourceSets {
        commonMain.dependencies {
            implementation(project(":revokt-clubcard"))
            implementation(libs.okio)
            api(libs.kotlinx.coroutines.core)
        }
        commonTest.dependencies {
            implementation(libs.kotlin.test)
        }
        jvmTest.dependencies {
            implementation(libs.kotlin.test.junit5)
            implementation(project.dependencies.platform(libs.junit.bom))
            implementation(libs.junit.jupiter)
            implementation(libs.jazzer.junit)
            implementation(libs.conscrypt.openjdk.uber)
            runtimeOnly(libs.junit.platform.launcher)
        }
    }
}

// The replay's recording hooks (native/*/record-goldens.sh) pass their output paths through.
tasks.withType<Test>().configureEach {
    for (name in listOf("revokt.writeProducerInputs", "revokt.writeRecords", "revokt.writeOracleInputs")) {
        providers.systemProperty(name).orNull?.let { systemProperty(name, it) }
    }
    // The zlint pin test reads the pin: go.mod is an input, so a bump that touches only go.mod re-runs it, and its
    // path reaches the test without entering the cache key.
    jvmArgumentProviders.add(ZlintGoMod(rootProject.file("native/zlint-oracle/go.mod")))
    // Oracle 2 (Conscrypt) loads its JNI library; JDK 24+ warn and a later release blocks it without this (JDK 17+).
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}

// Spec §9.2 Acceptance and CONTRIBUTING "Coverage": Kover branch coverage of the parser package of at least 90 % over
// the committed replay (jvmTest), part of `check`. The floor may only be raised.
kover {
    currentProject {
        createVariant("parser") { add("jvm") }
    }
    reports {
        variant("parser") {
            filters { includes { packages("dev.revokt.engine.parse") } }
            verify { rule("parser package branch coverage") { minBound(90, CoverageUnit.BRANCH) } }
        }
    }
}

tasks.named("check") { dependsOn("koverVerifyParser") }

class ZlintGoMod(
    @get:InputFile @get:PathSensitive(PathSensitivity.RELATIVE) val file: File,
) : CommandLineArgumentProvider {
    override fun asArguments(): List<String> = listOf("-Drevokt.zlintGoMod=${file.absolutePath}")
}

// The Conscrypt dimension of the §9.2 matrix (gradle/oracle-matrix.properties): jvmTest runs oracle 2 on the catalog's
// `conscrypt`; this task reruns the Conscrypt-dependent tests (and the recording hooks) on `conscrypt-previous`, with that
// uber jar in place of the current one. Part of `check`.
val conscryptPrevious by configurations.creating {
    isCanBeConsumed = false
    isCanBeResolved = true
    isTransitive = false
}
dependencies { conscryptPrevious(libs.conscrypt.openjdk.uber.previous) }

val jvmTestConscryptPrevious =
    tasks.register<Test>("jvmTestConscryptPrevious") {
        description = "The Conscrypt-dependent replay and records on the matrix's previous Conscrypt minor."
        group = "verification"
        val test = kotlin.jvm().compilations.getByName("test")
        testClassesDirs = test.output.classesDirs
        val runtime = test.output.allOutputs + files(test.runtimeDependencyFiles)
        classpath = runtime.filter { !it.name.startsWith("conscrypt-openjdk-uber-") } + conscryptPrevious
        useJUnitPlatform()
        filter {
            for (test in listOf("ConscryptReplayTest", "RecordsTest", "Oracle3aTest", "ProducerGoldensWriterTest")) {
                includeTestsMatching("*.$test")
            }
        }
    }

tasks.named("check") { dependsOn(jvmTestConscryptPrevious) }
