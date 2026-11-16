// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

plugins {
    id("revokt.kmp-library")
}

kotlin {
    sourceSets {
        commonMain.dependencies {
            implementation(libs.okio)
        }
        commonTest.dependencies {
            implementation(libs.kotlin.test)
        }
        jvmTest.dependencies {
            implementation(libs.kotlin.test.junit5)
            implementation(project.dependencies.platform(libs.junit.bom))
            implementation(libs.junit.jupiter)
            implementation(libs.jazzer.junit)
            runtimeOnly(libs.junit.platform.launcher)
        }
    }
}

// Spec §9.1 harness: a fuzzing run (JAZZER_FUZZ set, as Jazzer reads it; fuzz.yml) gets -Xmx256m, so the JVM stays under
// the -rss_limit_mb=1024 the workflow passes.
val jazzerFuzz = providers.environmentVariable("JAZZER_FUZZ").orNull?.lowercase()
if (jazzerFuzz == "1" || jazzerFuzz == "true" || jazzerFuzz == "yes") {
    tasks.named<Test>("jvmTest") { maxHeapSize = "256m" }
}

// The clubcard corpus replay (docs/dev/corpus.md "Clubcard corpus"): the oracle goldens are a test input.
val clubcardCorpus = rootProject.layout.projectDirectory.dir("corpus/clubcard")
tasks.withType<Test>().configureEach {
    inputs.dir(clubcardCorpus).withPathSensitivity(PathSensitivity.RELATIVE)
    systemProperty("revokt.clubcardCorpus", clubcardCorpus.asFile.path)
}
