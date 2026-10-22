// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import org.gradle.api.Project
import org.gradle.api.tasks.Exec
import org.gradle.kotlin.dsl.register

/**
 * The consumer builds under consumers/ (spec §3.1 item 4, §9), run under `-Prevokt.ci` after `publishToMavenLocal`
 * (CONTRIBUTING §6). Each is its own build so it resolves the artifacts the way a consumer would.
 */
internal fun Project.registerConsumerBuilds() {
    val version = providers.gradleProperty("revokt.version").getOrElse("0.1.0-SNAPSHOT")
    val publishAll = tasks.register("publishAllToMavenLocal") {
        description = "publishToMavenLocal on every published module, for the consumer builds."
        group = "revokt"
        dependsOn(subprojects.filter { it.plugins.hasPlugin("maven-publish") }.map { "${it.path}:publishToMavenLocal" })
    }
    val gradlew = layout.projectDirectory.file(if (System.getProperty("os.name").startsWith("Windows")) "gradlew.bat" else "gradlew").asFile.absolutePath

    val java = tasks.register<Exec>("consumerJava") {
        description = "consumers/java-consumer: resolves the BOM and the -jvm artifact from mavenLocal and runs."
        group = "verification"
        dependsOn(publishAll)
        workingDir = layout.projectDirectory.dir("consumers/java-consumer").asFile
        commandLine(gradlew, "--no-daemon", "-q", "run", "-Prevokt.version=$version")
    }
    val kotlin = tasks.register<Exec>("consumerKotlin") {
        description = "consumers/kotlin-consumer: resolves the KMP root artifact from mavenLocal and runs."
        group = "verification"
        dependsOn(publishAll)
        workingDir = layout.projectDirectory.dir("consumers/kotlin-consumer").asFile
        commandLine(gradlew, "--no-daemon", "-q", "run", "-Prevokt.version=$version")
    }
    val maven = tasks.register<Exec>("consumerMaven") {
        description = "consumers/maven-consumer: `mvn -q verify` against mavenLocal (Maven must be installed; CI has it)."
        group = "verification"
        dependsOn(publishAll)
        workingDir = layout.projectDirectory.dir("consumers/maven-consumer").asFile
        commandLine("mvn", "-q", "-B", "verify", "-Drevokt.version=$version")
    }
    tasks.named("check") { dependsOn(java, kotlin, maven) }
}
