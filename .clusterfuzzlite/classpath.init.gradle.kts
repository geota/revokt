// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

// ClusterFuzzLite build (#119): `cfliteClasspath` in every module with a `jvmTest` task writes that task's runtime
// classpath (the test and main class and resource directories, the module's dependencies and the other modules' jars),
// one absolute path per line, to <module>/build/cflite/classpath.txt; .github/scripts/cflite_build.py turns it into each
// fuzz target's launcher. It builds what the classpath needs and runs no test. Used only by .clusterfuzzlite/build.sh,
// with --no-configuration-cache (the task reads the classpath when it runs).

gradle.allprojects {
    afterEvaluate {
        val test = tasks.findByName("jvmTest") as? Test ?: return@afterEvaluate
        val classpath = test.classpath
        val out = layout.buildDirectory.file("cflite/classpath.txt")
        tasks.register("cfliteClasspath") {
            description = "Writes the jvmTest runtime classpath for the ClusterFuzzLite build (#119)."
            dependsOn(classpath)
            outputs.file(out)
            outputs.upToDateWhen { false }
            doLast {
                val file = out.get().asFile
                file.parentFile.mkdirs()
                file.writeText(classpath.files.joinToString("\n", postfix = "\n") { it.absolutePath })
            }
        }
    }
}
