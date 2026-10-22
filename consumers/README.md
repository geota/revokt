# consumers/

Consumer builds (spec §3.1 item 4, §9): a Maven project, a Java project and a Kotlin project that depend on the
published artifacts through `mavenLocal()`. Run by `./gradlew check -Prevokt.ci` (the `ci-extras` job), after
`publishToMavenLocal`; never part of the plain `check`. They assert that the artifacts resolve (the KMP root and the
`-jvm` artifact, the BOM), that a Java caller sees the `@JvmField` limits and the declared exceptions, and that
`@JvmSynthetic` members stay invisible to Java. Each grows with the API it consumes.
