# Local workflow

Gradle runs on **JDK 21** (`JAVA_HOME`); the daemon JVM is 21 because build-logic is compiled for it. The library
compiles to JDK 11 bytecode (`-Xjdk-release=11`) and Android API 26+ (animal-sniffer, from 0.2's jvm modules).
JDKs are never auto-provisioned: register local installs in `~/.gradle/gradle.properties` with
`org.gradle.java.installations.paths=…` when they are outside the OS defaults (Homebrew kegs, SDKMAN).

```
./gradlew specStatus                              # what is implemented, what is next (writes docs/dev/status.md)
git switch -c feat/42-tbs-parser main
# tests first
./gradlew check                                   # JDK-only, offline; the PR-tier core
./gradlew check -Prevokt.ci                       # adds consumers and the purity compile (Android modules from 0.3)
./gradlew check -Prevokt.testJdk=17               # run the tests on another installed JDK (the CI matrix)
./gradlew apiDump                                 # only when the public surface changed; commit the diff
./gradlew ktlintFormat                            # formatting is never a review topic
reuse lint && actionlint                          # headers and workflows
git commit -s                                     # human sign-off on every commit; fixup! commits are fine
gh pr create --draft --template .github/PULL_REQUEST_TEMPLATE.md
# after approval (or the independent review in the solo phase): gh pr merge --squash --auto
```

## What `check` covers

Unit tests (JUnit 5 through kotlin-test), the committed fixtures and corpus replay, Jazzer regression inputs
(`JAZZER_FUZZ` unset), ktlint, detekt with the repository rules (`revokt-detekt-rules`) on every source set and the
`detektCommonMain` purity check, `apiCheck`, `verifyPomLicenses`, `verifyDependencyScopes`, `verifyHeaderLocations`,
`verifyCorpusManifest`, `specStatusCheck` (stale `docs/dev/status.md` or a decreased fixture count fails), Kover, and
build-logic's own tests. No Android SDK, no Rust, no Go, no network.

`-Prevokt.ci` adds: the purity compile (`linuxX64`, downloads the Kotlin/Native toolchain once into `~/.konan`), the
consumer builds under `consumers/`, and from 0.3 the Android modules. `-Prevokt.native` includes `revokt-engine-upki`
(JDK 22) and expects `native/` built.

## Dependencies

See `deps.md`: one catalog, strict locking, verification metadata with a committed keyring.

## Measured durations

To be filled in after the bootstrap merges (CONTRIBUTING §6): `check` on a laptop, and each CI job.
