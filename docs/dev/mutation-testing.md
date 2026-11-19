<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Mutation testing (Pitest)

Pitest runs over the JVM classes of `revokt-engine`'s critical packages (`update`, `store`, `fetch`, `verify` and
`walker`) on dispatch and weekly, in `.github/workflows/pitest.yml`. It is never a PR gate and never part of `check`:
the run succeeds whatever survives, and the surviving mutants are the job summary and a 14-day artifact. A survivor
is a lead for a test, or an equivalent mutant; mutation is a working method, not evidence (the 2026-11-16 audit).

```
./gradlew :revokt-engine:pitestJvm                                  # all five packages
./gradlew :revokt-engine:pitestJvm -Prevokt.pitest.packages=store   # one; report in build/reports/pitest/
```

The `pitestJvm` task writes an arguments file from the `jvmTest` task's classpath, JVM and `-D` system properties, and
runs `tools/pitest/PitestRunner.java` as a single-file Java program. That program calls `pitest-entry`'s API
(`EntryPoint`) with Pitest's command-line defaults. The mutants are run against the chosen packages' own tests, not every test of the engine (see below).
Output is XML and CSV; `.github/scripts/pitest_summary.py` turns the XML into the job summary.

## Dependencies

The `pitest` configuration of `revokt-engine` resolves `pitest-entry` and `pitest-junit5-plugin` only (with `pitest`,
ASM 9.11 and Commons Text and Lang). Its one new PGP key, Henry Coles's, is trusted for exactly those three `org.pitest`
artifacts (`docs/dev/deps.md`). `pitest-junit5-plugin`'s POM imports the Groovy and Spock BOMs, whose two POMs are
verified by SHA-256 (cross-checked with Maven Central's SHA-1) rather than by two more keys.

## The spike (#215, 2026-11-19), what it found

Local runs, JDK 21, 4 threads, each package against its own tests:

| Package | Mutants | Killed | Survived | No coverage | Test strength | Time |
|---|---:|---:|---:|---:|---:|---:|
| `store` | 398 | 87 % | 32 | 20 | 92 % | 20 s |
| `update` | 790 | 79 % | 88 | 74 | 88 % | 91 s |
| `fetch` | 655 | 91 % | 48 | 13 | 93 % | 33 s |
| `verify` | 627 | 91 % | 28 | 27 | 95 % | 74 s |
| `walker` | 330 | 87 % | 12 | 30 | 96 % | 197 s |

The task's own run over all five (one Pitest run, the five packages' tests together) generated 2800 mutants, killed 87 % (test strength 92 %) and took 6 min 19 s. "Killed" counts timeouts as killed, as Pitest does. The 208 survivors break down by mutator as follows: changed
conditional boundary 59, removed void call 58, negated conditional 39, empty return 26, null return 9, maths 8,
primitive return 5, `true` return 4. `CrliteSync.kt` holds 62 of them.

### What did not work, and why

- **The Gradle Pitest plugin** (`info.solidsoft.pitest` 1.19.0) does not support Kotlin Multiplatform. It configures
  itself only under the `java` plugin, with the `main` and `test` source sets (`PitestPlugin.groovy`), which a KMP
  module does not have; its issue #234, "Support Kotlin Multiplatform", is open.
- **Pitest's command line** (`pitest-command-line`) runs, but it is the heavier dependency. It brings jopt-simple 4.9
  (signed with a 2011 DSA-1024 key) and the HTML report, whose stringtemplate 3.2.1 and antlr 2.7.7 are unsigned on
  Maven Central. Its `--jvmArgs` also splits on commas, which broke `-Drevokt.matrixConscrypt=2.8.0,2.7.0`: every
  minion died with `Could not find or load main class 2.7.0`. The runner reads one value per line instead.
- **The runner's own traps.** As a single-file program, its launch class path is not one Pitest can read its agent
  from (`Unable to load class content for org.pitest.boot.HotSwapAgent`), so the task lists Pitest's jars in the
  class path too. `ReportOptions` leaves the command line's defaults null, so the runner sets them.
- **Kotlin bytecode noise.** Without a filter, the largest group of survivors in `store` (11 of 43) were removed calls
  to `kotlin.jvm.internal.Intrinsics` (the compiler's null checks). `avoidCallsTo=kotlin.jvm.internal` drops them
  (`store`: 477 mutants to 398). Pitest's Kotlin filtering beyond that is Arcmutate's, a commercial plugin, which is
  not used. What is left still holds equivalent mutants:
  - the boundary of a `Char` range test (`c in 'a'..'z'`);
  - null and empty returns in lambdas;
  - void calls to argument checks a caller never fails.
- **Tests of other packages are not credited.** A package's mutants run only against that package's tests, so a mutant
  that only another package's test kills (say, one in `store` that only an `update` test reaches) counts as survived or
  not covered. Widening `targetTest` to `dev.revokt.*` was measured on `update`: it killed 632 instead of 628, left
  72 uncovered instead of 74, and took 168 s instead of 91 s. So the task keeps each package's own tests.
