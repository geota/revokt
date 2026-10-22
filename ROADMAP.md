<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Roadmap

**Current focus**: 0.1 bootstrap, then the `revokt-clubcard` port with recorded oracle goldens (CONTRIBUTING §2).

Scope per milestone is the spec's §11 table; `docs/dev/status.md` (from `./gradlew specStatus`) is the measured
state. Order inside a milestone is the 0.1 critical path in CONTRIBUTING §2 and each issue's dependency list.

| Milestone | Scope (spec §11) | State |
|---|---|---|
| 0.1 | engine scaffold, `RevocationEngine`, `Rule` model, parser with the §9.2 oracle, clubcard port, JSON, index reader, harness scaffolding | in progress |
| 0.2 | minimal `Revokt`, walker + fuzzer gate, Remote Settings + content signatures, updater in memory, upki cross-engine suite | not started |
| 0.3 | store, mirror, bindings, Android matrix, lifecycle, WorkManager, `revokt-testing` | not started |
| 0.4 → 1.0 | M2: preload, OneCRL, denylist, CRLSet | not started |

A maintainer edits the "Current focus" line; everything else is derived.
