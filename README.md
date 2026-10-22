<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# revokt

revokt, a Kotlin TLS revocation library, is not affiliated with Revokt (revokt.com).

A pure-Kotlin CRLite engine with JVM and Android bindings: it consumes Mozilla's signed CRLite filters and answers
"is this certificate revoked?" for every TLS handshake, layered on the platform verifier, with no per-connection
network lookups. It grows into a Web PKI client-policy library (OneCRL, CRLSets, CT, distrust, Merkle Tree
Certificates) by the milestones in `docs/spec/revokt-spec.md` §11.

**Status**: pre-release, milestone 0.1 (see `ROADMAP.md` and `docs/dev/status.md`). Nothing is published yet.

## Reading order

1. `docs/spec/revokt-spec.md`: the normative design.
2. `CONTRIBUTING.md`: how work is picked up, checked in and gated; `AGENTS.md` for AI-assisted work.
3. `docs/adr/`: the decisions behind the spec and the process.

## Building

Gradle runs on JDK 21 (`JAVA_HOME`), the library targets JDK 11 bytecode and Android API 26+.

```
./gradlew check                 # the full local gate: JDK-only, offline
./gradlew check -Prevokt.ci     # plus consumers, purity compile (and Android modules from 0.3)
```

## Licence

Apache-2.0, except `revokt-clubcard`'s port package, a translation of Mozilla's `clubcard` crates under MPL-2.0
(see `NOTICE`, `LICENSES/`). This project follows the REUSE specification.
