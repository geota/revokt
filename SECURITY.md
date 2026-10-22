<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Security policy

## Reporting

Use GitHub's private vulnerability reporting on this repository (Security → Report a vulnerability). Do not open a
public issue. You will get an acknowledgement within 7 days and a status update at least every 14 days.

## Disclosure

Coordinated disclosure with a **90-day** window from the first report (spec §14), shorter by agreement when a fix
ships earlier, longer only if a dependency upstream needs it and you agree. Fixes are developed in an advisory's
temporary private fork and land as one squash commit with the advisory published at the same time (CONTRIBUTING §8).

## Scope

The published artifacts (`dev.revokt:*`) and the data artifacts (`revokt-seed-*`). Out of scope until they ship:
anything marked a later milestone in `docs/spec/revokt-spec.md` §11. The spec's §10 lists the known residual risks;
a report that restates one of them is still welcome if it shows a new consequence.

## Verifying what you download

Every release attaches, to the GitHub release, the jars, `.asc` PGP signatures, `.sigstore.json` bundles and SLSA
provenance (`.intoto.jsonl`); Maven Central carries the same jars and `.asc` files. Verify with:

```
gh attestation verify revokt-engine-jvm-<version>.jar --repo geota/revokt
gpg --verify revokt-engine-jvm-<version>.jar.asc        # fingerprint published here once a release key exists
```

Gradle consumers add the key to `gradle/verification-metadata.xml` (`<trusted-key id="…" group="dev.revokt"/>`).

No release key exists yet; this section is updated in the PR that creates it (CONTRIBUTING §9).
