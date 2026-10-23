# Dependencies

- Versions live only in `gradle/libs.versions.toml`.
- Locking is `STRICT`; every lockfile is committed (`*.lockfile`, `settings-gradle.lockfile`,
  `buildscript-gradle.lockfile`, `build-logic/**/gradle.lockfile`).
- `gradle/verification-metadata.xml` verifies checksums and PGP signatures; `gradle/verification-keyring.keys`
  holds the exported keys so verification is offline.

## Adding or updating a dependency (also how a maintainer completes a Renovate PR)

```
./gradlew resolveAndLockAll --write-locks --write-verification-metadata sha256,pgp --export-keys \
  -Prevokt.purityGate -Prevokt.native -Prevokt.ci --no-configuration-cache
```

Commit the catalog, the lockfiles, `verification-metadata.xml` and `verification-keyring.keys` together. For a new
trusted key, check the fingerprint against the upstream project's published key before committing it; the reviewer
checks it again (CONTRIBUTING §3). Renovate cannot regenerate these files on the hosted plan, so a maintainer runs the
command on the Renovate branch and pushes.

The dependency ingress files are protected paths (CODEOWNERS).

## State of signature verification

`verification-metadata.xml` declares the key servers (`keyserver.ubuntu.com`, `keys.openpgp.org`) and trusts
`-sources`/`-javadoc` jars by pattern. At the bootstrap, Gradle could download the signing keys for only a minority of
the components (the rest carry `reason="A key couldn't be downloaded"` and are verified by SHA-256 only); every
component is checksum-verified regardless. Raising PGP coverage (re-running with `--refresh-keys` from a network that
reaches the key servers, checking the JetBrains, JUnit, detekt and Kover fingerprints upstream, and trimming the
`<component>` entries that then verify by signature) is a `kind/chore` issue on the 0.1 critical path, not a silent gap.
