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

`-Prevokt.native` includes `revokt-engine-upki`, which does not exist until the 0.2 upki issue; until then the command
fails at settings evaluation with it, so drop that flag.

Commit the catalog, the lockfiles, `verification-metadata.xml` and `verification-keyring.keys` together. For a new
trusted key, check the fingerprint against the upstream project's published key before committing it; the reviewer
checks it again (CONTRIBUTING §3). Renovate cannot regenerate these files on the hosted plan, so a maintainer runs the
command on the Renovate branch and pushes.

The dependency ingress files are protected paths (CODEOWNERS).

## Keys added after the bootstrap

| Key | Owner (key server uid) | Checked against | Added |
|---|---|---|---|
| `D233B6C6E7EDC0866D486C166054D87C226DFDC2` | Code Intelligence GmbH - Signing `<fuzzing@code-intelligence.com>` (`com.code-intelligence`, Jazzer) | the `.asc` signatures on Maven Central for `jazzer-junit` 0.30.0 carry this key id; uid on `keyserver.ubuntu.com` | 2026-10-22, clubcard port PR |
| `3EC80CAD1A3D50AFBBEFC136C2B98E64C61147AC` | Norbert Fabritius `<nfabritius@google.com>` (`org.conscrypt:conscrypt-openjdk-uber` 2.8.0, oracle 2; trusted for that version only) | the `.asc` signatures on Maven Central for 2.8.0 carry this key; its uid on `keyserver.ubuntu.com` names the GitHub user `inorick` (Norbert Fabritius), who published the 2.8.0 release on `github.com/google/conscrypt` and merges its upstream PRs | 2026-10-25, #13 |

## State of signature verification

`verification-metadata.xml` declares the key servers (`keyserver.ubuntu.com`, `keys.openpgp.org`) and trusts
`-sources`/`-javadoc` jars by pattern. At the bootstrap, Gradle could download the signing keys for only a minority of
the components (the rest carry `reason="A key couldn't be downloaded"` and are verified by SHA-256 only); every
component is checksum-verified regardless. Raising PGP coverage (re-running with `--refresh-keys` from a network that
reaches the key servers, checking the JetBrains, JUnit, detekt and Kover fingerprints upstream, and trimming the
`<component>` entries that then verify by signature) is a `kind/chore` issue on the 0.1 critical path, not a silent gap.
