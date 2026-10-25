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
| `3EC80CAD1A3D50AFBBEFC136C2B98E64C61147AC` | uid "Norbert Fabritius `<nfabritius@google.com>`" (self-asserted on `keyserver.ubuntu.com`, created 2026-09-23; not on `keys.openpgp.org`) for `org.conscrypt:conscrypt-openjdk-uber` 2.8.0, oracle 2; trusted for that version only | Conscrypt publishes no project key (its `release/README.md` has each releaser sign with a personal key), so CONTRIBUTING §3's check against an upstream-published key cannot be met literally. The evidence: the Maven Central `.asc` signatures for 2.8.0 carry this key's fingerprint, and the GitHub user `inorick` (Norbert Fabritius), who merges upstream PRs, published the 2.8.0 release on `github.com/google/conscrypt`. The uid's tie to that person is not otherwise verified (`inorick` lists no GPG key; the release commit is GitHub-verified by web-flow, not by this key). 2.7.0 is signed by a different key, `49CF4E3B2996BE658A57DD39655CCC51B9BD2C38`, for #13's second part | 2026-10-25, #13 |
| `49CF4E3B2996BE658A57DD39655CCC51B9BD2C38` | uid "Juerg Wullschleger (Key for signing maven artifacts) `<juerg@google.com>`" (self-asserted on `keyserver.ubuntu.com`, created 2026-05-27; `keys.openpgp.org` serves the key without a uid, so the email is unverified there) for `org.conscrypt:conscrypt-openjdk-uber` 2.7.0, the matrix's previous Conscrypt minor; trusted for that version only | As for 2.8.0, upstream publishes no project key. The evidence: the Maven Central `.asc` signatures for 2.7.0 carry this key's fingerprint (signed 2026-08-31), and the GitHub user `juergw` (Jürg Wullschleger), who made 74 of the last 100 upstream commits, published the 2.7.0 release on `github.com/google/conscrypt` that day. The uid's tie to that person is not otherwise verified | 2026-10-25, #13 |

## State of signature verification

`verification-metadata.xml` declares the key servers (`keyserver.ubuntu.com`, `keys.openpgp.org`) and trusts
`-sources`/`-javadoc` jars by pattern. At the bootstrap, Gradle could download the signing keys for only a minority of
the components (the rest carry `reason="A key couldn't be downloaded"` and are verified by SHA-256 only); every
component is checksum-verified regardless. Raising PGP coverage (re-running with `--refresh-keys` from a network that
reaches the key servers, checking the JetBrains, JUnit, detekt and Kover fingerprints upstream, and trimming the
`<component>` entries that then verify by signature) is a `kind/chore` issue on the 0.1 critical path, not a silent gap.
