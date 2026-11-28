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
./gradlew resolveAndLockAll --write-verification-metadata sha256 \
  -Prevokt.purityGate -Prevokt.native -Prevokt.ci --no-configuration-cache
```

`-Prevokt.native` includes `revokt-engine-upki`, which does not exist until the 0.2 upki issue; until then the command
fails at settings evaluation with it, so drop that flag.

The first command adds trusted keys, and checksums only for the artifacts it cannot verify by signature. The second
adds a SHA-256 beside every signature: when the `.asc` file cannot be fetched (Maven Central's rate limit), Gradle falls
back to the checksum, and an artifact with neither fails verification (#275). Gradle's writer drops the comment in
`<ignored-keys>` and moves the block; put it back. On macOS the second command also adds a checksum for that host's
`kotlin-native-prebuilt` archive; drop it, as the other hosts' archives are verified by signature only.

Commit the catalog, the lockfiles, `verification-metadata.xml` and `verification-keyring.keys` together. For a new
trusted key, check the fingerprint against the upstream project's published key before committing it; the reviewer
checks it again (CONTRIBUTING §3). Renovate cannot regenerate these files on the hosted plan, so a maintainer runs the
command on the Renovate branch and pushes.

The dependency ingress files are protected paths (CODEOWNERS).

## The seed job's oldest supported release

`revokt.oldestSupportedVersion` in `gradle.properties` (CONTRIBUTING §9) adds a `smokeOldest` source set to
`:revokt-seed` that depends on `dev.revokt:revokt-jsse:<that version>` from Maven Central, and so on its revokt-engine and
revokt-clubcard and their dependencies. The PR that sets or bumps it runs the two commands above with the property set:
they lock the `smokeOldest*` configurations and add a SHA-256 for each `dev.revokt` artifact of that version. Once the
release key exists, the first command also adds it as a trusted key for the `dev.revokt` group; check its fingerprint
against `SECURITY.md` and `MAINTAINERS.md` before committing it. Nothing is trusted by pattern for `dev.revokt`, so a
version with no entries fails the weekly job. While the property is empty the source set does not exist and nothing is
resolved.

## Keys added after the bootstrap

| Key | Owner (key server uid) | Checked against | Added |
|---|---|---|---|
| `D233B6C6E7EDC0866D486C166054D87C226DFDC2` | Code Intelligence GmbH - Signing `<fuzzing@code-intelligence.com>` (`com.code-intelligence`, Jazzer) | the `.asc` signatures on Maven Central for `jazzer-junit` 0.30.0 carry this key id; uid on `keyserver.ubuntu.com` | 2026-10-22, clubcard port PR |
| `18CD85CBC5C1DB1684C5E59FA8E3B39F19E1CCE7` | Henry Coles `<henry.coles@googlemail.com>` (`org.pitest`: `pitest`, `pitest-entry`, `pitest-junit5-plugin` and their parent POM `pitest-parent` only) | `gpg --verify` of the `.asc` signatures on Maven Central for pitest and pitest-entry 1.30.2, pitest-junit5-plugin 1.2.3 and the pitest-parent 1.30.2 POM (re-checked in the #258 review); uid on `keyserver.ubuntu.com`; the coordinator re-checked it | 2026-11-19, #215 |
| `3EC80CAD1A3D50AFBBEFC136C2B98E64C61147AC` | uid "Norbert Fabritius `<nfabritius@google.com>`" (self-asserted on `keyserver.ubuntu.com`, created 2026-09-23; not on `keys.openpgp.org`) for `org.conscrypt:conscrypt-openjdk-uber` 2.8.0, oracle 2; trusted for that version only | Conscrypt publishes no project key (its `release/README.md` has each releaser sign with a personal key), so CONTRIBUTING §3's check against an upstream-published key cannot be met literally. The evidence: the Maven Central `.asc` signatures for 2.8.0 carry this key's fingerprint, and the GitHub user `inorick` (Norbert Fabritius), who merges upstream PRs, published the 2.8.0 release on `github.com/google/conscrypt`. The uid's tie to that person is not otherwise verified (`inorick` lists no GPG key; the release commit is GitHub-verified by web-flow, not by this key). 2.7.0 is signed by a different key, `49CF4E3B2996BE658A57DD39655CCC51B9BD2C38`, for #13's second part | 2026-10-25, #13 |
| `49CF4E3B2996BE658A57DD39655CCC51B9BD2C38` | uid "Juerg Wullschleger (Key for signing maven artifacts) `<juerg@google.com>`" (self-asserted on `keyserver.ubuntu.com`, created 2026-05-27; `keys.openpgp.org` serves the key without a uid, so the email is unverified there) for `org.conscrypt:conscrypt-openjdk-uber` 2.7.0, the matrix's previous Conscrypt minor; trusted for that version only | As for 2.8.0, upstream publishes no project key. The evidence: the Maven Central `.asc` signatures for 2.7.0 carry this key's fingerprint (signed 2026-08-31), and the GitHub user `juergw` (Jürg Wullschleger), who made 74 of the last 100 upstream commits, published the 2.7.0 release on `github.com/google/conscrypt` that day. The uid's tie to that person is not otherwise verified | 2026-10-25, #13 |
| `F3FF33E96F18AA62DD580F9651FBF517CE6D6B80` | Gradle Inc. `<maven-publishing@gradle.com>`: the signing subkey of primary key `EA96F38569C044AAEF7FCF732887F479B0B9771A`, created 2026-08-14 (`org.gradle.kotlin:gradle-kotlin-dsl-plugins` 6.7.13 only, the `kotlin-dsl` plugin Gradle 9.9.2 applies) | both fingerprints in `KEYS.md` on `github.com/gradle/gradle`, which names the subkey as the one to trust and lists the previous key `1BD97A6A154E7810EE0BC832E2F38302C8075E3D` as revoked (superseded) on 2026-08-08; the same primary key and uid on `keyserver.ubuntu.com`; `gpg --verify` of the `.asc` signatures on the Plugin Portal for the 6.7.13 jar, `.module` and `.pom`, and of `gradle-9.9.2-bin.zip.asc` | 2026-11-26, Gradle 9.9.2 bump |

## State of signature verification

`verification-metadata.xml` declares the key servers (`keyserver.ubuntu.com`, `keys.openpgp.org`) and trusts
`-sources`/`-javadoc` jars by pattern. At the bootstrap, Gradle could download the signing keys for only a minority of
the components (the rest carry `reason="A key couldn't be downloaded"` and are verified by SHA-256 only); every
component is checksum-verified regardless. Raising PGP coverage (re-running with `--refresh-keys` from a network that
reaches the key servers and checking the JetBrains, JUnit, detekt and Kover fingerprints upstream) is a `kind/chore`
issue on the 0.1 critical path, not a silent gap. The checksums stay beside the signatures, as the fallback when a
signature file cannot be fetched.
