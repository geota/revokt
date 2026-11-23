# Seed predicate, version 1

Predicate type: `https://github.com/geota/revokt/blob/main/docs/attestation/seed-v1.md`

This is the in-toto predicate the weekly seed job (`.github/workflows/release-seed.yml`, CONTRIBUTING §9) attests for each
`revokt-seed-<channel>-<version>.jar` it attaches to a `seed-<version>` GitHub release. The statement's subject is
that jar, by its SHA-256. The job signs it with the workflow's GitHub OIDC identity through Sigstore, alongside an SLSA
build provenance attestation of the same jar.

The predicate repeats facts the jar already holds. Most come from the signed `records.json`, Mozilla's Remote Settings
payload, so a reader can audit a seed without unpacking it. What binds a seed to Mozilla is still the content
signature, which the loader checks at every load (spec §6.5, §7.1). This predicate adds that this repository's job on
`main` built the jar from that data and smoke-loaded it.

## Fields

| Field | Type | Meaning |
|---|---|---|
| `channel` | string | `compat` or `default`, the CRLite channel (spec §7.2) |
| `version` | string | `YYYY.MM.DD`, the run's UTC date, which is also the jar's version |
| `seedFormat` | integer | `seed.json`'s `seedFormat` (spec §6.5) |
| `recordsLastModified` | integer | the signed `<ts>`: `records.json`'s `last_modified`, equal to `seed.json`'s `recordsLastModified` |
| `archive.name` | string | the archive's entry in the jar, `revokt/seed-<channel>.zip` |
| `archive.sha256` | string | the archive's SHA-256, lowercase hex |
| `records` | array | the placed records, in the archive's entry order |
| `records[].id` | string | the signed record's `id` |
| `records[].filename` | string | its `attachment.filename`, the archive's `attachments/<filename>` entry |
| `records[].size` | integer | its signed `attachment.size`, equal to the entry's size |
| `records[].sha256` | string | its signed `attachment.hash`, equal to the entry's SHA-256 |
| `jdk.vendor` | string | `Eclipse Adoptium` |
| `jdk.runtimeVersion` | string | the job's JDK `java.runtime.version`, for example `21.0.13.1+2-LTS` |
| `jdk.archive` | string | the Temurin archive the job installed |
| `jdk.archiveSha256` | string | that archive's SHA-256, checked before install |
| `runner.imageOs`, `runner.imageVersion` | string | the hosted runner image (`ImageOS`, `ImageVersion`), empty when unset |

The job (`.github/scripts/seed_predicate.sh`) fails rather than attest a seed when any of these is untrue:
- the jar holds no `revokt/seed-<channel>.zip`;
- `seed.json`'s channel is another one;
- its `recordsLastModified` is not the signed `<ts>`;
- an attachment entry matches no signed record, or more than one, or differs from its record's size or SHA-256;
- the archive places no attachment.

The jar and archive bytes are reproducible from the same changeset on the same JDK build, because the deflated entries
are that JDK's zlib's (spec §6.5). The `jdk` fields name that build.

## Use

- Verify a jar before bundling it:

  ```
  gh attestation verify revokt-seed-compat-<version>.jar --repo geota/revokt \
    --signer-workflow geota/revokt/.github/workflows/release-seed.yml --source-ref refs/heads/main \
    --predicate-type https://github.com/geota/revokt/blob/main/docs/attestation/seed-v1.md
  ```

  Without `--predicate-type`, the same command checks the provenance attestation.
- The job's monotonic freshness check (spec §7.2) verifies the last seed release's jar this way. It requires the jar's
  own `<ts>` to equal the attested `recordsLastModified`, and refuses a new seed whose `<ts>` is older.

A change to these fields that a reader would notice is version 2, under a new predicate type. Version 1 stays as it is.
