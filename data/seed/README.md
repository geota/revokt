# data/seed

The seed job (spec §6.5, §7.2). It builds the `revokt-seed-<channel>` data artifacts through the `data-artifact`
convention plugin (build-logic). Nothing compiled here ships: the jars hold only Mozilla's data.

In 0.2 a seed is a **GitHub release asset with attestations, not on Maven Central** (the maintainer's decision,
2026-11-23). An app bundles the jar itself, and `SeedSource.bundled()` finds `/revokt/seed-<channel>.zip` on its class
path. Maven publishing is a later decision.

**What the build does (#145).** `writeSeed<Channel>` fetches the current `cert-revocations` changeset from Mozilla
Remote Settings, using the engine's own client over `JdkHttpFetcher`. It verifies the changeset exactly as a live sync
verifies a whole collection:

- `monitor/changes`, then the changeset;
- the content signature over the x5u chain to Mozilla's pinned root, checked at the run's clock;
- the schema and the placement;
- the server root's attachment base;
- each placed attachment, by size and SHA-256.

`buildSeed` writes the archive. The job then loads it once from memory under the same pins, and only after that writes
`build/seed/revokt-seed-<channel>.zip`, through a temporary file. `seedJar<Channel>` packs it stored as
`/revokt/seed-<channel>.zip` in `build/seed/revokt-seed-<channel>-<version>.jar`, and `verifySeedJar<Channel>` checks
the jar's layout. `smokeLoadSeed<Channel>` then starts
a `Revokt` on the jar alone, through the public builder (plus the engine seam that records the generation it activates), in the sole-seed `ENFORCE` configuration.

```
./gradlew :revokt-seed:smokeLoadSeedCompat -Prevokt.seedVersion=YYYY.MM.DD   # the run's UTC date; needs the network
```

**The hosts it reaches:**

| Host | What it serves |
|---|---|
| `firefox.settings.services.mozilla.com` | `monitor/changes`, the changeset and the server root |
| `content-signature-2.cdn.mozilla.net` | the x5u chain |
| `firefox-settings-attachments.cdn.mozilla.net` | the filters |

**What the artifact holds.** The jar contains the manifest, `META-INF/LICENSE-DATA` and the archive:

- `seed.json`: unsigned, our header;
- `records.json`: the canonical signed payload;
- `signature` and `x5u.pem`, as served;
- the placed filters, each bound to a signed record by its hash;
- `index.bin`, which every load rebuilds and compares.

The jar has no POM. The data licence, "No copyright claimed; contains Mozilla Remote Settings data", is the manifest's
`Revokt-Data-License` and the text of `META-INF/LICENSE-DATA`. The engine floor lives in `seed.json`.

**Reproducibility.** One changeset gives byte-equal archives on the same Temurin 21 build, since the deflate output is
that JDK's zlib's. The build asks for Temurin 21 (`DataArtifactPlugin.jobLauncher`), whatever 21.0.x is installed. The
weekly job pins the exact build: it installs Temurin's tarball, checked against a SHA-256 in the workflow, turns Gradle's
toolchain detection off, and records the build in the attestation.

**In `check`, with no network.** `writeTestSeed`, `testSeedJar`, `verifyTestSeedJar` and `smokeLoadTestSeed` run the
same chain over `src/test/resources/fixture`. That fixture is a Remote Settings exchange signed under the test suite's
own keys, never a real or Mozilla key, and its filters are the committed `corpus/clubcard` ones. Regenerate it with
revokt-engine's `SeedCheckFixtureWriter`.

**The weekly job** (`.github/workflows/release-seed.yml`, CONTRIBUTING §9). It runs every Monday at 05:41 UTC and on
dispatch. It runs both channels' `smokeLoadSeed<Channel>` and `smokeLoadOldestSeed<Channel>` with the run's UTC date.
The second smoke-loads each jar with the oldest supported engine minor. `revokt.oldestSupportedVersion` in
`gradle.properties` names that minor's release, and the smoke sources are then compiled and run against
`dev.revokt:revokt-jsse:<that version>` from Maven Central, under dependency verification, with the jar alone. While it
is empty, nothing is released, so the oldest supported minor is the run's own commit and the task is
`smokeLoadSeed<Channel>`. The job passes the newest `vX.Y.Z` tag as `-Prevokt.newestRelease`, and
`checkOldestSupportedVersion` fails the run when a release exists that the property does not name, or names a minor no
longer supported. A named release that does not resolve or verify fails the run too; neither falls back to the run's
commit.

```
./gradlew :revokt-seed:smokeLoadOldestSeedCompat -Prevokt.newestRelease= -Prevokt.seedVersion=YYYY.MM.DD   # empty: no release yet
```

The job then refuses a seed whose signed `<ts>` is older than the last seed release's for that channel. That release's
jar must verify by its attestation, and again by Mozilla's content signature. `seedTimestamp<Channel>` checks only what
does not depend on the seed format, as Firefox re-verifies its local data: `seed.json`'s channel, the x5u chain inside
the archive to Mozilla's pins, the signature over `records.json`, the canonical payload, and the x5u validity at its
signed `<ts>`. It needs no network and writes that `<ts>`. The verified `<ts>`, the jar's `records.json` `<ts>` and the
attested one must be equal. When every channel's `<ts>` equals the last release's, nothing is published. A `seed-*` tag
with no published seed release fails the run.

To run the re-verification by hand, give the jar's absolute path. The `<ts>` lands in
`build/seed-timestamp/revokt-seed-compat.ts`, or in `-Prevokt.seedTimestampOut=<file>`:

```
./gradlew :revokt-seed:seedTimestampCompat -Prevokt.seedJar=/abs/path/revokt-seed-compat-YYYY.MM.DD.jar
```

With publishing on (the `SEED_PUBLISH_ENABLED` repository variable and the `seed-publish` environment), the job then:
1. attests each jar: SLSA provenance and the seed predicate, [seed-v1](../../docs/attestation/seed-v1.md). The
   predicate holds the `<ts>`, the placed record ids, each attachment's size and SHA-256, and the JDK build;
2. creates the `seed-YYYY.MM.DD` release as a draft, holding both jars and the `.sigstore.json` bundles (the provenance
   also as `.intoto.jsonl`);
3. reads the assets back and checks them: their SHA-256, and the attestations from the API and from the bundles;
4. publishes the release and checks that its tag names the run's commit.

The scripts it runs are `.github/scripts/seed_predicate.sh`, `seed_floor.sh` and `seed_verify.sh`, which
`test_seed_scripts.py` tests.

**Using a seed.** Download the jar of your channel from the newest `seed-*` release, verify it, and bundle it. `SeedSource.bundled()`
then finds `/revokt/seed-<channel>.zip` on the class path:

```
gh attestation verify revokt-seed-compat-<version>.jar --repo geota/revokt \
  --signer-workflow geota/revokt/.github/workflows/release-seed.yml --source-ref refs/heads/main
```

Add `--predicate-type https://github.com/geota/revokt/blob/main/docs/attestation/seed-v1.md` to check the seed
predicate instead of the provenance.
