# data/seed

The seed job (spec §6.5, §7.2). It builds the `revokt-seed-<channel>` data artifacts through the `data-artifact`
convention plugin (build-logic). Nothing compiled here is published: the jars hold only Mozilla's data.

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
`/revokt/seed-<channel>.zip`, and `verifySeedJar<Channel>` checks the jar's layout. `smokeLoadSeed<Channel>` then starts
a `Revokt` on the jar alone, through the public API, in the sole-seed `ENFORCE` configuration.

```
./gradlew :revokt-seed:smokeLoadSeedCompat -Prevokt.seedVersion=YYYY.MM.DD   # the run's UTC date; needs the network
```

**The hosts it reaches:**

| Host | What it serves |
|---|---|
| `firefox.settings.services.mozilla.com` | `monitor/changes`, the changeset and the server root |
| `content-signature-2.cdn.mozilla.net` | the x5u chain |
| `firefox-settings-attachments.cdn.mozilla.net` | the filters |

**What the artifact holds.** The jar contains the manifest and the archive:

- `seed.json`: unsigned, our header;
- `records.json`: the canonical signed payload;
- `signature` and `x5u.pem`, as served;
- the placed filters, each bound to a signed record by its hash;
- `index.bin`, which every load rebuilds and compares.

The POM has no dependency and carries the data licence, "No copyright claimed; contains Mozilla Remote Settings data".
No Gradle module metadata is published. The engine floor lives in `seed.json`.

**Reproducibility.** One changeset gives byte-equal archives on one JDK build, since the deflate output is that JDK's
zlib's. The job therefore runs on a pinned Temurin 21 (`DataArtifactPlugin.jobLauncher`).

**In `check`, with no network.** `writeTestSeed`, `testSeedJar`, `verifyTestSeedJar` and `smokeLoadTestSeed` run the
same chain over `src/test/resources/fixture`. That fixture is a Remote Settings exchange signed under the test suite's
own keys, never a real or Mozilla key, and its filters are the committed `corpus/clubcard` ones. Regenerate it with
revokt-engine's `SeedCheckFixtureWriter`.

**Still to come (#149).** The weekly schedule and publishing under a separate Portal account that owns only the data
namespace, through the `seed-publish` environment. Also the attestation (changeset timestamp, record ids, each
attachment's SHA-256), the smoke load of the published artifact with the oldest supported engine minor, and the
sources and javadoc jars Central requires.
