# Corpora

Two kinds (CONTRIBUTING §3):

- **Committed** under `corpus/`, a few MB at most, listed in `corpus/manifest.sha256`; `verifyCorpusManifest` checks it on
  every `check`. Regenerate the manifest only in a PR that admits entries: `./gradlew writeCorpusManifest` (lands with
  the first corpus entry; until then the manifest is empty).
- **Large**, in the public `revokt-corpus` repository (CT leaves, `x509-limbo`, the D7 and issuer corpora, spec §9.2),
  pinned here by tag and checked out by CI into `build/corpus`; `-Prevokt.corpus=build/corpus` makes
  `verifyCorpusManifest` check it too and the replay task read it.

| Pin | Value |
|---|---|
| `revokt-corpus` tag | none yet (0.1 "parser" issue) |

## Admission

Every entry gets a record (spec §9.2 "Corpus record schema"): `{sha256, path, revokt: {outcome, rawSerial, spkiSha256,
scts[]}, oracles: [{id, version, outcome, fields | unavailable}], class, justification, added}`. Goldens for oracles 3a,
3b and 4 are computed by the nightly native job at admission so the PR replay needs no Rust or Go.

## Clubcard corpus (`corpus/clubcard/`)

The recorded form of the §9 end-to-end oracle for the clubcard port: `(filter, issuer, serial, scts) → status`
goldens produced by `clubcard-crlite 0.6.2` through `native/revokt-oracle`, replayed by
`ClubcardCorpusReplayTest` with zero tolerance. One directory per entry with the filter bytes (`*.filter*`, every
encoding of the same filter), `goldens.tsv` and `record.json`:

```
goldens.tsv   issuer_spki_hash_hex \t serial_hex \t log_id_hex:timestamp[,…] \t Good|Revoked|NotCovered|NotEnrolled
record.json   {entry, filters: [{path, sha256, source}], queries: {generator, seed, count}, oracle: {crate, version,
               tool, commit}, added}
```

| Entry | Filters | Goldens | Source |
|---|---|---|---|
| `synthetic` | `synthetic.v3.filter`, `synthetic.v4.filter` | 2171 | `revokt-oracle build-synthetic`: 5 issuers × 2^12 serials, one inverted block, one empty block, coverage edges |
| `compat-delta` | `20261021-1-compat.filter.delta` (v3, as served), `.v4` (oracle transcode) | 1500 | Mozilla Remote Settings `cert-revocations`, attachment hash in the record |
| `compat-full` | `20261017-1-compat.filter` (v3, as served) | 2000 | same collection; 1.5 MB, the one large committed fixture |

Regenerating (a maintainer, after an oracle or upstream change; the nightly native job will take this over):

```
cargo build --release --manifest-path native/Cargo.toml -p revokt-oracle
native/target/release/revokt-oracle build-synthetic corpus/clubcard/synthetic
native/target/release/revokt-oracle gen-queries <filter> <count> <seed> queries.tsv
native/target/release/revokt-oracle goldens <filter> queries.tsv corpus/clubcard/<entry>/goldens.tsv
./gradlew writeCorpusManifest
```

The real filters are Mozilla's published data artifacts (not code; `.gitattributes` marks them binary). A new entry is
admitted in its own PR with the record filled in; goldens are never edited by hand.
