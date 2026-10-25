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
scts[]}, oracles: [{id, version, outcome, fields | unavailable}], class, divergence?, keyability: {parser, clause, zlint}?,
justification, added}`; the spec's schema is authoritative. Goldens for oracles 3a,
3b and 4 are computed by the nightly native job at admission so the PR replay needs no Rust or Go.

## Parser replay records (`revokt-engine/src/jvmTest/resources/dev/revokt/engine/parse/records.jsonl`)

The records of the parser replay corpus (`ProducerCorpus`), one JSON object per line, sorted by path and class. An input
has one record per class it is admitted under. `RecordsTest` recomputes every class from the replay on the test JDK
and requires the committed records to equal it, field for field:

| Class | Admitted for | Depends on a platform oracle |
|---|---|---|
| `D1_DOM` | a platform-accepted input outside the D1 domain: oracle 4 rejects `canon(encoded)` or keys other bytes, or a rule (`[0]`, no platform canon) | yes |
| `D2_REENCODE_ALLOW` | a parsed input whose SPKI oracle 1 re-encodes under the allow-list's rule | yes |
| `D3_DIVERGENCE` | a parsed input in a 3a divergence class (`3A_HEADER_LAX`, `3A_TBS_LAX`, `DUPLICATE_EXTENSION`) | no |
| `KEYABILITY_GAP` | an end-entity input in the D1 domain whose read parses outside the keyability profile (the D8 gap), when it has no other class | yes |

- **`revokt`** is revokt's parse of the input bytes `b`; where the bytes read differ, the classes are decided on those.
- **Platform oracles** have one entry per version: oracle 1 per matrix JDK (its feature release), oracle 2 per Conscrypt
  release. Each has `read`, the SHA-256 of the bytes revokt reads where they differ from the input, and, on an
  oracle-dependent record, `holds`: whether the class holds on that oracle version. A record counts on a run where an
  entry of that run's versions holds. Oracles 3a and 3b carry their golden's outcome for the input, and oracle 4 its
  outcome for `canon` of the input, or of the bytes read (`read: …`) where the input has none. The spec's `fields |
  unavailable` are not recorded: the replay fails on any platform getter that throws on the committed corpus, so none is
  unavailable there; they arrive with the secondary corpus (#15), where the 0.1 % rate applies.
- **`keyability`** (`parser`, `clause`, `zlint` as `<errors> <fatals>` or `unparseable`/`panic`) rides on every record of a
  D8-gap input, whatever its class.
- **Justifications**: a rule-based one (the producer's error, the D1-dom rule, the divergence class, the re-encoding rule,
  the zlint errors) is compared too, so a changed reason fails. A record whose rule yields none (a D8-gap entry with no
  zlint error, a release blocker under §9.2) carries one written by hand.
- `D7_LENIENCY`, `FUZZ_FINDING` and `ISSUER_CORPUS` records arrive with their corpora (#14, #15).

Regenerate with `native/producer-oracle/record-goldens.sh` after `native/revokt-oracle/record-goldens.sh`. It runs the
writer once per JDK in `REVOKT_RECORD_JDKS` (by default the JDKs of `gradle/oracle-matrix.properties`) and once on the
matrix's previous Conscrypt (`jvmTestConscryptPrevious`), merging each run's view: `added` dates and hand-written
justifications are kept, rule-based justifications are recomputed, entries of versions that have left the matrix are
pruned, and a new D8-gap entry with no zlint error gets none, so the replay fails until one is written by hand.

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
| `compat-full` | `20261017-1-compat.filter` (v3, as served) | 2048 | same collection; 1.5 MB, the one large committed fixture; the first 48 queries are its 24 exception serials and a one-bit sibling of each |

Regenerating (a maintainer, after an oracle or upstream change; the nightly native job will take this over):

```
cargo build --release --manifest-path native/Cargo.toml -p revokt-oracle
native/target/release/revokt-oracle build-synthetic corpus/clubcard/synthetic
native/target/release/revokt-oracle gen-queries <filter> <count> <seed> queries.tsv
native/target/release/revokt-oracle goldens <filter> queries.tsv corpus/clubcard/<entry>/goldens.tsv
./gradlew writeCorpusManifest
```

Reproducibility. `gen-queries` is deterministic for a seed (coverage is sorted before sampling; it is a `HashMap`
upstream), so `goldens` over a real filter and its recorded seed reproduces the committed file byte for byte.
`build-synthetic` is not: `clubcard`'s builder draws from `thread_rng`, so a rebuild yields a different filter (its
queries are the same). Check the committed synthetic pair by replaying it, never by rebuilding:

```
cut -f1-3 corpus/clubcard/synthetic/goldens.tsv > q.tsv
native/target/release/revokt-oracle goldens corpus/clubcard/synthetic/synthetic.v3.filter q.tsv g.tsv
cmp g.tsv corpus/clubcard/synthetic/goldens.tsv
```

Coverage gaps, stated so they are not mistaken for checks: `compat-delta`, the only real v4 data, has no `Revoked`
golden and no inverted block (982 of its 1030 blocks have `approx_filter_m == 0`); the v4 membership and inverted
paths are covered by `synthetic.v4.filter` and by the structural-equality test, which proves the v4 transcode decodes
to the same filter as the v3 original. A real delta with inverted blocks is a later admission.

The real filters are Mozilla's published data artifacts (not code; `.gitattributes` marks them binary). A new entry is
admitted in its own PR with the record filled in; goldens are never edited by hand.
