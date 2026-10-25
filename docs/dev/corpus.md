# Corpora

Two kinds (CONTRIBUTING §3):

- **Committed** under `corpus/`, a few MB at most, listed in `corpus/manifest.sha256`; `verifyCorpusManifest` checks it on
  every `check`. Regenerate the manifest only in a PR that admits entries: `./gradlew writeCorpusManifest` (lands with
  the first corpus entry; until then the manifest is empty).
- **Large**, in the public `revokt-corpus` repository (CT leaves, `x509-limbo`, the D7 and issuer corpora, spec §9.2),
  pinned by tag and by its manifest's SHA-256 in `gradle/corpus-pin.properties` (a protected path): the manifest is
  committed in revokt-corpus and bound here by its hash, which is how §9.2's "committed SHA-256 manifest" holds for it.
  CI's `check` jobs check the tag out into `build/corpus` (cached by the pin); `-Prevokt.corpus=build/corpus` makes
  `verifyCorpusManifest` check the manifest against the pinned hash and every file but the root's `README.md` against
  the manifest, and adds the corpus to the replay, which reads only manifest-listed paths. Its `v*` tags are immutable
  (a ruleset on the repository); a new corpus, or regenerated replay data, arrives under a new tag through a revokt PR
  that updates the pin. Locally: `git clone -c core.autocrlf=false --depth 1 --branch <tag>
  https://github.com/geota/revokt-corpus build/corpus` (`v1` has no `.gitattributes`; from `v2` the repository marks
  every file `-text`).

| Pin | Value |
|---|---|
| `revokt-corpus` tag | `v2` (`gradle/corpus-pin.properties`, with its manifest's SHA-256): `x509-limbo/` at C2SP/x509-limbo@`554528a`, and `replay/` (its goldens and records) |

### The large corpus in the replay

With `-Prevokt.corpus=<checkout>` the build passes the checkout to the tests (`ExternalCorpus` in `revokt-engine`'s
jvmTest; the tree but its `.git` is a test input, and the test heap is 4 GB). The replay then covers its inputs too:

- **Inputs**: each distinct certificate of `x509-limbo/limbo.json`'s testcases (trusted, intermediates and peer), named
  `x509-limbo/<sha256>`; one the committed corpus already holds keeps its committed name and goldens.
- **Goldens and records** for those inputs, and for the bytes an oracle reads for them, are in `replay/` of the corpus:
  `3a.tsv.gz`, `3b.tsv.gz`, `producer.tsv.gz`, `zlint.tsv.gz` (the committed files' formats, gzipped) and
  `records.jsonl`. The readers merge them with the committed ones, so D1–D3, D6, D8 and the records run over both.
- **Recording**: set `REVOKT_CORPUS` to a revokt-corpus working tree for both recorders (below), never
  `-Prevokt.corpus`, which they reject. Each golden goes to the corpus that holds its input, and the records writer
  splits the records by path; the committed files come out unchanged where the committed corpus did not change, and a
  key or record found in both corpora fails the replay. The `.gz` files are written with `gzip -9n`; the recorded ones
  came from macOS's Apple gzip, and another gzip changes their bytes (not their content), so record on macOS or accept
  a new tag. Then regenerate the corpus's manifest (its README, "Manifest"), commit and tag the corpus, and update the
  pin with the new manifest hash in one revokt PR. D8-gap entries no rule justifies get their written justification
  from the corpus's `tools/limbo-gap-justifications/`; the writer keeps it on every later run.
- **Coverage**: the ubuntu `check` jobs measure the Kover parser gate with the large corpus included; `check-os` (macOS,
  Windows) runs it over the committed replay alone, the measure §9.2's acceptance names.

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
- The large corpus's records are in its `replay/records.jsonl`. Its D8-gap entries with no zlint verdict (zcrypto cannot
  parse them) or no zlint error carry justifications written per entry from the form that fails the clause; whether
  to widen K7 or K8 for the lint-clean ones is #57.

Regenerate with `native/producer-oracle/record-goldens.sh` after `native/revokt-oracle/record-goldens.sh` (with
`REVOKT_CORPUS=<revokt-corpus working tree>` for both when the large corpus's data must change too). It runs the
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
