<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# corpus/

Small committed fixture corpora (a few MB at most), each listed in `manifest.sha256`, which `verifyCorpusManifest`
checks on every `./gradlew check`. The large corpus (CT leaves, `x509-limbo`, the D7 and issuer corpora, spec §9.2) is
the public `revokt-corpus` repository, pinned by tag in `docs/dev/corpus.md` and checked out by CI into `build/corpus`.

Admission rules and the record schema are in `docs/dev/corpus.md`. Corpus files are data: `.gitattributes` marks them
binary so they hash identically on every OS.
