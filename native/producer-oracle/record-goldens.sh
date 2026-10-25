#!/bin/sh
# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
#
# Records the oracle-4 goldens of the D8 replay (spec §9.2, #11): every distinct canon(input) of ProducerCorpus,
# run through the producer pinned in go.mod, then the D8-gap baseline. Needs Go and the matrix JDKs; the PR tier replays the committed goldens and
# needs neither. Run from the repository root:  sh native/producer-oracle/record-goldens.sh
# REVOKT_RECORD_JDKS lists the JDKs to record on, by default the CI matrix of .github/workflows/ci.yml ("17 21 25 27");
# each must be installed. Any arguments are passed to Gradle, for example
# -Porg.gradle.java.installations.paths=<comma-separated JDK homes>.
set -eu
root=$(pwd)
out="$root/revokt-engine/src/jvmTest/resources/dev/revokt/engine/parse/producer/goldens.tsv"
work=$(mktemp -d)
trap 'rm -rf "${work:?}"' EXIT
( cd native/producer-oracle && go build -o "$work/producer-oracle" . )
# One pass per matrix JDK (the bytes revokt reads depend on oracle 1's version), merged.
jdks=${REVOKT_RECORD_JDKS:-17 21 25 27}
case $jdks in *[!0-9\ ]*) echo "REVOKT_RECORD_JDKS must list JDK feature versions: $jdks" >&2; exit 1 ;; esac
for jdk in $jdks; do
  ./gradlew -q :revokt-engine:jvmTest --tests 'dev.revokt.engine.parse.producer.ProducerGoldensWriterTest' \
    -Drevokt.writeProducerInputs="$work/inputs-$jdk.tsv" -Prevokt.testJdk="$jdk" --rerun "$@" </dev/null
done
LC_ALL=C sort -u "$work"/inputs-*.tsv > "$work/inputs.tsv"
cut -f2 "$work/inputs.tsv" > "$work/b64.txt"
echo '##' >> "$work/b64.txt"
"$work/producer-oracle" < "$work/b64.txt" | grep -v '^##$' > "$work/verdicts.txt"
[ "$(wc -l < "$work/inputs.tsv")" -eq "$(wc -l < "$work/verdicts.txt")" ] || { echo "verdict count mismatch" >&2; exit 1; }
{
  echo "# Oracle-4 verdicts (mozilla/crlite go/types, pinned in native/producer-oracle/go.mod) for canon(input) of ProducerCorpus."
  echo "# sha256 of canon <TAB> OK <serial-hex> <spki-sha256-hex> <ct|lax|zc> | REJECT <error>. Regenerate, never edit."
  cut -f1 "$work/inputs.tsv" | paste - "$work/verdicts.txt" | LC_ALL=C sort
} > "$out"
echo "wrote $(grep -vc '^#' "$out") goldens to $out"
baseline="$root/revokt-engine/src/jvmTest/resources/dev/revokt/engine/parse/producer/gap-baseline.tsv"
./gradlew -q :revokt-engine:jvmTest --tests 'dev.revokt.engine.parse.producer.ProducerD8Test.the D8 gap equals the recorded baseline' \
  -Drevokt.writeGapBaseline="$baseline" --rerun "$@" </dev/null
echo "wrote $(grep -vc '^#' "$baseline") gap entries to $baseline"
