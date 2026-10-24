#!/bin/sh
# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
#
# Records the oracle-4 goldens of the D8 replay (spec §9.2, #11): every distinct canon(input) of ProducerCorpus,
# run through the producer pinned in go.mod, then the D8-gap baseline. Needs Go and JDK 21; the PR tier replays the committed goldens and
# needs neither. Run from the repository root:  sh native/producer-oracle/record-goldens.sh
set -eu
root=$(pwd)
out="$root/revokt-engine/src/jvmTest/resources/dev/revokt/engine/parse/producer/goldens.tsv"
work=$(mktemp -d)
trap 'rm -rf "${work:?}"' EXIT
( cd native/producer-oracle && go build -o "$work/producer-oracle" . )
./gradlew -q :revokt-engine:jvmTest --tests 'dev.revokt.engine.parse.producer.ProducerGoldensWriterTest' \
  -Drevokt.writeProducerInputs="$work/inputs.tsv" --rerun </dev/null
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
  -Drevokt.writeGapBaseline="$baseline" --rerun </dev/null
echo "wrote $(grep -vc '^#' "$baseline") gap entries to $baseline"
