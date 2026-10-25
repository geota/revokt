#!/bin/sh
# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
#
# Records the oracle-4 goldens of the D8 replay (spec §9.2, #11): every distinct canon(input) of ProducerCorpus,
# run through the producer pinned in go.mod and through zlint (native/zlint-oracle, its own pin), then the corpus
# records. Needs Go and the matrix JDKs; the PR tier replays the committed goldens and
# needs neither. Run from the repository root:  sh native/producer-oracle/record-goldens.sh
# REVOKT_RECORD_JDKS lists the JDKs to record on, by default the matrix of gradle/oracle-matrix.properties; each must
# be installed. The matrix's previous Conscrypt gets one more pass (jvmTestConscryptPrevious). Any arguments are passed
# to Gradle, for example
# -Porg.gradle.java.installations.paths=<comma-separated JDK homes>.
set -eu
root=$(pwd)
out="$root/revokt-engine/src/jvmTest/resources/dev/revokt/engine/parse/producer/goldens.tsv"
work=$(mktemp -d)
trap 'rm -rf "${work:?}"' EXIT
( cd native/producer-oracle && go build -o "$work/producer-oracle" . )
( cd native/zlint-oracle && go build -o "$work/zlint-oracle" . )
# One pass per matrix JDK (the bytes revokt reads depend on oracle 1's version), merged.
jdks=${REVOKT_RECORD_JDKS:-$(sed -n 's/^jdk[[:space:]]*[=:][[:space:]]*//p' gradle/oracle-matrix.properties | tr ',' ' ')}
[ -n "$(printf '%s' "$jdks" | tr -d ' ')" ] || { echo "no JDKs to record on (REVOKT_RECORD_JDKS, gradle/oracle-matrix.properties)" >&2; exit 1; }
case $jdks in *[!0-9\ ]*) echo "REVOKT_RECORD_JDKS must list JDK feature versions: $jdks" >&2; exit 1 ;; esac
for jdk in $jdks; do
  ./gradlew -q :revokt-engine:jvmTest --tests 'dev.revokt.engine.parse.producer.ProducerGoldensWriterTest' \
    -Drevokt.writeProducerInputs="$work/inputs-$jdk.tsv" -Prevokt.testJdk="$jdk" --rerun "$@" </dev/null
done
./gradlew -q :revokt-engine:jvmTestConscryptPrevious --tests 'dev.revokt.engine.parse.producer.ProducerGoldensWriterTest' \
  -Drevokt.writeProducerInputs="$work/inputs-conscrypt-previous.tsv" --rerun "$@" </dev/null
LC_ALL=C sort -u "$work"/inputs-*.tsv > "$work/inputs.tsv"
cut -f2 "$work/inputs.tsv" > "$work/b64.txt"
echo '##' >> "$work/b64.txt"
# Both oracles run with GODEBUG unset: a GODEBUG setting would change zcrypto's parsing (the producer's zc path, zlint).
env -u GODEBUG "$work/producer-oracle" < "$work/b64.txt" | grep -v '^##$' > "$work/verdicts.txt"
[ "$(wc -l < "$work/inputs.tsv")" -eq "$(wc -l < "$work/verdicts.txt")" ] || { echo "verdict count mismatch" >&2; exit 1; }
env -u GODEBUG "$work/zlint-oracle" < "$work/b64.txt" | grep -v '^##$' > "$work/zlint.txt"
[ "$(wc -l < "$work/inputs.tsv")" -eq "$(wc -l < "$work/zlint.txt")" ] || { echo "zlint reply count mismatch" >&2; exit 1; }
zlint_pin=$(awk '$1 == "github.com/zmap/zlint/v3" { print $2 }' native/zlint-oracle/go.mod)
[ -n "$zlint_pin" ] || { echo "no zlint pin in native/zlint-oracle/go.mod" >&2; exit 1; }
# Both oracles answered every input: write their goldens.
{
  echo "# Oracle-4 verdicts (mozilla/crlite go/types, pinned in native/producer-oracle/go.mod) for canon(input) of ProducerCorpus."
  echo "# sha256 of canon <TAB> OK <serial-hex> <spki-sha256-hex> <ct|lax|zc> | REJECT <error>. Regenerate, never edit."
  cut -f1 "$work/inputs.tsv" | paste - "$work/verdicts.txt" | LC_ALL=C sort
} > "$out"
echo "wrote $(grep -vc '^#' "$out") goldens to $out"
zlint="$root/revokt-engine/src/jvmTest/resources/dev/revokt/engine/parse/producer/zlint.tsv"
{
  echo "# zlint pin: $zlint_pin (native/zlint-oracle/go.mod); results for canon(input) of ProducerCorpus."
  echo "# sha256 of canon <TAB> LINT <errors|-> <fatals|-> <warnings|-> | UNPARSEABLE <error> | PANIC <error>. Regenerate, never edit."
  cut -f1 "$work/inputs.tsv" | paste - "$work/zlint.txt" | LC_ALL=C sort
} > "$zlint"
echo "wrote $(grep -vc '^#' "$zlint") zlint results to $zlint"
# The corpus records (spec §9.2), merged one matrix JDK at a time; written justifications and dates are kept.
records="$root/revokt-engine/src/jvmTest/resources/dev/revokt/engine/parse/records.jsonl"
for jdk in $jdks; do
  ./gradlew -q :revokt-engine:jvmTest --tests 'dev.revokt.engine.parse.records.RecordsTest.the records writer*' \
    -Drevokt.writeRecords="$records" -Prevokt.testJdk="$jdk" --rerun "$@" </dev/null
done
./gradlew -q :revokt-engine:jvmTestConscryptPrevious --tests 'dev.revokt.engine.parse.records.RecordsTest.the records writer*' \
  -Drevokt.writeRecords="$records" --rerun "$@" </dev/null
echo "wrote $(grep -c . "$records") records to $records"
