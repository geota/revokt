#!/bin/sh
# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
#
# Records the goldens of oracles 3a (x509-parser 0.18.1) and 3b (the independent locator) for every input of the replay
# corpus (spec §9.2, #35, #36, #38). The D8 replay reads both (canon from 3a, else 3b), so run this before
# native/producer-oracle/record-goldens.sh.
# Needs Rust and the matrix JDKs; the PR tier replays the committed goldens and needs neither. Run from the repository root:
#   sh native/revokt-oracle/record-goldens.sh
# REVOKT_RECORD_JDKS lists the JDKs to record on, by default the CI matrix of .github/workflows/ci.yml ("17 21 25 27");
# each must be installed. Any arguments are passed to Gradle, for example
# -Porg.gradle.java.installations.paths=<comma-separated JDK homes>.
set -eu
root=$(pwd)
dir="$root/revokt-engine/src/jvmTest/resources/dev/revokt/engine/parse/oracle"
work=$(mktemp -d)
trap 'rm -rf "${work:?}"' EXIT
( cd native && cargo build --locked --release -q )
# One pass per matrix JDK (the bytes revokt reads depend on oracle 1's version), merged.
jdks=${REVOKT_RECORD_JDKS:-17 21 25 27}
case $jdks in *[!0-9\ ]*) echo "REVOKT_RECORD_JDKS must list JDK feature versions: $jdks" >&2; exit 1 ;; esac
for jdk in $jdks; do
  ./gradlew -q :revokt-engine:jvmTest --tests 'dev.revokt.engine.parse.oracle.Oracle3aTest.the 3a recording hook*' \
    -Drevokt.writeOracleInputs="$work/inputs-$jdk.tsv" -Prevokt.testJdk="$jdk" --rerun "$@" </dev/null
done
LC_ALL=C sort -u "$work"/inputs-*.tsv > "$work/inputs.tsv"
cut -f2 "$work/inputs.tsv" > "$work/b64.txt"
echo '##' >> "$work/b64.txt"
mkdir -p "$dir"
for oracle in "x509:3a:OK <fields> | ERR <error> | PANIC <error>" \
  "locate:3b:CANON <fields> | NOT_LOCATED <reason> | PANIC <reason>"; do
  cmd=${oracle%%:*}
  rest=${oracle#*:}
  name=${rest%%:*}
  format=${rest#*:}
  "$root/native/target/release/revokt-oracle" "$cmd" < "$work/b64.txt" | grep -v '^##$' > "$work/$name.txt"
  [ "$(wc -l < "$work/inputs.tsv")" -eq "$(wc -l < "$work/$name.txt")" ] || { echo "$name reply count mismatch" >&2; exit 1; }
  {
    echo "# Oracle $name (native/revokt-oracle $cmd) replies for the replay corpus of ProducerCorpus."
    echo "# sha256 of the input <TAB> $format. Regenerate with native/revokt-oracle/record-goldens.sh, never edit."
    cut -f1 "$work/inputs.tsv" | paste - "$work/$name.txt" | LC_ALL=C sort -u
  } > "$dir/$name.tsv"
  dups=$(grep -v '^#' "$dir/$name.tsv" | cut -f1 | uniq -d)
  [ -z "$dups" ] || { echo "$name inputs with more than one reply: $dups" >&2; exit 1; }
  echo "wrote $(grep -vc '^#' "$dir/$name.tsv") $name goldens"
done
