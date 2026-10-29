#!/bin/sh
# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
#
# Records the goldens of oracles 3a (x509-parser 0.18.1) and 3b (the independent locator) for every input of the replay
# corpus (spec §9.2, #35, #36, #38). The D8 replay reads both (canon from 3a, else 3b), so run this before
# native/producer-oracle/record-goldens.sh.
# Needs Rust and the matrix JDKs; the PR tier replays the committed goldens and needs neither. Run from the repository root:
#   sh native/revokt-oracle/record-goldens.sh
# REVOKT_RECORD_JDKS lists the JDKs to record on, by default the matrix of gradle/oracle-matrix.properties; each must
# be installed. The matrix's previous Conscrypt gets one more pass (jvmTestConscryptPrevious). Any arguments are passed
# to Gradle, for example
# -Porg.gradle.java.installations.paths=<comma-separated JDK homes>. REVOKT_CORPUS (below) adds the large corpus.
set -eu
root=$(pwd)
tab=$(printf '\t')
# REVOKT_CORPUS names a revokt-corpus working tree (docs/dev/corpus.md): its inputs join the replay corpus, and their
# goldens (and records) are written to its replay/, gzipped, for a new corpus tag; the committed corpus's stay here.
corpus=${REVOKT_CORPUS:-}
for arg in "$@"; do
  case $arg in -Prevokt.corpus=*) echo "set REVOKT_CORPUS, not -Prevokt.corpus: the large corpus's goldens go to it" >&2; exit 1 ;; esac
done
if [ -n "$corpus" ]; then
  [ -f "$corpus/x509-limbo/limbo.json" ] || { echo "REVOKT_CORPUS=$corpus is not a revokt-corpus working tree" >&2; exit 1; }
  corpus=$(CDPATH='' cd -- "$corpus" && pwd)
  mkdir -p "$corpus/replay"
  set -- "-Prevokt.corpus=$corpus" "$@"
fi
dir="$root/revokt-engine/src/jvmTest/resources/dev/revokt/engine/parse/oracle"
work=$(mktemp -d)
trap 'rm -rf "${work:?}"' EXIT
( cd native && cargo build --locked --release -q )
# One pass per matrix JDK (the bytes revokt reads depend on oracle 1's version), merged.
jdks=${REVOKT_RECORD_JDKS:-$(sed -n 's/^jdk[[:space:]]*[=:][[:space:]]*//p' gradle/oracle-matrix.properties | tr ',' ' ')}
[ -n "$(printf '%s' "$jdks" | tr -d ' ')" ] || { echo "no JDKs to record on (REVOKT_RECORD_JDKS, gradle/oracle-matrix.properties)" >&2; exit 1; }
case $jdks in *[!0-9\ ]*) echo "REVOKT_RECORD_JDKS must list JDK feature versions: $jdks" >&2; exit 1 ;; esac
for jdk in $jdks; do
  ./gradlew -q :revokt-engine:jvmTest --tests 'dev.revokt.engine.parse.oracle.Oracle3aTest.the 3a recording hook*' \
    -Drevokt.writeOracleInputs="$work/inputs-$jdk.tsv" -Prevokt.testJdk="$jdk" --rerun "$@" </dev/null
done
./gradlew -q :revokt-engine:jvmTestConscryptPrevious --tests 'dev.revokt.engine.parse.oracle.Oracle3aTest.the 3a recording hook*' \
  -Drevokt.writeOracleInputs="$work/inputs-conscrypt-previous.tsv" --rerun "$@" </dev/null
# Each input once, filed under the committed corpus (c) where both corpora have it.
LC_ALL=C sort -t "$tab" -k1,1 -k3,3 "$work"/inputs-*.tsv | awk -F "$tab" '$1 != prev { print; prev = $1 }' > "$work/inputs.tsv"
cut -f2 "$work/inputs.tsv" > "$work/b64.txt"
echo '##' >> "$work/b64.txt"
# write_goldens <replies> <committed tsv> <external name> <header lines>: each input's reply, filed by its origin.
write_goldens() {
  cut -f1,3 "$work/inputs.tsv" | paste - "$1" > "$work/keyed.tsv"
  { printf '%s\n' "$4"; awk -F "$tab" '$2 == "c"' "$work/keyed.tsv" | cut -f1,3- | LC_ALL=C sort -u; } > "$2"
  dups=$(grep -v '^#' "$2" | cut -f1 | uniq -d)
  [ -z "$dups" ] || { echo "$2: inputs with more than one reply: $dups" >&2; exit 1; }
  echo "wrote $(grep -vc '^#' "$2") goldens to $2"
  if [ -z "$corpus" ]; then
    [ "$(grep -vc '^#' "$2")" -eq "$(wc -l < "$work/inputs.tsv")" ] || { echo "$2: a reply was lost" >&2; exit 1; }
    return 0
  fi
  # The large corpus's goldens in 16 shards by the key's first hex digit (#64), each well under GitHub's 50 MB.
  ext="$corpus/replay/${3:?}"
  mkdir -p "$ext"
  awk -F "$tab" '$2 == "x"' "$work/keyed.tsv" | cut -f1,3- | LC_ALL=C sort -u > "$work/external.tsv"
  total=0
  for d in 0 1 2 3 4 5 6 7 8 9 a b c d e f; do
    { printf '%s\n' "$4" "# The large corpus's inputs (revokt-engine ExternalCorpus), keys starting $d; the committed corpus's are in revokt."
      grep "^$d" "$work/external.tsv" || true; } | gzip -9n > "$ext/$d.tsv.gz"
    n=$(gzip -dc "$ext/$d.tsv.gz" | grep -vc '^#' || true)
    total=$((total + n))
  done
  dups=$(cut -f1 "$work/external.tsv" | uniq -d)
  [ -z "$dups" ] || { echo "$ext: inputs with more than one reply: $dups" >&2; exit 1; }
  rm -f "$corpus/replay/$3.tsv.gz" # an older tag's single file, replaced by the shards
  echo "wrote $total goldens to $ext/"
  # Without pipefail a failed stage would leave a short shard: every input's reply is in one of the two corpora.
  [ $(( $(grep -vc '^#' "$2") + total )) -eq "$(wc -l < "$work/inputs.tsv")" ] ||
    { echo "$2, $ext: a reply was lost" >&2; exit 1; }
}
mkdir -p "$dir"
for oracle in "x509:3a:OK <fields> | ERR <error> | PANIC <error>" \
  "locate:3b:CANON <fields> | NOT_LOCATED <reason> | PANIC <reason>"; do
  cmd=${oracle%%:*}
  rest=${oracle#*:}
  name=${rest%%:*}
  format=${rest#*:}
  "$root/native/target/release/revokt-oracle" "$cmd" < "$work/b64.txt" | grep -v '^##$' > "$work/$name.txt"
  [ "$(wc -l < "$work/inputs.tsv")" -eq "$(wc -l < "$work/$name.txt")" ] || { echo "$name reply count mismatch" >&2; exit 1; }
  write_goldens "$work/$name.txt" "$dir/$name.tsv" "$name" \
    "# Oracle $name (native/revokt-oracle $cmd) replies for the replay corpus of ProducerCorpus.
# sha256 of the input <TAB> $format. Regenerate with native/revokt-oracle/record-goldens.sh, never edit."
done
